#include "ckks_cuda.cuh"
#include "kernelutils.cuh"

using namespace troy::util;
using namespace std;


#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy {

    namespace {
        
        [[maybe_unused]] void printDeviceArray(const DeviceArray<uint64_t>& r, bool dont_compress = false) {
            HostArray<uint64_t> start = r.toHost();
            size_t count = r.size();
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }

        [[maybe_unused]] void printDeviceArray(const uint64_t* r, size_t count, bool dont_compress = false) {
            HostArray<uint64_t> start(count);
            KernelProvider::retrieve(start.get(), r, count);
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }
        
        [[maybe_unused]] void printDeviceArray(const DeviceArray<complex<double>>& r, bool dont_compress = false) {
            HostArray<complex<double>> start = r.toHost();
            size_t count = r.size();
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }

        [[maybe_unused]] void printDeviceArray(const complex<double>* r, size_t count, bool dont_compress = false) {
            HostArray<complex<double>> start(count);
            KernelProvider::retrieve(start.get(), r, count);
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }
    }

    CKKSEncoderCuda::CKKSEncoderCuda(const SEALContextCuda& context)
        : context_(context) 
    {

        CKKSEncoder host(context.host());
        slots_ = host.slots_;
        root_powers_ = host.root_powers_;
        inv_root_powers_ = host.inv_root_powers_;
        matrix_reps_index_map_ = host.matrix_reps_index_map_;

        // calculate complex roots
        size_t coeff_count = context.firstContextData()->parms().polyModulusDegree();
        uint64_t m = static_cast<uint64_t>(coeff_count) << 1;
        
        const double pi = 3.1415926535897932384626433832795028842;
        util::HostArray<std::complex<double>> roots(m + 1);
        for (size_t i = 0; i <= m; i++) {
            roots[i] = std::polar<double>(1.0, 2 * pi * static_cast<double>(i) / static_cast<double>(m));
        }

        complex_roots_ = roots;

    }

    __device__ inline void dSetComplex(
        double* array, size_t index, double real, double imag
    ) {
        array[index * 2] = real;
        array[index * 2 + 1] = imag;
    }

    __global__ void gEncodeInternalSetConjValues(
        const double* copied_values,
        size_t values_size,
        size_t slots,
        double* conj_values,
        uint64_t* matrix_reps_index_map
    ) {
        GET_INDEX_COND_RETURN(slots);
        double real = (gindex < values_size) ? copied_values[gindex * 2] : 0;
        double imag = (gindex < values_size) ? copied_values[gindex * 2 + 1] : 0;
        // printf("gindex=%lu, real=%lf, imag=%lf\n", gindex, real, imag);
        dSetComplex(conj_values, matrix_reps_index_map[gindex], real, imag);
        dSetComplex(conj_values, matrix_reps_index_map[gindex + slots], real, -imag);
    }

    __global__ void gFftTransferFromRevLayered(
        size_t layer,
        double* operand,
        size_t poly_modulus_degree_power,
        const double* roots
    ) {
        GET_INDEX_COND_RETURN(1 << (poly_modulus_degree_power - 1));
        size_t m = 1 << (poly_modulus_degree_power - 1 - layer);
        size_t gap = 1 << layer;
        size_t rid = (1 << poly_modulus_degree_power) - (m << 1) + 1 + (gindex >> layer);
        size_t coeff_index = ((gindex >> layer) << (layer + 1)) + (gindex & (gap - 1));
        double* x = operand + coeff_index * 2;
        double* y = x + gap * 2;

        double ur = x[0], ui = x[1], vr = y[0], vi = y[1];
        double rr = roots[rid * 2], ri = roots[rid * 2 + 1];

        // x = u + v
        x[0] = ur + vr;
        x[1] = ui + vi;
        
        // y = (u-v) * r
        ur -= vr; ui -= vi; // u <- u - v
        y[0] = ur * rr - ui * ri;
        y[1] = ur * ri + ui * rr;
    }

    __global__ void gMultiplyScalar(
        double* operand, 
        size_t n,
        double scalar
    ) {
        GET_INDEX_COND_RETURN(n);
        operand[gindex * 2] *= scalar;
        operand[gindex * 2 + 1] *= scalar;
    }

    void kFftTransferFromRev(
        complex<double>* operand,
        size_t poly_modulus_degree_power,
        const complex<double>* roots,
        double fix = 1
    ) {
        std::size_t n = size_t(1) << poly_modulus_degree_power;
        std::size_t m = n >> 1; std::size_t layer = 0;
        for(; m >= 1; m>>=1) {
            KERNEL_CALL(gFftTransferFromRevLayered, n>>1)(
                layer, reinterpret_cast<double*>(operand),
                poly_modulus_degree_power,
                reinterpret_cast<const double*>(roots)
            );
            layer++;
        }
        if (fix != 1) {
            KERNEL_CALL(gMultiplyScalar, n)(
                reinterpret_cast<double*>(operand), n, fix
            );
        }
    }

    __global__ void gMaxReal(
        double* complexes,
        size_t n_sqrt,
        size_t n, 
        double* out
    ) {
        GET_INDEX_COND_RETURN(n_sqrt);
        double m = 0;
        FOR_N(i, n_sqrt) {
            size_t id = gindex * n_sqrt + i;
            if (id >= n) break;
            if (fabs(complexes[id * 2]) > m) m = fabs(complexes[id * 2]);
        }
        out[gindex] = m;
    }


    __global__ void gMax(
        double* values,
        size_t n_sqrt,
        size_t n, 
        double* out
    ) {
        GET_INDEX_COND_RETURN(n_sqrt);
        double m = 0;
        FOR_N(i, n_sqrt) {
            size_t id = gindex * n_sqrt + i;
            if (id >= n) break;
            if (fabs(values[id]) > m) m = fabs(values[id]);
        }
        out[gindex] = m;
    }

    __global__ void gEncodeInternalComplexArrayUtilA(
        double* conj_values,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* destination,
        bool is_complex = true
    ) {
        GET_INDEX_COND_RETURN(n);
        double coeffd = round(conj_values[gindex * (is_complex ? 2 : 1)]);
        bool is_negative = coeffd < 0;
        uint64_t coeffu = static_cast<uint64_t>(abs(coeffd));
        FOR_N(j, coeff_modulus_size) {
            if (is_negative) {
                destination[gindex + j * n] = kernel_util::dNegateUintMod(
                    kernel_util::dBarrettReduce64(coeffu, coeff_modulus[j]), coeff_modulus[j]
                );
            } else {
                destination[gindex + j * n] = kernel_util::dBarrettReduce64(coeffu, coeff_modulus[j]);
            }
        }
    }

    __global__ void gEncodeInternalComplexArrayUtilB(
        double* conj_values,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* destination,
        bool is_complex = true
    ) {
        GET_INDEX_COND_RETURN(n);
        double two_pow_64 = pow(2.0, 64);
        double coeffd = round(conj_values[gindex * (is_complex ? 2 : 1)]);
        bool is_negative = coeffd < 0;
        coeffd = fabs(coeffd);
        uint64_t coeffu[2] = {
            static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
            static_cast<uint64_t>(coeffd / two_pow_64),
        };
        FOR_N(j, coeff_modulus_size) {
            if (is_negative) {
                destination[gindex + j * n] = kernel_util::dNegateUintMod(
                    kernel_util::dBarrettReduce128(coeffu, coeff_modulus[j]), coeff_modulus[j]
                );
            } else {
                destination[gindex + j * n] = kernel_util::dBarrettReduce128(coeffu, coeff_modulus[j]);
            }
        }
    }

    __global__ void gEncodeInternalComplexArrayUtilC(
        double* conj_values,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* coeffu_array,
        bool is_complex = true
    ) {
        GET_INDEX_COND_RETURN(n);
        double two_pow_64 = pow(2.0, 64);
        double coeffd = round(conj_values[gindex * (is_complex ? 2 : 1)]);
        coeffd = fabs(coeffd);
        uint64_t* coeffu = coeffu_array + gindex * coeff_modulus_size;
        uint64_t* coeffu_ptr = coeffu;
        while (coeffd >= 1) {
            *coeffu_ptr++ = static_cast<std::uint64_t>(std::fmod(coeffd, two_pow_64));
            coeffd /= two_pow_64;
        }
    }

    __global__ void gEncodeInternalComplexArrayUtilD(
        const double* conj_values,
        const uint64_t* coeffu_array,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* destination,
        bool is_complex = true
    ) {
        GET_INDEX_COND_RETURN(n);
        double coeffd = round(conj_values[gindex * (is_complex ? 2 : 1)]);
        bool is_negative = coeffd < 0;
        const uint64_t* coeffu = coeffu_array + gindex * coeff_modulus_size;
        FOR_N(j, coeff_modulus_size) {
            if (is_negative) {
                destination[gindex + j * n] = kernel_util::dNegateUintMod(coeffu[j], coeff_modulus[j]);
            } else {
                destination[gindex + j * n] = coeffu[j];
            }
        }
    }

    __global__ void gCopyMulScalar(
        const double* from,
        double* to,
        size_t n,
        double scalar
    ) {
        GET_INDEX_COND_RETURN(n);
        to[gindex] = from[gindex] * scalar;
    }

    void CKKSEncoderCuda::encodeInternal(
        const std::complex<double> *values, std::size_t values_size, ParmsID parms_id, double scale, PlaintextCuda &destination)
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw std::invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!values && values_size > 0)
        {
            throw std::invalid_argument("values cannot be null");
        }
        if (values_size > slots_)
        {
            throw std::invalid_argument("values_size is too large");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        std::size_t coeff_count = parms.polyModulusDegree();

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) + 1 >= context_data.totalCoeffModulusBitCount()))
        {
            throw std::invalid_argument("scale out of bounds");
        }

        auto ntt_tables = context_data.smallNTTTables();

        // values_size is guaranteed to be no bigger than slots_
        std::size_t n = util::mul_safe(slots_, std::size_t(2));

        auto conj_values = util::DeviceArray<complex<double>>(n);
        auto copied_values = util::DeviceArray<complex<double>>(values_size);
        
        // printf("conj_values init\n");
        // printDeviceArray(conj_values);

        KernelProvider::copy(copied_values.get(), values, values_size);

        
        // printf("copy values init\n");
        // printDeviceArray(copied_values);

        { KERNEL_CALL(gEncodeInternalSetConjValues, slots_)(
            reinterpret_cast<const double*>(copied_values.get()), 
            values_size, slots_, 
            reinterpret_cast<double*>(conj_values.get()), 
            matrix_reps_index_map_.get() 
        ); }

        // printf("conj_values\n");
        // printDeviceArray(conj_values);

        double fix = scale / static_cast<double>(n);
        kFftTransferFromRev(
            conj_values.get(), 
            util::getPowerOfTwo(n),
            inv_root_powers_.get(), fix);


        // printf("conj_values transfered\n");
        // printDeviceArray(conj_values);

        // std::cout << "here" << std::endl;

        size_t n_sqrt = static_cast<size_t>(std::sqrt(n)) + 1;
        auto max_coeff_array = util::DeviceArray<double>(n_sqrt);
        { 
            KERNEL_CALL(gMaxReal, n_sqrt)(
                reinterpret_cast<double*>(conj_values.get()), 
                n_sqrt, n, max_coeff_array.get() 
            );
        }

        // std::cout << "here" << std::endl;

        auto max_coeff_array_cpu = max_coeff_array.toHost();
        double max_coeff = 0;
        for (std::size_t i = 0; i < max_coeff_array_cpu.size(); i++) {
            max_coeff = std::max<>(max_coeff, max_coeff_array_cpu[i]);
        }
        
        // Verify that the values are not too large to fit in coeff_modulus
        // Note that we have an extra + 1 for the sign bit
        // Don't compute logarithmis of numbers less than 1
        int max_coeff_bit_count = static_cast<int>(std::ceil(std::log2(std::max<>(max_coeff, 1.0)))) + 1;
        if (max_coeff_bit_count >= context_data.totalCoeffModulusBitCount())
        {
            throw std::invalid_argument("encoded values are too large");
        }

        double two_pow_64 = std::pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parmsID() = parmsIDZero;
        destination.resize(util::mul_safe(coeff_count, coeff_modulus_size));

        // Use faster decomposition methods when possible
        if (max_coeff_bit_count <= 64)
        {
            KERNEL_CALL(gEncodeInternalComplexArrayUtilA, n) (
                reinterpret_cast<double*>(conj_values.get()), 
                n, coeff_modulus_size, coeff_modulus.get(), destination.data()
            );
        }
        else if (max_coeff_bit_count <= 128)
        {
            KERNEL_CALL(gEncodeInternalComplexArrayUtilB, n) (
                reinterpret_cast<double*>(conj_values.get()), 
                n, coeff_modulus_size, coeff_modulus.get(), destination.data()
            );
        }
        else
        {
            auto coeffu_array = DeviceArray<uint64_t>(coeff_modulus_size * n);
            kernel_util::kSetZeroPolyArray(1, coeff_modulus_size, n, coeffu_array);
            KERNEL_CALL(gEncodeInternalComplexArrayUtilC, n) (
                reinterpret_cast<double*>(conj_values.get()), 
                n, coeff_modulus_size, coeff_modulus.get(), coeffu_array.get()
            );
            context_data.rnsTool()->baseq()->decomposeArrayKeepOrder(coeffu_array.get(), n);
            gEncodeInternalComplexArrayUtilD<<<block_count, 256>>>(
                reinterpret_cast<double*>(conj_values.get()), 
                coeffu_array.get(), n, 
                coeff_modulus_size, coeff_modulus.get(),
                destination.data()
            );
        }

        kernel_util::kNttNegacyclicHarvey(destination.data(), 1, coeff_modulus_size, getPowerOfTwo(n), ntt_tables);

        destination.parmsID() = parms_id;
        destination.scale() = scale;
    }

    void CKKSEncoderCuda::encodePolynomialInternal(
        const double* values, std::size_t values_size,
        ParmsID parms_id, double scale, PlaintextCuda& destination
    ) {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw std::invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!values && values_size > 0)
        {
            throw std::invalid_argument("values cannot be null");
        }
        if (values_size > slots_ * 2)
        {
            throw std::invalid_argument("values_size is too large");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        std::size_t coeff_count = parms.polyModulusDegree();
        auto ntt_tables = context_data.smallNTTTables();
        
        std::size_t n = util::mul_safe(slots_, std::size_t(2));
        
        auto values_cuda = DeviceArray<double>(n);
        KernelProvider::memsetZero(values_cuda.get(), n);
        KernelProvider::copy(values_cuda.get(), values, values_size);

        auto conj_values = util::DeviceArray<double>(n);
        KernelProvider::memsetZero<double>(conj_values.get(), n);
        {
            KERNEL_CALL(gCopyMulScalar, n)(
                values_cuda.get(),
                conj_values.get(),
                n,
                scale
            );
        }

        size_t n_sqrt = static_cast<size_t>(std::sqrt(n)) + 1;
        auto max_coeff_array = util::DeviceArray<double>(n_sqrt);
        { 
            KERNEL_CALL(gMax, n_sqrt)(
                reinterpret_cast<double*>(conj_values.get()), 
                n_sqrt, n, max_coeff_array.get() 
            );
        }

        // std::cout << "here" << std::endl;

        auto max_coeff_array_cpu = max_coeff_array.toHost();
        double max_coeff = 0;
        for (std::size_t i = 0; i < max_coeff_array_cpu.size(); i++) {
            max_coeff = std::max<>(max_coeff, max_coeff_array_cpu[i]);
        }
        
        // Verify that the values are not too large to fit in coeff_modulus
        // Note that we have an extra + 1 for the sign bit
        // Don't compute logarithmis of numbers less than 1
        int max_coeff_bit_count = static_cast<int>(std::ceil(std::log2(std::max<>(max_coeff, 1.0)))) + 1;
        if (max_coeff_bit_count >= context_data.totalCoeffModulusBitCount())
        {
            throw std::invalid_argument("encoded values are too large");
        }

        double two_pow_64 = std::pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parmsID() = parmsIDZero;
        destination.resize(util::mul_safe(coeff_count, coeff_modulus_size));

        // Use faster decomposition methods when possible
        if (max_coeff_bit_count <= 64)
        {
            KERNEL_CALL(gEncodeInternalComplexArrayUtilA, n) (
                reinterpret_cast<double*>(conj_values.get()), 
                n, coeff_modulus_size, coeff_modulus.get(), destination.data(),
                false
            );
        }
        else if (max_coeff_bit_count <= 128)
        {
            KERNEL_CALL(gEncodeInternalComplexArrayUtilB, n) (
                reinterpret_cast<double*>(conj_values.get()), 
                n, coeff_modulus_size, coeff_modulus.get(), destination.data(),
                false
            );
        }
        else
        {
            auto coeffu_array = DeviceArray<uint64_t>(coeff_modulus_size * n);
            kernel_util::kSetZeroPolyArray(1, coeff_modulus_size, n, coeffu_array);
            KERNEL_CALL(gEncodeInternalComplexArrayUtilC, n) (
                reinterpret_cast<double*>(conj_values.get()), 
                n, coeff_modulus_size, coeff_modulus.get(), coeffu_array.get(),
                false
            );
            context_data.rnsTool()->baseq()->decomposeArrayKeepOrder(coeffu_array.get(), n);
            gEncodeInternalComplexArrayUtilD<<<block_count, 256>>>(
                reinterpret_cast<double*>(conj_values.get()), 
                coeffu_array.get(), n, 
                coeff_modulus_size, coeff_modulus.get(),
                destination.data(),
                false
            );
        }

        kernel_util::kNttNegacyclicHarvey(destination.data(), 1, coeff_modulus_size, getPowerOfTwo(n), ntt_tables);

        destination.parmsID() = parms_id;
        destination.scale() = scale;
    }




    __global__ void gEncodeInternalDoubleUtilA(
        double coeffd,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* destination
    ) {
        GET_INDEX_COND_RETURN(n);
        bool is_negative = coeffd < 0;
        uint64_t coeffu = static_cast<uint64_t>(abs(coeffd));
        FOR_N(j, coeff_modulus_size) {
            uint64_t fill = is_negative 
                ? kernel_util::dNegateUintMod(kernel_util::dBarrettReduce64(coeffu, coeff_modulus[j]), coeff_modulus[j])
                : kernel_util::dBarrettReduce64(coeffu, coeff_modulus[j]);
            destination[gindex + j * n] = fill;
        }
    }

    __global__ void gEncodeInternalDoubleUtilB(
        double coeffd,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* destination
    ) {
        GET_INDEX_COND_RETURN(n);
        double two_pow_64 = pow(2.0, 64);
        bool is_negative = coeffd < 0;
        coeffd = fabs(coeffd);
        uint64_t coeffu[2] = {
            static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
            static_cast<uint64_t>(coeffd / two_pow_64),
        };
        FOR_N(j, coeff_modulus_size) {
            uint64_t fill = is_negative 
                ? kernel_util::dNegateUintMod(kernel_util::dBarrettReduce128(coeffu, coeff_modulus[j]), coeff_modulus[j])
                : kernel_util::dBarrettReduce128(coeffu, coeff_modulus[j]);
            destination[gindex + j * n] = fill;
        }
    }

    __global__ void gEncodeInternalDoubleUtilC(
        const uint64_t* coeffu,
        bool is_negative,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* destination
    ) {
        GET_INDEX_COND_RETURN(n);
        FOR_N(j, coeff_modulus_size) {
            uint64_t fill = is_negative 
                ? kernel_util::dNegateUintMod(coeffu[j], coeff_modulus[j])
                : coeffu[j];
            destination[gindex + j * n] = fill;
        }
    }


    void CKKSEncoderCuda::encodeInternal(
        double value, ParmsID parms_id, double scale, PlaintextCuda &destination)
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.polyModulusDegree();

        // Quick sanity check
        if (!productFitsIn(coeff_modulus_size, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) >= context_data.totalCoeffModulusBitCount()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // Compute the scaled value
        value *= scale;

        int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
        if (coeff_bit_count >= context_data.totalCoeffModulusBitCount())
        {
            throw invalid_argument("encoded value is too large");
        }

        double two_pow_64 = pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parmsID() = parmsIDZero;
        destination.resize(coeff_count * coeff_modulus_size);

        double coeffd = round(value);
        bool is_negative = signbit(coeffd);
        coeffd = fabs(coeffd);

        // Use faster decomposition methods when possible
        if (coeff_bit_count <= 64)
        {
            KERNEL_CALL(gEncodeInternalDoubleUtilA, coeff_count) (
                coeffd, coeff_count, 
                coeff_modulus_size, coeff_modulus.get(), destination.data()
            );
        }
        else if (coeff_bit_count <= 128)
        {
            KERNEL_CALL(gEncodeInternalDoubleUtilB, coeff_count) (
                coeffd, coeff_count, 
                coeff_modulus_size, coeff_modulus.get(), destination.data()
            );
        }
        else
        {
            // Slow case
            auto coeffu = allocateUint(coeff_modulus_size);

            // We are at this point guaranteed to fit in the allocated space
            setZeroUint(coeff_modulus_size, coeffu.get());
            auto coeffu_ptr = coeffu.get();
            while (coeffd >= 1)
            {
                *coeffu_ptr++ = static_cast<uint64_t>(fmod(coeffd, two_pow_64));
                coeffd /= two_pow_64;
            }

            // Next decompose this coefficient
            DeviceArray<uint64_t> coeffu_dev(coeffu);
            context_data.rnsTool()->baseq()->decomposeArray(coeffu_dev, 1);
            KERNEL_CALL(gEncodeInternalDoubleUtilC, coeff_count) (
                coeffu_dev.get(), is_negative, coeff_count, 
                coeff_modulus_size, coeff_modulus.get(), destination.data()
            );
        }

        destination.parmsID() = parms_id;
        destination.scale() = scale;
    }







    __global__ void gEncodeInternalInt64(
        int64_t value,
        size_t n,
        size_t coeff_modulus_size,
        const Modulus* coeff_modulus,
        uint64_t* destination
    ) {
        GET_INDEX_COND_RETURN(n);
        FOR_N(j, coeff_modulus_size) {
            uint64_t fill = (value < 0) 
                ? (static_cast<uint64_t>(value) + DeviceHelper::getModulusValue(coeff_modulus[j]))
                : static_cast<uint64_t>(value);
            destination[gindex + j * n] = kernel_util::dBarrettReduce64(fill, coeff_modulus[j]);
        }
    }

    void CKKSEncoderCuda::encodeInternal(int64_t value, ParmsID parms_id, PlaintextCuda &destination)
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.polyModulusDegree();

        // Quick sanity check
        if (!productFitsIn(coeff_modulus_size, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        int coeff_bit_count = getSignificantBitCount(static_cast<uint64_t>(llabs(value))) + 2;
        if (coeff_bit_count >= context_data.totalCoeffModulusBitCount())
        {
            throw invalid_argument("encoded value is too large");
        }

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parmsID() = parmsIDZero;
        destination.resize(coeff_count * coeff_modulus_size);


        KERNEL_CALL(gEncodeInternalInt64, coeff_count) (
            value, coeff_count, 
            coeff_modulus_size, coeff_modulus.get(), destination.data()
        );

        destination.parmsID() = parms_id;
        destination.scale() = 1.0;
    }


    __global__ void gDecodeInternal(
        const uint64_t* plain_copy,
        size_t coeff_count,
        size_t coeff_modulus_size,
        const uint64_t* decryption_modulus,
        const uint64_t* upper_half_threshold,
        double inv_scale,
        double* res
    ) {
        GET_INDEX_COND_RETURN(coeff_count); size_t i = gindex;
        bool greater = kernel_util::dCompareUint(plain_copy + i * coeff_modulus_size, upper_half_threshold, coeff_modulus_size) >= 0;
        double two_pow_64 = pow(2.0, 64);
        dSetComplex(res, i, 0, 0);
        if (greater) {
            double scaled_two_pow_64 = inv_scale;
            for (std::size_t j = 0; j < coeff_modulus_size; j++, scaled_two_pow_64 *= two_pow_64)
            {
                if (plain_copy[i * coeff_modulus_size + j] > decryption_modulus[j])
                {
                    auto diff = plain_copy[i * coeff_modulus_size + j] - decryption_modulus[j];
                    res[i * 2] += diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                }
                else
                {
                    auto diff = decryption_modulus[j] - plain_copy[i * coeff_modulus_size + j];
                    res[i * 2] -= diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                }
            }
        }
        else
        {
            double scaled_two_pow_64 = inv_scale;
            for (std::size_t j = 0; j < coeff_modulus_size; j++, scaled_two_pow_64 *= two_pow_64)
            {
                auto curr_coeff = plain_copy[i * coeff_modulus_size + j];
                res[i * 2] += curr_coeff ? static_cast<double>(curr_coeff) * scaled_two_pow_64 : 0.0;
            }
        }
    }

    __global__ void gFftTransferToRevLayered(
        size_t layer,
        double* operand,
        size_t poly_modulus_degree_power,
        const double* roots
    ) {
        GET_INDEX_COND_RETURN(1 << (poly_modulus_degree_power - 1));
        size_t m = 1 << layer;
        size_t gap_power = poly_modulus_degree_power - layer - 1;
        size_t gap = 1 << gap_power;
        size_t rid = m + (gindex >> gap_power);
        size_t coeff_index = ((gindex >> gap_power) << (gap_power + 1)) + (gindex & (gap - 1));
        // printf("m = %lu, coeff_index = %lu\n", m, coeff_index);
        double ur, ui, vr, vi;
        double rr = roots[rid * 2], ri = roots[rid * 2 + 1];

        double* x = operand + coeff_index * 2;
        double* y = x + gap * 2;
        ur = x[0]; ui = x[1];
        vr = y[0] * rr - y[1] * ri; vi = y[0] * ri + y[1] * rr; // v = y * r
        x[0] = ur + vr; x[1] = ui + vi; // x = u + v
        y[0] = ur - vr; y[1] = ui - vi; // y = u - v

    }

    void kFftTransferToRevLayered(
        size_t layer,
        complex<double>* operand,
        size_t poly_modulus_degree_power,
        const complex<double>* roots
    ) {
        std::size_t n = size_t(1) << poly_modulus_degree_power;
        KERNEL_CALL(gFftTransferToRevLayered, n)(
            layer, 
            reinterpret_cast<double*>(operand), 
            poly_modulus_degree_power, 
            reinterpret_cast<const double*>(roots)
        );
    }

    void kFftTransferToRev(
        complex<double>* operand,
        size_t poly_modulus_degree_power,
        const complex<double>* roots
    ) {
        std::size_t m = 1; std::size_t layer = 0;
        std::size_t n = size_t(1) << poly_modulus_degree_power;
        for(; m <= (n>>1); m<<=1) {
            kFftTransferToRevLayered(
                layer, operand, poly_modulus_degree_power, roots);
            layer++;
        }
    }



    __global__ void gDecodeInternalSetConjValues(
        const double* values,
        size_t slots,
        double* destination,
        uint64_t* matrix_reps_index_map
    ) {
        GET_INDEX_COND_RETURN(slots);
        size_t id = static_cast<std::size_t>(matrix_reps_index_map[gindex]);
        dSetComplex(destination, gindex, values[id * 2], values[id * 2 + 1]);
    }

    void CKKSEncoderCuda::decodeInternal(const PlaintextCuda &plain, std::complex<double> *destination)
    {
        if (!plain.isNttForm())
        {
            throw std::invalid_argument("plain is not in NTT form");
        }
        if (!destination)
        {
            throw std::invalid_argument("destination cannot be null");
        }

        auto &context_data = *context_.getContextData(plain.parmsID());
        auto &parms = context_data.parms();
        std::size_t coeff_modulus_size = parms.coeffModulus().size();
        std::size_t coeff_count = parms.polyModulusDegree();
        std::size_t rns_poly_uint64_count = util::mul_safe(coeff_count, coeff_modulus_size);

        auto ntt_tables = context_data.smallNTTTables();

        // Check that scale is positive and not too large
        if (plain.scale() <= 0 ||
            (static_cast<int>(log2(plain.scale())) >= context_data.totalCoeffModulusBitCount()))
        {
            throw std::invalid_argument("scale out of bounds");
        }

        auto& decryption_modulus = context_data.totalCoeffModulus();
        auto upper_half_threshold = context_data.upperHalfThreshold();
        int logn = util::getPowerOfTwo(coeff_count);

        // Quick sanity check
        if ((logn < 0) || (coeff_count < SEAL_POLY_MOD_DEGREE_MIN) || (coeff_count > SEAL_POLY_MOD_DEGREE_MAX))
        {
            throw std::logic_error("invalid parameters");
        }

        double inv_scale = double(1.0) / plain.scale();

        // Create mutable copy of input
        auto plain_copy = kernel_util::kAllocate(rns_poly_uint64_count);
        kernel_util::kSetPolyArray(plain.data(), 1, coeff_modulus_size, coeff_count, plain_copy.get());

        // Transform each polynomial from NTT domain
        kernel_util::kInverseNttNegacyclicHarvey(plain_copy.get(), 1, coeff_modulus_size, logn, ntt_tables);

        // printDeviceArray(plain_copy);

        // CRT-compose the polynomial
        context_data.rnsTool()->baseq()->composeArray(plain_copy.get(), coeff_count);

        // Create floating-point representations of the multi-precision integer coefficients
        double two_pow_64 = std::pow(2.0, 64);
        auto res = util::DeviceArray<std::complex<double>>(coeff_count);

        { KERNEL_CALL(gDecodeInternal, coeff_count)(
            plain_copy.get(), coeff_count, coeff_modulus_size, decryption_modulus.get(),
            upper_half_threshold.get(), inv_scale, 
            reinterpret_cast<double*>(res.get())
        ); }

        kFftTransferToRev(res.get(), logn, root_powers_.get());

        auto destination_device = util::DeviceArray<std::complex<double>>(slots_);

        { KERNEL_CALL(gDecodeInternalSetConjValues, slots_)(
            reinterpret_cast<const double*>(res.get()), slots_, 
            reinterpret_cast<double*>(destination_device.get()), 
            matrix_reps_index_map_.get() 
        ); }

        KernelProvider::retrieve(destination, destination_device.get(), slots_);
    }


    __global__ void gRetrieveReals(
        const double* from,
        double* to,
        size_t n
    ) {
        GET_INDEX_COND_RETURN(n);
        to[gindex] = from[gindex * 2];
    }

    void CKKSEncoderCuda::decodePolynomialInternal(const PlaintextCuda &plain, double *destination)
    {
        if (!plain.isNttForm())
        {
            throw std::invalid_argument("plain is not in NTT form");
        }
        if (!destination)
        {
            throw std::invalid_argument("destination cannot be null");
        }

        auto &context_data = *context_.getContextData(plain.parmsID());
        auto &parms = context_data.parms();
        std::size_t coeff_modulus_size = parms.coeffModulus().size();
        std::size_t coeff_count = parms.polyModulusDegree();
        std::size_t rns_poly_uint64_count = util::mul_safe(coeff_count, coeff_modulus_size);

        auto ntt_tables = context_data.smallNTTTables();

        // Check that scale is positive and not too large
        if (plain.scale() <= 0 ||
            (static_cast<int>(log2(plain.scale())) >= context_data.totalCoeffModulusBitCount()))
        {
            throw std::invalid_argument("scale out of bounds");
        }

        auto& decryption_modulus = context_data.totalCoeffModulus();
        auto upper_half_threshold = context_data.upperHalfThreshold();
        int logn = util::getPowerOfTwo(coeff_count);

        // Quick sanity check
        if ((logn < 0) || (coeff_count < SEAL_POLY_MOD_DEGREE_MIN) || (coeff_count > SEAL_POLY_MOD_DEGREE_MAX))
        {
            throw std::logic_error("invalid parameters");
        }

        double inv_scale = double(1.0) / plain.scale();

        // Create mutable copy of input
        auto plain_copy = kernel_util::kAllocate(rns_poly_uint64_count);
        kernel_util::kSetPolyArray(plain.data(), 1, coeff_modulus_size, coeff_count, plain_copy.get());

        // Transform each polynomial from NTT domain
        kernel_util::kInverseNttNegacyclicHarvey(plain_copy.get(), 1, coeff_modulus_size, logn, ntt_tables);

        // printDeviceArray(plain_copy);

        // CRT-compose the polynomial
        context_data.rnsTool()->baseq()->composeArray(plain_copy.get(), coeff_count);

        // Create floating-point representations of the multi-precision integer coefficients
        double two_pow_64 = std::pow(2.0, 64);
        auto res = util::DeviceArray<std::complex<double>>(coeff_count);

        { KERNEL_CALL(gDecodeInternal, coeff_count)(
            plain_copy.get(), coeff_count, coeff_modulus_size, decryption_modulus.get(),
            upper_half_threshold.get(), inv_scale, 
            reinterpret_cast<double*>(res.get())
        ); }

        auto destination_device = util::DeviceArray<double>(coeff_count);

        {
            KERNEL_CALL(gRetrieveReals, coeff_count)(
                reinterpret_cast<double*>(res.get()),
                destination_device.get(),
                coeff_count
            );
        }

        KernelProvider::retrieve(destination, destination_device.get(), coeff_count);
        
    }

}