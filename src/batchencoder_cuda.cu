#include "batchencoder_cuda.cuh"
#include "kernelutils.cuh"

using std::vector;
using std::invalid_argument;


#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

using namespace troy::util;

namespace troy {

    BatchEncoderCuda::BatchEncoderCuda(const SEALContextCuda& context): context_(context) {
        BatchEncoder host(context.host());
        slots_ = host.slots_;
        roots_of_unity_ = host.roots_of_unity_;
        matrix_reps_index_map_ = host.matrix_reps_index_map_;
    }


    __global__ void gEncodeUnsignedUtil(
        const uint64_t* values_matrix,
        size_t slots, 
        size_t values_matrix_size,
        uint64_t* destination,
        const uint64_t* matrix_reps_index_map
    ) {
        GET_INDEX_COND_RETURN(slots);
        destination[matrix_reps_index_map[gindex]] = 
            (gindex < values_matrix_size)
            ? values_matrix[gindex]
            : 0;
    }


    void BatchEncoderCuda::encode(const vector<uint64_t> &values_matrix, PlaintextCuda &destination) const
    {
        auto &context_data = *context_.firstContextData();

        // Validate input parameters
        size_t values_matrix_size = values_matrix.size();
        if (values_matrix_size > slots_)
        {
            throw invalid_argument("values_matrix size is too large");
        }
        // Set destination to full size
        destination.resize(slots_);
        destination.parmsID() = parmsIDZero;

        DeviceArray<uint64_t> values_matrix_device(values_matrix_size);
        KernelProvider::copy(values_matrix_device.get(), &values_matrix[0], values_matrix_size);

        KERNEL_CALL(gEncodeUnsignedUtil, slots_)(
            values_matrix_device.get(),
            slots_, values_matrix_size, destination.data(),
            matrix_reps_index_map_.get()
        );

        kernel_util::kInverseNttNegacyclicHarvey(
            destination.data(),
            1, 1, getPowerOfTwo(slots_), context_data.plainNTTTables()
        );
    }





    __global__ void gEncodeSignedUtil(
        const int64_t* values_matrix,
        size_t slots, 
        size_t values_matrix_size,
        uint64_t* destination,
        const uint64_t* matrix_reps_index_map,
        uint64_t modulus
    ) {
        GET_INDEX_COND_RETURN(slots);
        destination[matrix_reps_index_map[gindex]] = 
            (gindex < values_matrix_size)
            ? (
                (values_matrix[gindex] < 0) 
                ? (modulus + static_cast<uint64_t>(values_matrix[gindex]))
                : static_cast<uint64_t>(values_matrix[gindex])
            )
            : 0;
    }

    void BatchEncoderCuda::encode(const vector<int64_t> &values_matrix, PlaintextCuda &destination) const
    {
        auto &context_data = *context_.firstContextData();
        uint64_t modulus = context_data.parms().plainModulus().value();

        // Validate input parameters
        size_t values_matrix_size = values_matrix.size();
        if (values_matrix_size > slots_)
        {
            throw invalid_argument("values_matrix size is too large");
        }
        // Set destination to full size
        destination.resize(slots_);
        destination.parmsID() = parmsIDZero;
        
        DeviceArray<int64_t> values_matrix_device(values_matrix_size);
        KernelProvider::copy(values_matrix_device.get(), &values_matrix[0], values_matrix_size);

        KERNEL_CALL(gEncodeSignedUtil, slots_)(
            values_matrix_device.get(),
            slots_, values_matrix_size, destination.data(),
            matrix_reps_index_map_.get(), modulus
        );

        kernel_util::kInverseNttNegacyclicHarvey(
            destination.data(),
            1, 1, getPowerOfTwo(slots_), context_data.plainNTTTables()
        );
    }

    void BatchEncoderCuda::encodePolynomial(const std::vector<std::uint64_t>& values, PlaintextCuda& destination) const {

        auto &context_data = *context_.firstContextData();
        uint64_t modulus = context_data.parms().plainModulus().value();

        // Validate input parameters
        size_t values_matrix_size = values.size();
        if (values_matrix_size > slots_)
        {
            throw invalid_argument("values_matrix size is too large");
        }
        // Set destination to full size
        destination.resize(values_matrix_size);
        destination.parmsID() = parmsIDZero;
        
        HostArray<uint64_t> vs(values_matrix_size);
        for (size_t i = 0; i < values_matrix_size; i++) vs[i] = values[i] % modulus;
        // for (size_t i = values_matrix_size; i < slots_; i++) vs[i] = 0;

        KernelProvider::copy(destination.data(), vs.get(), values_matrix_size);
    }


    void BatchEncoderCuda::encodePolynomial(const std::vector<std::int64_t>& values, PlaintextCuda& destination) const {

        auto &context_data = *context_.firstContextData();
        uint64_t modulus = context_data.parms().plainModulus().value();

        // Validate input parameters
        size_t values_matrix_size = values.size();
        if (values_matrix_size > slots_)
        {
            throw invalid_argument("values_matrix size is too large");
        }
        // Set destination to full size
        destination.resize(slots_);
        destination.parmsID() = parmsIDZero;
        
        HostArray<uint64_t> vs(values_matrix_size);
        for (size_t i = 0; i < values_matrix_size; i++) {
            if (values[i] < 0) vs[i] = modulus - ((-values[i]) % modulus);
            else vs[i] = values[i] % modulus;
        }
        for (size_t i = values_matrix_size; i < slots_; i++) vs[i] = 0;

        KernelProvider::copy(destination.data(), vs.get(), slots_);
    }

    __global__ void gDecodeUnsignedUtil(
        const uint64_t* temp_dest,
        size_t slots, 
        uint64_t* destination,
        const uint64_t* matrix_reps_index_map
    ) {
        GET_INDEX_COND_RETURN(slots);
        destination[gindex] = temp_dest[matrix_reps_index_map[gindex]];
    }

    void BatchEncoderCuda::decode(const PlaintextCuda &plain, vector<uint64_t> &destination) const
    {
        if (plain.isNttForm())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }

        auto &context_data = *context_.firstContextData();

        // Set destination size
        destination.resize(slots_);

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeffCount(), slots_);

        DeviceArray<uint64_t> temp_dest(slots_);

        // Make a copy of poly
        kernel_util::kSetPolyArray(plain.data(), 1, 1, plain_coeff_count, temp_dest);
        kernel_util::kSetZeroPolyArray(1, 1, slots_ - plain_coeff_count, temp_dest + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        kernel_util::kNttNegacyclicHarvey(temp_dest.get(), 1, 1, getPowerOfTwo(slots_), context_data.plainNTTTables());

        DeviceArray<uint64_t> destination_device(slots_);
        KERNEL_CALL(gDecodeUnsignedUtil, slots_)(
            temp_dest.get(), slots_, destination_device.get(),
            matrix_reps_index_map_.get()
        );

        KernelProvider::retrieve(destination.data(), destination_device.get(), slots_);
    }



    __global__ void gDecodeSignedUtil(
        const uint64_t* temp_dest,
        size_t slots, 
        int64_t* destination,
        const uint64_t* matrix_reps_index_map,
        uint64_t modulus
    ) {
        GET_INDEX_COND_RETURN(slots);
        uint64_t plain_modulus_div_two = modulus >> 1;
        uint64_t value = temp_dest[matrix_reps_index_map[gindex]];
        destination[gindex] = (value > plain_modulus_div_two)
            ?  (static_cast<int64_t>(value) - static_cast<int64_t>(modulus))
            : static_cast<int64_t>(value);
    }

    void BatchEncoderCuda::decode(const PlaintextCuda &plain, vector<int64_t> &destination) const
    {
        if (plain.isNttForm())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }

        auto &context_data = *context_.firstContextData();

        // Set destination size
        destination.resize(slots_);

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeffCount(), slots_);

        DeviceArray<uint64_t> temp_dest(slots_);

        // Make a copy of poly
        kernel_util::kSetPolyArray(plain.data(), 1, 1, plain_coeff_count, temp_dest);
        kernel_util::kSetZeroPolyArray(1, 1, slots_ - plain_coeff_count, temp_dest + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        kernel_util::kNttNegacyclicHarvey(temp_dest.get(), 1, 1, getPowerOfTwo(slots_), context_data.plainNTTTables());

        uint64_t modulus = context_data.parms().plainModulus().value();

        DeviceArray<int64_t> destination_device(slots_);
        KERNEL_CALL(gDecodeSignedUtil, slots_)(
            temp_dest.get(), slots_, destination_device.get(),
            matrix_reps_index_map_.get(), modulus
        );

        KernelProvider::retrieve(destination.data(), destination_device.get(), slots_);
    }

    void BatchEncoderCuda::decodePolynomial(const PlaintextCuda& plain, std::vector<std::uint64_t>& destination) const {
        destination.resize(slots_);
        KernelProvider::retrieve(destination.data(), plain.data(), slots_);
    }

    void BatchEncoderCuda::decodePolynomial(const PlaintextCuda& plain, std::vector<std::int64_t>& destination) const {
        destination.resize(slots_);
        std::vector<std::uint64_t> r(slots_);
        KernelProvider::retrieve(r.data(), plain.data(), slots_);

        auto &context_data = *context_.firstContextData();
        uint64_t modulus = context_data.parms().plainModulus().value();
        uint64_t half = modulus >> 1;
        
        for (size_t i = 0; i < slots_; i++) {
            if (r[i] > half) destination[i] = r[i] - modulus;
            else destination[i] = r[i];
        }
    }

}