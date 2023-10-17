#pragma once

#include "kernelprovider.cuh"
#include "utils/devicearray.cuh"
#include "utils/hostarray.h"
#include "utils/uintarithsmallmod.h"
#include "utils/ntt_cuda.cuh"
#include "modulus.h"

#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree

namespace troy {

    // static class. use as namespace
    class DeviceHelper {
    public:
        __device__ inline static uint64_t getModulusValue(const Modulus& m) {
            return m.value_;
        }
        __device__ inline static const uint64_t* getModulusConstRatio(const Modulus& m) {
            return static_cast<const uint64_t*>(&m.const_ratio_[0]);
        }
    };
    
    namespace kernel_util {

        using troy::util::ConstDevicePointer;
        using troy::util::DevicePointer;
        using CPointer = ConstDevicePointer<uint64_t>;
        using Pointer = DevicePointer<uint64_t>;
        using MPointer = ConstDevicePointer<Modulus>;
        using troy::util::MultiplyUIntModOperand;
        using uint128_t = unsigned __int128;
        using troy::util::NTTTablesCuda;

        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s) {
            return util::DeviceArray<uint64_t>(s);
        }
        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s, uint64_t t) {
            return util::DeviceArray<uint64_t>(s*t);
        }
        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s, uint64_t t, uint64_t u) {
            return util::DeviceArray<uint64_t>(s*t*u);
        }

        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s) {
            auto ret = util::DeviceArray<uint64_t>(s);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }
        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s, uint64_t t) {
            auto ret = util::DeviceArray<uint64_t>(s*t);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }
        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s, uint64_t t, uint64_t u) {
            auto ret = util::DeviceArray<uint64_t>(s*t*u);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }
        











        inline size_t ceilDiv_(size_t a, size_t b) {
            return (a%b) ? (a/b+1) : (a/b); 
        }

        __device__ inline unsigned char dAddUint64(uint64_t operand1, uint64_t operand2, unsigned char carry, uint64_t *result) {
            operand1 += operand2;
            *result = operand1 + carry;
            return (operand1 < operand2) || (~operand1 < carry);
        }

        __device__ inline unsigned char dAddUint64(uint64_t operand1, uint64_t operand2, uint64_t* result) {
            *result = operand1 + operand2;
            return static_cast<unsigned char>(*result < operand1);
        }

        __device__ inline unsigned char dAddUint128(uint64_t* operand1, uint64_t* operand2, uint64_t* result) {
            unsigned char carry = dAddUint64(operand1[0], operand2[0], result);
            return dAddUint64(operand1[1], operand2[1], carry, result + 1);
        }


        __device__ inline void dMultiplyUint64HW64(uint64_t operand1, uint64_t operand2, uint64_t *hw64) {                                                         
            *hw64 = static_cast<uint64_t>( 
                ((static_cast<uint128_t>(operand1) * static_cast<uint128_t>(operand2)) >> 64)); 
        }

        __device__ inline uint64_t dBarrettReduce64(uint64_t input, const Modulus& modulus) {
            uint64_t tmp[2];
            const std::uint64_t *const_ratio = DeviceHelper::getModulusConstRatio(modulus);
            dMultiplyUint64HW64(input, const_ratio[1], tmp + 1);
            uint64_t modulusValue = DeviceHelper::getModulusValue(modulus);

            // Barrett subtraction
            tmp[0] = input - tmp[1] * modulusValue;

            // One more subtraction is enough
            return (tmp[0] >= modulusValue) ? (tmp[0] - modulusValue) : (tmp[0]);
        }
        

        __device__ inline void dMultiplyUint64(uint64_t operand1, uint64_t operand2, uint64_t *result128)
        {        
            uint128_t product = static_cast<uint128_t>(operand1) * operand2; 
            result128[0] = static_cast<unsigned long long>(product);         
            result128[1] = static_cast<unsigned long long>(product >> 64); 
        }

        __device__ inline uint64_t dMultiplyUintMod(uint64_t x, const MultiplyUIntModOperand& y, const Modulus& modulus) {
            uint64_t tmp1, tmp2;
            const std::uint64_t p = DeviceHelper::getModulusValue(modulus);
            dMultiplyUint64HW64(x, y.quotient, &tmp1);
            tmp2 = y.operand * x - tmp1 * p;
            return (tmp2 >= p) ? (tmp2 - p) : (tmp2);
        }


        __device__ inline std::uint64_t dMultiplyUintModLazy(
            std::uint64_t x, const MultiplyUIntModOperand& y, const Modulus &modulus)
        {
            uint64_t tmp1;
            const std::uint64_t p = DeviceHelper::getModulusValue(modulus);
            dMultiplyUint64HW64(x, y.quotient, &tmp1);
            return y.operand * x - tmp1 * p;
        }
        
        __device__ inline void dDivideUint128Inplace(uint64_t *numerator, uint64_t denominator, uint64_t *quotient)
        {        
            uint128_t n, q;                                                                            
            n = (static_cast<uint128_t>(numerator[1]) << 64) | (static_cast<uint128_t>(numerator[0])); 
            q = n / denominator;                                                                       
            n -= q * denominator;                                                                      
            numerator[0] = static_cast<std::uint64_t>(n);                                              
            numerator[1] = 0;                                                                          
            quotient[0] = static_cast<std::uint64_t>(q);                                                 
            quotient[1] = static_cast<std::uint64_t>(q >> 64);     
        }
        
        __device__ inline unsigned char dSubUint64(uint64_t operand1, uint64_t operand2, uint64_t* result) {
            *result = operand1 - operand2;
            return static_cast<unsigned char>(operand2 > operand1);
        }

        __device__ inline unsigned char dSubUint64(uint64_t operand1, uint64_t operand2, unsigned char borrow, uint64_t* result) {
            auto diff = operand1 - operand2;
            *result = diff - (borrow != 0);
            return (diff > operand1) || (diff < borrow);
        }

        __device__ inline uint64_t dBarrettReduce128(const uint64_t *input, const Modulus &modulus)
        {
            // Reduces input using base 2^64 Barrett reduction
            // input allocation size must be 128 bits

            uint64_t tmp1, tmp2[2], tmp3, carry;
            const std::uint64_t *const_ratio = DeviceHelper::getModulusConstRatio(modulus);

            // Multiply input and const_ratio
            // Round 1
            dMultiplyUint64HW64(input[0], const_ratio[0], &carry);

            dMultiplyUint64(input[0], const_ratio[1], tmp2);
            tmp3 = tmp2[1] + dAddUint64(tmp2[0], carry, &tmp1);

            // Round 2
            dMultiplyUint64(input[1], const_ratio[0], tmp2);
            carry = tmp2[1] + dAddUint64(tmp1, tmp2[0], &tmp1);

            // This is all we care about
            tmp1 = input[1] * const_ratio[1] + tmp3 + carry;

            // Barrett subtraction
            uint64_t modulus_value = DeviceHelper::getModulusValue(modulus);
            tmp3 = input[0] - tmp1 * modulus_value;

            // One more subtraction is enough
            return (tmp3 >= modulus_value) ? (tmp3 - modulus_value): (tmp3);
        }

        
        __device__ inline std::uint64_t dModuloUint(
            const std::uint64_t *value, std::size_t value_uint64_count, const Modulus &modulus)
        {
            if (value_uint64_count == 1)
            {
                // If value < modulus no operation is needed
                if (*value < DeviceHelper::getModulusValue(modulus))
                    return *value;
                else
                    return dBarrettReduce64(*value, modulus);
            }

            // Temporary space for 128-bit reductions
            uint64_t temp[2]{ 0, value[value_uint64_count - 1] };
            for (size_t k = value_uint64_count - 1; k--;)
            {
                temp[0] = value[k];
                temp[1] = dBarrettReduce128(temp, modulus);
            }

            // Save the result modulo i-th prime
            return temp[1];
        }


        __device__ inline void dMultiplyUint(
            const uint64_t *operand1, size_t operand1_uint64_count, uint64_t operand2, size_t result_uint64_count,
            uint64_t *result)
        {
            // Handle fast cases.
            if (!operand1_uint64_count || !operand2)
            {
                // If either operand is 0, then result is 0.
                for (size_t i = 0; i < result_uint64_count; i++) result[i] = 0;
                return;
            }
            if (result_uint64_count == 1)
            {
                *result = *operand1 * operand2;
                return;
            }

            // Clear out result.
            for (size_t i = 0; i < result_uint64_count; i++) result[i] = 0;

            // Multiply operand1 and operand2.
            uint64_t carry = 0;
            size_t operand1_index_max = min(operand1_uint64_count, result_uint64_count);
            for (size_t operand1_index = 0; operand1_index < operand1_index_max; operand1_index++)
            {
                uint64_t temp_result[2];
                dMultiplyUint64(*operand1++, operand2, temp_result);
                uint64_t temp;
                carry = temp_result[1] + dAddUint64(temp_result[0], carry, 0, &temp);
                *result++ = temp;
            }

            // Write carry if there is room in result
            if (operand1_index_max < result_uint64_count)
            {
                *result = carry;
            }
        }

        __device__ inline unsigned char dAddUint(const uint64_t* operand1, const uint64_t* operand2, std::size_t uint64Count, uint64_t* result) {
            // Unroll first iteration of loop. We assume uint64_count > 0.
            unsigned char carry = dAddUint64(*operand1++, *operand2++, result++);

            // Do the rest
            for (; --uint64Count; operand1++, operand2++, result++) {
                uint64_t temp_result;
                carry = dAddUint64(*operand1, *operand2, carry, &temp_result);
                *result = temp_result;
            }
            return carry;
        }

        __device__ inline int dCompareUint(
            const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count)
        {
            int result = 0;
            operand1 += uint64_count - 1;
            operand2 += uint64_count - 1;

            for (; (result == 0) && uint64_count--; operand1--, operand2--)
            {
                result = (*operand1 > *operand2) - (*operand1 < *operand2);
            }
            return result;
        }

        __device__ inline bool dIsGreaterThanOrEqualUint(
            const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count)
        {
            return dCompareUint(operand1, operand2, uint64_count) >= 0;
        }

        __device__ inline unsigned char dSubUint(
            const uint64_t* operand1, const uint64_t* operand2,
            std::size_t uint64Count, uint64_t* result
        ) {
            // Unroll first iteration of loop. We assume uint64_count > 0.
            unsigned char borrow = dSubUint64(*operand1++, *operand2++, result++);

            // Do the rest
            for (; --uint64Count; operand1++, operand2++, result++)
            {
                uint64_t temp_result;
                borrow = dSubUint64(*operand1, *operand2, borrow, &temp_result);
                *result = temp_result;
            }
            return borrow;
        }

        __device__ inline void dAddUintUintMod(
            const std::uint64_t *operand1, const std::uint64_t *operand2, const std::uint64_t *modulus,
            std::size_t uint64_count, std::uint64_t *result)
        {
            unsigned char carry = dAddUint(operand1, operand2, uint64_count, result);
            if (carry || dIsGreaterThanOrEqualUint(result, modulus, uint64_count))
            {
                dSubUint(result, modulus, uint64_count, result);
            }
        }

        __device__ inline uint64_t dDotProductMod(
            const uint64_t *operand1, const uint64_t *operand2, size_t count, const Modulus &modulus)
        {
            static_assert(SEAL_MULTIPLY_ACCUMULATE_MOD_MAX >= 16, "SEAL_MULTIPLY_ACCUMULATE_MOD_MAX");
            uint64_t accumulator[2]{ 0, 0 };
            uint64_t qword[2];
            for (size_t i = 0; i < count; i++) {
                dMultiplyUint64(operand1[i], operand2[i], qword);
                dAddUint128(qword, accumulator, accumulator);
                accumulator[0] = dBarrettReduce128(accumulator, modulus);
                accumulator[1] = 0;
            }
            return accumulator[0];
        }

        
        __device__ inline unsigned char dSubUint64(
            uint64_t operand1, uint64_t operand2, unsigned char borrow, unsigned long long *result)
        {
            auto diff = operand1 - operand2;
            *result = diff - (borrow != 0);
            return (diff > operand1) || (diff < borrow);
        }

        __device__ inline uint64_t dSubUintMod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
            unsigned long long temp;
            int64_t borrow = static_cast<std::int64_t>(dSubUint64(operand1, operand2, 0, &temp));
            return static_cast<std::uint64_t>(temp) + (DeviceHelper::getModulusValue(modulus) & static_cast<std::uint64_t>(-borrow));
        }

        __device__ inline std::uint64_t dMultiplyUintMod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
            uint64_t z[2];
            dMultiplyUint64(operand1, operand2, z);
            return dBarrettReduce128(z, modulus);
        }

        __device__ inline std::uint64_t dAddUintMod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
            // Sum of operands modulo Modulus can never wrap around 2^64
            operand1 += operand2;
            uint64_t modulus_value = DeviceHelper::getModulusValue(modulus);
            return (operand1 >= modulus_value) ? (operand1 - modulus_value) : (operand1);
        }

        __device__ inline MultiplyUIntModOperand dSetMultiplyModOperand(uint64_t operand, const Modulus& modulus) {
            MultiplyUIntModOperand ret;
            ret.operand = operand;
            std::uint64_t wide_quotient[2]{ 0, 0 };
            std::uint64_t wide_coeff[2]{ 0, operand };
            dDivideUint128Inplace(wide_coeff, DeviceHelper::getModulusValue(modulus), wide_quotient);
            ret.quotient = wide_quotient[0];
            return ret;
        }


        __device__ inline std::uint64_t dMultiplyAddUintMod(
            std::uint64_t operand1, const MultiplyUIntModOperand& operand2, std::uint64_t operand3, const Modulus &modulus)
        {
            return dAddUintMod(
                dMultiplyUintMod(operand1, operand2, modulus), dBarrettReduce64(operand3, modulus), modulus);
            
            // uint64_t tmp1, tmp2;
            // const std::uint64_t p = DeviceHelper::getModulusValue(modulus);
            // dMultiplyUint64HW64(x, y.quotient, &tmp1);
            // // printf("%llu, %llu, %llu\n");
            // printf("%llu\n", x);
            // tmp2 = 0;
            // return 0;
        }

        __device__ inline std::uint64_t dNegateUintMod(std::uint64_t operand, const Modulus &modulus)
        {
            std::int64_t non_zero = static_cast<std::int64_t>(operand != 0);
            return (DeviceHelper::getModulusValue(modulus) - operand) & static_cast<std::uint64_t>(-non_zero);
        }

        __device__ inline uint64_t dMultiplyScalarMod(uint64_t operand, std::uint64_t scalar, const Modulus &modulus)
        {
            // Scalar must be first reduced modulo modulus
            MultiplyUIntModOperand temp_scalar 
                = dSetMultiplyModOperand(dBarrettReduce64(scalar, modulus), modulus);
            return dMultiplyUintMod(operand, temp_scalar, modulus);
        }

        __device__ inline unsigned char dAddUint(
            const uint64_t* operand1, std::size_t uint64Count,
            uint64_t operand2, uint64_t* result
        ) {
                // Unroll first iteration of loop. We assume uint64_count > 0.
                unsigned char carry = dAddUint64(*operand1++, operand2, result++);

                // Do the rest
                for (; --uint64Count; operand1++, result++)
                {
                    uint64_t temp_result;
                    carry = dAddUint64(*operand1, uint64_t(0), carry, &temp_result);
                    *result = temp_result;
                }
                return carry;
        }
















        
        
        __global__ void gAddPolyCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t* result
        );

        void kAddPolyCoeffmod(
            CPointer operand1,
            CPointer operand2,
            POLY_ARRAY_ARGUMENTS,
            MPointer modulus,
            Pointer result
        );

        __global__ void gDyadicConvolutionCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2_reversed,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* moduli,
            uint64_t* single_poly_result_accumulator
        );

        void kDyadicConvolutionCoeffmod(
            CPointer operand1,
            CPointer operand2_reversed,
            POLY_ARRAY_ARGUMENTS,
            MPointer moduli,
            Pointer single_poly_result_accumulator
        );

        __global__ void gDyadicProductCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* moduli,
            uint64_t* output
        );

        void kDyadicProductCoeffmod(
            CPointer operand1,
            CPointer operand2,
            POLY_ARRAY_ARGUMENTS,
            MPointer moduli,
            Pointer output
        );

        __global__ void gDyadicSquareCoeffmod(
            const uint64_t* operand,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            const Modulus* moduli,
            uint64_t* output
        );

        void kDyadicSquareCoeffmod(
            CPointer operand,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            MPointer moduli,
            Pointer output
        );
        

        inline void kDyadicSquareCoeffmod(
            Pointer operand,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            MPointer moduli
        ) {
            kDyadicSquareCoeffmod(operand, coeff_modulus_size, poly_modulus_degree,
                moduli, operand);
        }

        __global__ void gModBoundedUsingNttTables(
            uint64_t* operand,
            POLY_ARRAY_ARGUMENTS,
            const NTTTablesCuda* ntt_tables);

        void kModBoundedUsingNttTables(
            Pointer operand,
            POLY_ARRAY_ARGUMENTS,
            ConstDevicePointer<NTTTablesCuda> ntt_tables);

        __global__ void gModuloPolyCoeffs(
            const uint64_t* operand,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* moduli,
            uint64_t* result
        );

        void kModuloPolyCoeffs(
            CPointer operand,
            POLY_ARRAY_ARGUMENTS,
            MPointer moduli,
            Pointer result
        );
        
        __global__ void gMultiplyPolyScalarCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const MultiplyUIntModOperand* reduced_scalar,
            const Modulus* modulus,
            uint64_t* result);

        void kMultiplyPolyScalarCoeffmod(
            CPointer poly_array, POLY_ARRAY_ARGUMENTS, 
            uint64_t scalar, MPointer modulus, Pointer result);

        __global__ void gNegatePolyCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t *result
        );

        void kNegatePolyCoeffmod(
            CPointer poly_array, POLY_ARRAY_ARGUMENTS,
            MPointer modulus, Pointer result
        );

        void kNttTransferToRev(
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables,
            bool use_inv_root_powers);

        void kNttTransferFromRev(
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables,
            bool use_inv_root_powers);

        inline void kNttNegacyclicHarveyLazy(
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables)
        {
            kNttTransferToRev(operand, poly_size, coeff_modulus_size,
                poly_modulus_degree_power, ntt_tables, false);
        }

        inline void kNttNegacyclicHarvey(
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables)
        {
            kNttNegacyclicHarveyLazy(
                operand, poly_size, coeff_modulus_size,
                poly_modulus_degree_power, ntt_tables
            );
            kModBoundedUsingNttTables(
                operand, poly_size, coeff_modulus_size,
                1 << poly_modulus_degree_power, ntt_tables);
        }



        inline void kInverseNttNegacyclicHarveyLazy(
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables)
        {
            kNttTransferFromRev(operand, poly_size, coeff_modulus_size,
                poly_modulus_degree_power, ntt_tables, true);
        }

        inline void kInverseNttNegacyclicHarvey(
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables)
        {
            kInverseNttNegacyclicHarveyLazy(
                operand, poly_size, coeff_modulus_size,
                poly_modulus_degree_power, ntt_tables
            );
            kModBoundedUsingNttTables(
                operand, poly_size, coeff_modulus_size,
                1 << poly_modulus_degree_power, ntt_tables);
        }

        __global__ void gNttTransferToRevLayered(
            size_t layer,
            uint64_t* operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            const NTTTablesCuda* ntt_tables ,
            bool use_inv_root_powers
        );

        void kNttTransferToRevLayered(
            size_t layer,
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables,
            bool use_inv_root_powers
        );

        __global__ void gNttTransferFromRevLayered(
            size_t layer,
            uint64_t* operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            const NTTTablesCuda* ntt_tables ,
            bool use_inv_root_powers
        );

        void kNttTransferFromRevLayered(
            size_t layer,
            Pointer operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            ConstDevicePointer<NTTTablesCuda> ntt_tables,
            bool use_inv_root_powers
        );

        __global__ void gSetMultiplyUIntModOperand(
            uint64_t scalar, const Modulus* moduli, size_t n,
            MultiplyUIntModOperand* result);

        
        inline void kSetPolyArray(
            CPointer poly, POLY_ARRAY_ARGUMENTS, Pointer result
        ) {
            KernelProvider::copyOnDevice(
                result.get(), poly.get(), 
                poly_size * coeff_modulus_size * poly_modulus_degree
            );
        }

        inline void kSetZeroPolyArray(POLY_ARRAY_ARGUMENTS, Pointer result) {
            KernelProvider::memsetZero(result.get(), poly_size * poly_modulus_degree * coeff_modulus_size);
        }
        
        __global__ void gSubPolyCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t* result
        );

        void kSubPolyCoeffmod(
            CPointer operand1,
            CPointer operand2,
            POLY_ARRAY_ARGUMENTS,
            MPointer modulus,
            Pointer result
        );

    }
}

#undef POLY_ARRAY_ARGUMENTS