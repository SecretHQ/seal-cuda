// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "scalingvariant_cuda.cuh"
#include "../kernelutils.cuh"

#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

using namespace std;

namespace troy
{
    namespace util
    {

        __global__ void gAddPlainWithoutScalingVariant(
            const uint64_t* plain_data,
            size_t plain_coeff_count,
            size_t coeff_count,
            size_t coeff_modulus_size,
            const Modulus* coeff_modulus,
            uint64_t* destination
        ) {
            GET_INDEX_COND_RETURN(plain_coeff_count);
            FOR_N(i, coeff_modulus_size) {
                uint64_t m = kernel_util::dBarrettReduce64(plain_data[gindex], coeff_modulus[i]);
                destination[i * coeff_count + gindex] = kernel_util::dAddUintMod(destination[i * coeff_count + gindex], m, coeff_modulus[i]);
            }
        }

        void addPlainWithoutScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            const size_t plain_coeff_count = plain.coeffCount();
            size_t coeff_count = parms.polyModulusDegree();
            const size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_data = plain.data();
            KERNEL_CALL(gAddPlainWithoutScalingVariant, plain_coeff_count)(
                plain_data, plain_coeff_count, coeff_count, coeff_modulus_size,
                coeff_modulus.get(), destination.get()
            );
        }
        

        __global__ void gSubPlainWithoutScalingVariant(
            const uint64_t* plain_data,
            size_t plain_coeff_count,
            size_t coeff_count,
            size_t coeff_modulus_size,
            const Modulus* coeff_modulus,
            uint64_t* destination
        ) {
            GET_INDEX_COND_RETURN(plain_coeff_count);
            FOR_N(i, coeff_modulus_size) {
                uint64_t m = kernel_util::dBarrettReduce64(plain_data[gindex], coeff_modulus[i]);
                destination[i * coeff_count + gindex] = kernel_util::dSubUintMod(destination[i * coeff_count + gindex], m, coeff_modulus[i]);
            }
        }

        void subPlainWithoutScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            const size_t plain_coeff_count = plain.coeffCount();
            size_t coeff_count = parms.polyModulusDegree();
            const size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_data = plain.data();
            KERNEL_CALL(gSubPlainWithoutScalingVariant, plain_coeff_count)(
                plain_data, plain_coeff_count, coeff_count, coeff_modulus_size,
                coeff_modulus.get(), destination.get()
            );
        }

        __global__ void gMultiplyAddPlainWithScalingVariant(
            const uint64_t* plain_data,
            size_t plain_coeff_count,
            size_t coeff_count,
            uint64_t plain_modulus_value,
            uint64_t plain_upper_half_threshold,
            size_t coeff_modulus_size,
            const Modulus* coeff_modulus,
            const MultiplyUIntModOperand* coeff_div_plain_modulus,
            uint64_t q_mod_t,
            uint64_t* destination
        ) {
            GET_INDEX_COND_RETURN(plain_coeff_count);
            uint64_t prod[2]{ 0, 0 };
            uint64_t numerator[2]{ 0, 0 };
            kernel_util::dMultiplyUint64(plain_data[gindex], q_mod_t, prod);
            unsigned char carry = kernel_util::dAddUint64(*prod, plain_upper_half_threshold, numerator);
            numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

            uint64_t fix[2] = { 0, 0 };
            kernel_util::dDivideUint128Inplace(numerator, plain_modulus_value, fix);

            for (size_t j = 0; j < coeff_modulus_size; j++) {
                uint64_t scaled_rounded_coeff = kernel_util::dMultiplyAddUintMod(plain_data[gindex], coeff_div_plain_modulus[j], fix[0], coeff_modulus[j]);
                destination[j * coeff_count + gindex] = kernel_util::dAddUintMod(destination[j * coeff_count + gindex], scaled_rounded_coeff, coeff_modulus[j]);
            }
        }

        void multiplyAddPlainWithScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination)
        {
            auto &parms = context_data.parms();
            size_t plain_coeff_count = plain.coeffCount();
            size_t coeff_count = parms.polyModulusDegree();
            auto &coeff_modulus = parms.coeffModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plainModulus();
            auto coeff_div_plain_modulus = context_data.coeffDivPlainModulus();
            uint64_t plain_upper_half_threshold = context_data.plainUpperHalfThreshold();
            uint64_t q_mod_t = context_data.coeffModulusModPlainModulus();
            auto plain_data = plain.data();
            KERNEL_CALL(gMultiplyAddPlainWithScalingVariant, plain_coeff_count)(
                plain_data, plain_coeff_count, coeff_count,
                plain_modulus.value(), plain_upper_half_threshold, coeff_modulus_size,
                coeff_modulus.get(), coeff_div_plain_modulus.get(), q_mod_t, destination.get()
            );
        }

        __global__ void gMultiplySubPlainWithScalingVariant(
            const uint64_t* plain_data,
            size_t plain_coeff_count,
            size_t coeff_count,
            uint64_t plain_modulus_value,
            uint64_t plain_upper_half_threshold,
            size_t coeff_modulus_size,
            const Modulus* coeff_modulus,
            const MultiplyUIntModOperand* coeff_div_plain_modulus,
            uint64_t q_mod_t,
            uint64_t* destination
        ) {
            GET_INDEX_COND_RETURN(plain_coeff_count);
            uint64_t prod[2]{ 0, 0 };
            uint64_t numerator[2]{ 0, 0 };
            kernel_util::dMultiplyUint64(plain_data[gindex], q_mod_t, prod);
            unsigned char carry = kernel_util::dAddUint64(*prod, plain_upper_half_threshold, numerator);
            numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

            uint64_t fix[2] = { 0, 0 };
            kernel_util::dDivideUint128Inplace(numerator, plain_modulus_value, fix);

            for (size_t j = 0; j < coeff_modulus_size; j++) {
                uint64_t scaled_rounded_coeff = kernel_util::dMultiplyAddUintMod(plain_data[gindex], coeff_div_plain_modulus[j], fix[0], coeff_modulus[j]);
                destination[j * coeff_count + gindex] = kernel_util::dSubUintMod(destination[j * coeff_count + gindex], scaled_rounded_coeff, coeff_modulus[j]);
            }
        }

        void multiplySubPlainWithScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination)
        {
            auto &parms = context_data.parms();
            size_t plain_coeff_count = plain.coeffCount();
            size_t coeff_count = parms.polyModulusDegree();
            auto &coeff_modulus = parms.coeffModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plainModulus();
            auto coeff_div_plain_modulus = context_data.coeffDivPlainModulus();
            uint64_t plain_upper_half_threshold = context_data.plainUpperHalfThreshold();
            uint64_t q_mod_t = context_data.coeffModulusModPlainModulus();
            auto plain_data = plain.data();
            KERNEL_CALL(gMultiplySubPlainWithScalingVariant, plain_coeff_count)(
                plain_data, plain_coeff_count, coeff_count,
                plain_modulus.value(), plain_upper_half_threshold, coeff_modulus_size,
                coeff_modulus.get(), coeff_div_plain_modulus.get(), q_mod_t, destination.get()
            );
        }
    } // namespace util
} // namespace seal
