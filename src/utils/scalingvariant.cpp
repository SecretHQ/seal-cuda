// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../encryptor.h"
#include "polyarithsmallmod.h"
#include "scalingvariant.h"
#include "uintarith.h"
#include <iostream>
#include <iomanip>

using namespace std;

namespace troy
{
    namespace util
    {
        void addPlainWithoutScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            const size_t plain_coeff_count = plain.coeffCount();
            size_t coeff_count = parms.polyModulusDegree();
            const size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_data = plain.data();
            for (size_t i = 0; i < coeff_modulus_size; i++) {
            // SEAL_ITERATE(iter(destination, coeff_modulus), coeff_modulus_size, [&](auto I) {
                for (size_t j = 0; j < plain_coeff_count; j++) {
                    uint64_t m = barrettReduce64(plain_data[j], coeff_modulus[i]);
                    destination[i * coeff_count + j] = addUintMod(destination[i * coeff_count + j], m, coeff_modulus[i]);
                }
            }
        }

        void subPlainWithoutScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            const size_t plain_coeff_count = plain.coeffCount();
            size_t coeff_count = parms.polyModulusDegree();
            const size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_data = plain.data();
            for (size_t i = 0; i < coeff_modulus_size; i++) {
            // SEAL_ITERATE(iter(destination, coeff_modulus), coeff_modulus_size, [&](auto I) {
                for (size_t j = 0; j < plain_coeff_count; j++) {
                    uint64_t m = barrettReduce64(plain_data[j], coeff_modulus[i]);
                    destination[i * coeff_count + j] = subUintMod(destination[i * coeff_count + j], m, coeff_modulus[i]);
                }
            }
        }

        void multiplyAddPlainWithScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination)
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
            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            auto plain_data = plain.data();
            for (size_t i = 0; i < plain_coeff_count; i++) {
            // SEAL_ITERATE(iter(plain.data(), size_t(0)), plain_coeff_count, [&](auto I) {
                // Compute numerator = (q mod t) * m[i] + (t+1)/2
                uint64_t prod[2]{ 0, 0 };
                uint64_t numerator[2]{ 0, 0 };
                multiplyUint64(plain_data[i], q_mod_t, prod);
                unsigned char carry = addUint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

                // Compute fix[0] = floor(numerator / t)
                uint64_t fix[2] = { 0, 0 };
                divideUint128Inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                size_t coeff_index = i;
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    uint64_t scaled_rounded_coeff = multiplyAddUintMod(plain_data[i], coeff_div_plain_modulus[j], fix[0], coeff_modulus[j]);
                    // std::cout << destination[j * coeff_count + i] << std::endl;
                    destination[j * coeff_count + i] = addUintMod(destination[j * coeff_count + i], scaled_rounded_coeff, coeff_modulus[j]);
                    // std::cout << "troy " << i << "," << j << " d[" << (j * coeff_count + i) << "]=" 
                    //     << destination[j * coeff_count + i]  << std::endl;
                }
            }
        }

        void multiplySubPlainWithScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination)
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
            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            auto plain_data = plain.data();
            for (size_t i = 0; i < plain_coeff_count; i++) {
            // SEAL_ITERATE(iter(plain.data(), size_t(0)), plain_coeff_count, [&](auto I) {
                // Compute numerator = (q mod t) * m[i] + (t+1)/2
                uint64_t prod[2]{ 0, 0 };
                uint64_t numerator[2]{ 0, 0 };
                multiplyUint64(plain_data[i], q_mod_t, prod);
                unsigned char carry = addUint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

                // Compute fix[0] = floor(numerator / t)
                uint64_t fix[2] = { 0, 0 };
                divideUint128Inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                size_t coeff_index = i;
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    uint64_t scaled_rounded_coeff = multiplyAddUintMod(plain_data[i], coeff_div_plain_modulus[j], fix[0], coeff_modulus[j]);
                    destination[j * coeff_count + i] = subUintMod(destination[j * coeff_count + i], scaled_rounded_coeff, coeff_modulus[j]);
                }
            }
        }
    } // namespace util
} // namespace seal
