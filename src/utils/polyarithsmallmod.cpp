// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "polyarithsmallmod.h"
#include "uintarith.h"
#include "uintcore.h"


namespace troy
{
    namespace util
    {
        void moduloPolyCoeffs(ConstHostPointer<uint64_t> poly, std::size_t coeff_count, const Modulus &modulus, HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_count; i++) {
                result[i] = barrettReduce64(poly[i], modulus);
            }
        }

        void addPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_count, const Modulus &modulus,
            HostPointer<uint64_t> result)
        {
            const uint64_t modulusValue = modulus.value();
            for (std::size_t i = 0; i < coeff_count; i++) {
                std::uint64_t sum = operand1[i] + operand2[i];
                result[i] = sum >= modulusValue ? sum-modulusValue : sum;
            }
        }

        void subPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_count, const Modulus &modulus,
            HostPointer<uint64_t> result)
        {
            const uint64_t modulus_value = modulus.value();
            for (std::size_t i = 0; i < coeff_count; i++) {
                uint64_t temp_result;
                std::int64_t borrow = subUint64(operand1[i], operand2[i], &temp_result);
                result[i] = temp_result + (modulus_value & static_cast<std::uint64_t>(-borrow));
            }
        }

        void addPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, size_t coeff_count, uint64_t scalar, const Modulus &modulus, HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_count; i++) {
                const uint64_t x = poly[i];
                result[i] = addUintMod(x, scalar, modulus);
            }
        }

        void subPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, size_t coeff_count, uint64_t scalar, const Modulus &modulus, HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_count; i++) {
                const uint64_t x = poly[i];
                result[i] = subUintMod(x, scalar, modulus);
            }
        }

        void multiplyPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, size_t coeff_count, MultiplyUIntModOperand scalar, const Modulus &modulus,
            HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_count; i++) {
                const uint64_t x = poly[i];
                result[i] = multiplyUintMod(x, scalar, modulus);
            }
        }

        void dyadicProductCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, size_t coeff_count, const Modulus &modulus,
            HostPointer<uint64_t> result)
        {
            const uint64_t modulus_value = modulus.value();
            const uint64_t const_ratio_0 = modulus.constRatio()[0];
            const uint64_t const_ratio_1 = modulus.constRatio()[1];

            for (std::size_t i = 0; i < coeff_count; i++) {
                // Reduces z using base 2^64 Barrett reduction
                uint64_t z[2], tmp1, tmp2[2], tmp3, carry;
                multiplyUint64(operand1[i], operand2[i], z);

                // Multiply input and const_ratio
                // Round 1
                multiplyUint64HW64(z[0], const_ratio_0, &carry);
                multiplyUint64(z[0], const_ratio_1, tmp2);
                tmp3 = tmp2[1] + addUint64(tmp2[0], carry, &tmp1);

                // Round 2
                multiplyUint64(z[1], const_ratio_0, tmp2);
                carry = tmp2[1] + addUint64(tmp1, tmp2[0], &tmp1);

                // This is all we care about
                tmp1 = z[1] * const_ratio_1 + tmp3 + carry;

                // Barrett subtraction
                tmp3 = z[0] - tmp1 * modulus_value;

                // Claim: One more subtraction is enough
                result[i] = (tmp3 >= modulus_value) ? (tmp3 - modulus_value) : (tmp3);
            }
        }

        uint64_t polyInftyNormCoeffmod(HostPointer<uint64_t> operand, size_t coeff_count, const Modulus &modulus)
        {
            // Construct negative threshold (first negative modulus value) to compute absolute values of coeffs.
            uint64_t modulus_neg_threshold = (modulus.value() + 1) >> 1;

            // Mod out the poly coefficients and choose a symmetric representative from
            // [-modulus,modulus). Keep track of the max.
            uint64_t result = 0;
            for (std::size_t i = 0; i < coeff_count; i++) {
                uint64_t poly_coeff = barrettReduce64(operand[i], modulus);
                if (poly_coeff >= modulus_neg_threshold)
                {
                    poly_coeff = modulus.value() - poly_coeff;
                }
                if (poly_coeff > result)
                {
                    result = poly_coeff;
                }
            }

            return result;
        }

        void negacyclicShiftPolyCoeffmod(
            ConstHostPointer<uint64_t> poly, size_t coeff_count, size_t shift, const Modulus &modulus, HostPointer<uint64_t> result)
        {
            // Nothing to do
            if (shift == 0)
            {
                setUint(poly.get(), coeff_count, result.get());
                return;
            }

            uint64_t index_raw = shift;
            uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
            for (size_t i = 0; i < coeff_count; i++, index_raw++)
            {
                uint64_t index = index_raw & coeff_count_mod_mask;
                if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !poly[i])
                {
                    result[index] = poly[i];
                }
                else
                {
                    result[index] = modulus.value() - poly[i];
                }
            }
        }
    } // namespace util
} // namespace seal
