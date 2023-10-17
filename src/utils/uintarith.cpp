#include <algorithm>

#include "uintarith.h"
#include "hostarray.h"

using namespace std;

namespace troy {
    namespace util {
        void multiplyUint(
            const uint64_t *operand1, size_t operand1_uint64_count, const uint64_t *operand2,
            size_t operand2_uint64_count, size_t result_uint64_count, uint64_t *result)
        {
            // Handle fast cases.
            if (!operand1_uint64_count || !operand2_uint64_count)
            {
                // If either operand is 0, then result is 0.
                setZeroUint(result_uint64_count, result);
                return;
            }
            if (result_uint64_count == 1)
            {
                *result = *operand1 * *operand2;
                return;
            }

            // In some cases these improve performance.
            operand1_uint64_count = getSignificantUint64CountUint(operand1, operand1_uint64_count);
            operand2_uint64_count = getSignificantUint64CountUint(operand2, operand2_uint64_count);

            // More fast cases
            if (operand1_uint64_count == 1)
            {
                multiplyUint(operand2, operand2_uint64_count, *operand1, result_uint64_count, result);
                return;
            }
            if (operand2_uint64_count == 1)
            {
                multiplyUint(operand1, operand1_uint64_count, *operand2, result_uint64_count, result);
                return;
            }

            // Clear out result.
            setZeroUint(result_uint64_count, result);

            // Multiply operand1 and operand2.
            size_t operand1_index_max = min(operand1_uint64_count, result_uint64_count);
            for (size_t operand1_index = 0; operand1_index < operand1_index_max; operand1_index++)
            {
                const uint64_t *inner_operand2 = operand2;
                uint64_t *inner_result = result++;
                uint64_t carry = 0;
                size_t operand2_index = 0;
                size_t operand2_index_max = min(operand2_uint64_count, result_uint64_count - operand1_index);
                for (; operand2_index < operand2_index_max; operand2_index++)
                {
                    // Perform 64-bit multiplication of operand1 and operand2
                    uint64_t temp_result[2];
                    multiplyUint64(*operand1, *inner_operand2++, temp_result);
                    carry = temp_result[1] + addUint64(temp_result[0], carry, 0, temp_result);
                    uint64_t temp;
                    carry += addUint64(*inner_result, temp_result[0], 0, &temp);
                    *inner_result++ = temp;
                }

                // Write carry if there is room in result
                if (operand1_index + operand2_index_max < result_uint64_count)
                {
                    *inner_result = carry;
                }

                operand1++;
            }
        }

        void multiplyUint(
            const uint64_t *operand1, size_t operand1_uint64_count, uint64_t operand2, size_t result_uint64_count,
            uint64_t *result)
        {
            // Handle fast cases.
            if (!operand1_uint64_count || !operand2)
            {
                // If either operand is 0, then result is 0.
                setZeroUint(result_uint64_count, result);
                return;
            }
            if (result_uint64_count == 1)
            {
                *result = *operand1 * operand2;
                return;
            }

            // Clear out result.
            setZeroUint(result_uint64_count, result);

            // Multiply operand1 and operand2.
            uint64_t carry = 0;
            size_t operand1_index_max = min(operand1_uint64_count, result_uint64_count);
            for (size_t operand1_index = 0; operand1_index < operand1_index_max; operand1_index++)
            {
                uint64_t temp_result[2];
                multiplyUint64(*operand1++, operand2, temp_result);
                uint64_t temp;
                carry = temp_result[1] + addUint64(temp_result[0], carry, 0, &temp);
                *result++ = temp;
            }

            // Write carry if there is room in result
            if (operand1_index_max < result_uint64_count)
            {
                *result = carry;
            }
        }

        void divideUintInplace(
            uint64_t *numerator, const uint64_t *denominator, size_t uint64_count, uint64_t *quotient)
        {
            if (!uint64_count)
            {
                return;
            }

            // Clear quotient. Set it to zero.
            setZeroUint(uint64_count, quotient);

            // Determine significant bits in numerator and denominator.
            int numerator_bits = getSignificantBitCountUint(numerator, uint64_count);
            int denominator_bits = getSignificantBitCountUint(denominator, uint64_count);

            // If numerator has fewer bits than denominator, then done.
            if (numerator_bits < denominator_bits)
            {
                return;
            }

            // Only perform computation up to last non-zero uint64s.
            uint64_count = safe_cast<size_t>(divideRoundUp(numerator_bits, bitsPerUint64));

            // Handle fast case.
            if (uint64_count == 1)
            {
                *quotient = *numerator / *denominator;
                *numerator -= *quotient * *denominator;
                return;
            }

            // FIXME: allocate related action
            // Create temporary space to store mutable copy of denominator.
            uint64_t *shifted_denominator = new uint64_t[uint64_count<<1]();

            // Create temporary space to store difference calculation.
            uint64_t *difference = shifted_denominator + uint64_count;

            // Shift denominator to bring MSB in alignment with MSB of numerator.
            int denominator_shift = numerator_bits - denominator_bits;
            leftShiftUint(denominator, denominator_shift, uint64_count, shifted_denominator);
            denominator_bits += denominator_shift;

            // Perform bit-wise division algorithm.
            int remaining_shifts = denominator_shift;
            while (numerator_bits == denominator_bits)
            {
                // NOTE: MSBs of numerator and denominator are aligned.

                // Even though MSB of numerator and denominator are aligned,
                // still possible numerator < shifted_denominator.
                if (subUint(numerator, shifted_denominator, uint64_count, difference))
                {
                    // numerator < shifted_denominator and MSBs are aligned,
                    // so current quotient bit is zero and next one is definitely one.
                    if (remaining_shifts == 0)
                    {
                        // No shifts remain and numerator < denominator so done.
                        break;
                    }

                    // Effectively shift numerator left by 1 by instead adding
                    // numerator to difference (to prevent overflow in numerator).
                    addUint(difference, numerator, uint64_count, difference);

                    // Adjust quotient and remaining shifts as a result of
                    // shifting numerator.
                    leftShiftUint(quotient, 1, uint64_count, quotient);
                    remaining_shifts--;
                }
                // Difference is the new numerator with denominator subtracted.

                // Update quotient to reflect subtraction.
                quotient[0] |= 1;

                // Determine amount to shift numerator to bring MSB in alignment
                // with denominator.
                numerator_bits = getSignificantBitCountUint(difference, uint64_count);
                int numerator_shift = denominator_bits - numerator_bits;
                if (numerator_shift > remaining_shifts)
                {
                    // Clip the maximum shift to determine only the integer
                    // (as opposed to fractional) bits.
                    numerator_shift = remaining_shifts;
                }

                // Shift and update numerator.
                if (numerator_bits > 0)
                {
                    leftShiftUint(difference, numerator_shift, uint64_count, numerator);
                    numerator_bits += numerator_shift;
                }
                else
                {
                    // Difference is zero so no need to shift, just set to zero.
                    setZeroUint(uint64_count, numerator);
                }

                // Adjust quotient and remaining shifts as a result of shifting numerator.
                leftShiftUint(quotient, numerator_shift, uint64_count, quotient);
                remaining_shifts -= numerator_shift;
            }

            // Correct numerator (which is also the remainder) for shifting of
            // denominator, unless it is just zero.
            if (numerator_bits > 0)
            {
                rightShiftUint(numerator, denominator_shift, uint64_count, numerator);
            }
            
            delete[] shifted_denominator;
        }

        void divide_uint128_uint64_inplace_generic(uint64_t *numerator, uint64_t denominator, uint64_t *quotient)
        {
#ifdef SEAL_DEBUG
            if (!numerator)
            {
                throw invalid_argument("numerator");
            }
            if (denominator == 0)
            {
                throw invalid_argument("denominator");
            }
            if (!quotient)
            {
                throw invalid_argument("quotient");
            }
            if (numerator == quotient)
            {
                throw invalid_argument("quotient cannot point to same value as numerator");
            }
#endif
            // We expect 128-bit input
            constexpr size_t uint64_count = 2;

            // Clear quotient. Set it to zero.
            quotient[0] = 0;
            quotient[1] = 0;

            // Determine significant bits in numerator and denominator.
            int numerator_bits = getSignificantBitCountUint(numerator, uint64_count);
            int denominator_bits = getSignificantBitCount(denominator);

            // If numerator has fewer bits than denominator, then done.
            if (numerator_bits < denominator_bits)
            {
                return;
            }

            // Create temporary space to store mutable copy of denominator.
            uint64_t shifted_denominator[uint64_count]{ denominator, 0 };

            // Create temporary space to store difference calculation.
            uint64_t difference[uint64_count]{ 0, 0 };

            // Shift denominator to bring MSB in alignment with MSB of numerator.
            int denominator_shift = numerator_bits - denominator_bits;

            leftShiftUint128(shifted_denominator, denominator_shift, shifted_denominator);
            denominator_bits += denominator_shift;

            // Perform bit-wise division algorithm.
            int remaining_shifts = denominator_shift;
            while (numerator_bits == denominator_bits)
            {
                // NOTE: MSBs of numerator and denominator are aligned.

                // Even though MSB of numerator and denominator are aligned,
                // still possible numerator < shifted_denominator.
                if (subUint(numerator, shifted_denominator, uint64_count, difference))
                {
                    // numerator < shifted_denominator and MSBs are aligned,
                    // so current quotient bit is zero and next one is definitely one.
                    if (remaining_shifts == 0)
                    {
                        // No shifts remain and numerator < denominator so done.
                        break;
                    }

                    // Effectively shift numerator left by 1 by instead adding
                    // numerator to difference (to prevent overflow in numerator).
                    addUint(difference, numerator, uint64_count, difference);

                    // Adjust quotient and remaining shifts as a result of shifting numerator.
                    quotient[1] = (quotient[1] << 1) | (quotient[0] >> (bitsPerUint64 - 1));
                    quotient[0] <<= 1;
                    remaining_shifts--;
                }
                // Difference is the new numerator with denominator subtracted.

                // Determine amount to shift numerator to bring MSB in alignment
                // with denominator.
                numerator_bits = getSignificantBitCountUint(difference, uint64_count);

                // Clip the maximum shift to determine only the integer
                // (as opposed to fractional) bits.
                int numerator_shift = min(denominator_bits - numerator_bits, remaining_shifts);

                // Shift and update numerator.
                // This may be faster; first set to zero and then update if needed

                // Difference is zero so no need to shift, just set to zero.
                numerator[0] = 0;
                numerator[1] = 0;

                if (numerator_bits > 0)
                {
                    leftShiftUint128(difference, numerator_shift, numerator);
                    numerator_bits += numerator_shift;
                }

                // Update quotient to reflect subtraction.
                quotient[0] |= 1;

                // Adjust quotient and remaining shifts as a result of shifting numerator.
                leftShiftUint128(quotient, numerator_shift, quotient);
                remaining_shifts -= numerator_shift;
            }

            // Correct numerator (which is also the remainder) for shifting of
            // denominator, unless it is just zero.
            if (numerator_bits > 0)
            {
                rightShiftUint128(numerator, denominator_shift, numerator);
            }
        }

        void divideUint192Inplace(uint64_t *numerator, uint64_t denominator, uint64_t *quotient)
        {
            // We expect 192-bit input
            size_t uint64_count = 3;

            // Clear quotient. Set it to zero.
            quotient[0] = 0;
            quotient[1] = 0;
            quotient[2] = 0;

            // Determine significant bits in numerator and denominator.
            int numerator_bits = getSignificantBitCountUint(numerator, uint64_count);
            int denominator_bits = getSignificantBitCount(denominator);

            // If numerator has fewer bits than denominator, then done.
            if (numerator_bits < denominator_bits)
            {
                return;
            }

            // Only perform computation up to last non-zero uint64s.
            uint64_count = safe_cast<size_t>(divideRoundUp(numerator_bits, bitsPerUint64));

            // Handle fast case.
            if (uint64_count == 1)
            {
                *quotient = *numerator / denominator;
                *numerator -= *quotient * denominator;
                return;
            }

            // Create temporary space to store mutable copy of denominator.
            vector<uint64_t> shifted_denominator(uint64_count, 0);
            shifted_denominator[0] = denominator;

            // Create temporary space to store difference calculation.
            vector<uint64_t> difference(uint64_count);

            // Shift denominator to bring MSB in alignment with MSB of numerator.
            int denominator_shift = numerator_bits - denominator_bits;

            leftShiftUint192(shifted_denominator.data(), denominator_shift, shifted_denominator.data());
            denominator_bits += denominator_shift;

            // Perform bit-wise division algorithm.
            int remaining_shifts = denominator_shift;
            while (numerator_bits == denominator_bits)
            {
                // NOTE: MSBs of numerator and denominator are aligned.

                // Even though MSB of numerator and denominator are aligned,
                // still possible numerator < shifted_denominator.
                if (subUint(numerator, shifted_denominator.data(), uint64_count, difference.data()))
                {
                    // numerator < shifted_denominator and MSBs are aligned,
                    // so current quotient bit is zero and next one is definitely one.
                    if (remaining_shifts == 0)
                    {
                        // No shifts remain and numerator < denominator so done.
                        break;
                    }

                    // Effectively shift numerator left by 1 by instead adding
                    // numerator to difference (to prevent overflow in numerator).
                    addUint(difference.data(), numerator, uint64_count, difference.data());

                    // Adjust quotient and remaining shifts as a result of shifting numerator.
                    leftShiftUint192(quotient, 1, quotient);
                    remaining_shifts--;
                }
                // Difference is the new numerator with denominator subtracted.

                // Update quotient to reflect subtraction.
                quotient[0] |= 1;

                // Determine amount to shift numerator to bring MSB in alignment with denominator.
                numerator_bits = getSignificantBitCountUint(difference.data(), uint64_count);
                int numerator_shift = denominator_bits - numerator_bits;
                if (numerator_shift > remaining_shifts)
                {
                    // Clip the maximum shift to determine only the integer
                    // (as opposed to fractional) bits.
                    numerator_shift = remaining_shifts;
                }

                // Shift and update numerator.
                if (numerator_bits > 0)
                {
                    leftShiftUint192(difference.data(), numerator_shift, numerator);
                    numerator_bits += numerator_shift;
                }
                else
                {
                    // Difference is zero so no need to shift, just set to zero.
                    setZeroUint(uint64_count, numerator);
                }

                // Adjust quotient and remaining shifts as a result of shifting numerator.
                leftShiftUint192(quotient, numerator_shift, quotient);
                remaining_shifts -= numerator_shift;
            }

            // Correct numerator (which is also the remainder) for shifting of
            // denominator, unless it is just zero.
            if (numerator_bits > 0)
            {
                rightShiftUint192(numerator, denominator_shift, numerator);
            }
        }

        // uint64_t exponentiate_uint_safe(uint64_t operand, uint64_t exponent)
        // {
        //     // Fast cases
        //     if (exponent == 0)
        //     {
        //         return 1;
        //     }
        //     if (exponent == 1)
        //     {
        //         return operand;
        //     }

        //     // Perform binary exponentiation.
        //     uint64_t power = operand;
        //     uint64_t product = 0;
        //     uint64_t intermediate = 1;

        //     // Initially: power = operand and intermediate = 1, product irrelevant.
        //     while (true)
        //     {
        //         if (exponent & 1)
        //         {
        //             product = mul_safe(power, intermediate);
        //             swap(product, intermediate);
        //         }
        //         exponent >>= 1;
        //         if (exponent == 0)
        //         {
        //             break;
        //         }
        //         product = mul_safe(power, power);
        //         swap(product, power);
        //     }

        //     return intermediate;
        // }

        // uint64_t exponentiate_uint(uint64_t operand, uint64_t exponent)
        // {
        //     // Fast cases
        //     if (exponent == 0)
        //     {
        //         return 1;
        //     }
        //     if (exponent == 1)
        //     {
        //         return operand;
        //     }

        //     // Perform binary exponentiation.
        //     uint64_t power = operand;
        //     uint64_t product = 0;
        //     uint64_t intermediate = 1;

        //     // Initially: power = operand and intermediate = 1, product irrelevant.
        //     while (true)
        //     {
        //         if (exponent & 1)
        //         {
        //             product = power * intermediate;
        //             swap(product, intermediate);
        //         }
        //         exponent >>= 1;
        //         if (exponent == 0)
        //         {
        //             break;
        //         }
        //         product = power * power;
        //         swap(product, power);
        //     }

        //     return intermediate;
        // }
    }
}