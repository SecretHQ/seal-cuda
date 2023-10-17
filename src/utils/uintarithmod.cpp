// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "common.h"
#include "uintarith.h"
#include "uintarithmod.h"
#include "uintcore.h"

using namespace std;

namespace troy
{
    namespace util
    {
        bool tryInvertUintMod(
            const uint64_t *operand, const uint64_t *modulus, size_t uint64_count, uint64_t *result)
        {
            // Cannot invert 0.
            int bit_count = getSignificantBitCountUint(operand, uint64_count);
            if (bit_count == 0)
            {
                return false;
            }

            // If it is 1, then its invert is itself.
            if (bit_count == 1)
            {
                setUint(1, uint64_count, result);
                return true;
            }

            // FIXME: allocate related action
            HostArray<uint64_t> alloc_anchor(7 * uint64_count);

            // Construct a mutable copy of operand and modulus, with numerator being modulus
            // and operand being denominator. Notice that numerator > denominator.
            uint64_t *numerator = alloc_anchor.get();
            setUint(modulus, uint64_count, numerator);

            uint64_t *denominator = numerator + uint64_count;
            setUint(operand, uint64_count, denominator);

            // Create space to store difference.
            uint64_t *difference = denominator + uint64_count;

            // Determine highest bit index of each.
            int numerator_bits = getSignificantBitCountUint(numerator, uint64_count);
            int denominator_bits = getSignificantBitCountUint(denominator, uint64_count);

            // Create space to store quotient.
            uint64_t *quotient = difference + uint64_count;

            // Create three sign/magnitude values to store coefficients.
            // Initialize invert_prior to +0 and invert_curr to +1.
            uint64_t *invert_prior = quotient + uint64_count;
            setZeroUint(uint64_count, invert_prior);
            bool invert_prior_positive = true;

            uint64_t *invert_curr = invert_prior + uint64_count;
            setUint(1, uint64_count, invert_curr);
            bool invert_curr_positive = true;

            uint64_t *invert_next = invert_curr + uint64_count;
            bool invert_next_positive = true;

            // Perform extended Euclidean algorithm.
            while (true)
            {
                // NOTE: Numerator is > denominator.

                // Only perform computation up to last non-zero uint64s.
                size_t division_uint64_count = static_cast<size_t>(divideRoundUp(numerator_bits, bitsPerUint64));

                // Shift denominator to bring MSB in alignment with MSB of numerator.
                int denominator_shift = numerator_bits - denominator_bits;
                leftShiftUint(denominator, denominator_shift, division_uint64_count, denominator);
                denominator_bits += denominator_shift;

                // Clear quotient.
                setZeroUint(uint64_count, quotient);

                // Perform bit-wise division algorithm.
                int remaining_shifts = denominator_shift;
                while (numerator_bits == denominator_bits)
                {
                    // NOTE: MSBs of numerator and denominator are aligned.

                    // Even though MSB of numerator and denominator are aligned,
                    // still possible numerator < denominator.
                    if (subUint(numerator, denominator, division_uint64_count, difference))
                    {
                        // numerator < denominator and MSBs are aligned, so current
                        // quotient bit is zero and next one is definitely one.
                        if (remaining_shifts == 0)
                        {
                            // No shifts remain and numerator < denominator so done.
                            break;
                        }

                        // Effectively shift numerator left by 1 by instead adding
                        // numerator to difference (to prevent overflow in numerator).
                        addUint(difference, numerator, division_uint64_count, difference);

                        // Adjust quotient and remaining shifts as a result of shifting numerator.
                        leftShiftUint(quotient, 1, division_uint64_count, quotient);
                        remaining_shifts--;
                    }
                    // Difference is the new numerator with denominator subtracted.

                    // Update quotient to reflect subtraction.
                    *quotient |= 1;

                    // Determine amount to shift numerator to bring MSB in alignment
                    // with denominator.
                    numerator_bits = getSignificantBitCountUint(difference, division_uint64_count);
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
                        leftShiftUint(difference, numerator_shift, division_uint64_count, numerator);
                        numerator_bits += numerator_shift;
                    }
                    else
                    {
                        // Difference is zero so no need to shift, just set to zero.
                        setZeroUint(division_uint64_count, numerator);
                    }

                    // Adjust quotient and remaining shifts as a result of
                    // shifting numerator.
                    leftShiftUint(quotient, numerator_shift, division_uint64_count, quotient);
                    remaining_shifts -= numerator_shift;
                }

                // Correct for shifting of denominator.
                rightShiftUint(denominator, denominator_shift, division_uint64_count, denominator);
                denominator_bits -= denominator_shift;

                // We are done if remainder (which is stored in numerator) is zero.
                if (numerator_bits == 0)
                {
                    break;
                }

                // Correct for shifting of denominator.
                rightShiftUint(numerator, denominator_shift, division_uint64_count, numerator);
                numerator_bits -= denominator_shift;

                // Integrate quotient with invert coefficients.
                // Calculate: invert_prior + -quotient * invert_curr
                multiplyTruncateUint(quotient, invert_curr, uint64_count, invert_next);
                invert_next_positive = !invert_curr_positive;
                if (invert_prior_positive == invert_next_positive)
                {
                    // If both sides of add have same sign, then simply add and
                    // do not need to worry about overflow due to known limits
                    // on the coefficients proved in the euclidean algorithm.
                    addUint(invert_prior, invert_next, uint64_count, invert_next);
                }
                else
                {
                    // If both sides of add have opposite sign, then subtract
                    // and check for overflow.
                    uint64_t borrow = subUint(invert_prior, invert_next, uint64_count, invert_next);
                    if (borrow == 0)
                    {
                        // No borrow means |invert_prior| >= |invert_next|,
                        // so sign is same as invert_prior.
                        invert_next_positive = invert_prior_positive;
                    }
                    else
                    {
                        // Borrow means |invert prior| < |invert_next|,
                        // so sign is opposite of invert_prior.
                        invert_next_positive = !invert_prior_positive;
                        negateUint(invert_next, uint64_count, invert_next);
                    }
                }

                // Swap prior and curr, and then curr and next.
                swap(invert_prior, invert_curr);
                swap(invert_prior_positive, invert_curr_positive);
                swap(invert_curr, invert_next);
                swap(invert_curr_positive, invert_next_positive);

                // Swap numerator and denominator using pointer swings.
                swap(numerator, denominator);
                swap(numerator_bits, denominator_bits);
            }

            if (!isEqualUint(denominator, uint64_count, 1))
            {
                // GCD is not one, so unable to find inverse.
                return false;
            }

            // Correct coefficient if negative by modulo.
            if (!invert_curr_positive && !isZeroUint(invert_curr, uint64_count))
            {
                subUint(modulus, invert_curr, uint64_count, invert_curr);
                invert_curr_positive = true;
            }

            // Set result.
            setUint(invert_curr, uint64_count, result);
            return true;
        }
    } // namespace util
} // namespace seal
