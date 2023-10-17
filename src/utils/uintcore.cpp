// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "common.h"
#include "uintarith.h"
#include "uintcore.h"
#include <algorithm>
#include <string>

using namespace std;

namespace troy
{
    namespace util
    {
        string uintToHexString(const uint64_t *value, size_t uint64_count)
        {
            // Start with a string with a zero for each nibble in the array.
            size_t num_nibbles = mul_safe(uint64_count, static_cast<size_t>(nibblesPerUint64));
            string output(num_nibbles, '0');

            // Iterate through each uint64 in array and set string with correct nibbles in hex.
            size_t nibble_index = num_nibbles;
            size_t leftmost_non_zero_pos = num_nibbles;
            for (size_t i = 0; i < uint64_count; i++)
            {
                uint64_t part = *value++;

                // Iterate through each nibble in the current uint64.
                for (size_t j = 0; j < nibblesPerUint64; j++)
                {
                    size_t nibble = safe_cast<size_t>(part & uint64_t(0x0F));
                    size_t pos = --nibble_index;
                    if (nibble != 0)
                    {
                        // If nibble is not zero, then update string and save this pos to determine
                        // number of leading zeros.
                        output[pos] = nibbleToUpperHex(static_cast<int>(nibble));
                        leftmost_non_zero_pos = pos;
                    }
                    part >>= 4;
                }
            }

            // Trim string to remove leading zeros.
            output.erase(0, leftmost_non_zero_pos);

            // Return 0 if nothing remains.
            if (output.empty())
            {
                return string("0");
            }

            return output;
        }

        string uintToDecString(const uint64_t *value, size_t uint64_count)
        {
            if (!uint64_count)
            {
                return string("0");
            }
            auto remainder(allocateUint(uint64_count));
            auto quotient(allocateUint(uint64_count));
            auto base(allocateUint(uint64_count));
            uint64_t *remainderptr = remainder.get();
            uint64_t *quotientptr = quotient.get();
            uint64_t *baseptr = base.get();
            setUint(10, uint64_count, baseptr);
            setUint(value, uint64_count, remainderptr);
            string output;
            while (!isZeroUint(remainderptr, uint64_count))
            {
                divideUintInplace(remainderptr, baseptr, uint64_count, quotientptr);
                char digit = static_cast<char>(remainderptr[0] + static_cast<uint64_t>('0'));
                output += digit;
                swap(remainderptr, quotientptr);
            }
            reverse(output.begin(), output.end());

            // Return 0 if nothing remains.
            if (output.empty())
            {
                return string("0");
            }

            return output;
        }
    } // namespace util
} // namespace seal
