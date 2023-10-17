#pragma once

#include <cstdint>
#include <algorithm>

#include "common.h"
#include "defines.h"
#include "hostarray.h"

namespace troy {
    namespace util {
        
        std::string uintToHexString(const uint64_t *value, std::size_t uint64_count);

        std::string uintToDecString(
            const uint64_t *value, std::size_t uint64_count);

        inline void hexStringToUint(
            const char *hex_string, int char_count, std::size_t uint64_count, uint64_t *result)
        {
            const char *hex_string_ptr = hex_string + char_count;
            for (std::size_t uint64_index = 0; uint64_index < uint64_count; uint64_index++)
            {
                uint64_t value = 0;
                for (int bit_index = 0; bit_index < bitsPerUint64; bit_index += bitsPerNibble)
                {
                    if (hex_string_ptr == hex_string)
                    {
                        break;
                    }
                    char hex = *--hex_string_ptr;
                    int nibble = hexToNibble(hex);
                    if (nibble == -1)
                    {
                        throw std::invalid_argument("hex_value");
                    }
                    value |= static_cast<uint64_t>(nibble) << bit_index;
                }
                result[uint64_index] = value;
            }
        }

        inline HostArray<uint64_t> allocateUint(std::size_t uint64_count)
        {
            return HostArray<uint64_t>(uint64_count);
        }

        inline void setZeroUint(std::size_t uint64_count, uint64_t *result)
        {
            std::fill_n(result, uint64_count, uint64_t(0));
        }

        inline HostArray<uint64_t> allocateZeroUint(std::size_t uint64_count)
        {
            HostArray<uint64_t> result(uint64_count);
            setZeroUint(uint64_count, result.get());
            return result;

            // The following looks better but seems to yield worse results.
            // return allocate<uint64_t>(uint64_count, pool, uint64_t(0));
        }

        inline void setUint(uint64_t value, std::size_t uint64_count, uint64_t *result)
        {
            *result++ = value;
            for (; --uint64_count; result++)
            {
                *result = 0;
            }
        }

        inline void setUint(const uint64_t *value, std::size_t uint64_count, uint64_t *result)
        {
            if ((value == result) || !uint64_count)
            {
                return;
            }
            std::copy_n(value, uint64_count, result);
        }

        inline bool isZeroUint(const uint64_t *value, std::size_t uint64_count)
        {
            return std::all_of(value, value + uint64_count, [](auto coeff) -> bool { return !coeff; });
        }

        inline bool isEqualUint(
            const uint64_t *value, std::size_t uint64_count, uint64_t scalar)
        {
            if (*value++ != scalar)
            {
                return false;
            }
            return std::all_of(value, value + uint64_count - 1, [](auto coeff) -> bool { return !coeff; });
        }

        inline bool isHighBitSetUint(const uint64_t *value, std::size_t uint64_count)
        {
            return (value[uint64_count - 1] >> (bitsPerUint64 - 1)) != 0;
        }
// #ifndef SEAL_USE_MAYBE_UNUSED
// #if (SEAL_COMPILER == SEAL_COMPILER_GCC)
// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wunused-parameter"
// #elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
// #pragma clang diagnostic push
// #pragma clang diagnostic ignored "-Wunused-parameter"
// #endif
// #endif
        inline bool isBitSetUint(
            const uint64_t *value, std::size_t uint64_count SEAL_MAYBE_UNUSED, int bit_index)
        {
            int uint64_index = bit_index / bitsPerUint64;
            int sub_bit_index = bit_index - uint64_index * bitsPerUint64;
            return ((value[static_cast<std::size_t>(uint64_index)] >> sub_bit_index) & 1) != 0;
        }

        inline void setBitUint(uint64_t *value, std::size_t uint64_count SEAL_MAYBE_UNUSED, int bit_index)
        {
            int uint64_index = bit_index / bitsPerUint64;
            int sub_bit_index = bit_index % bitsPerUint64;
            value[static_cast<std::size_t>(uint64_index)] |= uint64_t(1) << sub_bit_index;
        }
#ifndef SEAL_USE_MAYBE_UNUSED
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif
#endif
        inline int getSignificantBitCountUint(const uint64_t *value, std::size_t uint64_count)
        {
            value += uint64_count - 1;
            for (; *value == 0 && uint64_count > 1; uint64_count--)
            {
                value--;
            }

            return static_cast<int>(uint64_count - 1) * bitsPerUint64 + getSignificantBitCount(*value);
        }

        inline std::size_t getSignificantUint64CountUint(
            const uint64_t *value, std::size_t uint64_count)
        {
            value += uint64_count - 1;
            for (; uint64_count && !*value; uint64_count--)
            {
                value--;
            }

            return uint64_count;
        }

        inline std::size_t getNonzeroUint64CountUint(
            const uint64_t *value, std::size_t uint64_count)
        {
            std::size_t nonzero_count = uint64_count;

            value += uint64_count - 1;
            for (; uint64_count; uint64_count--)
            {
                if (*value-- == 0)
                {
                    nonzero_count--;
                }
            }

            return nonzero_count;
        }

        inline void setUint(
            const uint64_t *value, std::size_t value_uint64_count, std::size_t result_uint64_count,
            uint64_t *result)
        {
            if (value == result || !value_uint64_count)
            {
                // Fast path to handle self assignment.
                std::fill(result + value_uint64_count, result + result_uint64_count, uint64_t(0));
            }
            else
            {
                std::size_t min_uint64_count = std::min<>(value_uint64_count, result_uint64_count);
                std::copy_n(value, min_uint64_count, result);
                std::fill(result + min_uint64_count, result + result_uint64_count, uint64_t(0));
            }
        }

        /**
        If the value is a power of two, return the power; otherwise, return -1.
        */
        inline int getPowerOfTwo(uint64_t value)
        {
            if (value == 0 || (value & (value - 1)) != 0)
            {
                return -1;
            }

            unsigned long result = 63UL - static_cast<unsigned long>(__builtin_clzll(value));
            return static_cast<int>(result);
        }

        inline void filterHighbitsUint(uint64_t *operand, std::size_t uint64_count, int bit_count)
        {
            std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bitsPerUint64);
            if (unsigned_eq(bit_count, mul_safe(uint64_count, bits_per_uint64_sz)))
            {
                return;
            }
            int uint64_index = bit_count / bitsPerUint64;
            int subbit_index = bit_count - uint64_index * bitsPerUint64;
            operand += uint64_index;
            *operand++ &= (uint64_t(1) << subbit_index) - 1;
            for (int long_index = uint64_index + 1; unsigned_lt(long_index, uint64_count); long_index++)
            {
                *operand++ = 0;
            }
        }

        // NOTE: This implementation is different from SEAL.
        // Actually it copies the content every time it is called.
        inline HostArray<uint64_t> duplicateUintIfNeeded(
            const uint64_t *input, std::size_t uint64_count, std::size_t new_uint64_count, bool force)
        {
            // FIXME: allocate related action
            if (!force && uint64_count >= new_uint64_count) return HostArray<uint64_t>(input, uint64_count);

            HostArray<uint64_t> allocation(new_uint64_count);
            setUint(input, uint64_count, new_uint64_count, allocation.get());
            return allocation;
        }

        inline int compareUint(
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

        inline int compareUint(
            const uint64_t *operand1, std::size_t operand1_uint64_count, const uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            int result = 0;
            operand1 += operand1_uint64_count - 1;
            operand2 += operand2_uint64_count - 1;

            std::size_t min_uint64_count = std::min<>(operand1_uint64_count, operand2_uint64_count);

            operand1_uint64_count -= min_uint64_count;
            for (; (result == 0) && operand1_uint64_count--; operand1--)
            {
                result = (*operand1 > 0);
            }

            operand2_uint64_count -= min_uint64_count;
            for (; (result == 0) && operand2_uint64_count--; operand2--)
            {
                result = -(*operand2 > 0);
            }

            for (; (result == 0) && min_uint64_count--; operand1--, operand2--)
            {
                result = (*operand1 > *operand2) - (*operand1 < *operand2);
            }
            return result;
        }

        inline bool isGreaterThanUint(
            const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count)
        {
            return compareUint(operand1, operand2, uint64_count) > 0;
        }

        inline bool isGreaterThanOrEqualUint(
            const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count)
        {
            return compareUint(operand1, operand2, uint64_count) >= 0;
        }

        inline bool isLessThanUint(
            const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count)
        {
            return compareUint(operand1, operand2, uint64_count) < 0;
        }

        inline bool isLessThanOrEqualUint(
            const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count)
        {
            return compareUint(operand1, operand2, uint64_count) <= 0;
        }

        inline bool isEqualUint(
            const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count)
        {
            return compareUint(operand1, operand2, uint64_count) == 0;
        }

        inline bool isGreaterThanUint(
            const uint64_t *operand1, std::size_t operand1_uint64_count, const uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compareUint(operand1, operand1_uint64_count, operand2, operand2_uint64_count) > 0;
        }

        inline bool isGreaterThanOrEqualUint(
            const uint64_t *operand1, std::size_t operand1_uint64_count, const uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compareUint(operand1, operand1_uint64_count, operand2, operand2_uint64_count) >= 0;
        }

        inline bool isLessThanUint(
            const uint64_t *operand1, std::size_t operand1_uint64_count, const uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compareUint(operand1, operand1_uint64_count, operand2, operand2_uint64_count) < 0;
        }

        inline bool isLessThanOrEqualUint(
            const uint64_t *operand1, std::size_t operand1_uint64_count, const uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compareUint(operand1, operand1_uint64_count, operand2, operand2_uint64_count) <= 0;
        }

        inline bool isEqualUint(
            const uint64_t *operand1, std::size_t operand1_uint64_count, const uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compareUint(operand1, operand1_uint64_count, operand2, operand2_uint64_count) == 0;
        }
    }
}