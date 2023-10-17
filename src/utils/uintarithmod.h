// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "uintarith.h"
#include "uintcore.h"
#include <cstdint>

namespace troy
{
    namespace util
    {
        inline void incrementUintMod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
            unsigned char carry = incrementUint(operand, uint64_count, result);
            if (carry || isGreaterThanOrEqualUint(result, modulus, uint64_count))
            {
                subUint(result, modulus, uint64_count, result);
            }
        }

        inline void decrementUintMod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
            if (decrementUint(operand, uint64_count, result))
            {
                addUint(result, modulus, uint64_count, result);
            }
        }

        inline void negateUintMod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
            if (isZeroUint(operand, uint64_count))
            {
                // Negation of zero is zero.
                setZeroUint(uint64_count, result);
            }
            else
            {
                // Otherwise, we know operand > 0 and < modulus so subtract modulus - operand.
                subUint(modulus, operand, uint64_count, result);
            }
        }

        inline void div2UintMod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
            if (*operand & 1)
            {
                unsigned char carry = addUint(operand, modulus, uint64_count, result);
                rightShiftUint(result, 1, uint64_count, result);
                if (carry)
                {
                    setBitUint(result, uint64_count, static_cast<int>(uint64_count) * bitsPerUint64 - 1);
                }
            }
            else
            {
                rightShiftUint(operand, 1, uint64_count, result);
            }
        }

        inline void addUintUintMod(
            const std::uint64_t *operand1, const std::uint64_t *operand2, const std::uint64_t *modulus,
            std::size_t uint64_count, std::uint64_t *result)
        {
            unsigned char carry = addUint(operand1, operand2, uint64_count, result);
            if (carry || isGreaterThanOrEqualUint(result, modulus, uint64_count))
            {
                subUint(result, modulus, uint64_count, result);
            }
        }

        inline void subUintUintMod(
            const std::uint64_t *operand1, const std::uint64_t *operand2, const std::uint64_t *modulus,
            std::size_t uint64_count, std::uint64_t *result)
        {
            if (subUint(operand1, operand2, uint64_count, result))
            {
                addUint(result, modulus, uint64_count, result);
            }
        }

        bool tryInvertUintMod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result);
    } // namespace util
} // namespace seal
