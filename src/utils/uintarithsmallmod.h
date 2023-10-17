#pragma once

#include "../modulus.h"
#include "defines.h"
#include "numth.h"
#include "uintarith.h"
#include <iostream>

namespace troy {
    namespace util {
        
        /**
        Returns (operand++) mod modulus.
        Correctness: operand must be at most (2 * modulus -2) for correctness.
        */
        inline std::uint64_t incrementUintMod(std::uint64_t operand, const Modulus &modulus)
        {
            operand++;
            return operand - (modulus.value() &
                              static_cast<std::uint64_t>(-static_cast<std::int64_t>(operand >= modulus.value())));
        }

        /**
        Returns (operand--) mod modulus.
        @param[in] operand Must be at most (modulus - 1).
        */
        inline std::uint64_t decrementUintMod(std::uint64_t operand, const Modulus &modulus)
        {
            std::int64_t carry = static_cast<std::int64_t>(operand == 0);
            return operand - 1 + (modulus.value() & static_cast<std::uint64_t>(-carry));
        }

        /**
        Returns (-operand) mod modulus.
        Correctness: operand must be at most modulus for correctness.
        */
        inline std::uint64_t negateUintMod(std::uint64_t operand, const Modulus &modulus)
        {
            std::int64_t non_zero = static_cast<std::int64_t>(operand != 0);
            return (modulus.value() - operand) & static_cast<std::uint64_t>(-non_zero);
        }

        /**
        Returns (operand * inv(2)) mod modulus.
        Correctness: operand must be even and at most (2 * modulus - 2) or odd and at most (modulus - 2).
        @param[in] operand Should be at most (modulus - 1).
        */
        inline std::uint64_t div2UintMod(std::uint64_t operand, const Modulus &modulus)
        {
            if (operand & 1)
            {
                uint64_t temp;
                unsigned char carry = addUint64(operand, modulus.value(), 0, &temp);
                operand = temp >> 1;
                if (carry)
                {
                    return operand | (std::uint64_t(1) << (bitsPerUint64 - 1));
                }
                return operand;
            }
            return operand >> 1;
        }

        /**
        Returns (operand1 + operand2) mod modulus.
        Correctness: (operand1 + operand2) must be at most (2 * modulus - 1).
        */
        inline std::uint64_t addUintMod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
            // Sum of operands modulo Modulus can never wrap around 2^64
            operand1 += operand2;
            return (operand1 >= modulus.value()) ? (operand1 - modulus.value()) : (operand1);
        }

        /**
        Returns (operand1 - operand2) mod modulus.
        Correctness: (operand1 - operand2) must be at most (modulus - 1) and at least (-modulus).
        @param[in] operand1 Should be at most (modulus - 1).
        @param[in] operand2 Should be at most (modulus - 1).
        */
        inline std::uint64_t subUintMod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
            unsigned long long temp;
            std::int64_t borrow = static_cast<std::int64_t>(SEAL_SUB_BORROW_UINT64(operand1, operand2, 0, &temp));
            return static_cast<std::uint64_t>(temp) + (modulus.value() & static_cast<std::uint64_t>(-borrow));
        }

        /**
        Returns input mod modulus. This is not standard Barrett reduction.
        Correctness: modulus must be at most 63-bit.
        @param[in] input Should be at most 128-bit.
        */
        inline std::uint64_t barrettReduce128(const uint64_t *input, const Modulus &modulus)
        {
            // Reduces input using base 2^64 Barrett reduction
            // input allocation size must be 128 bits

            uint64_t tmp1, tmp2[2], tmp3, carry;
            const std::uint64_t *const_ratio = modulus.constRatio();

            // Multiply input and const_ratio
            // Round 1
            multiplyUint64HW64(input[0], const_ratio[0], &carry);

            multiplyUint64(input[0], const_ratio[1], tmp2);
            tmp3 = tmp2[1] + addUint64(tmp2[0], carry, &tmp1);

            // Round 2
            multiplyUint64(input[1], const_ratio[0], tmp2);
            carry = tmp2[1] + addUint64(tmp1, tmp2[0], &tmp1);

            // This is all we care about
            tmp1 = input[1] * const_ratio[1] + tmp3 + carry;

            // Barrett subtraction
            tmp3 = input[0] - tmp1 * modulus.value();

            // One more subtraction is enough
            return (tmp3 >= modulus.value()) ? (tmp3 - modulus.value()): (tmp3);
        }

        /**
        Returns input mod modulus. This is not standard Barrett reduction.
        Correctness: modulus must be at most 63-bit.
        */
        inline std::uint64_t barrettReduce64(uint64_t input, const Modulus &modulus)
        {
            // Reduces input using base 2^64 Barrett reduction
            // floor(2^64 / mod) == floor( floor(2^128 / mod) )
            uint64_t tmp[2];
            const std::uint64_t *const_ratio = modulus.constRatio();
            multiplyUint64HW64(input, const_ratio[1], tmp + 1);

            // Barrett subtraction
            tmp[0] = input - tmp[1] * modulus.value();

            // One more subtraction is enough
            return (tmp[0] >= modulus.value()) ? (tmp[0] - modulus.value()) : (tmp[0]);
        }

        /**
        Returns (operand1 * operand2) mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        inline std::uint64_t multiplyUintMod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
            uint64_t z[2];
            multiplyUint64(operand1, operand2, z);
            return barrettReduce128(z, modulus);
        }

        /**
        This struct contains a operand and a precomputed quotient: (operand << 64) / modulus, for a specific modulus.
        When passed to multiply_uint_mod, a faster variant of Barrett reduction will be performed.
        Operand must be less than modulus.
        */
        struct MultiplyUIntModOperand
        {
            std::uint64_t operand;
            std::uint64_t quotient;

            void setQuotient(const Modulus &modulus)
            {
                std::uint64_t wide_quotient[2]{ 0, 0 };
                std::uint64_t wide_coeff[2]{ 0, operand };
                divideUint128Inplace(wide_coeff, modulus.value(), wide_quotient);
                quotient = wide_quotient[0];
            }

            void set(std::uint64_t new_operand, const Modulus &modulus)
            {
                operand = new_operand;
                setQuotient(modulus);
            }
        };

        inline std::ostream& operator <<(std::ostream& o, const MultiplyUIntModOperand& p) {
            o << "(" << p.operand << "," << p.quotient << ")";
            return o;
        }

        /**
        Returns x * y mod modulus.
        This is a highly-optimized variant of Barrett reduction.
        Correctness: modulus should be at most 63-bit, and y must be less than modulus.
        */
        inline std::uint64_t multiplyUintMod(
            std::uint64_t x, MultiplyUIntModOperand y, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (y.operand >= modulus.value())
            {
                throw std::invalid_argument("operand y must be less than modulus");
            }
#endif
            uint64_t tmp1, tmp2;
            const std::uint64_t p = modulus.value();
            multiplyUint64HW64(x, y.quotient, &tmp1);
            tmp2 = y.operand * x - tmp1 * p;
            return (tmp2 >= p) ? (tmp2 - p) : (tmp2);
        }

        /**
        Returns x * y mod modulus or x * y mod modulus + modulus.
        This is a highly-optimized variant of Barrett reduction and reduce to [0, 2 * modulus - 1].
        Correctness: modulus should be at most 63-bit, and y must be less than modulus.
        */
        inline std::uint64_t multiplyUintModLazy(
            std::uint64_t x, MultiplyUIntModOperand y, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (y.operand >= modulus.value())
            {
                throw std::invalid_argument("operand y must be less than modulus");
            }
#endif
            uint64_t tmp1;
            const std::uint64_t p = modulus.value();
            multiplyUint64HW64(x, y.quotient, &tmp1);
            return y.operand * x - tmp1 * p;
        }

        /**
        Returns value[0] = value mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        inline void moduloUintInplace(std::uint64_t *value, std::size_t value_uint64_count, const Modulus &modulus)
        {
            if (value_uint64_count == 1)
            {
                if (*value < modulus.value())
                {
                    return;
                }
                else
                {
                    *value = barrettReduce64(*value, modulus);
                }
            }

            // Starting from the top, reduce always 128-bit blocks
            for (std::size_t i = value_uint64_count - 1; i--;)
            {
                value[i] = barrettReduce128(value + i, modulus);
                value[i + 1] = 0;
            }
        }

        /**
        Returns value mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        inline std::uint64_t moduloUint(
            const std::uint64_t *value, std::size_t value_uint64_count, const Modulus &modulus)
        {
            if (value_uint64_count == 1)
            {
                // If value < modulus no operation is needed
                if (*value < modulus.value())
                    return *value;
                else
                    return barrettReduce64(*value, modulus);
            }

            // Temporary space for 128-bit reductions
            uint64_t temp[2]{ 0, value[value_uint64_count - 1] };
            for (size_t k = value_uint64_count - 1; k--;)
            {
                temp[0] = value[k];
                temp[1] = barrettReduce128(temp, modulus);
            }

            // Save the result modulo i-th prime
            return temp[1];
        }

        /**
        Returns (operand1 * operand2) + operand3 mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        inline std::uint64_t multiplyAddUintMod(
            std::uint64_t operand1, std::uint64_t operand2, std::uint64_t operand3, const Modulus &modulus)
        {
            // Lazy reduction
            uint64_t temp[2];
            multiplyUint64(operand1, operand2, temp);
            temp[1] += addUint64(temp[0], operand3, temp);
            return barrettReduce128(temp, modulus);
        }

        /**
        Returns (operand1 * operand2) + operand3 mod modulus.
        Correctness: Follows the condition of multiply_uint_mod.
        */
        inline std::uint64_t multiplyAddUintMod(
            std::uint64_t operand1, MultiplyUIntModOperand operand2, std::uint64_t operand3, const Modulus &modulus)
        {
            return addUintMod(
                multiplyUintMod(operand1, operand2, modulus), barrettReduce64(operand3, modulus), modulus);
        }

        inline bool tryInvertUintMod(std::uint64_t operand, const Modulus &modulus, std::uint64_t &result)
        {
            return tryInvertUintMod(operand, modulus.value(), result);
        }

        /**
        Returns operand^exponent mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        std::uint64_t exponentiateUintMod(
            std::uint64_t operand, std::uint64_t exponent, const Modulus &modulus);

        /**
        Computes numerator = numerator mod modulus, quotient = numerator / modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        void divideUintModInplace(
            std::uint64_t *numerator, const Modulus &modulus, std::size_t uint64_count, std::uint64_t *quotient);

        /**
        Computes <operand1, operand2> mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        std::uint64_t dotProductMod(
            const std::uint64_t *operand1, const std::uint64_t *operand2, std::size_t count, const Modulus &modulus);
    }
}