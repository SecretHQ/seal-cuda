#include "uintarith.h"
#include "uintarithsmallmod.h"

using std::swap;

namespace troy {
    namespace util {


        uint64_t exponentiateUintMod(uint64_t operand, uint64_t exponent, const Modulus &modulus)
        {
            // Fast cases
            if (exponent == 0)
            {
                // Result is supposed to be only one digit
                return 1;
            }

            if (exponent == 1)
            {
                return operand;
            }

            // Perform binary exponentiation.
            uint64_t power = operand;
            uint64_t product = 0;
            uint64_t intermediate = 1;

            // Initially: power = operand and intermediate = 1, product is irrelevant.
            while (true)
            {
                if (exponent & 1)
                {
                    product = multiplyUintMod(power, intermediate, modulus);
                    swap(product, intermediate);
                }
                exponent >>= 1;
                if (exponent == 0)
                {
                    break;
                }
                product = multiplyUintMod(power, power, modulus);
                swap(product, power);
            }
            return intermediate;
        }

        void divideUintModInplace(
            uint64_t *numerator, const Modulus &modulus, size_t uint64_count, uint64_t *quotient)
        {
            // Handle base cases
            if (uint64_count == 2)
            {
                divideUint128Inplace(numerator, modulus.value(), quotient);
                return;
            }
            else if (uint64_count == 1)
            {
                *numerator = barrettReduce64(*numerator, modulus);
                *quotient = *numerator / modulus.value();
                return;
            }
            else
            {
                // If uint64_count > 2.
                // x = numerator = x1 * 2^128 + x2.
                // 2^128 = A*value + B.

                // FIXME: allocate related action (x1, quot, rem)
                uint64_t *x1 = new uint64_t[uint64_count - 2];
                uint64_t x2[2];
                uint64_t *quot = new uint64_t[uint64_count];
                uint64_t *rem = new uint64_t[uint64_count];
                setUint(numerator + 2, uint64_count - 2, x1);
                setUint(numerator, 2, x2); // x2 = (num) % 2^128.

                multiplyUint(x1, uint64_count - 2, &modulus.constRatio()[0], 2, uint64_count, quot); // x1*A.
                multiplyUint(x1, uint64_count - 2, modulus.constRatio()[2], uint64_count - 1, rem); // x1*B
                addUint(rem, uint64_count - 1, x2, 2, 0, uint64_count, rem); // x1*B + x2;

                size_t remainder_uint64_count = getSignificantUint64CountUint(rem, uint64_count);
                divideUintModInplace(rem, modulus, remainder_uint64_count, quotient);
                addUint(quotient, quot, uint64_count, quotient);
                *numerator = rem[0];

                delete[] x1; delete[] quot; delete[] rem;
                return;
            }
        }

        uint64_t dotProductMod(
            const uint64_t *operand1, const uint64_t *operand2, size_t count, const Modulus &modulus)
        {
            static_assert(SEAL_MULTIPLY_ACCUMULATE_MOD_MAX >= 16, "SEAL_MULTIPLY_ACCUMULATE_MOD_MAX");
            uint64_t accumulator[2]{ 0, 0 };
            switch (count)
            {
            case 0:
                return 0;
            case 1:
                multiplyAccumulateUint64<1>(operand1, operand2, accumulator);
                break;
            case 2:
                multiplyAccumulateUint64<2>(operand1, operand2, accumulator);
                break;
            case 3:
                multiplyAccumulateUint64<3>(operand1, operand2, accumulator);
                break;
            case 4:
                multiplyAccumulateUint64<4>(operand1, operand2, accumulator);
                break;
            case 5:
                multiplyAccumulateUint64<5>(operand1, operand2, accumulator);
                break;
            case 6:
                multiplyAccumulateUint64<6>(operand1, operand2, accumulator);
                break;
            case 7:
                multiplyAccumulateUint64<7>(operand1, operand2, accumulator);
                break;
            case 8:
                multiplyAccumulateUint64<8>(operand1, operand2, accumulator);
                break;
            case 9:
                multiplyAccumulateUint64<9>(operand1, operand2, accumulator);
                break;
            case 10:
                multiplyAccumulateUint64<10>(operand1, operand2, accumulator);
                break;
            case 11:
                multiplyAccumulateUint64<11>(operand1, operand2, accumulator);
                break;
            case 12:
                multiplyAccumulateUint64<12>(operand1, operand2, accumulator);
                break;
            case 13:
                multiplyAccumulateUint64<13>(operand1, operand2, accumulator);
                break;
            case 14:
                multiplyAccumulateUint64<14>(operand1, operand2, accumulator);
                break;
            case 15:
                multiplyAccumulateUint64<15>(operand1, operand2, accumulator);
                break;
            case 16:
            largest_case:
                multiplyAccumulateUint64<16>(operand1, operand2, accumulator);
                break;
            default:
                accumulator[0] = dotProductMod(operand1 + 16, operand2 + 16, count - 16, modulus);
                goto largest_case;
            };
            return barrettReduce128(accumulator, modulus);
        }

    }
}