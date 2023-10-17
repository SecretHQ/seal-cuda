// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/modulus.h"
#include "../../src/utils/uintarithsmallmod.h"
#include "../../src/utils/uintcore.h"
#include "gtest/gtest.h"

using namespace troy::util;
using namespace troy;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(UIntArithSmallMod, IncrementUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(1ULL, incrementUintMod(0, mod));
            ASSERT_EQ(0ULL, incrementUintMod(1ULL, mod));

            mod = 0x10000;
            ASSERT_EQ(1ULL, incrementUintMod(0, mod));
            ASSERT_EQ(2ULL, incrementUintMod(1ULL, mod));
            ASSERT_EQ(0ULL, incrementUintMod(0xFFFFULL, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(1ULL, incrementUintMod(0, mod));
            ASSERT_EQ(0ULL, incrementUintMod(2305843009211596800ULL, mod));
            ASSERT_EQ(1ULL, incrementUintMod(0, mod));
        }

        TEST(UIntArithSmallMod, DecrementUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, decrementUintMod(1, mod));
            ASSERT_EQ(1ULL, decrementUintMod(0ULL, mod));

            mod = 0x10000;
            ASSERT_EQ(0ULL, decrementUintMod(1, mod));
            ASSERT_EQ(1ULL, decrementUintMod(2ULL, mod));
            ASSERT_EQ(0xFFFFULL, decrementUintMod(0ULL, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, decrementUintMod(1, mod));
            ASSERT_EQ(2305843009211596800ULL, decrementUintMod(0ULL, mod));
            ASSERT_EQ(0ULL, decrementUintMod(1, mod));
        }

        TEST(UIntArithSmallMod, NegateUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, negateUintMod(0, mod));
            ASSERT_EQ(1ULL, negateUintMod(1, mod));

            mod = 0xFFFFULL;
            ASSERT_EQ(0ULL, negateUintMod(0, mod));
            ASSERT_EQ(0xFFFEULL, negateUintMod(1, mod));
            ASSERT_EQ(0x1ULL, negateUintMod(0xFFFEULL, mod));

            mod = 0x10000ULL;
            ASSERT_EQ(0ULL, negateUintMod(0, mod));
            ASSERT_EQ(0xFFFFULL, negateUintMod(1, mod));
            ASSERT_EQ(0x1ULL, negateUintMod(0xFFFFULL, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, negateUintMod(0, mod));
            ASSERT_EQ(2305843009211596800ULL, negateUintMod(1, mod));
        }

        TEST(UIntArithSmallMod, Div2UIntMod)
        {
            Modulus mod(3);
            ASSERT_EQ(0ULL, div2UintMod(0ULL, mod));
            ASSERT_EQ(2ULL, div2UintMod(1ULL, mod));

            mod = 17;
            ASSERT_EQ(11ULL, div2UintMod(5ULL, mod));
            ASSERT_EQ(4ULL, div2UintMod(8ULL, mod));

            mod = 0xFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0x800000000000000ULL, div2UintMod(1ULL, mod));
            ASSERT_EQ(0x800000000000001ULL, div2UintMod(3ULL, mod));
        }

        TEST(UIntArithSmallMod, AddUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, addUintMod(0, 0, mod));
            ASSERT_EQ(1ULL, addUintMod(0, 1, mod));
            ASSERT_EQ(1ULL, addUintMod(1, 0, mod));
            ASSERT_EQ(0ULL, addUintMod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, addUintMod(0, 0, mod));
            ASSERT_EQ(1ULL, addUintMod(0, 1, mod));
            ASSERT_EQ(1ULL, addUintMod(1, 0, mod));
            ASSERT_EQ(2ULL, addUintMod(1, 1, mod));
            ASSERT_EQ(4ULL, addUintMod(7, 7, mod));
            ASSERT_EQ(3ULL, addUintMod(6, 7, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, addUintMod(0, 0, mod));
            ASSERT_EQ(1ULL, addUintMod(0, 1, mod));
            ASSERT_EQ(1ULL, addUintMod(1, 0, mod));
            ASSERT_EQ(2ULL, addUintMod(1, 1, mod));
            ASSERT_EQ(0ULL, addUintMod(1152921504605798400ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(1ULL, addUintMod(1152921504605798401ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(2305843009211596799ULL, addUintMod(2305843009211596800ULL, 2305843009211596800ULL, mod));
        }

        TEST(UIntArithSmallMod, SubUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, subUintMod(0, 0, mod));
            ASSERT_EQ(1ULL, subUintMod(0, 1, mod));
            ASSERT_EQ(1ULL, subUintMod(1, 0, mod));
            ASSERT_EQ(0ULL, subUintMod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, subUintMod(0, 0, mod));
            ASSERT_EQ(9ULL, subUintMod(0, 1, mod));
            ASSERT_EQ(1ULL, subUintMod(1, 0, mod));
            ASSERT_EQ(0ULL, subUintMod(1, 1, mod));
            ASSERT_EQ(0ULL, subUintMod(7, 7, mod));
            ASSERT_EQ(9ULL, subUintMod(6, 7, mod));
            ASSERT_EQ(1ULL, subUintMod(7, 6, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, subUintMod(0, 0, mod));
            ASSERT_EQ(2305843009211596800ULL, subUintMod(0, 1, mod));
            ASSERT_EQ(1ULL, subUintMod(1, 0, mod));
            ASSERT_EQ(0ULL, subUintMod(1, 1, mod));
            ASSERT_EQ(2305843009211596800ULL, subUintMod(1152921504605798400ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(1ULL, subUintMod(1152921504605798401ULL, 1152921504605798400ULL, mod));
            ASSERT_EQ(0ULL, subUintMod(1152921504605798401ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(0ULL, subUintMod(2305843009211596800ULL, 2305843009211596800ULL, mod));
        }

        TEST(UIntArithSmallMod, BarrettReduce128)
        {
            uint64_t input[2];

            Modulus mod(2);
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrettReduce128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrettReduce128(input, mod));
            input[0] = 0xFFFFFFFFFFFFFFFFULL;
            input[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(1ULL, barrettReduce128(input, mod));

            mod = 3;
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrettReduce128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrettReduce128(input, mod));
            input[0] = 123;
            input[1] = 456;
            ASSERT_EQ(0ULL, barrettReduce128(input, mod));
            input[0] = 0xFFFFFFFFFFFFFFFFULL;
            input[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0ULL, barrettReduce128(input, mod));

            mod = 13131313131313ULL;
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrettReduce128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrettReduce128(input, mod));
            input[0] = 123;
            input[1] = 456;
            ASSERT_EQ(8722750765283ULL, barrettReduce128(input, mod));
            input[0] = 24242424242424;
            input[1] = 79797979797979;
            ASSERT_EQ(1010101010101ULL, barrettReduce128(input, mod));
        }

        TEST(UIntArithSmallMod, MultiplyUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, multiplyUintMod(0, 0, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(0, 1, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(1, 0, mod));
            ASSERT_EQ(1ULL, multiplyUintMod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, multiplyUintMod(0, 0, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(0, 1, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(1, 0, mod));
            ASSERT_EQ(1ULL, multiplyUintMod(1, 1, mod));
            ASSERT_EQ(9ULL, multiplyUintMod(7, 7, mod));
            ASSERT_EQ(2ULL, multiplyUintMod(6, 7, mod));
            ASSERT_EQ(2ULL, multiplyUintMod(7, 6, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, multiplyUintMod(0, 0, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(0, 1, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(1, 0, mod));
            ASSERT_EQ(1ULL, multiplyUintMod(1, 1, mod));
            ASSERT_EQ(576460752302899200ULL, multiplyUintMod(1152921504605798400ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(576460752302899200ULL, multiplyUintMod(1152921504605798401ULL, 1152921504605798400ULL, mod));
            ASSERT_EQ(1729382256908697601ULL, multiplyUintMod(1152921504605798401ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(1ULL, multiplyUintMod(2305843009211596800ULL, 2305843009211596800ULL, mod));
        }

        TEST(UIntArithSmallMod, MultiplyAddMod)
        {
            Modulus mod(7);
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, 0, 0, mod));
            ASSERT_EQ(0ULL, multiplyAddUintMod(1, 0, 0, mod));
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, 1, 0, mod));
            ASSERT_EQ(1ULL, multiplyAddUintMod(0, 0, 1, mod));
            ASSERT_EQ(3ULL, multiplyAddUintMod(3, 4, 5, mod));

            mod = 0x1FFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, 0, 0, mod));
            ASSERT_EQ(0ULL, multiplyAddUintMod(1, 0, 0, mod));
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, 1, 0, mod));
            ASSERT_EQ(1ULL, multiplyAddUintMod(0, 0, 1, mod));
            ASSERT_EQ(0ULL, multiplyAddUintMod(mod.value() - 1, mod.value() - 1, mod.value() - 1, mod));
        }

        TEST(UIntArithSmallMod, ModuloUIntMod)
        {
            
            auto value = HostArray<uint64_t>(4);

            Modulus mod(2);
            value[0] = 0;
            value[1] = 0;
            value[2] = 0;
            moduloUintInplace(value.get(), 3, mod);
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 1;
            value[1] = 0;
            value[2] = 0;
            moduloUintInplace(value.get(), 3, mod);
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 2;
            value[1] = 0;
            value[2] = 0;
            moduloUintInplace(value.get(), 3, mod);
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 3;
            value[1] = 0;
            value[2] = 0;
            moduloUintInplace(value.get(), 3, mod);
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0xFFFF;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 0;
            moduloUintInplace(value.get(), 3, mod);
            ASSERT_EQ(65143ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0x1000;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 0;
            moduloUintInplace(value.get(), 3, mod);
            ASSERT_EQ(0xDB4ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0xFFFFFFFFC001ULL;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 14447416709120365380ul;
            value[3] = 67450014862939159;
            moduloUintInplace(value.get(), 4, mod);
            ASSERT_EQ(124510066632001ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);
            ASSERT_EQ(0ULL, value[3]);
        }

        TEST(UIntArithSmallMod, TryInvertUIntMod)
        {
            uint64_t result;
            Modulus mod(5);
            ASSERT_FALSE(tryInvertUintMod(0, mod, result));
            ASSERT_TRUE(tryInvertUintMod(1, mod, result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(tryInvertUintMod(2, mod, result));
            ASSERT_EQ(3ULL, result);
            ASSERT_TRUE(tryInvertUintMod(3, mod, result));
            ASSERT_EQ(2ULL, result);
            ASSERT_TRUE(tryInvertUintMod(4, mod, result));
            ASSERT_EQ(4ULL, result);

            mod = 6;
            ASSERT_FALSE(tryInvertUintMod(2, mod, result));
            ASSERT_FALSE(tryInvertUintMod(3, mod, result));
            ASSERT_TRUE(tryInvertUintMod(5, mod, result));
            ASSERT_EQ(5ULL, result);

            mod = 1351315121;
            ASSERT_TRUE(tryInvertUintMod(331975426, mod, result));
            ASSERT_EQ(1052541512ULL, result);
        }

        TEST(UIntArithSmallMod, ExponentiateUIntMod)
        {
            Modulus mod(5);
            ASSERT_EQ(1ULL, exponentiateUintMod(1, 0, mod));
            ASSERT_EQ(1ULL, exponentiateUintMod(1, 0xFFFFFFFFFFFFFFFFULL, mod));
            ASSERT_EQ(3ULL, exponentiateUintMod(2, 0xFFFFFFFFFFFFFFFFULL, mod));

            mod = 0x1000000000000000ULL;
            ASSERT_EQ(0ULL, exponentiateUintMod(2, 60, mod));
            ASSERT_EQ(0x800000000000000ULL, exponentiateUintMod(2, 59, mod));

            mod = 131313131313;
            ASSERT_EQ(39418477653ULL, exponentiateUintMod(2424242424, 16, mod));
        }

        TEST(UIntArithSmallMod, DotProductMod)
        {
            Modulus mod(5);
            uint64_t arr1[64], arr2[64];
            for (size_t i = 0; i < 64; i++)
            {
                arr1[i] = 2;
                arr2[i] = 3;
            }

            ASSERT_EQ(0, dotProductMod(arr1, arr2, 0, mod));
            ASSERT_EQ(1, dotProductMod(arr1, arr2, 1, mod));
            ASSERT_EQ(2, dotProductMod(arr1, arr2, 2, mod));
            ASSERT_EQ(15 % mod.value(), dotProductMod(arr1, arr2, 15, mod));
            ASSERT_EQ(16 % mod.value(), dotProductMod(arr1, arr2, 16, mod));
            ASSERT_EQ(17 % mod.value(), dotProductMod(arr1, arr2, 17, mod));
            ASSERT_EQ(32 % mod.value(), dotProductMod(arr1, arr2, 32, mod));
            ASSERT_EQ(64 % mod.value(), dotProductMod(arr1, arr2, 64, mod));

            mod = getPrime(1024 * 2, SEAL_MOD_BIT_COUNT_MAX);
            for (size_t i = 0; i < 64; i++)
            {
                arr1[i] = mod.value() - 1;
                arr2[i] = mod.value() - 1;
            }

            ASSERT_EQ(0, dotProductMod(arr1, arr2, 0, mod));
            ASSERT_EQ(1, dotProductMod(arr1, arr2, 1, mod));
            ASSERT_EQ(2, dotProductMod(arr1, arr2, 2, mod));
            ASSERT_EQ(15, dotProductMod(arr1, arr2, 15, mod));
            ASSERT_EQ(16, dotProductMod(arr1, arr2, 16, mod));
            ASSERT_EQ(17, dotProductMod(arr1, arr2, 17, mod));
            ASSERT_EQ(32, dotProductMod(arr1, arr2, 32, mod));
            ASSERT_EQ(64, dotProductMod(arr1, arr2, 64, mod));
        }

        TEST(UIntArithSmallMod, MultiplyUIntModOperand)
        {
            Modulus mod(3);
            MultiplyUIntModOperand y;
            y.set(1, mod);
            ASSERT_EQ(1ULL, y.operand);
            ASSERT_EQ(6148914691236517205ULL, y.quotient);
            y.set(2, mod);
            y.setQuotient(mod);
            ASSERT_EQ(2ULL, y.operand);
            ASSERT_EQ(12297829382473034410ULL, y.quotient);

            mod = 2147483647ULL;
            y.set(1, mod);
            ASSERT_EQ(1ULL, y.operand);
            ASSERT_EQ(8589934596ULL, y.quotient);
            y.set(2147483646ULL, mod);
            y.setQuotient(mod);
            ASSERT_EQ(2147483646ULL, y.operand);
            ASSERT_EQ(18446744065119617019ULL, y.quotient);

            mod = 2305843009211596801ULL;
            y.set(1, mod);
            ASSERT_EQ(1ULL, y.operand);
            ASSERT_EQ(8ULL, y.quotient);
            y.set(2305843009211596800ULL, mod);
            y.setQuotient(mod);
            ASSERT_EQ(2305843009211596800ULL, y.operand);
            ASSERT_EQ(18446744073709551607ULL, y.quotient);
        }

        TEST(UIntArithSmallMod, MultiplyUIntMod2)
        {
            Modulus mod(2);
            MultiplyUIntModOperand y;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyUintMod(0, y, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyUintMod(0, y, mod));
            ASSERT_EQ(1ULL, multiplyUintMod(1, y, mod));

            mod = 10;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyUintMod(0, y, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyUintMod(0, y, mod));
            ASSERT_EQ(1ULL, multiplyUintMod(1, y, mod));
            y.set(6, mod);
            ASSERT_EQ(2ULL, multiplyUintMod(7, y, mod));
            y.set(7, mod);
            ASSERT_EQ(9ULL, multiplyUintMod(7, y, mod));
            ASSERT_EQ(2ULL, multiplyUintMod(6, y, mod));

            mod = 2305843009211596801ULL;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyUintMod(0, y, mod));
            ASSERT_EQ(0ULL, multiplyUintMod(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyUintMod(0, y, mod));
            ASSERT_EQ(1ULL, multiplyUintMod(1, y, mod));
            y.set(1152921504605798400ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiplyUintMod(1152921504605798401ULL, y, mod));
            y.set(1152921504605798401ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiplyUintMod(1152921504605798400ULL, y, mod));
            ASSERT_EQ(1729382256908697601ULL, multiplyUintMod(1152921504605798401ULL, y, mod));
            y.set(2305843009211596800ULL, mod);
            ASSERT_EQ(1ULL, multiplyUintMod(2305843009211596800ULL, y, mod));
        }

        TEST(UIntArithSmallMod, MultiplyUIntModLazy)
        {
            Modulus mod(2);
            MultiplyUIntModOperand y;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyUintModLazy(0, y, mod));
            ASSERT_EQ(0ULL, multiplyUintModLazy(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyUintModLazy(0, y, mod));
            ASSERT_EQ(1ULL, multiplyUintModLazy(1, y, mod));

            mod = 10;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyUintModLazy(0, y, mod));
            ASSERT_EQ(0ULL, multiplyUintModLazy(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyUintModLazy(0, y, mod));
            ASSERT_EQ(1ULL, multiplyUintModLazy(1, y, mod));
            y.set(6, mod);
            ASSERT_EQ(2ULL, multiplyUintModLazy(7, y, mod));
            y.set(7, mod);
            ASSERT_EQ(9ULL, multiplyUintModLazy(7, y, mod));
            ASSERT_EQ(2ULL, multiplyUintModLazy(6, y, mod));

            mod = 2305843009211596801ULL;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyUintModLazy(0, y, mod));
            ASSERT_EQ(0ULL, multiplyUintModLazy(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyUintModLazy(0, y, mod));
            ASSERT_EQ(1ULL, multiplyUintModLazy(1, y, mod));
            y.set(1152921504605798400ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiplyUintModLazy(1152921504605798401ULL, y, mod));
            y.set(1152921504605798401ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiplyUintModLazy(1152921504605798400ULL, y, mod));
            ASSERT_EQ(1729382256908697601ULL, multiplyUintModLazy(1152921504605798401ULL, y, mod));
            y.set(2305843009211596800ULL, mod);
            ASSERT_EQ(2305843009211596802ULL, multiplyUintModLazy(2305843009211596800ULL, y, mod));
        }

        TEST(UIntArithSmallMod, MultiplyAddMod2)
        {
            Modulus mod(7);
            MultiplyUIntModOperand y;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, y, 0, mod));
            ASSERT_EQ(0ULL, multiplyAddUintMod(1, y, 0, mod));
            ASSERT_EQ(1ULL, multiplyAddUintMod(0, 0, 1, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, y, 0, mod));
            y.set(4, mod);
            ASSERT_EQ(3ULL, multiplyAddUintMod(3, y, 5, mod));

            mod = 0x1FFFFFFFFFFFFFFFULL;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, y, 0, mod));
            ASSERT_EQ(0ULL, multiplyAddUintMod(1, y, 0, mod));
            ASSERT_EQ(1ULL, multiplyAddUintMod(0, y, 1, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiplyAddUintMod(0, y, 0, mod));
            y.set(mod.value() - 1, mod);
            ASSERT_EQ(0ULL, multiplyAddUintMod(mod.value() - 1, y, mod.value() - 1, mod));
        }
    } // namespace util
} // namespace sealtest
