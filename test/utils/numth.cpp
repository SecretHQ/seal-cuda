// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/utils/numth.h"
#include "../../src/utils/uintarith.h"
#include "../../src/utils/uintarithsmallmod.h"
#include <cstdint>
#include <numeric>
#include "gtest/gtest.h"

using namespace troy;
using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(NumberTheory, GCD)
        {
            ASSERT_EQ(1ULL, gcd(1, 1));
            ASSERT_EQ(1ULL, gcd(2, 1));
            ASSERT_EQ(1ULL, gcd(1, 2));
            ASSERT_EQ(2ULL, gcd(2, 2));
            ASSERT_EQ(3ULL, gcd(6, 15));
            ASSERT_EQ(3ULL, gcd(15, 6));
            ASSERT_EQ(1ULL, gcd(7, 15));
            ASSERT_EQ(1ULL, gcd(15, 7));
            ASSERT_EQ(1ULL, gcd(7, 15));
            ASSERT_EQ(3ULL, gcd(11112, 44445));
        }

        TEST(NumberTheory, ExtendedGCD)
        {
            tuple<uint64_t, int64_t, int64_t> result;

            // Corner case behavior
            result = xgcd(7, 7);
            ASSERT_TRUE(result == make_tuple<>(7, 0, 1));
            result = xgcd(2, 2);
            ASSERT_TRUE(result == make_tuple<>(2, 0, 1));

            result = xgcd(1, 1);
            ASSERT_TRUE(result == make_tuple<>(1, 0, 1));
            result = xgcd(1, 2);
            ASSERT_TRUE(result == make_tuple<>(1, 1, 0));
            result = xgcd(5, 6);
            ASSERT_TRUE(result == make_tuple<>(1, -1, 1));
            result = xgcd(13, 19);
            ASSERT_TRUE(result == make_tuple<>(1, 3, -2));
            result = xgcd(14, 21);
            ASSERT_TRUE(result == make_tuple<>(7, -1, 1));

            result = xgcd(2, 1);
            ASSERT_TRUE(result == make_tuple<>(1, 0, 1));
            result = xgcd(6, 5);
            ASSERT_TRUE(result == make_tuple<>(1, 1, -1));
            result = xgcd(19, 13);
            ASSERT_TRUE(result == make_tuple<>(1, -2, 3));
            result = xgcd(21, 14);
            ASSERT_TRUE(result == make_tuple<>(7, 1, -1));
        }

        TEST(NumberTheory, TryInvertUIntMod)
        {
            uint64_t input, modulus, result;

            input = 1, modulus = 2;
            ASSERT_TRUE(tryInvertUintMod(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 2, modulus = 2;
            ASSERT_FALSE(tryInvertUintMod(input, modulus, result));

            input = 3, modulus = 2;
            ASSERT_TRUE(tryInvertUintMod(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 0xFFFFFF, modulus = 2;
            ASSERT_TRUE(tryInvertUintMod(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 0xFFFFFE, modulus = 2;
            ASSERT_FALSE(tryInvertUintMod(input, modulus, result));

            input = 12345, modulus = 3;
            ASSERT_FALSE(tryInvertUintMod(input, modulus, result));

            input = 5, modulus = 19;
            ASSERT_TRUE(tryInvertUintMod(input, modulus, result));
            ASSERT_EQ(result, 4ULL);

            input = 4, modulus = 19;
            ASSERT_TRUE(tryInvertUintMod(input, modulus, result));
            ASSERT_EQ(result, 5ULL);
        }

        TEST(NumberTheory, IsPrime)
        {
            ASSERT_FALSE(isPrime(0));
            ASSERT_TRUE(isPrime(2));
            ASSERT_TRUE(isPrime(3));
            ASSERT_FALSE(isPrime(4));
            ASSERT_TRUE(isPrime(5));
            ASSERT_FALSE(isPrime(221));
            ASSERT_TRUE(isPrime(65537));
            ASSERT_FALSE(isPrime(65536));
            ASSERT_TRUE(isPrime(59399));
            ASSERT_TRUE(isPrime(72307));
            ASSERT_FALSE(isPrime(72307ULL * 59399ULL));
            ASSERT_TRUE(isPrime(36893488147419103ULL));
            ASSERT_FALSE(isPrime(36893488147419107ULL));
        }

        TEST(NumberTheory, NAF)
        {
            auto naf_vec = naf(0);
            ASSERT_EQ(0, naf_vec.size());

            naf_vec = naf(1);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(1, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-1);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(-1, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(2);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(2, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-2);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(-2, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(3);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(3, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-3);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(-3, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(127);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(127, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-127);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(-127, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(123);
            ASSERT_EQ(123, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-123);
            ASSERT_EQ(-123, accumulate(naf_vec.begin(), naf_vec.end(), 0));
        }

        TEST(NumberTheory, TryPrimitiveRootMod)
        {
            uint64_t result;
            Modulus mod(11);

            ASSERT_TRUE(tryPrimitiveRoot(2, mod, result));
            ASSERT_EQ(10ULL, result);

            mod = 29;
            ASSERT_TRUE(tryPrimitiveRoot(2, mod, result));
            ASSERT_EQ(28ULL, result);

            vector<uint64_t> corrects{ 12, 17 };
            ASSERT_TRUE(tryPrimitiveRoot(4, mod, result));
            ASSERT_TRUE(find(corrects.begin(), corrects.end(), result) != corrects.end());

            mod = 1234565441;
            ASSERT_TRUE(tryPrimitiveRoot(2, mod, result));
            ASSERT_EQ(1234565440ULL, result);
            corrects = { 984839708, 273658408, 249725733, 960907033 };
            ASSERT_TRUE(tryPrimitiveRoot(8, mod, result));
            ASSERT_TRUE(find(corrects.begin(), corrects.end(), result) != corrects.end());
        }

        TEST(NumberTheory, IsPrimitiveRootMod)
        {
            Modulus mod(11);
            ASSERT_TRUE(isPrimitiveRoot(10, 2, mod));
            ASSERT_FALSE(isPrimitiveRoot(9, 2, mod));
            ASSERT_FALSE(isPrimitiveRoot(10, 4, mod));

            mod = 29;
            ASSERT_TRUE(isPrimitiveRoot(28, 2, mod));
            ASSERT_TRUE(isPrimitiveRoot(12, 4, mod));
            ASSERT_FALSE(isPrimitiveRoot(12, 2, mod));
            ASSERT_FALSE(isPrimitiveRoot(12, 8, mod));

            mod = 1234565441ULL;
            ASSERT_TRUE(isPrimitiveRoot(1234565440ULL, 2, mod));
            ASSERT_TRUE(isPrimitiveRoot(960907033ULL, 8, mod));
            ASSERT_TRUE(isPrimitiveRoot(1180581915ULL, 16, mod));
            ASSERT_FALSE(isPrimitiveRoot(1180581915ULL, 32, mod));
            ASSERT_FALSE(isPrimitiveRoot(1180581915ULL, 8, mod));
            ASSERT_FALSE(isPrimitiveRoot(1180581915ULL, 2, mod));
        }

        TEST(NumberTheory, TryMinimalPrimitiveRootMod)
        {
            Modulus mod(11);

            uint64_t result;
            ASSERT_TRUE(tryMinimalPrimitiveRoot(2, mod, result));
            ASSERT_EQ(10ULL, result);

            mod = 29;
            ASSERT_TRUE(tryMinimalPrimitiveRoot(2, mod, result));
            ASSERT_EQ(28ULL, result);
            ASSERT_TRUE(tryMinimalPrimitiveRoot(4, mod, result));
            ASSERT_EQ(12ULL, result);

            mod = 1234565441;
            ASSERT_TRUE(tryMinimalPrimitiveRoot(2, mod, result));
            ASSERT_EQ(1234565440ULL, result);
            ASSERT_TRUE(tryMinimalPrimitiveRoot(8, mod, result));
            ASSERT_EQ(249725733ULL, result);
        }
    } // namespace util
} // namespace sealtest
