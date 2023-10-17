// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/utils/common.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace troy;
using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(Common, Constants)
        {
            ASSERT_EQ(4, bitsPerNibble);
            ASSERT_EQ(8, bitsPerByte);
            ASSERT_EQ(8, bytesPerUint64);
            ASSERT_EQ(64, bitsPerUint64);
            ASSERT_EQ(2, nibblesPerByte);
            ASSERT_EQ(16, nibblesPerUint64);
        }

        TEST(Common, UnsignedComparisons)
        {
            int pos_i = 5;
            int neg_i = -5;
            unsigned pos_u = 6;
            signed pos_s = 6;
            unsigned char pos_uc = 1;
            signed char neg_sc = -1;
            signed char pos_sc = 1;
            unsigned char pos_uc_max = 0xFF;
            unsigned long long pos_ull = 1;
            unsigned long long pos_ull_max = 0xFFFFFFFFFFFFFFFF;
            long long neg_ull = -1;

            ASSERT_TRUE(unsigned_eq(pos_i, pos_i));
            ASSERT_FALSE(unsigned_eq(pos_i, neg_i));
            // ASSERT_TRUE(unsigned_gt(pos_u, pos_i));
            ASSERT_TRUE(unsigned_lt(pos_i, neg_i));
            // ASSERT_TRUE(unsigned_geq(pos_u, pos_s));
            // ASSERT_TRUE(unsigned_gt(neg_sc, pos_sc));
            // ASSERT_TRUE(unsigned_geq(neg_sc, pos_sc));
            ASSERT_FALSE(unsigned_eq(neg_sc, pos_sc));
            // ASSERT_FALSE(unsigned_gt(pos_u, neg_sc));
            ASSERT_TRUE(unsigned_eq(pos_uc, pos_sc));
            // ASSERT_TRUE(unsigned_geq(pos_uc, pos_sc));
            // ASSERT_TRUE(unsigned_leq(pos_uc, pos_sc));
            ASSERT_TRUE(unsigned_lt(pos_uc_max, neg_sc));
            ASSERT_TRUE(unsigned_eq(neg_sc, pos_ull_max));
            ASSERT_TRUE(unsigned_eq(neg_ull, pos_ull_max));
            ASSERT_FALSE(unsigned_lt(neg_ull, pos_ull_max));
            ASSERT_TRUE(unsigned_lt(pos_ull, pos_ull_max));
        }

        TEST(Common, SafeArithmetic)
        {
            int pos_i = 5;
            int neg_i = -5;
            unsigned pos_u = 6;
            unsigned char pos_uc_max = 0xFF;
            unsigned long long pos_ull_max = 0xFFFFFFFFFFFFFFFF;
            long long neg_ull = -1;
            unsigned long long res_ul;
            long long res_l;

            ASSERT_EQ(25, mul_safe(pos_i, pos_i));
            ASSERT_EQ(25, mul_safe(neg_i, neg_i));
            ASSERT_EQ(10, add_safe(pos_i, pos_i));
            ASSERT_EQ(-10, add_safe(neg_i, neg_i));
            ASSERT_EQ(0, add_safe(pos_i, neg_i));
            ASSERT_EQ(0, add_safe(neg_i, pos_i));
            ASSERT_EQ(10, sub_safe(pos_i, neg_i));
            ASSERT_EQ(-10, sub_safe(neg_i, pos_i));
            ASSERT_EQ(unsigned(0), sub_safe(pos_u, pos_u));
            ASSERT_THROW(res_ul = sub_safe(unsigned(0), pos_u), logic_error);
            ASSERT_THROW(res_ul = sub_safe(unsigned(4), pos_u), logic_error);
            ASSERT_THROW(res_ul = add_safe(pos_uc_max, (unsigned char)1), logic_error);
            ASSERT_TRUE(pos_uc_max == add_safe(pos_uc_max, (unsigned char)0));
            ASSERT_THROW(res_ul = mul_safe(pos_ull_max, pos_ull_max), logic_error);
            ASSERT_EQ(0ULL, mul_safe(0ULL, pos_ull_max));
            ASSERT_TRUE((long long)1 == mul_safe(neg_ull, neg_ull));
            ASSERT_THROW(res_ul = mul_safe(pos_uc_max, pos_uc_max), logic_error);
            // ASSERT_EQ(15, add_safe(pos_i, -pos_i, pos_i, pos_i, pos_i));
            // ASSERT_EQ(6, add_safe(0, -pos_i, pos_i, 1, pos_i));
            // ASSERT_EQ(0, mul_safe(pos_i, pos_i, pos_i, 0, pos_i));
            // ASSERT_EQ(625, mul_safe(pos_i, pos_i, pos_i, pos_i));
            // ASSERT_THROW(
            //     res_l = mul_safe(
            //         pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i),
            //     logic_error);
        }

        TEST(Common, FitsIn)
        {
            // int neg_i = -5;
            // signed pos_s = 6;
            // unsigned char pos_uc = 1;
            // unsigned char pos_uc_max = 0xFF;
            // float f = 1.234f;
            // double d = -1234;

            // ASSERT_TRUE(fitsIn<unsigned>(pos_s));
            // ASSERT_TRUE(fitsIn<signed char>(pos_uc));
            // ASSERT_FALSE(fitsIn<unsigned>(neg_i));
            // ASSERT_FALSE(fitsIn<signed char>(pos_uc_max));
            // ASSERT_TRUE(fitsIn<float>(d));
            // ASSERT_TRUE(fitsIn<double>(f));
            // ASSERT_TRUE(fitsIn<int>(d));
            // ASSERT_TRUE(fitsIn<unsigned>(f));
            // ASSERT_FALSE(fitsIn<unsigned>(d));
        }

        TEST(Common, DivideRoundUp)
        {
            ASSERT_EQ(0, divideRoundUp(0, 4));
            ASSERT_EQ(1, divideRoundUp(1, 4));
            ASSERT_EQ(1, divideRoundUp(2, 4));
            ASSERT_EQ(1, divideRoundUp(3, 4));
            ASSERT_EQ(1, divideRoundUp(4, 4));
            ASSERT_EQ(2, divideRoundUp(5, 4));
            ASSERT_EQ(2, divideRoundUp(6, 4));
            ASSERT_EQ(2, divideRoundUp(7, 4));
            ASSERT_EQ(2, divideRoundUp(8, 4));
            ASSERT_EQ(3, divideRoundUp(9, 4));
            ASSERT_EQ(3, divideRoundUp(12, 4));
            ASSERT_EQ(4, divideRoundUp(13, 4));
        }

        // TEST(Common, HammingWeight)
        // {
        //     ASSERT_EQ(0, hamming_weight(0));
        //     ASSERT_EQ(8, hamming_weight(0xFF));
        //     ASSERT_EQ(4, hamming_weight(0xF0));
        //     ASSERT_EQ(4, hamming_weight(0x0F));
        //     ASSERT_EQ(2, hamming_weight(0xC0));
        //     ASSERT_EQ(2, hamming_weight(0x0C));
        //     ASSERT_EQ(2, hamming_weight(0x03));
        //     ASSERT_EQ(2, hamming_weight(0x30));
        //     ASSERT_EQ(4, hamming_weight(0xAA));
        //     ASSERT_EQ(4, hamming_weight(0x55));
        //     ASSERT_EQ(5, hamming_weight(0xD6));
        //     ASSERT_EQ(5, hamming_weight(0x6D));
        //     ASSERT_EQ(7, hamming_weight(0xBF));
        //     ASSERT_EQ(7, hamming_weight(0xFB));
        // }

        void ReverseBits32Helper()
        {
            ASSERT_EQ(static_cast<uint32_t>(0), reverseBits(static_cast<uint32_t>(0)));
            ASSERT_EQ(static_cast<uint32_t>(0x80000000), reverseBits(static_cast<uint32_t>(1)));
            ASSERT_EQ(static_cast<uint32_t>(0x40000000), reverseBits(static_cast<uint32_t>(2)));
            ASSERT_EQ(static_cast<uint32_t>(0xC0000000), reverseBits(static_cast<uint32_t>(3)));
            ASSERT_EQ(static_cast<uint32_t>(0x00010000), reverseBits(static_cast<uint32_t>(0x00008000)));
            ASSERT_EQ(static_cast<uint32_t>(0xFFFF0000), reverseBits(static_cast<uint32_t>(0x0000FFFF)));
            ASSERT_EQ(static_cast<uint32_t>(0x0000FFFF), reverseBits(static_cast<uint32_t>(0xFFFF0000)));
            ASSERT_EQ(static_cast<uint32_t>(0x00008000), reverseBits(static_cast<uint32_t>(0x00010000)));
            ASSERT_EQ(static_cast<uint32_t>(3), reverseBits(static_cast<uint32_t>(0xC0000000)));
            ASSERT_EQ(static_cast<uint32_t>(2), reverseBits(static_cast<uint32_t>(0x40000000)));
            ASSERT_EQ(static_cast<uint32_t>(1), reverseBits(static_cast<uint32_t>(0x80000000)));
            ASSERT_EQ(static_cast<uint32_t>(0xFFFFFFFF), reverseBits(static_cast<uint32_t>(0xFFFFFFFF)));

            // Reversing a 0-bit item should return 0
            ASSERT_EQ(static_cast<uint32_t>(0), reverseBits(static_cast<uint32_t>(0xFFFFFFFF), 0));

            // Reversing a 32-bit item returns is same as normal reverse
            ASSERT_EQ(static_cast<uint32_t>(0), reverseBits(static_cast<uint32_t>(0), 32));
            ASSERT_EQ(static_cast<uint32_t>(0x80000000), reverseBits(static_cast<uint32_t>(1), 32));
            ASSERT_EQ(static_cast<uint32_t>(0x40000000), reverseBits(static_cast<uint32_t>(2), 32));
            ASSERT_EQ(static_cast<uint32_t>(0xC0000000), reverseBits(static_cast<uint32_t>(3), 32));
            ASSERT_EQ(static_cast<uint32_t>(0x00010000), reverseBits(static_cast<uint32_t>(0x00008000), 32));
            ASSERT_EQ(static_cast<uint32_t>(0xFFFF0000), reverseBits(static_cast<uint32_t>(0x0000FFFF), 32));
            ASSERT_EQ(static_cast<uint32_t>(0x0000FFFF), reverseBits(static_cast<uint32_t>(0xFFFF0000), 32));
            ASSERT_EQ(static_cast<uint32_t>(0x00008000), reverseBits(static_cast<uint32_t>(0x00010000), 32));
            ASSERT_EQ(static_cast<uint32_t>(3), reverseBits(static_cast<uint32_t>(0xC0000000), 32));
            ASSERT_EQ(static_cast<uint32_t>(2), reverseBits(static_cast<uint32_t>(0x40000000), 32));
            ASSERT_EQ(static_cast<uint32_t>(1), reverseBits(static_cast<uint32_t>(0x80000000), 32));
            ASSERT_EQ(static_cast<uint32_t>(0xFFFFFFFF), reverseBits(static_cast<uint32_t>(0xFFFFFFFF), 32));

            // 16-bit reversal
            ASSERT_EQ(static_cast<uint32_t>(0), reverseBits(static_cast<uint32_t>(0), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x00008000), reverseBits(static_cast<uint32_t>(1), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x00004000), reverseBits(static_cast<uint32_t>(2), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x0000C000), reverseBits(static_cast<uint32_t>(3), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x00000001), reverseBits(static_cast<uint32_t>(0x00008000), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x0000FFFF), reverseBits(static_cast<uint32_t>(0x0000FFFF), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x00000000), reverseBits(static_cast<uint32_t>(0xFFFF0000), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x00000000), reverseBits(static_cast<uint32_t>(0x00010000), 16));
            ASSERT_EQ(static_cast<uint32_t>(3), reverseBits(static_cast<uint32_t>(0x0000C000), 16));
            ASSERT_EQ(static_cast<uint32_t>(2), reverseBits(static_cast<uint32_t>(0x00004000), 16));
            ASSERT_EQ(static_cast<uint32_t>(1), reverseBits(static_cast<uint32_t>(0x00008000), 16));
            ASSERT_EQ(static_cast<uint32_t>(0x0000FFFF), reverseBits(static_cast<uint32_t>(0xFFFFFFFF), 16));
        }

        TEST(Common, ReverseBits32)
        {
            ReverseBits32Helper();

            // Other types
            // SEAL_IF_CONSTEXPR(sizeof(unsigned) == 4)
            // ReverseBits32Helper<unsigned>();

            // SEAL_IF_CONSTEXPR(sizeof(unsigned long) == 4)
            // ReverseBits32Helper<unsigned long>();

            // SEAL_IF_CONSTEXPR(sizeof(unsigned long long) == 4)
            // ReverseBits32Helper<unsigned long long>();

            // SEAL_IF_CONSTEXPR(sizeof(size_t) == 4)
            // ReverseBits32Helper<size_t>();
        }

        void ReverseBits64Helper()
        {

            ASSERT_EQ(0ULL, reverseBits(0ULL));
            ASSERT_EQ(1ULL << 63, reverseBits(1ULL));
            ASSERT_EQ(1ULL << 32, reverseBits(1ULL << 31));
            ASSERT_EQ(0xFFFFULL << 32, reverseBits(0xFFFFULL << 16));
            ASSERT_EQ(0x0000FFFFFFFF0000ULL, reverseBits(0x0000FFFFFFFF0000ULL));
            ASSERT_EQ(0x0000FFFF0000FFFFULL, reverseBits(0xFFFF0000FFFF0000ULL));

            ASSERT_EQ(0ULL, reverseBits(0ULL, 0));
            ASSERT_EQ(0ULL, reverseBits(0ULL, 1));
            ASSERT_EQ(0ULL, reverseBits(0ULL, 32));
            ASSERT_EQ(0ULL, reverseBits(0ULL, 64));

            ASSERT_EQ(0ULL, reverseBits(1ULL, 0));
            ASSERT_EQ(1ULL, reverseBits(1ULL, 1));
            ASSERT_EQ(1ULL << 31, reverseBits(1ULL, 32));
            ASSERT_EQ(1ULL << 63, reverseBits(1ULL, 64));

            ASSERT_EQ(0ULL, reverseBits(1ULL << 31, 0));
            ASSERT_EQ(0ULL, reverseBits(1ULL << 31, 1));
            ASSERT_EQ(1ULL, reverseBits(1ULL << 31, 32));
            ASSERT_EQ(1ULL << 32, reverseBits(1ULL << 31, 64));

            ASSERT_EQ(0ULL, reverseBits(0xFFFFULL << 16, 0));
            ASSERT_EQ(0ULL, reverseBits(0xFFFFULL << 16, 1));
            ASSERT_EQ(0xFFFFULL, reverseBits(0xFFFFULL << 16, 32));
            ASSERT_EQ(0xFFFFULL << 32, reverseBits(0xFFFFULL << 16, 64));

            ASSERT_EQ(0ULL, reverseBits(0x0000FFFFFFFF0000ULL, 0));
            ASSERT_EQ(0ULL, reverseBits(0x0000FFFFFFFF0000ULL, 1));
            ASSERT_EQ(0xFFFFULL, reverseBits(0x0000FFFFFFFF0000ULL, 32));
            ASSERT_EQ(0x0000FFFFFFFF0000ULL, reverseBits(0x0000FFFFFFFF0000ULL, 64));

            ASSERT_EQ(0ULL, reverseBits(0xFFFF0000FFFF0000ULL, 0));
            ASSERT_EQ(0ULL, reverseBits(0xFFFF0000FFFF0000ULL, 1));
            ASSERT_EQ(0xFFFFULL, reverseBits(0xFFFF0000FFFF0000ULL, 32));
            ASSERT_EQ(0x0000FFFF0000FFFFULL, reverseBits(0xFFFF0000FFFF0000ULL, 64));
        }

        TEST(Common, ReverseBits64)
        {
            ReverseBits64Helper();

            // Other types
            // SEAL_IF_CONSTEXPR(sizeof(unsigned) == 8)
            // ReverseBits64Helper<unsigned>();

            // SEAL_IF_CONSTEXPR(sizeof(unsigned long) == 8)
            // ReverseBits64Helper<unsigned long>();

            // SEAL_IF_CONSTEXPR(sizeof(unsigned long long) == 8)
            // ReverseBits64Helper<unsigned long long>();

            // SEAL_IF_CONSTEXPR(sizeof(size_t) == 8)
            // ReverseBits64Helper<size_t>();
        }

        TEST(Common, GetSignificantBitCount)
        {
            ASSERT_EQ(0, getSignificantBitCount(0));
            ASSERT_EQ(1, getSignificantBitCount(1));
            ASSERT_EQ(2, getSignificantBitCount(2));
            ASSERT_EQ(2, getSignificantBitCount(3));
            ASSERT_EQ(3, getSignificantBitCount(4));
            ASSERT_EQ(3, getSignificantBitCount(5));
            ASSERT_EQ(3, getSignificantBitCount(6));
            ASSERT_EQ(3, getSignificantBitCount(7));
            ASSERT_EQ(4, getSignificantBitCount(8));
            ASSERT_EQ(63, getSignificantBitCount(0x7000000000000000));
            ASSERT_EQ(63, getSignificantBitCount(0x7FFFFFFFFFFFFFFF));
            ASSERT_EQ(64, getSignificantBitCount(0x8000000000000000));
            ASSERT_EQ(64, getSignificantBitCount(0xFFFFFFFFFFFFFFFF));
        }

        // TEST(Common, GetMSBIndexGeneric)
        // {
        //     unsigned long result;
        //     get_msb_index_generic(&result, 1);
        //     ASSERT_EQ(static_cast<unsigned long>(0), result);
        //     get_msb_index_generic(&result, 2);
        //     ASSERT_EQ(static_cast<unsigned long>(1), result);
        //     get_msb_index_generic(&result, 3);
        //     ASSERT_EQ(static_cast<unsigned long>(1), result);
        //     get_msb_index_generic(&result, 4);
        //     ASSERT_EQ(static_cast<unsigned long>(2), result);
        //     get_msb_index_generic(&result, 16);
        //     ASSERT_EQ(static_cast<unsigned long>(4), result);
        //     get_msb_index_generic(&result, 0xFFFFFFFF);
        //     ASSERT_EQ(static_cast<unsigned long>(31), result);
        //     get_msb_index_generic(&result, 0x100000000);
        //     ASSERT_EQ(static_cast<unsigned long>(32), result);
        //     get_msb_index_generic(&result, 0xFFFFFFFFFFFFFFFF);
        //     ASSERT_EQ(static_cast<unsigned long>(63), result);
        // }
    } // namespace util
} // namespace sealtest
