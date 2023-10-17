// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/utils/uintarith.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(UIntArith, AddUInt64Generic)
        {
            uint64_t result;
            ASSERT_FALSE(addUint64(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(addUint64(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_TRUE(addUint64(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(addUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_FALSE(addUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_TRUE(addUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0x0ULL, result);
        }

// #if SEAL_COMPILER == SEAL_COMPILER_MSVC
// #pragma optimize("", off)
// #elif SEAL_COMPILER == SEAL_COMPILER_GCC
// #pragma GCC push_options
// #pragma GCC optimize("O0")
// #elif SEAL_COMPILER == SEAL_COMPILER_CLANG
// #pragma clang optimize off
// #endif

        TEST(UIntArith, AddUInt64)
        {
            uint64_t result;
            ASSERT_FALSE(addUint64(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(addUint64(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_TRUE(addUint64(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(addUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_FALSE(addUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_TRUE(addUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0x0ULL, result);

            ASSERT_FALSE(addUint64(0ULL, 0ULL, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 1ULL, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(addUint64(1ULL, 0ULL, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_FALSE(addUint64(0ULL, 1ULL, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(addUint64(0xFFFFFFFFFFFFFFFFULL, 1ULL, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(addUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(addUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
        }

// #if SEAL_COMPILER == SEAL_COMPILER_MSVC
// #pragma optimize("", on)
// #elif SEAL_COMPILER == SEAL_COMPILER_GCC
// #pragma GCC pop_options
// #elif SEAL_COMPILER == SEAL_COMPILER_CLANG
// #pragma clang optimize on
// #endif

        TEST(UIntArith, SubUInt64Generic)
        {
            uint64_t result;
            ASSERT_FALSE(subUint64(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(subUint64(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(subUint64(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(subUint64(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(subUint64(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_FALSE(subUint64(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(subUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_TRUE(subUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(subUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(4ULL, result);
            ASSERT_TRUE(subUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_FALSE(subUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xE01E01E01E01E01FULL, result);
            ASSERT_FALSE(subUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0xE01E01E01E01E01EULL, result);
        }

        TEST(UIntArith, SubUInt64)
        {
            uint64_t result;
            ASSERT_FALSE(subUint64(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(subUint64(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(subUint64(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(subUint64(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(subUint64(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_FALSE(subUint64(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(subUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_TRUE(subUint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(subUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(4ULL, result);
            ASSERT_TRUE(subUint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_FALSE(subUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xE01E01E01E01E01FULL, result);
            ASSERT_FALSE(subUint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0xE01E01E01E01E01EULL, result);
        }

        TEST(UIntArith, AddUInt128)
        {
            auto setUint128 = [](uint64_t *destination, uint64_t val0, uint64_t val1) {
                destination[0] = val0;
                destination[1] = val1;
            };

            auto assertUint128_eq = [](uint64_t *test, uint64_t expect0,
                                        uint64_t expect1) {
                ASSERT_EQ(expect0, test[0]);
                ASSERT_EQ(expect1, test[1]);
            };

            uint64_t operand1[2]{ 0, 0 };
            uint64_t operand2[2]{ 0, 0 };
            uint64_t result[2]{ 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
            ASSERT_FALSE(addUint128(operand1, operand2, result));
            ASSERT_EQ(0, result[0] | result[1]);

            setUint128(operand1, 1, 1);
            setUint128(operand2, 1, 1);
            ASSERT_FALSE(addUint128(operand1, operand2, result));
            assertUint128_eq(result, 2, 2);

            setUint128(operand1, 0xFFFFFFFFFFFFFFFFULL, 0);
            setUint128(operand2, 1, 0);
            ASSERT_FALSE(addUint128(operand1, operand2, result));
            assertUint128_eq(result, 0, 1);

            setUint128(operand1, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
            setUint128(operand2, 1, 0);
            ASSERT_TRUE(addUint128(operand1, operand2, result));
            assertUint128_eq(result, 0, 0);
        }

        TEST(UIntArith, AddUInt)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            auto ptr3 = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_FALSE(addUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(addUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFE;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(addUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_TRUE(addUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;

            ASSERT_TRUE(addUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_TRUE(addUint(ptr.get(), ptr2.get(), 2, ptr.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(addUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(1ULL, ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 5;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(addUint(ptr.get(), 2, ptr2.get(), 1, false, 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(6), ptr3[1]);
            ASSERT_FALSE(addUint(ptr.get(), 2, ptr2.get(), 1, true, 2, ptr3.get()) != 0);
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(6), ptr3[1]);
        }

        TEST(UIntArith, SubUInt)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            auto ptr3 = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_FALSE(subUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(subUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(subUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_TRUE(subUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_TRUE(subUint(ptr.get(), ptr2.get(), 2, ptr.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(subUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_FALSE(subUint(ptr.get(), ptr2.get(), 2, ptr.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFE;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_TRUE(subUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 1;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(subUint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 1;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(subUint(ptr.get(), 2, ptr2.get(), 1, false, 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_FALSE(subUint(ptr.get(), 2, ptr2.get(), 1, true, 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
        }

        TEST(UIntArith, AddUIntUInt64)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);

            ptr[0] = 0ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(addUint(ptr.get(), 2, 0ULL, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(addUint(ptr.get(), 2, 0xFFFFFFFFULL, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0xFFFFFFFF00000000ULL;
            ASSERT_FALSE(addUint(ptr.get(), 2, 0x100000000ULL, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFF00000001ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFFULL;
            ptr[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_TRUE(addUint(ptr.get(), 2, 1ULL, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);
        }

        TEST(UIntArith, SubUIntUInt64)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);

            ptr[0] = 0ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(subUint(ptr.get(), 2, 0ULL, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0ULL;
            ptr[1] = 0ULL;
            ASSERT_TRUE(subUint(ptr.get(), 2, 1ULL, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[1]);

            ptr[0] = 1ULL;
            ptr[1] = 0ULL;
            ASSERT_TRUE(subUint(ptr.get(), 2, 2ULL, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(subUint(ptr.get(), 2, 0xFFFFFFFFULL, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFE00000001ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0xFFFFFFFF00000000ULL;
            ASSERT_FALSE(subUint(ptr.get(), 2, 0x100000000ULL, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFE00000000ULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFF00000000ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFFULL;
            ptr[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_FALSE(subUint(ptr.get(), 2, 1ULL, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[1]);
        }

        TEST(UIntArith, IncrementUInt)
        {
            
            auto ptr1 = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            ptr1[0] = 0;
            ptr1[1] = 0;
            ASSERT_FALSE(incrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_FALSE(incrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 0;
            ASSERT_FALSE(incrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(1ULL, ptr2[1]);
            ASSERT_FALSE(incrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(1ULL, ptr1[0]);
            ASSERT_EQ(1ULL, ptr1[1]);

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 1;
            ASSERT_FALSE(incrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[1]);
            ASSERT_FALSE(incrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(1ULL, ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr1[1]);

            ptr1[0] = 0xFFFFFFFFFFFFFFFE;
            ptr1[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_FALSE(incrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[1]);
            ASSERT_TRUE(incrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);
            ASSERT_FALSE(incrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
        }

        TEST(UIntArith, DecrementUInt)
        {
            
            auto ptr1 = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            ptr1[0] = 2;
            ptr1[1] = 2;
            ASSERT_FALSE(decrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[1]);
            ASSERT_FALSE(decrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr1[1]);
            ASSERT_FALSE(decrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(1ULL, ptr2[1]);
            ASSERT_FALSE(decrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr1[0]);
            ASSERT_EQ(1ULL, ptr1[1]);

            ptr1[0] = 2;
            ptr1[1] = 1;
            ASSERT_FALSE(decrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(1ULL, ptr2[1]);
            ASSERT_FALSE(decrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(1ULL, ptr1[1]);
            ASSERT_FALSE(decrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_FALSE(decrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);

            ptr1[0] = 2;
            ptr1[1] = 0;
            ASSERT_FALSE(decrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_FALSE(decrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);
            ASSERT_TRUE(decrementUint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[1]);
            ASSERT_FALSE(decrementUint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr1[1]);
        }

        TEST(UIntArith, NegateUInt)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 1;
            ptr[1] = 0;
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 2;
            ptr[1] = 0;
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0;
            ptr[1] = 1;
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(1ULL, ptr[1]);

            ptr[0] = 0;
            ptr[1] = 2;
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[1]);
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[1]);

            ptr[0] = 1;
            ptr[1] = 1;
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[1]);
            negateUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(1ULL, ptr[1]);
        }

        TEST(UIntArith, LeftShiftUInt)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            leftShiftUint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            leftShiftUint(ptr.get(), 10, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            leftShiftUint(ptr.get(), 10, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            leftShiftUint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            leftShiftUint(ptr.get(), 0, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            leftShiftUint(ptr.get(), 1, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[1]);
            leftShiftUint(ptr.get(), 2, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr2[1]);
            leftShiftUint(ptr.get(), 64, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            leftShiftUint(ptr.get(), 65, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            leftShiftUint(ptr.get(), 127, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[1]);

            leftShiftUint(ptr.get(), 2, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[1]);
            leftShiftUint(ptr.get(), 64, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[1]);
        }

        TEST(UIntArith, LeftShiftUInt128)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            leftShiftUint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            leftShiftUint128(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            leftShiftUint128(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            leftShiftUint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            leftShiftUint128(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            leftShiftUint128(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[1]);
            leftShiftUint128(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr2[1]);
            leftShiftUint128(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            leftShiftUint128(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            leftShiftUint128(ptr.get(), 127, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[1]);

            leftShiftUint128(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[1]);
            leftShiftUint128(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[1]);
        }

        TEST(UIntArith, LeftShiftUInt192)
        {
            
            auto ptr = HostArray<uint64_t>(3);
            auto ptr2 = HostArray<uint64_t>(3);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr[2] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            leftShiftUint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            leftShiftUint192(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            leftShiftUint192(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            ptr[2] = 0xCDCDCDCDCDCDCDCD;
            leftShiftUint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr2[2]);
            leftShiftUint192(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr[2]);
            leftShiftUint192(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x9B9B9B9B9B9B9B9B), ptr2[2]);
            leftShiftUint192(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3737373737373736), ptr2[2]);
            leftShiftUint192(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[2]);
            leftShiftUint192(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[2]);
            leftShiftUint192(ptr.get(), 191, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[2]);

            leftShiftUint192(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3737373737373736), ptr[2]);

            leftShiftUint192(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[2]);
        }

        TEST(UIntArith, RightShiftUInt)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            rightShiftUint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            rightShiftUint(ptr.get(), 10, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            rightShiftUint(ptr.get(), 10, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            rightShiftUint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            rightShiftUint(ptr.get(), 0, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            rightShiftUint(ptr.get(), 1, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            rightShiftUint(ptr.get(), 2, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[1]);
            rightShiftUint(ptr.get(), 64, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            rightShiftUint(ptr.get(), 65, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            rightShiftUint(ptr.get(), 127, 2, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            rightShiftUint(ptr.get(), 2, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[1]);
            rightShiftUint(ptr.get(), 64, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntArith, RightShiftUInt128)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            rightShiftUint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            rightShiftUint128(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            rightShiftUint128(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            rightShiftUint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            rightShiftUint128(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            rightShiftUint128(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            rightShiftUint128(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[1]);
            rightShiftUint128(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            rightShiftUint128(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            rightShiftUint128(ptr.get(), 127, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            rightShiftUint128(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[1]);
            rightShiftUint128(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntArith, RightShiftUInt192)
        {
            
            auto ptr = HostArray<uint64_t>(3);
            auto ptr2 = HostArray<uint64_t>(3);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr[2] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            rightShiftUint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            rightShiftUint192(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            rightShiftUint192(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            ptr[2] = 0xCDCDCDCDCDCDCDCD;

            rightShiftUint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr2[2]);
            rightShiftUint192(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr[2]);
            rightShiftUint192(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xD555555555555555), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x66E6E6E6E6E6E6E6), ptr2[2]);
            rightShiftUint192(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x6AAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3373737373737373), ptr2[2]);
            rightShiftUint192(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            rightShiftUint192(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xD555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x66E6E6E6E6E6E6E6), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            rightShiftUint192(ptr.get(), 191, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);

            rightShiftUint192(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x6AAAAAAAAAAAAAAA), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3373737373737373), ptr[2]);
            rightShiftUint192(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x6AAAAAAAAAAAAAAA), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3373737373737373), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);
        }

        TEST(UIntArith, HalfRoundUpUInt)
        {
            halfRoundUpUint(nullptr, 0, nullptr);

            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            halfRoundUpUint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            halfRoundUpUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 1;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            halfRoundUpUint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            halfRoundUpUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 2;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            halfRoundUpUint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            halfRoundUpUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 3;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            halfRoundUpUint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            ptr[0] = 4;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            halfRoundUpUint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            halfRoundUpUint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[1]);
            halfRoundUpUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr[1]);
        }

        TEST(UIntArith, NotUInt)
        {
            notUint(nullptr, 0, nullptr);

            
            auto ptr = HostArray<uint64_t>(2);
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            notUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            notUint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x00000000FFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x0000FFFF0000FFFF), ptr[1]);
        }

        TEST(UIntArith, AndUInt)
        {
            andUint(nullptr, nullptr, 0, nullptr);

            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            auto ptr3 = HostArray<uint64_t>(2);
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            andUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            ptr2[0] = 0x0000FFFF0000FFFF;
            ptr2[1] = 0xFF00FF00FF00FF00;
            ptr3[0] = 0;
            ptr3[1] = 0;
            andUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0x0000FFFF00000000), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFF000000FF000000), ptr3[1]);
            andUint(ptr.get(), ptr2.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x0000FFFF00000000), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFF000000FF000000), ptr[1]);
        }

        TEST(UIntArith, OrUInt)
        {
            orUint(nullptr, nullptr, 0, nullptr);

            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            auto ptr3 = HostArray<uint64_t>(2);
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            orUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            ptr2[0] = 0x0000FFFF0000FFFF;
            ptr2[1] = 0xFF00FF00FF00FF00;
            ptr3[0] = 0;
            ptr3[1] = 0;
            orUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFF0000FFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFF00FFFFFF00), ptr3[1]);
            orUint(ptr.get(), ptr2.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFF0000FFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFF00FFFFFF00), ptr[1]);
        }

        TEST(UIntArith, XorUInt)
        {
            xorUint(nullptr, nullptr, 0, nullptr);

            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            auto ptr3 = HostArray<uint64_t>(2);
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            xorUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            ptr2[0] = 0x0000FFFF0000FFFF;
            ptr2[1] = 0xFF00FF00FF00FF00;
            ptr3[0] = 0;
            ptr3[1] = 0;
            xorUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFF00000000FFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x00FFFF0000FFFF00), ptr3[1]);
            xorUint(ptr.get(), ptr2.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFF00000000FFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x00FFFF0000FFFF00), ptr[1]);
        }

        TEST(UIntArith, MultiplyUInt64Generic)
        {
            uint64_t result[2];

            multiplyUint64(0ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(0ULL, 1ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(1ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(1ULL, 1ULL, result);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(0x100000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xFAFABABA00000000ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(0x1000000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xAFABABA000000000ULL, result[0]);
            ASSERT_EQ(0xFULL, result[1]);
            multiplyUint64(1111222233334444ULL, 5555666677778888ULL, result);
            ASSERT_EQ(4140785562324247136ULL, result[0]);
            ASSERT_EQ(334670460471ULL, result[1]);
        }

        TEST(UIntArith, MultiplyUInt64)
        {
            uint64_t result[2];

            multiplyUint64(0ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(0ULL, 1ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(1ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(1ULL, 1ULL, result);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(0x100000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xFAFABABA00000000ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiplyUint64(0x1000000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xAFABABA000000000ULL, result[0]);
            ASSERT_EQ(0xFULL, result[1]);
            multiplyUint64(1111222233334444ULL, 5555666677778888ULL, result);
            ASSERT_EQ(4140785562324247136ULL, result[0]);
            ASSERT_EQ(334670460471ULL, result[1]);
        }

        TEST(UIntArith, MultiplyUInt64HW64Generic)
        {
            uint64_t result;

            multiplyUint64HW64(0ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(0ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(1ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(1ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(0x100000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(0x1000000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0xFULL, result);
            multiplyUint64HW64(1111222233334444ULL, 5555666677778888ULL, &result);
            ASSERT_EQ(334670460471ULL, result);
        }

        TEST(UIntArith, MultiplyUInt64HW64)
        {
            uint64_t result;

            multiplyUint64HW64(0ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(0ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(1ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(1ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(0x100000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0ULL, result);
            multiplyUint64HW64(0x1000000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0xFULL, result);
            multiplyUint64HW64(1111222233334444ULL, 5555666677778888ULL, &result);
            ASSERT_EQ(334670460471ULL, result);
        }

        TEST(UIntArith, MultiplyManyUInt64)
        {
            

            vector<uint64_t> in = { 0 };
            vector<uint64_t> out = { 0 };
            vector<uint64_t> expected = { 0 };
            multiplyManyUint64(in.data(), 1, out.data());
            ASSERT_TRUE(expected == out);

            in = { 1 };
            out = { 0 };
            expected = { 1 };
            multiplyManyUint64(in.data(), 1, out.data());
            ASSERT_TRUE(expected == out);

            in = { 0, 0, 0 };
            out = { 0, 0, 0 };
            expected = { 0, 0, 0 };
            multiplyManyUint64(in.data(), 1, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64(in.data(), 2, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64(in.data(), 3, out.data());
            ASSERT_TRUE(expected == out);

            in = { 1, 1, 1 };
            out = { 0, 0, 0 };
            expected = { 1, 0, 0 };
            multiplyManyUint64(in.data(), 1, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64(in.data(), 2, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64(in.data(), 3, out.data());
            ASSERT_TRUE(expected == out);

            in = { 10, 20, 40 };
            out = { 0, 0, 0 };
            expected = { 10, 0, 0 };
            multiplyManyUint64(in.data(), 1, out.data());
            ASSERT_TRUE(expected == out);
            expected = { 200, 0, 0 };
            multiplyManyUint64(in.data(), 2, out.data());
            ASSERT_TRUE(expected == out);
            expected = { 8000, 0, 0 };
            multiplyManyUint64(in.data(), 3, out.data());
            ASSERT_TRUE(expected == out);

            in = { 0xF0F0F0F0F0F0F0, 0xBABABABABABABA, 0xCECECECECECECE };
            out = { 0, 0, 0 };
            expected = { 0xade881380d001140, 0xd4d54d49088bd2dd, 0x8df9832af0 };
            multiplyManyUint64(in.data(), 3, out.data());
            ASSERT_TRUE(expected == out);
        }

        TEST(UIntArith, MultiplyManyUInt64Except)
        {
            

            vector<uint64_t> in = { 0, 0, 0 };
            vector<uint64_t> out = { 0, 0, 0 };
            vector<uint64_t> expected = { 0, 0, 0 };
            multiplyManyUint64Except(in.data(), 2, 0, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64Except(in.data(), 2, 1, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64Except(in.data(), 3, 0, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64Except(in.data(), 3, 1, out.data());
            ASSERT_TRUE(expected == out);
            multiplyManyUint64Except(in.data(), 3, 2, out.data());
            ASSERT_TRUE(expected == out);

            in = { 2, 3, 5 };
            out = { 0, 0, 0 };
            expected = { 3, 0, 0 };
            multiplyManyUint64Except(in.data(), 2, 0, out.data());
            ASSERT_TRUE(expected == out);
            expected = { 2, 0, 0 };
            multiplyManyUint64Except(in.data(), 2, 1, out.data());
            ASSERT_TRUE(expected == out);
            expected = { 15, 0, 0 };
            multiplyManyUint64Except(in.data(), 3, 0, out.data());
            ASSERT_TRUE(expected == out);
            expected = { 10, 0, 0 };
            multiplyManyUint64Except(in.data(), 3, 1, out.data());
            ASSERT_TRUE(expected == out);
            expected = { 6, 0, 0 };
            multiplyManyUint64Except(in.data(), 3, 2, out.data());
            ASSERT_TRUE(expected == out);

            in = { 0xF0F0F0F0F0F0F0, 0xBABABABABABABA, 0xCECECECECECECE };
            out = { 0, 0, 0 };
            expected = { 0x0c6a88a6c4e30120, 0xc2a486684a2c, 0x0 };
            multiplyManyUint64Except(in.data(), 3, 1, out.data());
            ASSERT_TRUE(expected == out);
        }

        TEST(UIntArith, MultiplyUInt)
        {
            
            auto ptr = HostArray<uint64_t>(2);
            auto ptr2 = HostArray<uint64_t>(2);
            auto ptr3 = HostArray<uint64_t>(4);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[2] = 0xFFFFFFFFFFFFFFFF;
            ptr3[3] = 0xFFFFFFFFFFFFFFFF;
            multiplyUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[2] = 0xFFFFFFFFFFFFFFFF;
            ptr3[3] = 0xFFFFFFFFFFFFFFFF;
            multiplyUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiplyUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 1;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiplyUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiplyUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[3]);

            ptr[0] = 9756571004902751654ul;
            ptr[1] = 731952007397389984;
            ptr2[0] = 701538366196406307;
            ptr2[1] = 1699883529753102283;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiplyUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(9585656442714717618ul), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(1817697005049051848), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(14447416709120365380ul), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(67450014862939159), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiplyUint(ptr.get(), 2, ptr2.get(), 1, 2, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiplyUint(ptr.get(), 2, ptr2.get(), 1, 3, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiplyTruncateUint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);
        }

        TEST(UIntArith, MultiplyUIntUInt64)
        {
            
            auto ptr = HostArray<uint64_t>(3);
            auto result = HostArray<uint64_t>(4);

            ptr[0] = 0;
            ptr[1] = 0;
            ptr[2] = 0;
            multiplyUint(ptr.get(), 3, 0ULL, 4, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiplyUint(ptr.get(), 3, 0ULL, 4, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiplyUint(ptr.get(), 3, 1ULL, 4, result.get());
            ASSERT_EQ(0xFFFFFFFFFULL, result[0]);
            ASSERT_EQ(0xAAAAAAAAAULL, result[1]);
            ASSERT_EQ(0x111111111ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiplyUint(ptr.get(), 3, 0x10000ULL, 4, result.get());
            ASSERT_EQ(0xFFFFFFFFF0000ULL, result[0]);
            ASSERT_EQ(0xAAAAAAAAA0000ULL, result[1]);
            ASSERT_EQ(0x1111111110000ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiplyUint(ptr.get(), 3, 0x100000000ULL, 4, result.get());
            ASSERT_EQ(0xFFFFFFFF00000000ULL, result[0]);
            ASSERT_EQ(0xAAAAAAAA0000000FULL, result[1]);
            ASSERT_EQ(0x111111110000000AULL, result[2]);
            ASSERT_EQ(1ULL, result[3]);

            ptr[0] = 5656565656565656ULL;
            ptr[1] = 3434343434343434ULL;
            ptr[2] = 1212121212121212ULL;
            multiplyUint(ptr.get(), 3, 7878787878787878ULL, 4, result.get());
            ASSERT_EQ(8891370032116156560ULL, result[0]);
            ASSERT_EQ(127835914414679452ULL, result[1]);
            ASSERT_EQ(9811042505314082702ULL, result[2]);
            ASSERT_EQ(517709026347ULL, result[3]);
        }

        TEST(UIntArith, DivideUInt)
        {
            
            divideUintInplace(nullptr, nullptr, 0, nullptr);
            divideUint(nullptr, nullptr, 0, nullptr, nullptr);

            auto ptr = HostArray<uint64_t>(4);
            auto ptr2 = HostArray<uint64_t>(4);
            auto ptr3 = HostArray<uint64_t>(4);
            auto ptr4 = HostArray<uint64_t>(4);
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 1;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divideUintInplace(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divideUintInplace(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFE;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divideUintInplace(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divideUintInplace(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 14;
            ptr[1] = 0;
            ptr2[0] = 3;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divideUintInplace(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(4), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 9585656442714717620ul;
            ptr[1] = 1817697005049051848;
            ptr[2] = 14447416709120365380ul;
            ptr[3] = 67450014862939159;
            ptr2[0] = 701538366196406307;
            ptr2[1] = 1699883529753102283;
            ptr2[2] = 0;
            ptr2[3] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[2] = 0xFFFFFFFFFFFFFFFF;
            ptr3[3] = 0xFFFFFFFFFFFFFFFF;
            ptr4[0] = 0xFFFFFFFFFFFFFFFF;
            ptr4[1] = 0xFFFFFFFFFFFFFFFF;
            ptr4[2] = 0xFFFFFFFFFFFFFFFF;
            ptr4[3] = 0xFFFFFFFFFFFFFFFF;
            divideUint(ptr.get(), ptr2.get(), 4, ptr3.get(), ptr4.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr4[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr4[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr4[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr4[3]);
            ASSERT_EQ(static_cast<uint64_t>(9756571004902751654ul), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(731952007397389984), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            divideUintInplace(ptr.get(), ptr2.get(), 4, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[3]);
            ASSERT_EQ(static_cast<uint64_t>(9756571004902751654ul), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(731952007397389984), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);
        }

        TEST(UIntArith, DivideUInt128UInt64)
        {
            uint64_t input[2];
            uint64_t quotient[2];

            input[0] = 0;
            input[1] = 0;
            divideUint128Inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);

            input[0] = 1;
            input[1] = 0;
            divideUint128Inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(1ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);

            input[0] = 0x10101010;
            input[1] = 0x2B2B2B2B;
            divideUint128Inplace(input, 0x1000ULL, quotient);
            ASSERT_EQ(0x10ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0xB2B0000000010101ULL, quotient[0]);
            ASSERT_EQ(0x2B2B2ULL, quotient[1]);

            input[0] = 1212121212121212ULL;
            input[1] = 3434343434343434ULL;
            divideUint128Inplace(input, 5656565656565656ULL, quotient);
            ASSERT_EQ(5252525252525252ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(11199808901895084909ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);
        }

        TEST(UIntArith, DivideUInt192UInt64)
        {
            uint64_t input[3];
            uint64_t quotient[3];

            input[0] = 0;
            input[1] = 0;
            input[2] = 0;
            divideUint192Inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(0ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);
            ASSERT_EQ(0ULL, quotient[2]);

            input[0] = 1;
            input[1] = 0;
            input[2] = 0;
            divideUint192Inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(1ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);
            ASSERT_EQ(0ULL, quotient[2]);

            input[0] = 0x10101010;
            input[1] = 0x2B2B2B2B;
            input[2] = 0xF1F1F1F1;
            divideUint192Inplace(input, 0x1000ULL, quotient);
            ASSERT_EQ(0x10ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(0xB2B0000000010101ULL, quotient[0]);
            ASSERT_EQ(0x1F1000000002B2B2ULL, quotient[1]);
            ASSERT_EQ(0xF1F1FULL, quotient[2]);

            input[0] = 1212121212121212ULL;
            input[1] = 3434343434343434ULL;
            input[2] = 5656565656565656ULL;
            divideUint192Inplace(input, 7878787878787878ULL, quotient);
            ASSERT_EQ(7272727272727272ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(17027763760347278414ULL, quotient[0]);
            ASSERT_EQ(13243816258047883211ULL, quotient[1]);
            ASSERT_EQ(0ULL, quotient[2]);
        }

        // TEST(UIntArith, ExponentiateUInt64)
        // {
        //     ASSERT_EQ(0ULL, exponentiateUint(0ULL, 1ULL));
        //     ASSERT_EQ(1ULL, exponentiateUint(1ULL, 0ULL));
        //     ASSERT_EQ(0ULL, exponentiateUint(0ULL, 0xFFFFFFFFFFFFFFFFULL));
        //     ASSERT_EQ(1ULL, exponentiateUint(0xFFFFFFFFFFFFFFFFULL, 0ULL));
        //     ASSERT_EQ(25ULL, exponentiateUint(5ULL, 2ULL));
        //     ASSERT_EQ(32ULL, exponentiateUint(2ULL, 5ULL));
        //     ASSERT_EQ(0x1000000000000000ULL, exponentiateUint(0x10ULL, 15ULL));
        //     ASSERT_EQ(0ULL, exponentiateUint(0x10ULL, 16ULL));
        //     ASSERT_EQ(12389286314587456613ULL, exponentiateUint(123456789ULL, 13ULL));
        // }
    } // namespace util
} // namespace sealtest
