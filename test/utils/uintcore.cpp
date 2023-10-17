// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/utils/uintcore.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        // TEST(UIntCore, AllocateUInt)
        // {
        //     auto ptr(allocateUint(0, pool));
        //     ASSERT_TRUE(nullptr == ptr.get());

        //     ptr = allocateUint(1, pool);
        //     ASSERT_TRUE(nullptr != ptr.get());

        //     ptr = HostArray<uint64_t>(2);
        //     ASSERT_TRUE(nullptr != ptr.get());
        // }

        TEST(UIntCore, SetZeroUInt)
        {
            setZeroUint(0, nullptr);

            auto ptr = HostArray<uint64_t>(1);
            ptr[0] = 0x1234567812345678;
            setZeroUint(1, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = HostArray<uint64_t>(2);
            ptr[0] = 0x1234567812345678;
            ptr[1] = 0x1234567812345678;
            setZeroUint(2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, AllocateZeroUInt)
        {
            auto ptr = HostArray<uint64_t>(0);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = HostArray<uint64_t>(1);
            ASSERT_TRUE(nullptr != ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = HostArray<uint64_t>(2);
            ASSERT_TRUE(nullptr != ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, SetUInt)
        {
            auto ptr = HostArray<uint64_t>(1);
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            setUint(1, 1, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            setUint(0x1234567812345678, 1, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567812345678), ptr[0]);

            ptr = HostArray<uint64_t>(2);
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            setUint(1, 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            setUint(0x1234567812345678, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567812345678), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, SetUInt2)
        {
            setUint(nullptr, 0, nullptr);

            auto ptr1 = HostArray<uint64_t>(1);
            ptr1[0] = 0x1234567887654321;
            auto ptr2 = HostArray<uint64_t>(1);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            setUint(ptr1.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);

            ptr1[0] = 0x1231231231231231;
            setUint(ptr1.get(), 1, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231231), ptr1[0]);

            ptr1 = HostArray<uint64_t>(2);
            ptr2 = HostArray<uint64_t>(2);
            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            setUint(ptr1.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8765432112345678), ptr2[1]);

            ptr1[0] = 0x1231231231231321;
            ptr1[1] = 0x3213213213213211;
            setUint(ptr1.get(), 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231321), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3213213213213211), ptr1[1]);
        }

        TEST(UIntCore, SetUInt3)
        {
            setUint(nullptr, 0, 0, nullptr);

            auto ptr1 = HostArray<uint64_t>(1);
            ptr1[0] = 0x1234567887654321;
            setUint(nullptr, 0, 1, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);

            auto ptr2 = HostArray<uint64_t>(1);
            ptr1[0] = 0x1234567887654321;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            setUint(ptr1.get(), 1, 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);

            ptr1[0] = 0x1231231231231231;
            setUint(ptr1.get(), 1, 1, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231231), ptr1[0]);

            ptr1 = HostArray<uint64_t>(2);
            ptr2 = HostArray<uint64_t>(2);
            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            setUint(nullptr, 0, 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);

            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            setUint(ptr1.get(), 1, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            setUint(ptr1.get(), 2, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8765432112345678), ptr2[1]);

            ptr1[0] = 0x1231231231231321;
            ptr1[1] = 0x3213213213213211;
            setUint(ptr1.get(), 2, 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231321), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3213213213213211), ptr1[1]);

            setUint(ptr1.get(), 1, 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231321), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);
        }

        TEST(UIntCore, IsZeroUInt)
        {
            ASSERT_TRUE(isZeroUint(nullptr, 0));

            auto ptr = HostArray<uint64_t>(1);
            ptr[0] = 1;
            ASSERT_FALSE(isZeroUint(ptr.get(), 1));
            ptr[0] = 0;
            ASSERT_TRUE(isZeroUint(ptr.get(), 1));

            ptr = HostArray<uint64_t>(2);
            ptr[0] = 0x8000000000000000;
            ptr[1] = 0x8000000000000000;
            ASSERT_FALSE(isZeroUint(ptr.get(), 2));
            ptr[0] = 0;
            ptr[1] = 0x8000000000000000;
            ASSERT_FALSE(isZeroUint(ptr.get(), 2));
            ptr[0] = 0x8000000000000000;
            ptr[1] = 0;
            ASSERT_FALSE(isZeroUint(ptr.get(), 2));
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_TRUE(isZeroUint(ptr.get(), 2));
        }

        TEST(UIntCore, IsEqualUInt)
        {
            auto ptr = HostArray<uint64_t>(1);
            ptr[0] = 1;
            ASSERT_TRUE(isEqualUint(ptr.get(), 1, 1));
            ASSERT_FALSE(isEqualUint(ptr.get(), 1, 0));
            ASSERT_FALSE(isEqualUint(ptr.get(), 1, 2));

            ptr = HostArray<uint64_t>(2);
            ptr[0] = 1;
            ptr[1] = 1;
            ASSERT_FALSE(isEqualUint(ptr.get(), 2, 1));
            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_TRUE(isEqualUint(ptr.get(), 2, 1));
            ptr[0] = 0x1234567887654321;
            ptr[1] = 0;
            ASSERT_TRUE(isEqualUint(ptr.get(), 2, 0x1234567887654321));
            ASSERT_FALSE(isEqualUint(ptr.get(), 2, 0x2234567887654321));
        }

        TEST(UIntCore, IsBitSetUInt)
        {
            auto ptr = HostArray<uint64_t>(2);;
            ptr[0] = 0;
            ptr[1] = 0;
            for (int i = 0; i < 128; ++i)
            {
                ASSERT_FALSE(isBitSetUint(ptr.get(), 2, i));
            }
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            for (int i = 0; i < 128; ++i)
            {
                ASSERT_TRUE(isBitSetUint(ptr.get(), 2, i));
            }

            ptr[0] = 0x0000000000000001;
            ptr[1] = 0x8000000000000000;
            for (int i = 0; i < 128; ++i)
            {
                if (i == 0 || i == 127)
                {
                    ASSERT_TRUE(isBitSetUint(ptr.get(), 2, i));
                }
                else
                {
                    ASSERT_FALSE(isBitSetUint(ptr.get(), 2, i));
                }
            }
        }

        TEST(UIntCore, IsHighBitSetUInt)
        {
            auto ptr = HostArray<uint64_t>(2);;
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_FALSE(isHighBitSetUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_TRUE(isHighBitSetUint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 0x8000000000000000;
            ASSERT_TRUE(isHighBitSetUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x7FFFFFFFFFFFFFFF;
            ASSERT_FALSE(isHighBitSetUint(ptr.get(), 2));
        }

        TEST(UIntCore, SetBitUInt)
        {
            auto ptr = HostArray<uint64_t>(2);;
            ptr[0] = 0;
            ptr[1] = 0;
            setBitUint(ptr.get(), 2, 0);
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            setBitUint(ptr.get(), 2, 127);
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr[1]);

            setBitUint(ptr.get(), 2, 63);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr[1]);

            setBitUint(ptr.get(), 2, 64);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[1]);

            setBitUint(ptr.get(), 2, 3);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000009), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[1]);
        }

        TEST(UIntCore, GetSignificantBitCountUInt)
        {
            auto ptr = HostArray<uint64_t>(2);;
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_EQ(0, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_EQ(1, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 2;
            ptr[1] = 0;
            ASSERT_EQ(2, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 3;
            ptr[1] = 0;
            ASSERT_EQ(2, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 29;
            ptr[1] = 0;
            ASSERT_EQ(5, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 4;
            ptr[1] = 0;
            ASSERT_EQ(3, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ASSERT_EQ(64, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 1;
            ASSERT_EQ(65, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 1;
            ASSERT_EQ(65, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x7000000000000000;
            ASSERT_EQ(127, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x8000000000000000;
            ASSERT_EQ(128, getSignificantBitCountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(128, getSignificantBitCountUint(ptr.get(), 2));
        }

        TEST(UIntCore, GetSignificantUInt64CountUInt)
        {
            auto ptr = HostArray<uint64_t>(2);;
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_EQ(0ULL, getSignificantUint64CountUint(ptr.get(), 2));

            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, getSignificantUint64CountUint(ptr.get(), 2));

            ptr[0] = 2;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, getSignificantUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, getSignificantUint64CountUint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 1;
            ASSERT_EQ(2ULL, getSignificantUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 1;
            ASSERT_EQ(2ULL, getSignificantUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x8000000000000000;
            ASSERT_EQ(2ULL, getSignificantUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(2ULL, getSignificantUint64CountUint(ptr.get(), 2));
        }

        TEST(UIntCore, GetNonzeroUInt64CountUInt)
        {
            auto ptr = HostArray<uint64_t>(2);;
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_EQ(0ULL, getNonzeroUint64CountUint(ptr.get(), 2));

            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, getNonzeroUint64CountUint(ptr.get(), 2));

            ptr[0] = 2;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, getNonzeroUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, getNonzeroUint64CountUint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 1;
            ASSERT_EQ(1ULL, getNonzeroUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 1;
            ASSERT_EQ(2ULL, getNonzeroUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x8000000000000000;
            ASSERT_EQ(2ULL, getNonzeroUint64CountUint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(2ULL, getNonzeroUint64CountUint(ptr.get(), 2));
        }

        TEST(UIntCore, FilterHighBitsUInt)
        {
            filterHighbitsUint(nullptr, 0, 0);

            auto ptr = HostArray<uint64_t>(2);;
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            filterHighbitsUint(ptr.get(), 2, 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            filterHighbitsUint(ptr.get(), 2, 128);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            filterHighbitsUint(ptr.get(), 2, 127);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF), ptr[1]);
            filterHighbitsUint(ptr.get(), 2, 126);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3FFFFFFFFFFFFFFF), ptr[1]);
            filterHighbitsUint(ptr.get(), 2, 64);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filterHighbitsUint(ptr.get(), 2, 63);
            ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filterHighbitsUint(ptr.get(), 2, 2);
            ASSERT_EQ(static_cast<uint64_t>(0x3), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filterHighbitsUint(ptr.get(), 2, 1);
            ASSERT_EQ(static_cast<uint64_t>(0x1), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filterHighbitsUint(ptr.get(), 2, 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            filterHighbitsUint(ptr.get(), 2, 128);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, CompareUInt)
        {
            ASSERT_EQ(0, compareUint(nullptr, nullptr, 0));
            ASSERT_TRUE(isEqualUint(nullptr, nullptr, 0));
            ASSERT_FALSE(isGreaterThanUint(nullptr, nullptr, 0));
            ASSERT_FALSE(isLessThanUint(nullptr, nullptr, 0));
            ASSERT_TRUE(isGreaterThanOrEqualUint(nullptr, nullptr, 0));
            ASSERT_TRUE(isLessThanOrEqualUint(nullptr, nullptr, 0));

            auto ptr1 = HostArray<uint64_t>(2);;
            auto ptr2 = HostArray<uint64_t>(2);;
            ptr1[0] = 0;
            ptr1[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ASSERT_EQ(0, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            ptr2[0] = 0x1234567887654321;
            ptr2[1] = 0x8765432112345678;
            ASSERT_EQ(0, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 1;
            ptr1[1] = 0;
            ptr2[0] = 2;
            ptr2[1] = 0;
            ASSERT_EQ(-1, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 1;
            ptr1[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 2;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(-1, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 0x0000000000000001;
            ptr2[0] = 0x0000000000000000;
            ptr2[1] = 0x0000000000000002;
            ASSERT_EQ(-1, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 2;
            ptr1[1] = 0;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ASSERT_EQ(1, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 2;
            ptr1[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(1, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 0x0000000000000003;
            ptr2[0] = 0x0000000000000000;
            ptr2[1] = 0x0000000000000002;
            ASSERT_EQ(1, compareUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(isGreaterThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(isLessThanOrEqualUint(ptr1.get(), ptr2.get(), 2));
        }

        TEST(UIntCore, GetPowerOfTwo)
        {
            ASSERT_EQ(-1, getPowerOfTwo(0));
            ASSERT_EQ(0, getPowerOfTwo(1));
            ASSERT_EQ(1, getPowerOfTwo(2));
            ASSERT_EQ(-1, getPowerOfTwo(3));
            ASSERT_EQ(2, getPowerOfTwo(4));
            ASSERT_EQ(-1, getPowerOfTwo(5));
            ASSERT_EQ(-1, getPowerOfTwo(6));
            ASSERT_EQ(-1, getPowerOfTwo(7));
            ASSERT_EQ(3, getPowerOfTwo(8));
            ASSERT_EQ(-1, getPowerOfTwo(15));
            ASSERT_EQ(4, getPowerOfTwo(16));
            ASSERT_EQ(-1, getPowerOfTwo(17));
            ASSERT_EQ(-1, getPowerOfTwo(255));
            ASSERT_EQ(8, getPowerOfTwo(256));
            ASSERT_EQ(-1, getPowerOfTwo(257));
            ASSERT_EQ(10, getPowerOfTwo(1 << 10));
            ASSERT_EQ(30, getPowerOfTwo(1 << 30));
            ASSERT_EQ(32, getPowerOfTwo(1ULL << 32));
            ASSERT_EQ(62, getPowerOfTwo(1ULL << 62));
            ASSERT_EQ(63, getPowerOfTwo(1ULL << 63));
        }

        // TEST(UIntCore, DuplicateUIntIfNeeded)
        // {
        //     auto ptr = HostArray<uint64_t>(2);;
        //     ptr[0] = 0xF0F0F0F0F0;
        //     ptr[1] = 0xABABABABAB;
        //     auto ptr2 = duplicateUintIfNeeded(ptr.get(), 0, 0, false);
        //     // No forcing and sizes are same (although zero) so just alias
        //     ASSERT_TRUE(ptr2.get() == ptr.get());

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 0, 0, true);
        //     // Forcing and size is zero so return nullptr
        //     ASSERT_TRUE(ptr2.get() == nullptr);

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 1, 0, false);
        //     ASSERT_TRUE(ptr2.get() == ptr.get());

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 1, 0, true);
        //     ASSERT_TRUE(ptr2.get() == nullptr);

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 1, 1, false);
        //     ASSERT_TRUE(ptr2.get() == ptr.get());

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 1, 1, true);
        //     ASSERT_TRUE(ptr2.get() != ptr.get());
        //     ASSERT_EQ(ptr[0], ptr2[0]);

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 2, 2, true);
        //     ASSERT_TRUE(ptr2.get() != ptr.get());
        //     ASSERT_EQ(ptr[0], ptr2[0]);
        //     ASSERT_EQ(ptr[1], ptr2[1]);

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 2, 2, false);
        //     ASSERT_TRUE(ptr2.get() == ptr.get());

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 2, 1, false);
        //     ASSERT_TRUE(ptr2.get() == ptr.get());

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 1, 2, false);
        //     ASSERT_TRUE(ptr2.get() != ptr.get());
        //     ASSERT_EQ(ptr[0], ptr2[0]);
        //     ASSERT_EQ(0ULL, ptr2[1]);

        //     ptr2 = duplicateUintIfNeeded(ptr.get(), 1, 2, true);
        //     ASSERT_TRUE(ptr2.get() != ptr.get());
        //     ASSERT_EQ(ptr[0], ptr2[0]);
        //     ASSERT_EQ(0ULL, ptr2[1]);
        // }
        
    } // namespace util
} // namespace sealtest
