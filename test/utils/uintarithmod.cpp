// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/utils/uintarithmod.h"
#include "../../src/utils/uintcore.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(UIntArithMod, IncrementUIntMod)
        {
            auto value = HostArray<uint64_t>(2);
            auto modulus = HostArray<uint64_t>(2);
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            incrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            incrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            incrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 0xFFFFFFFFFFFFFFFD;
            value[1] = 0xFFFFFFFFFFFFFFFF;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            incrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
            incrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            incrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
        }

        TEST(UIntArithMod, DecrementUIntMod)
        {
            
            auto value = HostArray<uint64_t>(2);
            auto modulus = HostArray<uint64_t>(2);
            value[0] = 2;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            decrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            decrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            decrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            decrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            decrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
            decrementUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFD), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
        }

        TEST(UIntArithMod, NegateUIntMod)
        {
            
            auto value = HostArray<uint64_t>(2);
            auto modulus = HostArray<uint64_t>(2);
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            negateUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            negateUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            negateUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 2;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            negateUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFD), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
            negateUintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
        }

        TEST(UIntArithMod, Div2UIntMod)
        {
            
            auto value = HostArray<uint64_t>(2);
            auto modulus = HostArray<uint64_t>(2);
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            div2UintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            div2UintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(2ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 8;
            value[1] = 0;
            modulus[0] = 17;
            modulus[1] = 0;
            div2UintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(4ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 5;
            value[1] = 0;
            modulus[0] = 17;
            modulus[1] = 0;
            div2UintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(11ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFFULL;
            modulus[1] = 0xFFFFFFFFFFFFFFFFULL;
            div2UintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0x8000000000000000ULL, value[1]);

            value[0] = 3;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFFULL;
            modulus[1] = 0xFFFFFFFFFFFFFFFFULL;
            div2UintMod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0x8000000000000000ULL, value[1]);
        }

        TEST(UIntArithMod, AddUIntMod)
        {
            
            auto value1 = HostArray<uint64_t>(2);
            auto value2 = HostArray<uint64_t>(2);
            auto modulus = HostArray<uint64_t>(2);
            value1[0] = 0;
            value1[1] = 0;
            value2[0] = 0;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            addUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 1;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            addUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            addUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 2;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            addUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(1ULL, value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 0xFFFFFFFFFFFFFFFE;
            value1[1] = 0xFFFFFFFFFFFFFFFF;
            value2[0] = 0xFFFFFFFFFFFFFFFE;
            value2[1] = 0xFFFFFFFFFFFFFFFF;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            addUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFD), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value1[1]);
        }

        TEST(UIntArithMod, SubUIntMod)
        {
            
            auto value1 = HostArray<uint64_t>(2);
            auto value2 = HostArray<uint64_t>(2);
            auto modulus = HostArray<uint64_t>(2);
            value1[0] = 0;
            value1[1] = 0;
            value2[0] = 0;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            subUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 2;
            value1[1] = 0;
            value2[0] = 1;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            subUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(1ULL, value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            subUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 2;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            subUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 0xFFFFFFFFFFFFFFFE;
            value2[1] = 0xFFFFFFFFFFFFFFFF;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            subUintUintMod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);
        }

        TEST(UIntArithMod, TryInvertUIntMod)
        {
            
            auto value = HostArray<uint64_t>(2);
            auto modulus = HostArray<uint64_t>(2);
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_FALSE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 2;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));
            ASSERT_EQ(static_cast<uint64_t>(3), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 3;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 4;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));
            ASSERT_EQ(static_cast<uint64_t>(4), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 2;
            value[1] = 0;
            modulus[0] = 6;
            modulus[1] = 0;
            ASSERT_FALSE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));

            value[0] = 3;
            value[1] = 0;
            modulus[0] = 6;
            modulus[1] = 0;
            ASSERT_FALSE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));

            value[0] = 331975426;
            value[1] = 0;
            modulus[0] = 1351315121;
            modulus[1] = 0;
            ASSERT_TRUE(tryInvertUintMod(value.get(), modulus.get(), 2, value.get()));
            ASSERT_EQ(static_cast<uint64_t>(1052541512), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
        }
    } // namespace util
} // namespace sealtest
