// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/modulus.h"
#include "../../src/utils/ntt.h"
#include "../../src/utils/numth.h"
#include <cstddef>
#include <cstdint>
#include <random>
#include "gtest/gtest.h"

using namespace troy;
using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(NTTTablesTest, NTTBasics)
        {
            
            HostObject<NTTTables> tables;
            int coeff_count_power = 1;
            Modulus modulus(getPrime(uint64_t(2) << coeff_count_power, 60));
            ASSERT_NO_THROW(tables = HostObject(new NTTTables(coeff_count_power, modulus)));
            ASSERT_EQ(2ULL, tables->coeffCount());
            ASSERT_EQ(1, tables->coeffCountPower());

            coeff_count_power = 2;
            modulus = getPrime(uint64_t(2) << coeff_count_power, 50);
            ASSERT_NO_THROW(tables = HostObject(new NTTTables(coeff_count_power, modulus)));
            ASSERT_EQ(4ULL, tables->coeffCount());
            ASSERT_EQ(2, tables->coeffCountPower());

            coeff_count_power = 10;
            modulus = getPrime(uint64_t(2) << coeff_count_power, 40);
            ASSERT_NO_THROW(tables = HostObject(new NTTTables(coeff_count_power, modulus)));
            ASSERT_EQ(1024ULL, tables->coeffCount());
            ASSERT_EQ(10, tables->coeffCountPower());

            HostArray<NTTTables> many_tables;
            ASSERT_NO_THROW(many_tables = CreateNTTTables(
                coeff_count_power, CoeffModulus::Create(uint64_t(1) << coeff_count_power, { 20, 20, 20, 20, 20 })));
            for (size_t i = 0; i < 5; i++)
            {
                ASSERT_EQ(1024ULL, many_tables[i].coeffCount());
                ASSERT_EQ(10, many_tables[i].coeffCountPower());
            }
        }

        TEST(NTTTablesTest, NTTPrimitiveRootsTest)
        {
            HostObject<NTTTables> tables;

            int coeff_count_power = 1;
            Modulus modulus(0xffffffffffc0001ULL);
            ASSERT_NO_THROW(tables = HostObject(new NTTTables(coeff_count_power, modulus)));
            ASSERT_EQ(1ULL, tables->getFromRootPowers(0).operand);
            ASSERT_EQ(288794978602139552ULL, tables->getFromRootPowers(1).operand);
            uint64_t inv;
            tryInvertUintMod(tables->getFromRootPowers(1).operand, modulus.value(), inv);
            ASSERT_EQ(inv, tables->getFromInvRootPowers(1).operand);

            coeff_count_power = 2;
            ASSERT_NO_THROW(tables = HostObject(new NTTTables(coeff_count_power, modulus)));
            ASSERT_EQ(1ULL, tables->getFromRootPowers(0).operand);
            ASSERT_EQ(288794978602139552ULL, tables->getFromRootPowers(1).operand);
            ASSERT_EQ(178930308976060547ULL, tables->getFromRootPowers(2).operand);
            ASSERT_EQ(748001537669050592ULL, tables->getFromRootPowers(3).operand);
        }

        TEST(NTTTablesTest, NegacyclicNTTTest)
        {
            
            HostObject<NTTTables> tables;

            int coeff_count_power = 1;
            Modulus modulus(0xffffffffffc0001ULL);
            ASSERT_NO_THROW(tables = HostObject(new NTTTables(coeff_count_power, modulus)));
            auto poly = HostArray<uint64_t>(2);
            poly[0] = 0;
            poly[1] = 0;
            nttNegacyclicHarvey(poly.asPointer(), *tables);
            ASSERT_EQ(0ULL, poly[0]);
            ASSERT_EQ(0ULL, poly[1]);

            poly[0] = 1;
            poly[1] = 0;
            nttNegacyclicHarvey(poly.asPointer(), *tables);
            ASSERT_EQ(1ULL, poly[0]);
            ASSERT_EQ(1ULL, poly[1]);

            poly[0] = 1;
            poly[1] = 1;
            nttNegacyclicHarvey(poly.asPointer(), *tables);
            ASSERT_EQ(288794978602139553ULL, poly[0]);
            ASSERT_EQ(864126526004445282ULL, poly[1]);
        }

        TEST(NTTTablesTest, InverseNegacyclicNTTTest)
        {
            
            HostObject<NTTTables> tables;

            int coeff_count_power = 3;
            Modulus modulus(0xffffffffffc0001ULL);
            ASSERT_NO_THROW(tables = HostObject(new NTTTables(coeff_count_power, modulus)));
            auto poly = HostArray<uint64_t>(800);
            auto temp = HostArray<uint64_t>(800);
            for (size_t i = 0; i < 800; i++) poly[i] = temp[i] = 0;

            inverseNttNegacyclicHarvey(poly.asPointer(), *tables);
            for (size_t i = 0; i < 800; i++)
            {
                ASSERT_EQ(0ULL, poly[i]);
            }

            random_device rd;
            for (size_t i = 0; i < 800; i++)
            {
                poly[i] = static_cast<uint64_t>(rd()) % modulus.value();
                temp[i] = poly[i];
            }

            nttNegacyclicHarvey(poly.asPointer(), *tables);
            inverseNttNegacyclicHarvey(poly.asPointer(), *tables);
            for (size_t i = 0; i < 800; i++)
            {
                ASSERT_EQ(temp[i], poly[i]);
            }
        }
    } // namespace util
} // namespace sealtest
