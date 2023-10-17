// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/utils/defines.h"
#include "../../src/utils/polyarithsmallmod.h"
// #include "../../src/utils/polycore.h"
#include "../../src/utils/uintcore.h"
#include <cstddef>
#include <cstdint>
#include "gtest/gtest.h"

using namespace troy;
using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(PolyArithSmallMod, ModuloPolyCoeffs)
        {
            
            {
                auto poly = HostArray<uint64_t>(3);
                auto modulus = HostArray<uint64_t>(2);
                poly[0] = 2;
                poly[1] = 15;
                poly[2] = 77;
                Modulus mod(15);
                moduloPolyCoeffs(poly.asPointer(), 3, mod, poly.asPointer());
                ASSERT_EQ(2ULL, poly[0]);
                ASSERT_EQ(0ULL, poly[1]);
                ASSERT_EQ(2ULL, poly[2]);
            }
            {
                auto poly = HostArray<uint64_t>(3 * 2);
                auto modulus = HostArray<uint64_t>(2);
                poly[0 * 3 + 0] = 2;
                poly[0 * 3 + 1] = 15;
                poly[0 * 3 + 2] = 77;
                poly[1 * 3 + 0] = 2;
                poly[1 * 3 + 1] = 15;
                poly[1 * 3 + 2] = 77;
                vector<Modulus> mod{ 15, 3 };
                moduloPolyCoeffs(poly.asPointer(), 2, 3, &mod[0], poly.asPointer());
                ASSERT_EQ(0ULL, poly[0 * 3 + 1]);
                ASSERT_EQ(2ULL, poly[0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[0 * 3 + 0]);
                ASSERT_EQ(2ULL, poly[1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly[1 * 3 + 2]);
            }
            {
                auto poly = HostArray<uint64_t>(2 * 3 * 2);
                // auto poly = HostArray<uint64_t>(2 * 3 * 2);
                auto modulus = HostArray<uint64_t>(2);
                poly[0 * 2 * 3 + 0 * 3 + 0] = 2;
                poly[0 * 2 * 3 + 0 * 3 + 1] = 15;
                poly[0 * 2 * 3 + 0 * 3 + 2] = 77;
                poly[0 * 2 * 3 + 1 * 3 + 0] = 2;
                poly[0 * 2 * 3 + 1 * 3 + 1] = 15;
                poly[0 * 2 * 3 + 1 * 3 + 2] = 77;
                poly[1 * 2 * 3 + 0 * 3 + 0] = 2;
                poly[1 * 2 * 3 + 0 * 3 + 1] = 15;
                poly[1 * 2 * 3 + 0 * 3 + 2] = 77;
                poly[1 * 2 * 3 + 1 * 3 + 0] = 2;
                poly[1 * 2 * 3 + 1 * 3 + 1] = 15;
                poly[1 * 2 * 3 + 1 * 3 + 2] = 77;
                vector<Modulus> mod{ 15, 3 };
                moduloPolyCoeffs(poly.asPointer(), 2, 2, 3, &mod[0], poly.asPointer());
                ASSERT_EQ(2ULL, poly[0 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[0 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(2ULL, poly[0 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[0 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[0 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly[0 * 2 * 3 + 1 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[1 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[1 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(2ULL, poly[1 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[1 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[1 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly[1 * 2 * 3 + 1 * 3 + 2]);
            }
        }

        TEST(PolyArithSmallMod, NegatePolyCoeffMod)
        {
            
            {
                auto poly = HostArray<uint64_t>(3);
                poly[0] = 2;
                poly[1] = 3;
                poly[2] = 4;
                Modulus mod(15);
                negatePolyCoeffmod(poly.asPointer(), 3, mod, poly.asPointer());
                ASSERT_EQ(static_cast<uint64_t>(13), poly[0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[2]);

                poly[0] = 2;
                poly[1] = 3;
                poly[2] = 4;
                mod = 0xFFFFFFFFFFFFFFULL;
                negatePolyCoeffmod(poly.asPointer(), 3, mod, poly.asPointer());
                ASSERT_EQ(0xFFFFFFFFFFFFFDULL, poly[0]);
                ASSERT_EQ(0xFFFFFFFFFFFFFCULL, poly[1]);
                ASSERT_EQ(0xFFFFFFFFFFFFFBULL, poly[2]);
            }
            {
                auto poly = HostArray<uint64_t>(3 * 2);
                poly[0 * 3 + 0] = 2;
                poly[0 * 3 + 1] = 3;
                poly[0 * 3 + 2] = 4;
                poly[1 * 3 + 0] = 2;
                poly[1 * 3 + 1] = 0;
                poly[1 * 3 + 2] = 1;
                vector<Modulus> mod{ 15, 3 };
                negatePolyCoeffmod(poly.asPointer(), 2, 3, &mod[0], poly.asPointer());
                ASSERT_EQ(static_cast<uint64_t>(13), poly[0 * 3 + 0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[0 * 3 + 1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[0 * 3 + 2]);
                ASSERT_EQ(static_cast<uint64_t>(1),  poly[1 * 3 + 0]);
                ASSERT_EQ(static_cast<uint64_t>(0),  poly[1 * 3 + 1]);
                ASSERT_EQ(static_cast<uint64_t>(2),  poly[1 * 3 + 2]);
            }
            {
                auto poly = HostArray<uint64_t>(2 * 3 * 2);
                poly[0 * 2 * 3 + 0 * 3 + 0] = 2;
                poly[0 * 2 * 3 + 0 * 3 + 1] = 3;
                poly[0 * 2 * 3 + 0 * 3 + 2] = 4;
                poly[0 * 2 * 3 + 1 * 3 + 0] = 2;
                poly[0 * 2 * 3 + 1 * 3 + 1] = 0;
                poly[0 * 2 * 3 + 1 * 3 + 2] = 1;
                poly[1 * 2 * 3 + 0 * 3 + 0] = 2;
                poly[1 * 2 * 3 + 0 * 3 + 1] = 3;
                poly[1 * 2 * 3 + 0 * 3 + 2] = 4;
                poly[1 * 2 * 3 + 1 * 3 + 0] = 2;
                poly[1 * 2 * 3 + 1 * 3 + 1] = 0;
                poly[1 * 2 * 3 + 1 * 3 + 2] = 1;
                vector<Modulus> mod{ 15, 3 };
                negatePolyCoeffmod(poly.asPointer(), 2, 2, 3, &mod[0], poly.asPointer());
                ASSERT_EQ(static_cast<uint64_t>(13), poly[0 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[0 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[0 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(static_cast<uint64_t>(1), poly[0 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(static_cast<uint64_t>(0), poly[0 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(static_cast<uint64_t>(2), poly[0 * 2 * 3 + 1 * 3 + 2]);
                ASSERT_EQ(static_cast<uint64_t>(13), poly[1 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[1 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[1 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(static_cast<uint64_t>(1), poly[1 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(static_cast<uint64_t>(0), poly[1 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(static_cast<uint64_t>(2), poly[1 * 2 * 3 + 1 * 3 + 2]);
            }
        }

        TEST(PolyArithSmallMod, AddPolyCoeffMod)
        {
            
            {
                auto poly1 = HostArray<uint64_t>(3);
                auto poly2 = HostArray<uint64_t>(3);
                poly1[0] = 1;
                poly1[1] = 3;
                poly1[2] = 4;
                poly2[0] = 1;
                poly2[1] = 2;
                poly2[2] = 4;
                Modulus mod(5);
                addPolyCoeffmod(poly1.asPointer(), poly2.asPointer(), 3, mod, poly1.asPointer());
                ASSERT_EQ(2ULL, poly1[0]);
                ASSERT_EQ(0ULL, poly1[1]);
                ASSERT_EQ(3ULL, poly1[2]);
            }
            {
                auto poly1 = HostArray<uint64_t>(3 * 2);
                auto poly2 = HostArray<uint64_t>(3 * 2);
                poly1[0 * 3 + 0] = 1;
                poly1[0 * 3 + 1] = 3;
                poly1[0 * 3 + 2] = 4;
                poly1[1 * 3 + 0] = 0;
                poly1[1 * 3 + 1] = 1;
                poly1[1 * 3 + 2] = 2;

                poly2[0 * 3 + 0] = 1;
                poly2[0 * 3 + 1] = 2;
                poly2[0 * 3 + 2] = 4;
                poly2[1 * 3 + 0] = 2;
                poly2[1 * 3 + 1] = 1;
                poly2[1 * 3 + 2] = 0;

                vector<Modulus> mod{ 5, 3 };
                addPolyCoeffmod(poly1.asPointer(), poly2.asPointer(), 2, 3, &mod[0], poly1.asPointer());

                ASSERT_EQ(2ULL, poly1[0 * 3 + 0]);
                ASSERT_EQ(0ULL, poly1[0 * 3 + 1]);
                ASSERT_EQ(3ULL, poly1[0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly1[1 * 3 + 0]);
                ASSERT_EQ(2ULL, poly1[1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly1[1 * 3 + 2]);
            }
            {
                auto poly1 = HostArray<uint64_t>(2 * 3 * 2);
                auto poly2 = HostArray<uint64_t>(2 * 3 * 2);
                poly1[0 * 2 * 3 + 0 * 3 + 0] = 1;
                poly1[0 * 2 * 3 + 0 * 3 + 1] = 3;
                poly1[0 * 2 * 3 + 0 * 3 + 2] = 4;
                poly1[0 * 2 * 3 + 1 * 3 + 0] = 0;
                poly1[0 * 2 * 3 + 1 * 3 + 1] = 1;
                poly1[0 * 2 * 3 + 1 * 3 + 2] = 2;
                poly1[1 * 2 * 3 + 0 * 3 + 0] = 2;
                poly1[1 * 2 * 3 + 0 * 3 + 1] = 4;
                poly1[1 * 2 * 3 + 0 * 3 + 2] = 0;
                poly1[1 * 2 * 3 + 1 * 3 + 0] = 1;
                poly1[1 * 2 * 3 + 1 * 3 + 1] = 2;
                poly1[1 * 2 * 3 + 1 * 3 + 2] = 0;

                poly2[0 * 2 * 3 + 0 * 3 + 0] = 1;
                poly2[0 * 2 * 3 + 0 * 3 + 1] = 2;
                poly2[0 * 2 * 3 + 0 * 3 + 2] = 4;
                poly2[0 * 2 * 3 + 1 * 3 + 0] = 2;
                poly2[0 * 2 * 3 + 1 * 3 + 1] = 1;
                poly2[0 * 2 * 3 + 1 * 3 + 2] = 0;
                poly2[1 * 2 * 3 + 0 * 3 + 0] = 2;
                poly2[1 * 2 * 3 + 0 * 3 + 1] = 4;
                poly2[1 * 2 * 3 + 0 * 3 + 2] = 0;
                poly2[1 * 2 * 3 + 1 * 3 + 0] = 0;
                poly2[1 * 2 * 3 + 1 * 3 + 1] = 2;
                poly2[1 * 2 * 3 + 1 * 3 + 2] = 1;

                vector<Modulus> mod{ 5, 3 };
                addPolyCoeffmod(poly1.asPointer(), poly2.asPointer(), 2, 2, 3, &mod[0], poly1.asPointer());

                ASSERT_EQ(2ULL, poly1[0 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(0ULL, poly1[0 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(3ULL, poly1[0 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly1[0 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(2ULL, poly1[0 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly1[0 * 2 * 3 + 1 * 3 + 2]);
                ASSERT_EQ(4ULL, poly1[1 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(3ULL, poly1[1 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(0ULL, poly1[1 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(1ULL, poly1[1 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(1ULL, poly1[1 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(1ULL, poly1[1 * 2 * 3 + 1 * 3 + 2]);
            }
        }

        TEST(PolyArithSmallMod, SubPolyCoeffMod)
        {
            
            {
                auto poly1 = HostArray<uint64_t>(3);
                auto poly2 = HostArray<uint64_t>(3);
                poly1[0] = 4;
                poly1[1] = 3;
                poly1[2] = 2;
                poly2[0] = 2;
                poly2[1] = 3;
                poly2[2] = 4;
                Modulus mod(5);
                subPolyCoeffmod(poly1.asPointer(), poly2.asPointer(), 3, mod, poly1.asPointer());
                ASSERT_EQ(2ULL, poly1[0]);
                ASSERT_EQ(0ULL, poly1[1]);
                ASSERT_EQ(3ULL, poly1[2]);
            }
            {
                auto poly1 = HostArray<uint64_t>(3 * 2);
                auto poly2 = HostArray<uint64_t>(3 * 2);
                poly1[0 * 3 + 0] = 1;
                poly1[0 * 3 + 1] = 3;
                poly1[0 * 3 + 2] = 4;
                poly1[1 * 3 + 0] = 0;
                poly1[1 * 3 + 1] = 1;
                poly1[1 * 3 + 2] = 2;

                poly2[0 * 3 + 0] = 1;
                poly2[0 * 3 + 1] = 2;
                poly2[0 * 3 + 2] = 4;
                poly2[1 * 3 + 0] = 2;
                poly2[1 * 3 + 1] = 1;
                poly2[1 * 3 + 2] = 0;

                vector<Modulus> mod{ 5, 3 };
                subPolyCoeffmod(poly1.asPointer(), poly2.asPointer(), 2, 3, &mod[0], poly1.asPointer());

                ASSERT_EQ(0ULL, poly1[0 * 3 + 0]);
                ASSERT_EQ(1ULL, poly1[0 * 3 + 1]);
                ASSERT_EQ(0ULL, poly1[0 * 3 + 2]);
                ASSERT_EQ(1ULL, poly1[1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly1[1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly1[1 * 3 + 2]);
            }
            {
                auto poly1 = HostArray<uint64_t>(2 * 3 * 2);
                auto poly2 = HostArray<uint64_t>(2 * 3 * 2);
                poly1[0 * 2 * 3 + 0 * 3 + 0] = 1;
                poly1[0 * 2 * 3 + 0 * 3 + 1] = 3;
                poly1[0 * 2 * 3 + 0 * 3 + 2] = 4;
                poly1[0 * 2 * 3 + 1 * 3 + 0] = 0;
                poly1[0 * 2 * 3 + 1 * 3 + 1] = 1;
                poly1[0 * 2 * 3 + 1 * 3 + 2] = 2;
                poly1[1 * 2 * 3 + 0 * 3 + 0] = 2;
                poly1[1 * 2 * 3 + 0 * 3 + 1] = 4;
                poly1[1 * 2 * 3 + 0 * 3 + 2] = 0;
                poly1[1 * 2 * 3 + 1 * 3 + 0] = 1;
                poly1[1 * 2 * 3 + 1 * 3 + 1] = 2;
                poly1[1 * 2 * 3 + 1 * 3 + 2] = 0;

                poly2[0 * 2 * 3 + 0 * 3 + 0] = 1;
                poly2[0 * 2 * 3 + 0 * 3 + 1] = 2;
                poly2[0 * 2 * 3 + 0 * 3 + 2] = 4;
                poly2[0 * 2 * 3 + 1 * 3 + 0] = 2;
                poly2[0 * 2 * 3 + 1 * 3 + 1] = 1;
                poly2[0 * 2 * 3 + 1 * 3 + 2] = 0;
                poly2[1 * 2 * 3 + 0 * 3 + 0] = 2;
                poly2[1 * 2 * 3 + 0 * 3 + 1] = 4;
                poly2[1 * 2 * 3 + 0 * 3 + 2] = 0;
                poly2[1 * 2 * 3 + 1 * 3 + 0] = 0;
                poly2[1 * 2 * 3 + 1 * 3 + 1] = 2;
                poly2[1 * 2 * 3 + 1 * 3 + 2] = 1;

                vector<Modulus> mod{ 5, 3 };
                subPolyCoeffmod(poly1.asPointer(), poly2.asPointer(), 2, 2, 3, &mod[0], poly1.asPointer());

                ASSERT_EQ(0ULL, poly1[0 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(1ULL, poly1[0 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(0ULL, poly1[0 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(1ULL, poly1[0 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly1[0 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly1[0 * 2 * 3 + 1 * 3 + 2]);
                ASSERT_EQ(0ULL, poly1[1 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(0ULL, poly1[1 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(0ULL, poly1[1 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(1ULL, poly1[1 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly1[1 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(2ULL, poly1[1 * 2 * 3 + 1 * 3 + 2]);
            }
        }

        TEST(PolyArithSmallMod, MultiplyPolyScalarCoeffMod)
        {
            
            {
                auto poly = HostArray<uint64_t>(3);

                poly[0] = 1;
                poly[1] = 3;
                poly[2] = 4;

                uint64_t scalar = 3;
                Modulus mod(5);
                multiplyPolyScalarCoeffmod(poly.asPointer(), 3, scalar, mod, poly.asPointer());
                ASSERT_EQ(3ULL, poly[0]);
                ASSERT_EQ(4ULL, poly[1]);
                ASSERT_EQ(2ULL, poly[2]);
            }
            {
                auto poly = HostArray<uint64_t>(3 * 2);

                poly[0 * 3 + 0] = 1;
                poly[0 * 3 + 1] = 3;
                poly[0 * 3 + 2] = 4;
                poly[1 * 3 + 0] = 1;
                poly[1 * 3 + 1] = 0;
                poly[1 * 3 + 2] = 2;

                uint64_t scalar = 2;
                vector<Modulus> mod{ 5, 3 };
                multiplyPolyScalarCoeffmod(poly.asPointer(), 2, 3, scalar, &mod[0], poly.asPointer());
                ASSERT_EQ(2ULL, poly[0 * 3 + 0]);
                ASSERT_EQ(1ULL, poly[0 * 3 + 1]);
                ASSERT_EQ(3ULL, poly[0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[1 * 3 + 1]);
                ASSERT_EQ(1ULL, poly[1 * 3 + 2]);
            }
            {
                auto poly = HostArray<uint64_t>(2 * 3 * 2);

                poly[0 * 2 * 3 + 0 * 3 + 0] = 1;
                poly[0 * 2 * 3 + 0 * 3 + 1] = 3;
                poly[0 * 2 * 3 + 0 * 3 + 2] = 4;
                poly[0 * 2 * 3 + 1 * 3 + 0] = 1;
                poly[0 * 2 * 3 + 1 * 3 + 1] = 0;
                poly[0 * 2 * 3 + 1 * 3 + 2] = 2;
                poly[1 * 2 * 3 + 0 * 3 + 0] = 1;
                poly[1 * 2 * 3 + 0 * 3 + 1] = 3;
                poly[1 * 2 * 3 + 0 * 3 + 2] = 4;
                poly[1 * 2 * 3 + 1 * 3 + 0] = 1;
                poly[1 * 2 * 3 + 1 * 3 + 1] = 0;
                poly[1 * 2 * 3 + 1 * 3 + 2] = 2;

                uint64_t scalar = 2;
                vector<Modulus> mod{ 5, 3 };
                multiplyPolyScalarCoeffmod(poly.asPointer(), 2, 2, 3, scalar, &mod[0], poly.asPointer());
                ASSERT_EQ(2ULL, poly[0 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(1ULL, poly[0 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(3ULL, poly[0 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[0 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[0 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(1ULL, poly[0 * 2 * 3 + 1 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[1 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(1ULL, poly[1 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(3ULL, poly[1 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(2ULL, poly[1 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(0ULL, poly[1 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(1ULL, poly[1 * 2 * 3 + 1 * 3 + 2]);
            }
        }

        TEST(PolyArithSmallMod, MultiplyPolyMonoCoeffMod)
        {
            
            {
                auto poly = HostArray<uint64_t>(4);
                poly[0] = 1;
                poly[1] = 3;
                poly[2] = 4;
                poly[3] = 2;
                uint64_t mono_coeff = 3;
                auto result = HostArray<uint64_t>(4);
                setZeroUint(4, result.get());
                Modulus mod(5);

                size_t mono_exponent = 0;
                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 1, mono_coeff, mono_exponent, mod, result.asPointer());
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 2, mono_coeff, mono_exponent, mod, result.asPointer());
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(4ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                mono_exponent = 1;
                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 2, mono_coeff, mono_exponent, mod, result.asPointer());
                ASSERT_EQ(1ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 4, mono_coeff, mono_exponent, mod, result.asPointer());
                ASSERT_EQ(4ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(4ULL, result[2]);
                ASSERT_EQ(2ULL, result[3]);

                mono_coeff = 1;
                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 4, mono_coeff, mono_exponent, mod, result.asPointer());
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(1ULL, result[1]);
                ASSERT_EQ(3ULL, result[2]);
                ASSERT_EQ(4ULL, result[3]);

                mono_coeff = 4;
                mono_exponent = 3;
                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 4, mono_coeff, mono_exponent, mod, result.asPointer());
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(4ULL, result[1]);
                ASSERT_EQ(2ULL, result[2]);
                ASSERT_EQ(4ULL, result[3]);

                mono_coeff = 1;
                mono_exponent = 0;
                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 4, mono_coeff, mono_exponent, mod, result.asPointer());
                ASSERT_EQ(1ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(4ULL, result[2]);
                ASSERT_EQ(2ULL, result[3]);
            }
            {
                auto poly = HostArray<uint64_t>(4 * 2);
                poly[0 * 4 + 0] = 1;
                poly[0 * 4 + 1] = 3;
                poly[0 * 4 + 2] = 4;
                poly[0 * 4 + 3] = 2;
                poly[1 * 4 + 0] = 1;
                poly[1 * 4 + 1] = 3;
                poly[1 * 4 + 2] = 4;
                poly[1 * 4 + 3] = 2;

                auto result = HostArray<uint64_t>(4 * 2);
                vector<Modulus> mod{ 5, 7 };

                uint64_t mono_coeff = 4;
                size_t mono_exponent = 2;
                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 2, 4, mono_coeff, mono_exponent, &mod[0], result.asPointer());

                ASSERT_EQ(4ULL, result[0 * 4 + 0]);
                ASSERT_EQ(2ULL, result[0 * 4 + 1]);
                ASSERT_EQ(4ULL, result[0 * 4 + 2]);
                ASSERT_EQ(2ULL, result[0 * 4 + 3]);
                ASSERT_EQ(5ULL, result[1 * 4 + 0]);
                ASSERT_EQ(6ULL, result[1 * 4 + 1]);
                ASSERT_EQ(4ULL, result[1 * 4 + 2]);
                ASSERT_EQ(5ULL, result[1 * 4 + 3]);
            }
            {
                auto poly = HostArray<uint64_t>(2 * 4 * 2);
                poly[0 * 2 * 4 + 0 * 4 + 0] = 1;
                poly[0 * 2 * 4 + 0 * 4 + 1] = 3;
                poly[0 * 2 * 4 + 0 * 4 + 2] = 4;
                poly[0 * 2 * 4 + 0 * 4 + 3] = 2;
                poly[0 * 2 * 4 + 1 * 4 + 0] = 1;
                poly[0 * 2 * 4 + 1 * 4 + 1] = 3;
                poly[0 * 2 * 4 + 1 * 4 + 2] = 4;
                poly[0 * 2 * 4 + 1 * 4 + 3] = 2;
                poly[1 * 2 * 4 + 0 * 4 + 0] = 1;
                poly[1 * 2 * 4 + 0 * 4 + 1] = 3;
                poly[1 * 2 * 4 + 0 * 4 + 2] = 4;
                poly[1 * 2 * 4 + 0 * 4 + 3] = 2;
                poly[1 * 2 * 4 + 1 * 4 + 0] = 1;
                poly[1 * 2 * 4 + 1 * 4 + 1] = 3;
                poly[1 * 2 * 4 + 1 * 4 + 2] = 4;
                poly[1 * 2 * 4 + 1 * 4 + 3] = 2;

                auto result = HostArray<uint64_t>(2 * 4 * 2);
                vector<Modulus> mod{ 5, 7 };

                uint64_t mono_coeff = 4;
                size_t mono_exponent = 2;
                negacyclicMultiplyPolyMonoCoeffmod(poly.asPointer(), 2, 2, 4, mono_coeff, mono_exponent, &mod[0], result.asPointer());

                ASSERT_EQ(4ULL, result[0 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(4ULL, result[0 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(5ULL, result[0 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(6ULL, result[0 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(4ULL, result[0 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(5ULL, result[0 * 2 * 4 + 1 * 4 + 3]);
                ASSERT_EQ(4ULL, result[1 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(4ULL, result[1 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(5ULL, result[1 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(6ULL, result[1 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(4ULL, result[1 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(5ULL, result[1 * 2 * 4 + 1 * 4 + 3]);
            }
        }

        TEST(PolyArithSmallMod, DyadicProductCoeffMod)
        {
            
            {
                auto poly1 = HostArray<uint64_t>(3);
                auto poly2 = HostArray<uint64_t>(3);
                auto result = HostArray<uint64_t>(3);
                Modulus mod(13);

                poly1[0] = 1;
                poly1[1] = 1;
                poly1[2] = 1;
                poly2[0] = 2;
                poly2[1] = 3;
                poly2[2] = 4;

                dyadicProductCoeffmod(poly1.asPointer(), poly2.asPointer(), 3, mod, result.asPointer());
                ASSERT_EQ(2ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(4ULL, result[2]);
            }
            {
                auto poly1 = HostArray<uint64_t>(3 * 2);
                auto poly2 = HostArray<uint64_t>(3 * 2);
                auto result = HostArray<uint64_t>(3 * 2);
                vector<Modulus> mod{ 13, 7 };

                poly1[0 * 3 + 0] = 1;
                poly1[0 * 3 + 1] = 2;
                poly1[0 * 3 + 2] = 1;
                poly1[1 * 3 + 0] = 2;
                poly1[1 * 3 + 1] = 1;
                poly1[1 * 3 + 2] = 2;

                poly2[0 * 3 + 0] = 2;
                poly2[0 * 3 + 1] = 3;
                poly2[0 * 3 + 2] = 4;
                poly2[1 * 3 + 0] = 2;
                poly2[1 * 3 + 1] = 3;
                poly2[1 * 3 + 2] = 4;

                dyadicProductCoeffmod(poly1.asPointer(), poly2.asPointer(), 2, 3, &mod[0], result.asPointer());
                ASSERT_EQ(2ULL, result[0 * 3 + 0]);
                ASSERT_EQ(6ULL, result[0 * 3 + 1]);
                ASSERT_EQ(4ULL, result[0 * 3 + 2]);
                ASSERT_EQ(4ULL, result[1 * 3 + 0]);
                ASSERT_EQ(3ULL, result[1 * 3 + 1]);
                ASSERT_EQ(1ULL, result[1 * 3 + 2]);
            }
            {
                auto poly1 = HostArray<uint64_t>(2 * 3 * 2);
                auto poly2 = HostArray<uint64_t>(2 * 3 * 2);
                auto result = HostArray<uint64_t>(2 * 3 * 2);
                vector<Modulus> mod{ 13, 7 };

                poly1[0 * 2 * 3 + 0 * 3 + 0] = 1;
                poly1[0 * 2 * 3 + 0 * 3 + 1] = 2;
                poly1[0 * 2 * 3 + 0 * 3 + 2] = 1;
                poly1[0 * 2 * 3 + 1 * 3 + 0] = 2;
                poly1[0 * 2 * 3 + 1 * 3 + 1] = 1;
                poly1[0 * 2 * 3 + 1 * 3 + 2] = 2;
                poly1[1 * 2 * 3 + 0 * 3 + 0] = 1;
                poly1[1 * 2 * 3 + 0 * 3 + 1] = 2;
                poly1[1 * 2 * 3 + 0 * 3 + 2] = 1;
                poly1[1 * 2 * 3 + 1 * 3 + 0] = 2;
                poly1[1 * 2 * 3 + 1 * 3 + 1] = 1;
                poly1[1 * 2 * 3 + 1 * 3 + 2] = 2;

                poly2[0 * 2 * 3 + 0 * 3 + 0] = 2;
                poly2[0 * 2 * 3 + 0 * 3 + 1] = 3;
                poly2[0 * 2 * 3 + 0 * 3 + 2] = 4;
                poly2[0 * 2 * 3 + 1 * 3 + 0] = 2;
                poly2[0 * 2 * 3 + 1 * 3 + 1] = 3;
                poly2[0 * 2 * 3 + 1 * 3 + 2] = 4;
                poly2[1 * 2 * 3 + 0 * 3 + 0] = 2;
                poly2[1 * 2 * 3 + 0 * 3 + 1] = 3;
                poly2[1 * 2 * 3 + 0 * 3 + 2] = 4;
                poly2[1 * 2 * 3 + 1 * 3 + 0] = 2;
                poly2[1 * 2 * 3 + 1 * 3 + 1] = 3;
                poly2[1 * 2 * 3 + 1 * 3 + 2] = 4;

                dyadicProductCoeffmod(poly1.asPointer(), poly2.asPointer(), 2, 2, 3, &mod[0], result.asPointer());
                ASSERT_EQ(2ULL, result[0 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(6ULL, result[0 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(4ULL, result[0 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(4ULL, result[0 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(3ULL, result[0 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(1ULL, result[0 * 2 * 3 + 1 * 3 + 2]);
                ASSERT_EQ(2ULL, result[1 * 2 * 3 + 0 * 3 + 0]);
                ASSERT_EQ(6ULL, result[1 * 2 * 3 + 0 * 3 + 1]);
                ASSERT_EQ(4ULL, result[1 * 2 * 3 + 0 * 3 + 2]);
                ASSERT_EQ(4ULL, result[1 * 2 * 3 + 1 * 3 + 0]);
                ASSERT_EQ(3ULL, result[1 * 2 * 3 + 1 * 3 + 1]);
                ASSERT_EQ(1ULL, result[1 * 2 * 3 + 1 * 3 + 2]);
            }
        }

        TEST(PolyArithSmallMod, PolyInftyNormCoeffMod)
        {
            
            auto poly = HostArray<uint64_t>(4);
            Modulus mod(10);

            poly[0] = 0;
            poly[1] = 1;
            poly[2] = 2;
            poly[3] = 3;
            ASSERT_EQ(0x3ULL, polyInftyNormCoeffmod(poly.asPointer(), 4, mod));

            poly[0] = 0;
            poly[1] = 1;
            poly[2] = 2;
            poly[3] = 8;
            ASSERT_EQ(0x2ULL, polyInftyNormCoeffmod(poly.asPointer(), 4, mod));
        }

        TEST(PolyArithSmallMod, NegacyclicShiftPolyCoeffMod)
        {
            
            {
                auto poly = HostArray<uint64_t>(4);
                auto result = HostArray<uint64_t>(4);
                setZeroUint(4, poly.get());
                setZeroUint(4, result.get());

                Modulus mod(10);

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 0, mod, result.asPointer());
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 1, mod, result.asPointer());
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 2, mod, result.asPointer());
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 3, mod, result.asPointer());
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                poly[0] = 1;
                poly[1] = 2;
                poly[2] = 3;
                poly[3] = 4;
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 0, mod, result.asPointer());
                ASSERT_EQ(1ULL, result[0]);
                ASSERT_EQ(2ULL, result[1]);
                ASSERT_EQ(3ULL, result[2]);
                ASSERT_EQ(4ULL, result[3]);
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 1, mod, result.asPointer());
                ASSERT_EQ(6ULL, result[0]);
                ASSERT_EQ(1ULL, result[1]);
                ASSERT_EQ(2ULL, result[2]);
                ASSERT_EQ(3ULL, result[3]);
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 2, mod, result.asPointer());
                ASSERT_EQ(7ULL, result[0]);
                ASSERT_EQ(6ULL, result[1]);
                ASSERT_EQ(1ULL, result[2]);
                ASSERT_EQ(2ULL, result[3]);
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 4, 3, mod, result.asPointer());
                ASSERT_EQ(8ULL, result[0]);
                ASSERT_EQ(7ULL, result[1]);
                ASSERT_EQ(6ULL, result[2]);
                ASSERT_EQ(1ULL, result[3]);

                poly[0] = 1;
                poly[1] = 2;
                poly[2] = 3;
                poly[3] = 4;
                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 1, mod, result.asPointer());
                negacyclicShiftPolyCoeffmod(poly + 2, 2, 1, mod, result + 2);
                ASSERT_EQ(8ULL, result[0]);
                ASSERT_EQ(1ULL, result[1]);
                ASSERT_EQ(6ULL, result[2]);
                ASSERT_EQ(3ULL, result[3]);
            }
            {
                auto poly = HostArray<uint64_t>(4 * 2);
                auto result = HostArray<uint64_t>(4 * 2);

                vector<Modulus> mod{ 10, 11 };

                poly[0 * 4 + 0] = 1;
                poly[0 * 4 + 1] = 2;
                poly[0 * 4 + 2] = 3;
                poly[0 * 4 + 3] = 4;
                poly[1 * 4 + 0] = 1;
                poly[1 * 4 + 1] = 2;
                poly[1 * 4 + 2] = 3;
                poly[1 * 4 + 3] = 4;

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 4, 0, &mod[0], result.asPointer());
                ASSERT_EQ(1ULL, result[0 * 4 + 0]);
                ASSERT_EQ(2ULL, result[0 * 4 + 1]);
                ASSERT_EQ(3ULL, result[0 * 4 + 2]);
                ASSERT_EQ(4ULL, result[0 * 4 + 3]);
                ASSERT_EQ(1ULL, result[1 * 4 + 0]);
                ASSERT_EQ(2ULL, result[1 * 4 + 1]);
                ASSERT_EQ(3ULL, result[1 * 4 + 2]);
                ASSERT_EQ(4ULL, result[1 * 4 + 3]);

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 4, 1, &mod[0], result.asPointer());
                ASSERT_EQ(6ULL, result[0 * 4 + 0]);
                ASSERT_EQ(1ULL, result[0 * 4 + 1]);
                ASSERT_EQ(2ULL, result[0 * 4 + 2]);
                ASSERT_EQ(3ULL, result[0 * 4 + 3]);
                ASSERT_EQ(7ULL, result[1 * 4 + 0]);
                ASSERT_EQ(1ULL, result[1 * 4 + 1]);
                ASSERT_EQ(2ULL, result[1 * 4 + 2]);
                ASSERT_EQ(3ULL, result[1 * 4 + 3]);

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 4, 2, &mod[0], result.asPointer());
                ASSERT_EQ(7ULL, result[0 * 4 + 0]);
                ASSERT_EQ(6ULL, result[0 * 4 + 1]);
                ASSERT_EQ(1ULL, result[0 * 4 + 2]);
                ASSERT_EQ(2ULL, result[0 * 4 + 3]);
                ASSERT_EQ(8ULL, result[1 * 4 + 0]);
                ASSERT_EQ(7ULL, result[1 * 4 + 1]);
                ASSERT_EQ(1ULL, result[1 * 4 + 2]);
                ASSERT_EQ(2ULL, result[1 * 4 + 3]);

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 4, 3, &mod[0], result.asPointer());
                ASSERT_EQ(8ULL, result[0 * 4 + 0]);
                ASSERT_EQ(7ULL, result[0 * 4 + 1]);
                ASSERT_EQ(6ULL, result[0 * 4 + 2]);
                ASSERT_EQ(1ULL, result[0 * 4 + 3]);
                ASSERT_EQ(9ULL, result[1 * 4 + 0]);
                ASSERT_EQ(8ULL, result[1 * 4 + 1]);
                ASSERT_EQ(7ULL, result[1 * 4 + 2]);
                ASSERT_EQ(1ULL, result[1 * 4 + 3]);
            }
            {
                auto poly = HostArray<uint64_t>(2 * 4 * 2);
                auto result = HostArray<uint64_t>(2 * 4 * 2);

                vector<Modulus> mod{ 10, 11 };

                poly[0 * 2 * 4 + 0 * 4 + 0] = 1;
                poly[0 * 2 * 4 + 0 * 4 + 1] = 2;
                poly[0 * 2 * 4 + 0 * 4 + 2] = 3;
                poly[0 * 2 * 4 + 0 * 4 + 3] = 4;
                poly[0 * 2 * 4 + 1 * 4 + 0] = 1;
                poly[0 * 2 * 4 + 1 * 4 + 1] = 2;
                poly[0 * 2 * 4 + 1 * 4 + 2] = 3;
                poly[0 * 2 * 4 + 1 * 4 + 3] = 4;

                poly[1 * 2 * 4 + 0 * 4 + 0] = 1;
                poly[1 * 2 * 4 + 0 * 4 + 1] = 2;
                poly[1 * 2 * 4 + 0 * 4 + 2] = 3;
                poly[1 * 2 * 4 + 0 * 4 + 3] = 4;
                poly[1 * 2 * 4 + 1 * 4 + 0] = 1;
                poly[1 * 2 * 4 + 1 * 4 + 1] = 2;
                poly[1 * 2 * 4 + 1 * 4 + 2] = 3;
                poly[1 * 2 * 4 + 1 * 4 + 3] = 4;

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 2, 4, 0, &mod[0], result.asPointer());
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(3ULL, result[0 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(4ULL, result[0 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(3ULL, result[0 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(4ULL, result[0 * 2 * 4 + 1 * 4 + 3]);

                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(3ULL, result[1 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(4ULL, result[1 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(3ULL, result[1 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(4ULL, result[1 * 2 * 4 + 1 * 4 + 3]);

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 2, 4, 1, &mod[0], result.asPointer());
                ASSERT_EQ(6ULL, result[0 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(3ULL, result[0 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(7ULL, result[0 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(3ULL, result[0 * 2 * 4 + 1 * 4 + 3]);

                ASSERT_EQ(6ULL, result[1 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(3ULL, result[1 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(7ULL, result[1 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(3ULL, result[1 * 2 * 4 + 1 * 4 + 3]);

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 2, 4, 2, &mod[0], result.asPointer());
                ASSERT_EQ(7ULL, result[0 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(6ULL, result[0 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(8ULL, result[0 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(7ULL, result[0 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(2ULL, result[0 * 2 * 4 + 1 * 4 + 3]);

                ASSERT_EQ(7ULL, result[1 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(6ULL, result[1 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(8ULL, result[1 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(7ULL, result[1 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(2ULL, result[1 * 2 * 4 + 1 * 4 + 3]);

                negacyclicShiftPolyCoeffmod(poly.asPointer(), 2, 2, 4, 3, &mod[0], result.asPointer());
                ASSERT_EQ(8ULL, result[0 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(7ULL, result[0 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(6ULL, result[0 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(9ULL, result[0 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(8ULL, result[0 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(7ULL, result[0 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(1ULL, result[0 * 2 * 4 + 1 * 4 + 3]);

                ASSERT_EQ(8ULL, result[1 * 2 * 4 + 0 * 4 + 0]);
                ASSERT_EQ(7ULL, result[1 * 2 * 4 + 0 * 4 + 1]);
                ASSERT_EQ(6ULL, result[1 * 2 * 4 + 0 * 4 + 2]);
                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 0 * 4 + 3]);
                ASSERT_EQ(9ULL, result[1 * 2 * 4 + 1 * 4 + 0]);
                ASSERT_EQ(8ULL, result[1 * 2 * 4 + 1 * 4 + 1]);
                ASSERT_EQ(7ULL, result[1 * 2 * 4 + 1 * 4 + 2]);
                ASSERT_EQ(1ULL, result[1 * 2 * 4 + 1 * 4 + 3]);
            }
        }
    } // namespace util
} // namespace sealtest
