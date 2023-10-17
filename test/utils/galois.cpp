// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../../src/context.h"
#include "../../src/utils/galois.h"
#include <stdexcept>
#include <vector>
#include "gtest/gtest.h"

using namespace troy;
using namespace troy::util;
using namespace std;

namespace troytest
{
    namespace util
    {
        TEST(GaloisToolTest, Create)
        {
            ASSERT_THROW(GaloisTool galois_tool(0), invalid_argument);
            ASSERT_THROW(GaloisTool galois_tool(18), invalid_argument);
            ASSERT_NO_THROW(GaloisTool galois_tool(1));
            ASSERT_NO_THROW(GaloisTool galois_tool(17));
        }

        TEST(GaloisToolTest, EltFromStep)
        {
            {
                GaloisTool galois_tool(3);
                ASSERT_EQ(15U, galois_tool.getEltFromStep(0));
                ASSERT_EQ(3U, galois_tool.getEltFromStep(1));
                ASSERT_EQ(3U, galois_tool.getEltFromStep(-3));
                ASSERT_EQ(9U, galois_tool.getEltFromStep(2));
                ASSERT_EQ(9U, galois_tool.getEltFromStep(-2));
                ASSERT_EQ(11U, galois_tool.getEltFromStep(3));
                ASSERT_EQ(11U, galois_tool.getEltFromStep(-1));
            }
        }

        TEST(GaloisToolTest, EltsFromSteps)
        {
            {
                GaloisTool galois_tool(3);
                auto elts = galois_tool.getEltsFromSteps({ 0, 1, -3, 2, -2, 3, -1 });
                uint32_t elts_true[7]{ 15, 3, 3, 9, 9, 11, 11 };
                for (size_t i = 0; i < elts.size(); i++)
                {
                    ASSERT_EQ(elts_true[i], elts[i]);
                }
            }
        }

        TEST(GaloisToolTest, EltsAll)
        {
            {
                GaloisTool galois_tool(3);
                auto elts = galois_tool.getEltsAll();
                uint32_t elts_true[5]{ 15, 3, 11, 9, 9 };
                for (size_t i = 0; i < elts.size(); i++)
                {
                    ASSERT_EQ(elts_true[i], elts[i]);
                }
            }
        }

        TEST(GaloisToolTest, IndexFromElt)
        {
            ASSERT_EQ(7, GaloisTool::GetIndexFromElt(15));
            ASSERT_EQ(1, GaloisTool::GetIndexFromElt(3));
            ASSERT_EQ(4, GaloisTool::GetIndexFromElt(9));
            ASSERT_EQ(5, GaloisTool::GetIndexFromElt(11));
        }

        TEST(GaloisToolTest, ApplyGalois)
        {
            EncryptionParameters parms(SchemeType::ckks);
            parms.setPolyModulusDegree(8);
            parms.setCoeffModulus({ 17 });
            SEALContext context(parms, false, SecurityLevel::none);
            auto context_data = context.keyContextData();
            auto galois_tool = context_data->galoisTool();
            uint64_t in[8]{ 0, 1, 2, 3, 4, 5, 6, 7 };
            uint64_t out[8];
            uint64_t out_true[8]{ 0, 14, 6, 1, 13, 7, 2, 12 };
            galois_tool->applyGalois(in, 3, Modulus(17), out);
            for (size_t i = 0; i < 8; i++)
            {
                ASSERT_EQ(out_true[i], out[i]);
            }
        }

        TEST(GaloisToolTest, ApplyGaloisNTT)
        {
            EncryptionParameters parms(SchemeType::ckks);
            parms.setPolyModulusDegree(8);
            parms.setCoeffModulus({ 17 });
            SEALContext context(parms, false, SecurityLevel::none);
            auto context_data = context.keyContextData();
            auto galois_tool = context_data->galoisTool();
            uint64_t in[8]{ 0, 1, 2, 3, 4, 5, 6, 7 };
            uint64_t out[8];
            uint64_t out_true[8]{ 4, 5, 7, 6, 1, 0, 2, 3 };
            const_cast<GaloisTool *>(galois_tool)->applyGaloisNtt(in, 3, out);
            for (size_t i = 0; i < 8; i++)
            {
                ASSERT_EQ(out_true[i], out[i]);
            }
        }
    } // namespace util
} // namespace sealtest
