// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../src/batchencoder.h"
#include "../src/context.h"
#include "../src/keygenerator.h"
#include "../src/modulus.h"
#include <vector>
#include "gtest/gtest.h"

using namespace troy;
using namespace troy::util;
using namespace std;

namespace troytest
{
    TEST(BatchEncoderTest, BatchUnbatchUIntVector)
    {
        EncryptionParameters parms(SchemeType::bfv);
        parms.setPolyModulusDegree(64);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 60 }));
        parms.setPlainModulus(257);

        SEALContext context(parms, false, SecurityLevel::none);
        ASSERT_TRUE(context.firstContextData()->qualifiers().using_batching);

        BatchEncoder batch_encoder(context);
        ASSERT_EQ(64ULL, batch_encoder.slotCount());
        vector<uint64_t> plain_vec;
        for (size_t i = 0; i < batch_encoder.slotCount(); i++)
        {
            plain_vec.push_back(i);
        }

        Plaintext plain;
        batch_encoder.encode(plain_vec, plain);
        vector<uint64_t> plain_vec2;
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        for (size_t i = 0; i < batch_encoder.slotCount(); i++)
        {
            plain_vec[i] = 5;
        }
        batch_encoder.encode(plain_vec, plain);
        ASSERT_TRUE(plain.to_string() == "5");
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        vector<uint64_t> short_plain_vec;
        for (size_t i = 0; i < 20; i++)
        {
            short_plain_vec.push_back(i);
        }
        batch_encoder.encode(short_plain_vec, plain);
        vector<uint64_t> short_plain_vec2;
        batch_encoder.decode(plain, short_plain_vec2);
        ASSERT_EQ(20ULL, short_plain_vec.size());
        ASSERT_EQ(64ULL, short_plain_vec2.size());
        for (size_t i = 0; i < 20; i++)
        {
            ASSERT_EQ(short_plain_vec[i], short_plain_vec2[i]);
        }
        for (size_t i = 20; i < batch_encoder.slotCount(); i++)
        {
            ASSERT_EQ(0ULL, short_plain_vec2[i]);
        }
    }

    TEST(BatchEncoderTest, BatchUnbatchIntVector)
    {
        EncryptionParameters parms(SchemeType::bfv);
        parms.setPolyModulusDegree(64);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 60 }));
        parms.setPlainModulus(257);

        SEALContext context(parms, false, SecurityLevel::none);
        ASSERT_TRUE(context.firstContextData()->qualifiers().using_batching);

        BatchEncoder batch_encoder(context);
        ASSERT_EQ(64ULL, batch_encoder.slotCount());
        vector<int64_t> plain_vec;
        for (uint64_t i = 0; i < static_cast<uint64_t>(batch_encoder.slotCount()); i++)
        {
            plain_vec.push_back(static_cast<int64_t>(i * (1 - (i & 1) * 2)));
        }

        Plaintext plain;
        batch_encoder.encode(plain_vec, plain);
        vector<int64_t> plain_vec2;
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        for (size_t i = 0; i < batch_encoder.slotCount(); i++)
        {
            plain_vec[i] = -5;
        }
        batch_encoder.encode(plain_vec, plain);
        ASSERT_TRUE(plain.to_string() == "FC");
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        vector<int64_t> short_plain_vec;
        for (int64_t i = 0; i < 20; i++)
        {
            short_plain_vec.push_back(i * (int64_t(1) - (i & 1) * 2));
        }
        batch_encoder.encode(short_plain_vec, plain);
        vector<int64_t> short_plain_vec2;
        batch_encoder.decode(plain, short_plain_vec2);
        ASSERT_EQ(20ULL, short_plain_vec.size());
        ASSERT_EQ(64ULL, short_plain_vec2.size());
        for (size_t i = 0; i < 20; i++)
        {
            ASSERT_EQ(short_plain_vec[i], short_plain_vec2[i]);
        }
        for (size_t i = 20; i < batch_encoder.slotCount(); i++)
        {
            ASSERT_EQ(0ULL, short_plain_vec2[i]);
        }
    }
} // namespace sealtest
