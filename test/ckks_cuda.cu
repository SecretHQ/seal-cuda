// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../src/troy_cuda.cuh"
#include <ctime>
#include <vector>
#include "gtest/gtest.h"

using namespace troyn;
using namespace std;

namespace troytest
{
    TEST(CKKSEncoderCudaTest, CKKSEncoderEncodeVectorDecodeTest)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            size_t slots = 32;
            parms.setPolyModulusDegree(slots << 1);
            parms.setCoeffModulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40 }));
            SEALContext context(parms, false, SecurityLevel::none);

            vector<complex<double>> values(slots);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(0.0, 0.0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 16);
            Plaintext plain;
            encoder.encode(values, context.firstParmsID(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 32;
            parms.setPolyModulusDegree(slots << 1);
            parms.setCoeffModulus(CoeffModulus::Create(slots << 1, { 60, 60, 60, 60 }));
            SEALContext context(parms, false, SecurityLevel::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.firstParmsID(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 64;
            parms.setPolyModulusDegree(slots << 1);
            parms.setCoeffModulus(CoeffModulus::Create(slots << 1, { 60, 60, 60 }));
            SEALContext context(parms, false, SecurityLevel::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.firstParmsID(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 64;
            parms.setPolyModulusDegree(slots << 1);
            parms.setCoeffModulus(CoeffModulus::Create(slots << 1, { 30, 30, 30, 30, 30 }));
            SEALContext context(parms, false, SecurityLevel::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.firstParmsID(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 32;
            parms.setPolyModulusDegree(128);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 30, 30, 30, 30, 30 }));
            SEALContext context(parms, false, SecurityLevel::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.firstParmsID(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Many primes
            size_t slots = 32;
            parms.setPolyModulusDegree(128);
            parms.setCoeffModulus(CoeffModulus::Create(
                128, { 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 }));
            SEALContext context(parms, false, SecurityLevel::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.firstParmsID(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 64;
            parms.setPolyModulusDegree(slots << 1);
            parms.setCoeffModulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40, 40 }));
            SEALContext context(parms, false, SecurityLevel::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 20);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            {
                // Use a very large scale
                double delta = pow(2.0, 110);
                Plaintext plain;
                encoder.encode(values, context.firstParmsID(), delta, plain);
                vector<complex<double>> result;
                encoder.decode(plain, result);

                for (size_t i = 0; i < slots; ++i)
                {
                    auto tmp = abs(values[i].real() - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
            {
                // Use a scale over 128 bits
                double delta = pow(2.0, 130);
                Plaintext plain;
                encoder.encode(values, context.firstParmsID(), delta, plain);
                vector<complex<double>> result;
                encoder.decode(plain, result);

                for (size_t i = 0; i < slots; ++i)
                {
                    auto tmp = abs(values[i].real() - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(CKKSEncoderCudaTest, CKKSEncoderEncodeSingleDecodeTest)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            size_t slots = 16;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));
            SEALContext context(parms, false, SecurityLevel::none);
            CKKSEncoder encoder(context);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);
            double delta = (1ULL << 16);
            Plaintext plain;
            vector<complex<double>> result;

            for (int iRun = 0; iRun < 50; iRun++)
            {
                double value = static_cast<double>(rand() % data_bound);
                encoder.encode(value, context.firstParmsID(), delta, plain);
                encoder.decode(plain, result);

                for (size_t i = 0; i < slots; ++i)
                {
                    auto tmp = abs(value - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            size_t slots = 32;
            parms.setPolyModulusDegree(slots << 1);
            parms.setCoeffModulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40 }));
            SEALContext context(parms, false, SecurityLevel::none);
            CKKSEncoder encoder(context);

            srand(static_cast<unsigned>(time(NULL)));
            {
                int data_bound = (1 << 30);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context.firstParmsID(), plain);
                    encoder.decode(plain, result);

                    for (size_t i = 0; i < slots; ++i)
                    {
                        auto tmp = abs(value - result[i].real());
                        ASSERT_TRUE(tmp < 0.5);
                    }
                }
            }
            {
                // Use a very large scale
                int data_bound = (1 << 20);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context.firstParmsID(), plain);
                    encoder.decode(plain, result);

                    for (size_t i = 0; i < slots; ++i)
                    {
                        auto tmp = abs(value - result[i].real());
                        ASSERT_TRUE(tmp < 0.5);
                    }
                }
            }
            {
                // Use a scale over 128 bits
                int data_bound = (1 << 20);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context.firstParmsID(), plain);
                    encoder.decode(plain, result);

                    for (size_t i = 0; i < slots; ++i)
                    {
                        auto tmp = abs(value - result[i].real());
                        ASSERT_TRUE(tmp < 0.5);
                    }
                }
            }
        }
    }
} // namespace sealtest
