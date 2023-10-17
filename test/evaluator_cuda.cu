// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../src/troy_cuda.cuh"
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include "gtest/gtest.h"

using namespace std;
using troy::ParmsID;
using troy::SchemeType;
using troy::SecurityLevel;
using troy::Modulus;
using troy::CoeffModulus;
using troy::PlainModulus;
using EncryptionParameters = troy::EncryptionParametersCuda;
using SEALContext = troy::SEALContextCuda;
using Plaintext = troy::PlaintextCuda;
using Ciphertext = troy::CiphertextCuda;
using Encryptor = troy::EncryptorCuda;
using Decryptor = troy::DecryptorCuda;
using Evaluator = troy::EvaluatorCuda;
using KeyGenerator = troy::KeyGeneratorCuda;
using PublicKey = troy::PublicKeyCuda;
using SecretKey = troy::SecretKeyCuda;
using RelinKeys = troy::RelinKeysCuda;
using GaloisKeys = troy::GaloisKeysCuda;
using CKKSEncoder = troy::CKKSEncoderCuda;
using BatchEncoder = troy::BatchEncoderCuda;
using KernelProvider = troy::KernelProvider;


namespace troytest
{
    TEST(EvaluatorCudaTest, BFVEncryptNegateDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(), "3Fx^28 + 3Fx^25 + 3Fx^21 + 3Fx^20 + 3Fx^18 + 3Fx^14 + 3Fx^12 + 3Fx^10 + 3Fx^9 + 3Fx^6 "
                               "+ 3Fx^5 + 3Fx^4 + 3Fx^3");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "3F");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "3F";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "3Fx^2 + 3F";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptAddDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ("0", plain.to_string());
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 3Fx^1");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3F");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "2x^2 + 1x^1 + 3";
        plain2 = "3x^3 + 4x^2 + 5x^1 + 6";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^3 + 6x^2 + 6x^1 + 9");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3x^5 + 1x^4 + 4x^3 + 1";
        plain2 = "5x^2 + 9x^1 + 2";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^5 + 1x^4 + 4x^3 + 5x^2 + 9x^1 + 3");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptNegateDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(), "40x^28 + 40x^25 + 40x^21 + 40x^20 + 40x^18 + 40x^14 + 40x^12 + 40x^10 + 40x^9 + 40x^6 "
                               "+ 40x^5 + 40x^4 + 40x^3");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "40");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "40";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "40x^1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "40x^2 + 40";
        encryptor.encrypt(plain, encrypted);
        evaluator.negateInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptAddDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        // Test correction factor
        plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
        plain2 = "40x^18 + 40x^16 + 40x^14 + 40x^9 + 40x^8 + 40x^5 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encrypted1.correctionFactor() = 2;
        encryptor.encrypt(plain2, encrypted2);
        encrypted2.correctionFactor() = 64;
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ("0", plain.to_string());
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "1x^2 + 1";
        plain2 = "40x^1 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 40x^1");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "40x^2 + 40x^1 + 40";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "40x^2 + 40");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "2x^2 + 1x^1 + 3";
        plain2 = "3x^3 + 4x^2 + 5x^1 + 6";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^3 + 6x^2 + 6x^1 + 9");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3x^5 + 1x^4 + 4x^3 + 1";
        plain2 = "5x^2 + 9x^1 + 2";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.addInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^5 + 1x^4 + 4x^3 + 5x^2 + 9x^1 + 3");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, CKKSEncryptAddDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Adding two zero vectors
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context.firstParmsID(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.addInplace(encrypted, encrypted);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Adding two random vectors 100 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 30);
            const double delta = static_cast<double>(1 << 16);

            srand(static_cast<unsigned>(time(NULL)));

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2[i];
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.addInplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Adding two random vectors 100 times
            size_t slot_size = 8;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 30);
            const double delta = static_cast<double>(1 << 16);

            srand(static_cast<unsigned>(time(NULL)));

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2[i];
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.addInplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptAddPlainDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Adding two zero vectors
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context.firstParmsID(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.addPlainInplace(encrypted, plain);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Adding two random vectors 50 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(static_cast<unsigned>(time(NULL)));

            for (int expCount = 0; expCount < 50; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2[i];
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.addPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Adding two random vectors 50 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            double input2;
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(static_cast<unsigned>(time(NULL)));

            for (int expCount = 0; expCount < 50; expCount++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / data_bound;
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2;
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.addPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Adding two random vectors 50 times
            size_t slot_size = 8;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            double input2;
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(static_cast<unsigned>(time(NULL)));

            for (int expCount = 0; expCount < 50; expCount++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / data_bound;
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2;
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.addPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptSubPlainDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Subtracting two zero vectors
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context.firstParmsID(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.addPlainInplace(encrypted, plain);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Subtracting two random vectors 100 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(static_cast<unsigned>(time(NULL)));

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] - input2[i];
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.subPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Subtracting two random vectors 100 times
            size_t slot_size = 8;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(static_cast<unsigned>(time(NULL)));

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] - input2[i];
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.subPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, BFVEncryptSubDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 3Fx^16 + 1x^12 + 1x^10 + 3Fx^8 + 1x^6 + 1x^4 + 1x^3 + 3F");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3F");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptAddPlainDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.addPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.addPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.addPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.addPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 3Fx^1");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.addPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptSubPlainDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 3Fx^16 + 1x^12 + 1x^10 + 3Fx^8 + 1x^6 + 1x^4 + 1x^3 + 3F");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3F");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptMultiplyPlainDecrypt)
    {
        KernelProvider::initialize();
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus(1 << 6);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^2";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^4 + 1x^3 + 1x^2");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^3 + 1x^2 + 1x^1");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "3Fx^2 + 3Fx^1 + 3F";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus((1ULL << 20) - 1);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain2 = "5";
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus((1ULL << 40) - 1);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain2 = "5";
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus(PlainModulus::Batching(64, 20));
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus(PlainModulus::Batching(64, 40));
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            // First test with constant plaintext
            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            // Now test a non-constant plaintext
            vector<int64_t> input(batch_encoder.slotCount() - 1, 7);
            input.push_back(1);
            vector<int64_t> true_result(batch_encoder.slotCount() - 1, 49);
            true_result.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            input = vector<int64_t>(batch_encoder.slotCount() - 1, -7);
            input.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
    }

    TEST(EvaluatorCudaTest, BFVEncryptMultiplyDecrypt)
    {
        KernelProvider::initialize();
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus(1 << 6);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus((1ULL << 60) - 1);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "FFFFFFFFFFFFFFEx^3 + FFFFFFFFFFFFFFEx^2 + FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus(1 << 6);
            parms.setPolyModulusDegree(128);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bfv);
            Modulus plain_modulus(1 << 8);
            parms.setPolyModulusDegree(128);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Plaintext plain, plain1;

            plain1 = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + "
                                   "6Cx^15 + 70x^14 + 74x^13 + 71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + "
                                   "26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
    }

    TEST(EvaluatorCudaTest, BGVEncryptSubDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        // Test correction factor
        plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
        plain2 = "40x^18 + 40x^16 + 40x^14 + 40x^9 + 40x^8 + 40x^5 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encrypted1.correctionFactor() = 2;
        encryptor.encrypt(plain2, encrypted2);
        encrypted2.correctionFactor() = 64;
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "40x^2 + 40");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "1x^2 + 1";
        plain2 = "40x^1 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.subInplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptAddPlainDecrypt)
    {
        KernelProvider::initialize();
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus(65);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.addPlainInplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            // Test correction factor
            plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encrypted1.correctionFactor() = 2;
            evaluator.addPlainInplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.addPlainInplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.addPlainInplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "40x^1 + 40";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.addPlainInplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 40x^1");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "40x^2 + 40x^1 + 40";
            plain2 = "1x^2 + 1x^1 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.addPlainInplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
    }

    TEST(EvaluatorCudaTest, BGVEncryptSubPlainDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(64);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        // Test correction factor
        plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encrypted1.correctionFactor() = 2;
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "40x^2 + 40");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "1x^2 + 1";
        plain2 = "40x^1 + 40";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.subPlainInplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptMultiplyPlainDecrypt)
    {
        KernelProvider::initialize();
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus(65);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^2";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^4 + 1x^3 + 1x^2");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^3 + 1x^2 + 1x^1");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain1 = "3Fx^2 + 3Fx^1 + 3F";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus((1ULL << 20) - 1);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain2 = "5";
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus((1ULL << 40) - 1);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain2 = "5";
            evaluator.multiplyPlainInplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus(PlainModulus::Batching(64, 20));
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus(PlainModulus::Batching(64, 40));
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            // First test with constant plaintext
            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slotCount(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slotCount(), 49) == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            // Now test a non-constant plaintext
            vector<int64_t> input(batch_encoder.slotCount() - 1, 7);
            input.push_back(1);
            vector<int64_t> true_result(batch_encoder.slotCount() - 1, 49);
            true_result.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            input = vector<int64_t>(batch_encoder.slotCount() - 1, -7);
            input.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyPlainInplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
    }

    TEST(EvaluatorCudaTest, BGVEncryptMultiplyDecrypt)
    {
        KernelProvider::initialize();
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus(65);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus((1ULL << 60) - 1);
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "FFFFFFFFFFFFFFEx^3 + FFFFFFFFFFFFFFEx^2 + FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus(1 << 6);
            parms.setPolyModulusDegree(128);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiplyInplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parmsID() == encrypted1.parmsID());
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            Modulus plain_modulus(1 << 8);
            parms.setPolyModulusDegree(128);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted1;
            Plaintext plain, plain1;

            plain1 = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + "
                                   "6Cx^15 + 70x^14 + 74x^13 + 71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + "
                                   "26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
        }
    }

#include "../src/randomgen.h"
    TEST(EvaluatorCudaTest, BFVRelinearize)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40, 40 }));

        SEALContext context(parms, true, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        RelinKeys rlk;
        keygen.createRelinKeys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted(context);
        Ciphertext encrypted2(context);

        Plaintext plain;
        Plaintext plain2;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain == plain2);

        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain == plain2);

        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");

        // Relinearization with modulus switching
        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.modSwitchToNextInplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.modSwitchToNextInplace(encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.modSwitchToNextInplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");
    }

    TEST(EvaluatorCudaTest, BGVRelinearize)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 60, 60, 60, 60 }));

        SEALContext context(parms, true, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        RelinKeys rlk;
        keygen.createRelinKeys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted(context);
        Ciphertext encrypted2(context);

        Plaintext plain;
        Plaintext plain2;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain == plain2);

        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain == plain2);

        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");

        // Relinearization with modulus switching
        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.modSwitchToNextInplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.modSwitchToNextInplace(encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.relinearizeInplace(encrypted, rlk);
        evaluator.modSwitchToNextInplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");
    }

    TEST(EvaluatorCudaTest, CKKSEncryptNaiveMultiplyDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Multiplying two zero vectors
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 30);
            encoder.encode(input, context.firstParmsID(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.multiplyInplace(encrypted, encrypted);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Multiplying two random vectors
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1ULL << 40);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.multiplyInplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors
            size_t slot_size = 16;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1ULL << 40);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.multiplyInplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptMultiplyByNumberDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Multiplying two random vectors by an integer
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            int64_t input2;
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = max(rand() % data_bound, 1);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * static_cast<double>(input2);
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiplyPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors by an integer
            size_t slot_size = 8;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            int64_t input2;
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = max(rand() % data_bound, 1);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * static_cast<double>(input2);
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiplyPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors by a double
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            double input2;
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / static_cast<double>(data_bound);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2;
                }

                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiplyPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors by a double
            size_t slot_size = 16;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 2.1);
            double input2;
            vector<complex<double>> expected(slot_size, 2.1);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / static_cast<double>(data_bound);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2;
                }

                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiplyPlainInplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptMultiplyRelinDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 10;

            for (int round = 0; round < 50; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 10;

            for (int round = 0; round < 50; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 2;
            parms.setPolyModulusDegree(8);
            parms.setCoeffModulus(CoeffModulus::Create(8, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            int data_bound = 1 << 10;
            const double delta = static_cast<double>(1ULL << 40);

            for (int round = 0; round < 50; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

                evaluator.multiplyInplace(encrypted1, encrypted2);
                // Evaluator.relinearizeInplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptSquareRelinDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                // Evaluator.squareInplace(encrypted);
                evaluator.multiplyInplace(encrypted, encrypted);
                evaluator.relinearizeInplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                // Evaluator.squareInplace(encrypted);
                evaluator.multiplyInplace(encrypted, encrypted);
                evaluator.relinearizeInplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                // Evaluator.squareInplace(encrypted);
                evaluator.multiplyInplace(encrypted, encrypted);
                evaluator.relinearizeInplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptMultiplyRelinRescaleDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 64;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30, 30 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);
                evaluator.rescaleToNextInplace(encrypted1);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parmsID() == next_parms_id);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.setPolyModulusDegree(128);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);
                evaluator.rescaleToNextInplace(encrypted1);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parmsID() == next_parms_id);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.setPolyModulusDegree(128);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 60, 60, 60, 60, 60 }));

            SEALContext context(parms, true, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 60);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);
                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);

                // Scale down by two levels
                auto target_parms = context.firstContextData()->nextContextData()->nextContextData()->parmsID();
                evaluator.rescaleToInplace(encrypted1, target_parms);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parmsID() == target_parms);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }

            // Test with inverted order: rescale then relin
            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 50);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);
                evaluator.multiplyInplace(encrypted1, encrypted2);

                // Scale down by two levels
                auto target_parms = context.firstContextData()->nextContextData()->nextContextData()->parmsID();
                evaluator.rescaleToInplace(encrypted1, target_parms);

                // Relinearize now
                evaluator.relinearizeInplace(encrypted1, rlk);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parmsID() == target_parms);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptSquareRelinRescaleDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 64;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 50, 50, 50 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 8;

            for (int round = 0; round < 100; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                evaluator.squareInplace(encrypted);
                evaluator.relinearizeInplace(encrypted, rlk);
                evaluator.rescaleToNextInplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parmsID() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.setPolyModulusDegree(128);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 50, 50, 50 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 8;

            for (int round = 0; round < 100; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                evaluator.squareInplace(encrypted);
                evaluator.relinearizeInplace(encrypted, rlk);
                evaluator.rescaleToNextInplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parmsID() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptModSwitchDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Modulus switching without rescaling for random vectors
            size_t slot_size = 64;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60, 60, 60 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            int data_bound = 1 << 30;
            srand(static_cast<unsigned>(time(NULL)));

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                // Not inplace
                Ciphertext destination;
                evaluator.modSwitchToNext(encrypted, destination);

                // Check correctness of modulus switching
                ASSERT_TRUE(destination.parmsID() == next_parms_id);

                decryptor.decrypt(destination, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }

                // Inplace
                evaluator.modSwitchToNextInplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parmsID() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Modulus switching without rescaling for random vectors
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40, 40 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            int data_bound = 1 << 30;
            srand(static_cast<unsigned>(time(NULL)));

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                // Not inplace
                Ciphertext destination;
                evaluator.modSwitchToNext(encrypted, destination);

                // Check correctness of modulus switching
                ASSERT_TRUE(destination.parmsID() == next_parms_id);

                decryptor.decrypt(destination, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }

                // Inplace
                evaluator.modSwitchToNextInplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parmsID() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Modulus switching without rescaling for random vectors
            size_t slot_size = 32;
            parms.setPolyModulusDegree(128);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40, 40, 40 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            int data_bound = 1 << 30;
            srand(static_cast<unsigned>(time(NULL)));

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.firstParmsID(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

                // Not inplace
                Ciphertext destination;
                evaluator.modSwitchToNext(encrypted, destination);

                // Check correctness of modulus switching
                ASSERT_TRUE(destination.parmsID() == next_parms_id);

                decryptor.decrypt(destination, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }

                // Inplace
                evaluator.modSwitchToNextInplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parmsID() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptMultiplyRelinRescaleModSwitchAddDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Multiplication and addition without rescaling for random vectors
            size_t slot_size = 64;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 50, 50, 50 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encrypted3;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plain3;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> input3(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 8;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] + input3[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);
                encoder.encode(input3, context.firstParmsID(), delta * delta, plain3);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                encryptor.encrypt(plain3, encrypted3);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted3.parmsID() == context.firstParmsID());

                // Enc1*enc2
                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);
                evaluator.rescaleToNextInplace(encrypted1);

                // Check correctness of modulus switching with rescaling
                ASSERT_TRUE(encrypted1.parmsID() == next_parms_id);

                // Move enc3 to the level of enc1 * enc2
                evaluator.rescaleToInplace(encrypted3, next_parms_id);

                // Enc1*enc2 + enc3
                evaluator.addInplace(encrypted1, encrypted3);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplication and addition without rescaling for random vectors
            size_t slot_size = 16;
            parms.setPolyModulusDegree(128);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 50, 50, 50 }));

            SEALContext context(parms, true, SecurityLevel::none);
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encrypted3;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plain3;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> input3(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 8;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] + input3[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.firstParmsID(), delta, plain1);
                encoder.encode(input2, context.firstParmsID(), delta, plain2);
                encoder.encode(input3, context.firstParmsID(), delta * delta, plain3);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                encryptor.encrypt(plain3, encrypted3);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted3.parmsID() == context.firstParmsID());

                // Enc1*enc2
                evaluator.multiplyInplace(encrypted1, encrypted2);
                evaluator.relinearizeInplace(encrypted1, rlk);
                evaluator.rescaleToNextInplace(encrypted1);

                // Check correctness of modulus switching with rescaling
                ASSERT_TRUE(encrypted1.parmsID() == next_parms_id);

                // Move enc3 to the level of enc1 * enc2
                evaluator.rescaleToInplace(encrypted3, next_parms_id);

                // Enc1*enc2 + enc3
                evaluator.addInplace(encrypted1, encrypted3);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptRotateDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Maximal number of slots
            size_t slot_size = 4;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            GaloisKeys glk;
            keygen.createGaloisKeys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());
            CKKSEncoder encoder(context);
            const double delta = static_cast<double>(1ULL << 30);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.firstParmsID(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.complexConjugateInplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[i].real(), round(output[i].real()));
                ASSERT_EQ(-input[i].imag(), round(output[i].imag()));
            }
        }
        {
            size_t slot_size = 32;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            GaloisKeys glk;
            keygen.createGaloisKeys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());
            CKKSEncoder encoder(context);
            const double delta = static_cast<double>(1ULL << 30);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.firstParmsID(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < input.size(); i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.complexConjugateInplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[i].real()), round(output[i].real()));
                ASSERT_EQ(round(-input[i].imag()), round(output[i].imag()));
            }
        }
    }

    TEST(EvaluatorCudaTest, CKKSEncryptRescaleRotateDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Maximal number of slots
            size_t slot_size = 4;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            SEALContext context(parms, true, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            GaloisKeys glk;
            keygen.createGaloisKeys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());
            CKKSEncoder encoder(context);
            const double delta = pow(2.0, 70);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.firstParmsID(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.complexConjugateInplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[i].real(), round(output[i].real()));
                ASSERT_EQ(-input[i].imag(), round(output[i].imag()));
            }
        }
        {
            size_t slot_size = 32;
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));

            SEALContext context(parms, true, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            GaloisKeys glk;
            keygen.createGaloisKeys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());
            CKKSEncoder encoder(context);
            const double delta = pow(2, 70);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.firstParmsID(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.rotateVectorInplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.firstParmsID(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.rescaleToNextInplace(encrypted);
            evaluator.complexConjugateInplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[i].real()), round(output[i].real()));
                ASSERT_EQ(round(-input[i].imag()), round(output[i].imag()));
            }
        }
    }

    TEST(EvaluatorCudaTest, BFVEncryptSquareDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 8);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "FFx^2 + FF";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^2 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "FF";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^12 + 2x^11 + 3x^10 + 4x^9 + 3x^8 + 4x^7 + 5x^6 + 4x^5 + 4x^4 + 2x^3 + 1x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^16";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + 6Cx^15 + 70x^14 + 74x^13 + "
            "71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + 26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptMultiplyManyDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        RelinKeys rlk;
        keygen.createRelinKeys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, product;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds{ encrypted1, encrypted2, encrypted3 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^6 + 2x^5 + 3x^4 + 3x^3 + 2x^2 + 1x^1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "3Fx^3 + 3F";
        plain2 = "3Fx^4 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = { encrypted1, encrypted2 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(2, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^7 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "1x^1";
        plain2 = "3Fx^4 + 3Fx^3 + 3Fx^2 + 3Fx^1 + 3F";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^7 + 3Ex^6 + 3Dx^5 + 3Dx^4 + 3Dx^3 + 3Ex^2 + 3Fx^1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "1";
        plain2 = "3F";
        plain3 = "1";
        plain4 = "3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptExponentiateDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        RelinKeys rlk;
        keygen.createRelinKeys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^2 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 1, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 2, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^3 + 3x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "3Fx^2 + 3Fx^1 + 3F";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 3, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^6 + 3Dx^5 + 3Ax^4 + 39x^3 + 3Ax^2 + 3Dx^1 + 3F");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^8";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 4, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptAddManyDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, sum;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3x^2 + 2x^1 + 2");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "3Fx^3 + 3F";
        plain2 = "3Fx^4 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = {
            encrypted1,
            encrypted2,
        };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^4 + 3Fx^3 + 3E");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "1x^1";
        plain2 = "3Fx^4 + 3Fx^3 + 3Fx^2 + 3Fx^1 + 3F";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^4 + 3Fx^3 + 1x^1");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "1";
        plain2 = "3F";
        plain3 = "1";
        plain4 = "3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^16 + 2x^15 + 1x^13 + 1x^12 + 1x^10 + 1x^9 + 2x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 2x^3 + 2x^2 + 1x^1 + 3");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptSquareDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(257);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "100x^2 + 100";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^2 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "100";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^12 + 2x^11 + 3x^10 + 4x^9 + 3x^8 + 4x^7 + 5x^6 + 4x^5 + 4x^4 + 2x^3 + 1x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^16";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.squareInplace(encrypted);
        evaluator.squareInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + 6Cx^15 + 70x^14 + 74x^13 + "
            "71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + 26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptMultiplyManyDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        RelinKeys rlk;
        keygen.createRelinKeys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, product;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds{ encrypted1, encrypted2, encrypted3 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^6 + 2x^5 + 3x^4 + 3x^3 + 2x^2 + 1x^1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "40x^3 + 40";
        plain2 = "40x^4 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = { encrypted1, encrypted2 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(2, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^7 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "1x^1";
        plain2 = "40x^4 + 40x^3 + 40x^2 + 40x^1 + 40";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "40x^7 + 3Fx^6 + 3Ex^5 + 3Ex^4 + 3Ex^3 + 3Fx^2 + 40x^1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "1";
        plain2 = "40";
        plain3 = "1";
        plain4 = "40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptExponentiateDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        RelinKeys rlk;
        keygen.createRelinKeys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^2 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 1, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 2, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^3 + 3x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "40x^2 + 40x^1 + 40";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 3, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "40x^6 + 3Ex^5 + 3Bx^4 + 3Ax^3 + 3Bx^2 + 3Ex^1 + 40");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^8";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiateInplace(encrypted, 4, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptAddManyDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, sum;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3x^2 + 2x^1 + 2");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "40x^3 + 40";
        plain2 = "40x^4 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = {
            encrypted1,
            encrypted2,
        };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "40x^4 + 40x^3 + 3F");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "1x^1";
        plain2 = "40x^4 + 40x^3 + 40x^2 + 40x^1 + 40";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "40x^4 + 40x^3 + 1x^1");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "1";
        plain2 = "40";
        plain3 = "1";
        plain4 = "40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.addMany(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^16 + 2x^15 + 1x^13 + 1x^12 + 1x^10 + 1x^9 + 2x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 2x^3 + 2x^2 + 1x^1 + 3");
        ASSERT_TRUE(encrypted1.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == sum.parmsID());
        ASSERT_TRUE(encrypted4.parmsID() == sum.parmsID());
        ASSERT_TRUE(sum.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, TransformPlainToNTT)
    {
        KernelProvider::initialize();
        auto evaluator_transform_plain_to_ntt = [](SchemeType scheme) {
            EncryptionParameters parms(scheme);
            Modulus plain_modulus(1 << 6);
            parms.setPolyModulusDegree(128);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));
            SEALContext context(parms, true, SecurityLevel::none);

            Evaluator evaluator(context);
            Plaintext plain("0");
            ASSERT_FALSE(plain.isNttForm());
            evaluator.transformToNttInplace(plain, context.firstParmsID());
            ASSERT_TRUE(plain.isZero());
            ASSERT_TRUE(plain.isNttForm());
            ASSERT_TRUE(plain.parmsID() == context.firstParmsID());

            plain.release();
            plain = "0";
            ASSERT_FALSE(plain.isNttForm());
            auto next_parms_id = context.firstContextData()->nextContextData()->parmsID();
            evaluator.transformToNttInplace(plain, next_parms_id);
            ASSERT_TRUE(plain.isZero());
            ASSERT_TRUE(plain.isNttForm());
            ASSERT_TRUE(plain.parmsID() == next_parms_id);

            plain.release();
            plain = "1";
            ASSERT_FALSE(plain.isNttForm());
            evaluator.transformToNttInplace(plain, context.firstParmsID());
            for (size_t i = 0; i < 256; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(1));
            }
            ASSERT_TRUE(plain.isNttForm());
            ASSERT_TRUE(plain.parmsID() == context.firstParmsID());

            plain.release();
            plain = "1";
            ASSERT_FALSE(plain.isNttForm());
            evaluator.transformToNttInplace(plain, next_parms_id);
            for (size_t i = 0; i < 128; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(1));
            }
            ASSERT_TRUE(plain.isNttForm());
            ASSERT_TRUE(plain.parmsID() == next_parms_id);

            plain.release();
            plain = "2";
            ASSERT_FALSE(plain.isNttForm());
            evaluator.transformToNttInplace(plain, context.firstParmsID());
            for (size_t i = 0; i < 256; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(2));
            }
            ASSERT_TRUE(plain.isNttForm());
            ASSERT_TRUE(plain.parmsID() == context.firstParmsID());

            plain.release();
            plain = "2";
            evaluator.transformToNttInplace(plain, next_parms_id);
            for (size_t i = 0; i < 128; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(2));
            }
            ASSERT_TRUE(plain.isNttForm());
            ASSERT_TRUE(plain.parmsID() == next_parms_id);
        };
        evaluator_transform_plain_to_ntt(SchemeType::bfv);
        evaluator_transform_plain_to_ntt(SchemeType::bgv);
    }

    TEST(EvaluatorCudaTest, TransformEncryptedToFromNTT)
    {
        KernelProvider::initialize();
        auto evaluator_transform_encrypted_to_from_ntt = [](SchemeType scheme) {
            EncryptionParameters parms(scheme);
            Modulus plain_modulus(1 << 6);
            parms.setPolyModulusDegree(128);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Plaintext plain;
            Ciphertext encrypted;
            plain = "0";
            encryptor.encrypt(plain, encrypted);
            evaluator.transformToNttInplace(encrypted);
            evaluator.transformFromNttInplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(plain.to_string() == "0");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain = "1";
            encryptor.encrypt(plain, encrypted);
            evaluator.transformToNttInplace(encrypted);
            evaluator.transformFromNttInplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(plain.to_string() == "1");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            plain = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
            encryptor.encrypt(plain, encrypted);
            evaluator.transformToNttInplace(encrypted);
            evaluator.transformFromNttInplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(
                plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        };
        evaluator_transform_encrypted_to_from_ntt(SchemeType::bfv);
        evaluator_transform_encrypted_to_from_ntt(SchemeType::bgv);
    }

    TEST(EvaluatorCudaTest, BFVEncryptMultiplyPlainNTTDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Plaintext plain;
        Plaintext plain_multiplier;
        Ciphertext encrypted;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier = 1;
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "0");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = 2;
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = 3;
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "6");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^20";
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(
            plain.to_string() ==
            "Fx^30 + Ex^29 + Dx^28 + Cx^27 + Bx^26 + Ax^25 + 1x^24 + 2x^23 + 3x^22 + 4x^21 + 5x^20");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BFVEncryptApplyGaloisDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(257);
        parms.setPolyModulusDegree(8);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        GaloisKeys glk;
        keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 15 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Plaintext plain("1");
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());

        plain = "1x^2";
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^6" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^6" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());

        plain = "1x^3 + 2x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("2x^6 + 1x^3 + 100x^1 + 1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7 + FFx^6 + 100x^5 + 1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
    }

    TEST(EvaluatorCudaTest, BFVEncryptRotateMatrixDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(257);
        parms.setPolyModulusDegree(8);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        GaloisKeys glk;
        keygen.createGaloisKeys(glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());
        BatchEncoder batch_encoder(context);

        Plaintext plain;
        vector<uint64_t> plain_vec{ 1, 2, 3, 4, 5, 6, 7, 8 };
        batch_encoder.encode(plain_vec, plain);
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        evaluator.rotateColumnsInplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 5, 6, 7, 8, 1, 2, 3, 4 }));

        evaluator.rotateRowsInplace(encrypted, -1, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 8, 5, 6, 7, 4, 1, 2, 3 }));

        evaluator.rotateRowsInplace(encrypted, 2, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 6, 7, 8, 5, 2, 3, 4, 1 }));

        evaluator.rotateColumnsInplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));

        evaluator.rotateRowsInplace(encrypted, 0, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));
    }

    TEST(EvaluatorCudaTest, BFVEncryptModSwitchToNextDecrypt)
    {
        KernelProvider::initialize();
        // The common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(1 << 6);

        // The parameters and the context of the higher level
        EncryptionParameters parms(SchemeType::bfv);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, SecurityLevel::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secretKey();
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());
        auto parms_id = context.firstParmsID();

        Ciphertext encrypted(context);
        Ciphertext encryptedRes;
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToNext(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        evaluator.modSwitchToNextInplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.firstParmsID();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToNext(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        evaluator.modSwitchToNextInplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.firstParmsID();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToNext(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        evaluator.modSwitchToNextInplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.firstParmsID();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToNext(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        evaluator.modSwitchToNextInplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }

    TEST(EvaluatorCudaTest, BFVEncryptModSwitchToDecrypt)
    {
        KernelProvider::initialize();
        // The common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(1 << 6);

        // The parameters and the context of the higher level
        EncryptionParameters parms(SchemeType::bfv);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, SecurityLevel::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secretKey();
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());
        auto parms_id = context.firstParmsID();

        Ciphertext encrypted(context);
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.firstParmsID();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.firstParmsID();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.firstParmsID();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }

    TEST(EvaluatorCudaTest, BGVEncryptMultiplyPlainNTTDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(65);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Plaintext plain;
        Plaintext plain_multiplier;
        Ciphertext encrypted;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier = 1;
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "0");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = 2;
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = 3;
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "6");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

        plain = "1x^20";
        encryptor.encrypt(plain, encrypted);
        evaluator.transformToNttInplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transformToNttInplace(plain_multiplier, context.firstParmsID());
        evaluator.multiplyPlainInplace(encrypted, plain_multiplier);
        evaluator.transformFromNttInplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(
            plain.to_string() ==
            "Fx^30 + Ex^29 + Dx^28 + Cx^27 + Bx^26 + Ax^25 + 1x^24 + 2x^23 + 3x^22 + 4x^21 + 5x^20");
        ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
    }

    TEST(EvaluatorCudaTest, BGVEncryptApplyGaloisDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(257);
        parms.setPolyModulusDegree(8);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(8, { 60, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        GaloisKeys glk;
        keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 15 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Plaintext plain("1");
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());

        plain = "1x^2";
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^6" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^6" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());

        plain = "1x^3 + 2x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.applyGaloisInplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("2x^6 + 1x^3 + 100x^1 + 1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7 + FFx^6 + 100x^5 + 1" == plain.to_string());
        evaluator.applyGaloisInplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
    }

    TEST(EvaluatorCudaTest, BGVEncryptRotateMatrixDecrypt)
    {
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(257);
        parms.setPolyModulusDegree(8);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        GaloisKeys glk;
        keygen.createGaloisKeys(glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());
        BatchEncoder batch_encoder(context);

        Plaintext plain;
        vector<uint64_t> plain_vec{ 1, 2, 3, 4, 5, 6, 7, 8 };
        batch_encoder.encode(plain_vec, plain);
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        evaluator.rotateColumnsInplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 5, 6, 7, 8, 1, 2, 3, 4 }));

        evaluator.rotateRowsInplace(encrypted, -1, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 8, 5, 6, 7, 4, 1, 2, 3 }));

        evaluator.rotateRowsInplace(encrypted, 2, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 6, 7, 8, 5, 2, 3, 4, 1 }));

        evaluator.rotateColumnsInplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));

        evaluator.rotateRowsInplace(encrypted, 0, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));
    }

    TEST(EvaluatorCudaTest, BGVEncryptModSwitchToNextDecrypt)
    {
        KernelProvider::initialize();
        {
            // The common parameters: the plaintext and the polynomial moduli
            Modulus plain_modulus(65);

            // The parameters and the context of the higher level
            EncryptionParameters parms(SchemeType::bgv);
            parms.setPolyModulusDegree(128);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

            SEALContext context(parms, true, SecurityLevel::none);
            KeyGenerator keygen(context);
            SecretKey secret_key = keygen.secretKey();
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());
            auto parms_id = context.firstParmsID();

            Ciphertext encrypted(context);
            Ciphertext encryptedRes;
            Plaintext plain;

            plain = 0;
            encryptor.encrypt(plain, encrypted);
            evaluator.modSwitchToNext(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "0");

            evaluator.modSwitchToNextInplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "0");

            parms_id = context.firstParmsID();
            plain = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.modSwitchToNext(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1");

            evaluator.modSwitchToNextInplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1");

            parms_id = context.firstParmsID();
            plain = "1x^127";
            encryptor.encrypt(plain, encrypted);
            evaluator.modSwitchToNext(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1x^127");

            evaluator.modSwitchToNextInplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1x^127");

            parms_id = context.firstParmsID();
            plain = "5x^64 + Ax^5";
            encryptor.encrypt(plain, encrypted);
            evaluator.modSwitchToNext(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

            evaluator.modSwitchToNextInplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
            ASSERT_TRUE(encryptedRes.parmsID() == parms_id);
            ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
        }
        {
            // Consider the case of qi mod p != 1
            Modulus plain_modulus(786433);

            EncryptionParameters parms(SchemeType::bgv);
            parms.setPolyModulusDegree(8192);
            parms.setPlainModulus(plain_modulus);
            parms.setCoeffModulus(CoeffModulus::BFVDefault(8192));
            SEALContext context(parms, true, SecurityLevel::tc128);

            KeyGenerator keygen(context);
            SecretKey secret_key = keygen.secretKey();
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted(context);
            Plaintext plain;

            plain = "1";
            encryptor.encrypt(plain, encrypted);
            evaluator.modSwitchToNextInplace(encrypted);
            evaluator.modSwitchToNextInplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(plain.to_string() == "1");
        }
    }

    TEST(EvaluatorCudaTest, BGVEncryptModSwitchToDecrypt)
    {
        KernelProvider::initialize();
        // The common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(65);

        // The parameters and the context of the higher level
        EncryptionParameters parms(SchemeType::bgv);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, SecurityLevel::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secretKey();
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());
        auto parms_id = context.firstParmsID();

        Ciphertext encrypted(context);
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.firstParmsID();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.firstParmsID();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.firstParmsID();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.getContextData(parms_id)->nextContextData()->parmsID();
        encryptor.encrypt(plain, encrypted);
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.firstParmsID();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.getContextData(parms_id)->nextContextData()->nextContextData()->parmsID();
        evaluator.modSwitchToInplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parmsID() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }

    TEST(EvaluatorCudaTest, SerializeTest) {

        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.setPolyModulusDegree(slot_size * 2);
            parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            RelinKeys rlk;
            keygen.createRelinKeys(rlk);

            stringstream p;
            pk.save(p);
            string str = p.str();
            stringstream q(str);
            pk.load(q);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 10;

            srand(static_cast<unsigned>(time(NULL)));
            for (size_t i = 0; i < slot_size; i++)
            {
                input1[i] = static_cast<double>(rand() % data_bound);
                input2[i] = static_cast<double>(rand() % data_bound);
                expected[i] = input1[i] * input2[i];
            }

            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1ULL << 40);
            encoder.encode(input1, context.firstParmsID(), delta, plain1);
            encoder.encode(input2, context.firstParmsID(), delta, plain2);

            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());
            // Check correctness of encryption
            ASSERT_TRUE(encrypted2.parmsID() == context.firstParmsID());

            evaluator.multiplyInplace(encrypted1, encrypted2);
            evaluator.relinearizeInplace(encrypted1, rlk);

            decryptor.decrypt(encrypted1, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(expected[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
    }

} // namespace sealtest
