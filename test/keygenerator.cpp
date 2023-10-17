// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../src/context.h"
// #include "../src/decryptor.h"
// #include "../src/encryptor.h"
// #include "../src/evaluator.h"
#include "../src/keygenerator.h"
#include "../src/valcheck.h"
#include "gtest/gtest.h"

using namespace troy;
using namespace troy::util;
using namespace std;

namespace troytest
{
    TEST(KeyGeneratorTest, BFVKeyGeneration)
    {
        EncryptionParameters parms(SchemeType::bfv);
        {
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(65537);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60 }));
            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(auto evk = keygen.createRelinKeys(), logic_error);
            ASSERT_THROW(auto galk = keygen.createGaloisKeys(), logic_error);
        }
        {
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(65537);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60 }));
            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.createRelinKeys(evk);
            ASSERT_TRUE(evk.parmsID() == context.keyParmsID());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(evk, context));

            GaloisKeys galks;
            keygen.createGaloisKeys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(galks, context));

            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(3));
            ASSERT_TRUE(galks.hasKey(5));
            ASSERT_TRUE(galks.hasKey(7));
            ASSERT_FALSE(galks.hasKey(9));
            ASSERT_FALSE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_FALSE(galks.hasKey(3));
            ASSERT_FALSE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 127 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_FALSE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.setPolyModulusDegree(256);
            parms.setPlainModulus(65537);
            parms.setCoeffModulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.createRelinKeys(evk);
            ASSERT_TRUE(evk.parmsID() == context.keyParmsID());
            ASSERT_EQ(2ULL, evk.key(2).size());

            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(evk, context));

            GaloisKeys galks;
            keygen.createGaloisKeys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(galks, context));

            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(3));
            ASSERT_TRUE(galks.hasKey(5));
            ASSERT_TRUE(galks.hasKey(7));
            ASSERT_FALSE(galks.hasKey(9));
            ASSERT_FALSE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_FALSE(galks.hasKey(3));
            ASSERT_FALSE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 511 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_FALSE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, BGVKeyGeneration)
    {
        EncryptionParameters parms(SchemeType::bgv);
        {
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(65537);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60 }));
            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(auto evk = keygen.createRelinKeys(), logic_error);
            ASSERT_THROW(auto galk = keygen.createGaloisKeys(), logic_error);
        }
        {
            parms.setPolyModulusDegree(64);
            parms.setPlainModulus(65537);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60 }));
            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.createRelinKeys(evk);
            ASSERT_TRUE(evk.parmsID() == context.keyParmsID());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(evk, context));

            GaloisKeys galks;
            keygen.createGaloisKeys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(galks, context));

            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(3));
            ASSERT_TRUE(galks.hasKey(5));
            ASSERT_TRUE(galks.hasKey(7));
            ASSERT_FALSE(galks.hasKey(9));
            ASSERT_FALSE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_FALSE(galks.hasKey(3));
            ASSERT_FALSE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 127 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_FALSE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.setPolyModulusDegree(256);
            parms.setPlainModulus(65537);
            parms.setCoeffModulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.createRelinKeys(evk);
            ASSERT_TRUE(evk.parmsID() == context.keyParmsID());
            ASSERT_EQ(2ULL, evk.key(2).size());

            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(evk, context));

            GaloisKeys galks;
            keygen.createGaloisKeys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(galks, context));

            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(3));
            ASSERT_TRUE(galks.hasKey(5));
            ASSERT_TRUE(galks.hasKey(7));
            ASSERT_FALSE(galks.hasKey(9));
            ASSERT_FALSE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_FALSE(galks.hasKey(3));
            ASSERT_FALSE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 511 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_FALSE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, CKKSKeyGeneration)
    {
        EncryptionParameters parms(SchemeType::ckks);
        {
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60 }));
            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(auto evk = keygen.createRelinKeys(), logic_error);
            ASSERT_THROW(auto galk = keygen.createGaloisKeys(), logic_error);
        }
        {
            parms.setPolyModulusDegree(64);
            parms.setCoeffModulus(CoeffModulus::Create(64, { 60, 60 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.createRelinKeys(evk);
            ASSERT_TRUE(evk.parmsID() == context.keyParmsID());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(evk, context));

            GaloisKeys galks;
            keygen.createGaloisKeys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(galks, context));

            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(3));
            ASSERT_TRUE(galks.hasKey(5));
            ASSERT_TRUE(galks.hasKey(7));
            ASSERT_FALSE(galks.hasKey(9));
            ASSERT_FALSE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_FALSE(galks.hasKey(3));
            ASSERT_FALSE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 127 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_FALSE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.setPolyModulusDegree(256);
            parms.setCoeffModulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.createRelinKeys(evk);
            ASSERT_TRUE(evk.parmsID() == context.keyParmsID());
            ASSERT_EQ(2ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(evk, context));

            GaloisKeys galks;
            keygen.createGaloisKeys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().isTransparent());
                }
            }
            ASSERT_TRUE(isValidFor(galks, context));

            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(3));
            ASSERT_TRUE(galks.hasKey(5));
            ASSERT_TRUE(galks.hasKey(7));
            ASSERT_FALSE(galks.hasKey(9));
            ASSERT_FALSE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_TRUE(galks.hasKey(1));
            ASSERT_FALSE(galks.hasKey(3));
            ASSERT_FALSE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.createGaloisKeys(vector<uint32_t>{ 511 }, galks);
            ASSERT_TRUE(galks.parmsID() == context.keyParmsID());
            ASSERT_FALSE(galks.hasKey(1));
            ASSERT_TRUE(galks.hasKey(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    // TEST(KeyGeneratorTest, Constructors)
    // {
    //     auto constructors = [](SchemeType scheme) {
    //         EncryptionParameters parms(scheme);
    //         parms.setPolyModulusDegree(128);
    //         parms.setPlainModulus(65537);
    //         parms.setCoeffModulus(CoeffModulus::Create(128, { 60, 50, 40 }));
    //         SEALContext context(parms, false, SecurityLevel::none);
    //         Evaluator evaluator(context);

    //         KeyGenerator keygen(context);
    //         PublicKey pk;
    //         keygen.create_public_key(pk);
    //         auto sk = keygen.secret_key();
    //         RelinKeys rlk;
    //         keygen.createRelinKeys(rlk);
    //         GaloisKeys galk;
    //         keygen.createGaloisKeys(galk);

    //         ASSERT_TRUE(isValidFor(rlk, context));
    //         ASSERT_TRUE(isValidFor(galk, context));

    //         Encryptor encryptor(context, pk);
    //         Decryptor decryptor(context, sk);
    //         Plaintext pt("1x^2 + 2"), ptres;
    //         Ciphertext ct;
    //         encryptor.encrypt(pt, ct);
    //         evaluator.square_inplace(ct);
    //         evaluator.relinearize_inplace(ct, rlk);
    //         decryptor.decrypt(ct, ptres);
    //         ASSERT_EQ("1x^4 + 4x^2 + 4", ptres.to_string());

    //         KeyGenerator keygen2(context, sk);
    //         auto sk2 = keygen.secret_key();
    //         PublicKey pk2;
    //         keygen2.create_public_key(pk2);
    //         ASSERT_EQ(sk2.data(), sk.data());

    //         RelinKeys rlk2;
    //         keygen2.createRelinKeys(rlk2);
    //         GaloisKeys galk2;
    //         keygen2.createGaloisKeys(galk2);

    //         ASSERT_TRUE(isValidFor(rlk2, context));
    //         ASSERT_TRUE(isValidFor(galk2, context));

    //         Encryptor encryptor2(context, pk2);
    //         Decryptor decryptor2(context, sk2);
    //         pt = "1x^2 + 2";
    //         ptres.set_zero();
    //         encryptor.encrypt(pt, ct);
    //         evaluator.square_inplace(ct);
    //         evaluator.relinearize_inplace(ct, rlk2);
    //         decryptor.decrypt(ct, ptres);
    //         ASSERT_EQ("1x^4 + 4x^2 + 4", ptres.to_string());

    //         PublicKey pk3;
    //         keygen2.create_public_key(pk3);

    //         // There is a small random chance for this to fail
    //         for (size_t i = 0; i < pk3.data().dyn_array().size(); i++)
    //         {
    //             ASSERT_NE(pk3.data().data()[i], pk2.data().data()[i]);
    //         }
    //     };

    //     constructors(SchemeType::bfv);
    //     constructors(SchemeType::bgv);
    // }
} // namespace sealtest
