// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../src/encryptionparams.h"
#include "../src/modulus.h"
#include "../src/utils/numth.h"
#include "gtest/gtest.h"

using namespace troy;
using namespace std;

namespace troytest
{
    TEST(EncryptionParametersTest, EncryptionParametersSet)
    {
        auto encryption_parameters_test = [](SchemeType scheme) {
            EncryptionParameters parms(scheme);
            parms.setCoeffModulus({ 2, 3 });
            if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
                parms.setPlainModulus(2);
            parms.setPolyModulusDegree(2);
            parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());

            ASSERT_TRUE(scheme == parms.scheme());
            ASSERT_TRUE(parms.coeffModulus()[0] == 2);
            ASSERT_TRUE(parms.coeffModulus()[1] == 3);
            if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
            {
                ASSERT_TRUE(parms.plainModulus().value() == 2);
            }
            else if (scheme == SchemeType::ckks)
            {
                ASSERT_TRUE(parms.plainModulus().value() == 0);
            }
            ASSERT_TRUE(parms.polyModulusDegree() == 2);
            ASSERT_TRUE(parms.randomGenerator() == UniformRandomGeneratorFactory::DefaultFactory());

            parms.setCoeffModulus(CoeffModulus::Create(2, { 30, 40, 50 }));
            if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
                parms.setPlainModulus(2);
            parms.setPolyModulusDegree(128);
            parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());

            ASSERT_TRUE(util::isPrime(parms.coeffModulus()[0]));
            ASSERT_TRUE(util::isPrime(parms.coeffModulus()[1]));
            ASSERT_TRUE(util::isPrime(parms.coeffModulus()[2]));

            if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
            {
                ASSERT_TRUE(parms.plainModulus().value() == 2);
            }
            else if (scheme == SchemeType::ckks)
            {
                ASSERT_TRUE(parms.plainModulus().value() == 0);
            }
            ASSERT_TRUE(parms.polyModulusDegree() == 128);
            ASSERT_TRUE(parms.randomGenerator() == UniformRandomGeneratorFactory::DefaultFactory());
        };
        encryption_parameters_test(SchemeType::bfv);
        encryption_parameters_test(SchemeType::ckks);
        encryption_parameters_test(SchemeType::bgv);
    }

    TEST(EncryptionParametersTest, EncryptionParametersCompare)
    {
        auto encryption_parameters_compare = [](SchemeType scheme) {
            EncryptionParameters parms1(scheme);
            parms1.setCoeffModulus(CoeffModulus::Create(64, { 30 }));
            if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
                parms1.setPlainModulus(1 << 6);
            parms1.setPolyModulusDegree(64);
            parms1.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());

            EncryptionParameters parms2(parms1);
            ASSERT_TRUE(parms1 == parms2);

            EncryptionParameters parms3(scheme);
            parms3 = parms2;
            ASSERT_TRUE(parms3 == parms2);
            parms3.setCoeffModulus(CoeffModulus::Create(64, { 32 }));
            ASSERT_FALSE(parms3 == parms2);

            parms3 = parms2;
            ASSERT_TRUE(parms3 == parms2);
            parms3.setCoeffModulus(CoeffModulus::Create(64, { 30, 30 }));
            ASSERT_FALSE(parms3 == parms2);

            parms3 = parms2;
            parms3.setPolyModulusDegree(128);
            ASSERT_FALSE(parms3 == parms1);

            parms3 = parms2;
            if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
                parms3.setPlainModulus((1 << 6) + 1);
            ASSERT_FALSE(parms3 == parms2);

            parms3 = parms2;
            ASSERT_TRUE(parms3 == parms2);

            parms3 = parms2;
            parms3.setRandomGenerator(nullptr);
            ASSERT_TRUE(parms3 == parms2);

            parms3 = parms2;
            parms3.setPolyModulusDegree(128);
            parms3.setPolyModulusDegree(64);
            ASSERT_TRUE(parms3 == parms1);

            parms3 = parms2;
            parms3.setCoeffModulus({ 2 });
            parms3.setCoeffModulus(CoeffModulus::Create(64, { 50 }));
            parms3.setCoeffModulus(parms2.coeffModulus());
            ASSERT_TRUE(parms3 == parms2);
        };
        encryption_parameters_compare(SchemeType::bfv);
        encryption_parameters_compare(SchemeType::bgv);
    }

    // TEST(EncryptionParametersTest, EncryptionParametersSaveLoad)
    // {
    //     auto encryption_parameters_save_load = [](SchemeType scheme) {
    //         stringstream stream;
    //         EncryptionParameters parms(scheme);
    //         EncryptionParameters parms2(scheme);
    //         parms.setCoeffModulus(CoeffModulus::Create(64, { 30 }));
    //         if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
    //             parms.setPlainModulus(1 << 6);
    //         parms.setPolyModulusDegree(64);
    //         parms.save(stream);
    //         parms2.load(stream);
    //         ASSERT_TRUE(parms.scheme() == parms2.scheme());
    //         ASSERT_TRUE(parms.coeffModulus() == parms2.coeffModulus());
    //         ASSERT_TRUE(parms.plainModulus() == parms2.plainModulus());
    //         ASSERT_TRUE(parms.polyModulusDegree() == parms2.polyModulusDegree());
    //         ASSERT_TRUE(parms == parms2);

    //         parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 60, 60 }));

    //         if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
    //             parms.setPlainModulus(1 << 30);
    //         parms.setPolyModulusDegree(256);

    //         parms.save(stream);
    //         parms2.load(stream);
    //         ASSERT_TRUE(parms.scheme() == parms2.scheme());
    //         ASSERT_TRUE(parms.coeffModulus() == parms2.coeffModulus());
    //         ASSERT_TRUE(parms.plainModulus() == parms2.plainModulus());
    //         ASSERT_TRUE(parms.polyModulusDegree() == parms2.polyModulusDegree());
    //         ASSERT_TRUE(parms == parms2);
    //     };
    //     encryption_parameters_save_load(SchemeType::bfv);
    //     encryption_parameters_save_load(SchemeType::bgv);
    // }
} // namespace sealtest
