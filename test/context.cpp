// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../src/context.h"
#include "../src/modulus.h"
#include "gtest/gtest.h"

using namespace troy;
using namespace std;

using ErrorType = EncryptionParameterQualifiers::ErrorType;

namespace troytest
{
    TEST(ContextTest, BFVContextConstructor)
    {
        // Nothing set
        auto scheme = SchemeType::bfv;
        EncryptionParameters parms(scheme);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_coeff_modulus_size);
            ASSERT_FALSE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Not relatively prime coeff moduli
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 2, 30 });
        parms.setPlainModulus(2);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::failed_creating_rns_base);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Plain modulus not relatively prime to coeff moduli
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(34);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_plain_modulus_coprimality);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Plain modulus not smaller than product of coeff moduli
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17 });
        parms.setPlainModulus(41);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(17ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_plain_modulus_too_large);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // FFT poly but not NTT modulus
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 3 });
        parms.setPlainModulus(2);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(3ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_coeff_modulus_no_ntt);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; no fast plain lift
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(18);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(697ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; fast plain lift
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(16);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(17ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_EQ(697ULL, *context.keyContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; no batching due to non-prime plain modulus
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(49);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(697ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; batching enabled
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(697ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; batching and fast plain lift enabled
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 137, 193 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(137ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_EQ(26441ULL, *context.keyContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; batching and fast plain lift enabled; nullptr RNG
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 137, 193 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(nullptr);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(137ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_EQ(26441ULL, *context.keyContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters not OK due to too small poly_modulus_degree and enforce_hes
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 137, 193 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(nullptr);
        {
            SEALContext context(parms, false, SecurityLevel::tc128);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_parameters_insecure);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters not OK due to too large coeff_modulus and enforce_hes
        parms.setPolyModulusDegree(2048);
        parms.setCoeffModulus(CoeffModulus::BFVDefault(4096, SecurityLevel::tc128));
        parms.setPlainModulus(73);
        parms.setRandomGenerator(nullptr);
        {
            SEALContext context(parms, false, SecurityLevel::tc128);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_parameters_insecure);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; descending modulus chain
        parms.setPolyModulusDegree(4096);
        parms.setCoeffModulus({ 0xffffee001, 0xffffc4001 });
        parms.setPlainModulus(73);
        {
            SEALContext context(parms, false, SecurityLevel::tc128);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::tc128, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; no standard security
        parms.setPolyModulusDegree(2048);
        parms.setCoeffModulus({ 0x1ffffe0001, 0xffffee001, 0xffffc4001 });
        parms.setPlainModulus(73);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; using batching; no keyswitching
        parms.setPolyModulusDegree(2048);
        parms.setCoeffModulus(CoeffModulus::Create(2048, { 40 }));
        parms.setPlainModulus(65537);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }
    }

    TEST(ContextTest, ModulusChainExpansion)
    {
        {
            EncryptionParameters parms(SchemeType::bfv);
            parms.setPolyModulusDegree(4);
            parms.setCoeffModulus({ 41, 137, 193, 65537 });
            parms.setPlainModulus(73);
            SEALContext context(parms, true, SecurityLevel::none);
            auto context_data = context.keyContextData();
            ASSERT_EQ(size_t(2), context_data->chainIndex());
            ASSERT_EQ(71047416497ULL, *context_data->totalCoeffModulus());
            ASSERT_FALSE(!!context_data->prevContextData());
            ASSERT_EQ(context_data->parmsID(), context.keyParmsID());
            auto prevContextData = context_data;
            context_data = context_data->nextContextData();
            ASSERT_EQ(size_t(1), context_data->chainIndex());
            ASSERT_EQ(1084081ULL, *context_data->totalCoeffModulus());
            ASSERT_EQ(context_data->prevContextData()->parmsID(), prevContextData->parmsID());
            prevContextData = context_data;
            context_data = context_data->nextContextData();
            ASSERT_EQ(size_t(0), context_data->chainIndex());
            ASSERT_EQ(5617ULL, *context_data->totalCoeffModulus());
            ASSERT_EQ(context_data->prevContextData()->parmsID(), prevContextData->parmsID());
            ASSERT_FALSE(!!context_data->nextContextData());
            ASSERT_EQ(context_data->parmsID(), context.lastParmsID());

            context = SEALContext(parms, false, SecurityLevel::none);
            ASSERT_EQ(size_t(1), context.keyContextData()->chainIndex());
            ASSERT_EQ(size_t(0), context.firstContextData()->chainIndex());
            ASSERT_EQ(71047416497ULL, *context.keyContextData()->totalCoeffModulus());
            ASSERT_EQ(1084081ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_FALSE(!!context.firstContextData()->nextContextData());
            ASSERT_TRUE(!!context.firstContextData()->prevContextData());
        }
        {
            EncryptionParameters parms(SchemeType::bgv);
            parms.setPolyModulusDegree(4);
            parms.setCoeffModulus({ 41, 137, 193, 65537 });
            parms.setPlainModulus(73);
            SEALContext context(parms, true, SecurityLevel::none);
            auto context_data = context.keyContextData();
            ASSERT_EQ(size_t(2), context_data->chainIndex());
            ASSERT_EQ(71047416497ULL, *context_data->totalCoeffModulus());
            ASSERT_FALSE(!!context_data->prevContextData());
            ASSERT_EQ(context_data->parmsID(), context.keyParmsID());
            auto prevContextData = context_data;
            context_data = context_data->nextContextData();
            ASSERT_EQ(size_t(1), context_data->chainIndex());
            ASSERT_EQ(1084081ULL, *context_data->totalCoeffModulus());
            ASSERT_EQ(context_data->prevContextData()->parmsID(), prevContextData->parmsID());
            prevContextData = context_data;
            context_data = context_data->nextContextData();
            ASSERT_EQ(size_t(0), context_data->chainIndex());
            ASSERT_EQ(5617ULL, *context_data->totalCoeffModulus());
            ASSERT_EQ(context_data->prevContextData()->parmsID(), prevContextData->parmsID());
            ASSERT_FALSE(!!context_data->nextContextData());
            ASSERT_EQ(context_data->parmsID(), context.lastParmsID());

            context = SEALContext(parms, false, SecurityLevel::none);
            ASSERT_EQ(size_t(1), context.keyContextData()->chainIndex());
            ASSERT_EQ(size_t(0), context.firstContextData()->chainIndex());
            ASSERT_EQ(71047416497ULL, *context.keyContextData()->totalCoeffModulus());
            ASSERT_EQ(1084081ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_FALSE(!!context.firstContextData()->nextContextData());
            ASSERT_TRUE(!!context.firstContextData()->prevContextData());
        }
        {
            EncryptionParameters parms(SchemeType::ckks);
            parms.setPolyModulusDegree(4);
            parms.setCoeffModulus({ 41, 137, 193, 65537 });
            SEALContext context(parms, true, SecurityLevel::none);
            auto context_data = context.keyContextData();
            ASSERT_EQ(size_t(3), context_data->chainIndex());
            ASSERT_EQ(71047416497ULL, *context_data->totalCoeffModulus());
            ASSERT_FALSE(!!context_data->prevContextData());
            ASSERT_EQ(context_data->parmsID(), context.keyParmsID());
            auto prevContextData = context_data;
            context_data = context_data->nextContextData();
            ASSERT_EQ(size_t(2), context_data->chainIndex());
            ASSERT_EQ(1084081ULL, *context_data->totalCoeffModulus());
            ASSERT_EQ(context_data->prevContextData()->parmsID(), prevContextData->parmsID());
            prevContextData = context_data;
            context_data = context_data->nextContextData();
            ASSERT_EQ(size_t(1), context_data->chainIndex());
            ASSERT_EQ(5617ULL, *context_data->totalCoeffModulus());
            ASSERT_EQ(context_data->prevContextData()->parmsID(), prevContextData->parmsID());
            prevContextData = context_data;
            context_data = context_data->nextContextData();
            ASSERT_EQ(size_t(0), context_data->chainIndex());
            ASSERT_EQ(41ULL, *context_data->totalCoeffModulus());
            ASSERT_EQ(context_data->prevContextData()->parmsID(), prevContextData->parmsID());
            ASSERT_FALSE(!!context_data->nextContextData());
            ASSERT_EQ(context_data->parmsID(), context.lastParmsID());

            context = SEALContext(parms, false, SecurityLevel::none);
            ASSERT_EQ(size_t(1), context.keyContextData()->chainIndex());
            ASSERT_EQ(size_t(0), context.firstContextData()->chainIndex());
            ASSERT_EQ(71047416497ULL, *context.keyContextData()->totalCoeffModulus());
            ASSERT_EQ(1084081ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_FALSE(!!context.firstContextData()->nextContextData());
            ASSERT_TRUE(!!context.firstContextData()->prevContextData());
        }
    }

    TEST(EncryptionParameterQualifiersTest, BFVParameterError)
    {
        auto scheme = SchemeType::bfv;
        EncryptionParameters parms(scheme);
        SEALContext context(parms, false, SecurityLevel::none);
        auto qualifiers = context.firstContextData()->qualifiers();

        qualifiers.parameter_error = ErrorType::none;
        ASSERT_STREQ(qualifiers.parameterErrorName(), "none");
        ASSERT_STREQ(qualifiers.parameterErrorMessage(), "constructed but not yet validated");

        qualifiers.parameter_error = ErrorType::success;
        ASSERT_STREQ(qualifiers.parameterErrorName(), "success");
        ASSERT_STREQ(qualifiers.parameterErrorMessage(), "valid");

        qualifiers.parameter_error = ErrorType::invalid_coeff_modulus_bit_count;
        ASSERT_STREQ(qualifiers.parameterErrorName(), "invalid_coeff_modulus_bit_count");
        ASSERT_STREQ(
            qualifiers.parameterErrorMessage(),
            "coeff_modulus's primes' bit counts are not bounded by SEAL_USER_MOD_BIT_COUNT_MIN(MAX)");

        parms.setPolyModulusDegree(127);
        parms.setCoeffModulus({ 17, 73 });
        parms.setPlainModulus(41);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        context = SEALContext(parms, false, SecurityLevel::none);
        ASSERT_FALSE(context.parametersSet());
        ASSERT_STREQ(context.parameterErrorName(), "invalid_poly_modulus_degree_non_power_of_two");
        ASSERT_STREQ(context.parameterErrorMessage(), "poly_modulus_degree is not a power of two");
    }

    TEST(ContextTest, BGVContextConstructor)
    {
        // Nothing set
        auto scheme = SchemeType::bgv;
        EncryptionParameters parms(scheme);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_coeff_modulus_size);
            ASSERT_FALSE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Not relatively prime coeff moduli
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 2, 30 });
        parms.setPlainModulus(2);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::failed_creating_rns_base);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Plain modulus not relatively prime to coeff moduli
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(34);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_plain_modulus_coprimality);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Plain modulus not smaller than product of coeff moduli
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17 });
        parms.setPlainModulus(41);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(17ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_plain_modulus_too_large);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // FFT poly but not NTT modulus
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 3 });
        parms.setPlainModulus(2);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(3ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_coeff_modulus_no_ntt);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; no fast plain lift
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(18);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(697ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; fast plain lift
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(16);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(17ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_EQ(697ULL, *context.keyContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; no batching due to non-prime plain modulus
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(49);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(697ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; batching enabled
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 17, 41 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(697ULL, *context.firstContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; batching and fast plain lift enabled
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 137, 193 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(137ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_EQ(26441ULL, *context.keyContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; batching and fast plain lift enabled; nullptr RNG
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 137, 193 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(nullptr);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            ASSERT_EQ(137ULL, *context.firstContextData()->totalCoeffModulus());
            ASSERT_EQ(26441ULL, *context.keyContextData()->totalCoeffModulus());
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters not OK due to too small poly_modulus_degree and enforce_hes
        parms.setPolyModulusDegree(4);
        parms.setCoeffModulus({ 137, 193 });
        parms.setPlainModulus(73);
        parms.setRandomGenerator(nullptr);
        {
            SEALContext context(parms, false, SecurityLevel::tc128);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_parameters_insecure);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters not OK due to too large coeff_modulus and enforce_hes
        parms.setPolyModulusDegree(2048);
        parms.setCoeffModulus(CoeffModulus::BFVDefault(4096, SecurityLevel::tc128));
        parms.setPlainModulus(73);
        parms.setRandomGenerator(nullptr);
        {
            SEALContext context(parms, false, SecurityLevel::tc128);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_FALSE(qualifiers.parametersSet());
            ASSERT_EQ(qualifiers.parameter_error, ErrorType::invalid_parameters_insecure);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }

        // Parameters OK; descending modulus chain
        parms.setPolyModulusDegree(4096);
        parms.setCoeffModulus({ 0xffffee001, 0xffffc4001 });
        parms.setPlainModulus(73);
        {
            SEALContext context(parms, false, SecurityLevel::tc128);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::tc128, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; no standard security
        parms.setPolyModulusDegree(2048);
        parms.setCoeffModulus({ 0x1ffffe0001, 0xffffee001, 0xffffc4001 });
        parms.setPlainModulus(73);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            auto key_qualifiers = context.keyContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_TRUE(context.using_keyswitching());
        }

        // Parameters OK; using batching; no keyswitching
        parms.setPolyModulusDegree(2048);
        parms.setCoeffModulus(CoeffModulus::Create(2048, { 40 }));
        parms.setPlainModulus(65537);
        {
            SEALContext context(parms, false, SecurityLevel::none);
            auto qualifiers = context.firstContextData()->qualifiers();
            ASSERT_TRUE(qualifiers.parametersSet());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(SecurityLevel::none, qualifiers.sec_level);
            ASSERT_FALSE(context.using_keyswitching());
        }
    }

    TEST(EncryptionParameterQualifiersTest, BGVParameterError)
    {
        auto scheme = SchemeType::bgv;
        EncryptionParameters parms(scheme);
        SEALContext context(parms, false, SecurityLevel::none);
        auto qualifiers = context.firstContextData()->qualifiers();

        qualifiers.parameter_error = ErrorType::none;
        ASSERT_STREQ(qualifiers.parameterErrorName(), "none");
        ASSERT_STREQ(qualifiers.parameterErrorMessage(), "constructed but not yet validated");

        qualifiers.parameter_error = ErrorType::success;
        ASSERT_STREQ(qualifiers.parameterErrorName(), "success");
        ASSERT_STREQ(qualifiers.parameterErrorMessage(), "valid");

        qualifiers.parameter_error = ErrorType::invalid_coeff_modulus_bit_count;
        ASSERT_STREQ(qualifiers.parameterErrorName(), "invalid_coeff_modulus_bit_count");
        ASSERT_STREQ(
            qualifiers.parameterErrorMessage(),
            "coeff_modulus's primes' bit counts are not bounded by SEAL_USER_MOD_BIT_COUNT_MIN(MAX)");

        parms.setPolyModulusDegree(127);
        parms.setCoeffModulus({ 17, 73 });
        parms.setPlainModulus(41);
        parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        context = SEALContext(parms, false, SecurityLevel::none);
        ASSERT_FALSE(context.parametersSet());
        ASSERT_STREQ(context.parameterErrorName(), "invalid_poly_modulus_degree_non_power_of_two");
        ASSERT_STREQ(context.parameterErrorMessage(), "poly_modulus_degree is not a power of two");
    }
} // namespace sealtest
