// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "encryptor.h"
#include "modulus.h"
#include "randomtostd.h"
#include "utils/common.h"
#include "utils/polyarithsmallmod.h"
#include "utils/rlwe.h"
#include "utils/scalingvariant.h"
#include <algorithm>
#include <stdexcept>
#include <iostream>

using namespace std;
using namespace troy::util;

namespace troy
{
    Encryptor::Encryptor(const SEALContext &context, const PublicKey &public_key) : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        setPublicKey(public_key);

        auto &parms = context_.keyContextData()->parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Quick sanity check
        if (!productFitsIn(coeff_count, mul_safe(coeff_modulus_size, size_t(2))))
        {
            throw logic_error("invalid parameters");
        }
    }

    Encryptor::Encryptor(const SEALContext &context, const SecretKey &secret_key) : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        setSecretKey(secret_key);

        auto &parms = context_.keyContextData()->parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Quick sanity check
        if (!productFitsIn(coeff_count, mul_safe(coeff_modulus_size, size_t(2))))
        {
            throw logic_error("invalid parameters");
        }
    }

    Encryptor::Encryptor(const SEALContext &context, const PublicKey &public_key, const SecretKey &secret_key)
        : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        setPublicKey(public_key);
        setSecretKey(secret_key);

        auto &parms = context_.keyContextData()->parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Quick sanity check
        if (!productFitsIn(coeff_count, mul_safe(coeff_modulus_size, size_t(2))))
        {
            throw logic_error("invalid parameters");
        }
    }

    void Encryptor::encryptZeroInternal(
        ParmsID parms_id, bool is_asymmetric, Ciphertext &destination) const
    {
        // Verify parameters.

        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_.getContextData(parms_id);
        auto &parms = context_data.parms();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t coeff_count = parms.polyModulusDegree();
        size_t poly_element_count = coeff_modulus_size * coeff_count;
        bool isNttForm = false;

        if (parms.scheme() == SchemeType::ckks)
        {
            isNttForm = true;
        }
        else if (parms.scheme() != SchemeType::bfv && parms.scheme() != SchemeType::bgv)
        {
            throw invalid_argument("unsupported scheme");
        }

        // Resize destination and save results
        destination.resize(context_, parms_id, 2);

        // If asymmetric key encryption
        if (is_asymmetric)
        {
            auto prev_context_data_ptr = context_data.prevContextData();
            if (prev_context_data_ptr)
            {
                // Requires modulus switching
                auto &prev_context_data = *prev_context_data_ptr;
                auto &prev_parms_id = prev_context_data.parmsID();
                auto rns_tool = prev_context_data.rnsTool();

                // Zero encryption without modulus switching
                Ciphertext temp;
                util::encryptZeroAsymmetric(public_key_, context_, prev_parms_id, isNttForm, temp);

                // Modulus switching
                for (size_t i = 0; i < temp.size(); i++) {
                    if (isNttForm)
                    {
                        rns_tool->divideAndRoundqLastNttInplace(
                            temp.data() + i * (poly_element_count + coeff_count), prev_context_data.smallNTTTables());
                    }
                    // bfv switch-to-next
                    else if (parms.scheme() != SchemeType::bgv)
                    {
                        rns_tool->divideAndRoundqLastInplace(temp.data() + i * (poly_element_count + coeff_count));
                    }
                    // bgv switch-to-next
                    else
                    {
                        rns_tool->modTAndDivideqLastInplace(temp.data() + i * (poly_element_count + coeff_count));
                    }
                    setPoly(temp.data() + i * (poly_element_count + coeff_count), coeff_count, coeff_modulus_size, 
                        destination.data() + i * poly_element_count);
                }

                destination.parmsID() = parms_id;
                destination.isNttForm() = isNttForm;
                destination.scale() = temp.scale();
                destination.correctionFactor() = temp.correctionFactor();
            }
            else
            {
                // Does not require modulus switching
                util::encryptZeroAsymmetric(public_key_, context_, parms_id, isNttForm, destination);
            }
        }
        else
        {
            // Does not require modulus switching
            util::encryptZeroSymmetric(secret_key_, context_, parms_id, isNttForm, destination);
        }
    }

    void Encryptor::encryptInternal(
        const Plaintext &plain, bool is_asymmetric, Ciphertext &destination) const
    {
        // Minimal verification that the keys are set
        if (is_asymmetric)
        {
            if (!isMetadataValidFor(public_key_, context_))
            {
                throw logic_error("public key is not set");
            }
        }
        else
        {
            if (!isMetadataValidFor(secret_key_, context_))
            {
                throw logic_error("secret key is not set");
            }
        }

        // Verify that plain is valid
        if (!isValidFor(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto scheme = context_.keyContextData()->parms().scheme();
        if (scheme == SchemeType::bfv)
        {
            if (plain.isNttForm())
            {
                throw invalid_argument("plain cannot be in NTT form");
            }

            encryptZeroInternal(context_.firstParmsID(), is_asymmetric, destination);

            // Multiply plain by scalar coeff_div_plaintext and reposition if in upper-half.
            // Result gets added into the c_0 term of ciphertext (c_0,c_1).
            multiplyAddPlainWithScalingVariant(plain, *context_.firstContextData(), HostPointer(destination.data()));
        }
        else if (scheme == SchemeType::ckks)
        {
            if (!plain.isNttForm())
            {
                throw invalid_argument("plain must be in NTT form");
            }

            auto context_data_ptr = context_.getContextData(plain.parmsID());
            if (!context_data_ptr)
            {
                throw invalid_argument("plain is not valid for encryption parameters");
            }
            encryptZeroInternal(plain.parmsID(), is_asymmetric, destination);

            auto &parms = context_.getContextData(plain.parmsID())->parms();
            auto &coeff_modulus = parms.coeffModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();

            // The plaintext gets added into the c_0 term of ciphertext (c_0,c_1).
            ConstHostPointer plain_iter(plain.data());
            HostPointer destination_iter = HostPointer(destination.data(0));
            addPolyCoeffmod(destination_iter, plain_iter, coeff_modulus_size, coeff_count, &coeff_modulus[0], destination_iter);

            destination.scale() = plain.scale();
        }
        else if (scheme == SchemeType::bgv)
        {
            if (plain.isNttForm())
            {
                throw invalid_argument("plain cannot be in NTT form");
            }
            encryptZeroInternal(context_.firstParmsID(), is_asymmetric, destination);
            auto context_data_ptr = context_.firstContextData();
            auto &parms = context_data_ptr->parms();
            size_t coeff_count = parms.polyModulusDegree();
            // c_{0} = pk_{0}*u + p*e_{0} + M
            addPlainWithoutScalingVariant(plain, *context_data_ptr, HostPointer(destination.data(0)));
        }
        else
        {
            throw invalid_argument("unsupported scheme");
        }
    }
} // namespace seal
