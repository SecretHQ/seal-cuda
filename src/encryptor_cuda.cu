// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "encryptor_cuda.cuh"
#include "randomtostd.h"
#include "utils/rlwe_cuda.cuh"
#include "utils/scalingvariant_cuda.cuh"
#include "kernelutils.cuh"
#include <algorithm>
#include <stdexcept>
#include <iostream>

using namespace std;
using namespace troy::util;

#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy
{

    __global__ void gInitCurandStates(curandState* states, size_t n, uint64_t seed) {
        GET_INDEX_COND_RETURN(n);
        curand_init(gindex + seed, 0, 0, &(states[gindex]));
    }

    void EncryptorCuda::setupCurandStates(uint64_t seed) {
        size_t n = context_.firstContextData()->parms().polyModulusDegree();
        curandStates = DeviceArray<curandState>(n);
        KERNEL_CALL(gInitCurandStates, n)(curandStates.get(), n, seed);
    }

    EncryptorCuda::EncryptorCuda(const SEALContextCuda &context, const PublicKeyCuda &public_key) : context_(context)
    {

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

        setupCurandStates();
    }

    EncryptorCuda::EncryptorCuda(const SEALContextCuda &context, const SecretKeyCuda &secret_key) : context_(context)
    {

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
        setupCurandStates();
    }

    EncryptorCuda::EncryptorCuda(const SEALContextCuda &context, const PublicKeyCuda &public_key, const SecretKeyCuda &secret_key)
        : context_(context)
    {

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
        setupCurandStates();
    }

    void EncryptorCuda::encryptZeroInternal(
        ParmsID parms_id, bool is_asymmetric, CiphertextCuda &destination) const
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
                CiphertextCuda temp;
                util::encryptZeroAsymmetric(public_key_, context_, prev_parms_id, isNttForm, temp, curandStates);

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
                    kernel_util::kSetPolyArray(temp.data() + i * (poly_element_count + coeff_count), 1, coeff_modulus_size, coeff_count, destination.data() + i * poly_element_count);
                }

                destination.parmsID() = parms_id;
                destination.isNttForm() = isNttForm;
                destination.scale() = temp.scale();
                destination.correctionFactor() = temp.correctionFactor();
            }
            else
            {
                // Does not require modulus switching
                util::encryptZeroAsymmetric(public_key_, context_, parms_id, isNttForm, destination, curandStates.asPointer());
            }
        }
        else
        {
            // Does not require modulus switching
            util::encryptZeroSymmetric(secret_key_, context_, parms_id, isNttForm, destination, curandStates.asPointer());
        }
    }

    void EncryptorCuda::encryptInternal(
        const PlaintextCuda &plain, bool is_asymmetric, CiphertextCuda &destination) const
    {


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
            multiplyAddPlainWithScalingVariant(plain, *context_.firstContextData(), destination.data());
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
            ConstDevicePointer plain_iter(plain.data());
            DevicePointer destination_iter = DevicePointer(destination.data(0));
            kernel_util::kAddPolyCoeffmod(destination_iter, plain_iter, 1, coeff_modulus_size, coeff_count, coeff_modulus, destination_iter);

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
            addPlainWithoutScalingVariant(plain, *context_data_ptr, DevicePointer(destination.data(0)));
        }
        else
        {
            throw invalid_argument("unsupported scheme");
        }
    }
} // namespace seal
