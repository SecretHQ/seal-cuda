// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "keygenerator.h"
#include "randomtostd.h"
#include "utils/common.h"
#include "utils/galois.h"
#include "utils/ntt.h"
#include "utils/polyarithsmallmod.h"
#include "utils/polycore.h"
#include "utils/rlwe.h"
#include "utils/uintarithsmallmod.h"
#include "utils/uintcore.h"
#include <algorithm>

using namespace std;
using namespace troy::util;

namespace troy
{
    KeyGenerator::KeyGenerator(const SEALContext &context) : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        // Secret key has not been generated
        sk_generated_ = false;

        // Generate the secret and public key
        generateSk();
    }

    KeyGenerator::KeyGenerator(const SEALContext &context, const SecretKey &secret_key) : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
        if (!isValidFor(secret_key, context_))
        {
            throw invalid_argument("secret key is not valid for encryption parameters");
        }

        // Set the secret key
        secret_key_ = secret_key;
        sk_generated_ = true;

        // Generate the public key
        generateSk(sk_generated_);
    }

    void KeyGenerator::generateSk(bool is_initialized)
    {
        // Extract encryption parameters.
        auto &context_data = *context_.keyContextData();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        if (!is_initialized)
        {
            // Initialize secret key.
            secret_key_ = SecretKey();
            sk_generated_ = false;
            secret_key_.data().resize(mul_safe(coeff_count, coeff_modulus_size));

            // Generate secret key
            HostPointer secret_key(secret_key_.data().data());
            samplePolyTernary(parms.randomGenerator()->create(), parms, secret_key.get());

            // Transform the secret s into NTT representation.
            auto ntt_tables = context_data.smallNTTTables();
            nttNegacyclicHarvey(secret_key, coeff_modulus_size, ntt_tables);

            // Set the parms_id for secret key
            secret_key_.parmsID() = context_data.parmsID();
        }

        // Set the secret_key_array to have size 1 (first power of secret)
        secret_key_array_ = allocatePoly(coeff_count, coeff_modulus_size);
        setPoly(secret_key_.data().data(), coeff_count, coeff_modulus_size, secret_key_array_.get());
        secret_key_array_size_ = 1;

        // Secret key has been generated
        sk_generated_ = true;
    }

    PublicKey KeyGenerator::generatePk() const
    {
        if (!sk_generated_)
        {
            throw logic_error("cannot generate public key for unspecified secret key");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.keyContextData();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        PublicKey public_key;
        encryptZeroSymmetric(secret_key_, context_, context_data.parmsID(), true, public_key.data());

        // Set the parms_id for public key
        public_key.parmsID() = context_data.parmsID();

        return public_key;
    }

    RelinKeys KeyGenerator::createRelinKeys(size_t count)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate relinearization keys for unspecified secret key");
        }
        if (!count || count > SEAL_CIPHERTEXT_SIZE_MAX - 2)
        {
            throw invalid_argument("invalid count");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.keyContextData();
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Make sure we have enough secret keys computed
        computeSecretKeyArray(context_data, count + 1);

        // Create the RelinKeys object to return
        RelinKeys relin_keys;

        // Assume the secret key is already transformed into NTT form.
        ConstHostPointer secret_key(secret_key_array_.get());
        generateKswitchKeys(secret_key + coeff_count * coeff_modulus_size, count, static_cast<KSwitchKeys &>(relin_keys));

        // Set the parms_id
        relin_keys.parmsID() = context_data.parmsID();

        return relin_keys;
    }

    GaloisKeys KeyGenerator::createGaloisKeysInternal(const vector<uint32_t> &galois_elts)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate Galois keys for unspecified secret key");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.keyContextData();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        auto galois_tool = context_data.galoisTool();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!productFitsIn(coeff_count, mul_safe(coeff_modulus_size, size_t(2))))
        {
            throw logic_error("invalid parameters");
        }

        // Create the GaloisKeys object to return
        GaloisKeys galois_keys;

        // The max number of keys is equal to number of coefficients
        galois_keys.data().resize(coeff_count);

        for (auto galois_elt : galois_elts)
        {
            // Verify coprime conditions.
            if (!(galois_elt & 1) || (galois_elt >= coeff_count << 1))
            {
                throw invalid_argument("Galois element is not valid");
            }

            // Do we already have the key?
            if (galois_keys.hasKey(galois_elt))
            {
                continue;
            }

            // Rotate secret key for each coeff_modulus
            // FIXME: allocate related action
            auto rotated_secret_key = HostArray<uint64_t>(coeff_count * coeff_modulus_size);
            // SEAL_ALLOCATE_GET_RNS_ITER(rotated_secret_key, coeff_count, coeff_modulus_size, pool_);
            ConstHostPointer secret_key(secret_key_.data().data());
            galois_tool->applyGaloisNtt(secret_key, coeff_modulus_size, galois_elt, rotated_secret_key.asPointer());

            // Initialize Galois key
            // This is the location in the galois_keys vector
            size_t index = GaloisKeys::getIndex(galois_elt);

            // Create Galois keys.
            generateOneKswitchKey(rotated_secret_key.asPointer(), galois_keys.data()[index]);
        }

        // Set the parms_id
        galois_keys.parms_id_ = context_data.parmsID();

        return galois_keys;
    }

    const SecretKey &KeyGenerator::secretKey() const
    {
        if (!sk_generated_)
        {
            throw logic_error("secret key has not been generated");
        }
        return secret_key_;
    }

    void KeyGenerator::computeSecretKeyArray(const SEALContext::ContextData &context_data, size_t max_power)
    {
        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!productFitsIn(coeff_count, mul_safe(coeff_modulus_size, max_power)))
        {
            throw logic_error("invalid parameters");
        }

        size_t old_size = secret_key_array_size_;
        size_t new_size = max(max_power, old_size);

        if (old_size == new_size)
        {
            return;
        }

        // Need to extend the array
        // Compute powers of secret key until max_power
        auto secret_key_array(allocatePolyArray(new_size, coeff_count, coeff_modulus_size));
        setPolyArray(secret_key_array_.get(), old_size, coeff_count, coeff_modulus_size, secret_key_array.get());
        ConstHostPointer secret_key(secret_key_array.get());

        HostPointer secret_key_power(secret_key_array.get());
        size_t poly_diff = coeff_count * coeff_modulus_size;
        secret_key_power += (old_size - 1) * poly_diff;
        auto next_secret_key_power = secret_key_power + poly_diff;

        // Since all of the key powers in secret_key_array_ are already NTT transformed, to get the next one we simply
        // need to compute a dyadic product of the last one with the first one [which is equal to NTT(secret_key_)].
        for (size_t i = 0; i < new_size - old_size; i++) {
            dyadicProductCoeffmod(secret_key_power + i * poly_diff, secret_key, coeff_modulus_size, coeff_count, &coeff_modulus[0], next_secret_key_power + i * poly_diff);
        }

        // Do we still need to update size?
        old_size = secret_key_array_size_;
        new_size = max(max_power, secret_key_array_size_);

        if (old_size == new_size)
        {
            return;
        }

        // Acquire new array
        secret_key_array_size_ = new_size;

        // for (size_t i = 0; i < secret_key_array.size(); i++) {
        //     std::cout << secret_key_array[i] << ", ";
        // }
        // std::cout << "\n";

        secret_key_array_ = std::move(secret_key_array);

    }

    void KeyGenerator::generateOneKswitchKey(ConstHostPointer<uint64_t> new_key, vector<PublicKey> &destination)
    {
        if (!context_.using_keyswitching())
        {
            throw logic_error("keyswitching is not supported by the context");
        }

        size_t coeff_count = context_.keyContextData()->parms().polyModulusDegree();
        size_t decomp_mod_count = context_.firstContextData()->parms().coeffModulus().size();
        auto &keyContextData = *context_.keyContextData();
        auto &key_parms = keyContextData.parms();
        auto &key_modulus = key_parms.coeffModulus();

        // Size check
        if (!productFitsIn(coeff_count, decomp_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
        destination.resize(decomp_mod_count);

        for (size_t i = 0; i < decomp_mod_count; i++) {
        // SEAL_ITERATE(iter(new_key, key_modulus, destination, size_t(0)), decomp_mod_count, [&](auto I) {
            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(coeff_count);
            encryptZeroSymmetric(
                secret_key_, context_, keyContextData.parmsID(), true, destination[i].data());
            uint64_t factor = barrettReduce64(key_modulus.back().value(), key_modulus[i]);
            multiplyPolyScalarCoeffmod(new_key + i * coeff_count, coeff_count, factor, key_modulus[i], temp.asPointer());

            // We use the SeqIter at get<3>(I) to find the i-th RNS factor of the first destination polynomial.
            auto destination_iter = HostPointer(destination[i].data().data() + i * coeff_count);
            addPolyCoeffmod(destination_iter, temp.asPointer(), coeff_count, key_modulus[i], destination_iter);
        }
    }

    void KeyGenerator::generateKswitchKeys(
        util::ConstHostPointer<uint64_t> new_keys, size_t num_keys, KSwitchKeys &destination)
    {
        size_t coeff_count = context_.keyContextData()->parms().polyModulusDegree();
        auto &keyContextData = *context_.keyContextData();
        auto &key_parms = keyContextData.parms();
        size_t coeff_modulus_size = key_parms.coeffModulus().size();

        // Size check
        if (!productFitsIn(coeff_count, mul_safe(coeff_modulus_size, num_keys)))
        {
            throw logic_error("invalid parameters");
        }
        destination.data().resize(num_keys);
        for (size_t i = 0; i < num_keys; i++) {
            this->generateOneKswitchKey(new_keys + i * coeff_count * coeff_modulus_size, destination.data()[i]);
        }
    }
} // namespace seal
