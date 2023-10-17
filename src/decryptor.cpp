// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "decryptor.h"
#include "valcheck.h"
#include "utils/common.h"
#include "utils/polyarithsmallmod.h"
#include "utils/polycore.h"
#include "utils/scalingvariant.h"
#include "utils/uintarith.h"
#include "utils/uintcore.h"
#include <algorithm>
#include <stdexcept>
#include <iostream>

using namespace std;
using namespace troy::util;

namespace troy
{
    namespace
    {
        void polyInftyNormCoeffmod(
            ConstHostPointer<uint64_t> poly, size_t coeff_uint64_count, size_t coeff_count, const uint64_t *modulus, uint64_t *result)
        {

            // Construct negative threshold: (modulus + 1) / 2
            auto modulus_neg_threshold = allocateUint(coeff_uint64_count);
            halfRoundUpUint(modulus, coeff_uint64_count, modulus_neg_threshold.get());

            // Mod out the poly coefficients and choose a symmetric representative from [-modulus,modulus)
            setZeroUint(coeff_uint64_count, result);
            auto coeff_abs_value = allocateUint(coeff_uint64_count);
            for (size_t i = 0; i < coeff_count; i++) {
            // SEAL_ITERATE(poly, coeff_count, [&](auto I) {
                auto polyi = poly.get() + i * coeff_uint64_count;
                if (isGreaterThanOrEqualUint(polyi, modulus_neg_threshold.get(), coeff_uint64_count))
                {
                    subUint(modulus, polyi, coeff_uint64_count, coeff_abs_value.get());
                }
                else
                {
                    setUint(polyi, coeff_uint64_count, coeff_abs_value.get());
                }

                if (isGreaterThanUint(coeff_abs_value.get(), result, coeff_uint64_count))
                {
                    // Store the new max
                    setUint(coeff_abs_value.get(), coeff_uint64_count, result);
                }
            }
        }
    } // namespace

    Decryptor::Decryptor(const SEALContext &context, const SecretKey &secret_key) : context_(context)
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

        auto &parms = context_.keyContextData()->parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Set the secret_key_array to have size 1 (first power of secret)
        // and copy over data
        secret_key_array_ = allocatePoly(coeff_count, coeff_modulus_size);
        setPoly(secret_key.data().data(), coeff_count, coeff_modulus_size, secret_key_array_.get());
        secret_key_array_size_ = 1;
    }

    void Decryptor::decrypt(const Ciphertext &encrypted, Plaintext &destination)
    {
        // Verify that encrypted is valid.
        if (!isValidFor(encrypted, context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Additionally check that ciphertext doesn't have trivial size
        if (encrypted.size() < SEAL_CIPHERTEXT_SIZE_MIN)
        {
            throw invalid_argument("encrypted is empty");
        }

        auto &context_data = *context_.firstContextData();
        auto &parms = context_data.parms();

        switch (parms.scheme())
        {
        case SchemeType::bfv:
            bfvDecrypt(encrypted, destination);
            return;

        case SchemeType::ckks:
            ckksDecrypt(encrypted, destination);
            return;

        case SchemeType::bgv:
            bgvDecrypt(encrypted, destination);
            return;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Decryptor::bfvDecrypt(const Ciphertext &encrypted, Plaintext &destination)
    {
        if (encrypted.isNttForm())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        // This is equal to Delta m + v where ||v|| < Delta/2.
        // Add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
        // Therefore, we can (integer) divide by Delta and the answer will round down to m.

        // Make a temp destination for all the arithmetic mod qi before calling FastBConverse
        auto tmp_dest_modq = allocateZeroPoly(coeff_count, coeff_modulus_size);
        // SEAL_ALLOCATE_ZERO_GET_RNS_ITER(tmp_dest_modq, coeff_count, coeff_modulus_size, pool);

        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        dotProductCtSkArray(encrypted, tmp_dest_modq.asPointer());

        // Allocate a full size destination to write to
        destination.parmsID() = parmsIDZero;
        destination.resize(coeff_count);

        // Divide scaling variant using BEHZ FullRNS techniques
        context_data.rnsTool()->decryptScaleAndRound(tmp_dest_modq.asPointer(), destination.data());

        // How many non-zero coefficients do we really have in the result?
        size_t plain_coeff_count = getSignificantUint64CountUint(destination.data(), coeff_count);

        // Resize destination to appropriate size
        destination.resize(max(plain_coeff_count, size_t(1)));
    }

    void Decryptor::ckksDecrypt(const Ciphertext &encrypted, Plaintext &destination)
    {
        if (!encrypted.isNttForm())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // We already know that the parameters are valid
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);

        // Decryption consists in finding
        // c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q_1 * q_2 * q_3
        // as long as ||m + v|| < q_1 * q_2 * q_3.
        // This is equal to m + v where ||v|| is small enough.

        // Since we overwrite destination, we zeroize destination parameters
        // This is necessary, otherwise resize will throw an exception.
        destination.parmsID() = parmsIDZero;

        // Resize destination to appropriate size
        destination.resize(rns_poly_uint64_count);

        // Do the dot product of encrypted and the secret key array using NTT.
        dotProductCtSkArray(encrypted, destination.data());

        // Set destination parameters as in encrypted
        destination.parmsID() = encrypted.parmsID();
        destination.scale() = encrypted.scale();
    }

    void Decryptor::bgvDecrypt(const Ciphertext &encrypted, Plaintext &destination)
    {
        if (encrypted.isNttForm())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        auto &plain_modulus = parms.plainModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        auto tmp_dest_modq = HostArray<uint64_t>(coeff_count * coeff_modulus_size);
        // SEAL_ALLOCATE_ZERO_GET_RNS_ITER(tmp_dest_modq, coeff_count, coeff_modulus_size, pool);

        dotProductCtSkArray(encrypted, tmp_dest_modq.asPointer());

        destination.parmsID() = parmsIDZero;
        destination.resize(coeff_count);

        context_data.rnsTool()->decryptModt(tmp_dest_modq.asPointer(), destination.data());

        if (encrypted.correctionFactor() != 1)
        {
            uint64_t fix = 1;
            if (!tryInvertUintMod(encrypted.correctionFactor(), plain_modulus, fix))
            {
                throw logic_error("invalid correction factor");
            }
            multiplyPolyScalarCoeffmod(
                ConstHostPointer(destination.data()), coeff_count, fix, plain_modulus, HostPointer(destination.data()));
        }

        // How many non-zero coefficients do we really have in the result?
        size_t plain_coeff_count = getSignificantUint64CountUint(destination.data(), coeff_count);

        // Resize destination to appropriate size
        destination.resize(max(plain_coeff_count, size_t(1)));
    }

    void Decryptor::computeSecretKeyArray(size_t max_power)
    {
        // WARNING: This function must be called with the original context_data
        auto &context_data = *context_.keyContextData();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        size_t old_size = secret_key_array_size_;
        size_t new_size = max(max_power, old_size);

        if (old_size == new_size)
        {
            return;
        }

        // Need to extend the array
        // Compute powers of secret key until max_power
        auto secret_key_array = (allocatePolyArray(new_size, coeff_count, coeff_modulus_size));
        setPolyArray(secret_key_array_.get(), old_size, coeff_count, coeff_modulus_size, secret_key_array.get());
        
        size_t poly_coeff_count = coeff_count * coeff_modulus_size;

        // Since all of the key powers in secret_key_array_ are already NTT transformed,
        // to get the next one we simply need to compute a dyadic product of the last
        // one with the first one [which is equal to NTT(secret_key_)].
        for (size_t i = 0; i < new_size - old_size; i++) {
            dyadicProductCoeffmod(
                secret_key_array.asPointer() + (old_size - 1 + i) * poly_coeff_count, secret_key_array.asPointer(), 
                coeff_modulus_size, coeff_count, &coeff_modulus[0], secret_key_array.asPointer() + (old_size + i) * poly_coeff_count);
        }

        // Take writer lock to update array

        // Do we still need to update size?
        old_size = secret_key_array_size_;
        new_size = max(max_power, secret_key_array_size_);

        if (old_size == new_size)
        {
            return;
        }

        // Acquire new array
        secret_key_array_size_ = new_size;
        secret_key_array_ = std::move(secret_key_array);
    }

    // Compute c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q.
    // Store result in destination in RNS form.
    void Decryptor::dotProductCtSkArray(const Ciphertext &encrypted, HostPointer<uint64_t> destination)
    {
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t key_coeff_modulus_size = context_.keyContextData()->parms().coeffModulus().size();
        size_t encrypted_size = encrypted.size();
        auto isNttForm = encrypted.isNttForm();

        auto ntt_tables = context_data.smallNTTTables();

        // Make sure we have enough secret key powers computed
        computeSecretKeyArray(encrypted_size - 1);

        if (encrypted_size == 2)
        {
            ConstHostPointer secret_key_array(secret_key_array_.get());
            ConstHostPointer c0(encrypted.data(0));
            ConstHostPointer c1(encrypted.data(1));
            if (isNttForm)
            {
                for (size_t i = 0; i < coeff_modulus_size; i++) {
                    size_t d = i * coeff_count;
                    // iter(c0, c1, secret_key_array, coeff_modulus, destination), coeff_modulus_size, [&](auto I) {
                    // put < c_1 * s > mod q in destination
                    dyadicProductCoeffmod(c1 + d, secret_key_array + d, coeff_count, coeff_modulus[i], destination + d);
                    // add c_0 to the result; note that destination should be in the same (NTT) form as encrypted
                    addPolyCoeffmod(destination + d, c0 + d, coeff_count, coeff_modulus[i], destination + d);
                }
            }
            else
            {
                for (size_t i = 0; i < coeff_modulus_size; i++) {
                    size_t d = i * coeff_count;
                    // iter(c0, c1, secret_key_array, coeff_modulus, ntt_tables, destination), coeff_modulus_size,
                    setUint(c1.get() + d, coeff_count, destination.get() + d);
                    // Transform c_1 to NTT form
                    nttNegacyclicHarveyLazy(destination + d, ntt_tables[i]);
                    // put < c_1 * s > mod q in destination
                    dyadicProductCoeffmod(destination + d, secret_key_array + d, coeff_count, coeff_modulus[i], destination + d);
                    // Transform back
                    inverseNttNegacyclicHarvey(destination + d, ntt_tables[i]);
                    // add c_0 to the result; note that destination should be in the same (NTT) form as encrypted
                    addPolyCoeffmod(destination + d, c0 + d, coeff_count, coeff_modulus[i], destination + d);
                }
            }
        }
        else
        {
            // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
            // Now do the dot product of encrypted_copy and the secret key array using NTT.
            // The secret key powers are already NTT transformed.
            auto encrypted_copy = HostArray<uint64_t>((encrypted_size - 1) * coeff_count * coeff_modulus_size);
            size_t poly_coeff_count = coeff_count * coeff_modulus_size;
            size_t key_poly_coeff_count = coeff_count * key_coeff_modulus_size;
            // assert(key_poly_coeff_count == poly_coeff_count);
            setPolyArray(encrypted.data(1), encrypted_size - 1, coeff_count, coeff_modulus_size, encrypted_copy.get());

            // Transform c_1, c_2, ... to NTT form unless they already are
            if (!isNttForm)
            {
                nttNegacyclicHarveyLazy(encrypted_copy.asPointer(), encrypted_size - 1, coeff_modulus_size, ntt_tables);
            }

            // Compute dyadic product with secret power array
            for (size_t i = 0; i < encrypted_size - 1; i++) {
                dyadicProductCoeffmod(encrypted_copy + i * poly_coeff_count, secret_key_array_ + i * key_poly_coeff_count, 
                    coeff_modulus_size, coeff_count, &coeff_modulus[0], encrypted_copy + i * poly_coeff_count);
            }

            // Aggregate all polynomials together to complete the dot product
            setZeroPoly(coeff_count, coeff_modulus_size, destination.get());
            for (size_t i = 0; i < encrypted_size - 1; i++) {
                addPolyCoeffmod(destination, encrypted_copy + i * poly_coeff_count, coeff_modulus_size, coeff_count, &coeff_modulus[0], destination);
            }

            if (!isNttForm)
            {
                // If the input was not in NTT form, need to transform back
                inverseNttNegacyclicHarvey(destination, coeff_modulus_size, ntt_tables);
            }

            // Finally add c_0 to the result; note that destination should be in the same (NTT) form as encrypted
            addPolyCoeffmod(destination, encrypted.data(), coeff_modulus_size, coeff_count, &coeff_modulus[0], destination);
        }
    }

    int Decryptor::invariantNoiseBudget(const Ciphertext &encrypted)
    {
        // Verify that encrypted is valid.
        if (!isValidFor(encrypted, context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Additionally check that ciphertext doesn't have trivial size
        if (encrypted.size() < SEAL_CIPHERTEXT_SIZE_MIN)
        {
            throw invalid_argument("encrypted is empty");
        }

        auto scheme = context_.keyContextData()->parms().scheme();
        if (scheme != SchemeType::bfv && scheme != SchemeType::bgv)
        {
            throw logic_error("unsupported scheme");
        }
        if (encrypted.isNttForm())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        auto &plain_modulus = parms.plainModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Storage for the infinity norm of noise poly
        auto norm = allocateUint(coeff_modulus_size);

        // Storage for noise poly
        auto noise_poly = HostArray<uint64_t>(coeff_count * coeff_modulus_size);
        // SEAL_ALLOCATE_ZERO_GET_RNS_ITER(noise_poly, coeff_count, coeff_modulus_size, pool_);

        // Now need to compute c(s) - Delta*m (mod q)
        // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        // This is equal to Delta m + v where ||v|| < Delta/2.
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q
        // in destination_poly.
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        dotProductCtSkArray(encrypted, noise_poly.asPointer());

        // Multiply by plain_modulus and reduce mod coeff_modulus to get
        // coeffModulus()*noise.
        if (scheme == SchemeType::bfv)
        {
            multiplyPolyScalarCoeffmod(
                noise_poly.asPointer(), coeff_modulus_size, coeff_count, plain_modulus.value(), &coeff_modulus[0], noise_poly.asPointer());
        }

        // CRT-compose the noise
        context_data.rnsTool()->baseq()->composeArray(noise_poly.get(), coeff_count);

        // Next we compute the infinity norm mod parms.coeffModulus()
        // StrideIter<const uint64_t *> wide_noise_poly((*noise_poly).ptr(), coeff_modulus_size);
        polyInftyNormCoeffmod(noise_poly.get(), coeff_modulus_size, coeff_count, context_data.totalCoeffModulus(), norm.get());

        // The -1 accounts for scaling the invariant noise by 2;
        // note that we already took plain_modulus into account in compose
        // so no need to subtract log(plain_modulus) from this
        int bit_count_diff = context_data.totalCoeffModulusBitCount() -
                             getSignificantBitCountUint(norm.get(), coeff_modulus_size) - 1;
        return max(0, bit_count_diff);
    }
} // namespace seal
