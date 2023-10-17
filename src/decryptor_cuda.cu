// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "kernelutils.cuh"
#include "decryptor_cuda.cuh"

using namespace std;
using namespace troy::util;

namespace troy
{
    // namespace
    // {
    //     void polyInftyNormCoeffmod(
    //         ConstHostPointer<uint64_t> poly, size_t coeff_uint64_count, size_t coeff_count, const uint64_t *modulus, uint64_t *result)
    //     {

    //         // Construct negative threshold: (modulus + 1) / 2
    //         auto modulus_neg_threshold = allocateUint(coeff_uint64_count);
    //         halfRoundUpUint(modulus, coeff_uint64_count, modulus_neg_threshold.get());

    //         // Mod out the poly coefficients and choose a symmetric representative from [-modulus,modulus)
    //         setZeroUint(coeff_uint64_count, result);
    //         auto coeff_abs_value = allocateUint(coeff_uint64_count);
    //         for (size_t i = 0; i < coeff_count; i++) {
    //         // SEAL_ITERATE(poly, coeff_count, [&](auto I) {
    //             auto polyi = poly.get() + i * coeff_uint64_count;
    //             if (isGreaterThanOrEqualUint(polyi, modulus_neg_threshold.get(), coeff_uint64_count))
    //             {
    //                 subUint(modulus, polyi, coeff_uint64_count, coeff_abs_value.get());
    //             }
    //             else
    //             {
    //                 setUint(polyi, coeff_uint64_count, coeff_abs_value.get());
    //             }

    //             if (isGreaterThanUint(coeff_abs_value.get(), result, coeff_uint64_count))
    //             {
    //                 // Store the new max
    //                 setUint(coeff_abs_value.get(), coeff_uint64_count, result);
    //             }
    //         }
    //     }
    // } // namespace

    DecryptorCuda::DecryptorCuda(const SEALContextCuda &context, const SecretKeyCuda &secret_key) : context_(context)
    {

        auto &parms = context_.keyContextData()->parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Set the secret_key_array to have size 1 (first power of secret)
        // and copy over data
        secret_key_array_ = kernel_util::kAllocate(coeff_count, coeff_modulus_size);
        kernel_util::kSetPolyArray(secret_key.data().data(), 1, coeff_modulus_size, coeff_count, secret_key_array_);
        secret_key_array_size_ = 1;
    }

    void DecryptorCuda::decrypt(const CiphertextCuda &encrypted, PlaintextCuda &destination)
    {

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

    void DecryptorCuda::bfvDecrypt(const CiphertextCuda &encrypted, PlaintextCuda &destination)
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
        auto tmp_dest_modq = kernel_util::kAllocateZero(coeff_count, coeff_modulus_size);
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
        // size_t plain_coeff_count = getSignificantUint64CountUint(destination.data(), coeff_count);

        // Resize destination to appropriate size
        // destination.resize(max(plain_coeff_count, size_t(1)));
    }

    void DecryptorCuda::ckksDecrypt(const CiphertextCuda &encrypted, PlaintextCuda &destination)
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

    void DecryptorCuda::bgvDecrypt(const CiphertextCuda &encrypted, PlaintextCuda &destination)
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

        auto tmp_dest_modq = kernel_util::kAllocateZero(coeff_count * coeff_modulus_size);

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
            kernel_util::kMultiplyPolyScalarCoeffmod(destination.data(), 1, 1, coeff_count, fix, parms.plainModulusCuda(), destination.data());
        }

        // How many non-zero coefficients do we really have in the result?
        // size_t plain_coeff_count = getSignificantUint64CountUint(destination.data(), coeff_count);

        // // Resize destination to appropriate size
        // destination.resize(max(plain_coeff_count, size_t(1)));
    }

    void DecryptorCuda::computeSecretKeyArray(size_t max_power)
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
        auto secret_key_array = kernel_util::kAllocate(new_size, coeff_count, coeff_modulus_size);
        kernel_util::kSetPolyArray(secret_key_array_.get(), old_size, coeff_count, coeff_modulus_size, secret_key_array.get());
        
        size_t poly_coeff_count = coeff_count * coeff_modulus_size;

        // Since all of the key powers in secret_key_array_ are already NTT transformed,
        // to get the next one we simply need to compute a dyadic product of the last
        // one with the first one [which is equal to NTT(secret_key_)].
        for (size_t i = 0; i < new_size - old_size; i++) {
            kernel_util::kDyadicProductCoeffmod(
                secret_key_array.asPointer() + (old_size - 1 + i) * poly_coeff_count,
                secret_key_array.asPointer(),
                1, coeff_modulus_size, coeff_count, coeff_modulus,
                secret_key_array.asPointer() + (old_size + i) * poly_coeff_count
            );
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
    void DecryptorCuda::dotProductCtSkArray(const CiphertextCuda &encrypted, DevicePointer<uint64_t> destination)
    {
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_power = getPowerOfTwo(coeff_count);
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t key_coeff_modulus_size = context_.keyContextData()->parms().coeffModulus().size();
        size_t encrypted_size = encrypted.size();
        auto isNttForm = encrypted.isNttForm();

        auto ntt_tables = context_data.smallNTTTables();

        // Make sure we have enough secret key powers computed
        computeSecretKeyArray(encrypted_size - 1);

        if (encrypted_size == 2)
        {
            ConstDevicePointer secret_key_array(secret_key_array_.get());
            ConstDevicePointer c0(encrypted.data(0));
            ConstDevicePointer c1(encrypted.data(1));
            if (isNttForm)
            {
                kernel_util::kDyadicProductCoeffmod(c1, secret_key_array, 1, coeff_modulus_size, coeff_count, coeff_modulus, destination);
                kernel_util::kAddPolyCoeffmod(destination, c0, 1, coeff_modulus_size, coeff_count, coeff_modulus, destination);
            }
            else
            {
                kernel_util::kSetPolyArray(c1, 1, coeff_modulus_size, coeff_count, destination);
                kernel_util::kNttNegacyclicHarveyLazy(destination, 1, coeff_modulus_size, coeff_power, ntt_tables);
                kernel_util::kDyadicProductCoeffmod(destination, secret_key_array, 1, coeff_modulus_size, coeff_count, coeff_modulus, destination);
                kernel_util::kInverseNttNegacyclicHarvey(destination, 1, coeff_modulus_size, coeff_power, ntt_tables);
                kernel_util::kAddPolyCoeffmod(destination, c0, 1, coeff_modulus_size, coeff_count, coeff_modulus, destination);
            }
        }
        else
        {
            // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
            // Now do the dot product of encrypted_copy and the secret key array using NTT.
            // The secret key powers are already NTT transformed.
            auto encrypted_copy = DeviceArray<uint64_t>((encrypted_size - 1) * coeff_count * coeff_modulus_size);
            size_t poly_coeff_count = coeff_count * coeff_modulus_size;
            size_t key_poly_coeff_count = coeff_count * key_coeff_modulus_size;
            // assert(key_poly_coeff_count == poly_coeff_count);
            kernel_util::kSetPolyArray(encrypted.data(1), encrypted_size - 1, coeff_modulus_size, coeff_count, encrypted_copy.get());
            if (!isNttForm) {
                kernel_util::kNttNegacyclicHarveyLazy(encrypted_copy, encrypted_size - 1, coeff_modulus_size, coeff_power, ntt_tables);
            }
            for (size_t i = 0; i < encrypted_size - 1; i++) {
                kernel_util::kDyadicProductCoeffmod(encrypted_copy + i * poly_coeff_count, secret_key_array_ + i * key_poly_coeff_count, 
                    1, coeff_modulus_size, coeff_count, coeff_modulus, encrypted_copy + i * poly_coeff_count);
            }


            kernel_util::kSetZeroPolyArray(1, coeff_count, coeff_modulus_size, destination.get());
            for (size_t i = 0; i < encrypted_size - 1; i++) {
                kernel_util::kAddPolyCoeffmod(destination, encrypted_copy + i * poly_coeff_count, 1, coeff_modulus_size, coeff_count, coeff_modulus, destination);
            }

            if (!isNttForm) {
                kernel_util::kInverseNttNegacyclicHarvey(destination, 1, coeff_modulus_size, coeff_power, ntt_tables);
            }

            kernel_util::kAddPolyCoeffmod(destination, encrypted.data(), 1, coeff_modulus_size, coeff_count, coeff_modulus, destination);
        }
    }

    // int Decryptor::invariantNoiseBudget(const Ciphertext &encrypted)
    // {
    //     // Verify that encrypted is valid.
    //     if (!isValidFor(encrypted, context_))
    //     {
    //         throw invalid_argument("encrypted is not valid for encryption parameters");
    //     }

    //     // Additionally check that ciphertext doesn't have trivial size
    //     if (encrypted.size() < SEAL_CIPHERTEXT_SIZE_MIN)
    //     {
    //         throw invalid_argument("encrypted is empty");
    //     }

    //     auto scheme = context_.keyContextData()->parms().scheme();
    //     if (scheme != SchemeType::bfv && scheme != SchemeType::bgv)
    //     {
    //         throw logic_error("unsupported scheme");
    //     }
    //     if (encrypted.isNttForm())
    //     {
    //         throw invalid_argument("encrypted cannot be in NTT form");
    //     }

    //     auto &context_data = *context_.getContextData(encrypted.parmsID());
    //     auto &parms = context_data.parms();
    //     auto &coeff_modulus = parms.coeffModulus();
    //     auto &plain_modulus = parms.plainModulus();
    //     size_t coeff_count = parms.polyModulusDegree();
    //     size_t coeff_modulus_size = coeff_modulus.size();

    //     // Storage for the infinity norm of noise poly
    //     auto norm = allocateUint(coeff_modulus_size);

    //     // Storage for noise poly
    //     auto noise_poly = HostArray<uint64_t>(coeff_count * coeff_modulus_size);
    //     // SEAL_ALLOCATE_ZERO_GET_RNS_ITER(noise_poly, coeff_count, coeff_modulus_size, pool_);

    //     // Now need to compute c(s) - Delta*m (mod q)
    //     // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
    //     // This is equal to Delta m + v where ||v|| < Delta/2.
    //     // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q
    //     // in destination_poly.
    //     // Now do the dot product of encrypted_copy and the secret key array using NTT.
    //     // The secret key powers are already NTT transformed.
    //     dotProductCtSkArray(encrypted, noise_poly.asPointer());

    //     // Multiply by plain_modulus and reduce mod coeff_modulus to get
    //     // coeffModulus()*noise.
    //     if (scheme == SchemeType::bfv)
    //     {
    //         multiplyPolyScalarCoeffmod(
    //             noise_poly.asPointer(), coeff_modulus_size, coeff_count, plain_modulus.value(), &coeff_modulus[0], noise_poly.asPointer());
    //     }

    //     // CRT-compose the noise
    //     context_data.rnsTool()->baseq()->composeArray(noise_poly.get(), coeff_count);

    //     // Next we compute the infinity norm mod parms.coeffModulus()
    //     // StrideIter<const uint64_t *> wide_noise_poly((*noise_poly).ptr(), coeff_modulus_size);
    //     polyInftyNormCoeffmod(noise_poly.get(), coeff_modulus_size, coeff_count, context_data.totalCoeffModulus(), norm.get());

    //     // The -1 accounts for scaling the invariant noise by 2;
    //     // note that we already took plain_modulus into account in compose
    //     // so no need to subtract log(plain_modulus) from this
    //     int bit_count_diff = context_data.totalCoeffModulusBitCount() -
    //                          getSignificantBitCountUint(norm.get(), coeff_modulus_size) - 1;
    //     return max(0, bit_count_diff);
    // }
} // namespace seal
