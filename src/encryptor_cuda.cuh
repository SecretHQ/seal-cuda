// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "ciphertext_cuda.cuh"
#include "context_cuda.cuh"
#include "plaintext_cuda.cuh"
#include "publickey_cuda.cuh"
#include "secretkey_cuda.cuh"
#include "encryptionparams_cuda.cuh"

#include <curand_kernel.h>

namespace troy
{
    /**
    Encrypts Plaintext objects into Ciphertext objects. Constructing an Encryptor
    requires a SEALContext with valid encryption parameters, the public key and/or
    the secret key. If an Encrytor is given a secret key, it supports symmetric-key
    encryption. If an Encryptor is given a public key, it supports asymmetric-key
    encryption.

    @par Overloads
    For the encrypt function we provide two overloads concerning the memory pool
    used in allocations needed during the operation. In one overload the global
    memory pool is used for this purpose, and in another overload the user can
    supply a MemoryPoolHandle to to be used instead. This is to allow one single
    Encryptor to be used concurrently by several threads without running into thread
    contention in allocations taking place during operations. For example, one can
    share one single Encryptor across any number of threads, but in each thread
    call the encrypt function by giving it a thread-local MemoryPoolHandle to use.
    It is important for a developer to understand how this works to avoid unnecessary
    performance bottlenecks.

    @par NTT form
    When using the BFV/BGV scheme (scheme_type::bfv/bgv), all plaintext and ciphertexts should
    remain by default in the usual coefficient representation, i.e. not in NTT form.
    When using the CKKS scheme (scheme_type::ckks), all plaintexts and ciphertexts
    should remain by default in NTT form. We call these scheme-specific NTT states
    the "default NTT form". Decryption requires the input ciphertexts to be in
    the default NTT form, and will throw an exception if this is not the case.
    */
    class EncryptorCuda
    {
    public:
        /**
        Creates an Encryptor instance initialized with the specified SEALContext
        and public key.

        @param[in] context The SEALContext
        @param[in] public_key The public key
        @throws std::invalid_argument if the encryption parameters are not valid
        @throws std::invalid_argument if public_key is not valid
        */
        EncryptorCuda(const SEALContextCuda &context, const PublicKeyCuda &public_key);

        /**
        Creates an Encryptor instance initialized with the specified SEALContext
        and secret key.

        @param[in] context The SEALContext
        @param[in] secret_key The secret key
        @throws std::invalid_argument if the encryption parameters are not valid
        @throws std::invalid_argument if secret_key is not valid
        */
        EncryptorCuda(const SEALContextCuda &context, const SecretKeyCuda &secret_key);

        /**
        Creates an Encryptor instance initialized with the specified SEALContext,
        secret key, and public key.

        @param[in] context The SEALContext
        @param[in] public_key The public key
        @param[in] secret_key The secret key
        @throws std::invalid_argument if the encryption parameters are not valid
        @throws std::invalid_argument if public_key or secret_key is not valid
        */
        EncryptorCuda(const SEALContextCuda &context, const PublicKeyCuda &public_key, const SecretKeyCuda &secret_key);

        /**
        Give a new instance of public key.

        @param[in] public_key The public key
        @throws std::invalid_argument if public_key is not valid
        */
        inline void setPublicKey(const PublicKeyCuda &public_key)
        {
            public_key_ = public_key;
        }

        /**
        Give a new instance of secret key.

        @param[in] secret_key The secret key
        @throws std::invalid_argument if secret_key is not valid
        */
        inline void setSecretKey(const SecretKeyCuda &secret_key)
        {
            secret_key_ = secret_key;
        }

        /**
        Encrypts a plaintext with the public key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to:
        1) in BFV/BGV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to encrypt
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt(
            const PlaintextCuda &plain, CiphertextCuda &destination) const
        {
            encryptInternal(plain, true, destination);
        }

        /**
        Encrypts a plaintext with the public key and returns the ciphertext as
        a serializable object.

        The encryption parameters for the resulting ciphertext correspond to:
        1) in BFV/BGV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to encrypt
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline CiphertextCuda encrypt(
            const PlaintextCuda &plain) const
        {
            CiphertextCuda destination;
            encryptInternal(plain, true, destination);
            return destination;
        }

        /**
        Encrypts a zero plaintext with the public key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encryptZero(CiphertextCuda &destination) const
        {
            encryptZero(context_.firstParmsID(), destination);
        }

        /**
        Encrypts a zero plaintext with the public key and returns the ciphertext
        as a serializable object.

        The encryption parameters for the resulting ciphertext correspond to the
        given parms_id. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline CiphertextCuda encryptZero(
            ParmsID parms_id) const
        {
            CiphertextCuda destination;
            encryptZeroInternal(parms_id, true, destination);
            return destination;
        }

        /**
        Encrypts a zero plaintext with the public key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        given parms_id. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encryptZero(
            ParmsID parms_id, CiphertextCuda &destination) const
        {
            encryptZeroInternal(parms_id, true, destination);
        }

        /**
        Encrypts a zero plaintext with the public key and returns the ciphertext
        as a serializable object.

        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline CiphertextCuda encryptZero() const
        {
            return encryptZero(context_.firstParmsID());
        }

        /**
        Encrypts a plaintext with the secret key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to:
        1) in BFV/BGV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to encrypt
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encryptSymmetric(
            const PlaintextCuda &plain, CiphertextCuda &destination) const
        {
            encryptInternal(plain, false, destination);
        }

        /**
        Encrypts a plaintext with the secret key and returns the ciphertext as
        a serializable object.

        Half of the ciphertext data is pseudo-randomly generated from a seed to
        reduce the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        The encryption parameters for the resulting ciphertext correspond to:
        1) in BFV/BGV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to encrypt
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline CiphertextCuda encryptSymmetric(const PlaintextCuda &plain) const
        {
            CiphertextCuda destination;
            encryptInternal(plain, false, destination);
            return destination;
        }

        /**
        Encrypts a zero plaintext with the secret key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        given parms_id. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encryptZeroSymmetric(
            ParmsID parms_id, CiphertextCuda &destination) const
        {
            encryptZeroInternal(parms_id, false, destination);
        }

        /**
        Encrypts a zero plaintext with the secret key and returns the ciphertext
        as a serializable object.

        Half of the ciphertext data is pseudo-randomly generated from a seed to
        reduce the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        The encryption parameters for the resulting ciphertext correspond to the
        given parms_id. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline CiphertextCuda encryptZeroSymmetric(
            ParmsID parms_id) const
        {
            CiphertextCuda destination;
            encryptZeroInternal(parms_id, false, destination);
            return destination;
        }

        /**
        Encrypts a zero plaintext with the secret key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encryptZeroSymmetric(
            CiphertextCuda &destination) const
        {
            encryptZeroSymmetric(context_.firstParmsID(), destination);
        }

        /**
        Encrypts a zero plaintext with the secret key and returns the ciphertext
        as a serializable object.

        Half of the ciphertext data is pseudo-randomly generated from a seed to
        reduce the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline CiphertextCuda encryptZeroSymmetric() const
        {
            return encryptZeroSymmetric(context_.firstParmsID());
        }

        /**
        Enables access to private members of seal::Encryptor for SEAL_C.
        */
        struct EncryptorPrivateHelper;

    private:
        EncryptorCuda(const EncryptorCuda &copy) = delete;

        EncryptorCuda(EncryptorCuda &&source) = delete;

        EncryptorCuda &operator=(const EncryptorCuda &assign) = delete;

        EncryptorCuda &operator=(EncryptorCuda &&assign) = delete;

        void encryptZeroInternal(
            ParmsID parms_id, bool is_asymmetric, CiphertextCuda &destination) const;

        void encryptInternal(
            const PlaintextCuda &plain, bool is_asymmetric, CiphertextCuda &destination) const;

        SEALContextCuda context_;

        PublicKeyCuda public_key_;

        SecretKeyCuda secret_key_;

        void setupCurandStates(uint64_t seed = 0);

        mutable util::DeviceArray<curandState> curandStates;
        

    };
} // namespace seal
