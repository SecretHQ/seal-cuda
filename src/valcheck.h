// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "context.h"
#include "utils/defines.h"

namespace troy
{
    class Plaintext;
    class Ciphertext;
    class SecretKey;
    class PublicKey;
    class KSwitchKeys;
    class RelinKeys;
    class GaloisKeys;

    /**
    Check whether the given plaintext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    plaintext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    plaintext data itself.

    @param[in] in The plaintext to check
    @param[in] context The SEALContext
    @param[in] allow_pure_key_levels Determines whether pure key levels (i.e.,
    non-data levels) should be considered valid
    */
    bool isMetadataValidFor(
        const Plaintext &in, const SEALContext &context, bool allow_pure_key_levels = false);

    /**
    Check whether the given ciphertext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    ciphertext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    ciphertext data itself.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    @param[in] allow_pure_key_levels Determines whether pure key levels (i.e.,
    non-data levels) should be considered valid
    */
    bool isMetadataValidFor(
        const Ciphertext &in, const SEALContext &context, bool allow_pure_key_levels = false);

    /**
    Check whether the given secret key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    secret key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    secret key data itself.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    bool isMetadataValidFor(const SecretKey &in, const SEALContext &context);

    /**
    Check whether the given public key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    public key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    public key data itself.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    bool isMetadataValidFor(const PublicKey &in, const SEALContext &context);

    /**
    Check whether the given KSwitchKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    KSwitchKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    KSwitchKeys data itself.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    bool isMetadataValidFor(const KSwitchKeys &in, const SEALContext &context);

    /**
    Check whether the given RelinKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    RelinKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    RelinKeys data itself.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    bool isMetadataValidFor(const RelinKeys &in, const SEALContext &context);

    /**
    Check whether the given GaloisKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    GaloisKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    GaloisKeys data itself.

    @param[in] in The GaloisKeys to check
    @param[in] context The SEALContext
    */
    bool isMetadataValidFor(const GaloisKeys &in, const SEALContext &context);

    /**
    Check whether the given plaintext data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the plaintext data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the plaintext data itself.

    @param[in] in The plaintext to check
    */
    bool isBufferValid(const Plaintext &in);

    /**
    Check whether the given ciphertext data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the ciphertext data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the ciphertext data itself.

    @param[in] in The ciphertext to check
    */
    bool isBufferValid(const Ciphertext &in);

    /**
    Check whether the given secret key data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the secret key data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the secret key data itself.

    @param[in] in The secret key to check
    */
    bool isBufferValid(const SecretKey &in);

    /**
    Check whether the given public key data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the public key data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the public key data itself.

    @param[in] in The public key to check
    */
    bool isBufferValid(const PublicKey &in);

    /**
    Check whether the given KSwitchKeys data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the KSwitchKeys data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the KSwitchKeys data itself.

    @param[in] in The KSwitchKeys to check
    */
    bool isBufferValid(const KSwitchKeys &in);

    /**
    Check whether the given RelinKeys data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the RelinKeys data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the RelinKeys data itself.

    @param[in] in The RelinKeys to check
    */
    bool isBufferValid(const RelinKeys &in);

    /**
    Check whether the given GaloisKeys data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the GaloisKeys data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the GaloisKeys data itself.

    @param[in] in The GaloisKeys to check
    */
    bool isBufferValid(const GaloisKeys &in);

    /**
    Check whether the given plaintext data and metadata are valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the plaintext data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire plaintext data buffer.

    @param[in] in The plaintext to check
    @param[in] context The SEALContext
    */
    bool isDataValidFor(const Plaintext &in, const SEALContext &context);

    /**
    Check whether the given ciphertext data and metadata are valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the ciphertext data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire ciphertext data buffer.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    */
    bool isDataValidFor(const Ciphertext &in, const SEALContext &context);

    /**
    Check whether the given secret key data and metadata are valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the secret key data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire secret key data buffer.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    bool isDataValidFor(const SecretKey &in, const SEALContext &context);

    /**
    Check whether the given public key data and metadata are valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the public key data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire public key data buffer.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    bool isDataValidFor(const PublicKey &in, const SEALContext &context);

    /**
    Check whether the given KSwitchKeys data and metadata are valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the KSwitchKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire KSwitchKeys data buffer.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    bool isDataValidFor(const KSwitchKeys &in, const SEALContext &context);

    /**
    Check whether the given RelinKeys data and metadata are valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the RelinKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire RelinKeys data buffer.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    bool isDataValidFor(const RelinKeys &in, const SEALContext &context);

    /**
    Check whether the given GaloisKeys data and metadata are valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the GaloisKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire GaloisKeys data buffer.

    @param[in] in The GaloisKeys to check
    @param[in] context The SEALContext
    */
    bool isDataValidFor(const GaloisKeys &in, const SEALContext &context);

    /**
    Check whether the given plaintext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    plaintext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire plaintext data buffer.

    @param[in] in The plaintext to check
    @param[in] context The SEALContext
    */
    inline bool isValidFor(const Plaintext &in, const SEALContext &context)
    {
        return isBufferValid(in) && isDataValidFor(in, context);
    }

    /**
    Check whether the given ciphertext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    ciphertext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire ciphertext data buffer.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    */
    inline bool isValidFor(const Ciphertext &in, const SEALContext &context)
    {
        return isBufferValid(in) && isDataValidFor(in, context);
    }

    /**
    Check whether the given secret key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    secret key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire secret key data buffer.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    inline bool isValidFor(const SecretKey &in, const SEALContext &context)
    {
        return isBufferValid(in) && isDataValidFor(in, context);
    }

    /**
    Check whether the given public key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    public key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire public key data buffer.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    inline bool isValidFor(const PublicKey &in, const SEALContext &context)
    {
        return isBufferValid(in) && isDataValidFor(in, context);
    }

    /**
    Check whether the given KSwitchKeys is valid for a given SEALContext. If
    the given SEALContext is not set, the encryption parameters are invalid,
    or the KSwitchKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire KSwitchKeys data buffer.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    inline bool isValidFor(const KSwitchKeys &in, const SEALContext &context)
    {
        return isBufferValid(in) && isDataValidFor(in, context);
    }

    /**
    Check whether the given RelinKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    RelinKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire RelinKeys data buffer.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    inline bool isValidFor(const RelinKeys &in, const SEALContext &context)
    {
        return isBufferValid(in) && isDataValidFor(in, context);
    }

    /**
    Check whether the given GaloisKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    GaloisKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire GaloisKeys data buffer.

    @param[in] in The GaloisKeys to check
    @param[in] context The SEALContext
    */
    inline bool isValidFor(const GaloisKeys &in, const SEALContext &context)
    {
        return isBufferValid(in) && isDataValidFor(in, context);
    }
} // namespace seal
