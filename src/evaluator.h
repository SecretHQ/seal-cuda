// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "ciphertext.h"
#include "context.h"
#include "galoiskeys.h"
#include "modulus.h"
#include "plaintext.h"
#include "relinkeys.h"
#include "secretkey.h"
#include "valcheck.h"
#include <map>
#include <stdexcept>
#include <vector>

namespace troy
{
    /**
    Provides operations on ciphertexts. Due to the properties of the encryption scheme, the arithmetic operations pass
    through the encryption layer to the underlying plaintext, changing it according to the type of the operation. Since
    the plaintext elements are fundamentally polynomials in the polynomial quotient ring Z_T[x]/(X^N+1), where T is the
    plaintext modulus and X^N+1 is the polynomial modulus, this is the ring where the arithmetic operations will take
    place. BatchEncoder (batching) provider an alternative possibly more convenient view of the plaintext elements as
    2-by-(N2/2) matrices of integers modulo the plaintext modulus. In the batching view the arithmetic operations act on
    the matrices element-wise. Some of the operations only apply in the batching view, such as matrix row and column
    rotations. Other operations such as relinearization have no semantic meaning but are necessary for performance
    reasons.

    @par Arithmetic Operations
    The core operations are arithmetic operations, in particular multiplication and addition of ciphertexts. In addition
    to these, we also provide negation, subtraction, squaring, exponentiation, and multiplication and addition of
    several ciphertexts for convenience. in many cases some of the inputs to a computation are plaintext elements rather
    than ciphertexts. For this we provide fast "plain" operations: plain addition, plain subtraction, and plain
    multiplication.

    @par Relinearization
    One of the most important non-arithmetic operations is relinearization, which takes as input a ciphertext of size
    K+1 and relinearization keys (at least K-1 keys are needed), and changes the size of the ciphertext down to 2
    (minimum size). For most use-cases only one relinearization key suffices, in which case relinearization should be
    performed after every multiplication. Homomorphic multiplication of ciphertexts of size K+1 and L+1 outputs a
    ciphertext of size K+L+1, and the computational cost of multiplication is proportional to K*L. Plain multiplication
    and addition operations of any type do not change the size. Relinearization requires relinearization keys to have
    been generated.

    @par Rotations
    When batching is enabled, we provide operations for rotating the plaintext matrix rows cyclically left or right, and
    for rotating the columns (swapping the rows). Rotations require Galois keys to have been generated.

    @par Other Operations
    We also provide operations for transforming ciphertexts to NTT form and back, and for transforming plaintext
    polynomials to NTT form. These can be used in a very fast plain multiplication variant, that assumes the inputs to
    be in NTT form. Since the NTT has to be done in any case in plain multiplication, this function can be used when
    e.g. one plaintext input is used in several plain multiplication, and transforming it several times would not make
    sense.

    @par NTT form
    When using the BFV/BGV scheme (SchemeType::bfv/bgv), all plaintexts and ciphertexts should remain by default in the
    usual coefficient representation, i.e., not in NTT form. When using the CKKS scheme (SchemeType::ckks), all
    plaintexts and ciphertexts should remain by default in NTT form. We call these scheme-specific NTT states the
    "default NTT form". Some functions, such as add, work even if the inputs are not in the default state, but others,
    such as multiply, will throw an exception. The output of all evaluation functions will be in the same state as the
    input(s), with the exception of the transformTo_ntt and transformFrom_ntt functions, which change the state.
    Ideally, unless these two functions are called, all other functions should "just work".

    @see EncryptionParameters for more details on encryption parameters.
    @see BatchEncoder for more details on batching
    @see RelinKeys for more details on relinearization keys.
    @see GaloisKeys for more details on Galois keys.
    */
    class Evaluator
    {
    public:
        /**
        Creates an Evaluator instance initialized with the specified SEALContext.

        @param[in] context The SEALContext
        @throws std::invalid_argument if the encryption parameters are not valid
        */
        Evaluator(const SEALContext &context);

        /**
        Negates a ciphertext.

        @param[in] encrypted The ciphertext to negate
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        */
        void negateInplace(Ciphertext &encrypted) const;

        /**
        Negates a ciphertext and stores the result in the destination parameter.

        @param[in] encrypted The ciphertext to negate
        @param[out] destination The ciphertext to overwrite with the negated result
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void negate(const Ciphertext &encrypted, Ciphertext &destination) const
        {
            destination = encrypted;
            negateInplace(destination);
        }

        /**
        Adds two ciphertexts. This function adds together encrypted1 and encrypted2 and stores the result in encrypted1.

        @param[in] encrypted1 The first ciphertext to add
        @param[in] encrypted2 The second ciphertext to add
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        void addInplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const;

        /**
        Adds two ciphertexts. This function adds together encrypted1 and encrypted2 and stores the result in the
        destination parameter.

        @param[in] encrypted1 The first ciphertext to add
        @param[in] encrypted2 The second ciphertext to add
        @param[out] destination The ciphertext to overwrite with the addition result
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void add(const Ciphertext &encrypted1, const Ciphertext &encrypted2, Ciphertext &destination) const
        {
            if (&encrypted2 == &destination)
            {
                addInplace(destination, encrypted1);
            }
            else
            {
                destination = encrypted1;
                addInplace(destination, encrypted2);
            }
        }

        /**
        Adds together a vector of ciphertexts and stores the result in the destination parameter.

        @param[in] encrypteds The ciphertexts to add
        @param[out] destination The ciphertext to overwrite with the addition result
        @throws std::invalid_argument if encrypteds is empty
        @throws std::invalid_argument if encrypteds are not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypteds are in different NTT forms
        @throws std::invalid_argument if encrypteds are at different level or scale
        @throws std::invalid_argument if destination is one of encrypteds
        @throws std::logic_error if result ciphertext is transparent
        */
        void addMany(const std::vector<Ciphertext> &encrypteds, Ciphertext &destination) const;

        /**
        Subtracts two ciphertexts. This function computes the difference of encrypted1 and encrypted2, and stores the
        result in encrypted1.

        @param[in] encrypted1 The ciphertext to subtract from
        @param[in] encrypted2 The ciphertext to subtract
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        void subInplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const;

        /**
        Subtracts two ciphertexts. This function computes the difference of encrypted1 and encrypted2 and stores the
        result in the destination parameter.

        @param[in] encrypted1 The ciphertext to subtract from
        @param[in] encrypted2 The ciphertext to subtract
        @param[out] destination The ciphertext to overwrite with the subtraction result
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void sub(const Ciphertext &encrypted1, const Ciphertext &encrypted2, Ciphertext &destination) const
        {
            if (&encrypted2 == &destination)
            {
                subInplace(destination, encrypted1);
                negateInplace(destination);
            }
            else
            {
                destination = encrypted1;
                subInplace(destination, encrypted2);
            }
        }

        /**
        Multiplies two ciphertexts. This functions computes the product of encrypted1 and encrypted2 and stores the
        result in encrypted1. Dynamic memory allocations in the process are allocated from the memory pool pointed to by
        the given MemoryPoolHandle.

        @param[in] encrypted1 The first ciphertext to multiply
        @param[in] encrypted2 The second ciphertext to multiply
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted1 or encrypted2 is not in the default NTT form
        @throws std::invalid_argument if encrypted1 and encrypted2 are at different level
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void multiplyInplace(
            Ciphertext &encrypted1, const Ciphertext &encrypted2) const;

        /**
        Multiplies two ciphertexts. This functions computes the product of encrypted1 and encrypted2 and stores the
        result in the destination parameter. Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted1 The first ciphertext to multiply
        @param[in] encrypted2 The second ciphertext to multiply
        @param[out] destination The ciphertext to overwrite with the multiplication result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are at different level
        @throws std::invalid_argument if encrypted1 or encrypted2 is not in the default NTT form
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void multiply(
            const Ciphertext &encrypted1, const Ciphertext &encrypted2, Ciphertext &destination) const
        {
            if (&encrypted2 == &destination)
            {
                multiplyInplace(destination, encrypted1);
            }
            else
            {
                destination = encrypted1;
                multiplyInplace(destination, encrypted2);
            }
        }

        /**
        Squares a ciphertext. This functions computes the square of encrypted. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to square
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void squareInplace(Ciphertext &encrypted) const;

        /**
        Squares a ciphertext. This functions computes the square of encrypted and stores the result in the destination
        parameter. Dynamic memory allocations in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] encrypted The ciphertext to square
        @param[out] destination The ciphertext to overwrite with the square
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void square(
            const Ciphertext &encrypted, Ciphertext &destination) const
        {
            destination = encrypted;
            squareInplace(destination);
        }

        /**
        Relinearizes a ciphertext. This functions relinearizes encrypted, reducing its size down to 2. If the size of
        encrypted is K+1, the given relinearization keys need to have size at least K-1. Dynamic memory allocations in
        the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to relinearize
        @param[in] relin_keys The relinearization keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if relin_keys do not correspond to the top level parameters in the current context
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void relinearizeInplace(
            Ciphertext &encrypted, const RelinKeys &relin_keys) const
        {
            relinearizeInternal(encrypted, relin_keys, 2);
        }

        /**
        Relinearizes a ciphertext. This functions relinearizes encrypted, reducing its size down to 2, and stores the
        result in the destination parameter. If the size of encrypted is K+1, the given relinearization keys need to
        have size at least K-1. Dynamic memory allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to relinearize
        @param[in] relin_keys The relinearization keys
        @param[out] destination The ciphertext to overwrite with the relinearized result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if relin_keys do not correspond to the top level parameters in the current context
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void relinearize(
            const Ciphertext &encrypted, const RelinKeys &relin_keys, Ciphertext &destination) const
        {
            destination = encrypted;
            relinearizeInplace(destination, relin_keys);
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1} and
        stores the result in the destination parameter. Dynamic memory allocations in the process are allocated from the
        memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void modSwitchToNext(
            const Ciphertext &encrypted, Ciphertext &destination) const;

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}. Dynamic
        memory allocations in the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void modSwitchToNextInplace(
            Ciphertext &encrypted) const
        {
            modSwitchToNext(encrypted, encrypted);
        }

        /**
        Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo q_1...q_{k-1}.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lowest level
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        */
        inline void modSwitchToNextInplace(Plaintext &plain) const
        {
            // Verify parameters.
            if (!isValidFor(plain, context_))
            {
                throw std::invalid_argument("plain is not valid for encryption parameters");
            }
            modSwitchDropToNext(plain);
        }

        /**
        Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo q_1...q_{k-1} and stores the
        result in the destination parameter.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @param[out] destination The plaintext to overwrite with the modulus switched result
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lowest level
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void modSwitchToNext(const Plaintext &plain, Plaintext &destination) const
        {
            destination = plain;
            modSwitchToNextInplace(destination);
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters
        reach the given parms_id. Dynamic memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain than the parameters
        corresponding to parms_id
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void modSwitchToInplace(
            Ciphertext &encrypted, ParmsID parms_id) const;

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters
        reach the given parms_id and stores the result in the destination parameter. Dynamic memory allocations in the
        process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain than the parameters
        corresponding to parms_id
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void modSwitchTo(
            const Ciphertext &encrypted, ParmsID parms_id, Ciphertext &destination) const
        {
            destination = encrypted;
            modSwitchToInplace(destination, parms_id);
        }

        /**
        Given an NTT transformed plaintext modulo q_1...q_k, this function switches the modulus down until the
        parameters reach the given parms_id.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lower level in modulus chain than the parameters
        corresponding to parms_id
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        */
        void modSwitchToInplace(Plaintext &plain, ParmsID parms_id) const;

        /**
        Given an NTT transformed plaintext modulo q_1...q_k, this function switches the modulus down until the
        parameters reach the given parms_id and stores the result in the destination parameter.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[out] destination The plaintext to overwrite with the modulus switched result
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lower level in modulus chain than the parameters
        corresponding to parms_id
        @throws std::invalid_argument if the scale is too large for the new encryption parameters
        */
        inline void modSwitchTo(const Plaintext &plain, ParmsID parms_id, Plaintext &destination) const
        {
            destination = plain;
            modSwitchToInplace(destination, parms_id);
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}, scales
        the message down accordingly, and stores the result in the destination parameter. Dynamic memory allocations in
        the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void rescaleToNext(
            const Ciphertext &encrypted, Ciphertext &destination) const;

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1} and
        scales the message down accordingly. Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rescaleToNextInplace(
            Ciphertext &encrypted) const
        {
            rescaleToNext(encrypted, encrypted);
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters
        reach the given parms_id and scales the message down accordingly. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain than the parameters
        corresponding to parms_id
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void rescaleToInplace(
            Ciphertext &encrypted, ParmsID parms_id) const;

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters
        reach the given parms_id, scales the message down accordingly, and stores the result in the destination
        parameter. Dynamic memory allocations in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain than the parameters
        corresponding to parms_id
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rescaleTo(
            const Ciphertext &encrypted, ParmsID parms_id, Ciphertext &destination) const
        {
            destination = encrypted;
            rescaleToInplace(destination, parms_id);
        }

        /**
        Multiplies several ciphertexts together. This function computes the product of several ciphertext given as an
        std::vector and stores the result in the destination parameter. The multiplication is done in a depth-optimal
        order, and relinearization is performed automatically after every multiplication in the process. In
        relinearization the given relinearization keys are used. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypteds The ciphertexts to multiply
        @param[in] relin_keys The relinearization keys
        @param[out] destination The ciphertext to overwrite with the multiplication result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::bfv or SchemeType::bgv
        @throws std::invalid_argument if encrypteds is empty
        @throws std::invalid_argument if ciphertexts or relin_keys are not valid for the encryption parameters
        @throws std::invalid_argument if encrypteds are not in the default NTT form
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        void multiplyMany(
            const std::vector<Ciphertext> &encrypteds, const RelinKeys &relin_keys, Ciphertext &destination) const;

        /**
        Exponentiates a ciphertext. This functions raises encrypted to a power. Dynamic memory allocations in the
        process are allocated from the memory pool pointed to by the given MemoryPoolHandle. The exponentiation is done
        in a depth-optimal order, and relinearization is performed automatically after every multiplication in the
        process. In relinearization the given relinearization keys are used.

        @param[in] encrypted The ciphertext to exponentiate
        @param[in] exponent The power to raise the ciphertext to
        @param[in] relin_keys The relinearization keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::bfv or SchemeType::bgv
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if exponent is zero
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        void exponentiateInplace(
            Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys) const;

        /**
        Exponentiates a ciphertext. This functions raises encrypted to a power and stores the result in the destination
        parameter. Dynamic memory allocations in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle. The exponentiation is done in a depth-optimal order, and relinearization is performed
        automatically after every multiplication in the process. In relinearization the given relinearization keys are
        used.

        @param[in] encrypted The ciphertext to exponentiate
        @param[in] exponent The power to raise the ciphertext to
        @param[in] relin_keys The relinearization keys
        @param[out] destination The ciphertext to overwrite with the power
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::bfv or SchemeType::bgv
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if exponent is zero
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void exponentiate(
            const Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys, Ciphertext &destination) const
        {
            destination = encrypted;
            exponentiateInplace(destination, exponent, relin_keys);
        }

        /**
        Adds a ciphertext and a plaintext.

        @param[in] encrypted The ciphertext to add
        @param[in] plain The plaintext to add
        @throws std::invalid_argument if encrypted or plain is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted or plain is not in the default NTT form
        @throws std::invalid_argument if encrypted and plain are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        void addPlainInplace(Ciphertext &encrypted, const Plaintext &plain) const;

        /**
        Adds a ciphertext and a plaintext. This function adds a ciphertext and a plaintext and stores the result in the
        destination parameter. Note that in many cases it can be much more efficient to perform any computations on raw
        unencrypted data before encoding it, rather than using this function to compute on the plaintext objects.

        @param[in] encrypted The ciphertext to add
        @param[in] plain The plaintext to add
        @param[out] destination The ciphertext to overwrite with the addition result
        @throws std::invalid_argument if encrypted or plain is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted or plain is not in the default NTT form
        @throws std::invalid_argument if encrypted and plain are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void addPlain(const Ciphertext &encrypted, const Plaintext &plain, Ciphertext &destination) const
        {
            destination = encrypted;
            addPlainInplace(destination, plain);
        }

        /**
        Subtracts a plaintext from a ciphertext.

        @param[in] encrypted The ciphertext to subtract from
        @param[in] plain The plaintext to subtract
        @throws std::invalid_argument if encrypted or plain is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted or plain is not in the default NTT form
        @throws std::invalid_argument if encrypted and plain are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        void subPlainInplace(Ciphertext &encrypted, const Plaintext &plain) const;

        /**
        Subtracts a plaintext from a ciphertext. This function subtracts a plaintext from a ciphertext and stores the
        result in the destination parameter.

        @param[in] encrypted The ciphertext to subtract from
        @param[in] plain The plaintext to subtract
        @param[out] destination The ciphertext to overwrite with the subtraction result
        @throws std::invalid_argument if encrypted or plain is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted or plain is not in the default NTT form
        @throws std::invalid_argument if encrypted and plain are at different level or scale
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void subPlain(const Ciphertext &encrypted, const Plaintext &plain, Ciphertext &destination) const
        {
            destination = encrypted;
            subPlainInplace(destination, plain);
        }

        /**
        Multiplies a ciphertext with a plaintext. The plaintext cannot be identically 0. Dynamic memory allocations in
        the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to multiply
        @param[in] plain The plaintext to multiply
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or plain is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted and plain are in different NTT forms
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void multiplyPlainInplace(
            Ciphertext &encrypted, const Plaintext &plain) const;

        /**
        Multiplies a ciphertext with a plaintext. This function multiplies a ciphertext with a plaintext and stores the
        result in the destination parameter. The plaintext cannot be identically 0. Dynamic memory allocations in the
        process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to multiply
        @param[in] plain The plaintext to multiply
        @param[out] destination The ciphertext to overwrite with the multiplication result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or plain is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted and plain are in different NTT forms
        @throws std::invalid_argument if the output scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void multiplyPlain(
            const Ciphertext &encrypted, const Plaintext &plain, Ciphertext &destination) const
        {
            destination = encrypted;
            multiplyPlainInplace(destination, plain);
        }

        /**
        Transforms a plaintext to NTT domain. This functions applies the Number Theoretic Transform to a plaintext by
        first embedding integers modulo the plaintext modulus to integers modulo the coefficient modulus and then
        performing David Harvey's NTT on the resulting polynomial. The transformation is done with respect to encryption
        parameters corresponding to a given parms_id. For the operation to be valid, the plaintext must have degree less
        than poly_modulus_degree and each coefficient must be less than the plaintext modulus, i.e., the plaintext must
        be a valid plaintext under the current encryption parameters. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to transform
        @param[in] parms_id The parms_id with respect to which the NTT is done
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is already in NTT form
        @throws std::invalid_argument if plain or parms_id is not valid for the
        encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        void transformToNttInplace(
            Plaintext &plain, ParmsID parms_id) const;

        /**
        Transforms a plaintext to NTT domain. This functions applies the Number Theoretic Transform to a plaintext by
        first embedding integers modulo the plaintext modulus to integers modulo the coefficient modulus and then
        performing David Harvey's NTT on the resulting polynomial. The transformation is done with respect to encryption
        parameters corresponding to a given parms_id. The result is stored in the destination_ntt parameter. For the
        operation to be valid, the plaintext must have degree less than poly_modulus_degree and each coefficient must be
        less than the plaintext modulus, i.e., the plaintext must be a valid plaintext under the current encryption
        parameters. Dynamic memory allocations in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] plain The plaintext to transform
        @param[in] parms_id The parms_id with respect to which the NTT is done
        @param[out] destinationNTT The plaintext to overwrite with the transformed result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is already in NTT form
        @throws std::invalid_argument if plain or parms_id is not valid for the
        encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void transformToNtt(
            const Plaintext &plain, ParmsID parms_id, Plaintext &destination_ntt) const
        {
            destination_ntt = plain;
            transformToNttInplace(destination_ntt, parms_id);
        }

        /**
        Transforms a ciphertext to NTT domain. This functions applies David Harvey's Number Theoretic Transform
        separately to each polynomial of a ciphertext.

        @param[in] encrypted The ciphertext to transform
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is already in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        void transformToNttInplace(Ciphertext &encrypted) const;

        /**
        Transforms a ciphertext to NTT domain. This functions applies David Harvey's Number Theoretic Transform
        separately to each polynomial of a ciphertext. The result is stored in the destination_ntt parameter.

        @param[in] encrypted The ciphertext to transform
        @param[out] destination_ntt The ciphertext to overwrite with the transformed result
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is already in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void transformToNtt(const Ciphertext &encrypted, Ciphertext &destination_ntt) const
        {
            destination_ntt = encrypted;
            transformToNttInplace(destination_ntt);
        }

        /**
        Transforms a ciphertext back from NTT domain. This functions applies the inverse of David Harvey's Number
        Theoretic Transform separately to each polynomial of a ciphertext.

        @param[in] encrypted_ntt The ciphertext to transform
        @throws std::invalid_argument if encrypted_ntt is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted_ntt is not in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        void transformFromNttInplace(Ciphertext &encrypted_ntt) const;

        /**
        Transforms a ciphertext back from NTT domain. This functions applies the inverse of David Harvey's Number
        Theoretic Transform separately to each polynomial of a ciphertext. The result is stored in the destination
        parameter.

        @param[in] encrypted_ntt The ciphertext to transform
        @param[out] destination The ciphertext to overwrite with the transformed result
        @throws std::invalid_argument if encrypted_ntt is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted_ntt is not in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void transformFromNtt(const Ciphertext &encrypted_ntt, Ciphertext &destination) const
        {
            destination = encrypted_ntt;
            transformFromNttInplace(destination);
        }

        /**
        Applies a Galois automorphism to a ciphertext. To evaluate the Galois automorphism, an appropriate set of Galois
        keys must also be provided. Dynamic memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        The desired Galois automorphism is given as a Galois element, and must be an odd integer in the interval
        [1, M-1], where M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element 3^i % M corresponds
        to a cyclic row rotation i steps to the left, and a Galois element 3^(N/2-i) % M corresponds to a cyclic row
        rotation i steps to the right. The Galois element M-1 corresponds to a column rotation (row swap) in BFV/BGV,
        and complex conjugation in CKKS. In the polynomial view (not batching), a Galois automorphism by a Galois
        element p changes Enc(plain(x)) to Enc(plain(x^p)).

        @param[in] encrypted The ciphertext to apply the Galois automorphism to
        @param[in] galois_elt The Galois element
        @param[in] galois_keys The Galois keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if the Galois element is not valid
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        void applyGaloisInplace(
            Ciphertext &encrypted, std::uint32_t galois_elt, const GaloisKeys &galois_keys) const;

        /**
        Applies a Galois automorphism to a ciphertext and writes the result to the destination parameter. To evaluate
        the Galois automorphism, an appropriate set of Galois keys must also be provided. Dynamic memory allocations in
        the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        The desired Galois automorphism is given as a Galois element, and must be an odd integer in the interval
        [1, M-1], where M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element 3^i % M corresponds
        to a cyclic row rotation i steps to the left, and a Galois element 3^(N/2-i) % M corresponds to a cyclic row
        rotation i steps to the right. The Galois element M-1 corresponds to a column rotation (row swap) in BFV/BGV,
        and complex conjugation in CKKS. In the polynomial view (not batching), a Galois automorphism by a Galois
        element p changes Enc(plain(x)) to Enc(plain(x^p)).

        @param[in] encrypted The ciphertext to apply the Galois automorphism to
        @param[in] galois_elt The Galois element
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if the Galois element is not valid
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void applyGalois(
            const Ciphertext &encrypted, std::uint32_t galois_elt, const GaloisKeys &galois_keys,
            Ciphertext &destination) const
        {
            destination = encrypted;
            applyGaloisInplace(destination, galois_elt, galois_keys);
        }

        /**
        Rotates plaintext matrix rows cyclically. When batching is used with the BFV/BGV scheme, this function rotates
        the encrypted plaintext matrix rows cyclically to the left (steps > 0) or to the right (steps < 0). Since the
        size of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial modulus, the number of steps
        to rotate must have absolute value at most N/2-1. Dynamic memory allocations in the process are allocated from
        the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (positive left, negative right)
        @param[in] galois_keys The Galois keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::bfv or SchemeType::bgv
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotateRowsInplace(
            Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys) const
        {
            auto scheme = context_.keyContextData()->parms().scheme();
            if (scheme != SchemeType::bfv && scheme != SchemeType::bgv)
            {
                throw std::logic_error("unsupported scheme");
            }
            rotateInternal(encrypted, steps, galois_keys);
        }

        /**
        Rotates plaintext matrix rows cyclically. When batching is used with the BFV/BGV scheme, this function rotates
        the encrypted plaintext matrix rows cyclically to the left (steps > 0) or to the right (steps < 0) and writes
        the result to the destination parameter. Since the size of the batched matrix is 2-by-(N/2), where N is the
        degree of the polynomial modulus, the number of steps to rotate must have absolute value at most N/2-1. Dynamic
        memory allocations in the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (positive left, negative right)
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::bfv or SchemeType::bgv
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotateRows(
            const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys, Ciphertext &destination) const
        {
            destination = encrypted;
            rotateRowsInplace(destination, steps, galois_keys);
        }

        /**
        Rotates plaintext matrix columns cyclically. When batching is used with the BFV scheme, this function rotates
        the encrypted plaintext matrix columns cyclically. Since the size of the batched matrix is 2-by-(N/2), where N
        is the degree of the polynomial modulus, this means simply swapping the two rows. Dynamic memory allocations in
        the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::bfv or SchemeType::bgv
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotateColumnsInplace(
            Ciphertext &encrypted, const GaloisKeys &galois_keys) const
        {
            auto scheme = context_.keyContextData()->parms().scheme();
            if (scheme != SchemeType::bfv && scheme != SchemeType::bgv)
            {
                throw std::logic_error("unsupported scheme");
            }
            conjugateInternal(encrypted, galois_keys);
        }

        /**
        Rotates plaintext matrix columns cyclically. When batching is used with the BFV/BGV scheme, this function
        rotates the encrypted plaintext matrix columns cyclically, and writes the result to the destination parameter.
        Since the size of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial modulus, this means
        simply swapping the two rows. Dynamic memory allocations in the process are allocated from the memory pool
        pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::bfv or SchemeType::bgv
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotateColumns(
            const Ciphertext &encrypted, const GaloisKeys &galois_keys, Ciphertext &destination) const
        {
            destination = encrypted;
            rotateColumnsInplace(destination, galois_keys);
        }

        /**
        Rotates plaintext vector cyclically. When using the CKKS scheme, this function rotates the encrypted plaintext
        vector cyclically to the left (steps > 0) or to the right (steps < 0). Since the size of the batched matrix is
        2-by-(N/2), where N is the degree of the polynomial modulus, the number of steps to rotate must have absolute
        value at most N/2-1. Dynamic memory allocations in the process are allocated from the memory pool pointed to by
        the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (positive left, negative right)
        @param[in] galois_keys The Galois keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::ckks
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotateVectorInplace(
            Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys) const
        {
            if (context_.keyContextData()->parms().scheme() != SchemeType::ckks)
            {
                throw std::logic_error("unsupported scheme");
            }
            rotateInternal(encrypted, steps, galois_keys);
        }

        /**
        Rotates plaintext vector cyclically. When using the CKKS scheme, this function rotates the encrypted plaintext
        vector cyclically to the left (steps > 0) or to the right (steps < 0) and writes the result to the destination
        parameter. Since the size of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial modulus,
        the number of steps to rotate must have absolute value at most N/2-1. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (positive left, negative right)
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::ckks
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotateVector(
            const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys, Ciphertext &destination) const
        {
            destination = encrypted;
            rotateVectorInplace(destination, steps, galois_keys);
        }

        /**
        Complex conjugates plaintext slot values. When using the CKKS scheme, this function complex conjugates all
        values in the underlying plaintext. Dynamic memory allocations in the process are allocated from the memory pool
        pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::ckks
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void complexConjugateInplace(
            Ciphertext &encrypted, const GaloisKeys &galois_keys) const
        {
            if (context_.keyContextData()->parms().scheme() != SchemeType::ckks)
            {
                throw std::logic_error("unsupported scheme");
            }
            conjugateInternal(encrypted, galois_keys);
        }

        /**
        Complex conjugates plaintext slot values. When using the CKKS scheme, this function complex conjugates all
        values in the underlying plaintext, and writes the result to the destination parameter. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not SchemeType::ckks
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void complexConjugate(
            const Ciphertext &encrypted, const GaloisKeys &galois_keys, Ciphertext &destination) const
        {
            destination = encrypted;
            complexConjugateInplace(destination, galois_keys);
        }

        /**
        Enables access to private members of seal::Evaluator for SEAL_C.
        */
        struct EvaluatorPrivateHelper;

    private:
        Evaluator(const Evaluator &copy) = delete;

        Evaluator(Evaluator &&source) = delete;

        Evaluator &operator=(const Evaluator &assign) = delete;

        Evaluator &operator=(Evaluator &&assign) = delete;

        void bfvMultiply(Ciphertext &encrypted1, const Ciphertext &encrypted2) const;

        void ckksMultiply(Ciphertext &encrypted1, const Ciphertext &encrypted2) const;

        void bgvMultiply(Ciphertext &encrypted1, const Ciphertext &encrypted2) const;

        void bfvSquare(Ciphertext &encrypted) const;

        void ckksSquare(Ciphertext &encrypted) const;

        void bgvSquare(Ciphertext &encrypted) const;

        void relinearizeInternal(
            Ciphertext &encrypted, const RelinKeys &relin_keys, std::size_t destination_size) const;

        void modSwitchScaleToNext(
            const Ciphertext &encrypted, Ciphertext &destination) const;

        void modSwitchDropToNext(const Ciphertext &encrypted, Ciphertext &destination) const;

        void modSwitchDropToNext(Plaintext &plain) const;

        void rotateInternal(
            Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys) const;

        inline void conjugateInternal(
            Ciphertext &encrypted, const GaloisKeys &galois_keys) const
        {
            // Verify parameters.
            auto context_data_ptr = context_.getContextData(encrypted.parmsID());
            if (!context_data_ptr)
            {
                throw std::invalid_argument("encrypted is not valid for encryption parameters");
            }

            // Extract encryption parameters.
            auto &context_data = *context_data_ptr;
            if (!context_data.qualifiers().using_batching)
            {
                throw std::logic_error("encryption parameters do not support batching");
            }

            auto galoisTool = context_data.galoisTool();

            // Perform rotation and key switching
            applyGaloisInplace(encrypted, galoisTool->getEltFromStep(0), galois_keys);
        }

        void switchKeyInplace(
            Ciphertext &encrypted, util::ConstHostPointer<uint64_t> target_iter, const KSwitchKeys &kswitch_keys,
            std::size_t key_index) const;

        void multiplyPlainNormal(Ciphertext &encrypted, const Plaintext &plain) const;

        void multiplyPlainNtt(Ciphertext &encrypted_ntt, const Plaintext &plain_ntt) const;

        SEALContext context_;
    };
} // namespace seal
