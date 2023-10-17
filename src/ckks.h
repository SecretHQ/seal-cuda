// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "context.h"
#include "plaintext.h"
#include "utils/common.h"
#include "utils/croots.h"
#include "utils/defines.h"
#include "utils/dwthandler.h"
#include "utils/uintarithsmallmod.h"
#include "utils/uintcore.h"
#include "valcheck.h"
#include <cmath>
#include <complex>
#include <limits>
#include <type_traits>
#include <vector>

namespace troy
{
    // template <
    //     typename T_out, typename = std::enable_if_t<
    //                         std::is_same<std::remove_cv_t<T_out>, double>::value ||
    //                         std::is_same<std::remove_cv_t<T_out>, std::complex<double>>::value>>
    // inline T_out fromComplex(std::complex<double> in);

    // inline double fromComplex(std::complex<double> in)
    // {
    //     return in.real();
    // }

    namespace util
    {
        template <>
        class Arithmetic<std::complex<double>, std::complex<double>, double>
        {
        public:
            Arithmetic()
            {}

            inline std::complex<double> add(const std::complex<double> &a, const std::complex<double> &b) const
            {
                return a + b;
            }

            inline std::complex<double> sub(const std::complex<double> &a, const std::complex<double> &b) const
            {
                return a - b;
            }

            inline std::complex<double> mulRoot(const std::complex<double> &a, const std::complex<double> &r) const
            {
                return a * r;
            }

            inline std::complex<double> mulScalar(const std::complex<double> &a, const double &s) const
            {
                return a * s;
            }

            inline std::complex<double> mulRootScalar(const std::complex<double> &r, const double &s) const
            {
                return r * s;
            }

            inline std::complex<double> guard(const std::complex<double> &a) const
            {
                return a;
            }
        };
    } // namespace util

    /**
    Provides functionality for encoding vectors of complex or real numbers into
    plaintext polynomials to be encrypted and computed on using the CKKS scheme.
    If the polynomial modulus degree is N, then CKKSEncoder converts vectors of
    N/2 complex numbers into plaintext elements. Homomorphic operations performed
    on such encrypted vectors are applied coefficient (slot-)wise, enabling
    powerful SIMD functionality for computations that are vectorizable. This
    functionality is often called "batching" in the homomorphic encryption
    literature.

    @par Mathematical Background
    Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of
    two, the CKKSEncoder implements an approximation of the canonical embedding
    of the ring of integers Z[X]/(X^N+1) into C^(N/2), where C denotes the complex
    numbers. The Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2)
    whose action on the primitive roots of unity modulo coeff_modulus is easy to
    describe. Since the batching slots correspond 1-to-1 to the primitive roots
    of unity, applying Galois automorphisms on the plaintext acts by permuting
    the slots. By applying generators of the two cyclic subgroups of the Galois
    group, we can effectively enable cyclic rotations and complex conjugations
    of the encrypted complex vectors.
    */
    class CKKSEncoder
    {
        using ComplexArith = util::Arithmetic<std::complex<double>, std::complex<double>, double>;
        using FFTHandler = util::DWTHandler<std::complex<double>, std::complex<double>, double>;

        friend class CKKSEncoderCuda;
    public:
        /**
        Creates a CKKSEncoder instance initialized with the specified SEALContext.

        @param[in] context The SEALContext
        @throws std::invalid_argument if the encryption parameters are not valid
        @throws std::invalid_argument if scheme is not scheme_type::CKKS
        */
        CKKSEncoder(const SEALContext &context);

        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] values The vector of double-precision floating-point numbers
        (of type T) to encode
        @param[in] parms_id parms_id determining the encryption parameters to
        be used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            const std::vector<std::complex<double>> &values, ParmsID parms_id, double scale, Plaintext &destination)
        {
            encodeInternal(values.data(), values.size(), parms_id, scale, destination);
        }

        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        The encryption parameters used are the top level parameters for the given
        context. Dynamic memory allocations in the process are allocated from the
        memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] values The vector of double-precision floating-point numbers
        (of type T) to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            const std::vector<std::complex<double>> &values, double scale, Plaintext &destination)
        {
            encode(values, context_.firstParmsID(), scale, destination);
        }
        /**
        Encodes a double-precision floating-point real number into a plaintext
        polynomial. The number repeats for N/2 times to fill all slots. Dynamic
        memory allocations in the process are allocated from the memory pool
        pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision floating-point number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            double value, ParmsID parms_id, double scale, Plaintext &destination)
        {
            encodeInternal(value, parms_id, scale, destination);
        }

        /**
        Encodes a double-precision floating-point real number into a plaintext
        polynomial. The number repeats for N/2 times to fill all slots. The
        encryption parameters used are the top level parameters for the given
        context. Dynamic memory allocations in the process are allocated from
        the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision floating-point number to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            double value, double scale, Plaintext &destination)
        {
            encode(value, context_.firstParmsID(), scale, destination);
        }

        /**
        Encodes a double-precision complex number into a plaintext polynomial.
        Append zeros to fill all slots. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision complex number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            std::complex<double> value, ParmsID parms_id, double scale, Plaintext &destination)
        {
            encodeInternal(value, parms_id, scale, destination);
        }

        /**
        Encodes a double-precision complex number into a plaintext polynomial.
        Append zeros to fill all slots. The encryption parameters used are the
        top level parameters for the given context. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the
        given MemoryPoolHandle.

        @param[in] value The double-precision complex number to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            std::complex<double> value, double scale, Plaintext &destination)
        {
            encode(value, context_.firstParmsID(), scale, destination);
        }

        /**
        Encodes an integer number into a plaintext polynomial without any scaling.
        The number repeats for N/2 times to fill all slots.
        @param[in] value The integer number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        */
        inline void encode(std::int64_t value, ParmsID parms_id, Plaintext &destination)
        {
            encodeInternal(value, parms_id, destination);
        }

        /**
        Encodes an integer number into a plaintext polynomial without any scaling.
        The number repeats for N/2 times to fill all slots. The encryption
        parameters used are the top level parameters for the given context.

        @param[in] value The integer number to encode
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        */
        inline void encode(std::int64_t value, Plaintext &destination)
        {
            encode(value, context_.firstParmsID(), destination);
        }

        /**
        Decodes a plaintext polynomial into double-precision floating-point
        real or complex numbers. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] plain The plaintext to decode
        @param[out] destination The vector to be overwritten with the values in
        the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not in NTT form or is invalid
        for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void decode(
            const Plaintext &plain, std::vector<std::complex<double>> &destination)
        {
            destination.resize(slots_);
            decodeInternal(plain, destination.data());
        }
        /**
        Returns the number of complex numbers encoded.
        */
        inline std::size_t slotCount() const noexcept
        {
            return slots_;
        }

    private:
        void encodeInternal(
            const std::complex<double> *values, std::size_t values_size, 
            ParmsID parms_id, double scale, Plaintext &destination);

        void decodeInternal(const Plaintext &plain, std::complex<double> *destination);

        void encodeInternal(
            double value, ParmsID parms_id, double scale, Plaintext &destination);

        inline void encodeInternal(
            std::complex<double> value, ParmsID parms_id, double scale, Plaintext &destination)
        {
            auto input = util::HostArray<std::complex<double>>(slots_);
            for (size_t i = 0; i < slots_; i++) input[i] = value;
            encodeInternal(input.get(), slots_, parms_id, scale, destination);
        }

        void encodeInternal(std::int64_t value, ParmsID parms_id, Plaintext &destination);

        SEALContext context_;

        std::size_t slots_;

        std::shared_ptr<util::ComplexRoots> complex_roots_;

        // Holds 1~(n-1)-th powers of root in bit-reversed order, the 0-th power is left unset.
        util::HostArray<std::complex<double>> root_powers_;

        // Holds 1~(n-1)-th powers of inverse root in scrambled order, the 0-th power is left unset.
        util::HostArray<std::complex<double>> inv_root_powers_;

        util::HostArray<std::size_t> matrix_reps_index_map_;

        ComplexArith complex_arith_;

        FFTHandler fft_handler_;
    };
} // namespace seal
