#pragma once

#include <cstdint>
#include <array>
#include <stdexcept>
#include <unordered_map>

#include "utils/common.h"
#include "utils/hestdparams.h"
#include "utils/uintcore.h"
#include "utils/globals.h"


namespace troy {

    class Modulus {

        friend class DeviceHelper;

        uint64_t value_ = 0;
        uint64_t const_ratio_[3];
        std::size_t uint64_count_ = 0;
        int bit_count_ = 0;
        bool is_prime_ = false;

        void setValue(uint64_t value);

    public:
        

        /**
        Creates a Modulus instance. The value of the Modulus is set to
        the given value, or to zero by default.

        @param[in] value The integer modulus
        @throws std::invalid_argument if value is 1 or more than 61 bits
        */
        Modulus(std::uint64_t value = 0)
        {
            for (size_t i = 0; i < 3; i++) const_ratio_[i] = 0;
            setValue(value);
        }

        /**
        Creates a new Modulus by copying a given one.

        @param[in] copy The Modulus to copy from
        */
        Modulus(const Modulus &copy) = default;

        /**
        Creates a new Modulus by copying a given one.

        @param[in] source The Modulus to move from
        */
        Modulus(Modulus &&source) = default;

        /**
        Copies a given Modulus to the current one.

        @param[in] assign The Modulus to copy from
        */
        Modulus &operator=(const Modulus &assign) = default;

        /**
        Moves a given Modulus to the current one.

        @param[in] assign The Modulus to move from
        */
        Modulus &operator=(Modulus &&assign) = default;

        /**
        Sets the value of the Modulus.

        @param[in] value The new integer modulus
        @throws std::invalid_argument if value is 1 or more than 61 bits
        */
        inline Modulus &operator=(std::uint64_t value)
        {
            setValue(value);
            return *this;
        }

        /**
        Returns the significant bit count of the value of the current Modulus.
        */
        inline int bitCount() const noexcept
        {
            return bit_count_;
        }

        /**
        Returns the size (in 64-bit words) of the value of the current Modulus.
        */
        inline std::size_t uint64Count() const noexcept
        {
            return uint64_count_;
        }

        /**
        Returns a const pointer to the value of the current Modulus.
        */
        inline const uint64_t *data() const noexcept
        {
            return &value_;
        }

        /**
        Returns the value of the current Modulus.
        */
        inline std::uint64_t value() const noexcept
        {
            return value_;
        }

        /**
        Returns the Barrett ratio computed for the value of the current Modulus.
        The first two components of the Barrett ratio are the floor of 2^128/value,
        and the third component is the remainder.
        */
        inline auto &constRatio() const noexcept
        {
            return const_ratio_;
        }

        inline const uint64_t* constRatioData() const noexcept {
            return &const_ratio_[0];
        }

        /**
        Returns whether the value of the current Modulus is zero.
        */
        inline bool isZero() const noexcept
        {
            return value_ == 0;
        }

        /**
        Returns whether the value of the current Modulus is a prime number.
        */
        inline bool isPrime() const noexcept
        {
            return is_prime_;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator==(const Modulus &compare) const noexcept
        {
            return value_ == compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator==(std::uint64_t compare) const noexcept
        {
            return value_ == compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator!=(const Modulus &compare) const noexcept
        {
            return !operator==(compare);
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator!=(std::uint64_t compare) const noexcept
        {
            return !operator==(compare);
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator<(const Modulus &compare) const noexcept
        {
            return value_ < compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator<(std::uint64_t compare) const noexcept
        {
            return value_ < compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator<=(const Modulus &compare) const noexcept
        {
            return value_ <= compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator<=(std::uint64_t compare) const noexcept
        {
            return value_ <= compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator>(const Modulus &compare) const noexcept
        {
            return value_ > compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator>(std::uint64_t compare) const noexcept
        {
            return value_ > compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator>=(const Modulus &compare) const noexcept
        {
            return value_ >= compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator>=(std::uint64_t compare) const noexcept
        {
            return value_ >= compare;
        }

        // /**
        // Returns an upper bound on the size of the Modulus, as if it was
        // written to an output stream.

        // @param[in] compr_mode The compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the size does not fit in the return type
        // */
        // inline std::streamoff save_size(
        //     compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     std::size_t members_size = Serialization::ComprSizeEstimate(util::add_safe(sizeof(value_)), compr_mode);

        //     return util::safe_cast<std::streamoff>(util::add_safe(sizeof(Serialization::SEALHeader), members_size));
        // }

        // /**
        // Saves the Modulus to an output stream. The output is in binary format
        // and not human-readable. The output stream must have the "binary" flag set.

        // @param[out] stream The stream to save the Modulus to
        // @param[in] compr_mode The desired compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the data to be saved is invalid, or if
        // compression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff save(
        //     std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Save(
        //         std::bind(&Modulus::save_members, this, _1), save_size(compr_mode_type::none), stream, compr_mode,
        //         false);
        // }

        // /**
        // Loads a Modulus from an input stream overwriting the current Modulus.

        // @param[in] stream The stream to load the Modulus from
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(std::istream &stream)
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Load(std::bind(&Modulus::load_members, this, _1, _2), stream, false);
        // }

        // /**
        // Saves the Modulus to a given memory location. The output is in binary
        // format and not human-readable.

        // @param[out] out The memory location to write the Modulus to
        // @param[in] size The number of bytes available in the given memory location
        // @param[in] compr_mode The desired compression mode
        // @throws std::invalid_argument if out is null or if size is too small to
        // contain a SEALHeader, or if the compression mode is not supported
        // @throws std::logic_error if the data to be saved is invalid, or if
        // compression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff save(
        //     seal_byte *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Save(
        //         std::bind(&Modulus::save_members, this, _1), save_size(compr_mode_type::none), out, size, compr_mode,
        //         false);
        // }

        // /**
        // Loads a Modulus from a given memory location overwriting the current
        // Modulus.

        // @param[in] in The memory location to load the Modulus from
        // @param[in] size The number of bytes available in the given memory location
        // @throws std::invalid_argument if in is null or if size is too small to
        // contain a SEALHeader
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(const seal_byte *in, std::size_t size)
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Load(std::bind(&Modulus::load_members, this, _1, _2), in, size, false);
        // }

        /**
        Reduces a given unsigned integer modulo this modulus.

        @param[in] value The unsigned integer to reduce
        @throws std::logic_error if the Modulus is zero
        */
        std::uint64_t reduce(std::uint64_t value) const;


    };




    /**
    Represents a standard security level according to the HomomorphicEncryption.org
    security standard. The value SecurityLevel::none signals that no standard
    security level should be imposed. The value SecurityLevel::tc128 provides
    a very high level of security and is the default security level enforced by
    Microsoft SEAL when constructing a SEALContext object. Normal users should not
    have to specify the security level explicitly anywhere.
    */
    enum class SecurityLevel : int
    {
        /**
        No security level specified.
        */
        none = 0,

        /**
        128-bit security level according to HomomorphicEncryption.org standard.
        */
        tc128 = 128,

        /**
        192-bit security level according to HomomorphicEncryption.org standard.
        */
        tc192 = 192,

        /**
        256-bit security level according to HomomorphicEncryption.org standard.
        */
        tc256 = 256
    };

    /**
    This class contains static methods for creating a coefficient modulus easily.
    Note that while these functions take a SecurityLevel argument, all security
    guarantees are lost if the output is used with encryption parameters with
    a mismatching value for the poly_modulus_degree.

    The default value SecurityLevel::tc128 provides a very high level of security
    and is the default security level enforced by Microsoft SEAL when constructing
    a SEALContext object. Normal users should not have to specify the security
    level explicitly anywhere.
    */
    class CoeffModulus
    {
    public:
        CoeffModulus() = delete;

        /**
        Returns the largest bit-length of the coefficient modulus, i.e., bit-length
        of the product of the primes in the coefficient modulus, that guarantees
        a given security level when using a given poly_modulus_degree, according
        to the HomomorphicEncryption.org security standard.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] sec_level The desired standard security level
        */
        static constexpr int MaxBitCount(
            std::size_t poly_modulus_degree, SecurityLevel sec_level = SecurityLevel::tc128) noexcept
        {
            switch (sec_level)
            {
            case SecurityLevel::tc128:
                return util::seal_he_std_parms_128_tc(poly_modulus_degree);

            case SecurityLevel::tc192:
                return util::seal_he_std_parms_192_tc(poly_modulus_degree);

            case SecurityLevel::tc256:
                return util::seal_he_std_parms_256_tc(poly_modulus_degree);

            case SecurityLevel::none:
                return (std::numeric_limits<int>::max)();

            default:
                return 0;
            }
        }

        /**
        Returns a default coefficient modulus for the BFV scheme that guarantees
        a given security level when using a given poly_modulus_degree, according
        to the HomomorphicEncryption.org security standard. Note that all security
        guarantees are lost if the output is used with encryption parameters with
        a mismatching value for the poly_modulus_degree.

        The coefficient modulus returned by this function will not perform well
        if used with the CKKS scheme.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] sec_level The desired standard security level
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if sec_level is SecurityLevel::none
        */
        static std::vector<Modulus> BFVDefault(
            std::size_t poly_modulus_degree, SecurityLevel sec_level = SecurityLevel::tc128);

        /**
        Returns a custom coefficient modulus suitable for use with the specified
        poly_modulus_degree. The return value will be a vector consisting of
        Modulus elements representing distinct prime numbers such that:
        1) have bit-lengths as given in the bit_sizes parameter (at most 60 bits) and
        2) are congruent to 1 modulo 2*poly_modulus_degree.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] bit_sizes The bit-lengths of the primes to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_sizes is too large or if its elements
        are out of bounds
        @throws std::logic_error if not enough suitable primes could be found
        */
        static std::vector<Modulus> Create(std::size_t poly_modulus_degree, std::vector<int> bit_sizes);

        /**
        Returns a custom coefficient modulus suitable for use with the specified
        poly_modulus_degree. The return value will be a vector consisting of
        Modulus elements representing distinct prime numbers such that:
        1) have bit-lengths as given in the bit_sizes parameter (at most 60 bits) and
        2) are congruent to 1 modulo LCM(2*poly_modulus_degree, plain_modulus).

        @param[in] poly_modulus_degree The value of the poly_modulus_degree encryption parameter
        @param[in] plain_modulus The value of the plain_modulus encryption parameter
        @param[in] bit_sizes The bit-lengths of the primes to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_sizes is too large or if its elements
        are out of bounds
        @throws std::logic_error if LCM(2*poly_modulus_degree, plain_modulus) is more than 64-bit
        @throws std::logic_error if not enough suitable primes could be found
        */
        static std::vector<Modulus> Create(
            std::size_t poly_modulus_degree, const Modulus &plain_modulus, std::vector<int> bit_sizes);
    };

    /**
    This class contains static methods for creating a plaintext modulus easily.
    */
    class PlainModulus
    {
    public:
        PlainModulus() = delete;

        /**
        Creates a prime number Modulus for use as plain_modulus encryption
        parameter that supports batching with a given poly_modulus_degree.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] bit_size The bit-length of the prime to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_size is out of bounds
        @throws std::logic_error if a suitable prime could not be found
        */
        static inline Modulus Batching(std::size_t poly_modulus_degree, int bit_size)
        {
            return CoeffModulus::Create(poly_modulus_degree, { bit_size })[0];
        }

        /**
        Creates several prime number Modulus elements that can be used as
        plain_modulus encryption parameters, each supporting batching with a given
        poly_modulus_degree.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] bit_sizes The bit-lengths of the primes to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_sizes is too large or if its elements
        are out of bounds
        @throws std::logic_error if not enough suitable primes could be found
        */
        static inline std::vector<Modulus> Batching(
            std::size_t poly_modulus_degree, std::vector<int> bit_sizes)
        {
            return CoeffModulus::Create(poly_modulus_degree, bit_sizes);
        }
    };

}