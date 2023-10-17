#pragma once

#include <cstdint>
#include <array>
#include <algorithm>
#include <memory>
#include <string.h>

#include "utils/hostarray.h"

#include "utils/common.h"

namespace troy {
    
    constexpr std::size_t prng_seed_uint64_count = 8;

    constexpr std::size_t prng_seed_byte_count = prng_seed_uint64_count * util::bytesPerUint64;

    using PRNGSeed = std::array<std::uint64_t, prng_seed_uint64_count>;

    /**
    A type indicating a specific pseud-random number generator.
    */
    enum class PRNGType : std::uint8_t
    {
        unknown = 0,

        blake2xb = 1,

        shake256 = 2
    };

    /**
    Fills a buffer with random bytes.
    */
    void random_bytes(std::byte *buf, std::size_t count);

    /**
    Returns a random 64-bit unsigned integer.
    */
    inline std::uint64_t random_uint64()
    {
        std::uint64_t result;
        random_bytes(reinterpret_cast<std::byte *>(&result), sizeof(result));
        return result;
    }

    class UniformRandomGenerator;

    class UniformRandomGeneratorInfo
    {
        friend class UniformRandomGenerator;

    public:
        /**
        Creates a new UniformRandomGeneratorInfo.
        */
        UniformRandomGeneratorInfo() = default;

        /**
        Creates a new UniformRandomGeneratorInfo.

        @param[in] type The PRNG type
        @param[in] seed The PRNG seed
        */
        UniformRandomGeneratorInfo(PRNGType type, PRNGSeed seed) : type_(type), seed_(std::move(seed))
        {}

        /**
        Creates a new UniformRandomGeneratorInfo by copying a given one.

        @param[in] copy The UniformRandomGeneratorInfo to copy from
        */
        UniformRandomGeneratorInfo(const UniformRandomGeneratorInfo &copy) = default;

        /**
        Copies a given UniformRandomGeneratorInfo to the current one.

        @param[in] assign The UniformRandomGeneratorInfo to copy from
        */
        UniformRandomGeneratorInfo &operator=(const UniformRandomGeneratorInfo &assign) = default;

        /**
        Compares two UniformRandomGeneratorInfo instances.

        @param[in] compare The UniformRandomGeneratorInfo to compare against
        */
        inline bool operator==(const UniformRandomGeneratorInfo &compare) const noexcept
        {
            return (seed_ == compare.seed_) && (type_ == compare.type_);
        }

        /**
        Compares two UniformRandomGeneratorInfo instances.

        @param[in] compare The UniformRandomGeneratorInfo to compare against
        */
        inline bool operator!=(const UniformRandomGeneratorInfo &compare) const noexcept
        {
            return !operator==(compare);
        }

        /**
        Clears all data in the UniformRandomGeneratorInfo.
        */
        void clear() noexcept
        {
            type_ = PRNGType::unknown;
            // util::seal_memzero(seed_.data(), prng_seed_byte_count);
            explicit_bzero(seed_.data(), prng_seed_byte_count);
        }

        /**
        Destroys the UniformRandomGeneratorInfo.
        */
        ~UniformRandomGeneratorInfo()
        {
            clear();
        }

        /**
        Creates a new UniformRandomGenerator object of type indicated by the PRNG
        type and seeded with the current seed. If the current PRNG type is not
        an official Microsoft SEAL PRNG type, the return value is nullptr.
        */
        std::shared_ptr<UniformRandomGenerator> make_prng() const;

        /**
        Returns whether this object holds a valid PRNG type.
        */
        inline bool has_valid_PRNGType() const noexcept
        {
            switch (type_)
            {
            case PRNGType::blake2xb:
                /* fall through */

            case PRNGType::shake256:
                /* fall through */

            case PRNGType::unknown:
                return true;
            }
            return false;
        }

        /**
        Returns the PRNG type.
        */
        inline PRNGType type() const noexcept
        {
            return type_;
        }

        /**
        Returns a reference to the PRNG type.
        */
        inline PRNGType &type() noexcept
        {
            return type_;
        }

        /**
        Returns a reference to the PRNG seed.
        */
        inline const PRNGSeed &seed() const noexcept
        {
            return seed_;
        }

        /**
        Returns a reference to the PRNG seed.
        */
        inline PRNGSeed &seed() noexcept
        {
            return seed_;
        }

        /**
        Returns an upper bound on the size of the UniformRandomGeneratorInfo, as
        if it was written to an output stream.

        // @param[in] compr_mode The compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the size does not fit in the return type
        // */
        // static inline std::streamoff SaveSize(
        //     compr_mode_type compr_mode = Serialization::compr_mode_default)
        // {
        //     std::size_t members_size =
        //         Serialization::ComprSizeEstimate(sizeof(PRNGType) + prng_seed_byte_count, compr_mode);
        //     return static_cast<std::streamoff>(sizeof(Serialization::SEALHeader) + members_size);
        // }

        // /**
        // Returns an upper bound on the size of the UniformRandomGeneratorInfo, as
        // if it was written to an output stream.

        // @param[in] compr_mode The compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the size does not fit in the return type
        // */
        // inline std::streamoff save_size(
        //     compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     return UniformRandomGeneratorInfo::SaveSize(compr_mode);
        // }

        /**
        Saves the UniformRandomGeneratorInfo to an output stream. The output is
        in binary format and is not human-readable. The output stream must have
        the "binary" flag set.

        // @param[out] stream The stream to save the UniformRandomGeneratorInfo to
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
        //         std::bind(&UniformRandomGeneratorInfo::save_members, this, _1), save_size(compr_mode_type::none),
        //         stream, compr_mode, true);
        // }

        // /**
        // Loads a UniformRandomGeneratorInfo from an input stream overwriting the
        // current UniformRandomGeneratorInfo.

        // @param[in] stream The stream to load the UniformRandomGeneratorInfo from
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(std::istream &stream)
        // {
        //     using namespace std::placeholders;
        //     UniformRandomGeneratorInfo new_info;
        //     auto in_size = Serialization::Load(
        //         std::bind(&UniformRandomGeneratorInfo::load_members, &new_info, _1, _2), stream, true);
        //     std::swap(*this, new_info);
        //     return in_size;
        // }

        // /**
        // Saves the UniformRandomGeneratorInfo to a given memory location. The output
        // is in binary format and is not human-readable.

        // @param[out] out The memory location to write the UniformRandomGeneratorInfo to
        // @param[in] size The number of bytes available in the given memory location
        // @param[in] compr_mode The desired compression mode
        // @throws std::invalid_argument if out is null or if size is too small to
        // contain a SEALHeader, or if the compression mode is not supported
        // @throws std::logic_error if the data to be saved is invalid, or if
        // compression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff save(
        //     std::byte *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Save(
        //         std::bind(&UniformRandomGeneratorInfo::save_members, this, _1), save_size(compr_mode_type::none), out,
        //         size, compr_mode, true);
        // }

        // /**
        // Loads a UniformRandomGeneratorInfo from a given memory location overwriting
        // the current UniformRandomGeneratorInfo.

        // @param[in] in The memory location to load the UniformRandomGeneratorInfo from
        // @param[in] size The number of bytes available in the given memory location
        // @throws std::invalid_argument if in is null or if size is too small to
        // contain a SEALHeader
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(const std::byte *in, std::size_t size)
        // {
        //     using namespace std::placeholders;
        //     UniformRandomGeneratorInfo new_info;
        //     auto in_size = Serialization::Load(
        //         std::bind(&UniformRandomGeneratorInfo::load_members, &new_info, _1, _2), in, size, true);
        //     std::swap(*this, new_info);
        //     return in_size;
        // }

    public:
        // void save_members(std::ostream &stream) const;

        // void load_members(std::istream &stream, SEALVersion version);

        PRNGType type_ = PRNGType::unknown;

        PRNGSeed seed_ = {};
    };

    /**
    Provides the base class for a seeded uniform random number generator. Instances
    of this class are meant to be created by an instance of the factory class
    UniformRandomGeneratorFactory. This class is meant for users to sub-class to
    implement their own random number generators.
    */
    class UniformRandomGenerator
    {
    public:
        /**
        Creates a new UniformRandomGenerator instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        UniformRandomGenerator(PRNGSeed seed)
            : seed_(util::HostArray<uint64_t>(seed.cbegin(), prng_seed_uint64_count)),
              buffer_(util::HostArray<std::byte>(4096)), buffer_current_(4096)
        {}

        inline PRNGSeed seed() const noexcept
        {
            PRNGSeed ret{};
            std::copy_n(seed_.get(), prng_seed_uint64_count, ret.begin());
            return ret;
        }

        /**
        Fills a given buffer with a given number of bytes of randomness.
        */
        void generate(std::size_t byte_count, std::byte *destination);

        /**
        Generates a new unsigned 32-bit random number.
        */
        inline std::uint32_t generate()
        {
            std::uint32_t result;
            generate(sizeof(result), reinterpret_cast<std::byte *>(&result));
            return result;
        }

        /**
        Discards the contents of the current randomness buffer and refills it
        with fresh randomness.
        */
        inline void refresh()
        {
            refill_buffer();
        }

        /**
        Returns a UniformRandomGeneratorInfo object representing this PRNG.
        */
        inline UniformRandomGeneratorInfo info() const noexcept
        {
            UniformRandomGeneratorInfo result;
            std::copy_n(seed_.get(), prng_seed_uint64_count, result.seed_.begin());
            result.type_ = type();
            return result;
        }

        /**
        Destroys the random number generator.
        */
        virtual ~UniformRandomGenerator() = default;

    protected:
        virtual PRNGType type() const noexcept = 0;

        virtual void refill_buffer() = 0;

        const util::HostArray<uint64_t> seed_;

        const std::size_t buffer_size_ = 4096;

    protected:
        util::HostArray<std::byte> buffer_;

        std::size_t buffer_current_;

    };

    /**
    Provides the base class for a factory instance that creates instances of
    UniformRandomGenerator. This class is meant for users to sub-class to implement
    their own random number generators.
    */
    class UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new UniformRandomGeneratorFactory. The seed will be sampled
        randomly for each UniformRandomGenerator instance created by the factory
        instance, which is desirable in most normal use-cases.
        */
        UniformRandomGeneratorFactory() : use_random_seed_(true)
        {}

        /**
        Creates a new UniformRandomGeneratorFactory and sets the default seed to
        the given value. For debugging purposes it may sometimes be convenient to
        have the same randomness be used deterministically and repeatedly. Such
        randomness sampling is naturally insecure and must be strictly restricted
        to debugging situations. Thus, most users should never have a reason to
        use this constructor.

        @param[in] default_seed The default value for a seed to be used by all
        created instances of UniformRandomGenerator
        */
        UniformRandomGeneratorFactory(PRNGSeed default_seed)
            : default_seed_(default_seed), use_random_seed_(false)
        {}

        /**
        Creates a new uniform random number generator.
        */
        auto create() -> std::shared_ptr<UniformRandomGenerator>
        {
            return use_random_seed_ ? create_impl([]() {
                PRNGSeed seed;
                random_bytes(reinterpret_cast<std::byte *>(seed.data()), prng_seed_byte_count);
                return seed;
            }())
                                    : create_impl(default_seed_);
        }

        /**
        Creates a new uniform random number generator seeded with the given seed,
        overriding the default seed for this factory instance.

        @param[in] seed The seed to be used for the created random number generator
        */
        auto create(PRNGSeed seed) -> std::shared_ptr<UniformRandomGenerator>
        {
            return create_impl(seed);
        }

        /**
        Destroys the random number generator factory.
        */
        virtual ~UniformRandomGeneratorFactory() = default;

        /**
        Returns the default random number generator factory. This instance should
        not be destroyed.
        */
        static auto DefaultFactory() -> std::shared_ptr<UniformRandomGeneratorFactory>;

        /**
        Returns whether the random number generator factory creates random number
        generators seeded with a random seed, or if a default seed is used.
        */
        inline bool use_random_seed() noexcept
        {
            return use_random_seed_;
        }

        /**
        Returns the default seed used to seed every random number generator created
        by this random number generator factory. If use_random_seed() is false, then
        the returned seed has no meaning.
        */
        inline PRNGSeed default_seed() noexcept
        {
            return default_seed_;
        }

    protected:
        virtual auto create_impl(PRNGSeed seed) -> std::shared_ptr<UniformRandomGenerator> = 0;

    private:
        PRNGSeed default_seed_ = {};

        bool use_random_seed_ = false;
    };

    /**
    Provides an implementation of UniformRandomGenerator for using Blake2xb for
    generating randomness with given 128-bit seed.
    */
    class Blake2xbPRNG : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new Blake2xbPRNG instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        Blake2xbPRNG(PRNGSeed seed) : UniformRandomGenerator(seed)
        {}

        /**
        Destroys the random number generator.
        */
        ~Blake2xbPRNG() = default;

    protected:
        PRNGType type() const noexcept override
        {
            return PRNGType::blake2xb;
        }

        void refill_buffer() override;

    private:
        std::uint64_t counter_ = 0;
    };

    class Blake2xbPRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new Blake2xbPRNGFactory. The seed will be sampled randomly
        for each Blake2xbPRNG instance created by the factory instance, which is
        desirable in most normal use-cases.
        */
        Blake2xbPRNGFactory() : UniformRandomGeneratorFactory()
        {}

        /**
        Creates a new Blake2xbPRNGFactory and sets the default seed to the given
        value. For debugging purposes it may sometimes be convenient to have the
        same randomness be used deterministically and repeatedly. Such randomness
        sampling is naturally insecure and must be strictly restricted to debugging
        situations. Thus, most users should never use this constructor.

        @param[in] default_seed The default value for a seed to be used by all
        created instances of Blake2xbPRNG
        */
        Blake2xbPRNGFactory(PRNGSeed default_seed) : UniformRandomGeneratorFactory(default_seed)
        {}

        /**
        Destroys the random number generator factory.
        */
        ~Blake2xbPRNGFactory() = default;

    protected:
        auto create_impl(PRNGSeed seed) -> std::shared_ptr<UniformRandomGenerator> override
        {
            return std::make_shared<Blake2xbPRNG>(seed);
        }

    private:
    };

    /**
    Provides an implementation of UniformRandomGenerator for using SHAKE-256 for
    generating randomness with given 128-bit seed.
    */
    class Shake256PRNG : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new Shake256PRNG instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        Shake256PRNG(PRNGSeed seed) : UniformRandomGenerator(seed)
        {}

        /**
        Destroys the random number generator.
        */
        ~Shake256PRNG() = default;

    protected:
        PRNGType type() const noexcept override
        {
            return PRNGType::shake256;
        }

        void refill_buffer() override;

    private:
        std::uint64_t counter_ = 0;
    };

    class Shake256PRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new Shake256PRNGFactory. The seed will be sampled randomly for
        each Shake256PRNG instance created by the factory instance, which is
        desirable in most normal use-cases.
        */
        Shake256PRNGFactory() : UniformRandomGeneratorFactory()
        {}

        /**
        Creates a new Shake256PRNGFactory and sets the default seed to the given
        value. For debugging purposes it may sometimes be convenient to have the
        same randomness be used deterministically and repeatedly. Such randomness
        sampling is naturally insecure and must be strictly restricted to debugging
        situations. Thus, most users should never use this constructor.

        @param[in] default_seed The default value for a seed to be used by all
        created instances of Shake256PRNG
        */
        Shake256PRNGFactory(PRNGSeed default_seed) : UniformRandomGeneratorFactory(default_seed)
        {}

        /**
        Destroys the random number generator factory.
        */
        ~Shake256PRNGFactory() = default;

    protected:
        auto create_impl(PRNGSeed seed) -> std::shared_ptr<UniformRandomGenerator> override
        {
            return std::make_shared<Shake256PRNG>(seed);
        }

    private:
    };
}