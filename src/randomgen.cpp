// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "randomgen.h"
#include "utils/blake2.h"
#include "utils/common.h"
#include "utils/fips202.h"
#include <algorithm>
#include <iostream>
#include <random>

using std::size_t;
using std::random_device;
using std::shared_ptr;
using std::make_shared;


namespace troy
{
    void random_bytes(std::byte *buf, size_t count)
    {
#if SEAL_SYSTEM == SEAL_SYSTEM_UNIX_LIKE
        random_device rd("/dev/urandom");
        while (count >= 4)
        {
            *reinterpret_cast<uint32_t *>(buf) = rd();
            buf += 4;
            count -= 4;
        }
        if (count)
        {
            uint32_t last = rd();
            memcpy(buf, &last, count);
        }
#elif SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS
        NTSTATUS status = BCryptGenRandom(
            NULL, reinterpret_cast<unsigned char *>(buf), safe_cast<ULONG>(count), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (BCRYPT_SUCCESS(status))
        {
            return;
        }

        last_bcrypt_error = status;

        HMODULE hAdvApi = LoadLibraryA("ADVAPI32.DLL");
        if (!hAdvApi)
        {
            last_genrandom_error = GetLastError();
            throw runtime_error("Failed to load ADVAPI32.DLL");
        }

        BOOLEAN(APIENTRY * RtlGenRandom)
        (void *, ULONG) = (BOOLEAN(APIENTRY *)(void *, ULONG))GetProcAddress(hAdvApi, RTL_GENRANDOM);

        BOOLEAN genrand_result = FALSE;
        if (RtlGenRandom)
        {
            genrand_result = RtlGenRandom(buf, bytes_per_uint64);
        }

        DWORD dwError = GetLastError();
        FreeLibrary(hAdvApi);

        if (!genrand_result)
        {
            last_genrandom_error = dwError;
            throw runtime_error("Failed to call RtlGenRandom");
        }
#elif SEAL_SYSTEM == SEAL_SYSTEM_OTHER
#warning "SECURITY WARNING: System detection failed; falling back to a potentially insecure randomness source!"
        random_device rd;
        while (count >= 4)
        {
            *reinterpret_cast<uint32_t *>(buf) = rd();
            buf += 4;
            count -= 4;
        }
        if (count)
        {
            uint32_t last = rd();
            memcpy(buf, &last, count);
        }
#endif
    }

    // void UniformRandomGeneratorInfo::save_members(ostream &stream) const
    // {
    //     // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
    //     auto old_except_mask = stream.exceptions();
    //     try
    //     {
    //         stream.exceptions(ios_base::badbit | ios_base::failbit);

    //         stream.write(reinterpret_cast<const char *>(&type_), sizeof(PRNGType));
    //         stream.write(reinterpret_cast<const char *>(seed_.data()), prng_seed_byte_count);
    //     }
    //     catch (const ios_base::failure &)
    //     {
    //         stream.exceptions(old_except_mask);
    //         throw runtime_error("I/O error");
    //     }
    //     catch (...)
    //     {
    //         stream.exceptions(old_except_mask);
    //         throw;
    //     }
    //     stream.exceptions(old_except_mask);
    // }

    // void UniformRandomGeneratorInfo::load_members(istream &stream, SEAL_MAYBE_UNUSED SEALVersion version)
    // {
    //     // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
    //     auto old_except_mask = stream.exceptions();
    //     try
    //     {
    //         stream.exceptions(ios_base::badbit | ios_base::failbit);

    //         UniformRandomGeneratorInfo info;

    //         // Read the PRNG type
    //         stream.read(reinterpret_cast<char *>(&info.type_), sizeof(PRNGType));
    //         if (!info.has_valid_PRNGType())
    //         {
    //             throw logic_error("PRNGType is invalid");
    //         }

    //         // Read the seed data
    //         stream.read(reinterpret_cast<char *>(info.seed_.data()), prng_seed_byte_count);

    //         swap(*this, info);

    //         stream.exceptions(old_except_mask);
    //     }
    //     catch (const ios_base::failure &)
    //     {
    //         stream.exceptions(old_except_mask);
    //         throw runtime_error("I/O error");
    //     }
    //     catch (...)
    //     {
    //         stream.exceptions(old_except_mask);
    //         throw;
    //     }
    //     stream.exceptions(old_except_mask);
    // }

    shared_ptr<UniformRandomGenerator> UniformRandomGeneratorInfo::make_prng() const
    {
        switch (type_)
        {
        case PRNGType::blake2xb:
            return make_shared<Blake2xbPRNG>(seed_);

        case PRNGType::shake256:
            return make_shared<Shake256PRNG>(seed_);

        case PRNGType::unknown:
            return nullptr;
        }
        return nullptr;
    }

    void UniformRandomGenerator::generate(size_t byte_count, std::byte *destination)
    {
        while (byte_count)
        {
            size_t current_bytes = std::min(byte_count, buffer_size_ - buffer_current_);
            copy_n(buffer_.get() + buffer_current_, current_bytes, destination);
            buffer_current_ += current_bytes;
            destination += current_bytes;
            byte_count -= current_bytes;

            if (buffer_current_ == buffer_size_)
            {
                refill_buffer();
                buffer_current_ = 0;
            }
        }
    }

    auto UniformRandomGeneratorFactory::DefaultFactory() -> shared_ptr<UniformRandomGeneratorFactory>
    {
        static shared_ptr<UniformRandomGeneratorFactory> default_factory{ new Blake2xbPRNGFactory() };
        return default_factory;
    }

    void Blake2xbPRNG::refill_buffer()
    {
        // Fill the randomness buffer
        if (blake2xb(
                buffer_.get(), buffer_size_, &counter_, sizeof(counter_), seed_.get(),
                seed_.length() * sizeof(uint64_t)) != 0)
        {
            throw std::runtime_error("blake2xb failed");
        }
        counter_++;
    }

    void Shake256PRNG::refill_buffer()
    {
        // Fill the randomness buffer
        std::array<uint64_t, prng_seed_uint64_count + 1> seed_ext;
        std::copy_n(seed_.get(), prng_seed_uint64_count, seed_ext.begin());
        seed_ext[prng_seed_uint64_count] = counter_;
        shake256(
            reinterpret_cast<uint8_t *>(buffer_.get()), buffer_size_,
            reinterpret_cast<const uint8_t *>(seed_ext.data()), seed_ext.size() * util::bytesPerUint64);
        explicit_bzero(seed_ext.data(), seed_ext.size() * util::bytesPerUint64);
        counter_++;
    }
} // namespace seal
