#pragma once

#include <cstdint>
#include <array>

#include "common.h"
#include "blake2.h"

namespace troy {
    namespace util {

        class HashFunction
        {
        public:
            HashFunction() = delete;

            static constexpr std::size_t hash_block_uint64_count = 4;

            static constexpr std::size_t hash_block_byte_count = hash_block_uint64_count * bytesPerUint64;

            using HashBlock = std::array<std::uint64_t, hash_block_uint64_count>;

            static constexpr HashBlock hash_zero_block{ { 0, 0, 0, 0 } };

            inline static void hash(const std::uint64_t *input, std::size_t uint64_count, HashBlock &destination)
            {
                if (blake2b(&destination, hash_block_byte_count, input, uint64_count * bytesPerUint64, nullptr, 0) !=
                    0)
                {
                    throw std::runtime_error("blake2b failed");
                }
            }
        };

    }
}