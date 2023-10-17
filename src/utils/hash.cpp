#include "hash.h"

namespace troy {
    namespace util {
        
        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr size_t HashFunction::hash_block_uint64_count;

        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr size_t HashFunction::hash_block_byte_count;

        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr HashFunction::HashBlock HashFunction::hash_zero_block;
    }
}