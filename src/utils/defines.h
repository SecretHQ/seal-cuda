
#pragma once

#include <x86intrin.h>

#define SEAL_MOD_BIT_COUNT_MAX 61

#define SEAL_FORCE_INLINE inline __attribute__((always_inline))

#define SEAL_MAYBE_UNUSED [[maybe_unused]]

#define SEAL_SUB_BORROW_UINT64(operand1, operand2, borrow, result) _subborrow_u64(borrow, operand1, operand2, result)

// Bit-length of internally used coefficient moduli, e.g., auxiliary base in BFV
#define SEAL_INTERNAL_MOD_BIT_COUNT 61


// Bounds for bit-length of user-defined coefficient moduli
#define SEAL_USER_MOD_BIT_COUNT_MAX 60
#define SEAL_USER_MOD_BIT_COUNT_MIN 2

// Bounds for bit-length of the plaintext modulus
#define SEAL_PLAIN_MOD_BIT_COUNT_MAX SEAL_USER_MOD_BIT_COUNT_MAX
#define SEAL_PLAIN_MOD_BIT_COUNT_MIN SEAL_USER_MOD_BIT_COUNT_MIN

// Bounds for number of coefficient moduli (no hard requirement)
#define SEAL_COEFF_MOD_COUNT_MAX 64
#define SEAL_COEFF_MOD_COUNT_MIN 1

// Bounds for polynomial modulus degree (no hard requirement)
#define SEAL_POLY_MOD_DEGREE_MAX 131072
#define SEAL_POLY_MOD_DEGREE_MIN 2

#define SEAL_CIPHERTEXT_SIZE_MAX 16
#if SEAL_CIPHERTEXT_SIZE_MAX > 0x100000000ULL / SEAL_POLY_MOD_DEGREE_MAX
#error "SEAL_CIPHERTEXT_SIZE_MAX is too large"
#endif
#define SEAL_CIPHERTEXT_SIZE_MIN 2

#if SEAL_MOD_BIT_COUNT_MAX > 32
#define SEAL_MULTIPLY_ACCUMULATE_MOD_MAX (1 << (128 - (SEAL_MOD_BIT_COUNT_MAX << 1)))
#define SEAL_MULTIPLY_ACCUMULATE_INTERNAL_MOD_MAX (1 << (128 - (SEAL_INTERNAL_MOD_BIT_COUNT_MAX << 1)))
#define SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX (1 << (128 - (SEAL_USER_MOD_BIT_COUNT_MAX << 1)))
#else
#define SEAL_MULTIPLY_ACCUMULATE_MOD_MAX SIZE_MAX
#define SEAL_MULTIPLY_ACCUMULATE_INTERNAL_MOD_MAX SIZE_MAX
#define SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX SIZE_MAX
#endif