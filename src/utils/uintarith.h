#pragma once

#include <cstdint>
#include <cassert>

#include "defines.h"
#include "common.h"
#include "uintcore.h"

namespace troy { namespace util {

    inline unsigned char addUint64(uint64_t operand1, uint64_t operand2, unsigned char carry, uint64_t *result) {
        operand1 += operand2;
        *result = operand1 + carry;
        return (operand1 < operand2) || (~operand1 < carry);
    }

    inline unsigned char addUint64(uint64_t operand1, uint64_t operand2, uint64_t* result) {
        *result = operand1 + operand2;
        return static_cast<unsigned char>(*result < operand1);
    }

    inline unsigned char addUint128(uint64_t* operand1, uint64_t* operand2, uint64_t* result) {
        unsigned char carry = addUint64(operand1[0], operand2[0], result);
        return addUint64(operand1[1], operand2[1], carry, result + 1);
    }

    inline unsigned char addUint(const uint64_t* operand1, std::size_t operand1Uint64Count,
        const uint64_t* operand2, std::size_t operand2Uint64Count,
        unsigned char carry, std::size_t resultUint64Count, uint64_t* result)
    {
        for (std::size_t i = 0; i < resultUint64Count; i++) {
            uint64_t temp_result;
            carry = addUint64(
                (i < operand1Uint64Count) ? *operand1++ : 0, (i < operand2Uint64Count) ? *operand2++ : 0, carry,
                &temp_result);
            *result++ = temp_result;
        }
        return carry;
    }

    inline unsigned char addUint(const uint64_t* operand1, const uint64_t* operand2, std::size_t uint64Count, uint64_t* result) {
        // Unroll first iteration of loop. We assume uint64_count > 0.
        unsigned char carry = addUint64(*operand1++, *operand2++, result++);

        // Do the rest
        for (; --uint64Count; operand1++, operand2++, result++) {
            uint64_t temp_result;
            carry = addUint64(*operand1, *operand2, carry, &temp_result);
            *result = temp_result;
        }
        return carry;
    }

    inline unsigned char addUint(
        const uint64_t* operand1, std::size_t uint64Count,
        uint64_t operand2, uint64_t* result
    ) {
            // Unroll first iteration of loop. We assume uint64_count > 0.
            unsigned char carry = addUint64(*operand1++, operand2, result++);

            // Do the rest
            for (; --uint64Count; operand1++, result++)
            {
                uint64_t temp_result;
                carry = addUint64(*operand1, uint64_t(0), carry, &temp_result);
                *result = temp_result;
            }
            return carry;
    }

    inline unsigned char subUint64(uint64_t operand1, uint64_t operand2, unsigned char borrow, uint64_t* result) {
        auto diff = operand1 - operand2;
        *result = diff - (borrow != 0);
        return (diff > operand1) || (diff < borrow);
    }

    inline unsigned char subUint64(uint64_t operand1, uint64_t operand2, uint64_t* result) {
        *result = operand1 - operand2;
        return static_cast<unsigned char>(operand2 > operand1);
    }

    inline unsigned char subUint(const uint64_t* operand1, std::size_t operand1Uint64Count,
        const uint64_t* operand2, std::size_t operand2Uint64Count,
        unsigned char borrow, std::size_t resultUint64Count, uint64_t* result)
    {
        for (std::size_t i = 0; i < resultUint64Count; i++, operand1++, operand2++, result++)
        {
            uint64_t temp_result;
            borrow = subUint64(
                (i < operand1Uint64Count) ? *operand1 : 0, (i < operand2Uint64Count) ? *operand2 : 0, borrow,
                &temp_result);
            *result = temp_result;
        }
        return borrow;
    }

    inline unsigned char subUint(
        const uint64_t* operand1, const uint64_t* operand2,
        std::size_t uint64Count, uint64_t* result
    ) {
        // Unroll first iteration of loop. We assume uint64_count > 0.
        unsigned char borrow = subUint64(*operand1++, *operand2++, result++);

        // Do the rest
        for (; --uint64Count; operand1++, operand2++, result++)
        {
            uint64_t temp_result;
            borrow = subUint64(*operand1, *operand2, borrow, &temp_result);
            *result = temp_result;
        }
        return borrow;
    }



    inline unsigned char subUint(
        const uint64_t *operand1, std::size_t uint64_count, uint64_t operand2, uint64_t *result)
    {
        // Unroll first iteration of loop. We assume uint64_count > 0.
        unsigned char borrow = subUint64(*operand1++, operand2, result++);

        // Do the rest
        for (; --uint64_count; operand1++, operand2++, result++)
        {
            uint64_t temp_result;
            borrow = subUint64(*operand1, uint64_t(0), borrow, &temp_result);
            *result = temp_result;
        }
        return borrow;
    }

    inline unsigned char incrementUint(
        const uint64_t *operand, std::size_t uint64_count, uint64_t *result)
    {
        return addUint(operand, uint64_count, 1, result);
    }

    inline unsigned char decrementUint(
        const uint64_t *operand, std::size_t uint64_count, uint64_t *result)
    {
        return subUint(operand, uint64_count, 1, result);
    }

    inline void negateUint(const uint64_t *operand, std::size_t uint64_count, uint64_t *result)
    {
        // Negation is equivalent to inverting bits and adding 1.
        unsigned char carry = addUint64(~*operand++, uint64_t(1), result++);
        for (; --uint64_count; operand++, result++)
        {
            uint64_t temp_result;
            carry = addUint64(~*operand, uint64_t(0), carry, &temp_result);
            *result = temp_result;
        }
    }


    inline void leftShiftUint(
        const uint64_t *operand, int shift_amount, std::size_t uint64_count, uint64_t *result)
    {
        const std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bitsPerUint64);

        // How many words to shift
        std::size_t uint64_shift_amount = static_cast<std::size_t>(shift_amount) / bits_per_uint64_sz;

        // Shift words
        for (std::size_t i = 0; i < uint64_count - uint64_shift_amount; i++)
        {
            result[uint64_count - i - 1] = operand[uint64_count - i - 1 - uint64_shift_amount];
        }
        for (std::size_t i = uint64_count - uint64_shift_amount; i < uint64_count; i++)
        {
            result[uint64_count - i - 1] = 0;
        }

        // How many bits to shift in addition
        std::size_t bit_shift_amount =
            static_cast<std::size_t>(shift_amount) - (uint64_shift_amount * bits_per_uint64_sz);

        if (bit_shift_amount)
        {
            std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

            for (std::size_t i = uint64_count - 1; i > 0; i--)
            {
                result[i] = (result[i] << bit_shift_amount) | (result[i - 1] >> neg_bit_shift_amount);
            }
            result[0] = result[0] << bit_shift_amount;
        }
    }

    inline void rightShiftUint(
        const uint64_t *operand, int shift_amount, std::size_t uint64_count, uint64_t *result)
    {
        const std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bitsPerUint64);

        // How many words to shift
        std::size_t uint64_shift_amount = static_cast<std::size_t>(shift_amount) / bits_per_uint64_sz;

        // Shift words
        for (std::size_t i = 0; i < uint64_count - uint64_shift_amount; i++)
        {
            result[i] = operand[i + uint64_shift_amount];
        }
        for (std::size_t i = uint64_count - uint64_shift_amount; i < uint64_count; i++)
        {
            result[i] = 0;
        }

        // How many bits to shift in addition
        std::size_t bit_shift_amount =
            static_cast<std::size_t>(shift_amount) - (uint64_shift_amount * bits_per_uint64_sz);

        if (bit_shift_amount)
        {
            std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

            for (std::size_t i = 0; i < uint64_count - 1; i++)
            {
                result[i] = (result[i] >> bit_shift_amount) | (result[i + 1] << neg_bit_shift_amount);
            }
            result[uint64_count - 1] = result[uint64_count - 1] >> bit_shift_amount;
        }
    }

    inline void leftShiftUint128(const uint64_t *operand, int shift_amount, uint64_t *result)
    {
        const std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bitsPerUint64);
        const std::size_t shift_amount_sz = static_cast<std::size_t>(shift_amount);

        // Early return
        if (shift_amount_sz & bits_per_uint64_sz)
        {
            result[1] = operand[0];
            result[0] = 0;
        }
        else
        {
            result[1] = operand[1];
            result[0] = operand[0];
        }

        // How many bits to shift in addition to word shift
        std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

        // Do we have a word shift
        if (bit_shift_amount)
        {
            std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

            // Warning: if bit_shift_amount == 0 this is incorrect
            result[1] = (result[1] << bit_shift_amount) | (result[0] >> neg_bit_shift_amount);
            result[0] = result[0] << bit_shift_amount;
        }
    }

    inline void rightShiftUint128(const uint64_t *operand, int shift_amount, uint64_t *result)
    {
        const std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bitsPerUint64);
        const std::size_t shift_amount_sz = static_cast<std::size_t>(shift_amount);

        if (shift_amount_sz & bits_per_uint64_sz)
        {
            result[0] = operand[1];
            result[1] = 0;
        }
        else
        {
            result[1] = operand[1];
            result[0] = operand[0];
        }

        // How many bits to shift in addition to word shift
        std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

        if (bit_shift_amount)
        {
            std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

            // Warning: if bit_shift_amount == 0 this is incorrect
            result[0] = (result[0] >> bit_shift_amount) | (result[1] << neg_bit_shift_amount);
            result[1] = result[1] >> bit_shift_amount;
        }
    }

    inline void leftShiftUint192(const uint64_t *operand, int shift_amount, uint64_t *result)
    {
        const std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bitsPerUint64);
        const std::size_t shift_amount_sz = static_cast<std::size_t>(shift_amount);

        if (shift_amount_sz & (bits_per_uint64_sz << 1))
        {
            result[2] = operand[0];
            result[1] = 0;
            result[0] = 0;
        }
        else if (shift_amount_sz & bits_per_uint64_sz)
        {
            result[2] = operand[1];
            result[1] = operand[0];
            result[0] = 0;
        }
        else
        {
            result[2] = operand[2];
            result[1] = operand[1];
            result[0] = operand[0];
        }

        // How many bits to shift in addition to word shift
        std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

        if (bit_shift_amount)
        {
            std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

            // Warning: if bit_shift_amount == 0 this is incorrect
            result[2] = (result[2] << bit_shift_amount) | (result[1] >> neg_bit_shift_amount);
            result[1] = (result[1] << bit_shift_amount) | (result[0] >> neg_bit_shift_amount);
            result[0] = result[0] << bit_shift_amount;
        }
    }

    inline void rightShiftUint192(const uint64_t *operand, int shift_amount, uint64_t *result)
    {
        const std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bitsPerUint64);
        const std::size_t shift_amount_sz = static_cast<std::size_t>(shift_amount);

        if (shift_amount_sz & (bits_per_uint64_sz << 1))
        {
            result[0] = operand[2];
            result[1] = 0;
            result[2] = 0;
        }
        else if (shift_amount_sz & bits_per_uint64_sz)
        {
            result[0] = operand[1];
            result[1] = operand[2];
            result[2] = 0;
        }
        else
        {
            result[2] = operand[2];
            result[1] = operand[1];
            result[0] = operand[0];
        }

        // How many bits to shift in addition to word shift
        std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

        if (bit_shift_amount)
        {
            std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

            // Warning: if bit_shift_amount == 0 this is incorrect
            result[0] = (result[0] >> bit_shift_amount) | (result[1] << neg_bit_shift_amount);
            result[1] = (result[1] >> bit_shift_amount) | (result[2] << neg_bit_shift_amount);
            result[2] = result[2] >> bit_shift_amount;
        }
    }

    inline void halfRoundUpUint(const uint64_t *operand, std::size_t uint64_count, uint64_t *result)
    {
        if (!uint64_count)
        {
            return;
        }
        // Set result to (operand + 1) / 2. To prevent overflowing operand, right shift
        // and then increment result if low-bit of operand was set.
        bool low_bit_set = operand[0] & 1;

        for (std::size_t i = 0; i < uint64_count - 1; i++)
        {
            result[i] = (operand[i] >> 1) | (operand[i + 1] << (bitsPerUint64 - 1));
        }
        result[uint64_count - 1] = operand[uint64_count - 1] >> 1;

        if (low_bit_set)
        {
            incrementUint(result, uint64_count, result);
        }
    }

    inline void notUint(const uint64_t *operand, std::size_t uint64_count, uint64_t *result)
    {
        for (; uint64_count--; result++, operand++)
        {
            *result = ~*operand;
        }
    }

    inline void andUint(
        const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count,
        uint64_t *result)
    {
        for (; uint64_count--; result++, operand1++, operand2++)
        {
            *result = *operand1 & *operand2;
        }
    }

    inline void orUint(
        const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count,
        uint64_t *result)
    {
        for (; uint64_count--; result++, operand1++, operand2++)
        {
            *result = *operand1 | *operand2;
        }
    }

    inline void xorUint(
        const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count,
        uint64_t *result)
    {
        for (; uint64_count--; result++, operand1++, operand2++)
        {
            *result = *operand1 ^ *operand2;
        }
    }

    // inline void multiplyUint64(uint64_t operand1, uint64_t operand2, uint64_t *result128)
    // {
    //     uint64_t operand1_coeff_right = operand1 & 0x00000000FFFFFFFF;
    //     uint64_t operand2_coeff_right = operand2 & 0x00000000FFFFFFFF;
    //     operand1 >>= 32;
    //     operand2 >>= 32;

    //     uint64_t middle1 = operand1 * operand2_coeff_right;
    //     uint64_t middle;
    //     uint64_t left = operand1 * operand2 +
    //                 (static_cast<uint64_t>(addUint64(middle1, operand2 * operand1_coeff_right, &middle)) << 32);
    //     uint64_t right = operand1_coeff_right * operand2_coeff_right;
    //     uint64_t temp_sum = (right >> 32) + (middle & 0x00000000FFFFFFFF);

    //     result128[1] = static_cast<uint64_t>(left + (middle >> 32) + (temp_sum >> 32));
    //     result128[0] = static_cast<uint64_t>((temp_sum << 32) | (right & 0x00000000FFFFFFFF));
    // }

    inline void multiplyUint64(uint64_t operand1, uint64_t operand2, uint64_t *result128)
    {        
        uint128_t product = static_cast<uint128_t>(operand1) * operand2; 
        result128[0] = static_cast<unsigned long long>(product);         
        result128[1] = static_cast<unsigned long long>(product >> 64); 
    }

//     inline void multiply_uint64_hw64_generic(T operand1, S operand2, uint64_t *hw64)
//     {
// #ifdef SEAL_DEBUG
//         if (!hw64)
//         {
//             throw std::invalid_argument("hw64 cannot be null");
//         }
// #endif
//         auto operand1_coeff_right = operand1 & 0x00000000FFFFFFFF;
//         auto operand2_coeff_right = operand2 & 0x00000000FFFFFFFF;
//         operand1 >>= 32;
//         operand2 >>= 32;

//         auto middle1 = operand1 * operand2_coeff_right;
//         T middle;
//         auto left = operand1 * operand2 +
//                     (static_cast<T>(add_uint64(middle1, operand2 * operand1_coeff_right, &middle)) << 32);
//         auto right = operand1_coeff_right * operand2_coeff_right;
//         auto temp_sum = (right >> 32) + (middle & 0x00000000FFFFFFFF);

//         *hw64 = static_cast<uint64_t>(left + (middle >> 32) + (temp_sum >> 32));
//     }

    inline void multiplyUint64HW64(uint64_t operand1, uint64_t operand2, uint64_t *hw64)
    {                                                         
        *hw64 = static_cast<uint64_t>( 
            ((static_cast<uint128_t>(operand1) * static_cast<uint128_t>(operand2)) >> 64)); 
    }

    void multiplyUint(
        const uint64_t *operand1, std::size_t operand1_uint64_count, const uint64_t *operand2,
        std::size_t operand2_uint64_count, std::size_t result_uint64_count, uint64_t *result);

    inline void multiplyUint(
        const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count,
        uint64_t *result)
    {
        multiplyUint(operand1, uint64_count, operand2, uint64_count, uint64_count * 2, result);
    }

    void multiplyUint(
        const uint64_t *operand1, std::size_t operand1_uint64_count, uint64_t operand2,
        std::size_t result_uint64_count, uint64_t *result);

    inline void multiplyTruncateUint(
        const uint64_t *operand1, const uint64_t *operand2, std::size_t uint64_count,
        uint64_t *result)
    {
        multiplyUint(operand1, uint64_count, operand2, uint64_count, uint64_count, result);
    }

    inline void multiplyManyUint64(uint64_t *operands, std::size_t count, uint64_t *result)
    {
        // Nothing to do
        if (!count)
        {
            return;
        }

        // Set result to operands[0]
        setUint(static_cast<uint64_t>(operands[0]), count, result);

        // FIXME: allocate related action
        // Compute product
        auto temp_mpi = new uint64_t[count];
        for (std::size_t i = 1; i < count; i++)
        {
            multiplyUint(result, i, operands[i], i + 1, temp_mpi);
            setUint(temp_mpi, i + 1, result);
        }
        delete[] temp_mpi;
    }

    inline void multiplyManyUint64Except(
        uint64_t *operands, std::size_t count, std::size_t except, uint64_t *result)
    {
        // An empty product; return 1
        if (count == 1 && except == 0)
        {
            setUint(1, count, result);
            return;
        }

        // Set result to operands[0] unless except is 0
        setUint(except == 0 ? uint64_t(1) : static_cast<uint64_t>(operands[0]), count, result);

        // FIXME: allocate related action
        // Compute punctured product
        auto temp_mpi = new uint64_t[count];
        for (std::size_t i = 1; i < count; i++)
        {
            if (i != except)
            {
                multiplyUint(result, i, operands[i], i + 1, temp_mpi);
                setUint(temp_mpi, i + 1, result);
            }
        }
        delete[] temp_mpi;
    }

    template <std::size_t Count>
    SEAL_FORCE_INLINE void multiplyAccumulateUint64(
        const uint64_t *operand1, const uint64_t *operand2, uint64_t *accumulator)
    {
        uint64_t qword[2];
        multiplyUint64(*operand1, *operand2, qword);
        multiplyAccumulateUint64<Count - 1>(operand1 + 1, operand2 + 1, accumulator);
        addUint128(qword, accumulator, accumulator);
    }

    template <>
    SEAL_FORCE_INLINE void multiplyAccumulateUint64<0>(
        SEAL_MAYBE_UNUSED const uint64_t *operand1, SEAL_MAYBE_UNUSED const uint64_t *operand2,
        SEAL_MAYBE_UNUSED uint64_t *accumulator)
    {
        // Base case; nothing to do
    }

    void divideUintInplace(
        uint64_t *numerator, const uint64_t *denominator, std::size_t uint64_count,
        uint64_t *quotient);

    inline void divideUint(
        const uint64_t *numerator, const uint64_t *denominator, std::size_t uint64_count,
        uint64_t *quotient, uint64_t *remainder)
    {
        setUint(numerator, uint64_count, remainder);
        divideUintInplace(remainder, denominator, uint64_count, quotient);
    }

    void divideUint128Uint64Inplace(
        uint64_t *numerator, uint64_t denominator, uint64_t *quotient);

    inline void divideUint128Inplace(uint64_t *numerator, uint64_t denominator, uint64_t *quotient)
    {        
        uint128_t n, q;                                                                            
        n = (static_cast<uint128_t>(numerator[1]) << 64) | (static_cast<uint128_t>(numerator[0])); 
        q = n / denominator;                                                                       
        n -= q * denominator;                                                                      
        numerator[0] = static_cast<std::uint64_t>(n);                                              
        numerator[1] = 0;                                                                          
        quotient[0] = static_cast<std::uint64_t>(q);                                                 
        quotient[1] = static_cast<std::uint64_t>(q >> 64);     
    }

    void divideUint192Inplace(uint64_t *numerator, uint64_t denominator, uint64_t *quotient);

    // uint64_t exponentiateUintSafe(uint64_t operand, uint64_t exponent);

    // uint64_t exponentiateUint(uint64_t operand, uint64_t exponent);

}}