#include "modulus.h"
#include "utils/numth.h"
#include "utils/uintarith.h"
#include "utils/uintarithsmallmod.h"

using std::logic_error;
using std::invalid_argument;
using std::vector;
using std::unordered_map;
using std::runtime_error;
using std::accumulate;

namespace troy {

    void Modulus::setValue(uint64_t value) {
        if (value == 0) {            
            // Zero settings
            bit_count_ = 0;
            uint64_count_ = 1;
            value_ = 0;
            for (size_t i = 0; i < 3 ; i++) const_ratio_[i] = 0;
            is_prime_ = false;
        } else if ((value >> SEAL_MOD_BIT_COUNT_MAX != 0) || (value == 1)) {
            throw std::invalid_argument("Value can be at most 61-bit and cannot be 1.");
        } else {
            // All normal, compute const_ratio and set everything
            value_ = value;
            bit_count_ = util::getSignificantBitCount(value_);
            // Compute Barrett ratios for 64-bit words (barrett_reduce_128)
            uint64_t numerator[3]{ 0, 0, 1 };
            uint64_t quotient[3]{ 0, 0, 0 };
            // Use a special method to avoid using memory pool
            util::divideUint192Inplace(numerator, value_, quotient);
            const_ratio_[0] = quotient[0];
            const_ratio_[1] = quotient[1];
            // We store also the remainder
            const_ratio_[2] = numerator[0];
            uint64_count_ = 1;
            // Set the primality flag
            is_prime_ = util::isPrime(*this);
        }
    }

    uint64_t Modulus::reduce(uint64_t value) const
    {
        if (value_ == 0)
        {
            throw logic_error("cannot reduce modulo a zero modulus");
        }
        return util::barrettReduce64(value, *this);
    }

    vector<Modulus> CoeffModulus::BFVDefault(size_t poly_modulus_degree, SecurityLevel sec_level)
    {
        if (!MaxBitCount(poly_modulus_degree, sec_level))
        {
            throw invalid_argument("non-standard poly_modulus_degree");
        }
        if (sec_level == SecurityLevel::none)
        {
            throw invalid_argument("invalid security level");
        }

        switch (sec_level)
        {
        case SecurityLevel::tc128:
            return util::global_variables::GetDefaultCoeffModulus128().at(poly_modulus_degree);

        case SecurityLevel::tc192:
            return util::global_variables::GetDefaultCoeffModulus192().at(poly_modulus_degree);

        case SecurityLevel::tc256:
            return util::global_variables::GetDefaultCoeffModulus256().at(poly_modulus_degree);

        default:
            throw runtime_error("invalid security level");
        }
    }

    vector<Modulus> CoeffModulus::Create(size_t poly_modulus_degree, vector<int> bit_sizes)
    {
        if (poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX || poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN ||
            util::getPowerOfTwo(static_cast<uint64_t>(poly_modulus_degree)) < 0)
        {
            throw invalid_argument("poly_modulus_degree is invalid");
        }
        if (bit_sizes.size() > SEAL_COEFF_MOD_COUNT_MAX)
        {
            throw invalid_argument("bit_sizes is invalid");
        }
        if (accumulate(
                bit_sizes.cbegin(), bit_sizes.cend(), SEAL_USER_MOD_BIT_COUNT_MIN,
                [](int a, int b) { return std::max(a, b); }) > SEAL_USER_MOD_BIT_COUNT_MAX ||
            accumulate(bit_sizes.cbegin(), bit_sizes.cend(), SEAL_USER_MOD_BIT_COUNT_MAX, [](int a, int b) {
                return std::min(a, b);
            }) < SEAL_USER_MOD_BIT_COUNT_MIN)
        {
            throw invalid_argument("bit_sizes is invalid");
        }

        unordered_map<int, size_t> count_table;
        unordered_map<int, vector<Modulus>> prime_table;
        for (int size : bit_sizes)
        {
            ++count_table[size];
        }

        uint64_t factor = util::mul_safe(uint64_t(2), util::safe_cast<uint64_t>(poly_modulus_degree));
        for (const auto &table_elt : count_table)
        {
            prime_table[table_elt.first] = util::getPrimes(factor, table_elt.first, table_elt.second);
        }

        vector<Modulus> result;
        for (int size : bit_sizes)
        {
            result.emplace_back(prime_table[size].back());
            prime_table[size].pop_back();
        }
        return result;
    }

    vector<Modulus> CoeffModulus::Create(
        size_t poly_modulus_degree, const Modulus &plain_modulus, vector<int> bit_sizes)
    {
        if (poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX || poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN ||
            util::getPowerOfTwo(static_cast<uint64_t>(poly_modulus_degree)) < 0)
        {
            throw invalid_argument("poly_modulus_degree is invalid");
        }
        if (bit_sizes.size() > SEAL_COEFF_MOD_COUNT_MAX)
        {
            throw invalid_argument("bit_sizes is invalid");
        }
        if (accumulate(
                bit_sizes.cbegin(), bit_sizes.cend(), SEAL_USER_MOD_BIT_COUNT_MIN,
                [](int a, int b) { return std::max(a, b); }) > SEAL_USER_MOD_BIT_COUNT_MAX ||
            accumulate(bit_sizes.cbegin(), bit_sizes.cend(), SEAL_USER_MOD_BIT_COUNT_MAX, [](int a, int b) {
                return std::min(a, b);
            }) < SEAL_USER_MOD_BIT_COUNT_MIN)
        {
            throw invalid_argument("bit_sizes is invalid");
        }

        unordered_map<int, size_t> count_table;
        unordered_map<int, vector<Modulus>> prime_table;
        for (int size : bit_sizes)
        {
            ++count_table[size];
        }

        uint64_t factor = util::mul_safe(uint64_t(2), util::safe_cast<uint64_t>(poly_modulus_degree));
        factor = util::mul_safe(factor, plain_modulus.value() / util::gcd(plain_modulus.value(), factor));
        for (const auto &table_elt : count_table)
        {
            prime_table[table_elt.first] = util::getPrimes(factor, table_elt.first, table_elt.second);
        }

        vector<Modulus> result;
        for (int size : bit_sizes)
        {
            result.emplace_back(prime_table[size].back());
            prime_table[size].pop_back();
        }
        return result;
    }

}