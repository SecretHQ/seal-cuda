// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "galois.h"
#include "numth.h"
#include "uintcore.h"

using namespace std;

namespace troy
{
    namespace util
    {
        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr uint32_t GaloisTool::generator_;

        void GaloisTool::generateTableNtt(uint32_t galois_elt, HostArray<uint32_t> &result) const
        {
            // ReaderLock reader_lock(permutation_tables_locker_.acquire_read());
            // if (result)
            // {
            //     return;
            // }
            // reader_lock.unlock();

            auto temp = HostArray<uint32_t>(coeff_count_);
            auto temp_ptr = temp.get();

            uint32_t coeff_count_minus_one = safe_cast<uint32_t>(coeff_count_) - 1;
            for (size_t i = coeff_count_; i < coeff_count_ << 1; i++)
            {
                uint32_t reversed = reverseBits(safe_cast<uint32_t>(i), coeff_count_power_ + 1);
                uint64_t index_raw = (static_cast<uint64_t>(galois_elt) * static_cast<uint64_t>(reversed)) >> 1;
                index_raw &= static_cast<uint64_t>(coeff_count_minus_one);
                *temp_ptr++ = reverseBits(static_cast<uint32_t>(index_raw), coeff_count_power_);
            }

            // WriterLock writer_lock(permutation_tables_locker_.acquire_write());
            // if (result)
            // {
            //     return;
            // }
            // result.acquire(move(temp));
            result = move(temp);
        }

        uint32_t GaloisTool::getEltFromStep(int step) const
        {
            uint32_t n = safe_cast<uint32_t>(coeff_count_);
            uint32_t m32 = mul_safe(n, uint32_t(2));
            uint64_t m = static_cast<uint64_t>(m32);

            if (step == 0)
            {
                return static_cast<uint32_t>(m - 1);
            }
            else
            {
                // Extract sign of steps. When steps is positive, the rotation
                // is to the left; when steps is negative, it is to the right.
                bool sign = step < 0;
                uint32_t pos_step = safe_cast<uint32_t>(abs(step));

                if (pos_step >= (n >> 1))
                {
                    throw invalid_argument("step count too large");
                }

                pos_step &= m32 - 1;
                if (sign)
                {
                    step = safe_cast<int>(n >> 1) - safe_cast<int>(pos_step);
                }
                else
                {
                    step = safe_cast<int>(pos_step);
                }

                // Construct Galois element for row rotation
                uint64_t gen = static_cast<uint64_t>(generator_);
                uint64_t galois_elt = 1;
                while (step--)
                {
                    galois_elt *= gen;
                    galois_elt &= m - 1;
                }
                return static_cast<uint32_t>(galois_elt);
            }
        }

        vector<uint32_t> GaloisTool::getEltsFromSteps(const vector<int> &steps) const
        {
            vector<uint32_t> galois_elts;
            transform(steps.begin(), steps.end(), back_inserter(galois_elts), [&](auto s) {
                return this->getEltFromStep(s);
            });
            return galois_elts;
        }

        vector<uint32_t> GaloisTool::getEltsAll() const noexcept
        {
            uint32_t m = safe_cast<uint32_t>(static_cast<uint64_t>(coeff_count_) << 1);
            vector<uint32_t> galois_elts{};

            // Generate Galois keys for m - 1 (X -> X^{m-1})
            galois_elts.push_back(m - 1);

            // Generate Galois key for power of generator_ mod m (X -> X^{3^k}) and
            // for negative power of generator_ mod m (X -> X^{-3^k})
            uint64_t pos_power = generator_;
            uint64_t neg_power = 0;
            tryInvertUintMod(generator_, m, neg_power);
            for (int i = 0; i < coeff_count_power_ - 1; i++)
            {
                galois_elts.push_back(static_cast<uint32_t>(pos_power));
                pos_power *= pos_power;
                pos_power &= (m - 1);

                galois_elts.push_back(static_cast<uint32_t>(neg_power));
                neg_power *= neg_power;
                neg_power &= (m - 1);
            }

            return galois_elts;
        }

        void GaloisTool::initialize(int coeff_count_power)
        {
            if ((coeff_count_power < getPowerOfTwo(SEAL_POLY_MOD_DEGREE_MIN)) ||
                coeff_count_power > getPowerOfTwo(SEAL_POLY_MOD_DEGREE_MAX))
            {
                throw invalid_argument("coeff_count_power out of range");
            }

            coeff_count_power_ = coeff_count_power;
            coeff_count_ = size_t(1) << coeff_count_power_;

            // Capacity for coeff_count_ number of tables
            permutation_tables_ = HostArray<HostArray<uint32_t>>(coeff_count_);
        }

        void GaloisTool::applyGalois(
            ConstHostPointer<uint64_t> operand, uint32_t galois_elt, const Modulus &modulus, HostPointer<uint64_t> result) const
        {
            const uint64_t modulus_value = modulus.value();
            const uint64_t coeff_count_minus_one = coeff_count_ - 1;
            uint64_t index_raw = 0;
            for (uint64_t i = 0; i <= coeff_count_minus_one; i++, ++operand, index_raw += galois_elt)
            {
                uint64_t index = index_raw & coeff_count_minus_one;
                uint64_t result_value = *operand;
                if ((index_raw >> coeff_count_power_) & 1)
                {
                    // Explicit inline
                    // result[index] = negate_uint_mod(result[index], modulus);
                    int64_t non_zero = (result_value != 0);
                    result_value = (modulus_value - result_value) & static_cast<uint64_t>(-non_zero);
                }
                result[index] = result_value;
            }
        }

        void GaloisTool::applyGaloisNtt(ConstHostPointer<uint64_t> operand, uint32_t galois_elt, HostPointer<uint64_t> result) const
        {
            auto index = GetIndexFromElt(galois_elt);
            generateTableNtt(galois_elt, permutation_tables_[index]);

            HostArray<uint32_t>& table = permutation_tables_[index];

            // Perform permutation.
            for (size_t i = 0; i < coeff_count_; i++) {
                result[i] = operand[table[i]];
            }
        }
    } // namespace util
} // namespace seal
