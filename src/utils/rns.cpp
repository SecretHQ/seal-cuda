// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "common.h"
#include "numth.h"
#include "polyarithsmallmod.h"
#include "rns.h"
#include "uintarithmod.h"
#include "uintarithsmallmod.h"
#include <algorithm>

#include <iostream>

using std::size_t;
using std::invalid_argument;
using std::logic_error;
using std::vector;
using std::copy_n;

namespace troy
{
    namespace util
    {
        RNSBase::RNSBase(const vector<Modulus> &rnsbase)
            : size_(rnsbase.size())
        {
            if (!size_)
            {
                throw invalid_argument("rnsbase cannot be empty");
            }

            for (size_t i = 0; i < rnsbase.size(); i++)
            {
                // The base elements cannot be zero
                if (rnsbase[i].isZero())
                {
                    throw invalid_argument("rnsbase is invalid");
                }

                for (size_t j = 0; j < i; j++)
                {
                    // The base must be coprime
                    if (!areCoprime(rnsbase[i].value(), rnsbase[j].value()))
                    {
                        throw invalid_argument("rnsbase is invalid");
                    }
                }
            }

            // Base is good; now copy it over to rnsbase_
            // FIXME: allocate related action
            base_ = std::move(HostArray<Modulus>(size_));
            std::copy_n(rnsbase.cbegin(), size_, base_.get());

            // Initialize CRT data
            if (!initialize())
            {
                throw invalid_argument("rnsbase is invalid");
            }
        }

        RNSBase::RNSBase(const RNSBase &copy) : size_(copy.size_)
        {

            // Copy over the base
            // FIXME: allocate related action
            base_ = std::move(HostArray<Modulus>(size_));
            std::copy_n(copy.base_.get(), size_, base_.get());

            // Copy over CRT data
            // FIXME: allocate related action
            base_prod_ = std::move(HostArray<uint64_t>(size_));
            setUint(copy.base_prod_.get(), size_, base_prod_.get());

            // FIXME: allocate related action
            punctured_prod_array_ = std::move(HostArray<uint64_t>(size_ * size_));
            setUint(copy.punctured_prod_array_.get(), size_ * size_, punctured_prod_array_.get());

            // FIXME: allocate related action
            inv_punctured_prod_mod_base_array_ = std::move(HostArray<MultiplyUIntModOperand>(size_));
            std::copy_n(copy.inv_punctured_prod_mod_base_array_.get(), size_, inv_punctured_prod_mod_base_array_.get());
        }

        bool RNSBase::contains(const Modulus &value) const noexcept
        {
            bool result = false;
            for (std::size_t i = 0; i < size_; i++) {
                result = result || (base_[i] == value);
            }
            return result;
        }

        bool RNSBase::isSubbaseOf(const RNSBase &superbase) const noexcept
        {
            bool result = true;
            for (std::size_t i = 0; i < size_; i++) {
                result = result && superbase.contains(base_[i]);
            }
            return result;
        }

        RNSBase RNSBase::extend(const Modulus &value) const
        {
            if (value.isZero())
            {
                throw invalid_argument("value cannot be zero");
            }

            for (std::size_t i = 0; i < size_; i++) {
                // The base must be coprime
                if (!areCoprime(base_[i].value(), value.value()))
                {
                    throw logic_error("cannot extend by given value");
                }
            };

            // Copy over this base
            RNSBase newbase;
            newbase.size_ = add_safe(size_, size_t(1));
            // FIXME: allocate related action
            newbase.base_ = std::move(HostArray<Modulus>(newbase.size_));
            copy_n(base_.get(), size_, newbase.base_.get());

            // Extend with value
            newbase.base_[newbase.size_ - 1] = value;

            // Initialize CRT data
            if (!newbase.initialize())
            {
                throw logic_error("cannot extend by given value");
            }

            return newbase;
        }

        RNSBase RNSBase::extend(const RNSBase &other) const
        {
            // The bases must be coprime
            for (size_t i = 0; i < other.size_; i++)
            {
                for (size_t j = 0; j < size_; j++)
                {
                    if (!areCoprime(other[i].value(), base_[j].value()))
                    {
                        throw invalid_argument("rnsbase is invalid");
                    }
                }
            }

            // Copy over this base
            RNSBase newbase;
            newbase.size_ = add_safe(size_, other.size_);
            // FIXME: allocate related action
            newbase.base_ = std::move(HostArray<Modulus>(newbase.size_));
            std::copy_n(base_.get(), size_, newbase.base_.get());

            // Extend with other base
            std::copy_n(other.base_.get(), other.size_, newbase.base_.get() + size_);

            // Initialize CRT data
            if (!newbase.initialize())
            {
                throw logic_error("cannot extend by given base");
            }

            return newbase;
        }

        RNSBase RNSBase::drop() const
        {
            if (size_ == 1)
            {
                throw logic_error("cannot drop from base of size 1");
            }

            // Copy over this base
            RNSBase newbase;
            newbase.size_ = size_ - 1;
            // FIXME: allocate related action
            newbase.base_ = std::move(HostArray<Modulus>(newbase.size_));
            std::copy_n(base_.get(), size_ - 1, newbase.base_.get());

            // Initialize CRT data
            newbase.initialize();

            return newbase;
        }

        RNSBase RNSBase::drop(const Modulus &value) const
        {
            if (size_ == 1)
            {
                throw logic_error("cannot drop from base of size 1");
            }
            if (!contains(value))
            {
                throw logic_error("base does not contain value");
            }

            // Copy over this base
            RNSBase newbase;
            newbase.size_ = size_ - 1;
            // FIXME: allocate related action
            newbase.base_ = std::move(HostArray<Modulus>(newbase.size_));
            size_t source_index = 0;
            size_t dest_index = 0;
            while (dest_index < size_ - 1)
            {
                if (base_[source_index] != value)
                {
                    newbase.base_[dest_index] = base_[source_index];
                    dest_index++;
                }
                source_index++;
            }

            // Initialize CRT data
            newbase.initialize();

            return newbase;
        }

        bool RNSBase::initialize()
        {
            // Verify that the size is not too large
            if (!productFitsIn(size_, size_))
            {
                return false;
            }

            // FIXME: allocate related action
            base_prod_ = std::move(HostArray<uint64_t>(size_));
            punctured_prod_array_ = std::move(HostArray<uint64_t>(size_ * size_));
            inv_punctured_prod_mod_base_array_ = std::move(HostArray<MultiplyUIntModOperand>(size_));

            if (size_ > 1)
            {
                // FIXME:: allocate related action
                auto rnsbase_values = HostArray<uint64_t>(size_);
                for (std::size_t i = 0; i < size_; i++) rnsbase_values[i] = base_[i].value();

                // Create punctured products
                for (std::size_t i = 0; i < size_; i++) {
                    multiplyManyUint64Except(rnsbase_values.get(), size_, i, punctured_prod_array_.get() + i * size_);
                }

                // Compute the full product
                // FIXME:: allocate related action
                auto temp_mpi = HostArray<uint64_t>(size_);
                multiplyUint(punctured_prod_array_.get(), size_, base_[0].value(), size_, temp_mpi.get());
                setUint(temp_mpi.get(), size_, base_prod_.get());

                // Compute inverses of punctured products mod primes
                bool invertible = true;
                for (std::size_t i = 0; i < size_; i++) {
                    uint64_t temp = moduloUint(punctured_prod_array_.get() + i * size_, size_, base_[i]);
                    invertible = invertible && tryInvertUintMod(temp, base_[i], temp);
                    inv_punctured_prod_mod_base_array_[i].set(temp, base_[i]);
                }

                return invertible;
            }

            // Case of a single prime
            base_prod_[0] = base_[0].value();
            punctured_prod_array_[0] = 1;
            inv_punctured_prod_mod_base_array_[0].set(1, base_[0]);

            return true;
        }

        void RNSBase::decompose(uint64_t *value) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }

            if (size_ > 1)
            {
                // Copy the value
                // FIXME:: allocate related action
                auto value_copy = HostArray<uint64_t>(size_);
                setUint(value, size_, value_copy.get());

                for (std::size_t i = 0; i < size_; i++) {
                    value[i] = moduloUint(value_copy.get(), size_, base_[i]);
                }
            }
        }

        void RNSBase::decomposeArray(uint64_t *value, size_t count) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }

            if (size_ > 1)
            {
                if (!productFitsIn(count, size_))
                {
                    throw logic_error("invalid parameters");
                }

                // Decompose an array of multi-precision integers into an array of arrays, one per each base element

                // Copy the input array into a temporary location and set a StrideIter pointing to it
                // Note that the stride size is size_
                auto value_copy = HostArray<uint64_t>(count * size_);
                // SEAL_ALLOCATE_GET_STRIDE_ITER(value_copy, uint64_t, count, size_, pool);
                setUint(value, count * size_, value_copy.get());

                // Note how value_copy and value_out have size_ and count reversed
                // RNSIter value_out(value, count);

                // For each output RNS array (one per base element) ...
                for (std::size_t i = 0; i < size_; i++) {
                // SEAL_ITERATE(iter(base_, value_out), size_, [&](auto I) {
                    // For each multi-precision integer in value_copy ...
                    for (std::size_t j = 0; j < count; j++) {
                    // SEAL_ITERATE(iter(get<1>(I), value_copy), count, [&](auto J) {
                        // Reduce the multi-precision integer modulo the base element and write to value_out
                        value[i * count + j] = moduloUint(value_copy.get() + j * size_, size_, base_[i]);
                        // get<0>(J) = moduloUint(get<1>(J), size_, get<0>(I));
                    }
                }
            }
        }

        void RNSBase::compose(uint64_t *value) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }

            if (size_ > 1)
            {
                // Copy the value
                // FIXME: allocate related action
                auto temp_value = HostArray<uint64_t>(size_);
                setUint(value, size_, temp_value.get());

                // Clear the result
                setZeroUint(size_, value);

                // Compose an array of integers (one per base element) into a single multi-precision integer
                // FIXME: allocate related action
                auto temp_mpi = HostArray<uint64_t>(size_);
                for (std::size_t i = 0; i < size_; i++) {
                    uint64_t temp_prod = multiplyUintMod(temp_value[i], inv_punctured_prod_mod_base_array_[i], base_[i]);
                    multiplyUint(punctured_prod_array_.get() + i * size_, size_, temp_prod, size_, temp_mpi.get());
                    addUintUintMod(temp_mpi.get(), value, base_prod_.get(), size_, value);
                }
            }
        }

        void RNSBase::composeArray(uint64_t *value, size_t count) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }

            if (size_ > 1)
            {
                if (!productFitsIn(count, size_))
                {
                    throw logic_error("invalid parameters");
                }

                // Merge the coefficients first
                // FIXME: allocate related action
                auto temp_array = HostArray<uint64_t>(size_ * count);
                for (size_t i = 0; i < count; i++)
                {
                    for (size_t j = 0; j < size_; j++)
                    {
                        temp_array[j + (i * size_)] = value[(j * count) + i];
                    }
                }

                // Clear the result
                setZeroUint(count * size_, value);

                // Compose an array of RNS integers into a single array of multi-precision integers
                // FIXME: allocate related action
                auto temp_mpi = HostArray<uint64_t>(size_);
                for (size_t i = 0; i < count; i++) {
                    for (size_t j = 0; j < size_; j++) {
                        uint64_t temp_prod = multiplyUintMod(temp_array[i * size_ + j], inv_punctured_prod_mod_base_array_[j], base_[j]);
                        multiplyUint(punctured_prod_array_.get() + j * size_, size_, temp_prod, size_, temp_mpi.get());
                        addUintUintMod(temp_mpi.get(), value + i * size_, base_prod_.get(), size_, value + i * size_);
                    }
                }
            }
        }

        void BaseConverter::fastConvert(ConstHostPointer<uint64_t> in, HostPointer<uint64_t> out) const
        {
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();

            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(ibase_size);
            for (size_t i = 0; i < ibase_size; i++) {
                temp[i] = multiplyUintMod(in[i], ibase_.invPuncturedProdModBaseArray()[i], ibase_.base()[i]);
            }
            for (size_t i = 0; i < obase_size; i++) {
                out[i] = dotProductMod(temp.get(), base_change_matrix_[i].get(), ibase_size, obase_.base()[i]);
            }
        }

        void BaseConverter::fastConvertArray(ConstHostPointer<uint64_t> in, HostPointer<uint64_t> out, size_t count) const
        {
#ifdef SEAL_DEBUG
            if (in.poly_modulus_degree() != out.poly_modulus_degree())
            {
                throw invalid_argument("in and out are incompatible");
            }
#endif
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();

            // Note that the stride size is ibase_size
            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(count * ibase_size);

            for (size_t i = 0; i < ibase_size; i++) {
                // The current ibase index
                size_t ibase_index = i;

                if (ibase_.invPuncturedProdModBaseArray()[i].operand == 1)
                {
                    // No multiplication needed
                    for (size_t j = 0; j < count; j++) {
                        // Reduce modulo ibase element
                        temp[j * ibase_size + ibase_index] = barrettReduce64(in[i * count + j], ibase_.base()[i]);
                    };
                }
                else
                {
                    // Multiplication needed
                    for (size_t j = 0; j < count; j++) {
                        // Multiply coefficient of in with ibase_.inv_punctured_prod_mod_base_array_ element
                        temp[j * ibase_size + ibase_index] = multiplyUintMod(in[i * count + j], ibase_.invPuncturedProdModBaseArray()[i], ibase_.base()[i]);
                    }
                }
            }

            for (size_t i = 0; i < obase_size; i++) {
                for (size_t j = 0; j < count; j++) {
                    // Compute the base conversion sum modulo obase element
                    out[i * count + j] = dotProductMod(temp.get() + j * ibase_size, base_change_matrix_[i].get(), ibase_size, obase_.base()[i]);
                }
            }

        }

        // See "An Improved RNS Variant of the BFV Homomorphic Encryption Scheme" (CT-RSA 2019) for details
        void BaseConverter::exactConvertArray(ConstHostPointer<uint64_t> in, HostPointer<uint64_t> out, size_t in_count) const
        {
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();
            size_t count = in_count;

            if (obase_size != 1)
            {
                throw invalid_argument("out base in exact_convert_array must be one.");
            }

            // FIXME: allocate related action
            // Note that the stride size is ibase_size
            // SEAL_ALLOCATE_GET_STRIDE_ITER(temp, uint64_t, count, ibase_size, pool);
            auto temp = HostArray<uint64_t>(count * ibase_size);

            // The iterator storing v
            // SEAL_ALLOCATE_GET_STRIDE_ITER(v, double_t, count, ibase_size, pool);
            auto v = HostArray<double>(count * ibase_size);

            // Aggregated rounded v
            // SEAL_ALLOCATE_GET_PTR_ITER(aggregated_rounded_v, uint64_t, count, pool);
            auto aggregated_rounded_v = HostArray<uint64_t>(count);

            // Calculate [x_{i} * \hat{q_{i}}]_{q_{i}}
            for (size_t i = 0; i < ibase_size; i++) {
            // SEAL_ITERATE(
            //     iter(in, ibase_.inv_punctured_prod_mod_base_array(), ibase_.base(), size_t(0)), ibase_size,
            //     [&](auto I) {
                // The current ibase index
                size_t ibase_index = i;
                const Modulus& ibase_modulus = ibase_.base()[i];
                double_t divisor = static_cast<double_t>(ibase_modulus.value());

                if (ibase_.invPuncturedProdModBaseArray()[i].operand == 1)
                {
                    // No multiplication needed
                    for (size_t j = 0; j < count; j++) {
                    // SEAL_ITERATE(iter(get<0>(I), temp, v), count, [&](auto J) {
                        // Reduce modulo ibase element
                        temp[j * ibase_size + ibase_index] = barrettReduce64(in[i * count + j], ibase_modulus);
                        double_t dividend = static_cast<double_t>(temp[j * ibase_size + ibase_index]);
                        v[j * ibase_size + ibase_index] = dividend / divisor;
                    }
                }
                else
                {
                    // Multiplication needed
                    for (size_t j = 0; j < count; j++) {
                    // SEAL_ITERATE(iter(get<0>(I), temp, v), count, [&](auto J) {
                        // Multiply coefficient of in with ibase_.inv_punctured_prod_mod_base_array_ element
                        temp[j * ibase_size + ibase_index] = multiplyUintMod(in[i * count + j], ibase_.invPuncturedProdModBaseArray()[i], ibase_modulus);
                        double_t dividend = static_cast<double_t>(temp[j * ibase_size + ibase_index]);
                        v[j * ibase_size + ibase_index] = dividend / divisor;
                    }
                }
            }

            // Aggrate v and rounding
            for (size_t i = 0; i < count; i++) {
            // SEAL_ITERATE(iter(v, aggregated_rounded_v), count, [&](auto I) {
                // Otherwise a memory space of the last execution will be used.
                double_t aggregated_v = 0.0;
                for (size_t j = 0; j < ibase_size; ++j)
                {
                    aggregated_v += v[i * ibase_size + j];
                }
                aggregated_v += 0.5;
                aggregated_rounded_v[i] = static_cast<uint64_t>(aggregated_v);
            }
            
            // for (size_t i = 0; i < temp.size(); i++)
            //     std::cout << "temp[" << i << "]=" << temp[i] << std::endl;

            const auto& p = obase_.base()[0];
            auto q_mod_p = moduloUint(ibase_.baseProd(), ibase_size, p);
            auto base_change_matrix_first = base_change_matrix_[0].get();
            // Final multiplication
            for (size_t j = 0; j < count; j++) {
            // SEAL_ITERATE(iter(out, temp, aggregated_rounded_v), count, [&](auto J) {
                // Compute the base conversion sum modulo obase element
                auto sum_mod_obase = dotProductMod(temp.get() + j * ibase_size, base_change_matrix_first, ibase_size, p);
                // Minus v*[q]_{p} mod p
                auto v_q_mod_p = multiplyUintMod(aggregated_rounded_v[j], q_mod_p, p);
                out[j] = subUintMod(sum_mod_obase, v_q_mod_p, p);
            };
        }

        void BaseConverter::initialize()
        {
            // Verify that the size is not too large
            if (!productFitsIn(ibase_.size(), obase_.size()))
            {
                throw logic_error("invalid parameters");
            }

            // Create the base-change matrix rows
            // FIXME: allocate related action
            base_change_matrix_ = std::move(HostArray<HostArray<uint64_t>>(obase_.size()));

            for (size_t i = 0; i < obase_.size(); i++) {
            // SEAL_ITERATE(iter(base_change_matrix_, obase_.base()), obase_.size(), [&](auto I) {
                // Create the base-change matrix columns
                // FIXME: allocate related action
                base_change_matrix_[i] = std::move(HostArray<uint64_t>(ibase_.size()));

                for (size_t j = 0; j < ibase_.size(); j++) {
                    // Base-change matrix contains the punctured products of ibase elements modulo the obase
                    base_change_matrix_[i][j] = moduloUint(ibase_.puncturedProdArray() + ibase_.size() * j, ibase_.size(), obase_.base()[i]);
                }
            }
        }

        RNSTool::RNSTool(
            size_t poly_modulus_degree, const RNSBase &coeff_modulus, const Modulus &plain_modulus)
        {
            initialize(poly_modulus_degree, coeff_modulus, plain_modulus);
        }

        void RNSTool::initialize(size_t poly_modulus_degree, const RNSBase &q, const Modulus &t)
        {
            // Return if q is out of bounds
            if (q.size() < SEAL_COEFF_MOD_COUNT_MIN || q.size() > SEAL_COEFF_MOD_COUNT_MAX)
            {
                throw invalid_argument("rnsbase is invalid");
            }

            // Return if coeff_count is not a power of two or out of bounds
            int coeff_count_power = getPowerOfTwo(poly_modulus_degree);
            if (coeff_count_power < 0 || poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX ||
                poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN)
            {
                throw invalid_argument("poly_modulus_degree is invalid");
            }

            t_ = t;
            coeff_count_ = poly_modulus_degree;

            // Allocate memory for the bases q, B, Bsk, Bsk U m_tilde, t_gamma
            size_t base_q_size = q.size();

            // In some cases we might need to increase the size of the base B by one, namely we require
            // K * n * t * q^2 < q * prod(B) * m_sk, where K takes into account cross terms when larger size ciphertexts
            // are used, and n is the "delta factor" for the ring. We reserve 32 bits for K * n. Here the coeff modulus
            // primes q_i are bounded to be SEAL_USER_MOD_BIT_COUNT_MAX (60) bits, and all primes in B and m_sk are
            // SEAL_INTERNAL_MOD_BIT_COUNT (61) bits.
            int total_coeff_bit_count = getSignificantBitCountUint(q.baseProd(), q.size());

            size_t base_B_size = base_q_size;
            if (32 + t_.bitCount() + total_coeff_bit_count >=
                SEAL_INTERNAL_MOD_BIT_COUNT * safe_cast<int>(base_q_size) + SEAL_INTERNAL_MOD_BIT_COUNT)
            {
                base_B_size++;
            }

            size_t base_Bsk_size = add_safe(base_B_size, size_t(1));
            size_t base_Bsk_m_tilde_size = add_safe(base_Bsk_size, size_t(1));

            size_t base_t_gamma_size = 0;

            // Size check
            if (!productFitsIn(coeff_count_, base_Bsk_m_tilde_size))
            {
                throw logic_error("invalid parameters");
            }

            // Sample primes for B and two more primes: m_sk and gamma
            auto baseconv_primes =
                getPrimes(mul_safe(size_t(2), coeff_count_), SEAL_INTERNAL_MOD_BIT_COUNT, base_Bsk_m_tilde_size);
            auto baseconv_primes_iter = baseconv_primes.cbegin();
            m_sk_ = *baseconv_primes_iter++;
            gamma_ = *baseconv_primes_iter++;
            vector<Modulus> base_B_primes;
            copy_n(baseconv_primes_iter, base_B_size, back_inserter(base_B_primes));

            // Set m_tilde_ to a non-prime value
            m_tilde_ = uint64_t(1) << 32;

            // Populate the base arrays
            // FIXME: allocate related action
            base_q_ = HostObject(new RNSBase(q));
            base_B_ = HostObject(new RNSBase(base_B_primes));
            base_Bsk_ = HostObject(new RNSBase(base_B_->extend(m_sk_)));
            base_Bsk_m_tilde_ = HostObject(new RNSBase(base_Bsk_->extend(m_tilde_)));

            // Set up t-gamma base if t_ is non-zero (using BFV)
            if (!t_.isZero())
            {
                base_t_gamma_size = 2;
                // FIXME: allocate related action
                base_t_gamma_ = HostObject(new RNSBase(vector<Modulus>{ t_, gamma_ }));
            }

            // Generate the Bsk NTTTables; these are used for NTT after base extension to Bsk
            try
            {
                base_Bsk_ntt_tables_ = CreateNTTTables(
                    coeff_count_power, vector<Modulus>(base_Bsk_->base(), base_Bsk_->base() + base_Bsk_size));
            }
            catch (const logic_error &)
            {
                throw logic_error("invalid rns bases");
            }

            // FIXME: allocate related action
            if (!t_.isZero())
            {
                // Set up BaseConvTool for q --> {t}
                base_q_to_t_conv_ = HostObject(new BaseConverter(*base_q_, RNSBase({t_})));
            }

            // Set up BaseConverter for q --> Bsk
            base_q_to_Bsk_conv_ = HostObject(new BaseConverter(*base_q_, *base_Bsk_));

            // Set up BaseConverter for q --> {m_tilde}
            base_q_to_m_tilde_conv_ = HostObject(new BaseConverter(*base_q_, RNSBase({ m_tilde_ })));

            // Set up BaseConverter for B --> q
            base_B_to_q_conv_ = HostObject(new BaseConverter(*base_B_, *base_q_));

            // Set up BaseConverter for B --> {m_sk}
            base_B_to_m_sk_conv_ = HostObject(new BaseConverter(*base_B_, RNSBase({ m_sk_ })));

            if (!base_t_gamma_.isNull())
            {
                // Set up BaseConverter for q --> {t, gamma}
                base_q_to_t_gamma_conv_ = HostObject(new BaseConverter(*base_q_, *base_t_gamma_));
            }

            // Compute prod(B) mod q
            // FIXME: allocate related action
            prod_B_mod_q_ = HostArray<uint64_t>(base_q_size);
            for (size_t i = 0; i < base_q_size; i++) {
                prod_B_mod_q_[i] = moduloUint(base_B_->baseProd(), base_B_size, base_q_->base()[i]);
            }

            uint64_t temp;

            // Compute prod(q)^(-1) mod Bsk
            // FIXME: allocate related action
            inv_prod_q_mod_Bsk_ = HostArray<MultiplyUIntModOperand>(base_Bsk_size);
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                temp = moduloUint(base_q_->baseProd(), base_q_size, (*base_Bsk_)[i]);
                if (!tryInvertUintMod(temp, (*base_Bsk_)[i], temp))
                {
                    throw logic_error("invalid rns bases");
                }
                inv_prod_q_mod_Bsk_[i].set(temp, (*base_Bsk_)[i]);
            }

            // Compute prod(B)^(-1) mod m_sk
            temp = moduloUint(base_B_->baseProd(), base_B_size, m_sk_);
            if (!tryInvertUintMod(temp, m_sk_, temp))
            {
                throw logic_error("invalid rns bases");
            }
            inv_prod_B_mod_m_sk_.set(temp, m_sk_);

            // Compute m_tilde^(-1) mod Bsk
            // FIXME: allocate related action
            inv_m_tilde_mod_Bsk_ = HostArray<MultiplyUIntModOperand>(base_Bsk_size);
            for (size_t i = 0; i < base_Bsk_size; i++) {
                const Modulus& b = base_Bsk_->base()[i];
                if (!tryInvertUintMod(barrettReduce64(m_tilde_.value(), b), b, temp))
                {
                    throw logic_error("invalid rns bases");
                }
                inv_m_tilde_mod_Bsk_[i].set(temp, b);
            }

            // Compute prod(q)^(-1) mod m_tilde
            temp = moduloUint(base_q_->baseProd(), base_q_size, m_tilde_);
            if (!tryInvertUintMod(temp, m_tilde_, temp))
            {
                throw logic_error("invalid rns bases");
            }
            neg_inv_prod_q_mod_m_tilde_.set(negateUintMod(temp, m_tilde_), m_tilde_);

            // Compute prod(q) mod Bsk
            // FIXME: allocate related action
            prod_q_mod_Bsk_ = HostArray<uint64_t>(base_Bsk_size);
            for (size_t i = 0; i < base_Bsk_size; i++) {
                prod_q_mod_Bsk_[i] = moduloUint(base_q_->baseProd(), base_q_size, base_Bsk_->base()[i]);
            }

            if (!base_t_gamma_.isNull())
            {
                // Compute gamma^(-1) mod t
                if (!tryInvertUintMod(barrettReduce64(gamma_.value(), t_), t_, temp))
                {
                    throw logic_error("invalid rns bases");
                }
                inv_gamma_mod_t_.set(temp, t_);

                // Compute prod({t, gamma}) mod q
                // FIXME: allocate related action
                prod_t_gamma_mod_q_ = HostArray<MultiplyUIntModOperand>(base_q_size);
                for (size_t i = 0; i < base_q_size; i++) {
                // SEAL_ITERATE(iter(prod_t_gamma_mod_q_, base_q_->base()), base_q_size, [&](auto I) {
                    prod_t_gamma_mod_q_[i].set(
                        multiplyUintMod((*base_t_gamma_)[0].value(), (*base_t_gamma_)[1].value(), base_q_->base()[i]),
                        base_q_->base()[i]);
                }

                // Compute -prod(q)^(-1) mod {t, gamma}
                // FIXME: allocate related action
                neg_inv_q_mod_t_gamma_ = HostArray<MultiplyUIntModOperand>(base_t_gamma_size);
                for (size_t i = 0; i < base_t_gamma_size; i++) {
                    const Modulus& b = base_t_gamma_->base()[i];
                    neg_inv_q_mod_t_gamma_[i].operand = moduloUint(base_q_->baseProd(), base_q_size, b);
                    if (!tryInvertUintMod(neg_inv_q_mod_t_gamma_[i].operand, b, neg_inv_q_mod_t_gamma_[i].operand))
                    {
                        throw logic_error("invalid rns bases");
                    }
                    neg_inv_q_mod_t_gamma_[i].set(negateUintMod(neg_inv_q_mod_t_gamma_[i].operand, b), b);
                }
            }

            // Compute q[last]^(-1) mod q[i] for i = 0..last-1
            // This is used by modulus switching and rescaling
            // FIXME: allocate related action
            inv_q_last_mod_q_ = HostArray<MultiplyUIntModOperand>(base_q_size - 1);
            for (size_t i = 0; i < base_q_size - 1; i++) {
            // SEAL_ITERATE(iter(inv_q_last_mod_q_, base_q_->base()), base_q_size - 1, [&](auto I) {
                if (!tryInvertUintMod((*base_q_)[base_q_size - 1].value(), base_q_->base()[i], temp))
                {
                    throw logic_error("invalid rns bases");
                }
                inv_q_last_mod_q_[i].set(temp, base_q_->base()[i]);
            }

            if (t_.value() != 0)
            {
                if (!tryInvertUintMod(base_q_->base()[base_q_size - 1].value(), t_, inv_q_last_mod_t_))
                {
                    throw logic_error("invalid rns bases");
                }

                q_last_mod_t_ = barrettReduce64(base_q_->base()[base_q_size - 1].value(), t_);
            }
        }

        void RNSTool::divideAndRoundqLastInplace(HostPointer<uint64_t> input) const
        {
            size_t base_q_size = base_q_->size();
            auto last_input = input + (base_q_size - 1) * coeff_count_;

            // Add (qi-1)/2 to change from flooring to rounding
            Modulus last_modulus = (*base_q_)[base_q_size - 1];
            uint64_t half = last_modulus.value() >> 1;
            addPolyScalarCoeffmod(last_input, coeff_count_, half, last_modulus, last_input);
            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(coeff_count_);
            for (size_t i = 0; i < base_q_size - 1; i++) {
            // SEAL_ITERATE(iter(input, inv_q_last_mod_q_, base_q_->base()), base_q_size - 1, [&](auto I) {
                const Modulus& b = base_q_->base()[i];
                // (ct mod qk) mod qi
                moduloPolyCoeffs(last_input, coeff_count_, b, temp.asPointer());
                // Subtract rounding correction here; the negative sign will turn into a plus in the next subtraction
                uint64_t half_mod = barrettReduce64(half, b);
                subPolyScalarCoeffmod(temp.asPointer(), coeff_count_, half_mod, b, temp.asPointer());
                // (ct mod qi) - (ct mod qk) mod qi
                subPolyCoeffmod(input + i * coeff_count_, temp.asPointer(), coeff_count_, b, input + i * coeff_count_);
                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiplyPolyScalarCoeffmod(input + i * coeff_count_, coeff_count_, inv_q_last_mod_q_[i], b, input + i * coeff_count_);
            }
        }

        void RNSTool::divideAndRoundqLastNttInplace(
            HostPointer<uint64_t> input, const NTTTables* rns_ntt_tables) const
        {
            size_t base_q_size = base_q_->size();
            auto last_input = input + (base_q_size - 1) * coeff_count_;

            // Convert to non-NTT form
            inverseNttNegacyclicHarvey(last_input, rns_ntt_tables[base_q_size - 1]);

            // Add (qi-1)/2 to change from flooring to rounding
            Modulus last_modulus = (*base_q_)[base_q_size - 1];
            uint64_t half = last_modulus.value() >> 1;
            addPolyScalarCoeffmod(last_input, coeff_count_, half, last_modulus, last_input);

            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(coeff_count_);
            auto temp_pointer = temp.asPointer();
            for (size_t i = 0; i < base_q_size - 1; i++) {
            // SEAL_ITERATE(iter(input, inv_q_last_mod_q_, base_q_->base(), rns_ntt_tables), base_q_size - 1, [&](auto I) {
                const Modulus& b = base_q_->base()[i];
                // (ct mod qk) mod qi
                if (b.value() < last_modulus.value())
                {
                    moduloPolyCoeffs(last_input, coeff_count_, b, temp_pointer);
                }
                else
                {
                    setUint(last_input.get(), coeff_count_, temp.get());
                }

                // Lazy subtraction here. ntt_negacyclic_harvey_lazy can take 0 < x < 4*qi input.
                uint64_t neg_half_mod = b.value() - barrettReduce64(half, b);

                // Note: lambda function parameter must be passed by reference here
                for (size_t j = 0; j < coeff_count_; j++) temp[j] += neg_half_mod;
                // Since SEAL uses at most 60-bit moduli, 8*qi < 2^63.
                // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                uint64_t qi_lazy = b.value() << 2;
                nttNegacyclicHarveyLazy(temp_pointer, rns_ntt_tables[i]);
                // Lazy subtraction again, results in [0, 2*qi_lazy),
                // The reduction [0, 2*qi_lazy) -> [0, qi) is done implicitly in multiply_poly_scalar_coeffmod.
                for (size_t j = 0; j < coeff_count_; j++) input[i * coeff_count_ + j] += qi_lazy - temp[j];

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiplyPolyScalarCoeffmod(input + i * coeff_count_, coeff_count_, inv_q_last_mod_q_[i], b, input + i * coeff_count_);
            }
        }

        void RNSTool::fastbconvSk(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const
        {
            /*
            Require: Input in base Bsk
            Ensure: Output in base q
            */

            size_t base_q_size = base_q_->size();
            size_t base_B_size = base_B_->size();

            // Fast convert B -> q; input is in Bsk but we only use B
            base_B_to_q_conv_->fastConvertArray(input, destination, coeff_count_);

            // Compute alpha_sk
            // Fast convert B -> {m_sk}; input is in Bsk but we only use B
            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(coeff_count_);
            base_B_to_m_sk_conv_->fastConvertArray(input, temp.asPointer(), coeff_count_);

            // Take the m_sk part of input, subtract from temp, and multiply by inv_prod_B_mod_m_sk_
            // Note: input_sk is allocated in input[base_B_size]
            // FIXME: allocate related action
            auto alpha_sk = HostArray<uint64_t>(coeff_count_);
            for (size_t i = 0; i < coeff_count_; i++) {
            // SEAL_ITERATE(iter(alpha_sk, temp, input[base_B_size]), coeff_count_, [&](auto I) {
                // It is not necessary for the negation to be reduced modulo the small prime
                alpha_sk[i] = multiplyUintMod(temp[i] + (m_sk_.value() - input[base_B_size * coeff_count_ + i]), inv_prod_B_mod_m_sk_, m_sk_);
            }

            // alpha_sk is now ready for the Shenoy-Kumaresan conversion; however, note that our
            // alpha_sk here is not a centered reduction, so we need to apply a correction below.
            const uint64_t m_sk_div_2 = m_sk_.value() >> 1;
            for (size_t i = 0; i < base_q_size; i++) {
            // SEAL_ITERATE(iter(prod_B_mod_q_, base_q_->base(), destination), base_q_size, [&](auto I) {
                const Modulus& b = base_q_->base()[i];
                // Set up the multiplication helpers
                MultiplyUIntModOperand prod_B_mod_q_elt;
                prod_B_mod_q_elt.set(prod_B_mod_q_[i], b);
                // printf("i=%lu, %llu, %llu\n", i, prod_B_mod_q_elt.operand, prod_B_mod_q_elt.quotient);

                MultiplyUIntModOperand neg_prod_B_mod_q_elt;
                neg_prod_B_mod_q_elt.set(b.value() - prod_B_mod_q_[i], b);
                // printf("i=%lu, x %llu, %llu\n", i, neg_prod_B_mod_q_elt.operand, neg_prod_B_mod_q_elt.quotient);

                for (size_t j = 0; j < coeff_count_; j++) {
                // SEAL_ITERATE(iter(alpha_sk, get<2>(I)), coeff_count_, [&](auto J) {
                    uint64_t& dest = destination[i * coeff_count_ + j];
                    // printf("i=%lu, j=%lu, dest=%llu, cp\n", i, j, dest);
                    // Correcting alpha_sk since it represents a negative value
                    if (alpha_sk[j] > m_sk_div_2)
                    {
                        dest = multiplyAddUintMod(
                            negateUintMod(alpha_sk[j], m_sk_), prod_B_mod_q_elt, dest, b);
                    }
                    // No correction needed
                    else
                    {
                        // It is not necessary for the negation to be reduced modulo the small prime
                        dest = multiplyAddUintMod(alpha_sk[j], neg_prod_B_mod_q_elt, dest, b);
                    }
                }
            }
        }

        void RNSTool::smMrq(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const
        {
            /*
            Require: Input in base Bsk U {m_tilde}
            Ensure: Output in base Bsk
            */

            size_t base_Bsk_size = base_Bsk_->size();

            // The last component of the input is mod m_tilde
            ConstHostPointer<uint64_t> input_m_tilde = input + base_Bsk_size * coeff_count_;
            const uint64_t m_tilde_div_2 = m_tilde_.value() >> 1;

            // Compute r_m_tilde
            // FIXME: allocate related action
            auto r_m_tilde = HostArray<uint64_t>(coeff_count_);
            multiplyPolyScalarCoeffmod(
                input_m_tilde, coeff_count_, neg_inv_prod_q_mod_m_tilde_, m_tilde_, r_m_tilde.asPointer());

            for (size_t i = 0; i < base_Bsk_size; i++) {
                // iter(input, prod_q_mod_Bsk_, inv_m_tilde_mod_Bsk_, base_Bsk_->base(), destination), base_Bsk_size,
                // [&](auto I) {
                const Modulus& b = base_Bsk_->base()[i];
                MultiplyUIntModOperand prod_q_mod_Bsk_elt;
                prod_q_mod_Bsk_elt.set(prod_q_mod_Bsk_[i], b);
                for (size_t j = 0; j < coeff_count_; j++) {
                // SEAL_ITERATE(iter(get<0>(I), r_m_tilde, get<4>(I)), coeff_count_, [&](auto J) {
                    // We need centered reduction of r_m_tilde modulo Bsk. Note that m_tilde is chosen
                    // to be a power of two so we have '>=' below.
                    uint64_t temp = r_m_tilde[j];
                    if (temp >= m_tilde_div_2)
                    {
                        temp += b.value() - m_tilde_.value();
                    }

                    // Compute (input + q*r_m_tilde)*m_tilde^(-1) mod Bsk
                    destination[i * coeff_count_ + j] = multiplyUintMod(
                        multiplyAddUintMod(temp, prod_q_mod_Bsk_elt, input[i * coeff_count_ + j], b), inv_m_tilde_mod_Bsk_[i], b);
                }
            }
        }

        void RNSTool::fastFloor(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const
        {
            /*
            Require: Input in base q U Bsk
            Ensure: Output in base Bsk
            */

            size_t base_q_size = base_q_->size();
            size_t base_Bsk_size = base_Bsk_->size();

            // Convert q -> Bsk
            base_q_to_Bsk_conv_->fastConvertArray(input, destination, coeff_count_);

            // Move input pointer to past the base q components
            input = input + base_q_size * coeff_count_;
            for (size_t i = 0; i < base_Bsk_size; i++) {
            // SEAL_ITERATE(iter(input, inv_prod_q_mod_Bsk_, base_Bsk_->base(), destination), base_Bsk_size, [&](auto I) {
                for (size_t j = 0; j < coeff_count_; j++) {
                // SEAL_ITERATE(iter(get<0>(I), get<3>(I)), coeff_count_, [&](auto J) {
                    // It is not necessary for the negation to be reduced modulo base_Bsk_elt
                    destination[i * coeff_count_ + j] = 
                        multiplyUintMod(input[i * coeff_count_ + j] + 
                        (base_Bsk_->base()[i].value() - destination[i * coeff_count_ + j]), inv_prod_q_mod_Bsk_[i], base_Bsk_->base()[i]);
                }
            }
        }

        void RNSTool::fastbconvmTilde(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const
        {
            /*
            Require: Input in q
            Ensure: Output in Bsk U {m_tilde}
            */

            size_t base_q_size = base_q_->size();
            size_t base_Bsk_size = base_Bsk_->size();

            // We need to multiply first the input with m_tilde mod q
            // This is to facilitate Montgomery reduction in the next step of multiplication
            // This is NOT an ideal approach: as mentioned in BEHZ16, multiplication by
            // m_tilde can be easily merge into the base conversion operation; however, then
            // we could not use the BaseConverter as below without modifications.
            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(coeff_count_ * base_q_size);
            // SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count_, base_q_size, pool);
            multiplyPolyScalarCoeffmod(input, base_q_size, coeff_count_, m_tilde_.value(), base_q_->base(), temp.asPointer());

            // Now convert to Bsk
            base_q_to_Bsk_conv_->fastConvertArray(temp.asPointer(), destination, coeff_count_);

            // Finally convert to {m_tilde}
            base_q_to_m_tilde_conv_->fastConvertArray(temp.asPointer(), destination + base_Bsk_size * coeff_count_, coeff_count_);
        }

        void RNSTool::decryptScaleAndRound(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const
        {
            size_t base_q_size = base_q_->size();
            size_t base_t_gamma_size = base_t_gamma_->size();

            // Compute |gamma * t|_qi * ct(s)
            // FIXME: allocate related action
            auto temp = HostArray<uint64_t>(coeff_count_ * base_q_size);
            for (size_t i = 0; i < base_q_size; i++) {
            // SEAL_ITERATE(iter(input, prod_t_gamma_mod_q_, base_q_->base(), temp), base_q_size, [&](auto I) {
                multiplyPolyScalarCoeffmod(input + i * coeff_count_, coeff_count_, prod_t_gamma_mod_q_[i], base_q_->base()[i], temp + coeff_count_ * i);
            }

            // Make another temp destination to get the poly in mod {t, gamma}
            // FIXME: allocate related action
            auto temp_t_gamma = HostArray<uint64_t>(coeff_count_ * base_t_gamma_size);
            // SEAL_ALLOCATE_GET_RNS_ITER(temp_t_gamma, coeff_count_, base_t_gamma_size, pool);

            // Convert from q to {t, gamma}
            base_q_to_t_gamma_conv_->fastConvertArray(temp.asPointer(), temp_t_gamma.asPointer(), coeff_count_);

            // Multiply by -prod(q)^(-1) mod {t, gamma}
            for (size_t i = 0; i < base_t_gamma_size; i++) {
            // SEAL_ITERATE(
                // iter(temp_t_gamma, neg_inv_q_mod_t_gamma_, base_t_gamma_->base(), temp_t_gamma), base_t_gamma_size,
                // [&](auto I) {
                multiplyPolyScalarCoeffmod(temp_t_gamma + i * coeff_count_, coeff_count_, neg_inv_q_mod_t_gamma_[i], base_t_gamma_->base()[i], temp_t_gamma + i * coeff_count_);
            }

            // Need to correct values in temp_t_gamma (gamma component only) which are
            // larger than floor(gamma/2)
            uint64_t gamma_div_2 = (*base_t_gamma_)[1].value() >> 1;

            // Now compute the subtraction to remove error and perform final multiplication by
            // gamma inverse mod t
            for (size_t i = 0; i < coeff_count_; i++) {
            // SEAL_ITERATE(iter(temp_t_gamma[0], temp_t_gamma[1], destination), coeff_count_, [&](auto I) {
                // Need correction because of centered mod
                if (temp_t_gamma[coeff_count_ + i] > gamma_div_2)
                {
                    // Compute -(gamma - a) instead of (a - gamma)
                    destination[i] = addUintMod(temp_t_gamma[i], barrettReduce64(gamma_.value() - temp_t_gamma[coeff_count_ + i], t_), t_);
                }
                // No correction needed
                else
                {
                    destination[i] = subUintMod(temp_t_gamma[i], barrettReduce64(temp_t_gamma[coeff_count_ + i], t_), t_);
                }

                // If this coefficient was non-zero, multiply by gamma^(-1)
                if (0 != destination[i])
                {
                    // Perform final multiplication by gamma inverse mod t
                    destination[i] = multiplyUintMod(destination[i], inv_gamma_mod_t_, t_);
                }
            }
        }

        void RNSTool::modTAndDivideqLastInplace(HostPointer<uint64_t> input) const
        {
            size_t modulus_size = base_q_->size();
            const Modulus *curr_modulus = base_q_->base();
            const Modulus plain_modulus = t_;
            uint64_t last_modulus_value = curr_modulus[modulus_size - 1].value();

            // FIXME: allocate related action
            auto neg_c_last_mod_t = HostArray<uint64_t>(coeff_count_);
            // neg_c_last_mod_t = - c_last (mod t)
            moduloPolyCoeffs(input + (modulus_size - 1) * coeff_count_, coeff_count_, plain_modulus, neg_c_last_mod_t.asPointer());
            negatePolyCoeffmod(neg_c_last_mod_t.asPointer(), coeff_count_, plain_modulus, neg_c_last_mod_t.asPointer());
            if (inv_q_last_mod_t_ != 1)
            {
                // neg_c_last_mod_t *= q_last^(-1) (mod t)
                multiplyPolyScalarCoeffmod(
                    neg_c_last_mod_t.asPointer(), coeff_count_, inv_q_last_mod_t_, plain_modulus, neg_c_last_mod_t.asPointer());
            }

            // FIXME: allocate related action
            auto delta_mod_q_i = HostArray<uint64_t>(coeff_count_);
            for (size_t i = 0; i < coeff_count_; i++) delta_mod_q_i[i] = 0;
            // SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(delta_mod_q_i, coeff_count_, pool);

            for (size_t i = 0; i < modulus_size - 1; i++) {
            // SEAL_ITERATE(iter(input, curr_modulus, inv_q_last_mod_q_), modulus_size - 1, [&](auto I) {
                // delta_mod_q_i = neg_c_last_mod_t (mod q_i)
                moduloPolyCoeffs(neg_c_last_mod_t.asPointer(), coeff_count_, curr_modulus[i], delta_mod_q_i.asPointer());

                // delta_mod_q_i *= q_last (mod q_i)
                multiplyPolyScalarCoeffmod(
                    delta_mod_q_i.asPointer(), coeff_count_, last_modulus_value, curr_modulus[i], delta_mod_q_i.asPointer());

                // c_i = c_i - c_last - neg_c_last_mod_t * q_last (mod 2q_i)
                const uint64_t two_times_q_i = curr_modulus[i].value() << 1;
                for (size_t j = 0; j < coeff_count_; j++) {
                // SEAL_ITERATE(iter(get<0>(I), delta_mod_q_i, input[modulus_size - 1]), coeff_count_, [&](auto J) {
                    input[i * coeff_count_ + j] += two_times_q_i - barrettReduce64(input[(modulus_size - 1) * coeff_count_ + j], curr_modulus[i]) - delta_mod_q_i[j];
                }

                // c_i = c_i * inv_q_last_mod_q_i (mod q_i)
                multiplyPolyScalarCoeffmod(input + i * coeff_count_, coeff_count_, inv_q_last_mod_q_[i], curr_modulus[i], input + i * coeff_count_);
            }
        }

        void RNSTool::decryptModt(ConstHostPointer<uint64_t> phase, HostPointer<uint64_t> destination) const
        {
            // Use exact base convension rather than convert the base through the compose API
            base_q_to_t_conv_->exactConvertArray(phase, destination, coeff_count_);
        }
    } // namespace util
} // namespace seal
