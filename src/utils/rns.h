#pragma once

#include "../modulus.h"
#include "ntt.h"
#include "uintarithsmallmod.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <vector>

namespace troy
{
    namespace util
    {
        class RNSBase
        {
            friend class RNSBaseCuda;
        public:
            RNSBase(const std::vector<Modulus> &rnsbase);

            RNSBase(RNSBase &&source) = default;

            RNSBase(const RNSBase &copy);

            RNSBase &operator=(const RNSBase &assign) = delete;

            inline const Modulus &operator[](std::size_t index) const
            {
                if (index >= size_)
                {
                    throw std::out_of_range("index is out of range");
                }
                return base_[index];
            }

            inline std::size_t size() const noexcept
            {
                return size_;
            }

            bool contains(const Modulus &value) const noexcept;

            bool isSubbaseOf(const RNSBase &superbase) const noexcept;

            inline bool isSuperbaseOf(const RNSBase &subbase) const noexcept
            {
                return subbase.isSubbaseOf(*this);
            }

            inline bool isProperSubbaseOf(const RNSBase &superbase) const noexcept
            {
                return (size_ < superbase.size_) && isSubbaseOf(superbase);
            }

            inline bool isProperSuperbaseOf(const RNSBase &subbase) const noexcept
            {
                return (size_ > subbase.size_) && !isSubbaseOf(subbase);
                // FIXME: wrong? isSuperbaseOf(subbase)?
            }

            RNSBase extend(const Modulus &value) const;

            RNSBase extend(const RNSBase &other) const;

            RNSBase drop() const;

            RNSBase drop(const Modulus &value) const;

            void decompose(std::uint64_t *value) const;

            void decomposeArray(std::uint64_t *value, std::size_t count) const;

            void compose(std::uint64_t *value) const;

            void composeArray(std::uint64_t *value, std::size_t count) const;

            inline const Modulus *base() const noexcept
            {
                return base_.get();
            }

            inline const std::uint64_t *baseProd() const noexcept
            {
                return base_prod_.get();
            }

            inline const std::uint64_t *puncturedProdArray() const noexcept
            {
                return punctured_prod_array_.get();
            }

            inline const MultiplyUIntModOperand *invPuncturedProdModBaseArray() const noexcept
            {
                return inv_punctured_prod_mod_base_array_.get();
            }

        private:
            RNSBase() : size_(0)
            {}

            bool initialize();

            std::size_t size_;

            HostArray<Modulus> base_;

            HostArray<std::uint64_t> base_prod_;

            HostArray<std::uint64_t> punctured_prod_array_;

            HostArray<MultiplyUIntModOperand> inv_punctured_prod_mod_base_array_;
        };

        class BaseConverter
        {
            friend class BaseConverterCuda;
        public:
            BaseConverter(const RNSBase &ibase, const RNSBase &obase)
                : ibase_(ibase), obase_(obase)
            {
                initialize();
            }

            inline std::size_t ibaseSize() const noexcept
            {
                return ibase_.size();
            }

            inline std::size_t obaseSize() const noexcept
            {
                return obase_.size();
            }

            inline const RNSBase &ibase() const noexcept
            {
                return ibase_;
            }

            inline const RNSBase &obase() const noexcept
            {
                return obase_;
            }

            void fastConvert(ConstHostPointer<uint64_t> in, HostPointer<uint64_t> out) const;

            void fastConvertArray(ConstHostPointer<uint64_t> in, HostPointer<uint64_t> out, size_t count) const;

            // The exact base convertion function, only supports obase size of 1.
            void exactConvertArray(ConstHostPointer<uint64_t> in, HostPointer<uint64_t> out, size_t in_count) const;

        private:
            BaseConverter(const BaseConverter &copy) = delete;

            BaseConverter(BaseConverter &&source) = delete;

            BaseConverter &operator=(const BaseConverter &assign) = delete;

            BaseConverter &operator=(BaseConverter &&assign) = delete;

            void initialize();

            RNSBase ibase_;

            RNSBase obase_;

            HostArray<HostArray<std::uint64_t>> base_change_matrix_;
        };

        class RNSTool
        {
            friend class RNSToolCuda;
        public:
            /**
            @throws std::invalid_argument if poly_modulus_degree is out of range, coeff_modulus is not valid, or pool is
            invalid.
            @throws std::logic_error if coeff_modulus and extended bases do not support NTT or are not coprime.
            */
            RNSTool(
                std::size_t poly_modulus_degree, const RNSBase &coeff_modulus, const Modulus &plain_modulus);

            /**
            @param[in] input Must be in RNS form, i.e. coefficient must be less than the associated modulus.
            */
            void divideAndRoundqLastInplace(HostPointer<uint64_t> input) const;

            void divideAndRoundqLastNttInplace(
                HostPointer<uint64_t> input, const NTTTables* rns_ntt_tables) const;

            /**
            Shenoy-Kumaresan conversion from Bsk to q
            */
            void fastbconvSk(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const;

            /**
            Montgomery reduction mod q; changes base from Bsk U {m_tilde} to Bsk
            */
            void smMrq(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const;

            /**
            Divide by q and fast floor from q U Bsk to Bsk
            */
            void fastFloor(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const;

            /**
            Fast base conversion from q to Bsk U {m_tilde}
            */
            void fastbconvmTilde(ConstHostPointer<uint64_t> input, HostPointer<uint64_t> destination) const;

            /**
            Compute round(t/q * |input|_q) mod t exactly
            */
            void decryptScaleAndRound(ConstHostPointer<uint64_t> phase, HostPointer<uint64_t> destination) const;

            /**
            Remove the last q for bgv ciphertext
            */
            void modTAndDivideqLastInplace(HostPointer<uint64_t> input) const;

            /**
            Compute mod t
            */
            void decryptModt(ConstHostPointer<uint64_t> phase, HostPointer<uint64_t> destination) const;

            inline auto invqLastModq() const noexcept
            {
                return inv_q_last_mod_q_.get();
            }

            inline auto baseBskNttTables() const noexcept
            {
                // std::cout << "baseBskNttTables count = " << base_Bsk_ntt_tables_.size() << std::endl;
                return base_Bsk_ntt_tables_.get();
            }

            inline auto baseq() const noexcept
            {
                return base_q_.get();
            }

            inline auto baseB() const noexcept
            {
                return base_B_.get();
            }

            inline auto baseBsk() const noexcept
            {
                return base_Bsk_.get();
            }

            inline auto baseBskmTilde() const noexcept
            {
                return base_Bsk_m_tilde_.get();
            }

            inline auto basetGamma() const noexcept
            {
                return base_t_gamma_.get();
            }

            inline auto &mTilde() const noexcept
            {
                return m_tilde_;
            }

            inline auto &msk() const noexcept
            {
                return m_sk_;
            }

            inline auto &t() const noexcept
            {
                return t_;
            }

            inline auto &gamma() const noexcept
            {
                return gamma_;
            }

            inline auto &invqLastModt() const noexcept
            {
                return inv_q_last_mod_t_;
            }

            inline const uint64_t &qLastModt() const noexcept
            {
                return q_last_mod_t_;
            }

        private:
            RNSTool(const RNSTool &copy) = delete;

            RNSTool(RNSTool &&source) = delete;

            RNSTool &operator=(const RNSTool &assign) = delete;

            RNSTool &operator=(RNSTool &&assign) = delete;

            /**
            Generates the pre-computations for the given parameters.
            */
            void initialize(std::size_t poly_modulus_degree, const RNSBase &q, const Modulus &t);

            std::size_t coeff_count_ = 0;

            HostObject<RNSBase> base_q_;

            HostObject<RNSBase> base_B_;

            HostObject<RNSBase> base_Bsk_;

            HostObject<RNSBase> base_Bsk_m_tilde_;

            HostObject<RNSBase> base_t_gamma_;

            // Base converter: q --> B_sk
            HostObject<BaseConverter> base_q_to_Bsk_conv_;

            // Base converter: q --> {m_tilde}
            HostObject<BaseConverter> base_q_to_m_tilde_conv_;

            // Base converter: B --> q
            HostObject<BaseConverter> base_B_to_q_conv_;

            // Base converter: B --> {m_sk}
            HostObject<BaseConverter> base_B_to_m_sk_conv_;

            // Base converter: q --> {t, gamma}
            HostObject<BaseConverter> base_q_to_t_gamma_conv_;

            // Base converter: q --> t
            HostObject<BaseConverter> base_q_to_t_conv_;

            // prod(q)^(-1) mod Bsk
            HostArray<MultiplyUIntModOperand> inv_prod_q_mod_Bsk_;

            // prod(q)^(-1) mod m_tilde
            MultiplyUIntModOperand neg_inv_prod_q_mod_m_tilde_;

            // prod(B)^(-1) mod m_sk
            MultiplyUIntModOperand inv_prod_B_mod_m_sk_;

            // gamma^(-1) mod t
            MultiplyUIntModOperand inv_gamma_mod_t_;

            // prod(B) mod q
            HostArray<std::uint64_t> prod_B_mod_q_;

            // m_tilde^(-1) mod Bsk
            HostArray<MultiplyUIntModOperand> inv_m_tilde_mod_Bsk_;

            // prod(q) mod Bsk
            HostArray<std::uint64_t> prod_q_mod_Bsk_;

            // -prod(q)^(-1) mod {t, gamma}
            HostArray<MultiplyUIntModOperand> neg_inv_q_mod_t_gamma_;

            // prod({t, gamma}) mod q
            HostArray<MultiplyUIntModOperand> prod_t_gamma_mod_q_;

            // q[last]^(-1) mod q[i] for i = 0..last-1
            HostArray<MultiplyUIntModOperand> inv_q_last_mod_q_;

            // NTTTables for Bsk
            HostArray<NTTTables> base_Bsk_ntt_tables_;

            Modulus m_tilde_;

            Modulus m_sk_;

            Modulus t_;

            Modulus gamma_;

            std::uint64_t inv_q_last_mod_t_ = 1;

            std::uint64_t q_last_mod_t_ = 1;
        };
    } // namespace util
} // namespace seal
