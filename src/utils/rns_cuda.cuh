#pragma once

#include "rns.h"
#include "devicearray.cuh"
#include "ntt_cuda.cuh"



namespace troy {

    namespace util {

        class RNSBaseCuda {
        public:
            RNSBaseCuda(const RNSBase& copy):
                size_(copy.size_),
                base_(copy.base_),
                base_prod_(copy.base_prod_),
                punctured_prod_array_(copy.punctured_prod_array_),
                inv_punctured_prod_mod_base_array_(copy.inv_punctured_prod_mod_base_array_)
            {}
            RNSBaseCuda(RNSBaseCuda&& move) = default;
            RNSBaseCuda(const RNSBaseCuda& copy) = default;

            void decomposeArray(DevicePointer<uint64_t> value, size_t coeff_count) const;
            void decomposeArrayKeepOrder(DevicePointer<uint64_t> value, size_t coeff_count) const;
            void composeArray(DevicePointer<uint64_t> value, size_t coeff_count) const;
            size_t size() const {return size_;}
            ConstDevicePointer<Modulus> base() const {return base_.asPointer();}
            ConstDevicePointer<MultiplyUIntModOperand> invPuncturedProdModBaseArray() const {
                return inv_punctured_prod_mod_base_array_.asPointer();
            }
            ConstDevicePointer<uint64_t> baseProd() const {
                return base_prod_.asPointer();
            }

        private:
            std::size_t size_;
            DeviceArray<Modulus> base_;
            DeviceArray<uint64_t> base_prod_;
            DeviceArray<uint64_t> punctured_prod_array_;
            DeviceArray<MultiplyUIntModOperand> inv_punctured_prod_mod_base_array_;
            mutable DeviceDynamicArray<uint64_t> copy_;
            mutable DeviceDynamicArray<uint64_t> temp_;
        };

        class BaseConverterCuda {
        public:
            BaseConverterCuda(const BaseConverter& copy):
                ibase_(copy.ibase_), obase_(copy.obase_) 
            {
                base_change_matrix_ = DeviceArray<uint64_t>(obase_.size() * ibase_.size());;
                size_t isize = ibase_.size();
                for (size_t i = 0; i < obase_.size(); i++) {
                    KernelProvider::copy<uint64_t>(
                        base_change_matrix_.get() + i * isize, 
                        copy.base_change_matrix_[i].get(), isize);
                }
            }
            void fastConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const;
            void exactConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const;
        private:
            BaseConverterCuda(const BaseConverterCuda& copy) = delete;
            BaseConverterCuda(BaseConverterCuda&& move) = delete;
            BaseConverterCuda& operator =(const BaseConverterCuda&) = delete;
            BaseConverterCuda& operator =(BaseConverterCuda&&) = delete;
            RNSBaseCuda ibase_;
            RNSBaseCuda obase_;
            DeviceArray<uint64_t> base_change_matrix_; // obase_ * ibase_
            mutable DeviceDynamicArray<uint64_t> temp_;
            mutable DeviceDynamicArray<uint64_t> aggregated_rounded_v_;
        };

        class RNSToolCuda {
        public:
            RNSToolCuda(const RNSTool& copy):
                coeff_count_(copy.coeff_count_),
                base_q_(copy.base_q_.isNull() ? nullptr : new RNSBaseCuda(*copy.base_q_)),
                base_B_(copy.base_B_.isNull() ? nullptr : new RNSBaseCuda(*copy.base_B_)),
                base_Bsk_(copy.base_Bsk_.isNull() ? nullptr : new RNSBaseCuda(*copy.base_Bsk_)),
                base_Bsk_m_tilde_(copy.base_Bsk_m_tilde_.isNull() ? nullptr : new RNSBaseCuda(*copy.base_Bsk_m_tilde_)),
                base_t_gamma_(copy.base_t_gamma_.isNull() ? nullptr : new RNSBaseCuda(*copy.base_t_gamma_)),
                base_q_to_Bsk_conv_(copy.base_q_to_Bsk_conv_.isNull() ? nullptr : new BaseConverterCuda(*copy.base_q_to_Bsk_conv_)),
                base_q_to_m_tilde_conv_(copy.base_q_to_m_tilde_conv_.isNull() ? nullptr : new BaseConverterCuda(*copy.base_q_to_m_tilde_conv_)),
                base_B_to_q_conv_(copy.base_B_to_q_conv_.isNull() ? nullptr : new BaseConverterCuda(*copy.base_B_to_q_conv_)),
                base_B_to_m_sk_conv_(copy.base_B_to_m_sk_conv_.isNull() ? nullptr : new BaseConverterCuda(*copy.base_B_to_m_sk_conv_)),
                base_q_to_t_gamma_conv_(copy.base_q_to_t_gamma_conv_.isNull() ? nullptr : new BaseConverterCuda(*copy.base_q_to_t_gamma_conv_)),
                base_q_to_t_conv_(copy.base_q_to_t_conv_.isNull() ? nullptr : new BaseConverterCuda(*copy.base_q_to_t_conv_)),
                inv_prod_q_mod_Bsk_(copy.inv_prod_q_mod_Bsk_),
                neg_inv_prod_q_mod_m_tilde_(copy.neg_inv_prod_q_mod_m_tilde_),
                inv_prod_B_mod_m_sk_(copy.inv_prod_B_mod_m_sk_),
                inv_gamma_mod_t_(copy.inv_gamma_mod_t_),
                prod_B_mod_q_(copy.prod_B_mod_q_),
                inv_m_tilde_mod_Bsk_(copy.inv_m_tilde_mod_Bsk_),
                prod_q_mod_Bsk_(copy.prod_q_mod_Bsk_),
                neg_inv_q_mod_t_gamma_(copy.neg_inv_q_mod_t_gamma_),
                prod_t_gamma_mod_q_(copy.prod_t_gamma_mod_q_),
                inv_q_last_mod_q_(copy.inv_q_last_mod_q_),
                m_tilde_(copy.m_tilde_),
                m_sk_(copy.m_sk_),
                t_(copy.t_),
                gamma_(copy.gamma_),    
                inv_q_last_mod_t_(copy.inv_q_last_mod_t_),            
                q_last_mod_t_(copy.q_last_mod_t_)
            {
                // std::cout << "constructing rns tool\n";
                size_t n = copy.base_Bsk_ntt_tables_.size();
                base_Bsk_ntt_tables_support = HostArray<NTTTablesCuda>(n);
                for (size_t i = 0; i < n; i++) {
                    base_Bsk_ntt_tables_support[i] = NTTTablesCuda(copy.base_Bsk_ntt_tables_[i]);
                }
                base_Bsk_ntt_tables_ = DeviceArray<NTTTablesCuda>(base_Bsk_ntt_tables_support);
                q_last_half_ = (*copy.baseq())[copy.baseq()->size()-1].value() >> 1;

                Modulus* cuda_memory = KernelProvider::malloc<Modulus>(1);
                KernelProvider::copy<Modulus>(cuda_memory, &m_tilde_, 1);
                m_tilde_cuda_ = DeviceObject<Modulus>(cuda_memory);

                cuda_memory = KernelProvider::malloc<Modulus>(1);
                KernelProvider::copy<Modulus>(cuda_memory, &m_sk_, 1);
                m_sk_cuda_ = DeviceObject<Modulus>(cuda_memory);

                cuda_memory = KernelProvider::malloc<Modulus>(1);
                KernelProvider::copy<Modulus>(cuda_memory, &t_, 1);
                t_cuda_ = DeviceObject<Modulus>(cuda_memory);

                cuda_memory = KernelProvider::malloc<Modulus>(1);
                KernelProvider::copy<Modulus>(cuda_memory, &gamma_, 1);
                gamma_cuda_ = DeviceObject<Modulus>(cuda_memory);

                // temp = HostObject(new Modulus(m_sk_));
                // gamma_cuda_ = DeviceObject<Modulus>(temp);
                
                // temp = HostObject(new Modulus(t_));
                // t_cuda_ = DeviceObject<Modulus>(temp);
                
                // temp = HostObject(new Modulus(gamma_));
                // gamma_cuda_ = DeviceObject<Modulus>(temp);
                // std::cout << "constructing rns tool done\n";

            }
            
            void divideAndRoundqLastInplace(DevicePointer<uint64_t> input) const;

            void divideAndRoundqLastNttInplace(
                DevicePointer<uint64_t> input, ConstDevicePointer<NTTTablesCuda> rns_ntt_tables) const;

            void fastbconvSk(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const;

            void smMrq(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const;

            void fastFloor(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const;

            void fastbconvmTilde(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const;

            void decryptScaleAndRound(ConstDevicePointer<uint64_t> phase, DevicePointer<uint64_t> destination) const;

            void modTAndDivideqLastInplace(DevicePointer<uint64_t> input) const;

            void decryptModt(ConstDevicePointer<uint64_t> phase, DevicePointer<uint64_t> destination) const;
        

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

            std::size_t coeff_count_ = 0;

            HostObject<RNSBaseCuda> base_q_;

            HostObject<RNSBaseCuda> base_B_;

            HostObject<RNSBaseCuda> base_Bsk_;

            HostObject<RNSBaseCuda> base_Bsk_m_tilde_;

            HostObject<RNSBaseCuda> base_t_gamma_;

            // Base converter: q --> B_sk
            HostObject<BaseConverterCuda> base_q_to_Bsk_conv_;

            // Base converter: q --> {m_tilde}
            HostObject<BaseConverterCuda> base_q_to_m_tilde_conv_;

            // Base converter: B --> q
            HostObject<BaseConverterCuda> base_B_to_q_conv_;

            // Base converter: B --> {m_sk}
            HostObject<BaseConverterCuda> base_B_to_m_sk_conv_;

            // Base converter: q --> {t, gamma}
            HostObject<BaseConverterCuda> base_q_to_t_gamma_conv_;

            // Base converter: q --> t
            HostObject<BaseConverterCuda> base_q_to_t_conv_;

            // prod(q)^(-1) mod Bsk
            DeviceArray<MultiplyUIntModOperand> inv_prod_q_mod_Bsk_;

            // prod(q)^(-1) mod m_tilde
            MultiplyUIntModOperand neg_inv_prod_q_mod_m_tilde_;

            // prod(B)^(-1) mod m_sk
            MultiplyUIntModOperand inv_prod_B_mod_m_sk_;

            // gamma^(-1) mod t
            MultiplyUIntModOperand inv_gamma_mod_t_;

            // prod(B) mod q
            DeviceArray<std::uint64_t> prod_B_mod_q_;

            // m_tilde^(-1) mod Bsk
            DeviceArray<MultiplyUIntModOperand> inv_m_tilde_mod_Bsk_;

            // prod(q) mod Bsk
            DeviceArray<std::uint64_t> prod_q_mod_Bsk_;

            // -prod(q)^(-1) mod {t, gamma}
            DeviceArray<MultiplyUIntModOperand> neg_inv_q_mod_t_gamma_;

            // prod({t, gamma}) mod q
            DeviceArray<MultiplyUIntModOperand> prod_t_gamma_mod_q_;

            // q[last]^(-1) mod q[i] for i = 0..last-1
            DeviceArray<MultiplyUIntModOperand> inv_q_last_mod_q_;

            // NTTTables for Bsk
            HostArray<NTTTablesCuda> base_Bsk_ntt_tables_support;
            DeviceArray<NTTTablesCuda> base_Bsk_ntt_tables_;

            Modulus m_tilde_;
            Modulus m_sk_;
            Modulus t_;
            Modulus gamma_;


            DeviceObject<Modulus> m_tilde_cuda_;
            DeviceObject<Modulus> m_sk_cuda_;
            DeviceObject<Modulus> t_cuda_;
            DeviceObject<Modulus> gamma_cuda_;

            std::uint64_t inv_q_last_mod_t_ = 1;
            std::uint64_t q_last_mod_t_ = 1;

            uint64_t q_last_half_;
            uint64_t gamma_half;
        
            RNSToolCuda(const RNSToolCuda& copy) = delete;
            RNSToolCuda(RNSToolCuda&& move) = delete;
            RNSToolCuda& operator =(const RNSToolCuda&) = delete;
            RNSToolCuda& operator =(RNSToolCuda&&) = delete;

            mutable DeviceDynamicArray<uint64_t> temp_;
            mutable DeviceDynamicArray<uint64_t> temp_t_gamma_;

        };

    }
}