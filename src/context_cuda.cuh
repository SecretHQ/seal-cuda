#pragma once

#include "context.h"
#include "encryptionparams_cuda.cuh"
#include "utils/ntt_cuda.cuh"
#include "utils/rns_cuda.cuh"
#include "utils/galois_cuda.cuh"

namespace troy {

    class SEALContextCuda {
    public:

        class ContextDataCuda {

            friend class SEALContextCuda;
        
        public:
            ContextDataCuda() = delete;
            ContextDataCuda(const ContextDataCuda& copy) = delete;
            ContextDataCuda(ContextDataCuda&& move) = default;
            ContextDataCuda& operator=(const ContextDataCuda& copy) = delete;
            ContextDataCuda& operator=(ContextDataCuda&& move) = default;

            // Note that calling this constructor
            // sets the created to have prev-context-data and next-context-data
            // to nullptr. You need to set them up manually.
            ContextDataCuda(const SEALContext::ContextData& contextData):
                qualifiers_(contextData.qualifiers()),
                parms_(contextData.parms()),
                total_coeff_modulus_bit_count_(contextData.totalCoeffModulusBitCount()),
                plain_upper_half_threshold_(contextData.plainUpperHalfThreshold()),
                coeff_modulus_mod_plain_modulus_(contextData.coeffModulusModPlainModulus()),
                prev_context_data_(),
                next_context_data_(nullptr),
                chain_index_(contextData.chainIndex()),
                total_coeff_modulus_(contextData.total_coeff_modulus_),
                coeff_div_plain_modulus_(contextData.coeff_div_plain_modulus_),
                plain_upper_half_increment_(contextData.plain_upper_half_increment_),
                upper_half_threshold_(contextData.upper_half_threshold_),
                upper_half_increment_(contextData.upper_half_increment_)
            { 
                // std::cout << "constructing context data cuda" << std::endl;
                rns_tool_ = new util::RNSToolCuda(*contextData.rns_tool_);
                // std::cout << "constructing context data cuda: rns tool created" << std::endl;
                size_t n = contextData.small_ntt_tables_.size();
                small_ntt_tables_support_ = util::HostArray<util::NTTTablesCuda>(n);
                for (size_t i = 0; i < n; i++) {
                    small_ntt_tables_support_[i] = util::NTTTablesCuda(contextData.small_ntt_tables_[i]);
                }
                small_ntt_tables_ = util::DeviceArray(small_ntt_tables_support_);

                n = contextData.plain_ntt_tables_.size();
                plain_ntt_tables_support_ = util::HostArray<util::NTTTablesCuda>(n);
                for (size_t i = 0; i < n; i++) {
                    plain_ntt_tables_support_[i] = util::NTTTablesCuda(contextData.plain_ntt_tables_[i]);
                }
                plain_ntt_tables_ = util::DeviceArray(plain_ntt_tables_support_);
                galois_tool_ = new util::GaloisToolCuda(util::getPowerOfTwo(contextData.parms_.polyModulusDegree()));
                // std::cout << "constructing context data cuda done" << std::endl;
            }

            const EncryptionParametersCuda& parms() const {return parms_;}
            inline const ParmsID& parmsID() const noexcept {
                return parms_.parmsID();
            }
            inline int totalCoeffModulusBitCount() const {
                return total_coeff_modulus_bit_count_;
            }
            
            inline util::ConstDevicePointer<util::NTTTablesCuda> smallNTTTables() const {
                return small_ntt_tables_.asPointer();
            }
            
            inline util::ConstDevicePointer<util::NTTTablesCuda> plainNTTTables() const {
                return plain_ntt_tables_.asPointer();
            }

            inline const util::RNSToolCuda* rnsTool() const {
                return rns_tool_.get();
            }

            inline size_t chainIndex() const {
                return chain_index_;
            }

            
            inline std::shared_ptr<const ContextDataCuda> prevContextData() const noexcept
            {
                return prev_context_data_.lock();
            }

            inline std::shared_ptr<const ContextDataCuda> nextContextData() const noexcept
            {
                return next_context_data_;
            }

            inline util::ConstDevicePointer<util::MultiplyUIntModOperand> coeffDivPlainModulus() const noexcept
            {
                return coeff_div_plain_modulus_;
            }

            inline std::uint64_t plainUpperHalfThreshold() const noexcept
            {
                return plain_upper_half_threshold_;
            }

            inline util::ConstDevicePointer<uint64_t> plainUpperHalfIncrement() const noexcept
            {
                return plain_upper_half_increment_;
            }

            inline util::ConstDevicePointer<uint64_t> upperHalfThreshold() const noexcept{
                return upper_half_threshold_;
            }

            inline util::ConstDevicePointer<uint64_t> upperHalfIncrement() const noexcept{
                return upper_half_increment_;
            }

            inline std::uint64_t coeffModulusModPlainModulus() const noexcept{
                return coeff_modulus_mod_plain_modulus_;
            }
            
            inline EncryptionParameterQualifiers qualifiers() const noexcept
            {
                return qualifiers_;
            }

            inline const util::GaloisToolCuda* galoisTool() const {return galois_tool_.get();}

            inline const util::DeviceArray<uint64_t>& totalCoeffModulus() const {
                return total_coeff_modulus_;
            }


        private:

            EncryptionParametersCuda parms_;
            EncryptionParameterQualifiers qualifiers_;

            util::HostObject<util::RNSToolCuda> rns_tool_;
            util::DeviceArray<util::NTTTablesCuda> small_ntt_tables_;
            util::DeviceArray<util::NTTTablesCuda> plain_ntt_tables_;
            util::HostArray<util::NTTTablesCuda> small_ntt_tables_support_;
            util::HostArray<util::NTTTablesCuda> plain_ntt_tables_support_;

            util::HostObject<util::GaloisToolCuda> galois_tool_;

            util::DeviceArray<uint64_t> total_coeff_modulus_;
            
            int total_coeff_modulus_bit_count_ = 0;
            
            util::DeviceArray<util::MultiplyUIntModOperand> coeff_div_plain_modulus_;
            
            uint64_t plain_upper_half_threshold_ = 0;

            util::DeviceArray<uint64_t> plain_upper_half_increment_;
            util::DeviceArray<uint64_t> upper_half_threshold_;
            util::DeviceArray<uint64_t> upper_half_increment_;

            uint64_t coeff_modulus_mod_plain_modulus_ = 0;
            
            std::weak_ptr<const ContextDataCuda> prev_context_data_;

            std::shared_ptr<const ContextDataCuda> next_context_data_{ nullptr };

            std::size_t chain_index_ = 0;

        };

        SEALContextCuda(const SEALContext& context): context_host_(context) {
            initialize(context);
        }
        
        SEALContextCuda(const SEALContextCuda& copy) = default;
        SEALContextCuda(SEALContextCuda&& move) = default;

        SEALContextCuda(EncryptionParameters parms, bool expand_mod_chain = true, SecurityLevel sec_level = SecurityLevel::tc128) :
            context_host_(parms, expand_mod_chain, sec_level) 
        {
            initialize(context_host_);
        }

        SEALContextCuda(EncryptionParametersCuda parms, bool expand_mod_chain = true, SecurityLevel sec_level = SecurityLevel::tc128):
            context_host_(parms.host(), expand_mod_chain, sec_level)
        {
            initialize(context_host_);
        }

        inline std::shared_ptr<ContextDataCuda> getContextData(ParmsID parms_id) const {
            auto data = context_data_map_.find(parms_id);
            return 
                (data != context_data_map_.end()) ?
                data->second : std::shared_ptr<ContextDataCuda>{nullptr};
        }

        inline std::shared_ptr<ContextDataCuda> firstContextData() const {
            return getContextData(first_parms_id_);
        }

        inline std::shared_ptr<ContextDataCuda> lastContextData() const {
            return getContextData(last_parms_id_);
        }

        inline std::shared_ptr<ContextDataCuda> keyContextData() const {
            return getContextData(key_parms_id_);
        }

        inline const ParmsID& keyParmsID() const {return key_parms_id_;}
        inline const ParmsID& firstParmsID() const {return first_parms_id_;}
        inline const ParmsID& lastParmsID() const {return last_parms_id_;}


        inline bool using_keyswitching() const {
            return using_keyswitching_;
        }

        inline const SEALContext& host() const {return context_host_;}
    
    private:

        void initialize(const SEALContext& context);

        // ParmsID createNextContextData(const ParmsID &prev_parms);
        
        ParmsID key_parms_id_;
        ParmsID first_parms_id_;
        ParmsID last_parms_id_;

        std::unordered_map<ParmsID, std::shared_ptr<ContextDataCuda>, std::TroyHashParmsID> context_data_map_{};

        SecurityLevel sec_level_;
        bool using_keyswitching_;

        SEALContext context_host_; // todo: delete this

    };

}