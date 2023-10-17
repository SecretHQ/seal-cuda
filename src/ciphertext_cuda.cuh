#pragma once

#include <iostream>
#include "utils/devicearray.cuh"
#include "ciphertext.h"
#include "context_cuda.cuh"

namespace troy {

    class EvaluatorCuda;

    class CiphertextCuda {

    public:
        
        using ct_coeff_type = std::uint64_t;

        CiphertextCuda(): data_() {}

        CiphertextCuda(const Ciphertext& host):
            parms_id_(host.parms_id_),
            is_ntt_form_(host.is_ntt_form_),
            size_(host.size_),
            poly_modulus_degree_(host.poly_modulus_degree_),
            coeff_modulus_size_(host.coeff_modulus_size_),
            scale_(host.scale_),
            correction_factor_(host.correction_factor_),
            data_(host.data_) {}

        CiphertextCuda(const CiphertextCuda& copy) = default;
        CiphertextCuda(CiphertextCuda &&source) = default;

        

        CiphertextCuda& operator=(const CiphertextCuda& copy) = default;
        CiphertextCuda& operator=(CiphertextCuda &&source) = default;

        Ciphertext cpu() const {
            Ciphertext ret;
            ret.parms_id_ = parms_id_;
            ret.is_ntt_form_ = is_ntt_form_;
            ret.size_ = size_;
            ret.poly_modulus_degree_ = poly_modulus_degree_;
            ret.coeff_modulus_size_ = coeff_modulus_size_;
            ret.scale_ = scale_;
            ret.correction_factor_ = correction_factor_;
            ret.data_ = data_.toHost();
            return ret;
        }

        inline Ciphertext toHost() const {return cpu();}

        inline bool isTransparent() const {return cpu().isTransparent();}

        inline uint64_t& correctionFactor() noexcept 
            {return correction_factor_;}
        inline const uint64_t& correctionFactor() const noexcept 
            {return correction_factor_;}
        inline size_t size() const noexcept {return size_;}
        inline util::DevicePointer<uint64_t> data() {return data_.asPointer();}
        inline util::ConstDevicePointer<uint64_t> data() const {return data_.asPointer();}
        inline util::DevicePointer<uint64_t> data(size_t i) {
            return data_.asPointer() + coeff_modulus_size_ * poly_modulus_degree_ * i;
        }
        inline util::ConstDevicePointer<uint64_t> data(size_t i) const {
            return data_.asPointer() + coeff_modulus_size_ * poly_modulus_degree_ * i;
        }
        inline void resize(const SEALContextCuda& context, ParmsID parms_id, size_t size) {
            auto context_data_ptr = context.getContextData(parms_id);
            if (!context_data_ptr) 
                throw std::invalid_argument("parms_id is not valid for encryption parameters");
            auto &parms = context_data_ptr->parms();
            parms_id_ = context_data_ptr->parmsID();
            resizeInternal(size, parms.polyModulusDegree(), parms.coeffModulus().size());
        }
        
        inline void resize(const SEALContextCuda &context, std::size_t size)
        {
            auto parms_id = context.firstParmsID();
            resize(context, parms_id, size);
        }
        
        inline void resize(std::size_t size)
        {
            // Note: poly_modulus_degree_ and coeff_modulus_size_ are either valid
            // or coeff_modulus_size_ is zero (in which case no memory is allocated).
            resizeInternal(size, poly_modulus_degree_, coeff_modulus_size_);
        }

        inline ParmsID& parmsID() noexcept {return parms_id_;}
        inline const ParmsID& parmsID() const noexcept {return parms_id_;}
        inline bool isNttForm() const noexcept {return is_ntt_form_;}
        inline bool& isNttForm() noexcept {return is_ntt_form_;}
        inline double& scale() noexcept {return scale_;}
        inline double scale() const noexcept {return scale_;}
        inline const util::DeviceDynamicArray<ct_coeff_type>& dynArray() const {return data_;}
        inline util::DeviceDynamicArray<ct_coeff_type>& dynArray() {return data_;}
        inline size_t polyCoeffSize() const {
            return poly_modulus_degree_ * coeff_modulus_size_;
        }

        explicit CiphertextCuda(const SEALContextCuda &context)
            : data_()
        {
            // Allocate memory but don't resize
            reserve(context, 2);
        }

        explicit CiphertextCuda(
            const SEALContextCuda &context, ParmsID parms_id)
            : data_()
        {
            // Allocate memory but don't resize
            reserve(context, parms_id, 2);
        }
        
        explicit CiphertextCuda(
            const SEALContextCuda &context, ParmsID parms_id, std::size_t size_capacity)
            : data_()
        {
            // Allocate memory but don't resize
            reserve(context, parms_id, size_capacity);
        }

        void reserve(const SEALContextCuda &context, ParmsID parms_id, std::size_t size_capacity) 
        {

            auto context_data_ptr = context.getContextData(parms_id);
            if (!context_data_ptr)
            {
                throw std::invalid_argument("parms_id is not valid for encryption parameters");
            }

            // Need to set parms_id first
            auto &parms = context_data_ptr->parms();
            parms_id_ = context_data_ptr->parmsID();

            reserveInternal(size_capacity, parms.polyModulusDegree(), parms.coeffModulus().size());
        }

        inline void reserve(const SEALContextCuda &context, std::size_t size_capacity)
        {
            auto parms_id = context.firstParmsID();
            reserve(context, parms_id, size_capacity);
        }

        inline void reserve(std::size_t size_capacity)
        {
            // Note: poly_modulus_degree_ and coeff_modulus_size_ are either valid
            // or coeff_modulus_size_ is zero (in which case no memory is allocated).
            reserveInternal(size_capacity, poly_modulus_degree_, coeff_modulus_size_);
        }

        inline void release() noexcept
        {
            parms_id_ = parmsIDZero;
            is_ntt_form_ = false;
            size_ = 0;
            poly_modulus_degree_ = 0;
            coeff_modulus_size_ = 0;
            scale_ = 1.0;
            correction_factor_ = 1;
            data_.release();
        }

        
        inline std::size_t coeffModulusSize() const noexcept
        {
            return coeff_modulus_size_;
        }
        
        inline std::size_t polyModulusDegree() const noexcept
        {
            return poly_modulus_degree_;
        }

        inline std::size_t sizeCapacity() const noexcept
        {
            std::size_t poly_uint64_count = poly_modulus_degree_ * coeff_modulus_size_;
            return poly_uint64_count ? data_.capacity() / poly_uint64_count : std::size_t(0);
        }

        void save(std::ostream& stream) const;
        void saveTerms(std::ostream& stream, EvaluatorCuda& evaluator, const std::vector<size_t>& termIds) const;
        void load(std::istream& stream);
        void load(std::istream& stream, const SEALContextCuda& context);
        void loadTerms(std::istream& stream, EvaluatorCuda& evaluator, const std::vector<size_t>& termIds);

        inline std::uint64_t seed() const noexcept {return seed_;}
        inline std::uint64_t& seed() {return seed_;}

    private:
    
        void reserveInternal(
            std::size_t size_capacity, std::size_t poly_modulus_degree, std::size_t coeff_modulus_size)
        {
            if (size_capacity < SEAL_CIPHERTEXT_SIZE_MIN || size_capacity > SEAL_CIPHERTEXT_SIZE_MAX)
            {
                throw std::invalid_argument("invalid size_capacity");
            }

            size_t new_data_capacity = size_capacity * poly_modulus_degree * coeff_modulus_size;
            size_t new_data_size = std::min<size_t>(new_data_capacity, data_.size());

            // First reserve, then resize
            data_.reserve(new_data_capacity);
            data_.resize(new_data_size);

            // Set the size
            size_ = std::min<size_t>(size_capacity, size_);
            poly_modulus_degree_ = poly_modulus_degree;
            coeff_modulus_size_ = coeff_modulus_size;
        }

        void resizeInternal(size_t size, size_t poly_modulus_degree, size_t coeff_modulus_size) {
            // std::cout << "resize internal " << size << " " << poly_modulus_degree << " " << coeff_modulus_size << std::endl;
            if ((size < SEAL_CIPHERTEXT_SIZE_MIN && size != 0) || size > SEAL_CIPHERTEXT_SIZE_MAX)
            {
                throw std::invalid_argument("invalid size");
            }
            size_t new_data_size = size * poly_modulus_degree * coeff_modulus_size;
            data_.resize(new_data_size);
            // std::cout << "resize internal: after: " << data_.size() << std::endl;
            size_ = size;
            poly_modulus_degree_ = poly_modulus_degree;
            coeff_modulus_size_ = coeff_modulus_size;
        }

        ParmsID parms_id_ = parmsIDZero;

        bool is_ntt_form_ = false;

        std::size_t size_ = 0;

        std::size_t poly_modulus_degree_ = 0;

        std::size_t coeff_modulus_size_ = 0;

        double scale_ = 1.0;

        std::uint64_t correction_factor_ = 1;

        util::DeviceDynamicArray<ct_coeff_type> data_;

        std::uint64_t seed_ = 0;
    };

}