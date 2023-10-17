#include "ciphertext_cuda.cuh"
#include "serialize.h"
#include "utils/rlwe_cuda.cuh"
#include "evaluator_cuda.cuh"

namespace troy {

    void CiphertextCuda::save(std::ostream& stream) const {
        savet(stream, &parms_id_);
        savet(stream, &is_ntt_form_);
        savet(stream, &size_);
        savet(stream, &poly_modulus_degree_);
        savet(stream, &coeff_modulus_size_);
        savet(stream, &scale_);
        savet(stream, &correction_factor_);
        savet(stream, &seed_);
        bool terms = false;
        savet(stream, &terms);
        if (seed_ != 0 && size_ > 2) {
            throw std::invalid_argument("Seed exists but size is not 2.");
        }
        if (seed_ != 0) {
            util::HostArray<uint64_t> r(poly_modulus_degree_ * coeff_modulus_size_);
            KernelProvider::retrieve(r.get(), data_.get(), r.size());
            size_t dataSize = r.size();
            savet(stream, &dataSize);
            stream.write(reinterpret_cast<char*>(r.get()), sizeof(CiphertextCuda::ct_coeff_type) * r.size());
        } else {
            auto r = data_.toHost();
            size_t dataSize = r.size();
            savet(stream, &dataSize);
            stream.write(reinterpret_cast<char*>(r.begin()), sizeof(CiphertextCuda::ct_coeff_type) * r.size());
        }
    }

    void CiphertextCuda::saveTerms(std::ostream& stream, EvaluatorCuda& evaluator, const std::vector<size_t>& termIds) const {
        savet(stream, &parms_id_);
        savet(stream, &is_ntt_form_);

        util::HostDynamicArray<ct_coeff_type> r;

        if (is_ntt_form_) {
            CiphertextCuda copy = *this;
            evaluator.transformFromNttInplace(copy);
            r = copy.data_.toHost();
        } else {
            r = data_.toHost();
        }

        savet(stream, &size_);
        savet(stream, &poly_modulus_degree_);
        savet(stream, &coeff_modulus_size_);
        savet(stream, &scale_);
        savet(stream, &correction_factor_);
        savet(stream, &seed_);
        bool terms = true;
        savet(stream, &terms);
        if (seed_ != 0) {
            throw std::invalid_argument("Seed is not zero.");
        }
        // save degree 0 terms
        for (size_t id: termIds) {
            for (size_t j = 0; j < coeff_modulus_size_; j++) {
                auto num = r[j * poly_modulus_degree_ + id];
                stream.write(reinterpret_cast<char*>(&num), sizeof(decltype(num)));
            }
        }
        size_t offset = poly_modulus_degree_ * coeff_modulus_size_;
        size_t dataSize = r.size() - offset;
        savet(stream, &dataSize);
        stream.write(reinterpret_cast<char*>(r.begin() + offset), sizeof(CiphertextCuda::ct_coeff_type) * dataSize);
    }

    void CiphertextCuda::load(std::istream& stream) {
        seed_ = 0;
        loadt(stream, &parms_id_);
        loadt(stream, &is_ntt_form_);
        loadt(stream, &size_);
        loadt(stream, &poly_modulus_degree_);
        loadt(stream, &coeff_modulus_size_);
        loadt(stream, &scale_);
        loadt(stream, &correction_factor_);
        uint64_t seed; loadt(stream, &seed);
        bool terms; loadt(stream, &terms);
        if (terms) throw std::invalid_argument("Trying to load a termed ciphertext, but indices is not specified");
        if (seed == 0) {
            size_t dataSize;
            loadt(stream, &dataSize);
            util::HostArray<ct_coeff_type> host(dataSize);
            stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(ct_coeff_type));
            data_.ensure(host.size());
            KernelProvider::copy(data_.get(), host.get(), dataSize);
        } else {
            throw std::invalid_argument("seed is not zero.");
        }
    }

    void CiphertextCuda::loadTerms(std::istream& stream, EvaluatorCuda& evaluator, const std::vector<size_t>& termIds) {
        seed_ = 0;
        loadt(stream, &parms_id_);
        loadt(stream, &is_ntt_form_);
        loadt(stream, &size_);
        loadt(stream, &poly_modulus_degree_);
        loadt(stream, &coeff_modulus_size_);
        loadt(stream, &scale_);
        loadt(stream, &correction_factor_);
        uint64_t seed; loadt(stream, &seed);
        bool terms; loadt(stream, &terms);
        if (!terms) throw std::invalid_argument("Trying to load a normal ciphertext, but term indices is specified");

        util::HostArray<ct_coeff_type> host(coeff_modulus_size_ * poly_modulus_degree_ * size_);
        // load degree 0 terms
        for (size_t id: termIds) {
            for (size_t j = 0; j < coeff_modulus_size_; j++) {
                ct_coeff_type num;
                stream.read(reinterpret_cast<char*>(&num), sizeof(decltype(num)));
                host[j * poly_modulus_degree_ + id] = num;
            }
        }
        // load terms degree greater than 0
        if (seed == 0) {
            size_t offset = poly_modulus_degree_ * coeff_modulus_size_;
            size_t dataSize;
            loadt(stream, &dataSize);
            stream.read(reinterpret_cast<char*>(host.get() + offset), dataSize * sizeof(ct_coeff_type));
            data_.ensure(host.size());
            KernelProvider::copy(data_.get(), host.get(), host.size());
        } else {
            throw std::invalid_argument("seed is not zero.");
        }

        if (is_ntt_form_) {
            is_ntt_form_ = false;
            evaluator.transformToNttInplace(*this);
        }
    }

    void CiphertextCuda::load(std::istream& stream, const SEALContextCuda& context) {
        seed_ = 0;
        loadt(stream, &parms_id_);
        loadt(stream, &is_ntt_form_);
        loadt(stream, &size_);
        loadt(stream, &poly_modulus_degree_);
        loadt(stream, &coeff_modulus_size_);
        loadt(stream, &scale_);
        loadt(stream, &correction_factor_);
        uint64_t seed; loadt(stream, &seed);
        bool terms; loadt(stream, &terms);
        if (terms) throw std::invalid_argument("Trying to load a termed ciphertext, but indices is not specified");
        if (seed == 0) {
            size_t dataSize;
            loadt(stream, &dataSize);
            util::HostArray<ct_coeff_type> host(dataSize);
            stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(ct_coeff_type));
            data_.ensure(host.size());
            KernelProvider::copy(data_.get(), host.get(), dataSize);
        } else {
            if (size_ > 2) throw std::invalid_argument("Seed exists but size is not 2.");
            size_t dataSize;
            loadt(stream, &dataSize);
            util::HostArray<ct_coeff_type> host(dataSize);
            stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(ct_coeff_type));
            data_.ensure(2 * poly_modulus_degree_ * coeff_modulus_size_);
            KernelProvider::copy(data_.get(), host.get(), dataSize);
            util::DeviceArray<curandState> curandStates(poly_modulus_degree_ * coeff_modulus_size_);
            auto& modulus = context.getContextData(parms_id_)->parms().coeffModulus();
            util::sampler::setupCurandStates(curandStates.get(), poly_modulus_degree_, seed);
            util::sampler::kSamplePolyUniform(curandStates.get(), modulus.size(), poly_modulus_degree_, modulus, data(1));

            auto &context_data = *context.getContextData(parms_id_);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            auto &plain_modulus = parms.plainModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            size_t coeff_power = util::getPowerOfTwo(coeff_count);
            auto ntt_tables = context_data.smallNTTTables();
            SchemeType type = parms.scheme();

            if (type == SchemeType::bfv) {
                kernel_util::kInverseNttNegacyclicHarvey(data(1), 1, coeff_modulus_size, coeff_power, ntt_tables);
            }
        }
    }

}