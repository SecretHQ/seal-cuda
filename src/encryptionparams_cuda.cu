#include "encryptionparams_cuda.cuh"

namespace troy {
    
    using std::logic_error;

    void EncryptionParametersCuda::computeParmsID()
    {
        size_t coeff_modulus_size = coeff_modulus_.size();

        size_t total_uint64_count = 
            size_t(1) + // scheme
            size_t(1) + // poly_modulus_degree
            coeff_modulus_size + plain_modulus_.uint64Count();

        uint64_t *param_data = new uint64_t[total_uint64_count];
        for (size_t i = 0; i < total_uint64_count; i++) param_data[i] = 0;
        uint64_t *param_data_ptr = param_data;

        // Write the scheme identifier
        *param_data_ptr++ = static_cast<uint64_t>(scheme_);

        // Write the poly_modulus_degree. Note that it will always be positive.
        *param_data_ptr++ = static_cast<uint64_t>(poly_modulus_degree_);

        util::HostArray coeff_modulus_host = coeff_modulus_.toHost();
        std::vector<Modulus> coeff_modulus_vec; 
        for (size_t i = 0; i < coeff_modulus_host.size(); i++) coeff_modulus_vec.push_back(coeff_modulus_host[i]);

        for (const auto &mod : coeff_modulus_vec)
        {
            *param_data_ptr++ = mod.value();
        }

        util::setUint(plain_modulus_.data(), plain_modulus_.uint64Count(), param_data_ptr);
        param_data_ptr += plain_modulus_.uint64Count();

        util::HashFunction::hash(param_data, total_uint64_count, parms_id_);

        // Did we somehow manage to get a zero block as result? This is reserved for
        // plaintexts to indicate non-NTT-transformed form.
        if (parms_id_ == parmsIDZero)
        {
            throw logic_error("parms_id cannot be zero");
        }
        
        delete[] param_data;
    }

}