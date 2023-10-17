// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "ckks.h"
#include "plaintext_cuda.cuh"
#include "context_cuda.cuh"


namespace troy
{

    class CKKSEncoderCuda
    {

    public:

        CKKSEncoderCuda(const SEALContextCuda &context);

        inline void encode(
            const std::vector<std::complex<double>> &values, ParmsID parms_id, double scale, PlaintextCuda &destination)
        {
            encodeInternal(values.data(), values.size(), parms_id, scale, destination);
        }


        inline void encode(
            const std::vector<std::complex<double>> &values, double scale, PlaintextCuda &destination)
        {
            encode(values, context_.firstParmsID(), scale, destination);
        }
        
        inline void encodePolynomial(const std::vector<double>& values, ParmsID parms_id, double scale, PlaintextCuda& destination) {
            encodePolynomialInternal(values.data(), values.size(), parms_id, scale, destination);
        }

        inline void encodePolynomial(const std::vector<double>& values, double scale, PlaintextCuda& destination) {
            encodePolynomial(values, context_.firstParmsID(), scale, destination);
        }
        
        inline void encode(
            double value, ParmsID parms_id, double scale, PlaintextCuda &destination)
        {
            encodeInternal(value, parms_id, scale, destination);
        }
        
        inline void encode(
            double value, double scale, PlaintextCuda &destination)
        {
            encode(value, context_.firstParmsID(), scale, destination);
        }

        inline void encode(
            std::complex<double> value, ParmsID parms_id, double scale, PlaintextCuda &destination)
        {
            encodeInternal(value, parms_id, scale, destination);
        }

        inline void encode(
            std::complex<double> value, double scale, PlaintextCuda &destination)
        {
            encode(value, context_.firstParmsID(), scale, destination);
        }


        inline void encode(std::int64_t value, ParmsID parms_id, PlaintextCuda &destination)
        {
            encodeInternal(value, parms_id, destination);
        }

        inline void encode(std::int64_t value, PlaintextCuda &destination)
        {
            encode(value, context_.firstParmsID(), destination);
        }

        inline void decode(
            const PlaintextCuda &plain, std::vector<std::complex<double>> &destination)
        {
            destination.resize(slots_);
            decodeInternal(plain, destination.data());
        }

        inline void decodePolynomial(const PlaintextCuda& plain, std::vector<double> &destination) {
            destination.resize(slots_ * 2);
            decodePolynomialInternal(plain, destination.data());
        }

        inline std::size_t slotCount() const noexcept
        {
            return slots_;
        }

    private:

    
        void encodeInternal(
            const std::complex<double> *values, std::size_t values_size, 
            ParmsID parms_id, double scale, PlaintextCuda &destination);

        
        void encodePolynomialInternal(
            const double* coeffs, std::size_t values_size,
            ParmsID parms_id, double scale, PlaintextCuda& destination
        );
        
        
        void decodeInternal(const PlaintextCuda &plain, std::complex<double> *destination);

        void decodePolynomialInternal(const PlaintextCuda& plain, double *destination);

        
        void encodeInternal(
            double value, ParmsID parms_id, double scale, PlaintextCuda &destination);

        inline void encodeInternal(
            std::complex<double> value, ParmsID parms_id, double scale, PlaintextCuda &destination)
        {
            auto input = util::HostArray<std::complex<double>>(slots_);
            for (size_t i = 0; i < slots_; i++) input[i] = value;
            encodeInternal(input.get(), slots_, parms_id, scale, destination);
        }

        void encodeInternal(std::int64_t value, ParmsID parms_id, PlaintextCuda &destination);

        SEALContextCuda context_;

        std::size_t slots_;

        util::DeviceArray<std::complex<double>> complex_roots_;

        // Holds 1~(n-1)-th powers of root in bit-reversed order, the 0-th power is left unset.
        util::DeviceArray<std::complex<double>> root_powers_;

        // Holds 1~(n-1)-th powers of inverse root in scrambled order, the 0-th power is left unset.
        util::DeviceArray<std::complex<double>> inv_root_powers_;

        util::DeviceArray<std::size_t> matrix_reps_index_map_;
        
    };
} // namespace seal
