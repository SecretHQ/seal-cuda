// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "rlwe.h"
#include "../publickey_cuda.cuh"
#include "../ciphertext_cuda.cuh"
#include "../publickey_cuda.cuh"
#include "../context_cuda.cuh"
#include "../secretkey_cuda.cuh"
#include <cstdint>

#include <curand_kernel.h>

namespace troy
{
    namespace util
    {

        namespace sampler {
            void setupCurandStates(curandState* states, size_t n, uint64_t seed);
            
            void kSamplePolyUniform(
                DevicePointer<curandState> states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                ConstDevicePointer<Modulus> modulus,
                DevicePointer<uint64_t> destination
            );
        }
        
        void encryptZeroAsymmetric(
            const PublicKeyCuda &public_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination, DevicePointer<curandState> curandStates);

        void encryptZeroSymmetric(
            const SecretKeyCuda &secret_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination, DevicePointer<curandState> curandStates);
            
    } // namespace util
} // namespace seal
