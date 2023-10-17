// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "../context_cuda.cuh"
#include "../plaintext_cuda.cuh"
#include <cstdint>

namespace troy
{
    namespace util
    {
        void addPlainWithoutScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination);

        void subPlainWithoutScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination);

        void multiplyAddPlainWithScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination);

        void multiplySubPlainWithScalingVariant(
            const PlaintextCuda &plain, const SEALContextCuda::ContextDataCuda &context_data, DevicePointer<uint64_t> destination);
    } // namespace util
} // namespace seal
