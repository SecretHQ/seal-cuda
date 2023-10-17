// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "../context.h"
#include "../plaintext.h"
#include <cstdint>

namespace troy
{
    namespace util
    {
        void addPlainWithoutScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination);

        void subPlainWithoutScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination);

        void multiplyAddPlainWithScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination);

        void multiplySubPlainWithScalingVariant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, HostPointer<uint64_t> destination);
    } // namespace util
} // namespace seal
