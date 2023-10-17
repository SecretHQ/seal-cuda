// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "defines.h"
#include "uintcore.h"
#include <complex>
#include <cstddef>
#include <stdexcept>

namespace troy
{
    namespace util
    {
        class ComplexRoots
        {
        public:
            ComplexRoots() = delete;

            ComplexRoots(std::size_t degree_of_roots);

            std::complex<double> getRoot(std::size_t index) const;

        private:
            static constexpr double PI_ = 3.1415926535897932384626433832795028842;

            // Contains 0~(n/8-1)-th powers of the n-th primitive root.
            util::HostArray<std::complex<double>> roots_;

            std::size_t degree_of_roots_;

        };
    } // namespace util
} // namespace seal
