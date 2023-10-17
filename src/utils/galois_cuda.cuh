// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "galois.h"
#include "devicearray.cuh"

namespace troy
{
    namespace util
    {
        class GaloisToolCuda
        {
        public:
            GaloisToolCuda(int coeff_count_power)
            {
                initialize(coeff_count_power);
            }

            void applyGalois(
                ConstDevicePointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, std::uint32_t galois_elt, ConstDevicePointer<Modulus> modulus, DevicePointer<uint64_t> result) const;


            void applyGaloisNtt(ConstDevicePointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, std::uint32_t galois_elt, DevicePointer<uint64_t> result) const;

            /**
            Compute the Galois element corresponding to a given rotation step.
            */
            std::uint32_t getEltFromStep(int step) const;

            /**
            Compute the Galois elements corresponding to a vector of given rotation steps.
            */
            std::vector<std::uint32_t> getEltsFromSteps(const std::vector<int> &steps) const;

            /**
            Compute a vector of all necessary galois_elts.
            */
            std::vector<std::uint32_t> getEltsAll() const noexcept;

            /**
            Compute the index in the range of 0 to (coeff_count_ - 1) of a given Galois element.
            */
            static inline std::size_t GetIndexFromElt(std::uint32_t galois_elt)
            {
                return util::safe_cast<std::size_t>((galois_elt - 1) >> 1);
            }

        private:
            GaloisToolCuda(const GaloisToolCuda &copy) = delete;

            GaloisToolCuda(GaloisTool &&source) = delete;

            GaloisToolCuda &operator=(const GaloisToolCuda &assign) = delete;

            GaloisToolCuda &operator=(GaloisToolCuda &&assign) = delete;

            void initialize(int coeff_count_power);

            void generateTableNtt(std::uint32_t galois_elt, DeviceArray<std::uint32_t> &result) const;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            static constexpr std::uint32_t generator_ = 3;

            mutable HostArray<DeviceArray<std::uint32_t>> permutation_tables_;

            // mutable util::ReaderWriterLocker permutation_tables_locker_;
        };
    } // namespace util
} // namespace seal
