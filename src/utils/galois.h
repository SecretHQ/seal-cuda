// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "../modulus.h"
#include "defines.h"
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace troy
{
    namespace util
    {
        class GaloisTool
        {
        public:
            GaloisTool(int coeff_count_power)
            {
                initialize(coeff_count_power);
            }

            void applyGalois(
                ConstHostPointer<uint64_t> operand, std::uint32_t galois_elt, const Modulus &modulus, HostPointer<uint64_t> result) const;

            inline void applyGalois(
                ConstHostPointer<uint64_t> operand, std::size_t coeff_modulus_size, std::uint32_t galois_elt,
                const Modulus* modulus, HostPointer<uint64_t> result) const
            {
                for (size_t i = 0; i < coeff_modulus_size; i++) {
                    this->applyGalois(operand + i * coeff_count_, galois_elt, modulus[i], result + i * coeff_count_);
                }
            }

            void applyGalois(
                ConstHostPointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, std::uint32_t galois_elt, const Modulus* modulus,
                HostPointer<uint64_t> result) const
            {
                size_t d = coeff_modulus_size * coeff_count_;
                for (size_t i = 0; i < poly_size; i++) {
                    this->applyGalois(operand + i * d, coeff_modulus_size, galois_elt, modulus, result + i * d);
                }
            }

            void applyGaloisNtt(ConstHostPointer<uint64_t> operand, std::uint32_t galois_elt, HostPointer<uint64_t> result) const;

            void applyGaloisNtt(
                ConstHostPointer<uint64_t> operand, std::size_t coeff_modulus_size, std::uint32_t galois_elt, HostPointer<uint64_t> result) const
            {
                for (size_t i = 0; i < coeff_modulus_size; i++) {
                    this->applyGaloisNtt(operand + i * coeff_count_, galois_elt, result + i * coeff_count_);
                }
            }

            void applyGaloisNtt(
                ConstHostPointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, std::uint32_t galois_elt, HostPointer<uint64_t> result) const
            {
                size_t d = coeff_modulus_size * coeff_count_;
                for (size_t i = 0; i < poly_size; i++) {
                    this->applyGaloisNtt(operand + i * d, coeff_modulus_size, galois_elt, result + i * d);
                }
            }

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
#ifdef SEAL_DEBUG
                if (!(galois_elt & 1))
                {
                    throw std::invalid_argument("galois_elt is not valid");
                }
#endif
                return util::safe_cast<std::size_t>((galois_elt - 1) >> 1);
            }

        private:
            GaloisTool(const GaloisTool &copy) = delete;

            GaloisTool(GaloisTool &&source) = delete;

            GaloisTool &operator=(const GaloisTool &assign) = delete;

            GaloisTool &operator=(GaloisTool &&assign) = delete;

            void initialize(int coeff_count_power);

            void generateTableNtt(std::uint32_t galois_elt, HostArray<std::uint32_t> &result) const;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            static constexpr std::uint32_t generator_ = 3;

            mutable HostArray<HostArray<std::uint32_t>> permutation_tables_;

            // mutable util::ReaderWriterLocker permutation_tables_locker_;
        };
    } // namespace util
} // namespace seal
