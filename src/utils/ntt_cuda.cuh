
#pragma once

#include "devicearray.cuh"
#include "ntt.h"
#include <stdexcept>
#include <iostream>

namespace troy
{
    namespace util
    {

        // this is meant to be stored in the device
        class NTTTablesCuda
        {

        public:
            NTTTablesCuda() {}

            NTTTablesCuda(NTTTablesCuda &&source) = default;

            // This construction should be down on host.
            NTTTablesCuda(const NTTTables &copy)
                : root_(copy.root_), coeff_count_power_(copy.coeff_count_power_),
                  coeff_count_(copy.coeff_count_), modulus_(copy.modulus_), inv_degree_modulo_(copy.inv_degree_modulo_),
                  root_powers_(copy.root_powers_), inv_root_powers_(copy.inv_root_powers_)
            {
            }

            __device__ inline std::uint64_t getRoot() const
            {
                return root_;
            }

            __device__ inline const MultiplyUIntModOperand *getFromRootPowers() const
            {
                return root_powers_.deviceGet();
            }

            __device__ inline const MultiplyUIntModOperand *getFromInvRootPowers() const
            {
                return inv_root_powers_.deviceGet();
            }

            // __device__ inline MultiplyUIntModOperand getFromRootPowers(std::size_t index) const
            // {
            //     return root_powers_[index];
            // }

            // __device__ inline MultiplyUIntModOperand getFromInvRootPowers(std::size_t index) const
            // {
            //     return inv_root_powers_[index];
            // }

            __device__ inline const MultiplyUIntModOperand &invDegreeModulo() const
            {
                return inv_degree_modulo_;
            }

            __device__ inline const Modulus &modulus() const
            {
                return modulus_;
            }

            __device__ inline int coeffCountPower() const
            {
                return coeff_count_power_;
            }

            __device__ inline std::size_t coeffCount() const
            {
                return coeff_count_;
            }

            NTTTablesCuda &operator=(NTTTablesCuda &&assign) = default;

        private:
            NTTTablesCuda &operator=(const NTTTablesCuda &assign) = delete;

            std::uint64_t root_ = 0;

            std::uint64_t inv_root_ = 0;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            Modulus modulus_;

            // Inverse of coeff_count_ modulo modulus_.
            MultiplyUIntModOperand inv_degree_modulo_;

            // Holds 1~(n-1)-th powers of root_ in bit-reversed order, the 0-th power is left unset.
            // device pointer
            DeviceArray<MultiplyUIntModOperand> root_powers_; 

            // Holds 1~(n-1)-th powers of inv_root_ in scrambled order, the 0-th power is left unset.
            // device pointer
            DeviceArray<MultiplyUIntModOperand> inv_root_powers_;

        };

    } // namespace util
} // namespace seal
