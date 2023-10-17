
#pragma once

#include "../modulus.h"
#include "defines.h"
#include "dwthandler.h"
#include "uintarithsmallmod.h"
#include "uintcore.h"
#include "hostarray.h"
#include <stdexcept>
#include <iostream>

namespace troy
{
    namespace util
    {
        template <>
        class Arithmetic<std::uint64_t, MultiplyUIntModOperand, MultiplyUIntModOperand>
        {
        public:
            Arithmetic()
            {}

            Arithmetic(const Modulus &modulus) : modulus_(modulus), two_times_modulus_(modulus.value() << 1)
            {}

            inline std::uint64_t add(const std::uint64_t &a, const std::uint64_t &b) const
            {
                return a + b;
            }

            inline std::uint64_t sub(const std::uint64_t &a, const std::uint64_t &b) const
            {
                return a + two_times_modulus_ - b;
            }

            inline std::uint64_t mulRoot(const std::uint64_t &a, const MultiplyUIntModOperand &r) const
            {
                return multiplyUintModLazy(a, r, modulus_);
            }

            inline std::uint64_t mulScalar(const std::uint64_t &a, const MultiplyUIntModOperand &s) const
            {
                return multiplyUintModLazy(a, s, modulus_);
            }

            inline MultiplyUIntModOperand mulRootScalar(
                const MultiplyUIntModOperand &r, const MultiplyUIntModOperand &s) const
            {
                MultiplyUIntModOperand result;
                result.set(multiplyUintMod(r.operand, s, modulus_), modulus_);
                return result;
            }

            inline std::uint64_t guard(const std::uint64_t &a) const
            {
                return (a >= two_times_modulus_) ? (a - two_times_modulus_) : (a);
            }

        private:
            Modulus modulus_;

            std::uint64_t two_times_modulus_;
        };

        class NTTTables
        {
            using ModArithLazy = Arithmetic<uint64_t, MultiplyUIntModOperand, MultiplyUIntModOperand>;
            using NTTHandler = DWTHandler<std::uint64_t, MultiplyUIntModOperand, MultiplyUIntModOperand>;
            friend class NTTTablesCuda;
            
        public:
            NTTTables() {}

            NTTTables(NTTTables &&source) = default;

            NTTTables(NTTTables &copy)
                : root_(copy.root_), coeff_count_power_(copy.coeff_count_power_),
                  coeff_count_(copy.coeff_count_), modulus_(copy.modulus_), inv_degree_modulo_(copy.inv_degree_modulo_),
                  root_powers_(copy.coeff_count_), inv_root_powers_(copy.coeff_count_)
            {
                // FIXME: allocate related action
                // root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
                // inv_root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);

                std::copy_n(copy.root_powers_.get(), coeff_count_, root_powers_.get());
                std::copy_n(copy.inv_root_powers_.get(), coeff_count_, inv_root_powers_.get());
            }

            NTTTables(int coeff_count_power, const Modulus &modulus);

            inline std::uint64_t getRoot() const
            {
                return root_;
            }

            inline const MultiplyUIntModOperand *getFromRootPowers() const
            {
                return root_powers_.get();
            }

            inline const MultiplyUIntModOperand *getFromInvRootPowers() const
            {
                return inv_root_powers_.get();
            }

            inline MultiplyUIntModOperand getFromRootPowers(std::size_t index) const
            {
                return root_powers_[index];
            }

            inline MultiplyUIntModOperand getFromInvRootPowers(std::size_t index) const
            {
                return inv_root_powers_[index];
            }

            inline const MultiplyUIntModOperand &invDegreeModulo() const
            {
                return inv_degree_modulo_;
            }

            inline const Modulus &modulus() const
            {
                return modulus_;
            }

            inline int coeffCountPower() const
            {
                return coeff_count_power_;
            }

            inline std::size_t coeffCount() const
            {
                return coeff_count_;
            }

            const NTTHandler &nttHandler() const
            {
                return ntt_handler_;
            }

            NTTTables &operator=(NTTTables &&assign) = default;

        private:
            NTTTables &operator=(const NTTTables &assign) = delete;

            void initialize(int coeff_count_power, const Modulus &modulus);

            std::uint64_t root_ = 0;

            std::uint64_t inv_root_ = 0;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            Modulus modulus_;

            // Inverse of coeff_count_ modulo modulus_.
            MultiplyUIntModOperand inv_degree_modulo_;

            // Holds 1~(n-1)-th powers of root_ in bit-reversed order, the 0-th power is left unset.
            HostArray<MultiplyUIntModOperand> root_powers_;

            // Holds 1~(n-1)-th powers of inv_root_ in scrambled order, the 0-th power is left unset.
            HostArray<MultiplyUIntModOperand> inv_root_powers_;

            ModArithLazy mod_arith_lazy_;

            NTTHandler ntt_handler_;
        };

        /**
        Allocate and construct an array of NTTTables each with different a modulus.

        @throws std::invalid_argument if modulus is empty, modulus does not support NTT, coeff_count_power is invalid,
        or pool is uninitialized.
        */
        HostArray<NTTTables> CreateNTTTables(
            int coeff_count_power, const std::vector<Modulus> &modulus);

        void nttNegacyclicHarveyLazy(HostPointer<uint64_t> operand, const NTTTables &tables);

        inline void nttNegacyclicHarveyLazy(HostPointer<uint64_t> operand, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            std::size_t d = (1 << tables[0].coeffCountPower());
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                nttNegacyclicHarveyLazy(operand + d * i, tables[i]);
            }
        }

        inline void nttNegacyclicHarveyLazy(HostPointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            if (poly_size == 0) return;
            // assert(tables.length() > 0);
            std::size_t d = (1 << tables[0].coeffCountPower()) * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                nttNegacyclicHarveyLazy(operand + d * i, coeff_modulus_size, tables);
            }
        }

        void nttNegacyclicHarvey(HostPointer<uint64_t> operand, const NTTTables &tables);

        inline void nttNegacyclicHarvey(HostPointer<uint64_t> operand, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            std::size_t d = (1 << tables[0].coeffCountPower());
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                nttNegacyclicHarvey(operand + d * i, tables[i]);
            }
        }

        inline void nttNegacyclicHarvey(HostPointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            if (poly_size == 0) return;
            // assert(tables.length() > 0);
            std::size_t d = (1 << tables[0].coeffCountPower()) * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                nttNegacyclicHarvey(operand + d * i, coeff_modulus_size, tables);
            }
        }

        void inverseNttNegacyclicHarveyLazy(HostPointer<uint64_t> operand, const NTTTables &tables);

        inline void inverseNttNegacyclicHarveyLazy(
            HostPointer<uint64_t> operand, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            // assert(tables.length() > 0);
            std::size_t d = (1 << tables[0].coeffCountPower());
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                // std::cout << "inverseNttNegacyclicHarveyLazy i = " << i << std::endl;
                inverseNttNegacyclicHarveyLazy(operand + d * i, tables[i]);
                // std::cout << "inverseNttNegacyclicHarveyLazy i = " << i << std::endl;
            }
        }

        inline void inverseNttNegacyclicHarveyLazy(HostPointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            if (poly_size == 0) return;
            // assert(tables.length() > 0);
            std::size_t d = (1 << tables[0].coeffCountPower()) * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                inverseNttNegacyclicHarveyLazy(operand + d * i, coeff_modulus_size, tables);
            }
        }

        void inverseNttNegacyclicHarvey(HostPointer<uint64_t> operand, const NTTTables &tables);

        inline void inverseNttNegacyclicHarvey(
            HostPointer<uint64_t> operand, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            // assert(tables.length() > 0);
            std::size_t d = (1 << tables[0].coeffCountPower());
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                inverseNttNegacyclicHarvey(operand + d * i, tables[i]);
            }
        }

        inline void inverseNttNegacyclicHarvey(HostPointer<uint64_t> operand, std::size_t poly_size, std::size_t coeff_modulus_size, const NTTTables* tables)
        {
            if (poly_size == 0) return;
            // assert(tables.length() > 0);
            std::size_t d = (1 << tables[0].coeffCountPower()) * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                inverseNttNegacyclicHarvey(operand + d * i, coeff_modulus_size, tables);
            }
        }
    } // namespace util
} // namespace seal
