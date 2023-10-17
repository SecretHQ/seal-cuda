
#include "ntt.h"
#include "uintarith.h"
#include "uintarithsmallmod.h"
#include <algorithm>

using std::invalid_argument;

namespace troy {
    namespace util {
        
        NTTTables::NTTTables(int coeff_count_power, const Modulus &modulus)
        {
            initialize(coeff_count_power, modulus);
        }

        void NTTTables::initialize(int coeff_count_power, const Modulus &modulus)
        {
            coeff_count_power_ = coeff_count_power;
            coeff_count_ = size_t(1) << coeff_count_power_;
            modulus_ = modulus;
            // We defer parameter checking to try_minimal_primitive_root(...)
            if (!tryMinimalPrimitiveRoot(2 * coeff_count_, modulus_, root_))
            {
                throw invalid_argument("invalid modulus");
            }
            if (!tryInvertUintMod(root_, modulus_, inv_root_))
            {
                throw invalid_argument("invalid modulus");
            }

            // Populate tables with powers of root in specific orders.
            // FIXME: allocate related action
            root_powers_ = std::move(HostArray<MultiplyUIntModOperand>(coeff_count_));
            MultiplyUIntModOperand root;
            root.set(root_, modulus_);
            uint64_t power = root_;
            for (size_t i = 1; i < coeff_count_; i++)
            {
                root_powers_[reverseBits(i, coeff_count_power_)].set(power, modulus_);
                power = multiplyUintMod(power, root, modulus_);
            }
            root_powers_[0].set(static_cast<uint64_t>(1), modulus_);

            // FIXME: allocate related action
            inv_root_powers_ = std::move(HostArray<MultiplyUIntModOperand>(coeff_count_));
            root.set(inv_root_, modulus_);
            power = inv_root_;
            for (size_t i = 1; i < coeff_count_; i++)
            {
                inv_root_powers_[reverseBits(i - 1, coeff_count_power_) + 1].set(power, modulus_);
                power = multiplyUintMod(power, root, modulus_);
            }
            inv_root_powers_[0].set(static_cast<uint64_t>(1), modulus_);

            // Compute n^(-1) modulo q.
            uint64_t degree_uint = static_cast<uint64_t>(coeff_count_);
            if (!tryInvertUintMod(degree_uint, modulus_, inv_degree_modulo_.operand))
            {
                throw invalid_argument("invalid modulus");
            }
            inv_degree_modulo_.setQuotient(modulus_);

            mod_arith_lazy_ = ModArithLazy(modulus_);
            ntt_handler_ = NTTHandler(mod_arith_lazy_);
        }

        // class NTTTablesCreateIter
        // {
        // public:
        //     using value_type = NTTTables;
        //     using pointer = void;
        //     using reference = value_type;
        //     using difference_type = ptrdiff_t;

        //     // LegacyInputIterator allows reference to be equal to value_type so we can construct
        //     // the return objects on the fly and return by value.
        //     using iterator_category = input_iterator_tag;

        //     // Require default constructor
        //     NTTTablesCreateIter()
        //     {}

        //     // Other constructors
        //     NTTTablesCreateIter(int coeff_count_power, vector<Modulus> modulus, MemoryPoolHandle pool)
        //         : coeff_count_power_(coeff_count_power), modulus_(modulus), pool_(move(pool))
        //     {}

        //     // Require copy and move constructors and assignments
        //     NTTTablesCreateIter(const NTTTablesCreateIter &copy) = default;

        //     NTTTablesCreateIter(NTTTablesCreateIter &&source) = default;

        //     NTTTablesCreateIter &operator=(const NTTTablesCreateIter &assign) = default;

        //     NTTTablesCreateIter &operator=(NTTTablesCreateIter &&assign) = default;

        //     // Dereferencing creates NTTTables and returns by value
        //     inline value_type operator*() const
        //     {
        //         return { coeff_count_power_, modulus_[index_] };
        //     }

        //     // Pre-increment
        //     inline NTTTablesCreateIter &operator++() noexcept
        //     {
        //         index_++;
        //         return *this;
        //     }

        //     // Post-increment
        //     inline NTTTablesCreateIter operator++(int) noexcept
        //     {
        //         NTTTablesCreateIter result(*this);
        //         index_++;
        //         return result;
        //     }

        //     // Must be EqualityComparable
        //     inline bool operator==(const NTTTablesCreateIter &compare) const noexcept
        //     {
        //         return (compare.index_ == index_) && (coeff_count_power_ == compare.coeff_count_power_);
        //     }

        //     inline bool operator!=(const NTTTablesCreateIter &compare) const noexcept
        //     {
        //         return !operator==(compare);
        //     }

        //     // Arrow operator must be defined
        //     value_type operator->() const
        //     {
        //         return **this;
        //     }

        // private:
        //     size_t index_ = 0;
        //     int coeff_count_power_ = 0;
        //     vector<Modulus> modulus_;
        // };

        HostArray<NTTTables> CreateNTTTables(
            int coeff_count_power, const std::vector<Modulus> &modulus)
        {
            if (!modulus.size())
            {
                throw invalid_argument("invalid modulus");
            }
            // coeff_count_power and modulus will be validated by "allocate"
            // FIXME: allocate related action
            HostArray<NTTTables> ret(modulus.size());
            for (size_t i = 0; i < modulus.size(); i++) {
                ret[i] = std::move(NTTTables(coeff_count_power, modulus[i]));
            }
            return ret;
        }

        void nttNegacyclicHarveyLazy(HostPointer<uint64_t> operand, const NTTTables &tables)
        {
            tables.nttHandler().transformToRev(
                operand.get(), tables.coeffCountPower(), tables.getFromRootPowers());
        }

        void nttNegacyclicHarvey(HostPointer<uint64_t> operand, const NTTTables &tables)
        {
            nttNegacyclicHarveyLazy(operand, tables);
            // Finally maybe we need to reduce every coefficient modulo q, but we
            // know that they are in the range [0, 4q).
            // Since word size is controlled this is fast.
            std::uint64_t modulus = tables.modulus().value();
            std::uint64_t two_times_modulus = modulus * 2;
            std::size_t n = std::size_t(1) << tables.coeffCountPower();

            uint64_t* ptr = operand.get();
            for (std::size_t i = 0; i < n; i++, ptr++) {
                // Note: I must be passed to the lambda by reference.
                uint64_t& I = *ptr; 
                if (I >= two_times_modulus)
                {
                    I -= two_times_modulus;
                }
                if (I >= modulus)
                {
                    I -= modulus;
                }
            }
        }

        void inverseNttNegacyclicHarveyLazy(HostPointer<uint64_t> operand, const NTTTables &tables)
        {
            MultiplyUIntModOperand inv_degree_modulo = tables.invDegreeModulo();
            tables.nttHandler().transformFromRev(
                operand.get(), tables.coeffCountPower(), tables.getFromInvRootPowers(), &inv_degree_modulo);
        }

        void inverseNttNegacyclicHarvey(HostPointer<uint64_t> operand, const NTTTables &tables)
        {
            inverseNttNegacyclicHarveyLazy(operand, tables);
            std::uint64_t modulus = tables.modulus().value();
            std::size_t n = std::size_t(1) << tables.coeffCountPower();

            // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
            // We incorporated the final adjustment in the butterfly. Only need to reduce here.
            uint64_t* ptr = operand.get();
            for (std::size_t i = 0; i < n; i++, ptr++) {
                // Note: I must be passed to the lambda by reference.
                uint64_t& I = *ptr; 
                if (I >= modulus)
                {
                    I -= modulus;
                }
            };
        }
    }
}