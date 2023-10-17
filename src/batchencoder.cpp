// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "batchencoder.h"
#include "valcheck.h"
#include "utils/common.h"
#include <algorithm>
#include <limits>
#include <random>
#include <stdexcept>

using namespace std;
using namespace troy::util;

namespace troy
{
    BatchEncoder::BatchEncoder(const SEALContext &context) : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto &context_data = *context_.firstContextData();
        if (context_data.parms().scheme() != SchemeType::bfv && context_data.parms().scheme() != SchemeType::bgv)
        {
            throw invalid_argument("unsupported scheme");
        }

        // Set the slot count
        slots_ = context_data.parms().polyModulusDegree();


        if (context_data.qualifiers().using_batching)
        {
            // Reserve space for all of the primitive roots
            roots_of_unity_ = allocateUint(slots_);

            // Fill the vector of roots of unity with all distinct odd powers of generator.
            // These are all the primitive (2*slots_)-th roots of unity in integers modulo
            // parms.plain_modulus().
            populateRootsOfUnityVector(context_data);

            // Populate matrix representation index map
            populateMatrixRepsIndexMap();
        }
    }

    void BatchEncoder::populateRootsOfUnityVector(const SEALContext::ContextData &context_data)
    {
        uint64_t root = context_data.plainNTTTables()->getRoot();
        auto &modulus = context_data.parms().plainModulus();

        uint64_t generator_sq = multiplyUintMod(root, root, modulus);
        roots_of_unity_[0] = root;

        for (size_t i = 1; i < slots_; i++)
        {
            roots_of_unity_[i] = multiplyUintMod(roots_of_unity_[i - 1], generator_sq, modulus);
        }
    }

    void BatchEncoder::populateMatrixRepsIndexMap()
    {
        int logn = getPowerOfTwo(slots_);
        matrix_reps_index_map_ = HostArray<size_t>(slots_);

        // Copy from the matrix to the value vectors
        size_t row_size = slots_ >> 1;
        size_t m = slots_ << 1;
        uint64_t gen = 3;
        uint64_t pos = 1;
        for (size_t i = 0; i < row_size; i++)
        {
            // Position in normal bit order
            uint64_t index1 = (pos - 1) >> 1;
            uint64_t index2 = (m - pos - 1) >> 1;

            // Set the bit-reversed locations
            matrix_reps_index_map_[i] = safe_cast<size_t>(util::reverseBits(index1, logn));
            matrix_reps_index_map_[row_size | i] = safe_cast<size_t>(util::reverseBits(index2, logn));

            // Next primitive root
            pos *= gen;
            pos &= (m - 1);
        }
    }

    void BatchEncoder::reverseBits(uint64_t *input)
    {
        size_t coeff_count = context_.firstContextData()->parms().polyModulusDegree();
        int logn = getPowerOfTwo(coeff_count);
        for (size_t i = 0; i < coeff_count; i++)
        {
            uint64_t reversed_i = util::reverseBits(i, logn);
            if (i < reversed_i)
            {
                swap(input[i], input[reversed_i]);
            }
        }
    }

    void BatchEncoder::encode(const vector<uint64_t> &values_matrix, Plaintext &destination) const
    {
        auto &context_data = *context_.firstContextData();

        // Validate input parameters
        size_t values_matrix_size = values_matrix.size();
        if (values_matrix_size > slots_)
        {
            throw invalid_argument("values_matrix size is too large");
        }
        // Set destination to full size
        destination.resize(slots_);
        destination.parmsID() = parmsIDZero;

        // First write the values to destination coefficients.
        // Read in top row, then bottom row.
        for (size_t i = 0; i < values_matrix_size; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = values_matrix[i];
        }
        for (size_t i = values_matrix_size; i < slots_; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = 0;
        }

        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        inverseNttNegacyclicHarvey(destination.data(), *context_data.plainNTTTables());
    }

    void BatchEncoder::encode(const vector<int64_t> &values_matrix, Plaintext &destination) const
    {
        auto &context_data = *context_.firstContextData();
        uint64_t modulus = context_data.parms().plainModulus().value();

        // Validate input parameters
        size_t values_matrix_size = values_matrix.size();
        if (values_matrix_size > slots_)
        {
            throw invalid_argument("values_matrix size is too large");
        }
        // Set destination to full size
        destination.resize(slots_);
        destination.parmsID() = parmsIDZero;

        // First write the values to destination coefficients.
        // Read in top row, then bottom row.
        for (size_t i = 0; i < values_matrix_size; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) =
                (values_matrix[i] < 0) ? (modulus + static_cast<uint64_t>(values_matrix[i]))
                                       : static_cast<uint64_t>(values_matrix[i]);
        }
        for (size_t i = values_matrix_size; i < slots_; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = 0;
        }

        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        inverseNttNegacyclicHarvey(destination.data(), *context_data.plainNTTTables());
    }

    void BatchEncoder::decode(const Plaintext &plain, vector<uint64_t> &destination) const
    {
        if (!isValidFor(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (plain.isNttForm())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }

        auto &context_data = *context_.firstContextData();

        // Set destination size
        destination.resize(slots_);

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeffCount(), slots_);

        auto temp_dest(allocateUint(slots_));

        // Make a copy of poly
        setUint(plain.data(), plain_coeff_count, temp_dest.get());
        setZeroUint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        nttNegacyclicHarvey(temp_dest.get(), *context_data.plainNTTTables());

        // Read top row, then bottom row
        for (size_t i = 0; i < slots_; i++)
        {
            destination[i] = temp_dest[matrix_reps_index_map_[i]];
        }
    }

    void BatchEncoder::decode(const Plaintext &plain, vector<int64_t> &destination) const
    {
        if (!isValidFor(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (plain.isNttForm())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }

        auto &context_data = *context_.firstContextData();
        uint64_t modulus = context_data.parms().plainModulus().value();

        // Set destination size
        destination.resize(slots_);

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeffCount(), slots_);

        auto temp_dest(allocateUint(slots_));

        // Make a copy of poly
        setUint(plain.data(), plain_coeff_count, temp_dest.get());
        setZeroUint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        nttNegacyclicHarvey(temp_dest.get(), *context_data.plainNTTTables());

        // Read top row, then bottom row
        uint64_t plain_modulus_div_two = modulus >> 1;
        for (size_t i = 0; i < slots_; i++)
        {
            uint64_t curr_value = temp_dest[matrix_reps_index_map_[i]];
            destination[i] = (curr_value > plain_modulus_div_two)
                                 ? (static_cast<int64_t>(curr_value) - static_cast<int64_t>(modulus))
                                 : static_cast<int64_t>(curr_value);
        }
    }
} // namespace seal
