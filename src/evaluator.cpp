// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "evaluator.h"
#include "utils/common.h"
#include "utils/galois.h"
#include "utils/numth.h"
#include "utils/polyarithsmallmod.h"
#include "utils/polycore.h"
#include "utils/scalingvariant.h"
#include "utils/uintarith.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <functional>

using namespace std;
using namespace troy::util;

namespace troy
{
    namespace
    {

        inline void print(const char* message) {std::cout << message << std::endl;}
        template <typename T> void print(const char* message, T i, T total) {std::cout << message << " = " << i << " / " << total << "\n";}
        inline void printArray(const uint64_t* start, size_t count, bool dont_compress = false) {
            std::cout << "[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }
        inline void printArray(const HostArray<uint64_t>& s, bool dont_compress = false) {
            printArray(s.get(), s.size(), dont_compress);
        } 

        template <typename T, typename S>
        inline bool areSameScale(const T &value1, const S &value2) noexcept
        {
            return util::areClose<double>(value1.scale(), value2.scale());
        }

        inline bool isScaleWithinBounds(
            double scale, const SEALContext::ContextData &context_data) noexcept
        {
            int scale_bit_count_bound = 0;
            switch (context_data.parms().scheme())
            {
            case SchemeType::bfv:
            case SchemeType::bgv:
                scale_bit_count_bound = context_data.parms().plainModulus().bitCount();
                break;
            case SchemeType::ckks:
                scale_bit_count_bound = context_data.totalCoeffModulusBitCount();
                break;
            default:
                // Unsupported scheme; check will fail
                scale_bit_count_bound = -1;
            };

            return !(scale <= 0 || (static_cast<int>(log2(scale)) >= scale_bit_count_bound));
        }

        /**
        Returns (f, e1, e2) such that
        (1) e1 * factor1 = e2 * factor2 = f mod p;
        (2) gcd(e1, p) = 1 and gcd(e2, p) = 1;
        (3) abs(e1_bal) + abs(e2_bal) is minimal, where e1_bal and e2_bal represent e1 and e2 in (-p/2, p/2].
        */
        inline auto balanceCorrectionFactors(
            uint64_t factor1, uint64_t factor2, const Modulus &plain_modulus) -> tuple<uint64_t, uint64_t, uint64_t>
        {
            uint64_t t = plain_modulus.value();
            uint64_t half_t = t / 2;

            auto sum_abs = [&](uint64_t x, uint64_t y) {
                int64_t x_bal = static_cast<int64_t>(x > half_t ? x - t : x);
                int64_t y_bal = static_cast<int64_t>(y > half_t ? y - t : y);
                return abs(x_bal) + abs(y_bal);
            };

            // ratio = f2 / f1 mod p
            uint64_t ratio = 1;
            if (!tryInvertUintMod(factor1, plain_modulus, ratio))
            {
                throw logic_error("invalid correction factor1");
            }
            ratio = multiplyUintMod(ratio, factor2, plain_modulus);
            uint64_t e1 = ratio;
            uint64_t e2 = 1;
            int64_t sum = sum_abs(e1, e2);

            // Extended Euclidean
            int64_t prev_a = static_cast<int64_t>(plain_modulus.value());
            int64_t prev_b = static_cast<int64_t>(0);
            int64_t a = static_cast<int64_t>(ratio);
            int64_t b = 1;

            while (a != 0)
            {
                int64_t q = prev_a / a;
                int64_t temp = prev_a % a;
                prev_a = a;
                a = temp;

                temp = sub_safe(prev_b, mul_safe(b, q));
                prev_b = b;
                b = temp;

                uint64_t a_mod = barrettReduce64(static_cast<uint64_t>(abs(a)), plain_modulus);
                if (a < 0)
                {
                    a_mod = negateUintMod(a_mod, plain_modulus);
                }
                uint64_t b_mod = barrettReduce64(static_cast<uint64_t>(abs(b)), plain_modulus);
                if (b < 0)
                {
                    b_mod = negateUintMod(b_mod, plain_modulus);
                }
                if (a_mod != 0 && gcd(a_mod, t) == 1) // which also implies gcd(b_mod, t) == 1
                {
                    int64_t new_sum = sum_abs(a_mod, b_mod);
                    if (new_sum < sum)
                    {
                        sum = new_sum;
                        e1 = a_mod;
                        e2 = b_mod;
                    }
                }
            }
            return make_tuple(multiplyUintMod(e1, factor1, plain_modulus), e1, e2);
        }
    } // namespace

    Evaluator::Evaluator(const SEALContext &context) : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
    }

    void Evaluator::negateInplace(Ciphertext &encrypted) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t encrypted_size = encrypted.size();

        // Negate each poly in the array
        negatePolyCoeffmod(encrypted.data(), encrypted_size, coeff_modulus.size(), parms.polyModulusDegree(), &coeff_modulus[0], encrypted.data());
    }

    void Evaluator::addInplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted1, context_) || !isBufferValid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!isMetadataValidFor(encrypted2, context_) || !isBufferValid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parmsID() != encrypted2.parmsID())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.isNttForm() != encrypted2.isNttForm())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!areSameScale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        auto &plain_modulus = parms.plainModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!productFitsIn(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        if (encrypted1.correctionFactor() != encrypted2.correctionFactor())
        {
            // Balance correction factors and multiply by scalars before addition in BGV
            auto factors = balanceCorrectionFactors(
                encrypted1.correctionFactor(), encrypted2.correctionFactor(), plain_modulus);
            multiplyPolyScalarCoeffmod(
                encrypted1.data(), encrypted1.size(), coeff_modulus_size, coeff_count, get<1>(factors),
                &coeff_modulus[0], encrypted1.data());

            Ciphertext encrypted2_copy = encrypted2;
            multiplyPolyScalarCoeffmod(
                encrypted2.data(), encrypted2.size(), coeff_modulus_size, coeff_count, get<2>(factors),
                &coeff_modulus[0], encrypted2_copy.data());

            // Set new correction factor
            encrypted1.correctionFactor() = get<0>(factors);
            encrypted2_copy.correctionFactor() = get<0>(factors);

            addInplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parmsID(), max_count);
            // Add ciphertexts
            addPolyCoeffmod(encrypted1.data(), encrypted2.data(), min_count, coeff_modulus_size, coeff_count, &coeff_modulus[0], encrypted1.data());

            // Copy the remainding polys of the array with larger count into encrypted1
            if (encrypted1_size < encrypted2_size)
            {
                setPolyArray(
                    encrypted2.data(min_count), encrypted2_size - encrypted1_size, coeff_count, coeff_modulus_size,
                    encrypted1.data(encrypted1_size));
            }
        }

    }

    void Evaluator::addMany(const vector<Ciphertext> &encrypteds, Ciphertext &destination) const
    {
        if (encrypteds.empty())
        {
            throw invalid_argument("encrypteds cannot be empty");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        destination = encrypteds[0];
        for (size_t i = 1; i < encrypteds.size(); i++)
        {
            addInplace(destination, encrypteds[i]);
        }
    }

    void Evaluator::subInplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted1, context_) || !isBufferValid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!isMetadataValidFor(encrypted2, context_) || !isBufferValid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parmsID() != encrypted2.parmsID())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.isNttForm() != encrypted2.isNttForm())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!areSameScale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        auto &plain_modulus = parms.plainModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!productFitsIn(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        if (encrypted1.correctionFactor() != encrypted2.correctionFactor())
        {
            // Balance correction factors and multiply by scalars before subtraction in BGV
            auto factors = balanceCorrectionFactors(
                encrypted1.correctionFactor(), encrypted2.correctionFactor(), plain_modulus);

            multiplyPolyScalarCoeffmod(
                encrypted1.data(), encrypted1.size(), coeff_modulus_size, coeff_count, get<1>(factors),
                coeff_modulus.data(), encrypted1.data());

            Ciphertext encrypted2_copy = encrypted2;
            multiplyPolyScalarCoeffmod(
                encrypted2.data(), encrypted2.size(), coeff_modulus_size, coeff_count, get<2>(factors),
                coeff_modulus.data(), encrypted2_copy.data());

            // Set new correction factor
            encrypted1.correctionFactor() = get<0>(factors);
            encrypted2_copy.correctionFactor() = get<0>(factors);

            subInplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parmsID(), max_count);

            // Subtract ciphertexts
            subPolyCoeffmod(encrypted1.data(), encrypted2.data(), min_count, coeff_modulus_size, coeff_count, coeff_modulus.data(), encrypted1.data());

            // If encrypted2 has larger count, negate remaining entries
            if (encrypted1_size < encrypted2_size)
            {
                negatePolyCoeffmod(
                    encrypted2.data(min_count), encrypted2_size - min_count, coeff_modulus_size, coeff_count, coeff_modulus.data(),
                    encrypted1.data(min_count));
            }
        }
    }

    void Evaluator::multiplyInplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted1, context_) || !isBufferValid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!isMetadataValidFor(encrypted2, context_) || !isBufferValid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parmsID() != encrypted2.parmsID())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }

        auto context_data_ptr = context_.firstContextData();
        switch (context_data_ptr->parms().scheme())
        {
        case SchemeType::bfv:
            bfvMultiply(encrypted1, encrypted2);
            break;

        case SchemeType::ckks:
            ckksMultiply(encrypted1, encrypted2);
            break;

        case SchemeType::bgv:
            bgvMultiply(encrypted1, encrypted2);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Evaluator::bfvMultiply(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // std::cout << "bfv multiply invoked\n";
        if (encrypted1.isNttForm() || encrypted2.isNttForm())
        {
            throw invalid_argument("encrypted1 or encrypted2 cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t base_q_size = parms.coeffModulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        uint64_t plain_modulus = parms.plainModulus().value();

        auto rns_tool = context_data.rnsTool();
        size_t base_Bsk_size = rns_tool->baseBsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->baseBskmTilde()->size();

        // Determine destination.size()
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!productFitsIn(dest_size, mul_safe(coeff_count, base_Bsk_m_tilde_size)))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterators for bases
        auto base_q = parms.coeffModulus().data();
        auto base_Bsk = rns_tool->baseBsk()->base();

        // Set up iterators for NTT tables
        auto base_q_ntt_tables = context_data.smallNTTTables();
        auto base_Bsk_ntt_tables = rns_tool->baseBskNttTables();

        // Microsoft SEAL uses BEHZ-style RNS multiplication. This process is somewhat complex and consists of the
        // following steps:
        //
        // (1) Lift encrypted1 and encrypted2 (initially in base q) to an extended base q U Bsk U {m_tilde}
        // (2) Remove extra multiples of q from the results with Montgomery reduction, switching base to q U Bsk
        // (3) Transform the data to NTT form
        // (4) Compute the ciphertext polynomial product using dyadic multiplication
        // (5) Transform the data back from NTT form
        // (6) Multiply the result by t (plain_modulus)
        // (7) Scale the result by q using a divide-and-floor algorithm, switching base to Bsk
        // (8) Use Shenoy-Kumaresan method to convert the result to base q

        // Resize encrypted1 to destination size
        
        encrypted1.resize(context_, context_data.parmsID(), dest_size);
        // std::cout << "encrypted1 resized\n";

        // Allocate space for a base q output of behz_extend_base_convertToNtt for encrypted1
        auto encrypted1_q = allocatePolyArray(encrypted1_size, coeff_count, base_q_size);

        // Allocate space for a base Bsk output of behz_extend_base_convertToNtt for encrypted1
        auto encrypted1_Bsk = allocatePolyArray(encrypted1_size, coeff_count, base_Bsk_size);

        // Perform BEHZ steps (1)-(3) for encrypted1
        // SEAL_ITERATE(iter(encrypted1, encrypted1_q, encrypted1_Bsk), encrypted1_size, behz_extend_base_convertToNtt);
        for (size_t i = 0; i < encrypted1_size; i++) {
        // This lambda function takes as input an IterTuple with three components:
        //
        // 1. (Const)RNSIter to read an input polynomial from
        // 2. RNSIter for the output in base q
        // 3. RNSIter for the output in base Bsk
        //
        // It performs steps (1)-(3) of the BEHZ multiplication (see above) on the given input polynomial (given as an
        // RNSIter or ConstRNSIter) and writes the results in base q and base Bsk to the given output
        // iterators.
        // auto behz_extend_base_convertToNtt = [&](auto I) {
            // Make copy of input polynomial (in base q) and convert to NTT form
            // Lazy reduction
            setPoly(encrypted1.data(i), coeff_count, base_q_size, encrypted1_q.get() + i * coeff_count * base_q_size);
            nttNegacyclicHarveyLazy(encrypted1_q.get() + i * coeff_count * base_q_size, base_q_size, base_q_ntt_tables);

            // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
            // FIXME: allocate related action frequent
            auto temp = allocatePoly(coeff_count, base_Bsk_m_tilde_size);

            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool->fastbconvmTilde(encrypted1.data(i), temp.asPointer());

            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            rns_tool->smMrq(temp.asPointer(), encrypted1_Bsk.get() + i * coeff_count * base_Bsk_size);

            // Transform to NTT form in base Bsk
            // Lazy reduction
            nttNegacyclicHarveyLazy(encrypted1_Bsk.get() + i * coeff_count * base_Bsk_size, base_Bsk_size, base_Bsk_ntt_tables);
        }

        
        // std::cout << "Encrypted1_q: ";
        // printArray(encrypted1_q);
        // std::cout << "Encrypted1_Bsk: ";
        // printArray(encrypted1_Bsk);

        // std::cout << "encrypted2 process\n";
        // Repeat for encrypted2
        auto encrypted2_q = allocatePolyArray(encrypted2_size, coeff_count, base_q_size);
        auto encrypted2_Bsk = allocatePolyArray(encrypted2_size, coeff_count, base_Bsk_size);

        for (size_t i = 0; i < encrypted2_size; i++) {
            setPoly(encrypted2.data(i), coeff_count, base_q_size, encrypted2_q.get() + i * coeff_count * base_q_size);
            nttNegacyclicHarveyLazy(encrypted2_q.get() + i * coeff_count * base_q_size, base_q_size, base_q_ntt_tables);

            // FIXME: allocate related action frequent
            auto temp = allocatePoly(coeff_count, base_Bsk_m_tilde_size);

            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool->fastbconvmTilde(encrypted2.data(i), temp.asPointer());

            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            rns_tool->smMrq(temp.asPointer(), encrypted2_Bsk.get() + i * coeff_count * base_Bsk_size);

            nttNegacyclicHarveyLazy(encrypted2_Bsk.get() + i * coeff_count * base_Bsk_size, base_Bsk_size, base_Bsk_ntt_tables);
        }

        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components
        auto temp_dest_q = allocateZeroPolyArray(dest_size, coeff_count, base_q_size);
        auto temp_dest_Bsk = allocateZeroPolyArray(dest_size, coeff_count, base_Bsk_size);
        // std::cout << "temp dest process\n";

        // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphertexts
        for (size_t i = 0; i < dest_size; i++) {
            // print("behz4 i", i, dest_size);
        // SEAL_ITERATE(iter(size_t(0)), dest_size, [&](au to I) {
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            size_t curr_encrypted1_last = min<size_t>(i, encrypted1_size - 1);
            size_t curr_encrypted2_first = min<size_t>(i, encrypted2_size - 1);
            size_t curr_encrypted1_first = i - curr_encrypted2_first;
            // size_t curr_encrypted2_last = I - curr_encrypted1_last;

            // The total number of dyadic products is now easy to compute
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            // Perform the BEHZ ciphertext product both for base q and base Bsk
            {
                size_t d = coeff_count * base_q_size;
                // Create a shifted iterator for the first input
                auto shifted_in1_iter = encrypted1_q + curr_encrypted1_first * d;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_in2_iter = encrypted2_q + curr_encrypted2_first * d;

                // Create a shifted iterator for the output
                auto shifted_out_iter = temp_dest_q + i * d;

                for (size_t j = 0; j < steps; j++) {
                    for (size_t k = 0; k < base_q_size; k++) {
                        // FIXME: frequent allocate
                        auto temp = allocateUint(coeff_count);
                        // std::cout << std::hex << *(shifted_in1_iter + j * d + k * coeff_count) << std::endl;
                        dyadicProductCoeffmod(shifted_in1_iter + j * d + k * coeff_count, shifted_reversed_in2_iter - j * d + k * coeff_count, coeff_count, base_q[k], temp.asPointer());
                        // std::cout << "first of temp: " << temp[0] << std::endl;
                        addPolyCoeffmod(temp.asPointer(), shifted_out_iter + k * coeff_count, coeff_count, base_q[k], shifted_out_iter + k * coeff_count);
                        // std::cout << "first of res: " << *(shifted_out_iter + k * coeff_count) << std::endl;
                    }
                }
            }
            {
                size_t d = coeff_count * base_Bsk_size;
                // Create a shifted iterator for the first input
                auto shifted_in1_iter = encrypted1_Bsk + curr_encrypted1_first * d;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_in2_iter = encrypted2_Bsk + curr_encrypted2_first * d;

                // Create a shifted iterator for the output
                auto shifted_out_iter = temp_dest_Bsk + i * d;

                for (size_t j = 0; j < steps; j++) {
                    for (size_t k = 0; k < base_Bsk_size; k++) {
                        // FIXME: frequent allocate
                        auto temp = allocateUint(coeff_count);
                        dyadicProductCoeffmod(shifted_in1_iter + j * d + k * coeff_count, shifted_reversed_in2_iter - j * d + k * coeff_count, coeff_count, base_Bsk[k], temp.asPointer());
                        addPolyCoeffmod(temp.asPointer(), shifted_out_iter + k * coeff_count, coeff_count, base_Bsk[k], shifted_out_iter + k * coeff_count);
                    }
                }
            }
        }

        // std::cout << "before invs dest process\n";

        // std::cout << "temp_dest_q: ";
        // printArray(temp_dest_q);
        // std::cout << "temp_dest_Bsk: ";
        // printArray(temp_dest_Bsk);

        // Perform BEHZ step (5): transform data from NTT form
        // Lazy reduction here. The following multiplyPolyScalarCoeffmod will correct the value back to [0, p)
        inverseNttNegacyclicHarveyLazy(temp_dest_q.asPointer(), dest_size, base_q_size, base_q_ntt_tables);
        inverseNttNegacyclicHarveyLazy(temp_dest_Bsk.asPointer(), dest_size, base_Bsk_size, base_Bsk_ntt_tables);

        // std::cout << "after ntt temp_dest_q: ";
        // printArray(temp_dest_q);
        // std::cout << "after ntt temp_dest_Bsk: ";
        // printArray(temp_dest_Bsk);

        // std::cout << "last dest process\n";
        // Perform BEHZ steps (6)-(8)
        for (size_t i = 0; i < dest_size; i++) {
        // SEAL_ITERATE(iter(temp_dest_q, temp_dest_Bsk, encrypted1), dest_size, [&](auto I) {
            // Bring together the base q and base Bsk components into a single allocation
            auto temp_q_Bsk = allocatePoly(coeff_count, base_q_size + base_Bsk_size);

            // Step (6): multiply base q components by t (plain_modulus)
            multiplyPolyScalarCoeffmod(temp_dest_q + i * coeff_count * base_q_size, base_q_size, coeff_count, plain_modulus, base_q, temp_q_Bsk.asPointer());

            multiplyPolyScalarCoeffmod(temp_dest_Bsk + i * coeff_count * base_Bsk_size, base_Bsk_size, coeff_count, plain_modulus, base_Bsk, temp_q_Bsk + base_q_size * coeff_count);

            // std::cout << "i = " << i << std::endl;
            // std::cout << "temp_q_Bsk" << std::endl;
            // printArray(temp_q_Bsk);

            // Allocate yet another temporary for fast divide-and-floor result in base Bsk
            auto temp_Bsk = allocatePoly(coeff_count, base_Bsk_size);

            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool->fastFloor(temp_q_Bsk.asPointer(), temp_Bsk.asPointer());


            // std::cout << "temp_Bsk" << std::endl;
            // printArray(temp_Bsk);

            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool->fastbconvSk(temp_Bsk.asPointer(), encrypted1.data(i));
        
            // std::cout << "enc i" << std::endl;
            // printArray(encrypted1.data(i), coeff_count * base_q_size);
        }
        
        // printArray(encrypted1.data(), dest_size * base_q_size * coeff_count, true);
    }

    void Evaluator::ckksMultiply(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        if (!(encrypted1.isNttForm() && encrypted2.isNttForm()))
        {
            throw invalid_argument("encrypted1 or encrypted2 must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!productFitsIn(dest_size, mul_safe(coeff_count, coeff_modulus_size)))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = parms.coeffModulus().data();

        // Prepare destination
        encrypted1.resize(context_, context_data.parmsID(), dest_size);

        // Set up iterators for input ciphertexts
        // PolyIter encrypted1_iter = iter(encrypted1);
        // ConstPolyIter encrypted2_iter = iter(encrypted2);

        // Allocate temporary space for the result
        auto temp = allocateZeroPolyArray(dest_size, coeff_count, coeff_modulus_size);

        for (size_t i = 0; i < dest_size; i++) {
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            size_t curr_encrypted1_last = min<size_t>(i, encrypted1_size - 1);
            size_t curr_encrypted2_first = min<size_t>(i, encrypted2_size - 1);
            size_t curr_encrypted1_first = i - curr_encrypted2_first;
            // size_t curr_encrypted2_last = secret_power_index - curr_encrypted1_last;

            // The total number of dyadic products is now easy to compute
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            size_t d = coeff_count * coeff_modulus_size;

            // Create a shifted iterator for the first input
            auto shifted_encrypted1_iter = encrypted1.data(curr_encrypted1_first);

            // Create a shifted reverse iterator for the second input
            auto shifted_reversed_encrypted2_iter = encrypted2.data(curr_encrypted2_first);

            for (size_t j = 0; j < steps; j++) {
                for (size_t k = 0; k < coeff_modulus_size; k++) {
                    auto prod = allocateUint(coeff_count);
                    dyadicProductCoeffmod(shifted_encrypted1_iter + j * d + k * coeff_count, shifted_reversed_encrypted2_iter - j * d + k * coeff_count, coeff_count, coeff_modulus[k], prod.asPointer());
                    addPolyCoeffmod(prod.asPointer(), temp + i * d + k * coeff_count, coeff_count, coeff_modulus[k], temp + i * d + k * coeff_count);
                }
            }
        }

        // Set the final result
        setPolyArray(temp.get(), dest_size, coeff_count, coeff_modulus_size, encrypted1.data());

        // Set the scale
        encrypted1.scale() *= encrypted2.scale();
        if (!isScaleWithinBounds(encrypted1.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::bgvMultiply(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        if (encrypted1.isNttForm() || encrypted2.isNttForm())
        {
            throw invalid_argument("encryped1 or encrypted2 must be not in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        auto ntt_table = context_data.smallNTTTables();

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Set up iterator for the base
        auto coeff_modulus = parms.coeffModulus().data();

        // Prepare destination
        encrypted1.resize(context_, context_data.parmsID(), dest_size);

        // Convert c0 and c1 to ntt
        // Set up iterators for input ciphertexts
        HostPointer<uint64_t> encrypted1_iter = encrypted1.data();
        nttNegacyclicHarvey(encrypted1.data(), encrypted1_size, coeff_modulus_size, ntt_table);
        HostPointer<uint64_t> encrypted2_iter;
        Ciphertext encrypted2_cpy;
        if (&encrypted1 == &encrypted2)
        {
            encrypted2_iter = encrypted1.data();
        }
        else
        {
            encrypted2_cpy = encrypted2;
            nttNegacyclicHarvey(encrypted2_cpy.data(), encrypted2_size, coeff_modulus_size, ntt_table);
            encrypted2_iter = encrypted2_cpy.data();
        }

        // Allocate temporary space for the result
        auto temp = allocateZeroPolyArray(dest_size, coeff_count, coeff_modulus_size);

        for (size_t i = 0; i < dest_size; i++) {
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            size_t curr_encrypted1_last = min<size_t>(i, encrypted1_size - 1);
            size_t curr_encrypted2_first = min<size_t>(i, encrypted2_size - 1);
            size_t curr_encrypted1_first = i - curr_encrypted2_first;
            // size_t curr_encrypted2_last = secret_power_index - curr_encrypted1_last;

            // The total number of dyadic products is now easy to compute
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            size_t d = coeff_count * coeff_modulus_size;

            // Create a shifted iterator for the first input
            auto shifted_encrypted1_iter = encrypted1_iter + curr_encrypted1_first * d;

            // Create a shifted reverse iterator for the second input
            auto shifted_reversed_encrypted2_iter = encrypted2_iter + curr_encrypted2_first * d;

            for (size_t j = 0; j < steps; j++) {
                for (size_t k = 0; k < coeff_modulus_size; k++) {
                    auto prod = allocateUint(coeff_count);
                    dyadicProductCoeffmod(
                        shifted_encrypted1_iter + j * d + k * coeff_count, 
                        shifted_reversed_encrypted2_iter - j * d + k * coeff_count, 
                        coeff_count, coeff_modulus[k], prod.asPointer());
                    addPolyCoeffmod(prod.asPointer(), 
                        temp + i * d + k * coeff_count, 
                        coeff_count, coeff_modulus[k], 
                        temp + i * d + k * coeff_count);
                }
            }
        }

        // Set the final result
        setPolyArray(temp.get(), dest_size, coeff_count, coeff_modulus_size, encrypted1.data());

        // Convert the result (and the original ciphertext) back to non-NTT
        inverseNttNegacyclicHarvey(encrypted1.data(), encrypted1.size(), coeff_modulus_size, ntt_table);

        // Set the correction factor
        encrypted1.correctionFactor() =
            multiplyUintMod(encrypted1.correctionFactor(), encrypted2.correctionFactor(), parms.plainModulus());
    }

    void Evaluator::squareInplace(Ciphertext &encrypted) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.firstContextData();
        switch (context_data_ptr->parms().scheme())
        {
        case SchemeType::bfv:
            bfvSquare(encrypted);
            break;

        case SchemeType::ckks:
            ckksSquare(encrypted);
            break;

        case SchemeType::bgv:
            bgvSquare(encrypted);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Evaluator::bfvSquare(Ciphertext &encrypted) const
    {
        if (encrypted.isNttForm())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t base_q_size = parms.coeffModulus().size();
        size_t encrypted_size = encrypted.size();
        uint64_t plain_modulus = parms.plainModulus().value();

        auto rns_tool = context_data.rnsTool();
        size_t base_Bsk_size = rns_tool->baseBsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->baseBskmTilde()->size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            bfvMultiply(encrypted, encrypted);
            return;
        }

        // Determine destination.size()
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!productFitsIn(dest_size, mul_safe(coeff_count, base_Bsk_m_tilde_size)))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterators for bases
        auto base_q = parms.coeffModulus().data();
        auto base_Bsk = rns_tool->baseBsk()->base();

        // Set up iterators for NTT tables
        auto base_q_ntt_tables = context_data.smallNTTTables();
        auto base_Bsk_ntt_tables = rns_tool->baseBskNttTables();

        // Microsoft SEAL uses BEHZ-style RNS multiplication. For details, see Evaluator::bfv_multiply. This function
        // uses additionally Karatsuba multiplication to reduce the complexity of squaring a size-2 ciphertext, but the
        // steps are otherwise the same as in Evaluator::bfv_multiply.

        // Resize encrypted to destination size
        encrypted.resize(context_, context_data.parmsID(), dest_size);

        // Allocate space for a base q output of behz_extend_base_convertToNtt
        auto encrypted_q = allocatePolyArray(encrypted_size, coeff_count, base_q_size);
        // SEAL_ALLOCATE_GET_POLY_ITER(encrypted_q, encrypted_size, coeff_count, base_q_size, pool);

        // Allocate space for a base Bsk output of behz_extend_base_convertToNtt
        auto encrypted_Bsk = allocatePolyArray(encrypted_size, coeff_count, base_Bsk_size);
        // SEAL_ALLOCATE_GET_POLY_ITER(encrypted_Bsk, encrypted_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ steps (1)-(3)
        for (size_t i = 0; i < encrypted_size; i++) {
        // SEAL_ITERATE(iter(encrypted, encrypted_q, encrypted_Bsk), encrypted_size, 

        // This lambda function takes as input an IterTuple with three components:
        //
        // 1. (Const)RNSIter to read an input polynomial from
        // 2. RNSIter for the output in base q
        // 3. RNSIter for the output in base Bsk
        //
        // It performs steps (1)-(3) of the BEHZ multiplication on the given input polynomial (given as an RNSIter
        // or ConstRNSIter) and writes the results in base q and base Bsk to the given output iterators.
        // [&](auto I) {
            // Make copy of input polynomial (in base q) and convert to NTT form
            // Lazy reduction
            setPoly(encrypted.data(i), coeff_count, base_q_size, encrypted_q.get() + i * coeff_count * base_q_size);
            nttNegacyclicHarveyLazy(encrypted_q.get() + i * coeff_count * base_q_size, base_q_size, base_q_ntt_tables);

            // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
            // FIXME: allocate related action frequent
            auto temp = allocatePoly(coeff_count, base_Bsk_m_tilde_size);
            // SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, base_Bsk_m_tilde_size, pool);

            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool->fastbconvmTilde(encrypted.data(i), temp.asPointer());

            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            rns_tool->smMrq(temp.asPointer(), encrypted_Bsk.get() + i * coeff_count * base_Bsk_size);

            // Transform to NTT form in base Bsk
            // Lazy reduction
            nttNegacyclicHarveyLazy(encrypted_Bsk.get() + i * coeff_count * base_Bsk_size, base_Bsk_size, base_Bsk_ntt_tables);
        }

        


        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components
        auto temp_dest_q = allocateZeroPolyArray(dest_size, coeff_count, base_q_size);
        auto temp_dest_Bsk = allocateZeroPolyArray(dest_size, coeff_count, base_Bsk_size);

        // Perform BEHZ step (4): dyadic Karatsuba-squaring on size-2 ciphertexts

        // This lambda function computes the size-2 ciphertext square for BFV multiplication. Since we use the BEHZ
        // approach, the multiplication of individual polynomials is done using a dyadic product where the inputs
        // are already in NTT form. The arguments of the lambda function are expected to be as follows:
        //
        // 1. a ConstPolyIter pointing to the beginning of the input ciphertext (in NTT form)
        // 3. a ConstModulusIter pointing to an array of Modulus elements for the base
        // 4. the size of the base
        // 5. a PolyIter pointing to the beginning of the output ciphertext

        size_t d_q = coeff_count * base_q_size;
        size_t d_Bsk = coeff_count * base_Bsk_size;

        // Perform the BEHZ ciphertext square both for base q and base Bsk
        
        // Compute c0^2
        dyadicProductCoeffmod(encrypted_q + 0 * d_q, encrypted_q + 0 * d_q, base_q_size, coeff_count, base_q, temp_dest_q + 0 * d_q);
        // Compute 2*c0*c1
        dyadicProductCoeffmod(encrypted_q + 0 * d_q, encrypted_q + 1 * d_q, base_q_size, coeff_count, base_q, temp_dest_q + 1 * d_q);
        addPolyCoeffmod(temp_dest_q + 1 * d_q, temp_dest_q + 1 * d_q, base_q_size, coeff_count, base_q, temp_dest_q + 1 * d_q);
        // Compute c1^2
        dyadicProductCoeffmod(encrypted_q + 1 * d_q, encrypted_q + 1 * d_q, base_q_size, coeff_count, base_q, temp_dest_q + 2 * d_q);
        
        // Compute c0^2
        dyadicProductCoeffmod(encrypted_Bsk + 0 * d_Bsk, encrypted_Bsk + 0 * d_Bsk, base_Bsk_size, coeff_count, base_Bsk, temp_dest_Bsk + 0 * d_Bsk);
        // Compute 2*c0*c1
        dyadicProductCoeffmod(encrypted_Bsk + 0 * d_Bsk, encrypted_Bsk + 1 * d_Bsk, base_Bsk_size, coeff_count, base_Bsk, temp_dest_Bsk + 1 * d_Bsk);
        addPolyCoeffmod(temp_dest_Bsk + 1 * d_Bsk, temp_dest_Bsk + 1 * d_Bsk, base_Bsk_size, coeff_count, base_Bsk, temp_dest_Bsk + 1 * d_Bsk);
        // Compute c1^2
        dyadicProductCoeffmod(encrypted_Bsk + 1 * d_Bsk, encrypted_Bsk + 1 * d_Bsk, base_Bsk_size, coeff_count, base_Bsk, temp_dest_Bsk + 2 * d_Bsk);

        // Perform BEHZ step (5): transform data from NTT form
        inverseNttNegacyclicHarvey(temp_dest_q.asPointer(), dest_size, base_q_size, base_q_ntt_tables);
        inverseNttNegacyclicHarvey(temp_dest_Bsk.asPointer(), dest_size, base_Bsk_size, base_Bsk_ntt_tables);

        // Perform BEHZ steps (6)-(8)
        for (size_t i = 0; i < dest_size; i++) {
        // SEAL_ITERATE(iter(temp_dest_q, temp_dest_Bsk, encrypted1), dest_size, [&](auto I) {
            // Bring together the base q and base Bsk components into a single allocation
            auto temp_q_Bsk = allocatePoly(coeff_count, base_q_size + base_Bsk_size);

            // Step (6): multiply base q components by t (plain_modulus)
            multiplyPolyScalarCoeffmod(temp_dest_q + i * coeff_count * base_q_size, base_q_size, coeff_count, plain_modulus, base_q, temp_q_Bsk.asPointer());

            multiplyPolyScalarCoeffmod(temp_dest_Bsk + i * coeff_count * base_Bsk_size, base_Bsk_size, coeff_count, plain_modulus, base_Bsk, temp_q_Bsk + base_q_size * coeff_count);

            // Allocate yet another temporary for fast divide-and-floor result in base Bsk
            auto temp_Bsk = allocatePoly(coeff_count, base_Bsk_size);

            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool->fastFloor(temp_q_Bsk.asPointer(), temp_Bsk.asPointer());

            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool->fastbconvSk(temp_Bsk.asPointer(), encrypted.data(i));
        }
    }

    void Evaluator::ckksSquare(Ciphertext &encrypted) const
    {
        if (!encrypted.isNttForm())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted_size = encrypted.size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            ckksMultiply(encrypted, encrypted);
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!productFitsIn(dest_size, mul_safe(coeff_count, coeff_modulus_size)))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = parms.coeffModulus().data();

        // Prepare destination
        encrypted.resize(context_, context_data.parmsID(), dest_size);
        size_t d = coeff_count * coeff_modulus_size;

        // Set up iterators for input ciphertext
        auto encrypted_iter = encrypted.data();

        // Compute c1^2
        dyadicProductCoeffmod(
            encrypted_iter + 1 * d, encrypted_iter + 1 * d, coeff_modulus_size, coeff_count, coeff_modulus, encrypted_iter + 2 * d);

        // Compute 2*c0*c1
        dyadicProductCoeffmod(
            encrypted_iter + 0 * d, encrypted_iter + 1 * d, coeff_modulus_size, coeff_count, coeff_modulus, encrypted_iter + 1 * d);
        addPolyCoeffmod(encrypted_iter + 1 * d, encrypted_iter + 1 * d, coeff_modulus_size, coeff_count, coeff_modulus, encrypted_iter + 1 * d);

        // Compute c0^2
        dyadicProductCoeffmod(
            encrypted_iter + 0 * d, encrypted_iter + 0 * d, coeff_modulus_size, coeff_count, coeff_modulus, encrypted_iter + 0 * d);

        // Set the scale
        encrypted.scale() *= encrypted.scale();
        if (!isScaleWithinBounds(encrypted.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::bgvSquare(Ciphertext &encrypted) const
    {
        if (encrypted.isNttForm())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted_size = encrypted.size();
        auto ntt_table = context_data.smallNTTTables();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            bgvMultiply(encrypted, encrypted);
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!productFitsIn(dest_size, mul_safe(coeff_count, coeff_modulus_size)))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = parms.coeffModulus().data();

        // Prepare destination
        encrypted.resize(context_, context_data.parmsID(), dest_size);

        // Convert c0 and c1 to ntt
        nttNegacyclicHarvey(encrypted.data(), encrypted_size, coeff_modulus_size, ntt_table);

        // Set up iterators for input ciphertext
        auto encrypted_iter = encrypted.data();

        // Allocate temporary space for the result
        auto temp = allocateZeroPolyArray(dest_size, coeff_count, coeff_modulus_size);
        size_t d = coeff_count * coeff_modulus_size;

        // Compute c0^2
        dyadicProductCoeffmod(encrypted_iter + 0 * d, encrypted_iter + 0 * d, coeff_modulus_size, coeff_count, coeff_modulus, temp + 0 * d);

        // Compute 2*c0*c1
        dyadicProductCoeffmod(encrypted_iter+ 0 * d, encrypted_iter + 1 * d, coeff_modulus_size, coeff_count, coeff_modulus, temp + 1 * d);
        addPolyCoeffmod(temp + 1 * d, temp + 1 * d, coeff_modulus_size, coeff_count, coeff_modulus, temp + 1 * d);

        // Compute c1^2
        dyadicProductCoeffmod(encrypted_iter + 1 * d, encrypted_iter + 1 * d, coeff_modulus_size, coeff_count, coeff_modulus, temp + 2 * d);

        // Set the final result
        setPolyArray(temp.get(), dest_size, coeff_count, coeff_modulus_size, encrypted.data());

        // Convert the final output to Non-NTT form
        inverseNttNegacyclicHarvey(encrypted.data(), dest_size, coeff_modulus_size, ntt_table);

        // Set the correction factor
        encrypted.correctionFactor() =
            multiplyUintMod(encrypted.correctionFactor(), encrypted.correctionFactor(), parms.plainModulus());
    }

    void Evaluator::relinearizeInternal(
        Ciphertext &encrypted, const RelinKeys &relin_keys, size_t destination_size) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (relin_keys.parmsID() != context_.keyParmsID())
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }

        size_t encrypted_size = encrypted.size();

        // Verify parameters.
        if (destination_size < 2 || destination_size > encrypted_size)
        {
            throw invalid_argument("destination_size must be at least 2 and less than or equal to current count");
        }
        if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
        {
            throw invalid_argument("not enough relinearization keys");
        }

        // If encrypted is already at the desired level, return
        if (destination_size == encrypted_size)
        {
            return;
        }

        // Calculate number of relinearize_one_step calls needed
        size_t relins_needed = encrypted_size - destination_size;

        // Iterator pointing to the last component of encrypted
        auto encrypted_iter = encrypted.data(encrypted_size - 1);

        for (size_t i = 0; i < relins_needed; i++) {
            // std::cout << "encrypted_iter diff = " << std::dec << encrypted_iter - encrypted.data() << std::endl;
            this->switchKeyInplace(
                encrypted, encrypted_iter, static_cast<const KSwitchKeys &>(relin_keys),
                RelinKeys::getIndex(encrypted_size - 1 - i));
            // std::cout << "relinearization " << i << ":";
            // printArray(encrypted.data(), encrypted.dynArray().size());
        }

        // Put the output of final relinearization into destination.
        // Prepare destination only at this point because we are resizing down
        encrypted.resize(context_, context_data_ptr->parmsID(), destination_size);
    }

    void Evaluator::modSwitchScaleToNext(
        const Ciphertext &encrypted, Ciphertext &destination) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (context_data_ptr->parms().scheme() == SchemeType::bfv && encrypted.isNttForm())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == SchemeType::ckks && !encrypted.isNttForm())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == SchemeType::bgv && encrypted.isNttForm())
        {
            throw invalid_argument("BGV encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &next_context_data = *context_data.nextContextData();
        auto &next_parms = next_context_data.parms();
        auto rns_tool = context_data.rnsTool();

        size_t encrypted_size = encrypted.size();
        size_t coeff_count = next_parms.polyModulusDegree();
        size_t next_coeff_modulus_size = next_parms.coeffModulus().size();
        
        // size_t d = context_data.parms().coeffModulus().size() * context_

        Ciphertext encrypted_copy;
        encrypted_copy = encrypted;

        switch (next_parms.scheme())
        {
        case SchemeType::bfv:
            for (size_t i = 0; i < encrypted_size; i++) 
                rns_tool->divideAndRoundqLastInplace(encrypted_copy.data(i));
            break;

        case SchemeType::ckks:
            for (size_t i = 0; i < encrypted_size; i++) 
                rns_tool->divideAndRoundqLastNttInplace(encrypted_copy.data(i), context_data.smallNTTTables());
            break;

        case SchemeType::bgv:
            for (size_t i = 0; i < encrypted_size; i++) 
                rns_tool->modTAndDivideqLastInplace(encrypted_copy.data(i));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }

        // Copy result to destination
        destination.resize(context_, next_context_data.parmsID(), encrypted_size);
        for (size_t i = 0; i < encrypted_size; i++) {
            setPoly(encrypted_copy.data(i), coeff_count, next_coeff_modulus_size, destination.data(i));
        }

        // Set other attributes
        destination.isNttForm() = encrypted.isNttForm();
        if (next_parms.scheme() == SchemeType::ckks)
        {
            // Change the scale when using CKKS
            destination.scale() =
                encrypted.scale() / static_cast<double>(context_data.parms().coeffModulus().back().value());
        }
        else if (next_parms.scheme() == SchemeType::bgv)
        {
            // Change the correction factor when using BGV
            destination.correctionFactor() = multiplyUintMod(
                encrypted.correctionFactor(), rns_tool->invqLastModt(), next_parms.plainModulus());
        }
    }

    void Evaluator::modSwitchDropToNext(
        const Ciphertext &encrypted, Ciphertext &destination) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (context_data_ptr->parms().scheme() == SchemeType::ckks && !encrypted.isNttForm())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->nextContextData();
        auto &next_parms = next_context_data.parms();

        if (!isScaleWithinBounds(encrypted.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        size_t next_coeff_modulus_size = next_parms.coeffModulus().size();
        size_t coeff_count = next_parms.polyModulusDegree();
        size_t encrypted_size = encrypted.size();

        // Size check
        if (!productFitsIn(encrypted_size, mul_safe(coeff_count, next_coeff_modulus_size)))
        {
            throw logic_error("invalid parameters");
        }

        if (&encrypted == &destination)
        {
            // Switching in-place so need temporary space
            auto temp = allocatePolyArray(encrypted_size, coeff_count, next_coeff_modulus_size);

            // Copy data over to temp; only copy the RNS components relevant after modulus drop
            for (size_t i = 0; i < encrypted_size; i++) {
                for (size_t j = 0; j < next_coeff_modulus_size; j++) {
                    setUint(encrypted.data(i) + j * coeff_count, coeff_count, temp.get() + i * coeff_count * next_coeff_modulus_size + j * coeff_count);
                }
            }

            // Resize destination before writing
            destination.resize(context_, next_context_data.parmsID(), encrypted_size);

            // Copy data to destination
            setPolyArray(temp.get(), encrypted_size, coeff_count, next_coeff_modulus_size, destination.data());
            // TODO: avoid copying and temporary space allocation
        }
        else
        {
            // Resize destination before writing
            destination.resize(context_, next_context_data.parmsID(), encrypted_size);

            // Copy data over to destination; only copy the RNS components relevant after modulus drop
            for (size_t i = 0; i < encrypted_size; i++) {
                for (size_t j = 0; j < next_coeff_modulus_size; j++) {
                    setUint(encrypted.data(i) + j * coeff_count, coeff_count, destination.data(i) + j * coeff_count);
                }
            }
        }
        destination.isNttForm() = true;
        destination.scale() = encrypted.scale();
        destination.correctionFactor() = encrypted.correctionFactor();
    }

    void Evaluator::modSwitchDropToNext(Plaintext &plain) const
    {
        // Assuming at this point plain is already validated.
        auto context_data_ptr = context_.getContextData(plain.parmsID());
        if (!plain.isNttForm())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (!context_data_ptr->nextContextData())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->nextContextData();
        auto &next_parms = context_data_ptr->nextContextData()->parms();

        if (!isScaleWithinBounds(plain.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        auto &next_coeff_modulus = next_parms.coeffModulus();
        size_t next_coeff_modulus_size = next_coeff_modulus.size();
        size_t coeff_count = next_parms.polyModulusDegree();

        // Compute destination size first for exception safety
        auto dest_size = mul_safe(next_coeff_modulus_size, coeff_count);

        plain.parmsID() = parmsIDZero;
        plain.resize(dest_size);
        plain.parmsID() = next_context_data.parmsID();
    }

    void Evaluator::modSwitchToNext(
        const Ciphertext &encrypted, Ciphertext &destination) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (context_.lastParmsID() == encrypted.parmsID())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        switch (context_.firstContextData()->parms().scheme())
        {
        case SchemeType::bfv:
            // Modulus switching with scaling
            modSwitchScaleToNext(encrypted, destination);
            break;

        case SchemeType::ckks:
            // Modulus switching without scaling
            modSwitchDropToNext(encrypted, destination);
            break;

        case SchemeType::bgv:
            modSwitchScaleToNext(encrypted, destination);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Evaluator::modSwitchToInplace(Ciphertext &encrypted, ParmsID parms_id) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        auto targetContextData_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!targetContextData_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chainIndex() < targetContextData_ptr->chainIndex())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (encrypted.parmsID() != parms_id)
        {
            modSwitchToNextInplace(encrypted);
        }
    }

    void Evaluator::modSwitchToInplace(Plaintext &plain, ParmsID parms_id) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(plain.parmsID());
        auto targetContextData_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!context_.getContextData(parms_id))
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!plain.isNttForm())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (context_data_ptr->chainIndex() < targetContextData_ptr->chainIndex())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (plain.parmsID() != parms_id)
        {
            modSwitchToNextInplace(plain);
        }
    }

    void Evaluator::rescaleToNext(const Ciphertext &encrypted, Ciphertext &destination) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (context_.lastParmsID() == encrypted.parmsID())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        switch (context_.firstContextData()->parms().scheme())
        {
        case SchemeType::bfv:
            /* Fall through */
        case SchemeType::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case SchemeType::ckks:
            // Modulus switching with scaling
            modSwitchScaleToNext(encrypted, destination);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Evaluator::rescaleToInplace(Ciphertext &encrypted, ParmsID parms_id) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        auto targetContextData_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!targetContextData_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chainIndex() < targetContextData_ptr->chainIndex())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        switch (context_data_ptr->parms().scheme())
        {
        case SchemeType::bfv:
            /* Fall through */
        case SchemeType::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case SchemeType::ckks:
            while (encrypted.parmsID() != parms_id)
            {
                // Modulus switching with scaling
                modSwitchScaleToNext(encrypted, encrypted);
            }
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Evaluator::multiplyMany(
        const vector<Ciphertext> &encrypteds, const RelinKeys &relin_keys, Ciphertext &destination) const
    {
        // Verify parameters.
        if (encrypteds.size() == 0)
        {
            throw invalid_argument("encrypteds vector must not be empty");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        // There is at least one ciphertext
        auto context_data_ptr = context_.getContextData(encrypteds[0].parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypteds is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();

        if (parms.scheme() != SchemeType::bfv && parms.scheme() != SchemeType::bgv)
        {
            throw logic_error("unsupported scheme");
        }

        // If there is only one ciphertext, return it.
        if (encrypteds.size() == 1)
        {
            destination = encrypteds[0];
            return;
        }

        // Do first level of multiplications
        vector<Ciphertext> product_vec;
        for (size_t i = 0; i < encrypteds.size() - 1; i += 2)
        {
            Ciphertext temp(context_, context_data.parmsID());
            if (encrypteds[i].data() == encrypteds[i + 1].data())
            {
                square(encrypteds[i], temp);
            }
            else
            {
                multiply(encrypteds[i], encrypteds[i + 1], temp);
            }
            relinearizeInplace(temp, relin_keys);
            product_vec.emplace_back(move(temp));
        }
        if (encrypteds.size() & 1)
        {
            product_vec.emplace_back(encrypteds.back());
        }

        // Repeatedly multiply and add to the back of the vector until the end is reached
        for (size_t i = 0; i < product_vec.size() - 1; i += 2)
        {
            Ciphertext temp(context_, context_data.parmsID());
            multiply(product_vec[i], product_vec[i + 1], temp);
            relinearizeInplace(temp, relin_keys);
            product_vec.emplace_back(move(temp));
        }

        destination = product_vec.back();
    }

    void Evaluator::exponentiateInplace(
        Ciphertext &encrypted, uint64_t exponent, const RelinKeys &relin_keys) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.getContextData(relin_keys.parmsID()))
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }
        if (exponent == 0)
        {
            throw invalid_argument("exponent cannot be 0");
        }

        // Fast case
        if (exponent == 1)
        {
            return;
        }

        // Create a vector of copies of encrypted
        vector<Ciphertext> exp_vector(static_cast<size_t>(exponent), encrypted);
        multiplyMany(exp_vector, relin_keys, encrypted);
    }

    void Evaluator::addPlainInplace(Ciphertext &encrypted, const Plaintext &plain) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!isMetadataValidFor(plain, context_) || !isBufferValid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        if (parms.scheme() == SchemeType::bfv && encrypted.isNttForm())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (parms.scheme() == SchemeType::ckks && !encrypted.isNttForm())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (parms.scheme() == SchemeType::bgv && encrypted.isNttForm())
        {
            throw invalid_argument("BGV encrypted cannot be in NTT form");
        }
        if (plain.isNttForm() != encrypted.isNttForm())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (encrypted.isNttForm() && (encrypted.parmsID() != plain.parmsID()))
        {
            throw invalid_argument("encrypted and plain parameter mismatch");
        }
        if (!areSameScale(encrypted, plain))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case SchemeType::bfv:
        {
            multiplyAddPlainWithScalingVariant(plain, context_data, encrypted.data(0));
            break;
        }

        case SchemeType::ckks:
        {
            HostPointer encrypted_iter(encrypted.data());
            ConstHostPointer plain_iter(plain.data());
            addPolyCoeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_count, coeff_modulus.data(), encrypted_iter);
            break;
        }

        case SchemeType::bgv:
        {
            Plaintext plain_copy = plain;
            multiplyPolyScalarCoeffmod(
                plain.data(), plain.coeffCount(), encrypted.correctionFactor(), parms.plainModulus(),
                plain_copy.data());
            addPlainWithoutScalingVariant(plain_copy, context_data, encrypted.data(0));
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Evaluator::subPlainInplace(Ciphertext &encrypted, const Plaintext &plain) const
    {        
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!isMetadataValidFor(plain, context_) || !isBufferValid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        if (parms.scheme() == SchemeType::bfv && encrypted.isNttForm())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (parms.scheme() == SchemeType::ckks && !encrypted.isNttForm())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (parms.scheme() == SchemeType::bgv && encrypted.isNttForm())
        {
            throw invalid_argument("BGV encrypted cannot be in NTT form");
        }
        if (plain.isNttForm() != encrypted.isNttForm())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (encrypted.isNttForm() && (encrypted.parmsID() != plain.parmsID()))
        {
            throw invalid_argument("encrypted and plain parameter mismatch");
        }
        if (!areSameScale(encrypted, plain))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case SchemeType::bfv:
        {
            multiplySubPlainWithScalingVariant(plain, context_data, encrypted.data(0));
            break;
        }

        case SchemeType::ckks:
        {
            HostPointer encrypted_iter(encrypted.data());
            ConstHostPointer plain_iter(plain.data());
            subPolyCoeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_count, coeff_modulus.data(), encrypted_iter);
            break;
        }

        case SchemeType::bgv:
        {
            Plaintext plain_copy = plain;
            multiplyPolyScalarCoeffmod(
                plain.data(), plain.coeffCount(), encrypted.correctionFactor(), parms.plainModulus(),
                plain_copy.data());
            subPlainWithoutScalingVariant(plain_copy, context_data, encrypted.data(0));
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Evaluator::multiplyPlainInplace(Ciphertext &encrypted, const Plaintext &plain) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!isMetadataValidFor(plain, context_) || !isBufferValid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (encrypted.isNttForm() != plain.isNttForm())
        {
            throw invalid_argument("NTT form mismatch");
        }

        if (encrypted.isNttForm())
        {
            multiplyPlainNtt(encrypted, plain);
        }
        else
        {
            multiplyPlainNormal(encrypted, plain);
        }
    }

    void Evaluator::multiplyPlainNormal(Ciphertext &encrypted, const Plaintext &plain) const
    {
        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();

        uint64_t plain_upper_half_threshold = context_data.plainUpperHalfThreshold();
        auto plain_upper_half_increment = context_data.plainUpperHalfIncrement();
        auto ntt_tables = context_data.smallNTTTables();

        size_t encrypted_size = encrypted.size();
        size_t plain_coeff_count = plain.coeffCount();
        size_t plain_nonzero_coeff_count = plain.nonzeroCoeffCount();

        // Size check
        if (!productFitsIn(encrypted_size, mul_safe(coeff_count, coeff_modulus_size)))
        {
            throw logic_error("invalid parameters");
        }

        /*
        Optimizations for constant / monomial multiplication can lead to the presence of a timing side-channel in
        use-cases where the plaintext data should also be kept private.
        */
        if (plain_nonzero_coeff_count == 1)
        {
            // Multiplying by a monomial?
            size_t mono_exponent = plain.significantCoeffCount() - 1;

            if (plain[mono_exponent] >= plain_upper_half_threshold)
            {
                if (!context_data.qualifiers().using_fast_plain_lift)
                {
                    // Allocate temporary space for a single RNS coefficient
                    auto temp = allocateUint(coeff_modulus_size);
                    // SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_modulus_size, pool);

                    // We need to adjust the monomial modulo each coeff_modulus prime separately when the coeff_modulus
                    // primes may be larger than the plain_modulus. We add plain_upper_half_increment (i.e., q-t) to
                    // the monomial to ensure it is smaller than coeff_modulus and then do an RNS multiplication. Note
                    // that in this case plain_upper_half_increment contains a multi-precision integer, so after the
                    // addition we decompose the multi-precision integer into RNS components, and then multiply.
                    addUint(plain_upper_half_increment, coeff_modulus_size, plain[mono_exponent], temp.get());
                    context_data.rnsTool()->baseq()->decompose(temp.get());
                    negacyclicMultiplyPolyMonoCoeffmod(
                        encrypted.data(), encrypted_size, coeff_modulus_size, coeff_count, temp.asPointer(), mono_exponent, coeff_modulus.data(), encrypted.data());
                }
                else
                {
                    // Every coeff_modulus prime is larger than plain_modulus, so there is no need to adjust the
                    // monomial. Instead, just do an RNS multiplication.
                    negacyclicMultiplyPolyMonoCoeffmod(
                        encrypted.data(), encrypted_size, coeff_modulus_size, coeff_count, plain[mono_exponent], mono_exponent, coeff_modulus.data(), encrypted.data());
                }
            }
            else
            {
                // The monomial represents a positive number, so no RNS multiplication is needed.
                negacyclicMultiplyPolyMonoCoeffmod(
                    encrypted.data(), encrypted_size, coeff_modulus_size, coeff_count, plain[mono_exponent], mono_exponent, coeff_modulus.data(), encrypted.data());
            }

            // Set the scale
            if (parms.scheme() == SchemeType::ckks)
            {
                encrypted.scale() *= plain.scale();
                if (!isScaleWithinBounds(encrypted.scale(), context_data))
                {
                    throw invalid_argument("scale out of bounds");
                }
            }

            return;
        }

        // Generic case: any plaintext polynomial
        // Allocate temporary space for an entire RNS polynomial
        auto temp = allocateZeroPoly(coeff_count, coeff_modulus_size);

        if (!context_data.qualifiers().using_fast_plain_lift)
        {
            // StrideIter<uint64_t *> temp_iter(temp.get(), coeff_modulus_size);

            for (size_t i = 0; i < plain_coeff_count; i++) {
            // SEAL_ITERATE(iter(plain.data(), temp_iter), plain_coeff_count, [&](auto I) {
                auto plain_value = plain.data()[i];
                if (plain_value >= plain_upper_half_threshold)
                {
                    addUint(plain_upper_half_increment, coeff_modulus_size, plain_value, temp.get() + coeff_modulus_size * i);
                }
                else
                {
                    temp[coeff_modulus_size * i] = plain_value;
                }
            }

            context_data.rnsTool()->baseq()->decomposeArray(temp.get(), coeff_count);
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.
            for (size_t i = 0; i < coeff_modulus_size; i++) {
            // SEAL_ITERATE(iter(temp_iter, plain_upper_half_increment), coeff_modulus_size, [&](auto I) {
                for (size_t j = 0; j < plain_coeff_count; j++) {
                // SEAL_ITERATE(iter(get<0>(I), plain.data()), plain_coeff_count, [&](auto J) {
                    temp[i * coeff_count + j] = plain.data()[j] >= plain_upper_half_threshold ? plain.data()[j] + plain_upper_half_increment[i] : plain.data()[j];
                }
            }
        }

        // Need to multiply each component in encrypted with temp; first step is to transform to NTT form
        // RNSIter temp_iter(temp.get(), coeff_count);
        nttNegacyclicHarvey(temp.asPointer(), coeff_modulus_size, ntt_tables);

        for (size_t i = 0; i < encrypted_size; i++) {
        // SEAL_ITERATE(iter(encrypted), encrypted_size, [&](auto I) {
            for (size_t j = 0; j < coeff_modulus_size; j++) {
            // SEAL_ITERATE(iter(I, temp_iter, coeff_modulus, ntt_tables), coeff_modulus_size, [&](auto J) {
                // Lazy reduction
                auto target_ptr = encrypted.data(i) + j * coeff_count;
                nttNegacyclicHarveyLazy(target_ptr, ntt_tables[j]);
                dyadicProductCoeffmod(target_ptr, temp + j * coeff_count, coeff_count, coeff_modulus[j], target_ptr);
                inverseNttNegacyclicHarvey(target_ptr, ntt_tables[j]);
            }
        }

        // Set the scale
        if (parms.scheme() == SchemeType::ckks)
        {
            encrypted.scale() *= plain.scale();
            if (!isScaleWithinBounds(encrypted.scale(), context_data))
            {
                throw invalid_argument("scale out of bounds");
            }
        }
    }

    void Evaluator::multiplyPlainNtt(Ciphertext &encrypted_ntt, const Plaintext &plain_ntt) const
    {
        // Verify parameters.
        if (!plain_ntt.isNttForm())
        {
            throw invalid_argument("plain_ntt is not in NTT form");
        }
        if (encrypted_ntt.parmsID() != plain_ntt.parmsID())
        {
            throw invalid_argument("encrypted_ntt and plain_ntt parameter mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted_ntt.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        // Size check
        if (!productFitsIn(encrypted_ntt_size, mul_safe(coeff_count, coeff_modulus_size)))
        {
            throw logic_error("invalid parameters");
        }

        auto plain_ntt_iter = plain_ntt.data();
        for (size_t i = 0; i < encrypted_ntt_size; i++) {
        // SEAL_ITERATE(iter(encrypted_ntt), encrypted_ntt_size, [&](auto I) {
            dyadicProductCoeffmod(encrypted_ntt.data(i), plain_ntt_iter, coeff_modulus_size, coeff_count, coeff_modulus.data(), encrypted_ntt.data(i));
        }

        // Set the scale
        encrypted_ntt.scale() *= plain_ntt.scale();
        if (!isScaleWithinBounds(encrypted_ntt.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::transformToNttInplace(Plaintext &plain, ParmsID parms_id) const
    {
        // Verify parameters.
        if (!isValidFor(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for the current context");
        }
        if (plain.isNttForm())
        {
            throw invalid_argument("plain is already in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t plain_coeff_count = plain.coeffCount();

        uint64_t plain_upper_half_threshold = context_data.plainUpperHalfThreshold();
        auto plain_upper_half_increment = context_data.plainUpperHalfIncrement();

        auto ntt_tables = context_data.smallNTTTables();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Resize to fit the entire NTT transformed (ciphertext size) polynomial
        // Note that the new coefficients are automatically set to 0
        plain.resize(coeff_count * coeff_modulus_size);
        auto plain_iter = plain.data();

        if (!context_data.qualifiers().using_fast_plain_lift)
        {
            // Allocate temporary space for an entire RNS polynomial
            // Slight semantic misuse of RNSIter here, but this works well
            auto temp = allocateZeroPoly(coeff_modulus_size, coeff_count);
            // SEAL_ALLOCATE_ZERO_GET_RNS_ITER(temp, coeff_modulus_size, coeff_count, pool);

            for (size_t i = 0; i < plain_coeff_count; i++) {
            // SEAL_ITERATE(iter(plain.data(), temp), plain_coeff_count, [&](auto I) {
                auto plain_value = plain.data()[i];
                if (plain_value >= plain_upper_half_threshold)
                {
                    addUint(plain_upper_half_increment, coeff_modulus_size, plain_value, temp.get() + i * coeff_modulus_size);
                }
                else
                {
                    temp[i * coeff_modulus_size] = plain_value;
                }
            }

            context_data.rnsTool()->baseq()->decomposeArray(temp.get(), coeff_count);

            // Copy data back to plain
            setPoly(temp.get(), coeff_count, coeff_modulus_size, plain.data());
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.

            // Create a "reversed" helper iterator that iterates in the reverse order both plain RNS components and
            // the plain_upper_half_increment values.
            // auto helper_iter = reverse_iter(plain_iter, plain_upper_half_increment);
            // advance(helper_iter, -safe_cast<ptrdiff_t>(coeff_modulus_size - 1));

            // SEAL_ITERATE(helper_iter, coeff_modulus_size, [&](auto I) {
            //     SEAL_ITERATE(iter(*plain_iter, get<0>(I)), plain_coeff_count, [&](auto J) {
            //         get<1>(J) =
            //             SEAL_COND_SELECT(get<0>(J) >= plain_upper_half_threshold, get<0>(J) + get<1>(I), get<0>(J));
            //     });
            // });

            for (size_t i = 0; i < coeff_modulus_size; i++) {
                for (size_t j = 0; j < plain_coeff_count; j++) {
                    size_t plain_index = (coeff_modulus_size - 1 - i) * coeff_count + j; // get<1>(J)
                    size_t increment_index = (coeff_modulus_size - 1) - i;
                    plain_iter[plain_index] = (plain_iter[j] >= plain_upper_half_threshold) ?
                        (plain_iter[j] + plain_upper_half_increment[increment_index]) : plain_iter[j];
                 }
            }
        }

        // Transform to NTT domain
        nttNegacyclicHarvey(plain_iter, coeff_modulus_size, ntt_tables);

        plain.parmsID() = parms_id;
    }

    void Evaluator::transformToNttInplace(Ciphertext &encrypted) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (encrypted.isNttForm())
        {
            throw invalid_argument("encrypted is already in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        auto ntt_tables = context_data.smallNTTTables();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial to NTT domain
        nttNegacyclicHarvey(encrypted.data(), encrypted_size, coeff_modulus_size, ntt_tables);

        // Finally change the is_ntt_transformed flag
        encrypted.isNttForm() = true;
    }

    void Evaluator::transformFromNttInplace(Ciphertext &encrypted_ntt) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted_ntt, context_) || !isBufferValid(encrypted_ntt))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.getContextData(encrypted_ntt.parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted_ntt is not valid for encryption parameters");
        }
        if (!encrypted_ntt.isNttForm())
        {
            throw invalid_argument("encrypted_ntt is not in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        auto ntt_tables = context_data.smallNTTTables();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial from NTT domain
        inverseNttNegacyclicHarvey(encrypted_ntt.data(), encrypted_ntt_size, coeff_modulus_size, ntt_tables);

        // Finally change the is_ntt_transformed flag
        encrypted_ntt.isNttForm() = false;
    }

    void Evaluator::applyGaloisInplace(
        Ciphertext &encrypted, uint32_t galois_elt, const GaloisKeys &galois_keys) const
    {
        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Don't validate all of galois_keys but just check the parms_id.
        if (galois_keys.parmsID() != context_.keyParmsID())
        {
            throw invalid_argument("galois_keys is not valid for encryption parameters");
        }

        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();
        // Use key_context_data where permutation tables exist since previous runs.
        auto galois_tool = context_.keyContextData()->galoisTool();

        // Size check
        if (!productFitsIn(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Check if Galois key is generated or not.
        if (!galois_keys.hasKey(galois_elt))
        {
            throw invalid_argument("Galois key not present");
        }

        uint64_t m = mul_safe(static_cast<uint64_t>(coeff_count), uint64_t(2));

        // Verify parameters
        if (!(galois_elt & 1) || galois_elt >= m)
        {
            throw invalid_argument("Galois element is not valid");
        }
        if (encrypted_size > 2)
        {
            throw invalid_argument("encrypted size must be 2");
        }

        // SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, pool);
        auto temp = allocatePoly(coeff_count, coeff_modulus_size);

        // DO NOT CHANGE EXECUTION ORDER OF FOLLOWING SECTION
        // BEGIN: Apply Galois for each ciphertext
        // Execution order is sensitive, since apply_galois is not inplace!
        if (parms.scheme() == SchemeType::bfv || parms.scheme() == SchemeType::bgv)
        {
            // !!! DO NOT CHANGE EXECUTION ORDER!!!

            // First transform encrypted.data(0)
            // auto encrypted_iter = iter(encrypted);
            galois_tool->applyGalois(encrypted.data(0), coeff_modulus_size, galois_elt, coeff_modulus.data(), temp.asPointer());

            // Copy result to encrypted.data(0)
            setPoly(temp.get(), coeff_count, coeff_modulus_size, encrypted.data(0));

            // Next transform encrypted.data(1)
            galois_tool->applyGalois(encrypted.data(1), coeff_modulus_size, galois_elt, coeff_modulus.data(), temp.asPointer());
        }
        else if (parms.scheme() == SchemeType::ckks)
        {
            // !!! DO NOT CHANGE EXECUTION ORDER!!!

            // First transform encrypted.data(0)
            // auto encrypted_iter = iter(encrypted);
            galois_tool->applyGaloisNtt(encrypted.data(0), coeff_modulus_size, galois_elt, temp.asPointer());

            // Copy result to encrypted.data(0)
            setPoly(temp.get(), coeff_count, coeff_modulus_size, encrypted.data(0));

            // Next transform encrypted.data(1)
            galois_tool->applyGaloisNtt(encrypted.data(1), coeff_modulus_size, galois_elt, temp.asPointer());
        }
        else
        {
            throw logic_error("scheme not implemented");
        }

        // Wipe encrypted.data(1)
        setZeroPoly(coeff_count, coeff_modulus_size, encrypted.data(1));

        // END: Apply Galois for each ciphertext
        // REORDERING IS SAFE NOW

        // Calculate (temp * galois_key[0], temp * galois_key[1]) + (ct[0], 0)
        switchKeyInplace(
            encrypted, temp.get(), static_cast<const KSwitchKeys &>(galois_keys), GaloisKeys::getIndex(galois_elt));
    }

    void Evaluator::rotateInternal(
        Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys) const
    {
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_data_ptr->qualifiers().using_batching)
        {
            throw logic_error("encryption parameters do not support batching");
        }
        if (galois_keys.parmsID() != context_.keyParmsID())
        {
            throw invalid_argument("galois_keys is not valid for encryption parameters");
        }

        // Is there anything to do?
        if (steps == 0)
        {
            return;
        }

        size_t coeff_count = context_data_ptr->parms().polyModulusDegree();
        auto galois_tool = context_data_ptr->galoisTool();

        // Check if Galois key is generated or not.
        if (galois_keys.hasKey(galois_tool->getEltFromStep(steps)))
        {
            // Perform rotation and key switching
            applyGaloisInplace(encrypted, galois_tool->getEltFromStep(steps), galois_keys);
        }
        else
        {
            // Convert the steps to NAF: guarantees using smallest HW
            vector<int> naf_steps = naf(steps);

            // If naf_steps contains only one element, then this is a power-of-two
            // rotation and we would have expected not to get to this part of the
            // if-statement.
            if (naf_steps.size() == 1)
            {
                throw invalid_argument("Galois key not present");
            }

            for (size_t i = 0; i < naf_steps.size(); i++) {
            // SEAL_ITERATE(naf_steps.cbegin(), naf_steps.size(), [&](auto step) {
                // We might have a NAF-term of size coeff_count / 2; this corresponds
                // to no rotation so we skip it. Otherwise call rotate_internal.
                if (safe_cast<size_t>(abs(naf_steps[i])) != (coeff_count >> 1))
                {
                    // Apply rotation for this step
                    this->rotateInternal(encrypted, naf_steps[i], galois_keys);
                }
            }
        }
    }

    // target_iter is rnsiter
    void Evaluator::switchKeyInplace(
        Ciphertext &encrypted, ConstHostPointer<uint64_t> target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index) const
    {
        auto parms_id = encrypted.parmsID();
        auto &context_data = *context_.getContextData(parms_id);
        auto &parms = context_data.parms();
        auto &key_context_data = *context_.keyContextData();
        auto &key_parms = key_context_data.parms();
        auto scheme = parms.scheme();

        // Verify parameters.
        if (!isMetadataValidFor(encrypted, context_) || !isBufferValid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (target_iter.isNull())
        {
            throw invalid_argument("target_iter");
        }
        if (!context_.using_keyswitching())
        {
            throw logic_error("keyswitching is not supported by the context");
        }

        // Don't validate all of kswitch_keys but just check the parms_id.
        if (kswitch_keys.parmsID() != context_.keyParmsID())
        {
            throw invalid_argument("parameter mismatch");
        }

        if (kswitch_keys_index >= kswitch_keys.data().size())
        {
            throw out_of_range("kswitch_keys_index");
        }
        if (scheme == SchemeType::bfv && encrypted.isNttForm())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (scheme == SchemeType::ckks && !encrypted.isNttForm())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (scheme == SchemeType::bgv && encrypted.isNttForm())
        {
            throw invalid_argument("BGV encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        size_t coeff_count = parms.polyModulusDegree();
        size_t decomp_modulus_size = parms.coeffModulus().size();
        auto &key_modulus = key_parms.coeffModulus();
        size_t key_modulus_size = key_modulus.size();
        size_t rns_modulus_size = decomp_modulus_size + 1;
        auto key_ntt_tables = key_context_data.smallNTTTables();
        auto modswitch_factors = key_context_data.rnsTool()->invqLastModq();

        // Size check
        if (!productFitsIn(coeff_count, mul_safe(rns_modulus_size, size_t(2))))
        {
            throw logic_error("invalid parameters");
        }

        // Prepare input
        auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
        size_t key_component_count = key_vector[0].data().size();

        // Check only the used component in KSwitchKeys.
        for (auto &each_key : key_vector)
        {
            if (!isMetadataValidFor(each_key, context_) || !isBufferValid(each_key))
            {
                throw invalid_argument("kswitch_keys is not valid for encryption parameters");
            }
        }

        // Create a copy of target_iter
        // SEAL_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);
        auto t_target = allocatePoly(coeff_count, decomp_modulus_size);
        setUint(target_iter.get(), decomp_modulus_size * coeff_count, t_target.get());

        // std::cout << "t_target: "; printArray(t_target);

        // In CKKS t_target is in NTT form; switch back to normal form
        if (scheme == SchemeType::ckks)
        {
            inverseNttNegacyclicHarvey(t_target.asPointer(), decomp_modulus_size, key_ntt_tables);
        }

        // Temporary result
        auto t_poly_prod = allocateZeroPolyArray(key_component_count, coeff_count, rns_modulus_size);

        for (size_t i = 0; i < rns_modulus_size; i++) {
            
            // std::cout << "i = " << i << std::endl;
            size_t key_index = (i == decomp_modulus_size ? key_modulus_size - 1 : i);

            // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
            size_t lazy_reduction_summand_bound = size_t(SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
            size_t lazy_reduction_counter = lazy_reduction_summand_bound;

            // Allocate memory for a lazy accumulator (128-bit coefficients)
            auto t_poly_lazy = allocateZeroPolyArray(key_component_count, coeff_count, 2);

            // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
            size_t poly_coeff_count = 2 * coeff_count;
            // PolyIter accumulator_iter(t_poly_lazy.get(), 2, coeff_count);

            // Multiply with keys and perform lazy reduction on product's coefficients
            for (size_t j = 0; j < decomp_modulus_size; j++) {
                auto t_ntt = allocateUint(coeff_count);
                // SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
                ConstHostPointer<uint64_t> t_operand;

                // RNS-NTT form exists in input
                if ((scheme == SchemeType::ckks) && (i == j))
                {
                    t_operand = target_iter + j * coeff_count;
                }
                // Perform RNS-NTT conversion
                else
                {
                    // No need to perform RNS conversion (modular reduction)
                    if (key_modulus[j] <= key_modulus[key_index])
                    {
                        // printf("branch a - ");
                        setUint(t_target.get() + j * coeff_count, coeff_count, t_ntt.get());
                    }
                    // Perform RNS conversion (modular reduction)
                    else
                    {
                        // printf("branch b - ");
                        moduloPolyCoeffs(t_target.get() + j * coeff_count, coeff_count, key_modulus[key_index], t_ntt.get());
                    }
                    // printArray(t_ntt.get(), coeff_count);
                    // NTT conversion lazy outputs in [0, 4q)
                    nttNegacyclicHarveyLazy(t_ntt.get(), key_ntt_tables[key_index]);
                    t_operand = t_ntt.get();
                }

                // std::cout << "  j = " << j << std::endl;
                // std::cout << "  t_operand: "; printArray(t_operand.get(), coeff_count);

                // Multiply with keys and modular accumulate products in a lazy fashion
                for (size_t k = 0; k < key_component_count; k++) {
                // SEAL_ITERATE(iter(key_vector[J].data(), accumulator_iter), key_component_count, [&](auto K) {
                    HostPointer<uint64_t> accumulator = t_poly_lazy + k * poly_coeff_count;
                    if (!lazy_reduction_counter)
                    {
                        for (size_t l = 0; l < coeff_count; l++) {
                        // SEAL_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            uint64_t qword[2]{ 0, 0 };
                            multiplyUint64(t_operand[l], key_vector[j].data().data(k)[key_index * coeff_count + l], qword);

                            // Accumulate product of t_operand and t_key_acc to t_poly_lazy and reduce
                            auto accumulator_l = accumulator.get() + 2 * l;
                            addUint128(qword, accumulator_l, qword);
                            accumulator_l[0] = barrettReduce128(qword, key_modulus[key_index]);
                            accumulator_l[1] = 0;
                        }
                    }
                    else
                    {
                        for (size_t l = 0; l < coeff_count; l++) {
                        // Same as above but no reduction
                        // SEAL_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            uint64_t qword[2]{ 0, 0 };
                            multiplyUint64(t_operand[l], key_vector[j].data().data(k)[key_index * coeff_count + l], qword);
                            auto accumulator_l = accumulator.get() + 2 * l;
                            addUint128(qword, accumulator_l, qword);
                            accumulator_l[0] = qword[0];
                            accumulator_l[1] = qword[1];
                        }
                    }
                }

                if (!--lazy_reduction_counter)
                {
                    lazy_reduction_counter = lazy_reduction_summand_bound;
                }
            }

            // std::cout << "  t_poly_lazy: ";
            // printArray(t_poly_lazy);

            // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
            auto t_poly_prod_iter = t_poly_prod.get() + i * coeff_count;
            // PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count, rns_modulus_size);

            // Final modular reduction
            for (size_t k = 0; k < key_component_count; k++) {
            // SEAL_ITERATE(iter(accumulator_iter, t_poly_prod_iter), key_component_count, [&](auto K) {
                HostPointer<uint64_t> accumulator = t_poly_lazy + k * poly_coeff_count;
                if (lazy_reduction_counter == lazy_reduction_summand_bound)
                {
                    for (size_t l = 0; l < coeff_count; l++) {
                        // std::cout << "*get<0>(L): " << accumulator[l * 2] << std::endl;
                        t_poly_prod_iter[k * coeff_count * rns_modulus_size + l] = static_cast<uint64_t>(accumulator[l * 2]);
                    }
                }
                else
                {
                    // Same as above except need to still do reduction
                    for (size_t l = 0; l < coeff_count; l++) {
                        // std::cout << "*get<0>(L): " << accumulator[l * 2] << std::endl;
                        t_poly_prod_iter[k * coeff_count * rns_modulus_size + l] = barrettReduce128(accumulator.get() + l * 2, key_modulus[key_index]);
                    }
                }
            }
        }
        // Accumulated products are now stored in t_poly_prod

        // std::cout << "t_poly_prod: ";
        // printArray(t_poly_prod, true);

        // Perform modulus switching with scaling
        // PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, rns_modulus_size);
        for (size_t i = 0; i < key_component_count; i++) {
        // SEAL_ITERATE(iter(encrypted, t_poly_prod_iter), key_component_count, [&](auto I) {
            if (scheme == SchemeType::bgv)
            {
                const Modulus &plain_modulus = parms.plainModulus();
                // qk is the special prime
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_inv_qp = context_.keyContextData()->rnsTool()->invqLastModt();

                // Lazy reduction; this needs to be then reduced mod qi
                auto t_last = t_poly_prod + coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count;
                // CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                inverseNttNegacyclicHarvey(t_last, key_ntt_tables[key_modulus_size - 1]);

                // SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(k, coeff_count, pool);
                auto k = allocateZeroUint(coeff_count);
                moduloPolyCoeffs(t_last.get(), coeff_count, plain_modulus, k.get());
                negatePolyCoeffmod(k.get(), coeff_count, plain_modulus, k.get());
                if (qk_inv_qp != 1)
                {
                    multiplyPolyScalarCoeffmod(k.get(), coeff_count, qk_inv_qp, plain_modulus, k.get());
                }

                auto delta = allocateZeroUint(coeff_count);
                auto c_mod_qi = allocateZeroUint(coeff_count);
                for (size_t j = 0; j < decomp_modulus_size; j++) {
                // SEAL_ITERATE(iter(I, key_modulus, modswitch_factors, key_ntt_tables), decomp_modulus_size, [&](auto J) {
                    size_t t_poly_prod_index = i * coeff_count * rns_modulus_size + j * coeff_count;
                    inverseNttNegacyclicHarvey(t_poly_prod + t_poly_prod_index, key_ntt_tables[j]);
                    // delta = k mod q_i
                    moduloPolyCoeffs(k.get(), coeff_count, key_modulus[j], delta.get());
                    // delta = k * q_k mod q_i
                    multiplyPolyScalarCoeffmod(delta.get(), coeff_count, qk, key_modulus[j], delta.get());

                    // c mod q_i
                    moduloPolyCoeffs(t_last.get(), coeff_count, key_modulus[j], c_mod_qi.get());
                    // delta = c + k * q_k mod q_i
                    // c_{i} = c_{i} - delta mod q_i
                    const uint64_t Lqi = key_modulus[j].value() * 2;
                    for (size_t k = 0; k < coeff_count; k++) {
                        t_poly_prod[t_poly_prod_index + k] = t_poly_prod[t_poly_prod_index + k] + Lqi - (delta[k] + c_mod_qi[k]);
                    }
                    // SEAL_ITERATE(iter(delta, c_mod_qi, get<0, 1>(J)), coeff_count, [Lqi](auto K) {
                    //     get<2>(K) = get<2>(K) + Lqi - (get<0>(K) + get<1>(K));
                    // });

                    multiplyPolyScalarCoeffmod(t_poly_prod + t_poly_prod_index, coeff_count, 
                        modswitch_factors[j], key_modulus[j], t_poly_prod + t_poly_prod_index);

                    addPolyCoeffmod(t_poly_prod + t_poly_prod_index, encrypted.data(i) + j * coeff_count, 
                        coeff_count, key_modulus[j], encrypted.data(i) + j * coeff_count);
                }
            }
            else
            {
                // Lazy reduction; this needs to be then reduced mod qi
                auto t_last = t_poly_prod + coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count;
                // std::cout << "t_last diff: " << coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count << std::endl;
                
                // std::cout << "t_last: "; printArray(t_last.get(), coeff_count);
                inverseNttNegacyclicHarveyLazy(t_last, key_ntt_tables[key_modulus_size - 1]);

                // Add (p-1)/2 to change from flooring to rounding.
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_half = qk >> 1;
                for (size_t j = 0; j < coeff_count; j++) {
                // SEAL_ITERATE(t_last, coeff_count, [&](auto &J) {
                    t_last[j] = barrettReduce64(t_last[j] + qk_half, key_modulus[key_modulus_size - 1]);
                }

                // std::cout << "t_last: "; printArray(t_last.get(), coeff_count);

                for (size_t j = 0; j < decomp_modulus_size; j++) {
                // SEAL_ITERATE(iter(I, key_modulus, key_ntt_tables, modswitch_factors), decomp_modulus_size, [&](auto J) {
                    // std::cout << "  ski j = " << j << std::endl;
                    size_t t_poly_prod_index = i * coeff_count * rns_modulus_size + j * coeff_count;
                    auto t_poly_prod_ptr = t_poly_prod + t_poly_prod_index;

                    auto t_ntt = allocateUint(coeff_count);
                    // SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);

                    // (ct mod 4qk) mod qi
                    uint64_t qi = key_modulus[j].value();
                    if (qk > qi)
                    {
                        // This cannot be spared. NTT only tolerates input that is less than 4*modulus (i.e. qk <=4*qi).
                        moduloPolyCoeffs(t_last.get(), coeff_count, key_modulus[j], t_ntt.get());
                    }
                    else
                    {
                        setUint(t_last.get(), coeff_count, t_ntt.get());
                    }

                    // Lazy substraction, results in [0, 2*qi), since fix is in [0, qi].
                    uint64_t fix = qi - barrettReduce64(qk_half, key_modulus[j]);
                    for (size_t k = 0; k < coeff_count; k++) t_ntt[k] += fix;
                    // SEAL_ITERATE(t_ntt, coeff_count, [fix](auto &K) { K += fix; });

                    uint64_t qi_lazy = qi << 1; // some multiples of qi
                    if (scheme == SchemeType::ckks)
                    {
                        // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                        nttNegacyclicHarveyLazy(t_ntt.asPointer(), key_ntt_tables[j]);
                        // Since SEAL uses at most 60bit moduli, 8*qi < 2^63.
                        qi_lazy = qi << 2;
                    }
                    else if (scheme == SchemeType::bfv)
                    {
                        inverseNttNegacyclicHarveyLazy(t_poly_prod_ptr, key_ntt_tables[j]);
                    }
                    
                    // std::cout << "  t_ntt: " << j << " - "; printArray(t_ntt);
                    // std::cout << "  t_ptr: " << j << " - "; printArray(t_poly_prod_ptr.get(), coeff_count);

                    // ((ct mod qi) - (ct mod qk)) mod qi with output in [0, 2 * qi_lazy)
                    for (size_t k = 0; k < coeff_count; k++) t_poly_prod_ptr[k] += qi_lazy - t_ntt[k];
                    // SEAL_ITERATE(
                    //     iter(get<0, 1>(J), t_ntt), coeff_count, [&](auto K) { get<0>(K) += qi_lazy - get<1>(K); });

                    // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                    multiplyPolyScalarCoeffmod(t_poly_prod_ptr, coeff_count, modswitch_factors[j], key_modulus[j], t_poly_prod_ptr);
                    addPolyCoeffmod(t_poly_prod_ptr, encrypted.data(i) + j * coeff_count, coeff_count, key_modulus[j], encrypted.data(i) + j * coeff_count);
                }
            }
            
            // printf("enc %ld: ", i); printArray(encrypted.data(i), key_component_count * coeff_count);
        }
    }
} // namespace seal
