// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "ckks.h"
#include <random>
#include <stdexcept>

using namespace std;
using namespace troy::util;

namespace troy
{


    namespace {
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

    }

    CKKSEncoder::CKKSEncoder(const SEALContext &context) : context_(context)
    {
        // Verify parameters
        if (!context_.parametersSet())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto &context_data = *context_.firstContextData();
        if (context_data.parms().scheme() != SchemeType::ckks)
        {
            throw invalid_argument("unsupported scheme");
        }

        size_t coeff_count = context_data.parms().polyModulusDegree();
        slots_ = coeff_count >> 1;
        int logn = getPowerOfTwo(coeff_count);

        matrix_reps_index_map_ = HostArray<size_t>(coeff_count);

        // Copy from the matrix to the value vectors
        uint64_t gen = 3;
        uint64_t pos = 1;
        uint64_t m = static_cast<uint64_t>(coeff_count) << 1;
        for (size_t i = 0; i < slots_; i++)
        {
            // Position in normal bit order
            uint64_t index1 = (pos - 1) >> 1;
            uint64_t index2 = (m - pos - 1) >> 1;

            // Set the bit-reversed locations
            matrix_reps_index_map_[i] = safe_cast<size_t>(reverseBits(index1, logn));
            matrix_reps_index_map_[slots_ | i] = safe_cast<size_t>(reverseBits(index2, logn));

            // Next primitive root
            pos *= gen;
            pos &= (m - 1);
        }

        // We need 1~(n-1)-th powers of the primitive 2n-th root, m = 2n
        root_powers_ = HostArray<complex<double>>(coeff_count);
        inv_root_powers_ = HostArray<complex<double>>(coeff_count);
        // Powers of the primitive 2n-th root have 4-fold symmetry
        if (m >= 8)
        {
            complex_roots_ = make_shared<util::ComplexRoots>(util::ComplexRoots(static_cast<size_t>(m)));
            for (size_t i = 1; i < coeff_count; i++)
            {
                root_powers_[i] = complex_roots_->getRoot(reverseBits(i, logn));
                inv_root_powers_[i] = conj(complex_roots_->getRoot(reverseBits(i - 1, logn) + 1));
            }
        }
        else if (m == 4)
        {
            root_powers_[1] = { 0, 1 };
            inv_root_powers_[1] = { 0, -1 };
        }

        complex_arith_ = ComplexArith();
        fft_handler_ = FFTHandler(complex_arith_);
    }





    void CKKSEncoder::encodeInternal(
        const std::complex<double> *values, std::size_t values_size, ParmsID parms_id, double scale, Plaintext &destination)
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw std::invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!values && values_size > 0)
        {
            throw std::invalid_argument("values cannot be null");
        }
        if (values_size > slots_)
        {
            throw std::invalid_argument("values_size is too large");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        std::size_t coeff_count = parms.polyModulusDegree();

        // Quick sanity check
        if (!util::productFitsIn(coeff_modulus_size, coeff_count))
        {
            throw std::logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) + 1 >= context_data.totalCoeffModulusBitCount()))
        {
            throw std::invalid_argument("scale out of bounds");
        }

        auto ntt_tables = context_data.smallNTTTables();

        // values_size is guaranteed to be no bigger than slots_
        std::size_t n = util::mul_safe(slots_, std::size_t(2));

        auto conj_values = util::HostArray<std::complex<double>>(n);
        for (std::size_t i = 0; i < values_size; i++)
        {
            conj_values[matrix_reps_index_map_[i]] = values[i];
            // TODO: if values are real, the following values should be set to zero, and multiply results by 2.
            conj_values[matrix_reps_index_map_[i + slots_]] = std::conj(values[i]);
        }
        double fix = scale / static_cast<double>(n);
        fft_handler_.transformFromRev(conj_values.get(), util::getPowerOfTwo(n), inv_root_powers_.get(), &fix);

        double max_coeff = 0;
        for (std::size_t i = 0; i < n; i++)
        {
            max_coeff = std::max<>(max_coeff, std::fabs(conj_values[i].real()));
        }
        // Verify that the values are not too large to fit in coeff_modulus
        // Note that we have an extra + 1 for the sign bit
        // Don't compute logarithmis of numbers less than 1
        int max_coeff_bit_count = static_cast<int>(std::ceil(std::log2(std::max<>(max_coeff, 1.0)))) + 1;
        if (max_coeff_bit_count >= context_data.totalCoeffModulusBitCount())
        {
            throw std::invalid_argument("encoded values are too large");
        }

        double two_pow_64 = std::pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parmsID() = parmsIDZero;
        destination.resize(util::mul_safe(coeff_count, coeff_modulus_size));

        // Use faster decomposition methods when possible
        if (max_coeff_bit_count <= 64)
        {
            for (std::size_t i = 0; i < n; i++)
            {
                double coeffd = std::round(conj_values[i].real());
                bool is_negative = std::signbit(coeffd);

                std::uint64_t coeffu = static_cast<std::uint64_t>(std::fabs(coeffd));

                if (is_negative)
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = util::negateUintMod(
                            util::barrettReduce64(coeffu, coeff_modulus[j]), coeff_modulus[j]);
                    }
                }
                else
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = util::barrettReduce64(coeffu, coeff_modulus[j]);
                    }
                }
            }
        }
        else if (max_coeff_bit_count <= 128)
        {
            for (std::size_t i = 0; i < n; i++)
            {
                double coeffd = std::round(conj_values[i].real());
                bool is_negative = std::signbit(coeffd);
                coeffd = std::fabs(coeffd);

                std::uint64_t coeffu[2]{ static_cast<std::uint64_t>(std::fmod(coeffd, two_pow_64)),
                                            static_cast<std::uint64_t>(coeffd / two_pow_64) };

                if (is_negative)
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = util::negateUintMod(
                            util::barrettReduce128(coeffu, coeff_modulus[j]), coeff_modulus[j]);
                    }
                }
                else
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = util::barrettReduce128(coeffu, coeff_modulus[j]);
                    }
                }
            }
        }
        else
        {
            // Slow case
            auto coeffu = util::HostArray<uint64_t>(coeff_modulus_size);
            for (std::size_t i = 0; i < n; i++)
            {
                double coeffd = std::round(conj_values[i].real());
                bool is_negative = std::signbit(coeffd);
                coeffd = std::fabs(coeffd);

                // We are at this point guaranteed to fit in the allocated space
                util::setZeroUint(coeff_modulus_size, coeffu.get());
                auto coeffu_ptr = coeffu.get();
                while (coeffd >= 1)
                {
                    *coeffu_ptr++ = static_cast<std::uint64_t>(std::fmod(coeffd, two_pow_64));
                    coeffd /= two_pow_64;
                }

                // Next decompose this coefficient
                context_data.rnsTool()->baseq()->decompose(coeffu.get());
                // Finally replace the sign if necessary
                if (is_negative)
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = util::negateUintMod(coeffu[j], coeff_modulus[j]);
                    }
                }
                else
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = coeffu[j];
                    }
                }
            }
        }

        // Transform to NTT domain
        for (std::size_t i = 0; i < coeff_modulus_size; i++)
        {
            util::nttNegacyclicHarvey(destination.data(i * coeff_count), ntt_tables[i]);
        }

        destination.parmsID() = parms_id;
        destination.scale() = scale;
    }





    void CKKSEncoder::encodeInternal(
        double value, ParmsID parms_id, double scale, Plaintext &destination)
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.polyModulusDegree();

        // Quick sanity check
        if (!productFitsIn(coeff_modulus_size, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) >= context_data.totalCoeffModulusBitCount()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // Compute the scaled value
        value *= scale;

        int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
        if (coeff_bit_count >= context_data.totalCoeffModulusBitCount())
        {
            throw invalid_argument("encoded value is too large");
        }

        double two_pow_64 = pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parmsID() = parmsIDZero;
        destination.resize(coeff_count * coeff_modulus_size);

        double coeffd = round(value);
        bool is_negative = signbit(coeffd);
        coeffd = fabs(coeffd);

        // Use faster decomposition methods when possible
        if (coeff_bit_count <= 64)
        {
            uint64_t coeffu = static_cast<uint64_t>(fabs(coeffd));

            if (is_negative)
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        negateUintMod(barrettReduce64(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        barrettReduce64(coeffu, coeff_modulus[j]));
                }
            }
        }
        else if (coeff_bit_count <= 128)
        {
            uint64_t coeffu[2]{ static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
                                static_cast<uint64_t>(coeffd / two_pow_64) };

            if (is_negative)
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        negateUintMod(barrettReduce128(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        barrettReduce128(coeffu, coeff_modulus[j]));
                }
            }
        }
        else
        {
            // Slow case
            auto coeffu = allocateUint(coeff_modulus_size);

            // We are at this point guaranteed to fit in the allocated space
            setZeroUint(coeff_modulus_size, coeffu.get());
            auto coeffu_ptr = coeffu.get();
            while (coeffd >= 1)
            {
                *coeffu_ptr++ = static_cast<uint64_t>(fmod(coeffd, two_pow_64));
                coeffd /= two_pow_64;
            }

            // Next decompose this coefficient
            context_data.rnsTool()->baseq()->decompose(coeffu.get());

            // Finally replace the sign if necessary
            if (is_negative)
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        negateUintMod(coeffu[j], coeff_modulus[j]));
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(destination.data() + (j * coeff_count), coeff_count, coeffu[j]);
                }
            }
        }

        destination.parmsID() = parms_id;
        destination.scale() = scale;
    }

    void CKKSEncoder::encodeInternal(int64_t value, ParmsID parms_id, Plaintext &destination)
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.polyModulusDegree();

        // Quick sanity check
        if (!productFitsIn(coeff_modulus_size, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        int coeff_bit_count = getSignificantBitCount(static_cast<uint64_t>(llabs(value))) + 2;
        if (coeff_bit_count >= context_data.totalCoeffModulusBitCount())
        {
            throw invalid_argument("encoded value is too large");
        }

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parmsID() = parmsIDZero;
        destination.resize(coeff_count * coeff_modulus_size);

        if (value < 0)
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                uint64_t tmp = static_cast<uint64_t>(value);
                tmp += coeff_modulus[j].value();
                tmp = barrettReduce64(tmp, coeff_modulus[j]);
                fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
            }
        }
        else
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                uint64_t tmp = static_cast<uint64_t>(value);
                tmp = barrettReduce64(tmp, coeff_modulus[j]);
                fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
            }
        }

        destination.parmsID() = parms_id;
        destination.scale() = 1.0;
    }


    void CKKSEncoder::decodeInternal(const Plaintext &plain, std::complex<double> *destination)
    {
        // Verify parameters.
        if (!isValidFor(plain, context_))
        {
            throw std::invalid_argument("plain is not valid for encryption parameters");
        }
        if (!plain.isNttForm())
        {
            throw std::invalid_argument("plain is not in NTT form");
        }
        if (!destination)
        {
            throw std::invalid_argument("destination cannot be null");
        }

        auto &context_data = *context_.getContextData(plain.parmsID());
        auto &parms = context_data.parms();
        std::size_t coeff_modulus_size = parms.coeffModulus().size();
        std::size_t coeff_count = parms.polyModulusDegree();
        std::size_t rns_poly_uint64_count = util::mul_safe(coeff_count, coeff_modulus_size);

        auto ntt_tables = context_data.smallNTTTables();

        // Check that scale is positive and not too large
        if (plain.scale() <= 0 ||
            (static_cast<int>(log2(plain.scale())) >= context_data.totalCoeffModulusBitCount()))
        {
            throw std::invalid_argument("scale out of bounds");
        }

        auto decryption_modulus = context_data.totalCoeffModulus();
        auto upper_half_threshold = context_data.upperHalfThreshold();
        int logn = util::getPowerOfTwo(coeff_count);

        // Quick sanity check
        if ((logn < 0) || (coeff_count < SEAL_POLY_MOD_DEGREE_MIN) || (coeff_count > SEAL_POLY_MOD_DEGREE_MAX))
        {
            throw std::logic_error("invalid parameters");
        }

        double inv_scale = double(1.0) / plain.scale();

        // Create mutable copy of input
        auto plain_copy = util::allocateUint(rns_poly_uint64_count);
        util::setUint(plain.data(), rns_poly_uint64_count, plain_copy.get());

        // Transform each polynomial from NTT domain
        for (std::size_t i = 0; i < coeff_modulus_size; i++)
        {
            util::inverseNttNegacyclicHarvey(plain_copy.get() + (i * coeff_count), ntt_tables[i]);
        }

        // printArray(plain_copy);

        // CRT-compose the polynomial
        context_data.rnsTool()->baseq()->composeArray(plain_copy.get(), coeff_count);

        // Create floating-point representations of the multi-precision integer coefficients
        double two_pow_64 = std::pow(2.0, 64);
        auto res = util::HostArray<std::complex<double>>(coeff_count);
        for (std::size_t i = 0; i < coeff_count; i++)
        {
            res[i] = 0.0;
            if (util::isGreaterThanOrEqualUint(
                    plain_copy.get() + (i * coeff_modulus_size), upper_half_threshold, coeff_modulus_size))
            {
                double scaled_two_pow_64 = inv_scale;
                for (std::size_t j = 0; j < coeff_modulus_size; j++, scaled_two_pow_64 *= two_pow_64)
                {
                    if (plain_copy[i * coeff_modulus_size + j] > decryption_modulus[j])
                    {
                        auto diff = plain_copy[i * coeff_modulus_size + j] - decryption_modulus[j];
                        res[i] += diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                    }
                    else
                    {
                        auto diff = decryption_modulus[j] - plain_copy[i * coeff_modulus_size + j];
                        res[i] -= diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                    }
                }
            }
            else
            {
                double scaled_two_pow_64 = inv_scale;
                for (std::size_t j = 0; j < coeff_modulus_size; j++, scaled_two_pow_64 *= two_pow_64)
                {
                    auto curr_coeff = plain_copy[i * coeff_modulus_size + j];
                    res[i] += curr_coeff ? static_cast<double>(curr_coeff) * scaled_two_pow_64 : 0.0;
                }
            }

            // Scaling instead incorporated above; this can help in cases
            // where otherwise pow(two_pow_64, j) would overflow due to very
            // large coeff_modulus_size and very large scale
            // res[i] = res_accum * inv_scale;
        }

        fft_handler_.transformToRev(res.get(), logn, root_powers_.get());

        for (std::size_t i = 0; i < slots_; i++)
        {
            destination[i] = res[static_cast<std::size_t>(matrix_reps_index_map_[i])];
        }
    }
} // namespace seal
