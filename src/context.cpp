// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.


#include "context.h"
#include "utils/numth.h"
// #include "utils/pointer.h"
// #include "seal/util/polycore.h"
#include "utils/uintarith.h"
#include "utils/uintarithsmallmod.h"
#include <algorithm>
#include <stdexcept>
#include <utility>

// using namespace std;
using std::invalid_argument;
using std::make_shared;
using namespace troy::util;

using ErrorType = troy::EncryptionParameterQualifiers::ErrorType;

namespace troy
{
    const char *EncryptionParameterQualifiers::parameterErrorName() const noexcept
    {
        switch (parameter_error)
        {
        case ErrorType::none:
            return "none";

        case ErrorType::success:
            return "success";

        case ErrorType::invalid_scheme:
            return "invalid_scheme";

        case ErrorType::invalid_coeff_modulus_size:
            return "invalid_coeff_modulus_size";

        case ErrorType::invalid_coeff_modulus_bit_count:
            return "invalid_coeff_modulus_bit_count";

        case ErrorType::invalid_coeff_modulus_no_ntt:
            return "invalid_coeff_modulus_no_ntt";

        case ErrorType::invalid_poly_modulus_degree:
            return "invalid_poly_modulus_degree";

        case ErrorType::invalid_poly_modulus_degree_non_power_of_two:
            return "invalid_poly_modulus_degree_non_power_of_two";

        case ErrorType::invalid_parameters_too_large:
            return "invalid_parameters_too_large";

        case ErrorType::invalid_parameters_insecure:
            return "invalid_parameters_insecure";

        case ErrorType::failed_creating_rns_base:
            return "failed_creating_rns_base";

        case ErrorType::invalid_plain_modulus_bit_count:
            return "invalid_plain_modulus_bit_count";

        case ErrorType::invalid_plain_modulus_coprimality:
            return "invalid_plain_modulus_coprimality";

        case ErrorType::invalid_plain_modulus_too_large:
            return "invalid_plain_modulus_too_large";

        case ErrorType::invalid_plain_modulus_nonzero:
            return "invalid_plain_modulus_nonzero";

        case ErrorType::failed_creating_rns_tool:
            return "failed_creating_rns_tool";

        default:
            return "invalid parameter_error";
        }
    }

    const char *EncryptionParameterQualifiers::parameterErrorMessage() const noexcept
    {
        switch (parameter_error)
        {
        case ErrorType::none:
            return "constructed but not yet validated";

        case ErrorType::success:
            return "valid";

        case ErrorType::invalid_scheme:
            return "scheme must be BFV or CKKS or BGV";

        case ErrorType::invalid_coeff_modulus_size:
            return "coeff_modulus's primes' count is not bounded by SEAL_COEFF_MOD_COUNT_MIN(MAX)";

        case ErrorType::invalid_coeff_modulus_bit_count:
            return "coeff_modulus's primes' bit counts are not bounded by SEAL_USER_MOD_BIT_COUNT_MIN(MAX)";

        case ErrorType::invalid_coeff_modulus_no_ntt:
            return "coeff_modulus's primes are not congruent to 1 modulo (2 * poly_modulus_degree)";

        case ErrorType::invalid_poly_modulus_degree:
            return "poly_modulus_degree is not bounded by SEAL_POLY_MOD_DEGREE_MIN(MAX)";

        case ErrorType::invalid_poly_modulus_degree_non_power_of_two:
            return "poly_modulus_degree is not a power of two";

        case ErrorType::invalid_parameters_too_large:
            return "parameters are too large to fit in size_t type";

        case ErrorType::invalid_parameters_insecure:
            return "parameters are not compliant with HomomorphicEncryption.org security standard";

        case ErrorType::failed_creating_rns_base:
            return "RNSBase cannot be constructed";

        case ErrorType::invalid_plain_modulus_bit_count:
            return "plain_modulus's bit count is not bounded by SEAL_PLAIN_MOD_BIT_COUNT_MIN(MAX)";

        case ErrorType::invalid_plain_modulus_coprimality:
            return "plain_modulus is not coprime to coeff_modulus";

        case ErrorType::invalid_plain_modulus_too_large:
            return "plain_modulus is not smaller than coeff_modulus";

        case ErrorType::invalid_plain_modulus_nonzero:
            return "plain_modulus is not zero";

        case ErrorType::failed_creating_rns_tool:
            return "RNSTool cannot be constructed";

        default:
            return "invalid parameter_error";
        }
    }

    SEALContext::ContextData SEALContext::validate(EncryptionParameters parms)
    {
        ContextData context_data(parms);
        context_data.qualifiers_.parameter_error = ErrorType::success;

        // Is a scheme set?
        if (parms.scheme() == SchemeType::none)
        {
            context_data.qualifiers_.parameter_error = ErrorType::invalid_scheme;
            return context_data;
        }

        auto &coeff_modulus = parms.coeffModulus();
        auto &plain_modulus = parms.plainModulus();

        // The number of coeff moduli is restricted to 64 to prevent unexpected behaviors
        if (coeff_modulus.size() > SEAL_COEFF_MOD_COUNT_MAX || coeff_modulus.size() < SEAL_COEFF_MOD_COUNT_MIN)
        {
            context_data.qualifiers_.parameter_error = ErrorType::invalid_coeff_modulus_size;
            return context_data;
        }

        size_t coeff_modulus_size = coeff_modulus.size();
        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            // Check coefficient moduli bounds
            if (coeff_modulus[i].value() >> SEAL_USER_MOD_BIT_COUNT_MAX ||
                !(coeff_modulus[i].value() >> (SEAL_USER_MOD_BIT_COUNT_MIN - 1)))
            {
                context_data.qualifiers_.parameter_error = ErrorType::invalid_coeff_modulus_bit_count;
                return context_data;
            }
        }

        // Compute the product of all coeff moduli
        // FIXME: allocate related action
        context_data.total_coeff_modulus_ = util::HostArray<uint64_t>(coeff_modulus_size);
        auto coeff_modulus_values = util::HostArray<uint64_t>(coeff_modulus_size);
        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            coeff_modulus_values[i] = coeff_modulus[i].value();
        }
        multiplyManyUint64(
            coeff_modulus_values.get(), coeff_modulus_size, context_data.total_coeff_modulus_.get());
        context_data.total_coeff_modulus_bit_count_ =
            getSignificantBitCountUint(context_data.total_coeff_modulus_.get(), coeff_modulus_size);

        // Check polynomial modulus degree and create poly_modulus
        size_t poly_modulus_degree = parms.polyModulusDegree();
        if (poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN || poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX)
        {
            // Parameters are not valid
            context_data.qualifiers_.parameter_error = ErrorType::invalid_poly_modulus_degree;
            return context_data;
        }
        int coeff_count_power = getPowerOfTwo(poly_modulus_degree);
        if (coeff_count_power < 0)
        {
            // Parameters are not valid
            context_data.qualifiers_.parameter_error = ErrorType::invalid_poly_modulus_degree_non_power_of_two;
            return context_data;
        }

        // Quick sanity check
        if (!productFitsIn(coeff_modulus_size, poly_modulus_degree))
        {
            context_data.qualifiers_.parameter_error = ErrorType::invalid_parameters_too_large;
            return context_data;
        }

        // Polynomial modulus X^(2^k) + 1 is guaranteed at this point
        context_data.qualifiers_.using_fft = true;

        // Assume parameters satisfy desired security level
        context_data.qualifiers_.sec_level = sec_level_;

        // Check if the parameters are secure according to HomomorphicEncryption.org security standard
        if (context_data.total_coeff_modulus_bit_count_ > CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level_))
        {
            // Not secure according to HomomorphicEncryption.org security standard
            context_data.qualifiers_.sec_level = SecurityLevel::none;
            if (sec_level_ != SecurityLevel::none)
            {
                // Parameters are not valid
                context_data.qualifiers_.parameter_error = ErrorType::invalid_parameters_insecure;
                return context_data;
            }
        }

        // Set up RNSBase for coeff_modulus
        // RNSBase's constructor may fail due to:
        //   (1) coeff_mod not coprime
        //   (2) cannot find inverse of punctured products (because of (1))
        HostObject<RNSBase> coeff_modulus_base;
        try
        {
            coeff_modulus_base = HostObject(new RNSBase(coeff_modulus));
        }
        catch (const invalid_argument &)
        {
            // Parameters are not valid
            context_data.qualifiers_.parameter_error = ErrorType::failed_creating_rns_base;
            return context_data;
        }

        // Can we use NTT with coeff_modulus?
        context_data.qualifiers_.using_ntt = true;
        try
        {
            context_data.small_ntt_tables_ = CreateNTTTables(coeff_count_power, coeff_modulus);
        }
        catch (const invalid_argument &)
        {
            context_data.qualifiers_.using_ntt = false;
            // Parameters are not valid
            context_data.qualifiers_.parameter_error = ErrorType::invalid_coeff_modulus_no_ntt;
            return context_data;
        }

        if (parms.scheme() == SchemeType::bfv || parms.scheme() == SchemeType::bgv)
        {
            // Plain modulus must be at least 2 and at most 60 bits
            if (plain_modulus.value() >> SEAL_PLAIN_MOD_BIT_COUNT_MAX ||
                !(plain_modulus.value() >> (SEAL_PLAIN_MOD_BIT_COUNT_MIN - 1)))
            {
                context_data.qualifiers_.parameter_error = ErrorType::invalid_plain_modulus_bit_count;
                return context_data;
            }

            // Check that all coeff moduli are relatively prime to plain_modulus
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                if (!areCoprime(coeff_modulus[i].value(), plain_modulus.value()))
                {
                    context_data.qualifiers_.parameter_error = ErrorType::invalid_plain_modulus_coprimality;
                    return context_data;
                }
            }

            // Check that plain_modulus is smaller than total coeff modulus
            if (!isLessThanUint(
                    plain_modulus.data(), plain_modulus.uint64Count(), context_data.total_coeff_modulus_.get(),
                    coeff_modulus_size))
            {
                // Parameters are not valid
                context_data.qualifiers_.parameter_error = ErrorType::invalid_plain_modulus_too_large;
                return context_data;
            }

            // Can we use batching? (NTT with plain_modulus)
            context_data.qualifiers_.using_batching = true;
            try
            {
                context_data.plain_ntt_tables_ = CreateNTTTables(coeff_count_power, { plain_modulus });
            }
            catch (const invalid_argument &)
            {
                context_data.qualifiers_.using_batching = false;
            }

            // Check for plain_lift
            // If all the small coefficient moduli are larger than plain modulus, we can quickly
            // lift plain coefficients to RNS form
            context_data.qualifiers_.using_fast_plain_lift = true;
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                context_data.qualifiers_.using_fast_plain_lift &= (coeff_modulus[i].value() > plain_modulus.value());
            }

            // Calculate coeff_div_plain_modulus (BFV-"Delta") and the remainder upper_half_increment
            // FIXME: allocate related action
            auto temp_coeff_div_plain_modulus = HostArray<uint64_t>(coeff_modulus_size);
            context_data.coeff_div_plain_modulus_ = HostArray<MultiplyUIntModOperand>(coeff_modulus_size);
            context_data.upper_half_increment_ = HostArray<uint64_t>(coeff_modulus_size);
            auto wide_plain_modulus(duplicateUintIfNeeded(
                plain_modulus.data(), plain_modulus.uint64Count(), coeff_modulus_size, false));
            divideUint(
                context_data.total_coeff_modulus_.get(), wide_plain_modulus.get(), coeff_modulus_size,
                temp_coeff_div_plain_modulus.get(), context_data.upper_half_increment_.get());

            // Store the non-RNS form of upper_half_increment for BFV encryption
            context_data.coeff_modulus_mod_plain_modulus_ = context_data.upper_half_increment_[0];

            // Decompose coeff_div_plain_modulus into RNS factors
            coeff_modulus_base->decompose(temp_coeff_div_plain_modulus.get());

            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                context_data.coeff_div_plain_modulus_[i].set(
                    temp_coeff_div_plain_modulus[i], coeff_modulus_base->base()[i]);
            }

            // Decompose upper_half_increment into RNS factors
            coeff_modulus_base->decompose(context_data.upper_half_increment_.get());

            // Calculate (plain_modulus + 1) / 2.
            context_data.plain_upper_half_threshold_ = (plain_modulus.value() + 1) >> 1;

            // Calculate coeff_modulus - plain_modulus.
            context_data.plain_upper_half_increment_ = HostArray<uint64_t>(coeff_modulus_size);
            if (context_data.qualifiers_.using_fast_plain_lift)
            {
                // Calculate coeff_modulus[i] - plain_modulus if using_fast_plain_lift
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    context_data.plain_upper_half_increment_[i] = coeff_modulus[i].value() - plain_modulus.value();
                }
            }
            else
            {
                subUint(
                    context_data.totalCoeffModulus(), wide_plain_modulus.get(), coeff_modulus_size,
                    context_data.plain_upper_half_increment_.get());
            }
        }
        else if (parms.scheme() == SchemeType::ckks)
        {
            // Check that plain_modulus is set to zero
            if (!plain_modulus.isZero())
            {
                // Parameters are not valid
                context_data.qualifiers_.parameter_error = ErrorType::invalid_plain_modulus_nonzero;
                return context_data;
            }

            // When using CKKS batching (BatchEncoder) is always enabled
            context_data.qualifiers_.using_batching = true;

            // Cannot use fast_plain_lift for CKKS since the plaintext coefficients
            // can easily be larger than coefficient moduli
            context_data.qualifiers_.using_fast_plain_lift = false;

            // Calculate 2^64 / 2 (most negative plaintext coefficient value)
            context_data.plain_upper_half_threshold_ = uint64_t(1) << 63;

            // Calculate plain_upper_half_increment = 2^64 mod coeff_modulus for CKKS plaintexts
            context_data.plain_upper_half_increment_ = HostArray<uint64_t>(coeff_modulus_size);
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                uint64_t tmp = barrettReduce64(uint64_t(1) << 63, coeff_modulus[i]);
                context_data.plain_upper_half_increment_[i] =
                    multiplyUintMod(tmp, sub_safe(coeff_modulus[i].value(), uint64_t(2)), coeff_modulus[i]);
            }

            // Compute the upper_half_threshold for this modulus.
            context_data.upper_half_threshold_ = HostArray<uint64_t>(coeff_modulus_size);
            incrementUint(
                context_data.totalCoeffModulus(), coeff_modulus_size, context_data.upper_half_threshold_.get());
            rightShiftUint(
                context_data.upper_half_threshold_.get(), 1, coeff_modulus_size,
                context_data.upper_half_threshold_.get());
        }
        else
        {
            context_data.qualifiers_.parameter_error = ErrorType::invalid_scheme;
            return context_data;
        }

        // Create RNSTool
        // RNSTool's constructor may fail due to:
        //   (1) auxiliary base being too large
        //   (2) cannot find inverse of punctured products in auxiliary base
        try
        {
            context_data.rns_tool_ = HostObject(new RNSTool(poly_modulus_degree, *coeff_modulus_base, plain_modulus));
        }
        catch (const std::exception &)
        {
            // Parameters are not valid
            context_data.qualifiers_.parameter_error = ErrorType::failed_creating_rns_tool;
            return context_data;
        }

        // Check whether the coefficient modulus consists of a set of primes that are in decreasing order
        context_data.qualifiers_.using_descending_modulus_chain = true;
        for (size_t i = 0; i < coeff_modulus_size - 1; i++)
        {
            context_data.qualifiers_.using_descending_modulus_chain &=
                (coeff_modulus[i].value() > coeff_modulus[i + 1].value());
        }

        // Create GaloisTool
        context_data.galois_tool_ = HostObject(new GaloisTool(coeff_count_power));

        // Done with validation and pre-computations
        return context_data;
    }

    ParmsID SEALContext::createNextContextData(const ParmsID &prev_parms_id)
    {
        // Create the next set of parameters by removing last modulus
        auto next_parms = context_data_map_.at(prev_parms_id)->parms_;
        auto next_coeff_modulus = next_parms.coeffModulus();
        next_coeff_modulus.pop_back();
        next_parms.setCoeffModulus(next_coeff_modulus);
        auto next_parms_id = next_parms.parmsID();

        // Validate next parameters and create next context_data
        auto next_context_data = validate(next_parms);

        // If not valid then return zero parms_id
        if (!next_context_data.qualifiers_.parametersSet())
        {
            return parmsIDZero;
        }

        // Add them to the context_data_map_
        context_data_map_.emplace(make_pair(next_parms_id, make_shared<const ContextData>(std::move(next_context_data))));

        // Add pointer to next context_data to the previous one (linked list)
        // Add pointer to previous context_data to the next one (doubly linked list)
        // We need to remove constness first to modify this
        std::const_pointer_cast<ContextData>(context_data_map_.at(prev_parms_id))->next_context_data_ =
            context_data_map_.at(next_parms_id);
        std::const_pointer_cast<ContextData>(context_data_map_.at(next_parms_id))->prev_context_data_ =
            context_data_map_.at(prev_parms_id);

        return next_parms_id;
    }

    SEALContext::SEALContext(
        EncryptionParameters parms, bool expand_mod_chain, SecurityLevel sec_level)
        : sec_level_(sec_level)
    {

        // Set random generator
        if (!parms.randomGenerator())
        {
            parms.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());
        }

        // Validate parameters and add new ContextData to the map
        // Note that this happens even if parameters are not valid

        // First create key_parms_id_.
        context_data_map_.emplace(make_pair(parms.parmsID(), make_shared<const ContextData>(validate(parms))));
        key_parms_id_ = parms.parmsID();

        // Then create first_parms_id_ if the parameters are valid and there is
        // more than one modulus in coeff_modulus. This is equivalent to expanding
        // the chain by one step. Otherwise, we set first_parms_id_ to equal
        // key_parms_id_.
        if (!context_data_map_.at(key_parms_id_)->qualifiers_.parametersSet() || parms.coeffModulus().size() == 1)
        {
            first_parms_id_ = key_parms_id_;
        }
        else
        {
            auto next_parms_id = createNextContextData(key_parms_id_);
            first_parms_id_ = (next_parms_id == parmsIDZero) ? key_parms_id_ : next_parms_id;
        }

        // Set last_parms_id_ to point to first_parms_id_
        last_parms_id_ = first_parms_id_;

        // Check if keyswitching is available
        using_keyswitching_ = (first_parms_id_ != key_parms_id_);

        // If modulus switching chain is to be created, compute the remaining parameter sets as long as they are valid
        // to use (i.e., parameters_set() == true).
        if (expand_mod_chain && context_data_map_.at(first_parms_id_)->qualifiers_.parametersSet())
        {
            auto prev_parms_id = first_parms_id_;
            while (context_data_map_.at(prev_parms_id)->parms().coeffModulus().size() > 1)
            {
                auto next_parms_id = createNextContextData(prev_parms_id);
                if (next_parms_id == parmsIDZero)
                {
                    break;
                }
                prev_parms_id = next_parms_id;
                last_parms_id_ = next_parms_id;
            }
        }

        // Set the chain_index for each context_data
        size_t parms_count = context_data_map_.size();
        auto context_data_ptr = context_data_map_.at(key_parms_id_);
        while (context_data_ptr)
        {
            // We need to remove constness first to modify this
            std::const_pointer_cast<ContextData>(context_data_ptr)->chain_index_ = --parms_count;
            context_data_ptr = context_data_ptr->next_context_data_;
        }
    }
} // namespace seal
