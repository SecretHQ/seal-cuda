// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "common.h"
#include "uintcore.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace troy
{
    namespace util
    {
        inline std::string polyToHexString(
            const std::uint64_t *value, std::size_t coeff_count, std::size_t coeff_uint64_count)
        {
            // First check if there is anything to print
            if (!coeff_count || !coeff_uint64_count)
            {
                return "0";
            }

            std::ostringstream result;
            bool empty = true;
            value += util::mul_safe(coeff_count - 1, coeff_uint64_count);
            while (coeff_count--)
            {
                if (isZeroUint(value, coeff_uint64_count))
                {
                    value -= coeff_uint64_count;
                    continue;
                }
                if (!empty)
                {
                    result << " + ";
                }
                result << uintToHexString(value, coeff_uint64_count);
                if (coeff_count)
                {
                    result << "x^" << coeff_count;
                }
                empty = false;
                value -= coeff_uint64_count;
            }
            if (empty)
            {
                result << "0";
            }
            return result.str();
        }

        inline std::string polyToDecString(
            const std::uint64_t *value, std::size_t coeff_count, std::size_t coeff_uint64_count)
        {
            // First check if there is anything to print
            if (!coeff_count || !coeff_uint64_count)
            {
                return "0";
            }

            std::ostringstream result;
            bool empty = true;
            value += coeff_count - 1;
            while (coeff_count--)
            {
                if (isZeroUint(value, coeff_uint64_count))
                {
                    value -= coeff_uint64_count;
                    continue;
                }
                if (!empty)
                {
                    result << " + ";
                }
                result << uintToDecString(value, coeff_uint64_count);
                if (coeff_count)
                {
                    result << "x^" << coeff_count;
                }
                empty = false;
                value -= coeff_uint64_count;
            }
            if (empty)
            {
                result << "0";
            }
            return result.str();
        }

        inline auto allocatePoly(
            std::size_t coeff_count, std::size_t coeff_uint64_count)
        {
            return allocateUint(util::mul_safe(coeff_count, coeff_uint64_count));
        }

        inline void setZeroPoly(std::size_t coeff_count, std::size_t coeff_uint64_count, std::uint64_t *result)
        {
            setZeroUint(util::mul_safe(coeff_count, coeff_uint64_count), result);
        }

        inline auto allocateZeroPoly(
            std::size_t coeff_count, std::size_t coeff_uint64_count)
        {
            return allocateZeroUint(util::mul_safe(coeff_count, coeff_uint64_count));
        }

        inline auto allocatePolyArray(
            std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count)
        {
            return allocateUint(util::mul_safe(poly_count, util::mul_safe(coeff_count, coeff_uint64_count)));
        }

        inline void setZeroPolyArray(
            std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count, std::uint64_t *result)
        {
            setZeroUint(util::mul_safe(poly_count, util::mul_safe(coeff_count, coeff_uint64_count)), result);
        }

        inline auto allocateZeroPolyArray(
            std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count)
        {
            return allocateZeroUint(util::mul_safe(poly_count, util::mul_safe(coeff_count, coeff_uint64_count)));
        }

        inline void setPoly(
            const std::uint64_t *poly, std::size_t coeff_count, std::size_t coeff_uint64_count, std::uint64_t *result)
        {
            setUint(poly, util::mul_safe(coeff_count, coeff_uint64_count), result);
        }

        inline void setPolyArray(
            const std::uint64_t *poly, std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count,
            std::uint64_t *result)
        {
            setUint(poly, util::mul_safe(poly_count, util::mul_safe(coeff_count, coeff_uint64_count)), result);
        }
    } // namespace util
} // namespace seal
