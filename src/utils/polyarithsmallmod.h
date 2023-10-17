// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "../modulus.h"
#include "common.h"
#include "defines.h"
// #include "polycore.h"
#include "uintarithsmallmod.h"
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <iomanip>

namespace troy
{
    namespace util
    {
        void moduloPolyCoeffs(ConstHostPointer<uint64_t> poly, std::size_t coeff_count, const Modulus &modulus, HostPointer<uint64_t> result);

        inline void moduloPolyCoeffs(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                moduloPolyCoeffs(poly + i * poly_modulus_degree, poly_modulus_degree, modulus[i], result + i * poly_modulus_degree);
            }
        }

        inline void moduloPolyCoeffs(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                moduloPolyCoeffs(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, modulus, result + i * d);
            }
        }

        inline void negatePolyCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_count, const Modulus &modulus, HostPointer<uint64_t> result)
        {
            const uint64_t modulus_value = modulus.value();
            for (std::size_t i = 0; i < coeff_count; i++) {
                auto coeff = poly[i];
                std::int64_t non_zero = (coeff != 0);
                result[i] = (modulus_value - coeff) & static_cast<std::uint64_t>(-non_zero);
            }
        }

        inline void negatePolyCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                negatePolyCoeffmod(poly + i * poly_modulus_degree, poly_modulus_degree, modulus[i], result + i * poly_modulus_degree);
            }
        }

        inline void negatePolyCoeffmod(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                negatePolyCoeffmod(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, modulus, result + i * d);
            }
        }

        void addPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_count, const Modulus &modulus,
            HostPointer<uint64_t> result);

        inline void addPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus,
            HostPointer<uint64_t> result)
        {
            
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                addPolyCoeffmod(
                    operand1 + i * poly_modulus_degree, 
                    operand2 + i * poly_modulus_degree,
                    poly_modulus_degree,
                    modulus[i], 
                    result + i * poly_modulus_degree
                );
            }
        }

        inline void addPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                addPolyCoeffmod(operand1 + i * d, operand2 + i * d, coeff_modulus_size, poly_modulus_degree, modulus, result + i * d);
            }
        }

        void subPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_count, const Modulus &modulus,
            HostPointer<uint64_t> result);

        inline void subPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus,
            HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                subPolyCoeffmod(
                    operand1 + i * poly_modulus_degree, 
                    operand2 + i * poly_modulus_degree,
                    poly_modulus_degree,
                    modulus[i], 
                    result + i * poly_modulus_degree
                );
            }
        }

        inline void subPolyCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                subPolyCoeffmod(operand1 + i * d, operand2 + i * d, coeff_modulus_size, poly_modulus_degree, modulus, result + i * d);
            }
        }

        /**
        @param[in] scalar Must be less than modulus.value().
        */
        void addPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_count, std::uint64_t scalar, const Modulus &modulus,
            HostPointer<uint64_t> result);

        /**
        @param[in] scalar Must be less than modulus.value().
        */
        inline void addPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t scalar, const Modulus* modulus,
            HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                addPolyScalarCoeffmod(poly + i * poly_modulus_degree, poly_modulus_degree, scalar, modulus[i], result + i * poly_modulus_degree);
            }
        }

        /**
        @param[in] scalar Must be less than modulus.value().
        */
        inline void addPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t scalar, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                addPolyScalarCoeffmod(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, scalar, modulus, result + i * d);
            }
        }

        /**
        @param[in] scalar Must be less than modulus.value().
        */
        void subPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_count, std::uint64_t scalar, const Modulus &modulus,
            HostPointer<uint64_t> result);

        /**
        @param[in] scalar Must be less than modulus.value().
        */
        inline void subPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t scalar, const Modulus* modulus,
            HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                subPolyScalarCoeffmod(poly + i * poly_modulus_degree, poly_modulus_degree, scalar, modulus[i], result + i * poly_modulus_degree);
            }
        }

        /**
        @param[in] scalar Must be less than modulus.value().
        */
        inline void subPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t scalar, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                subPolyScalarCoeffmod(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, scalar, modulus, result + i * d);
            }
        }

        void multiplyPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_count, MultiplyUIntModOperand scalar, const Modulus &modulus,
            HostPointer<uint64_t> result);

        inline void multiplyPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_count, std::uint64_t scalar, const Modulus &modulus,
            HostPointer<uint64_t> result)
        {
            // Scalar must be first reduced modulo modulus
            MultiplyUIntModOperand temp_scalar;
            temp_scalar.set(barrettReduce64(scalar, modulus), modulus);
            multiplyPolyScalarCoeffmod(poly, coeff_count, temp_scalar, modulus, result);
        }

        inline void multiplyPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t scalar, const Modulus* modulus,
            HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                multiplyPolyScalarCoeffmod(poly + i * poly_modulus_degree, poly_modulus_degree, scalar, modulus[i], result + i * poly_modulus_degree);
            }
        }

        inline void multiplyPolyScalarCoeffmod(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t scalar, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                multiplyPolyScalarCoeffmod(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, scalar, modulus, result + i * d);
            }
        }

        void dyadicProductCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_count, const Modulus &modulus,
            HostPointer<uint64_t> result);

        inline void dyadicProductCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus,
            HostPointer<uint64_t> result)
        {
            
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                // std::cout << " xpoly oper2 i = " << i << ": "; 
                // for (size_t j=0; j<poly_modulus_degree; j++) {
                //     std::cout << std::hex << operand2[j] << ", ";
                // } std::cout << std::endl;
                dyadicProductCoeffmod(
                    operand1 + i * poly_modulus_degree, operand2 + i * poly_modulus_degree,
                    poly_modulus_degree, modulus[i], result + i * poly_modulus_degree);
            }
        }

        inline void dyadicProductCoeffmod(
            ConstHostPointer<uint64_t> operand1, ConstHostPointer<uint64_t> operand2, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                dyadicProductCoeffmod(operand1 + i * d, operand2 + i * d, coeff_modulus_size, poly_modulus_degree, modulus, result + i * d);
            }
        }

        std::uint64_t polyInftyNormCoeffmod(HostPointer<uint64_t> operand, std::size_t coeff_count, const Modulus &modulus);

        void negacyclicShiftPolyCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_count, std::size_t shift, const Modulus &modulus, HostPointer<uint64_t> result);

        inline void negacyclicShiftPolyCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::size_t shift, const Modulus* modulus,
            HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                negacyclicShiftPolyCoeffmod(poly + i * poly_modulus_degree, poly_modulus_degree, shift, modulus[i], result + i * poly_modulus_degree);
            }
        }

        inline void negacyclicShiftPolyCoeffmod(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::size_t shift, const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                negacyclicShiftPolyCoeffmod(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, shift, modulus, result + i * d);
            }
        }

        inline void negacyclicMultiplyPolyMonoCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_count, std::uint64_t mono_coeff, std::size_t mono_exponent,
            const Modulus &modulus, HostPointer<uint64_t> result)
        {
            // FIXME: Frequent allocation
            HostArray<uint64_t> temp(coeff_count);
            multiplyPolyScalarCoeffmod(poly, coeff_count, mono_coeff, modulus, temp + 0);
            negacyclicShiftPolyCoeffmod(temp + 0, coeff_count, mono_exponent, modulus, result);
        }

        inline void negacyclicMultiplyPolyMonoCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t mono_coeff, std::size_t mono_exponent,
            const Modulus* modulus, HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                negacyclicMultiplyPolyMonoCoeffmod(poly + i * poly_modulus_degree, poly_modulus_degree, mono_coeff, mono_exponent, modulus[i], result + i * poly_modulus_degree);
            }
        }

        inline void negacyclicMultiplyPolyMonoCoeffmod(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, std::uint64_t mono_coeff, std::size_t mono_exponent,
            const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                negacyclicMultiplyPolyMonoCoeffmod(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, mono_coeff, mono_exponent, modulus, result + i * d);
            }
        }

        inline void negacyclicMultiplyPolyMonoCoeffmod(
            ConstHostPointer<uint64_t> poly, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, HostPointer<uint64_t> mono_coeff, std::size_t mono_exponent,
            const Modulus* modulus, HostPointer<uint64_t> result)
        {
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                negacyclicMultiplyPolyMonoCoeffmod(poly + i * poly_modulus_degree, poly_modulus_degree, mono_coeff[i], mono_exponent, modulus[i], result + i * poly_modulus_degree);
            }
        }

        inline void negacyclicMultiplyPolyMonoCoeffmod(
            ConstHostPointer<uint64_t> poly_array, std::size_t poly_size, std::size_t coeff_modulus_size, std::size_t poly_modulus_degree, HostPointer<uint64_t> mono_coeff, std::size_t mono_exponent,
            const Modulus* modulus, HostPointer<uint64_t> result)
        {
            std::size_t d = poly_modulus_degree * coeff_modulus_size;
            for (std::size_t i = 0; i < poly_size; i++) {
                negacyclicMultiplyPolyMonoCoeffmod(poly_array + i * d, coeff_modulus_size, poly_modulus_degree, mono_coeff, mono_exponent, modulus, result + i * d);
            }
        }
    } // namespace util
} // namespace seal
