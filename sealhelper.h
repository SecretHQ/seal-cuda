#include <seal/seal.h>
#include <seal/util/common.h>
#include <seal/util/polyarithsmallmod.h>
#include <iostream>
#include <iomanip>

void printArray(const uint64_t* start, size_t count, bool dont_compress=false) {
    std::cout << "[";
    for (size_t i = 0; i < count; i++) {
        if (!dont_compress && i == 5 && count >= 10) 
            {i = count - 5; std::cout << "...";}
        std::cout << std::hex << start[i];
        if (i!=count-1) std::cout << ", ";
    }
    std::cout << "]\n";
}

namespace sealhelper {
    using namespace seal;
    using namespace seal::util;
    using namespace std;

    void bfv_multiply(SEALContext& context_, Ciphertext &encrypted1, const Ciphertext &encrypted2)
    {

        MemoryPoolHandle pool = MemoryManager::GetPool();
        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t base_q_size = parms.coeff_modulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        uint64_t plain_modulus = parms.plain_modulus().value();

        auto rns_tool = context_data.rns_tool();
        size_t base_Bsk_size = rns_tool->base_Bsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->base_Bsk_m_tilde()->size();

        // Determine destination.size()
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Set up iterators for bases
        auto base_q = iter(parms.coeff_modulus());
        auto base_Bsk = iter(rns_tool->base_Bsk()->base());

        // Set up iterators for NTT tables
        auto base_q_ntt_tables = iter(context_data.small_ntt_tables());
        auto base_Bsk_ntt_tables = iter(rns_tool->base_Bsk_ntt_tables());

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
        encrypted1.resize(context_, context_data.parms_id(), dest_size);

        // This lambda function takes as input an IterTuple with three components:
        //
        // 1. (Const)RNSIter to read an input polynomial from
        // 2. RNSIter for the output in base q
        // 3. RNSIter for the output in base Bsk
        //
        // It performs steps (1)-(3) of the BEHZ multiplication (see above) on the given input polynomial (given as an
        // RNSIter or ConstRNSIter) and writes the results in base q and base Bsk to the given output
        // iterators.
        auto behz_extend_base_convert_to_ntt = [&](auto I) {
            // Make copy of input polynomial (in base q) and convert to NTT form
            // Lazy reduction
            set_poly(get<0>(I), coeff_count, base_q_size, get<1>(I));
            ntt_negacyclic_harvey_lazy(get<1>(I), base_q_size, base_q_ntt_tables);

            // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
            SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, base_Bsk_m_tilde_size, pool);

            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool->fastbconv_m_tilde(get<0>(I), temp, pool);

            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            rns_tool->sm_mrq(temp, get<2>(I), pool);

            // Transform to NTT form in base Bsk
            // Lazy reduction
            ntt_negacyclic_harvey_lazy(get<2>(I), base_Bsk_size, base_Bsk_ntt_tables);
        };

        // Allocate space for a base q output of behz_extend_base_convert_to_ntt for encrypted1
        SEAL_ALLOCATE_GET_POLY_ITER(encrypted1_q, encrypted1_size, coeff_count, base_q_size, pool);

        // Allocate space for a base Bsk output of behz_extend_base_convert_to_ntt for encrypted1
        SEAL_ALLOCATE_GET_POLY_ITER(encrypted1_Bsk, encrypted1_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ steps (1)-(3) for encrypted1
        SEAL_ITERATE(iter(encrypted1, encrypted1_q, encrypted1_Bsk), encrypted1_size, behz_extend_base_convert_to_ntt);

        std::cout << "Encrypted1_q: ";
        printArray(**encrypted1_q, encrypted1_size * coeff_count * base_q_size);
        std::cout << "Encrypted1_Bsk: ";
        printArray(**encrypted1_Bsk, encrypted1_size * coeff_count * base_Bsk_size);

        // Repeat for encrypted2
        SEAL_ALLOCATE_GET_POLY_ITER(encrypted2_q, encrypted2_size, coeff_count, base_q_size, pool);
        SEAL_ALLOCATE_GET_POLY_ITER(encrypted2_Bsk, encrypted2_size, coeff_count, base_Bsk_size, pool);

        SEAL_ITERATE(iter(encrypted2, encrypted2_q, encrypted2_Bsk), encrypted2_size, behz_extend_base_convert_to_ntt);

        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components
        SEAL_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_q, dest_size, coeff_count, base_q_size, pool);
        SEAL_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_Bsk, dest_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphertexts
        SEAL_ITERATE(iter(size_t(0)), dest_size, [&](auto I) {
            // std::cout << "behz4 i = " << I << std::endl;
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            size_t curr_encrypted1_last = min<size_t>(I, encrypted1_size - 1);
            size_t curr_encrypted2_first = min<size_t>(I, encrypted2_size - 1);
            size_t curr_encrypted1_first = I - curr_encrypted2_first;
            // size_t curr_encrypted2_last = I - curr_encrypted1_last;

            // The total number of dyadic products is now easy to compute
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            // This lambda function computes the ciphertext product for BFV multiplication. Since we use the BEHZ
            // approach, the multiplication of individual polynomials is done using a dyadic product where the inputs
            // are already in NTT form. The arguments of the lambda function are expected to be as follows:
            //
            // 1. a ConstPolyIter pointing to the beginning of the first input ciphertext (in NTT form)
            // 2. a ConstPolyIter pointing to the beginning of the second input ciphertext (in NTT form)
            // 3. a ConstModulusIter pointing to an array of Modulus elements for the base
            // 4. the size of the base
            // 5. a PolyIter pointing to the beginning of the output ciphertext
            auto behz_ciphertext_product = [&](ConstPolyIter in1_iter, ConstPolyIter in2_iter,
                                               ConstModulusIter base_iter, size_t base_size, PolyIter out_iter) {
                // Create a shifted iterator for the first input
                auto shifted_in1_iter = in1_iter + curr_encrypted1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_in2_iter = reverse_iter(in2_iter + curr_encrypted2_first);

                // Create a shifted iterator for the output
                auto shifted_out_iter = out_iter[I];

                SEAL_ITERATE(iter(shifted_in1_iter, shifted_reversed_in2_iter), steps, [&](auto J) {
                    SEAL_ITERATE(iter(J, base_iter, shifted_out_iter), base_size, [&](auto K) {
                        SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool);
                        // std::cout << "first of k: " << *(get<0, 0>(K)) << std::endl;
                        dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K), coeff_count, get<1>(K), temp);
                        // std::cout << "first of temp: " << *(temp) << std::endl;
                        add_poly_coeffmod(temp, get<2>(K), coeff_count, get<1>(K), get<2>(K));
                        // std::cout << "first of result: " << *(get<2>(K)) << std::endl;
                    });
                });
            };

            // Perform the BEHZ ciphertext product both for base q and base Bsk
            behz_ciphertext_product(encrypted1_q, encrypted2_q, base_q, base_q_size, temp_dest_q);
            behz_ciphertext_product(encrypted1_Bsk, encrypted2_Bsk, base_Bsk, base_Bsk_size, temp_dest_Bsk);
        });

        std::cout << "temp_dest_q: ";
        printArray(**temp_dest_q, dest_size * coeff_count * base_q_size);
        std::cout << "temp_dest_Bsk: ";
        printArray(**temp_dest_Bsk, dest_size * coeff_count * base_Bsk_size);

        // Perform BEHZ step (5): transform data from NTT form
        // Lazy reduction here. The following multiply_poly_scalar_coeffmod will correct the value back to [0, p)
        inverse_ntt_negacyclic_harvey_lazy(temp_dest_q, dest_size, base_q_ntt_tables);
        inverse_ntt_negacyclic_harvey_lazy(temp_dest_Bsk, dest_size, base_Bsk_ntt_tables);

        std::cout << "after ntt temp_dest_q: ";
        printArray(**temp_dest_q, dest_size * coeff_count * base_q_size);
        std::cout << "after ntt temp_dest_Bsk: ";
        printArray(**temp_dest_Bsk, dest_size * coeff_count * base_Bsk_size);

        // Perform BEHZ steps (6)-(8)
        SEAL_ITERATE(iter(temp_dest_q, temp_dest_Bsk, encrypted1, size_t(0)), dest_size, [&](auto I) {
            // Bring together the base q and base Bsk components into a single allocation
            SEAL_ALLOCATE_GET_RNS_ITER(temp_q_Bsk, coeff_count, base_q_size + base_Bsk_size, pool);

            // Step (6): multiply base q components by t (plain_modulus)
            multiply_poly_scalar_coeffmod(get<0>(I), base_q_size, plain_modulus, base_q, temp_q_Bsk);

            multiply_poly_scalar_coeffmod(get<1>(I), base_Bsk_size, plain_modulus, base_Bsk, temp_q_Bsk + base_q_size);

            std::cout << "i = " << get<3>(I) << std::endl;
            std::cout << "temp_q_Bsk" << std::endl;
            printArray(*temp_q_Bsk, coeff_count * (base_q_size + base_Bsk_size));

            // Allocate yet another temporary for fast divide-and-floor result in base Bsk
            SEAL_ALLOCATE_GET_RNS_ITER(temp_Bsk, coeff_count, base_Bsk_size, pool);

            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool->fast_floor(temp_q_Bsk, temp_Bsk, pool);
            
            std::cout << "temp_Bsk" << std::endl;
            printArray(*temp_Bsk, coeff_count * base_Bsk_size);

            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool->fastbconv_sk(temp_Bsk, get<2>(I), pool);

            
            std::cout << "enc i" << std::endl;
            printArray(*get<2>(I), coeff_count * base_q_size);
        });
    }

    void switch_key_inplace(
        SEALContext& context_,
        Ciphertext &encrypted, ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index)
    {
        auto pool = MemoryManager::GetPool();
        auto parms_id = encrypted.parms_id();
        auto &context_data = *context_.get_context_data(parms_id);
        auto &parms = context_data.parms();
        auto &key_context_data = *context_.key_context_data();
        auto &key_parms = key_context_data.parms();
        auto scheme = parms.scheme();

        // Extract encryption parameters.
        size_t coeff_count = parms.poly_modulus_degree();
        size_t decomp_modulus_size = parms.coeff_modulus().size();
        auto &key_modulus = key_parms.coeff_modulus();
        size_t key_modulus_size = key_modulus.size();
        size_t rns_modulus_size = decomp_modulus_size + 1;
        auto key_ntt_tables = iter(key_context_data.small_ntt_tables());
        auto modswitch_factors = key_context_data.rns_tool()->inv_q_last_mod_q();

        // Prepare input
        auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
        size_t key_component_count = key_vector[0].data().size();

        // Create a copy of target_iter
        SEAL_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);
        set_uint(target_iter, decomp_modulus_size * coeff_count, t_target);

        std::cout << "t_target: "; printArray(*t_target, coeff_count * decomp_modulus_size);

        // In CKKS t_target is in NTT form; switch back to normal form
        if (scheme == scheme_type::ckks)
        {
            inverse_ntt_negacyclic_harvey(t_target, decomp_modulus_size, key_ntt_tables);
        }

        // Temporary result
        auto t_poly_prod(allocate_zero_poly_array(key_component_count, coeff_count, rns_modulus_size, pool));

        SEAL_ITERATE(iter(size_t(0)), rns_modulus_size, [&](auto I) {
            std::cout << "ski i = " << I << std::endl;
            size_t key_index = (I == decomp_modulus_size ? key_modulus_size - 1 : I);

            // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
            size_t lazy_reduction_summand_bound = size_t(SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
            size_t lazy_reduction_counter = lazy_reduction_summand_bound;

            // Allocate memory for a lazy accumulator (128-bit coefficients)
            auto t_poly_lazy(allocate_zero_poly_array(key_component_count, coeff_count, 2, pool));

            // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
            PolyIter accumulator_iter(t_poly_lazy.get(), 2, coeff_count);

            // Multiply with keys and perform lazy reduction on product's coefficients
            SEAL_ITERATE(iter(size_t(0)), decomp_modulus_size, [&](auto J) {
                SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
                ConstCoeffIter t_operand;

                // RNS-NTT form exists in input
                if ((scheme == scheme_type::ckks) && (I == J))
                {
                    t_operand = target_iter[J];
                }
                // Perform RNS-NTT conversion
                else
                {
                    // No need to perform RNS conversion (modular reduction)
                    if (key_modulus[J] <= key_modulus[key_index])
                    {
                        set_uint(t_target[J], coeff_count, t_ntt);
                    }
                    // Perform RNS conversion (modular reduction)
                    else
                    {
                        modulo_poly_coeffs(t_target[J], coeff_count, key_modulus[key_index], t_ntt);
                    }
                    // NTT conversion lazy outputs in [0, 4q)
                    ntt_negacyclic_harvey_lazy(t_ntt, key_ntt_tables[key_index]);
                    t_operand = t_ntt;
                }
                
                std::cout << "j = " << J << std::endl;
                std::cout << "t_operand: "; printArray(t_operand.ptr(), coeff_count);

                // Multiply with keys and modular accumulate products in a lazy fashion
                SEAL_ITERATE(iter(key_vector[J].data(), accumulator_iter), key_component_count, [&](auto K) {
                    if (!lazy_reduction_counter)
                    {
                        SEAL_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            unsigned long long qword[2]{ 0, 0 };
                            multiply_uint64(get<0>(L), get<1>(L), qword);

                            // Accumulate product of t_operand and t_key_acc to t_poly_lazy and reduce
                            add_uint128(qword, get<2>(L).ptr(), qword);
                            get<2>(L)[0] = barrett_reduce_128(qword, key_modulus[key_index]);
                            get<2>(L)[1] = 0;
                        });
                    }
                    else
                    {
                        // Same as above but no reduction
                        SEAL_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            unsigned long long qword[2]{ 0, 0 };
                            multiply_uint64(get<0>(L), get<1>(L), qword);
                            add_uint128(qword, get<2>(L).ptr(), qword);
                            get<2>(L)[0] = qword[0];
                            get<2>(L)[1] = qword[1];
                        });
                    }
                });

                if (!--lazy_reduction_counter)
                {
                    lazy_reduction_counter = lazy_reduction_summand_bound;
                }
            });

            std::cout << "  t_poly_lazy: ";
            printArray(t_poly_lazy.get(), key_component_count * coeff_count * 2, true);

            // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
            PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count, rns_modulus_size);

            // Final modular reduction
            SEAL_ITERATE(iter(accumulator_iter, t_poly_prod_iter), key_component_count, [&](auto K) {
                if (lazy_reduction_counter == lazy_reduction_summand_bound)
                {
                    SEAL_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                        
                        // std::cout << "get<0>(K): " << *get<0>(L) << std::endl;
                        get<1>(L) = static_cast<uint64_t>(*get<0>(L));
                    });
                }
                else
                {
                    // Same as above except need to still do reduction
                    SEAL_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                        // std::cout << "get<0>(K): " << *get<0>(L) << std::endl;
                        get<1>(L) = barrett_reduce_128(get<0>(L).ptr(), key_modulus[key_index]);
                    });
                }
            });
        });
        // Accumulated products are now stored in t_poly_prod

        std::cout << "t_poly_prod: ";
        printArray(t_poly_prod.get(), key_component_count * coeff_count * rns_modulus_size, true);

        // Perform modulus switching with scaling
        PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, rns_modulus_size);
        SEAL_ITERATE(iter(encrypted, t_poly_prod_iter), key_component_count, [&](auto I) {
            if (scheme == scheme_type::bgv)
            {
                const Modulus &plain_modulus = parms.plain_modulus();
                // qk is the special prime
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_inv_qp = context_.key_context_data()->rns_tool()->inv_q_last_mod_t();

                // Lazy reduction; this needs to be then reduced mod qi
                CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                inverse_ntt_negacyclic_harvey(t_last, key_ntt_tables[key_modulus_size - 1]);

                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(k, coeff_count, pool);
                modulo_poly_coeffs(t_last, coeff_count, plain_modulus, k);
                negate_poly_coeffmod(k, coeff_count, plain_modulus, k);
                if (qk_inv_qp != 1)
                {
                    multiply_poly_scalar_coeffmod(k, coeff_count, qk_inv_qp, plain_modulus, k);
                }

                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(delta, coeff_count, pool);
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(c_mod_qi, coeff_count, pool);
                SEAL_ITERATE(iter(I, key_modulus, modswitch_factors, key_ntt_tables), decomp_modulus_size, [&](auto J) {
                    inverse_ntt_negacyclic_harvey(get<0, 1>(J), get<3>(J));
                    // delta = k mod q_i
                    modulo_poly_coeffs(k, coeff_count, get<1>(J), delta);
                    // delta = k * q_k mod q_i
                    multiply_poly_scalar_coeffmod(delta, coeff_count, qk, get<1>(J), delta);

                    // c mod q_i
                    modulo_poly_coeffs(t_last, coeff_count, get<1>(J), c_mod_qi);
                    // delta = c + k * q_k mod q_i
                    // c_{i} = c_{i} - delta mod q_i
                    const uint64_t Lqi = get<1>(J).value() * 2;
                    SEAL_ITERATE(iter(delta, c_mod_qi, get<0, 1>(J)), coeff_count, [Lqi](auto K) {
                        get<2>(K) = get<2>(K) + Lqi - (get<0>(K) + get<1>(K));
                    });

                    multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<2>(J), get<1>(J), get<0, 1>(J));

                    add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
                });
            }
            else
            {
                // Lazy reduction; this needs to be then reduced mod qi
                CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                // std::cout << "t_last diff: " << t_last.ptr() - t_poly_prod.get() << std::endl;
                
                // std::cout << "t_last: "; printArray(t_last.ptr(), coeff_count);
                inverse_ntt_negacyclic_harvey_lazy(t_last, key_ntt_tables[key_modulus_size - 1]);

                // Add (p-1)/2 to change from flooring to rounding.
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_half = qk >> 1;
                SEAL_ITERATE(t_last, coeff_count, [&](auto &J) {
                    J = barrett_reduce_64(J + qk_half, key_modulus[key_modulus_size - 1]);
                });
                
                // std::cout << "t_last: "; printArray(t_last.ptr(), coeff_count);

                SEAL_ITERATE(iter(I, key_modulus, key_ntt_tables, modswitch_factors, size_t(0)), decomp_modulus_size, [&](auto J) {
                    SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
                    auto j = get<4>(J);
                    // std::cout << "  ski j = " << j << std::endl;
                    // (ct mod 4qk) mod qi
                    uint64_t qi = get<1>(J).value();
                    if (qk > qi)
                    {
                        // This cannot be spared. NTT only tolerates input that is less than 4*modulus (i.e. qk <=4*qi).
                        modulo_poly_coeffs(t_last, coeff_count, get<1>(J), t_ntt);
                    }
                    else
                    {
                        set_uint(t_last, coeff_count, t_ntt);
                    }

                    // Lazy substraction, results in [0, 2*qi), since fix is in [0, qi].
                    uint64_t fix = qi - barrett_reduce_64(qk_half, get<1>(J));
                    SEAL_ITERATE(t_ntt, coeff_count, [fix](auto &K) { K += fix; });

                    // std::cout << "  t_ntt: "; printArray(t_ntt.ptr(), coeff_count);

                    uint64_t qi_lazy = qi << 1; // some multiples of qi
                    if (scheme == scheme_type::ckks)
                    {
                        // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                        ntt_negacyclic_harvey_lazy(t_ntt, get<2>(J));
#if SEAL_USER_MOD_BIT_COUNT_MAX > 60
                        // Reduce from [0, 4qi) to [0, 2qi)
                        SEAL_ITERATE(
                            t_ntt, coeff_count, [&](auto &K) { K -= SEAL_COND_SELECT(K >= qi_lazy, qi_lazy, 0); });
#else
                        // Since SEAL uses at most 60bit moduli, 8*qi < 2^63.
                        qi_lazy = qi << 2;
#endif
                    }
                    else if (scheme == scheme_type::bfv)
                    {
                        inverse_ntt_negacyclic_harvey_lazy(get<0, 1>(J), get<2>(J));
                    }

                    // ((ct mod qi) - (ct mod qk)) mod qi with output in [0, 2 * qi_lazy)
                    SEAL_ITERATE(
                        iter(get<0, 1>(J), t_ntt), coeff_count, [&](auto K) { get<0>(K) += qi_lazy - get<1>(K); });

                    // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                    multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<3>(J), get<1>(J), get<0, 1>(J));
                    add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
                });
            }
        });
    }

    void relinearize_internal(
        SEALContext& context_,
        Ciphertext &encrypted, const RelinKeys &relin_keys, size_t destination_size)
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (relin_keys.parms_id() != context_.key_parms_id())
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
        auto encrypted_iter = iter(encrypted);
        encrypted_iter += encrypted_size - 1;

        SEAL_ITERATE(iter(size_t(0)), relins_needed, [&](auto I) {
            auto ptr = (**encrypted_iter).ptr();
            std::cout << "encrypted_iter diff = " << std::dec << (ptr - encrypted.data()) << std::endl;
            switch_key_inplace(
                context_,
                encrypted, *encrypted_iter, static_cast<const KSwitchKeys &>(relin_keys),
                RelinKeys::get_index(encrypted_size - 1 - I));
            // std::cout << "relinearization " << I << ":";
            // printArray(encrypted.data(), encrypted.dyn_array().size());
        });

        // Put the output of final relinearization into destination.
        // Prepare destination only at this point because we are resizing down
        encrypted.resize(context_, context_data_ptr->parms_id(), destination_size);

    }

    void compute_secret_key_array(uint64_t* secret_key_array_, const SEALContext::ContextData &context_data, size_t max_power)
    {
        auto pool_ = MemoryManager::GetPool();

        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size, max_power))
        {
            throw logic_error("invalid parameters");
        }

        size_t old_size = 1;
        size_t new_size = max(max_power, old_size);

        if (old_size == new_size)
        {
            return;
        }

        // Need to extend the array
        // Compute powers of secret key until max_power
        auto secret_key_array(allocate_poly_array(new_size, coeff_count, coeff_modulus_size, pool_));
        set_poly_array(secret_key_array_, old_size, coeff_count, coeff_modulus_size, secret_key_array.get());
        RNSIter secret_key(secret_key_array.get(), coeff_count);

        PolyIter secret_key_power(secret_key_array.get(), coeff_count, coeff_modulus_size);
        secret_key_power += (old_size - 1);
        auto next_secret_key_power = secret_key_power + 1;

        // Since all of the key powers in secret_key_array_ are already NTT transformed, to get the next one we simply
        // need to compute a dyadic product of the last one with the first one [which is equal to NTT(secret_key_)].
        SEAL_ITERATE(iter(secret_key_power, next_secret_key_power), new_size - old_size, [&](auto I) {
            dyadic_product_coeffmod(get<0>(I), secret_key, coeff_modulus_size, coeff_modulus, get<1>(I));
        });

        std::cout << "Secret key array: ";
        printArray(secret_key_array.get(), new_size * coeff_count * coeff_modulus_size);

    }

        inline void xdyadic_product_coeffmod(
            ConstRNSIter operand1, ConstRNSIter operand2, std::size_t coeff_modulus_size, ConstModulusIter modulus,
            RNSIter result)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && coeff_modulus_size > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && coeff_modulus_size > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (!result && coeff_modulus_size > 0)
            {
                throw std::invalid_argument("result");
            }
            if (!modulus && coeff_modulus_size > 0)
            {
                throw std::invalid_argument("modulus");
            }
            if (operand1.poly_modulus_degree() != result.poly_modulus_degree() ||
                operand2.poly_modulus_degree() != result.poly_modulus_degree())
            {
                throw std::invalid_argument("incompatible iterators");
            }
#endif
            auto poly_modulus_degree = result.poly_modulus_degree();
            SEAL_ITERATE(iter(operand1, operand2, modulus, result, size_t(0)), coeff_modulus_size, [&](auto I) {
                // size_t i = get<4>(I);
                // std::cout << " xpoly oper2 i = " << i << ": "; 
                // printArray(&(get<1>(I)[0]), poly_modulus_degree, true);
                dyadic_product_coeffmod(get<0>(I), get<1>(I), poly_modulus_degree, get<2>(I), get<3>(I));

            });
        }
    
    void multiply_plain_ntt(SEALContext& context_, Ciphertext &encrypted_ntt, const Plaintext &plain_ntt) 
    {

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted_ntt.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        // Size check
        if (!product_fits_in(encrypted_ntt_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        ConstRNSIter plain_ntt_iter(plain_ntt.data(), coeff_count);
        SEAL_ITERATE(iter(encrypted_ntt, size_t(0)), encrypted_ntt_size, [&](auto I) {
            std::cout << "before dyadic " << get<1>(I) << ": ";
            printArray(encrypted_ntt.data(get<1>(I)), coeff_modulus_size * coeff_count);
            xdyadic_product_coeffmod(get<0>(I), plain_ntt_iter, coeff_modulus_size, coeff_modulus, get<0>(I));
            
            std::cout << "after dyadic " << get<1>(I) << ": ";
            printArray(encrypted_ntt.data(get<1>(I)), coeff_modulus_size * coeff_count);
        });

        // Set the scale
        encrypted_ntt.scale() *= plain_ntt.scale();
    }

}