// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../ciphertext.h"
#include "../randomgen.h"
#include "../randomtostd.h"
#include "clipnormal.h"
#include "common.h"
#include "globals.h"
#include "ntt.h"
#include "polyarithsmallmod.h"
#include "polycore.h"
#include "rlwe.h"

using namespace std;

namespace troy
{
    namespace util
    {
        void samplePolyTernary(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeffModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();

            RandomToStandardAdapter engine(prng);
            uniform_int_distribution<uint64_t> dist(0, 2);
            
            for (size_t i = 0; i < coeff_count; i++) {
            // SEAL_ITERATE(iter(destination), coeff_count, [&](auto &I) {
                uint64_t rand = dist(engine);
                uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(rand == 0));
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                // SEAL_ITERATE(
                //     iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
                    destination[i + j * coeff_count] = rand + (flag & coeff_modulus[j].value()) - 1;
                }
            }
        }

        void samplePolyNormal(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeffModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();

            if (areClose(global_variables::noise_max_deviation, 0.0))
            {
                setZeroPoly(coeff_count, coeff_modulus_size, destination);
                return;
            }

            RandomToStandardAdapter engine(prng);
            ClippedNormalDistribution dist(
                0, global_variables::noise_standard_deviation, global_variables::noise_max_deviation);

            for (size_t i = 0; i < coeff_count; i++) {
            // SEAL_ITERATE(iter(destination), coeff_count, [&](auto &I) {
                int64_t noise = static_cast<int64_t>(dist(engine));
                uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    destination[i + j * coeff_count] = static_cast<uint64_t>(noise) + (flag & coeff_modulus[j].value()); 
                }
            }
        }

        void samplePolyCbd(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeffModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();

            if (areClose(global_variables::noise_max_deviation, 0.0))
            {
                setZeroPoly(coeff_count, coeff_modulus_size, destination);
                return;
            }

            if (!areClose(global_variables::noise_standard_deviation, 3.2))
            {
                throw logic_error("centered binomial distribution only supports standard deviation 3.2; use rounded "
                                  "Gaussian instead");
            }

            auto cbd = [&]() {
                unsigned char x[6];
                prng->generate(6, reinterpret_cast<byte*>(x));
                x[2] &= 0x1F;
                x[5] &= 0x1F;
                return hammingWeight(x[0]) + hammingWeight(x[1]) + hammingWeight(x[2]) - hammingWeight(x[3]) -
                       hammingWeight(x[4]) - hammingWeight(x[5]);
            };

            for (size_t i = 0; i < coeff_count; i++) {
                int32_t noise = cbd();
                uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    destination[i + j * coeff_count] = static_cast<uint64_t>(noise) + (flag & coeff_modulus[j].value());
                }
            }
        }

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


        void samplePolyUniform(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            // Extract encryption parameters
            auto coeff_modulus = parms.coeffModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            size_t dest_byte_count = mul_safe(coeff_modulus_size, mul_safe(coeff_count, sizeof(uint64_t)));

            constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);

            // Fill the destination buffer with fresh randomness
            prng->generate(dest_byte_count, reinterpret_cast<byte *>(destination));

            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                auto &modulus = coeff_modulus[j];
                uint64_t max_multiple = max_random - barrettReduce64(max_random, modulus) - 1;
                transform(destination, destination + coeff_count, destination, [&](uint64_t rand) {
                    // This ensures uniform distribution
                    while (rand >= max_multiple)
                    {
                        prng->generate(sizeof(uint64_t), reinterpret_cast<byte *>(&rand));
                    }
                    return barrettReduce64(rand, modulus);
                });
                destination += coeff_count;
            }
        }

        void encryptZeroAsymmetric(
            const PublicKey &public_key, const SEALContext &context, ParmsID parms_id, bool is_ntt_form,
            Ciphertext &destination)
        {
            // We use a fresh memory pool with `clear_on_destruction' enabled

            auto &context_data = *context.getContextData(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            auto &plain_modulus = parms.plainModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            auto ntt_tables = context_data.smallNTTTables();
            size_t encrypted_size = public_key.data().size();
            SchemeType type = parms.scheme();

            // Make destination have right size and parms_id
            // Ciphertext (c_0,c_1, ...)
            destination.resize(context, parms_id, encrypted_size);
            destination.isNttForm() = is_ntt_form;
            destination.scale() = 1.0;
            destination.correctionFactor() = 1;

            // c[j] = public_key[j] * u + e[j] in BFV/CKKS = public_key[j] * u + p * e[j] in BGV
            // where e[j] <-- chi, u <-- R_3

            // Create a PRNG; u and the noise/error share the same PRNG
            auto prng = parms.randomGenerator()->create();

            // Generate u <-- R_3
            auto u(allocatePoly(coeff_count, coeff_modulus_size));
            samplePolyTernary(prng, parms, u.get());

            // c[j] = u * public_key[j]
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                nttNegacyclicHarvey(u.get() + i * coeff_count, ntt_tables[i]);
                for (size_t j = 0; j < encrypted_size; j++)
                {
                    dyadicProductCoeffmod(
                        u.get() + i * coeff_count, public_key.data().data(j) + i * coeff_count, coeff_count,
                        coeff_modulus[i], destination.data(j) + i * coeff_count);

                    // Addition with e_0, e_1 is in non-NTT form
                    if (!is_ntt_form)
                    {
                        inverseNttNegacyclicHarvey(destination.data(j) + i * coeff_count, ntt_tables[i]);
                    }
                }
            }


            // Generate e_j <-- chi
            // c[j] = public_key[j] * u + e[j] in BFV/CKKS, = public_key[j] * u + p * e[j] in BGV,
            for (size_t j = 0; j < encrypted_size; j++)
            {
                samplePolyCbd(prng, parms, u.get());
                auto gaussian_iter = u.asPointer();

                // In BGV, p * e is used
                if (type == SchemeType::bgv)
                {
                    if (is_ntt_form)
                    {
                        nttNegacyclicHarveyLazy(gaussian_iter, coeff_modulus_size, ntt_tables);
                    }
                    multiplyPolyScalarCoeffmod(
                        gaussian_iter.toConst(), coeff_modulus_size, coeff_count, plain_modulus.value(), &coeff_modulus[0], gaussian_iter);
                }
                else
                {
                    if (is_ntt_form)
                    {
                        nttNegacyclicHarvey(gaussian_iter, coeff_modulus_size, ntt_tables);
                    }
                }
                HostPointer dst_iter(destination.data(j));
                addPolyCoeffmod(gaussian_iter.toConst(), dst_iter.toConst(), coeff_modulus_size, coeff_count, &coeff_modulus[0], dst_iter);
            }
        }

        // The second last argument "save_seed" is deleted. set it to false.
        void encryptZeroSymmetric(
            const SecretKey &secret_key, const SEALContext &context, ParmsID parms_id, bool is_ntt_form,
            Ciphertext &destination)
        {
            // We use a fresh memory pool with `clear_on_destruction' enabled.

            auto &context_data = *context.getContextData(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            auto &plain_modulus = parms.plainModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            auto ntt_tables = context_data.smallNTTTables();
            size_t encrypted_size = 2;
            SchemeType type = parms.scheme();

            // // If a polynomial is too small to store UniformRandomGeneratorInfo,
            // // it is best to just disable save_seed. Note that the size needed is
            // // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
            // // of an indicator word that indicates a seeded ciphertext.
            // size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
            // size_t prng_info_byte_count =
            //     static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
            // size_t prng_info_uint64_count =
            //     divide_round_up(prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
            // if (save_seed && poly_uint64_count < prng_info_uint64_count + 1)
            // {
            bool save_seed = false;
            // }

            destination.resize(context, parms_id, encrypted_size);
            destination.isNttForm() = is_ntt_form;
            destination.scale() = 1.0;
            destination.correctionFactor() = 1;

            // Create an instance of a random number generator. We use this for sampling
            // a seed for a second PRNG used for sampling u (the seed can be public
            // information. This PRNG is also used for sampling the noise/error below.
            auto bootstrap_prng = parms.randomGenerator()->create();

            // Sample a public seed for generating uniform randomness
            PRNGSeed public_prng_seed;
            bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<byte *>(public_prng_seed.data()));

            // Set up a new default PRNG for expanding u from the seed sampled above
            auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);

            // Generate ciphertext: (c[0], c[1]) = ([-(as+ e)]_q, a) in BFV/CKKS
            // Generate ciphertext: (c[0], c[1]) = ([-(as+pe)]_q, a) in BGV
            uint64_t *c0 = destination.data();
            uint64_t *c1 = destination.data(1);

            // Sample a uniformly at random
            if (is_ntt_form || !save_seed)
            {
                // Sample the NTT form directly
                samplePolyUniform(ciphertext_prng, parms, c1);
            }
            else if (save_seed)
            {
                // Sample non-NTT form and store the seed
                samplePolyUniform(ciphertext_prng, parms, c1);
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into NTT representation
                    nttNegacyclicHarvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            // Sample e <-- chi
            auto noise(allocatePoly(coeff_count, coeff_modulus_size));
            samplePolyCbd(bootstrap_prng, parms, noise.get());

            // Calculate -(as+ e) (mod q) and store in c[0] in BFV/CKKS
            // Calculate -(as+pe) (mod q) and store in c[0] in BGV
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                dyadicProductCoeffmod(
                    secret_key.data().data() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation
                    nttNegacyclicHarvey(noise.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    inverseNttNegacyclicHarvey(c0 + i * coeff_count, ntt_tables[i]);
                }

                if (type == SchemeType::bgv)
                {
                    // noise = pe instead of e in BGV
                    multiplyPolyScalarCoeffmod(
                        noise.get() + i * coeff_count, coeff_count, plain_modulus.value(), coeff_modulus[i],
                        noise.get() + i * coeff_count);
                }

                // c0 = as + noise
                addPolyCoeffmod(
                    noise.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                // (as + noise, a) -> (-(as + noise), a),
                negatePolyCoeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
            }

            if (!is_ntt_form && !save_seed)
            {
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into non-NTT representation
                    inverseNttNegacyclicHarvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            // if (save_seed)
            // {
            //     UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();

            //     // Write prng_info to destination.data(1) after an indicator word
            //     c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
            //     prng_info.save(reinterpret_cast<seal_byte *>(c1 + 1), prng_info_byte_count, compr_mode_type::none);
            // }
        }
    } // namespace util
} // namespace seal
