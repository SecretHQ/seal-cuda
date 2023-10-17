// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "rlwe_cuda.cuh"
#include "../kernelutils.cuh"
#include <curand_normal.h>

using namespace std;


#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy
{
    namespace util
    {
        
        namespace sampler {
            
            __global__ void gInitCurandStates(curandState* states, size_t n, uint64_t seed) {
                GET_INDEX_COND_RETURN(n);
                curand_init(gindex + seed, 0, 0, &(states[gindex]));
            }

            void setupCurandStates(curandState* states, size_t n, uint64_t seed) {
                KERNEL_CALL(gInitCurandStates, n)(states, n, seed);
            }

            __global__ void gSamplePolyTenary(
                curandState* states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                const Modulus* modulus,
                uint64_t* destination
            ) {
                GET_INDEX_COND_RETURN(coeff_count);
                int r = static_cast<int>(curand_uniform(states + gindex) * 3);
                FOR_N(j, coeff_modulus_size) {
                    uint64_t modulus_value = DeviceHelper::getModulusValue(modulus[j]);
                    if (r==2) destination[gindex + j * coeff_count] = modulus_value - 1;
                    else destination[gindex + j * coeff_count] = r;
                }
            }

            inline void kSamplePolyTenary(
                DevicePointer<curandState> states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                ConstDevicePointer<Modulus> modulus,
                DevicePointer<uint64_t> destination
            ) {
                KERNEL_CALL(gSamplePolyTenary, coeff_count)(
                    states.get(), coeff_modulus_size, coeff_count, modulus.get(), destination.get()
                );
            }

            constexpr double standard_deviation = 3.2;
            constexpr double noise_max_deviation = 19.2;

            __global__ void gSamplePolyNormal(
                curandState* states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                const Modulus* modulus,
                uint64_t* destination
            ) {
                GET_INDEX_COND_RETURN(coeff_count);
                double r;
                while (true) {
                    r = curand_normal(states + gindex);
                    if (r < noise_max_deviation / standard_deviation) break;
                }
                r *= standard_deviation;
                int64_t ri = static_cast<int64_t>(r);
                FOR_N(j, coeff_modulus_size) {
                    uint64_t modulus_value = DeviceHelper::getModulusValue(modulus[j]);
                    if (ri >= 0) destination[gindex + j * coeff_count] = ri;
                    else destination[gindex + j * coeff_count] = modulus_value - static_cast<uint64_t>(-ri);
                }
            }

            inline void kSamplePolyNormal(
                DevicePointer<curandState> states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                ConstDevicePointer<Modulus> modulus,
                DevicePointer<uint64_t> destination
            ) {
                KERNEL_CALL(gSamplePolyNormal, coeff_count)(
                    states.get(), coeff_modulus_size, coeff_count, modulus.get(), destination.get()
                );
            }

            __device__ inline int dHammingWeight(unsigned char value)
            {
                int t = static_cast<int>(value);
                t -= (t >> 1) & 0x55;
                t = (t & 0x33) + ((t >> 2) & 0x33);
                return (t + (t >> 4)) & 0x0F;
            }

            __global__ void gSamplePolyCbd(
                curandState* states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                const Modulus* modulus,
                uint64_t* destination
            ) {
                GET_INDEX_COND_RETURN(coeff_count);
                unsigned char x[6];
                for (size_t j = 0; j < 6; j++) 
                    x[j] = static_cast<unsigned char>(curand_uniform(states + gindex) * 256);
                x[2] &= 0x1f; x[5] &= 0x1f;
                int r = dHammingWeight(x[0]) + dHammingWeight(x[1]) + dHammingWeight(x[2]) - dHammingWeight(x[3]) -
                       dHammingWeight(x[4]) - dHammingWeight(x[5]);
                FOR_N(j, coeff_modulus_size) {
                    uint64_t modulus_value = DeviceHelper::getModulusValue(modulus[j]);
                    if (r >= 0) destination[gindex + j * coeff_count] = r;
                    else destination[gindex + j * coeff_count] = modulus_value - static_cast<uint64_t>(-r);
                }
            }

            inline void kSamplePolyCbd(
                DevicePointer<curandState> states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                ConstDevicePointer<Modulus> modulus,
                DevicePointer<uint64_t> destination
            ) {
                KERNEL_CALL(gSamplePolyCbd, coeff_count)(
                    states.get(), coeff_modulus_size, coeff_count, modulus.get(), destination.get()
                );
            }

            __global__ void gSamplePolyUniform(
                curandState* states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                const Modulus* modulus,
                uint64_t* destination
            ) {
                GET_INDEX_COND_RETURN(coeff_count);
                FOR_N(j, coeff_modulus_size) {
                    destination[gindex + j * coeff_count] = curand_uniform_double(states + gindex) * DeviceHelper::getModulusValue(modulus[j]);
                }
            }

            void kSamplePolyUniform(
                DevicePointer<curandState> states,
                size_t coeff_modulus_size,
                size_t coeff_count,
                ConstDevicePointer<Modulus> modulus,
                DevicePointer<uint64_t> destination
            ) {
                KERNEL_CALL(gSamplePolyUniform, coeff_count)(
                    states.get(), coeff_modulus_size, coeff_count, modulus.get(), destination.get()
                );
            }

        }

        [[maybe_unused]] void printDeviceArray(const DeviceArray<uint64_t>& r, bool dont_compress = false) {
            HostArray<uint64_t> start = r.toHost();
            size_t count = r.size();
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }

        [[maybe_unused]] void printDeviceArray(const uint64_t* r, size_t count, bool dont_compress = false) {
            HostArray<uint64_t> start(count);
            KernelProvider::retrieve(start.get(), r, count);
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }

        void encryptZeroAsymmetric(
            const PublicKeyCuda &public_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination, DevicePointer<curandState> curandStates)
        {
            // We use a fresh memory pool with `clear_on_destruction' enabled

            auto &context_data = *context.getContextData(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            auto &plain_modulus = parms.plainModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            size_t coeff_power = getPowerOfTwo(coeff_count);
            auto ntt_tables = context_data.smallNTTTables();
            size_t encrypted_size = public_key.data().size();
            SchemeType type = parms.scheme();

            // Make destination have right size and parms_id
            // Ciphertext (c_0,c_1, ...)
            destination.resize(context, parms_id, encrypted_size);
            destination.isNttForm() = is_ntt_form;
            destination.scale() = 1.0;
            destination.correctionFactor() = 1;
            destination.seed() = 0;

            // c[j] = public_key[j] * u + e[j] in BFV/CKKS = public_key[j] * u + p * e[j] in BGV
            // where e[j] <-- chi, u <-- R_3

            // Create a PRNG; u and the noise/error share the same PRNG
            auto prng = parms.randomGenerator()->create();

            // Generate u <-- R_3
            DeviceArray<uint64_t> u(coeff_count * coeff_modulus_size);
            sampler::kSamplePolyTenary(curandStates, coeff_modulus_size, coeff_count, coeff_modulus, u);

            // c[j] = u * public_key[j]
            kernel_util::kNttNegacyclicHarvey(u.get(), 1, coeff_modulus_size, coeff_power, ntt_tables);
            for (size_t j = 0; j < encrypted_size; j++)
            {
                kernel_util::kDyadicProductCoeffmod(u, public_key.data().data(j), 1, coeff_modulus_size, coeff_count, coeff_modulus, destination.data(j));
                if (!is_ntt_form) {
                    kernel_util::kInverseNttNegacyclicHarvey(destination.data(j), 1, coeff_modulus_size, coeff_power, ntt_tables);
                }
            }

            // Generate e_j <-- chi
            // c[j] = public_key[j] * u + e[j] in BFV/CKKS, = public_key[j] * u + p * e[j] in BGV,
            for (size_t j = 0; j < encrypted_size; j++)
            {
                sampler::kSamplePolyCbd(curandStates, coeff_modulus_size, coeff_count, coeff_modulus, u);
                auto gaussian_iter = u.asPointer();

                // In BGV, p * e is used
                if (type == SchemeType::bgv)
                {
                    if (is_ntt_form)
                        kernel_util::kNttNegacyclicHarveyLazy(gaussian_iter, 1, coeff_modulus_size, coeff_power, ntt_tables);
                    kernel_util::kMultiplyPolyScalarCoeffmod(gaussian_iter, 1, coeff_modulus_size, coeff_count, plain_modulus.value(), coeff_modulus, gaussian_iter);
                }
                else
                {
                    if (is_ntt_form)
                        kernel_util::kNttNegacyclicHarvey(gaussian_iter, 1, coeff_modulus_size, coeff_power, ntt_tables);
                }
                kernel_util::kAddPolyCoeffmod(gaussian_iter, destination.data(j), 1, coeff_modulus_size, coeff_count, coeff_modulus, destination.data(j));
            }
        }

        // The second last argument "save_seed" is deleted. set it to false.
        void encryptZeroSymmetric(
            const SecretKeyCuda &secret_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination, DevicePointer<curandState> curandStates)
        {
            // We use a fresh memory pool with `clear_on_destruction' enabled.

            auto &context_data = *context.getContextData(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            auto &plain_modulus = parms.plainModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            size_t coeff_power = getPowerOfTwo(coeff_count);
            auto ntt_tables = context_data.smallNTTTables();
            size_t encrypted_size = 2;
            SchemeType type = parms.scheme();

            destination.resize(context, parms_id, encrypted_size);
            destination.isNttForm() = is_ntt_form;
            destination.scale() = 1.0;
            destination.correctionFactor() = 1;

            auto bootstrap_prng = parms.randomGenerator()->create();

            PRNGSeed public_prng_seed;
            bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<byte *>(public_prng_seed.data()));

            auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);

            auto newStates = DeviceArray<curandState>(coeff_count);
            uint64_t seed;
            while (true) {
                seed = (static_cast<uint64_t>(ciphertext_prng->generate()) << 32) + static_cast<uint64_t>(ciphertext_prng->generate());
                if (seed) break;
            }
            destination.seed() = seed;
            sampler::setupCurandStates(newStates.get(), coeff_count, seed);

            // Generate ciphertext: (c[0], c[1]) = ([-(as+ e)]_q, a) in BFV/CKKS
            // Generate ciphertext: (c[0], c[1]) = ([-(as+pe)]_q, a) in BGV
            auto c0 = destination.data();
            auto c1 = destination.data(1);

            // Sample a uniformly at random

            sampler::kSamplePolyUniform(newStates.get(), coeff_modulus_size, coeff_count, coeff_modulus, c1.get());

            // Sample e <-- chi
            DeviceArray<uint64_t> noise(coeff_modulus_size * coeff_count);
            sampler::kSamplePolyCbd(curandStates, coeff_modulus_size, coeff_count, coeff_modulus, noise);

            // Calculate -(as+ e) (mod q) and store in c[0] in BFV/CKKS
            // Calculate -(as+pe) (mod q) and store in c[0] in BGV

            kernel_util::kDyadicProductCoeffmod(secret_key.data().data(), c1, 1, coeff_modulus_size, coeff_count, coeff_modulus, c0);
            if (is_ntt_form) {
                kernel_util::kNttNegacyclicHarvey(noise.get(), 1, coeff_modulus_size, coeff_power, ntt_tables);
            } else {
                kernel_util::kInverseNttNegacyclicHarvey(c0, 1, coeff_modulus_size, coeff_power, ntt_tables);
            }
            if (type == SchemeType::bgv) {
                kernel_util::kMultiplyPolyScalarCoeffmod(noise, 1, coeff_modulus_size, coeff_count, plain_modulus.value(), coeff_modulus, noise);
            }
            kernel_util::kAddPolyCoeffmod(noise, c0, 1, coeff_modulus_size, coeff_count, coeff_modulus, c0);
            kernel_util::kNegatePolyCoeffmod(c0, 1, coeff_modulus_size, coeff_count, coeff_modulus, c0);
            if (!is_ntt_form) {
                kernel_util::kInverseNttNegacyclicHarvey(c1, 1, coeff_modulus_size, coeff_power, ntt_tables);
            }

        }
    } // namespace util
} // namespace seal
