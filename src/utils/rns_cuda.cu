#include "rns_cuda.cuh"
#include "../kernelutils.cuh"

#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define POLY_ARGUMENTS size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARGCALL coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy {

    namespace util {

        __global__ void gDecomposeArray(
            const uint64_t* values, POLY_ARGUMENTS, const Modulus* moduli,
            uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                size_t oid = gindex * coeff_modulus_size;
                size_t nid = rns_index * poly_modulus_degree + gindex;
                result[nid] = kernel_util::dModuloUint(values + oid, coeff_modulus_size, moduli[rns_index]);
            }
        } 

        __global__ void gDecomposeArrayKeepOrder(
            const uint64_t* values, POLY_ARGUMENTS, const Modulus* moduli,
            uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                size_t oid = gindex * coeff_modulus_size;
                size_t nid = gindex * coeff_modulus_size + rns_index;
                result[nid] = kernel_util::dModuloUint(values + oid, coeff_modulus_size, moduli[rns_index]);
            }
        } 

        // temp should be at least coeff_modulus_size * poly_modulus_degree large
        __global__ void gComposeArray(
            const uint64_t* value, POLY_ARGUMENTS, const Modulus* moduli,
            const uint64_t* base_prod,
            const uint64_t* punctured_prod_array,
            const MultiplyUIntModOperand* inv_punctured_prod_mod_base_array,
            uint64_t* temp, uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            uint64_t* temp_target = temp + gindex * coeff_modulus_size;
            FOR_N(rns_index, coeff_modulus_size) temp_target[rns_index] = 0;
            FOR_N(rns_index, coeff_modulus_size) {
                uint64_t temp_prod = kernel_util::dMultiplyUintMod(
                    value[rns_index * poly_modulus_degree + gindex],
                    inv_punctured_prod_mod_base_array[rns_index], moduli[rns_index]);
                kernel_util::dMultiplyUint(
                    punctured_prod_array + rns_index * coeff_modulus_size, 
                    coeff_modulus_size, temp_prod, coeff_modulus_size, temp_target);
                kernel_util::dAddUintUintMod(temp_target, 
                    result + gindex * coeff_modulus_size, 
                    base_prod, coeff_modulus_size, result + gindex * coeff_modulus_size);
            }
        }

        void RNSBaseCuda::decomposeArray(DevicePointer<uint64_t> values, size_t coeff_count) const {
            if (size_ <= 1) return;
            auto copy = copy_.ensure(size_ * coeff_count);
            KernelProvider::copyOnDevice(copy.get(), values.get(), size_ * coeff_count);
            KERNEL_CALL(gDecomposeArray, coeff_count)(
                copy.get(), size_, coeff_count, base_.get(), values.get()
            );
        }

        void RNSBaseCuda::decomposeArrayKeepOrder(DevicePointer<uint64_t> values, size_t coeff_count) const {
            if (size_ <= 1) return;
            auto copy = copy_.ensure(size_ * coeff_count);
            KernelProvider::copyOnDevice(copy.get(), values.get(), size_ * coeff_count);
            KERNEL_CALL(gDecomposeArrayKeepOrder, coeff_count)(
                copy.get(), size_, coeff_count, base_.get(), values.get()
            );
        }

        void RNSBaseCuda::composeArray(DevicePointer<uint64_t> values, size_t coeff_count) const {
            if (size_ <= 1) return;
            auto copy = copy_.ensure(size_ * coeff_count);
            auto temp = temp_.ensure(size_ * coeff_count);
            KernelProvider::copyOnDevice(copy.get(), values.get(), size_ * coeff_count);
            KernelProvider::memsetZero<uint64_t>(values.get(), size_ * coeff_count);
            KERNEL_CALL(gComposeArray, coeff_count)(
                copy.get(), size_, coeff_count,
                base_.get(), base_prod_.get(), punctured_prod_array_.get(),
                inv_punctured_prod_mod_base_array_.get(), temp.get(), values.get()
            );
        }

        __global__ void gFastConvertArrayStepA(
            const uint64_t* in,
            size_t ibase_size,
            size_t count,
            const Modulus* moduli,
            const MultiplyUIntModOperand* inv_punctured_prod_mod_base_array,
            uint64_t* out
        ) {
            GET_INDEX_COND_RETURN(count);
            FOR_N(i, ibase_size) {
                MultiplyUIntModOperand r = inv_punctured_prod_mod_base_array[i];
                if (r.operand == 1)
                    out[gindex * ibase_size + i] = kernel_util::dBarrettReduce64(in[i * count + gindex], moduli[i]);
                else
                    out[gindex * ibase_size + i] = kernel_util::dMultiplyUintMod(in[i * count + gindex], r, moduli[i]);
            }
        }

        __global__ void gFastConvertArrayStepB(
            const uint64_t* in,
            size_t ibase_size,
            size_t obase_size,
            size_t count,
            const Modulus* moduli,
            const uint64_t* base_change_matrix_,
            uint64_t* out
        ) {
            GET_INDEX_COND_RETURN(count);
            FOR_N(i, obase_size) {
                out[i * count + gindex] = kernel_util::dDotProductMod(in + gindex * ibase_size, base_change_matrix_ + i * ibase_size, ibase_size, moduli[i]);
            }
        }

        void BaseConverterCuda::fastConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const {
            
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();

            auto temp = temp_.ensure(count * ibase_size);

            KERNEL_CALL(gFastConvertArrayStepA, count)(
                in.get(), ibase_size, count, ibase_.base().get(), 
                ibase_.invPuncturedProdModBaseArray().get(), temp.get()
            );
            gFastConvertArrayStepB<<<block_count, 256>>>(
                temp.get(), ibase_size, obase_size, count,
                obase_.base().get(), base_change_matrix_.get(), out.get()
            );

        }

        __global__ void gExactConvertArray(
            const uint64_t* in,
            size_t ibase_size,
            size_t count,
            const Modulus* ibase,
            const MultiplyUIntModOperand* inv_punctured_prod_mod_base_array,
            const uint64_t* ibase_prod,
            const Modulus* obase,
            const uint64_t* base_change_matrix,
            uint64_t* temp,
            uint64_t* out
        ) {
            GET_INDEX_COND_RETURN(count);
            double aggregated = 0;
            FOR_N(i, ibase_size) {
                MultiplyUIntModOperand r = inv_punctured_prod_mod_base_array[i];
                double divisor = static_cast<double>(DeviceHelper::getModulusValue(ibase[i]));
                uint64_t temp_single;
                if (r.operand == 1) {
                    temp_single = kernel_util::dBarrettReduce64(in[i * count + gindex], ibase[i]);
                } else {
                    temp_single = kernel_util::dMultiplyUintMod(in[i * count + gindex], r, ibase[i]);
                }
                temp[gindex * ibase_size + i] = temp_single;
                aggregated += static_cast<double>(temp_single) / divisor;
            }
            aggregated += 0.5;
            uint64_t rounded = static_cast<uint64_t>(aggregated);
            const Modulus& p = obase[0];
            uint64_t q_mod_p = kernel_util::dModuloUint(ibase_prod, ibase_size, p);
            uint64_t sum_mod_obase = kernel_util::dDotProductMod(temp + gindex * ibase_size, base_change_matrix, ibase_size, p);
            auto v_q_mod_p = kernel_util::dMultiplyUintMod(rounded, q_mod_p, p);
            out[gindex] = kernel_util::dSubUintMod(sum_mod_obase, v_q_mod_p, p);
        }


        void BaseConverterCuda::exactConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const {
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();
            if (obase_size != 1)
                throw std::invalid_argument("out base in exact_convert_array must be one.");

            auto temp = temp_.ensure(count * ibase_size);
            auto aggregated_rounded_v = aggregated_rounded_v_.ensure(count);
            KERNEL_CALL(gExactConvertArray, count)(
                in.get(), ibase_size, count,
                ibase_.base().get(),
                ibase_.invPuncturedProdModBaseArray().get(),
                ibase_.baseProd().get(),
                obase_.base().get(),
                base_change_matrix_.get(),
                temp.get(),
                out.get()
            );
            // auto p = temp.toHost();
            // for (size_t i = 0; i < p.size(); i++)
            //     std::cout << "temp[" << i << "]=" << p[i] << std::endl;
        }

        __global__ void gDivideAndRoundqLastInplace(
            uint64_t* input,
            size_t coeff_count,
            size_t base_q_size,
            const Modulus* base_q,
            const MultiplyUIntModOperand* inv_q_last_mod_q,
            uint64_t half
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            auto last_input = input + (base_q_size - 1) * coeff_count;
            last_input[gindex] = kernel_util::dAddUintMod(last_input[gindex], half, base_q[base_q_size-1]);
            FOR_N(i, base_q_size - 1) {
                uint64_t temp;
                const Modulus& b = base_q[i];
                temp = kernel_util::dBarrettReduce64(last_input[gindex], b);
                uint64_t half_mod = kernel_util::dBarrettReduce64(half, b);
                temp = kernel_util::dSubUintMod(temp, half_mod, b);
                uint64_t temp_result;
                std::int64_t borrow = kernel_util::dSubUint64(input[i * coeff_count + gindex], temp, &temp_result);
                input[i * coeff_count + gindex] = temp_result + (DeviceHelper::getModulusValue(b) & static_cast<std::uint64_t>(-borrow));
                input[i * coeff_count + gindex] = kernel_util::dMultiplyUintMod(
                    input[i * coeff_count + gindex],
                    inv_q_last_mod_q[i],
                    b
                );
            }
        }

        void RNSToolCuda::divideAndRoundqLastInplace(DevicePointer<uint64_t> input) const {
            KERNEL_CALL(gDivideAndRoundqLastInplace, coeff_count_)(
                input.get(), coeff_count_, 
                base_q_->size(), base_q_->base().get(),
                inv_q_last_mod_q_.get(), q_last_half_
            );
        }

        __global__ void gDivideAndRoundqLastNttInplaceStepA(
            uint64_t* last_input,
            uint64_t* temp,
            size_t coeff_count,
            size_t base_q_size, 
            const Modulus* base_q,
            uint64_t half
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            last_input[gindex] = kernel_util::dAddUintMod(last_input[gindex], half, base_q[base_q_size-1]);
            FOR_N(i, base_q_size - 1) {
                size_t temp_id = i * coeff_count + gindex;
                const Modulus& b = base_q[i];
                if (DeviceHelper::getModulusValue(b) < DeviceHelper::getModulusValue(base_q[base_q_size-1])) 
                    temp[temp_id] = kernel_util::dBarrettReduce64(last_input[gindex], b);
                else
                    temp[temp_id] = last_input[gindex];
                uint64_t neg_half_mod = DeviceHelper::getModulusValue(b) - kernel_util::dBarrettReduce64(half, b);
                temp[temp_id] += neg_half_mod;
            }
        }

        __global__ void gDivideAndRoundqLastNttInplaceStepB(
            const uint64_t* temp,
            uint64_t* input,
            size_t coeff_count,
            size_t base_q_size,
            const Modulus* base_q,
            const MultiplyUIntModOperand* inv_q_last_mod_q
        ) { 
            GET_INDEX_COND_RETURN(coeff_count);
            FOR_N(i, base_q_size - 1) {
                size_t temp_id = i * coeff_count + gindex;
                const Modulus& b = base_q[i];
                uint64_t qi_lazy = DeviceHelper::getModulusValue(b) << 2;
                input[temp_id] += qi_lazy - temp[temp_id];
                input[temp_id] = kernel_util::dMultiplyUintMod(input[temp_id], inv_q_last_mod_q[i], b);
            }
        }


        void RNSToolCuda::divideAndRoundqLastNttInplace(
            DevicePointer<uint64_t> input, ConstDevicePointer<NTTTablesCuda> rns_ntt_tables) const
        {
            size_t base_q_size = base_q_->size();
            kernel_util::kInverseNttNegacyclicHarvey(input + coeff_count_ * (base_q_size - 1),
                1, 1, getPowerOfTwo(coeff_count_), rns_ntt_tables + (base_q_size - 1));
            auto temp = temp_.ensure(coeff_count_ * (base_q_size - 1));
            KERNEL_CALL(gDivideAndRoundqLastNttInplaceStepA, coeff_count_) (
                input.get() + coeff_count_ * (base_q_size - 1), temp.get(),
                coeff_count_, base_q_size, base_q_->base().get(), q_last_half_); 
            kernel_util::kNttNegacyclicHarveyLazy(temp.get(), 1, base_q_size - 1, getPowerOfTwo(coeff_count_), rns_ntt_tables);
            gDivideAndRoundqLastNttInplaceStepB<<<block_count, 256>>>(
                temp.get(), input.get(), coeff_count_, base_q_size,
                base_q_->base().get(), inv_q_last_mod_q_.get()
            );
        }

        __global__ void gFaskbconvSk(
            const uint64_t* input,
            const uint64_t* temp,
            size_t coeff_count,
            const Modulus* m_sk,
            size_t base_B_size,
            size_t base_q_size,
            const Modulus* base_q,
            MultiplyUIntModOperand inv_prod_B_mod_m_sk,
            const uint64_t* prod_B_mod_q,
            uint64_t* destination
            
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            uint64_t m_sk_value = DeviceHelper::getModulusValue(*m_sk);
            uint64_t alpha_sk = kernel_util::dMultiplyUintMod(temp[gindex] + (m_sk_value - input[base_B_size * coeff_count + gindex]), inv_prod_B_mod_m_sk, *m_sk);
            // printf("%llu\n", alpha_sk);
            uint64_t m_sk_div_2 = m_sk_value >> 1;
            FOR_N(i, base_q_size) {
                const Modulus& b = base_q[i];
                uint64_t b_value = DeviceHelper::getModulusValue(b);
                MultiplyUIntModOperand prod_B_mod_q_elt
                    = kernel_util::dSetMultiplyModOperand(prod_B_mod_q[i], b);
                MultiplyUIntModOperand neg_prod_B_mod_q_elt
                    = kernel_util::dSetMultiplyModOperand(b_value - prod_B_mod_q[i], b);
                uint64_t& dest = destination[i * coeff_count + gindex];
                // printf("i=%ld, gindex=%ld, %ld %llu, %llu\n", i, gindex, i * coeff_count + gindex, prod_B_mod_q_elt.operand, prod_B_mod_q_elt.quotient);
                // printf("i=%ld, xgindex=%ld, %ld %llu, %llu\n", i, gindex, i * coeff_count + gindex, neg_prod_B_mod_q_elt.operand, neg_prod_B_mod_q_elt.quotient);
                if (alpha_sk > m_sk_div_2)
                    dest = kernel_util::dMultiplyAddUintMod(
                        kernel_util::dNegateUintMod(alpha_sk, *m_sk), prod_B_mod_q_elt, dest, b);
                else
                    dest = kernel_util::dMultiplyAddUintMod(
                        alpha_sk, neg_prod_B_mod_q_elt, dest, b);
            }

        }

        
        void RNSToolCuda::fastbconvSk(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const {

            size_t base_q_size = base_q_->size();
            size_t base_B_size = base_B_->size();
            base_B_to_q_conv_->fastConvertArray(input, destination, coeff_count_);

            auto temp = temp_.ensure(coeff_count_);
            base_B_to_m_sk_conv_->fastConvertArray(input, temp.get(), coeff_count_);

            KERNEL_CALL(gFaskbconvSk, coeff_count_)(
                input.get(),
                temp.get(), coeff_count_, m_sk_cuda_.get(),
                base_B_size, base_q_size, base_q_->base().get(),
                inv_prod_B_mod_m_sk_, prod_B_mod_q_.get(),
                destination.get()
            );

        }

        __global__ void gSmMrq(
            const uint64_t* input,
            size_t coeff_count,
            size_t base_Bsk_size,
            const Modulus* base_Bsk,
            const uint64_t m_tilde_div_2,
            const Modulus* m_tilde,
            MultiplyUIntModOperand neg_inv_prod_q_mod_m_tilde,
            const uint64_t* prod_q_mod_Bsk,
            const MultiplyUIntModOperand* inv_m_tilde_mod_Bsk,
            uint64_t* destination
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            const uint64_t* input_m_tilde = input + base_Bsk_size * coeff_count;
            uint64_t r_m_tilde = kernel_util::dMultiplyUintMod(input_m_tilde[gindex], neg_inv_prod_q_mod_m_tilde, *m_tilde);
            FOR_N(i, base_Bsk_size) {
                const Modulus& b = base_Bsk[i];
                MultiplyUIntModOperand prod_q_mod_Bsk_elt
                    = kernel_util::dSetMultiplyModOperand(prod_q_mod_Bsk[i], b);
                uint64_t temp = r_m_tilde;
                if (temp >= m_tilde_div_2)
                    temp += DeviceHelper::getModulusValue(b) - DeviceHelper::getModulusValue(*m_tilde);
                destination[i * coeff_count + gindex] = kernel_util::dMultiplyUintMod(
                    kernel_util::dMultiplyAddUintMod(temp, prod_q_mod_Bsk_elt, input[i * coeff_count + gindex], b),
                    inv_m_tilde_mod_Bsk[i], b
                );
            }
        }

        void RNSToolCuda::smMrq(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const {
            
            size_t base_Bsk_size = base_Bsk_->size();
            uint64_t m_tilde_div_2 = m_tilde_.value() >> 1;
            KERNEL_CALL(gSmMrq, coeff_count_)(
                input.get(), coeff_count_, base_Bsk_size,
                base_Bsk_->base().get(), m_tilde_div_2,
                m_tilde_cuda_.get(), neg_inv_prod_q_mod_m_tilde_,
                prod_q_mod_Bsk_.get(), inv_m_tilde_mod_Bsk_.get(),
                destination.get()
            );

        }

        __global__ void gFastFloor(
            const uint64_t* input,
            size_t coeff_count,
            size_t base_Bsk_size, 
            const Modulus* base_Bsk,
            const MultiplyUIntModOperand* inv_prod_q_mod_Bsk,
            uint64_t* destination
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            FOR_N(i, base_Bsk_size) {
                size_t id = i * coeff_count + gindex;
                destination[id] = kernel_util::dMultiplyUintMod(
                    input[id] + (DeviceHelper::getModulusValue(base_Bsk[i]) - destination[id]),
                    inv_prod_q_mod_Bsk[i], base_Bsk[i]
                );
            }
        }

        void RNSToolCuda::fastFloor(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const {
            
            size_t base_q_size = base_q_->size();
            size_t base_Bsk_size = base_Bsk_->size();
            
            base_q_to_Bsk_conv_->fastConvertArray(input, destination, coeff_count_);

            input = input + base_q_size * coeff_count_;

            KERNEL_CALL(gFastFloor, coeff_count_)(
                input.get(), coeff_count_, base_Bsk_size, base_Bsk_->base().get(),
                inv_prod_q_mod_Bsk_.get(), destination.get()
            );

        }
        
        void RNSToolCuda::fastbconvmTilde(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const {
            size_t base_q_size = base_q_->size();
            size_t base_Bsk_size = base_Bsk_->size();
            auto temp = temp_.ensure(coeff_count_ * base_q_size);
            kernel_util::kMultiplyPolyScalarCoeffmod(input, 1, base_q_size, 
                coeff_count_, m_tilde_.value(), base_q_->base(), temp.get());
            base_q_to_Bsk_conv_->fastConvertArray(temp.get(), destination, coeff_count_);
            base_q_to_m_tilde_conv_->fastConvertArray(temp.get(), destination + base_Bsk_size * coeff_count_, coeff_count_);
        }

        __global__ void gDecryptScaleAndRoundStepA(
            const uint64_t* input,
            size_t base_q_size,
            const Modulus* base_q,
            size_t coeff_count,
            const MultiplyUIntModOperand* prod_t_gamma_mod_q,
            uint64_t* temp
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            FOR_N(i, base_q_size) {
                size_t id = i * coeff_count + gindex;
                temp[id] = kernel_util::dMultiplyUintMod(input[id], prod_t_gamma_mod_q[i], base_q[i]);
            }
        }

        __global__ void gDecryptScaleAndRoundStepB(
            const uint64_t* temp_t_gamma,
            size_t coeff_count,
            uint64_t gamma,
            const Modulus* t,
            MultiplyUIntModOperand inv_gamma_mod_t,
            uint64_t* destination
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            uint64_t gamma_div_2 = gamma>>1;
            if (temp_t_gamma[coeff_count + gindex] > gamma_div_2) 
                destination[gindex] = kernel_util::dAddUintMod(
                    temp_t_gamma[gindex], 
                    kernel_util::dBarrettReduce64(
                        gamma - temp_t_gamma[coeff_count + gindex], *t), *t);
            else
                destination[gindex] = kernel_util::dSubUintMod(
                    temp_t_gamma[gindex], 
                    kernel_util::dBarrettReduce64(
                        temp_t_gamma[coeff_count + gindex], *t), *t);
            if (0 != destination[gindex])
                destination[gindex] = kernel_util::dMultiplyUintMod(
                    destination[gindex], inv_gamma_mod_t, *t);
        }


        void RNSToolCuda::decryptScaleAndRound(ConstDevicePointer<uint64_t> input, DevicePointer<uint64_t> destination) const
        {
            size_t base_q_size = base_q_->size();
            size_t base_t_gamma_size = base_t_gamma_->size();

            auto temp = temp_.ensure(coeff_count_ * base_q_size);
            
            KERNEL_CALL(gDecryptScaleAndRoundStepA, coeff_count_)(
                input.get(), base_q_size, base_q_->base().get(),
                coeff_count_, prod_t_gamma_mod_q_.get(), temp.get()
            );

            auto temp_t_gamma = temp_t_gamma_.ensure(coeff_count_ * base_t_gamma_size);

            // Convert from q to {t, gamma}
            base_q_to_t_gamma_conv_->fastConvertArray(temp.get(), temp_t_gamma.get(), coeff_count_);

            gDecryptScaleAndRoundStepA<<<block_count, 256>>>(
                temp_t_gamma.get(), base_t_gamma_size, base_t_gamma_->base().get(),
                coeff_count_, neg_inv_q_mod_t_gamma_.get(), temp_t_gamma.get()
            );

            gDecryptScaleAndRoundStepB<<<block_count, 256>>>(
                temp_t_gamma.get(), coeff_count_, gamma_.value(),
                t_cuda_.get(), inv_gamma_mod_t_, destination.get()
            );
        }

        __global__ void gModTAndDivideqLastInplace(
            uint64_t* input,
            size_t coeff_count,
            size_t modulus_size,
            const Modulus* base_q,
            const Modulus* plain_modulus,
            uint64_t inv_q_last_mod_t,
            const MultiplyUIntModOperand* inv_q_last_mod_q
        ) {
            GET_INDEX_COND_RETURN(coeff_count);
            uint64_t* last_input = input + (modulus_size - 1) * coeff_count;
            uint64_t last_modulus_value = DeviceHelper::getModulusValue(base_q[modulus_size - 1]);
            uint64_t neg_c_last_mod_t = kernel_util::dBarrettReduce64(last_input[gindex], *plain_modulus);
            neg_c_last_mod_t = kernel_util::dNegateUintMod(neg_c_last_mod_t, *plain_modulus);
            if (inv_q_last_mod_t != 1) {
                neg_c_last_mod_t = kernel_util::dMultiplyScalarMod(neg_c_last_mod_t, inv_q_last_mod_t, *plain_modulus);
            }
            uint64_t delta_mod_q_i = 0;
            FOR_N(i, modulus_size - 1) {
                delta_mod_q_i = kernel_util::dBarrettReduce64(neg_c_last_mod_t, base_q[i]);
                delta_mod_q_i = kernel_util::dMultiplyScalarMod(delta_mod_q_i, last_modulus_value, base_q[i]);
                const uint64_t two_times_q_i = DeviceHelper::getModulusValue(base_q[i]) << 1;
                input[i * coeff_count + gindex] += two_times_q_i - kernel_util::dBarrettReduce64(last_input[gindex], base_q[i]) - delta_mod_q_i;
                input[i * coeff_count + gindex] = kernel_util::dMultiplyUintMod(input[i * coeff_count + gindex], inv_q_last_mod_q[i], base_q[i]);
            }
        }

        void RNSToolCuda::modTAndDivideqLastInplace(DevicePointer<uint64_t> input) const {
            
            size_t modulus_size = base_q_->size();

            KERNEL_CALL(gModTAndDivideqLastInplace, coeff_count_)(
                input.get(), coeff_count_, modulus_size, base_q_->base().get(),
                t_cuda_.get(), inv_q_last_mod_t_, inv_q_last_mod_q_.get()
            );
        }
        

        void RNSToolCuda::decryptModt(ConstDevicePointer<uint64_t> phase, DevicePointer<uint64_t> destination) const
        {
            // Use exact base convension rather than convert the base through the compose API
            base_q_to_t_conv_->exactConvertArray(phase, destination, coeff_count_);
        }

    }

}