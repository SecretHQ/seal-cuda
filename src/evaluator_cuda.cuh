#pragma once

#include "context_cuda.cuh"
#include "plaintext_cuda.cuh"
#include "ciphertext_cuda.cuh"
#include "kernelutils.cuh"
#include "relinkeys_cuda.cuh"
#include "galoiskeys_cuda.cuh"
#include <stdexcept>

namespace troy {

    class EvaluatorCuda {

    public:

        EvaluatorCuda(const SEALContextCuda& context): context_(context)
        {
            auto& parms = context_.firstContextData()->parms();
            temp_ = util::DeviceDynamicArray<uint64_t>(parms.coeffModulus().size() * parms.polyModulusDegree());
        }

        void negateInplace(CiphertextCuda& encrypted) const;

        inline void negate(const CiphertextCuda &encrypted, CiphertextCuda &destination) const
        {
            destination = encrypted;
            negateInplace(destination);
        }
        void addInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        
        inline void add(const CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2, CiphertextCuda &destination) const
        {
            if (&encrypted2 == &destination)
            {
                addInplace(destination, encrypted1);
            }
            else
            {
                destination = encrypted1;
                addInplace(destination, encrypted2);
            }
        }
        
        void addMany(const std::vector<CiphertextCuda> &encrypteds, CiphertextCuda &destination) const {
            if (encrypteds.empty())
            {
                throw std::invalid_argument("encrypteds cannot be empty");
            }
            for (size_t i = 0; i < encrypteds.size(); i++)
            {
                if (&encrypteds[i] == &destination)
                {
                    throw std::invalid_argument("encrypteds must be different from destination");
                }
            }

            destination = encrypteds[0];
            for (size_t i = 1; i < encrypteds.size(); i++)
            {
                addInplace(destination, encrypteds[i]);
            }
        }

        void subInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        
        
        inline void sub(const CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2, CiphertextCuda &destination) const
        {
            if (&encrypted2 == &destination)
            {
                subInplace(destination, encrypted1);
                negateInplace(destination);
            }
            else
            {
                destination = encrypted1;
                subInplace(destination, encrypted2);
            }
        }

        void multiplyInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        
        
        inline void multiply(
            const CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2, CiphertextCuda &destination) const
        {
            if (&encrypted2 == &destination)
            {
                multiplyInplace(destination, encrypted1);
            }
            else
            {
                destination = encrypted1;
                multiplyInplace(destination, encrypted2);
            }
        }

        void squareInplace(CiphertextCuda& encrypted) const;

        inline void relinearizeInplace(
            CiphertextCuda &encrypted, const RelinKeysCuda &relin_keys) const
        {
            relinearizeInternal(encrypted, relin_keys, 2);
        }

        
        inline void square(
            const CiphertextCuda &encrypted, CiphertextCuda &destination) const
        {
            destination = encrypted;
            squareInplace(destination);
        }

        
        inline void relinearize(
            const CiphertextCuda &encrypted, const RelinKeysCuda &relin_keys, CiphertextCuda &destination) const
        {
            destination = encrypted;
            relinearizeInplace(destination, relin_keys);
        }



        void modSwitchToNext(
            const CiphertextCuda &encrypted, CiphertextCuda &destination) const;


        inline void modSwitchToNextInplace(
            CiphertextCuda &encrypted) const
        {
            modSwitchToNext(encrypted, encrypted);
        }

        inline void modSwitchToNextInplace(PlaintextCuda &plain) const
        {
            modSwitchDropToNext(plain);
        }


        inline void modSwitchToNext(const PlaintextCuda &plain, PlaintextCuda &destination) const
        {
            destination = plain;
            modSwitchToNextInplace(destination);
        }


        void modSwitchToInplace(
            CiphertextCuda &encrypted, ParmsID parms_id) const;


        inline void modSwitchTo(
            const CiphertextCuda &encrypted, ParmsID parms_id, CiphertextCuda &destination) const
        {
            destination = encrypted;
            modSwitchToInplace(destination, parms_id);
        }


        void modSwitchToInplace(PlaintextCuda &plain, ParmsID parms_id) const;


        inline void modSwitchTo(const PlaintextCuda &plain, ParmsID parms_id, PlaintextCuda &destination) const
        {
            destination = plain;
            modSwitchToInplace(destination, parms_id);
        }
        
        void rescaleToNext(
            const CiphertextCuda &encrypted, CiphertextCuda &destination) const;

        
        inline void rescaleToNextInplace(
            CiphertextCuda &encrypted) const
        {
            rescaleToNext(encrypted, encrypted);
        }
        
        void rescaleToInplace(
            CiphertextCuda &encrypted, ParmsID parms_id) const;


        inline void rescaleTo(
            const CiphertextCuda &encrypted, ParmsID parms_id, CiphertextCuda &destination) const
        {
            destination = encrypted;
            rescaleToInplace(destination, parms_id);
        }

        void multiplyMany(
            const std::vector<CiphertextCuda> &encrypteds, const RelinKeysCuda &relin_keys, CiphertextCuda &destination) const;

        void exponentiateInplace(
            CiphertextCuda &encrypted, std::uint64_t exponent, const RelinKeysCuda &relin_keys) const;

        inline void exponentiate(
            const CiphertextCuda &encrypted, std::uint64_t exponent, const RelinKeysCuda &relin_keys, CiphertextCuda &destination) const
        {
            destination = encrypted;
            exponentiateInplace(destination, exponent, relin_keys);
        }


        void addPlainInplace(CiphertextCuda &encrypted, const PlaintextCuda &plain) const;

        inline void addPlain(const CiphertextCuda &encrypted, const PlaintextCuda &plain, CiphertextCuda &destination) const
        {
            destination = encrypted;
            addPlainInplace(destination, plain);
        }


        void subPlainInplace(CiphertextCuda &encrypted, const PlaintextCuda &plain) const;

        inline void subPlain(const CiphertextCuda &encrypted, const PlaintextCuda &plain, CiphertextCuda &destination) const
        {
            destination = encrypted;
            subPlainInplace(destination, plain);
        }

        
        void multiplyPlainInplace(
            CiphertextCuda &encrypted, const PlaintextCuda &plain) const;

        inline void multiplyPlain(
            const CiphertextCuda &encrypted, const PlaintextCuda &plain, CiphertextCuda &destination) const
        {
            destination = encrypted;
            multiplyPlainInplace(destination, plain);
        }
        
        void transformToNttInplace(
            PlaintextCuda &plain, ParmsID parms_id) const;
        
    
        inline void transformToNtt(
            const PlaintextCuda &plain, ParmsID parms_id, PlaintextCuda &destination_ntt) const
        {
            destination_ntt = plain;
            transformToNttInplace(destination_ntt, parms_id);
        }
        
        void transformToNttInplace(CiphertextCuda &encrypted) const;
        
        inline void transformToNtt(const CiphertextCuda &encrypted, CiphertextCuda &destination_ntt) const
        {
            destination_ntt = encrypted;
            transformToNttInplace(destination_ntt);
        }
        
        void transformFromNttInplace(CiphertextCuda &encrypted_ntt) const;
        
        inline void transformFromNtt(const CiphertextCuda &encrypted_ntt, CiphertextCuda &destination) const
        {
            destination = encrypted_ntt;
            transformFromNttInplace(destination);
        }


        void applyGaloisInplace(
            CiphertextCuda &encrypted, std::uint32_t galois_elt, const GaloisKeysCuda &galois_keys) const;

        inline void applyGalois(
            const CiphertextCuda &encrypted, std::uint32_t galois_elt, const GaloisKeysCuda &galois_keys,
            CiphertextCuda &destination) const
        {
            destination = encrypted;
            applyGaloisInplace(destination, galois_elt, galois_keys);
        }

        inline void rotateRowsInplace(
            CiphertextCuda &encrypted, int steps, const GaloisKeysCuda &galois_keys) const
        {
            auto scheme = context_.keyContextData()->parms().scheme();
            if (scheme != SchemeType::bfv && scheme != SchemeType::bgv)
            {
                throw std::logic_error("unsupported scheme");
            }
            rotateInternal(encrypted, steps, galois_keys);
        }

        inline void rotateRows(
            const CiphertextCuda &encrypted, int steps, const GaloisKeysCuda &galois_keys, CiphertextCuda &destination) const
        {
            destination = encrypted;
            rotateRowsInplace(destination, steps, galois_keys);
        }

        inline void rotateColumnsInplace(
            CiphertextCuda &encrypted, const GaloisKeysCuda &galois_keys) const
        {
            auto scheme = context_.keyContextData()->parms().scheme();
            if (scheme != SchemeType::bfv && scheme != SchemeType::bgv)
            {
                throw std::logic_error("unsupported scheme");
            }
            conjugateInternal(encrypted, galois_keys);
        }

        inline void rotateColumns(
            const CiphertextCuda &encrypted, const GaloisKeysCuda &galois_keys, CiphertextCuda &destination) const
        {
            destination = encrypted;
            rotateColumnsInplace(destination, galois_keys);
        }

        inline void rotateVectorInplace(
            CiphertextCuda &encrypted, int steps, const GaloisKeysCuda &galois_keys) const
        {
            if (context_.keyContextData()->parms().scheme() != SchemeType::ckks)
            {
                throw std::logic_error("unsupported scheme");
            }
            rotateInternal(encrypted, steps, galois_keys);
        }

        inline void rotateVector(
            const CiphertextCuda &encrypted, int steps, const GaloisKeysCuda &galois_keys, CiphertextCuda &destination) const
        {
            destination = encrypted;
            rotateVectorInplace(destination, steps, galois_keys);
        }

        inline void complexConjugateInplace(
            CiphertextCuda &encrypted, const GaloisKeysCuda &galois_keys) const
        {
            if (context_.keyContextData()->parms().scheme() != SchemeType::ckks)
            {
                throw std::logic_error("unsupported scheme");
            }
            conjugateInternal(encrypted, galois_keys);
        }

        inline void complexConjugate(
            const CiphertextCuda &encrypted, const GaloisKeysCuda &galois_keys, CiphertextCuda &destination) const
        {
            destination = encrypted;
            complexConjugateInplace(destination, galois_keys);
        }

    private:

        void bfvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void ckksMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void bgvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void bfvSquare(CiphertextCuda &encrypted) const;
        void ckksSquare(CiphertextCuda& encrypted) const;
        void bgvSquare(CiphertextCuda& encrypted) const;

        
        void relinearizeInternal(CiphertextCuda &encrypted, const RelinKeysCuda &relin_keys, std::size_t destination_size) const;

        void switchKeyInplace(
            CiphertextCuda &encrypted, util::ConstDevicePointer<uint64_t> target_iter, const KSwitchKeysCuda &kswitch_keys,
            std::size_t key_index) const;


        EvaluatorCuda(const EvaluatorCuda&) = delete;
        EvaluatorCuda(EvaluatorCuda&&) = delete;

        EvaluatorCuda& operator=(const EvaluatorCuda&) = delete;
        EvaluatorCuda& operator=(EvaluatorCuda&&) = delete;

        void modSwitchScaleToNext(
            const CiphertextCuda &encrypted, CiphertextCuda &destination) const;

        void modSwitchDropToNext(const CiphertextCuda &encrypted, CiphertextCuda &destination) const;
        void modSwitchDropToNext(PlaintextCuda &plain) const;

        void multiplyPlainNormal(CiphertextCuda &encrypted, const PlaintextCuda &plain) const;
        void multiplyPlainNtt(CiphertextCuda &encrypted_ntt, const PlaintextCuda &plain_ntt) const;

        
        void rotateInternal(
            CiphertextCuda &encrypted, int steps, const GaloisKeysCuda &galois_keys) const;

        inline void conjugateInternal(
            CiphertextCuda &encrypted, const GaloisKeysCuda &galois_keys) const
        {
            // Verify parameters.
            auto context_data_ptr = context_.getContextData(encrypted.parmsID());
            if (!context_data_ptr)
            {
                throw std::invalid_argument("encrypted is not valid for encryption parameters");
            }

            // Extract encryption parameters.
            auto &context_data = *context_data_ptr;
            if (!context_data.qualifiers().using_batching)
            {
                throw std::logic_error("encryption parameters do not support batching");
            }

            auto galoisTool = context_data.galoisTool();

            // Perform rotation and key switching
            applyGaloisInplace(encrypted, galoisTool->getEltFromStep(0), galois_keys);
        }

        SEALContextCuda context_;

        mutable util::DeviceDynamicArray<uint64_t> temp_;
        mutable util::DeviceDynamicArray<uint64_t> switch_key_t_target_;
        mutable util::DeviceDynamicArray<uint64_t> switch_key_t_poly_prod_;
        mutable util::DeviceDynamicArray<uint64_t> switch_key_t_ntt_;
        mutable util::DeviceDynamicArray<uint64_t> switch_key_t_poly_lazy_;
        mutable util::DeviceDynamicArray<uint64_t> encrypted1_q_;
        mutable util::DeviceDynamicArray<uint64_t> encrypted1_Bsk_;
        mutable util::DeviceDynamicArray<uint64_t> encrypted2_q_;
        mutable util::DeviceDynamicArray<uint64_t> encrypted2_Bsk_;
        mutable util::DeviceDynamicArray<uint64_t> temp_dest_q_;
        mutable util::DeviceDynamicArray<uint64_t> temp_dest_Bsk_;
        mutable util::DeviceDynamicArray<uint64_t> temp_q_Bsk_;
        mutable util::DeviceDynamicArray<uint64_t> temp_Bsk_;
        mutable CiphertextCuda temp_ciphertext_;

    };

}