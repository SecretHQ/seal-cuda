#pragma once

#include "batchencoder_cuda.cuh"
#include "ciphertext_cuda.cuh"
#include "ckks_cuda.cuh"
#include "context_cuda.cuh"
#include "decryptor_cuda.cuh"
#include "encryptionparams_cuda.cuh"
#include "encryptor_cuda.cuh"
#include "evaluator_cuda.cuh"
#include "galoiskeys_cuda.cuh"
#include "keygenerator_cuda.cuh"
#include "kswitchkeys_cuda.cuh"
#include "plaintext_cuda.cuh"
#include "publickey_cuda.cuh"
#include "relinkeys_cuda.cuh"
#include "secretkey_cuda.cuh"
#include "utils/rns_cuda.cuh"

namespace troyn {
    using troy::ParmsID;
    using troy::SchemeType;
    using troy::SecurityLevel;
    using troy::Modulus;
    using troy::CoeffModulus;
    using troy::PlainModulus;
    using EncryptionParameters = troy::EncryptionParametersCuda;
    using SEALContext = troy::SEALContextCuda;
    using Plaintext = troy::PlaintextCuda;
    using Ciphertext = troy::CiphertextCuda;
    using Encryptor = troy::EncryptorCuda;
    using Decryptor = troy::DecryptorCuda;
    using Evaluator = troy::EvaluatorCuda;
    using KeyGenerator = troy::KeyGeneratorCuda;
    using PublicKey = troy::PublicKeyCuda;
    using SecretKey = troy::SecretKeyCuda;
    using KSwitchKeys = troy::KSwitchKeysCuda;
    using RelinKeys = troy::RelinKeysCuda;
    using GaloisKeys = troy::GaloisKeysCuda;
    using CKKSEncoder = troy::CKKSEncoderCuda;
    using BatchEncoder = troy::BatchEncoderCuda;
    using KernelProvider = troy::KernelProvider;
}