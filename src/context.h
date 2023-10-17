#pragma once

#include "utils/rns.h"
#include "utils/galois.h"
#include "modulus.h"
#include "encryptionparams.h"
#include <memory>
#include <unordered_map>

namespace troy {

    /**
    Stores a set of attributes (qualifiers) of a set of encryption parameters.
    These parameters are mainly used internally in various parts of the library,
    e.g., to determine which algorithmic optimizations the current support. The
    qualifiers are automatically created by the SEALContext class, silently passed
    on to classes such as Encryptor, Evaluator, and Decryptor, and the only way to
    change them is by changing the encryption parameters themselves. In other
    words, a user will never have to create their own instance of this class, and
    in most cases never have to worry about it at all.
    */
    class EncryptionParameterQualifiers
    {
    public:
        /**
        Identifies the reason why encryption parameters are not valid.
        */
        enum class ErrorType : int
        {
            /**
            constructed but not yet validated
            */
            none = -1,

            /**
            valid
            */
            success = 0,

            /**
            scheme must be BFV or CKKS or BGV
            */
            invalid_scheme = 1,

            /**
            coeff_modulus's primes' count is not bounded by SEAL_COEFF_MOD_COUNT_MIN(MAX)
            */
            invalid_coeff_modulus_size = 2,

            /**
            coeff_modulus's primes' bit counts are not bounded by SEAL_USER_MOD_BIT_COUNT_MIN(MAX)
            */
            invalid_coeff_modulus_bit_count = 3,

            /**
            coeff_modulus's primes are not congruent to 1 modulo (2 * poly_modulus_degree)
            */
            invalid_coeff_modulus_no_ntt = 4,

            /**
            poly_modulus_degree is not bounded by SEAL_POLY_MOD_DEGREE_MIN(MAX)
            */
            invalid_poly_modulus_degree = 5,

            /**
            poly_modulus_degree is not a power of two
            */
            invalid_poly_modulus_degree_non_power_of_two = 6,

            /**
            parameters are too large to fit in size_t type
            */
            invalid_parameters_too_large = 7,

            /**
            parameters are not compliant with HomomorphicEncryption.org security standard
            */
            invalid_parameters_insecure = 8,

            /**
            RNSBase cannot be constructed
            */
            failed_creating_rns_base = 9,

            /**
            plain_modulus's bit count is not bounded by SEAL_PLAIN_MOD_BIT_COUNT_MIN(MAX)
            */
            invalid_plain_modulus_bit_count = 10,

            /**
            plain_modulus is not coprime to coeff_modulus
            */
            invalid_plain_modulus_coprimality = 11,

            /**
            plain_modulus is not smaller than coeff_modulus
            */
            invalid_plain_modulus_too_large = 12,

            /**
            plain_modulus is not zero
            */
            invalid_plain_modulus_nonzero = 13,

            /**
            RNSTool cannot be constructed
            */
            failed_creating_rns_tool = 14,
        };

        /**
        The variable parameter_error is set to:
        - none, if parameters are not validated;
        - success, if parameters are considered valid by Microsoft SEAL;
        - other values, if parameters are validated and invalid.
        */
        ErrorType parameter_error;

        /**
        Returns the name of parameter_error.
        */
        const char *parameterErrorName() const noexcept;

        /**
        Returns a comprehensive message that interprets parameter_error.
        */
        const char *parameterErrorMessage() const noexcept;

        /**
        Tells whether parameter_error is ErrorType::success.
        */
        inline bool parametersSet() const noexcept
        {
            return parameter_error == ErrorType::success;
        }

        /**
        Tells whether FFT can be used for polynomial multiplication. If the
        polynomial modulus is of the form X^N+1, where N is a power of two, then
        FFT can be used for fast multiplication of polynomials modulo the polynomial
        modulus. In this case the variable using_fft will be set to true. However,
        currently Microsoft SEAL requires this to be the case for the parameters
        to be valid. Therefore, parameters_set can only be true if using_fft is
        true.
        */
        bool using_fft;

        /**
        Tells whether NTT can be used for polynomial multiplication. If the primes
        in the coefficient modulus are congruent to 1 modulo 2N, where X^N+1 is the
        polynomial modulus and N is a power of two, then the number-theoretic
        transform (NTT) can be used for fast multiplications of polynomials modulo
        the polynomial modulus and coefficient modulus. In this case the variable
        using_ntt will be set to true. However, currently Microsoft SEAL requires
        this to be the case for the parameters to be valid. Therefore, parameters_set
        can only be true if using_ntt is true.
        */
        bool using_ntt;

        /**
        Tells whether batching is supported by the encryption parameters. If the
        plaintext modulus is congruent to 1 modulo 2N, where X^N+1 is the polynomial
        modulus and N is a power of two, then it is possible to use the BatchEncoder
        class to view plaintext elements as 2-by-(N/2) matrices of integers modulo
        the plaintext modulus. This is called batching, and allows the user to
        operate on the matrix elements (slots) in a SIMD fashion, and rotate the
        matrix rows and columns. When the computation is easily vectorizable, using
        batching can yield a huge performance boost. If the encryption parameters
        support batching, the variable using_batching is set to true.
        */
        bool using_batching;

        /**
        Tells whether fast plain lift is supported by the encryption parameters.
        A certain performance optimization in multiplication of a ciphertext by
        a plaintext (Evaluator::multiply_plain) and in transforming a plaintext
        element to NTT domain (Evaluator::transform_to_ntt) can be used when the
        plaintext modulus is smaller than each prime in the coefficient modulus.
        In this case the variable using_fast_plain_lift is set to true.
        */
        bool using_fast_plain_lift;

        /**
        Tells whether the coefficient modulus consists of a set of primes that
        are in decreasing order. If this is true, certain modular reductions in
        base conversion can be omitted, improving performance.
        */
        bool using_descending_modulus_chain;

        /**
        Tells whether the encryption parameters are secure based on the standard
        parameters from HomomorphicEncryption.org security standard.
        */
        SecurityLevel sec_level;

    private:
        EncryptionParameterQualifiers()
            : parameter_error(ErrorType::none), using_fft(false), using_ntt(false), using_batching(false),
              using_fast_plain_lift(false), using_descending_modulus_chain(false), sec_level(SecurityLevel::none)
        {}

        friend class SEALContext;
    };

    /**
    Performs sanity checks (validation) and pre-computations for a given set of encryption
    parameters. While the EncryptionParameters class is intended to be a light-weight class
    to store the encryption parameters, the SEALContext class is a heavy-weight class that
    is constructed from a given set of encryption parameters. It validates the parameters
    for correctness, evaluates their properties, and performs and stores the results of
    several costly pre-computations.

    After the user has set at least the poly_modulus, coeff_modulus, and plain_modulus
    parameters in a given EncryptionParameters instance, the parameters can be validated
    for correctness and functionality by constructing an instance of SEALContext. The
    constructor of SEALContext does all of its work automatically, and concludes by
    constructing and storing an instance of the EncryptionParameterQualifiers class, with
    its flags set according to the properties of the given parameters. If the created
    instance of EncryptionParameterQualifiers has the parameters_set flag set to true, the
    given parameter set has been deemed valid and is ready to be used. If the parameters
    were for some reason not appropriately set, the parameters_set flag will be false,
    and a new SEALContext will have to be created after the parameters are corrected.

    By default, SEALContext creates a chain of SEALContext::ContextData instances. The
    first one in the chain corresponds to special encryption parameters that are reserved
    to be used by the various key classes (SecretKey, PublicKey, etc.). These are the exact
    same encryption parameters that are created by the user and passed to th constructor of
    SEALContext. The functions key_context_data() and keyParmsID() return the ContextData
    and the parms_id corresponding to these special parameters. The rest of the ContextData
    instances in the chain correspond to encryption parameters that are derived from the
    first encryption parameters by always removing the last one of the moduli in the
    coeff_modulus, until the resulting parameters are no longer valid, e.g., there are no
    more primes left. These derived encryption parameters are used by ciphertexts and
    plaintexts and their respective ContextData can be accessed through the
    get_context_data(ParmsID) function. The functions first_context_data() and
    last_context_data() return the ContextData corresponding to the first and the last
    set of parameters in the "data" part of the chain, i.e., the second and the last element
    in the full chain. The chain itself is a doubly linked list, and is referred to as the
    modulus switching chain.

    @see EncryptionParameters for more details on the parameters.
    @see EncryptionParameterQualifiers for more details on the qualifiers.
    */
    class SEALContext
    {

        friend class SEALContextCuda;

    public:
        /**
        Class to hold pre-computation data for a given set of encryption parameters.
        */
        class ContextData
        {
            friend class SEALContext;
            friend class SEALContextCuda;
            friend class ContextDataCuda;

        public:
            ContextData() = delete;

            ContextData(const ContextData &copy) = delete;

            ContextData(ContextData &&move) = default;

            ContextData &operator=(ContextData &&move) = default;

            /**
            Returns a const reference to the underlying encryption parameters.
            */
            inline const EncryptionParameters &parms() const noexcept
            {
                return parms_;
            }

            /**
            Returns the parms_id of the current parameters.
            */
            inline const ParmsID &parmsID() const noexcept
            {
                return parms_.parmsID();
            }

            /**
            Returns a copy of EncryptionParameterQualifiers corresponding to the
            current encryption parameters. Note that to change the qualifiers it is
            necessary to create a new instance of SEALContext once appropriate changes
            to the encryption parameters have been made.
            */
            inline EncryptionParameterQualifiers qualifiers() const noexcept
            {
                return qualifiers_;
            }

            /**
            Returns a pointer to a pre-computed product of all primes in the coefficient
            modulus. The security of the encryption parameters largely depends on the
            bit-length of this product, and on the degree of the polynomial modulus.
            */
            inline const std::uint64_t *totalCoeffModulus() const noexcept
            {
                return total_coeff_modulus_.get();
            }

            /**
            Returns the significant bit count of the total coefficient modulus.
            */
            inline int totalCoeffModulusBitCount() const noexcept
            {
                return total_coeff_modulus_bit_count_;
            }

            /**
            Returns a constant pointer to the RNSTool.
            */
            inline const util::RNSTool *rnsTool() const noexcept
            {
                return rns_tool_.get();
            }

            /**
            Returns a constant pointer to the NTT tables.
            */
            inline const util::NTTTables *smallNTTTables() const noexcept
            {
                // std::cout << "get small ntt tables: size = " << small_ntt_tables_.size() << std::endl;
                return small_ntt_tables_.get();
            }

            /**
            Returns a constant pointer to the NTT tables.
            */
            inline const util::NTTTables *plainNTTTables() const noexcept
            {
                return plain_ntt_tables_.get();
            }

            /**
            Returns a constant pointer to the GaloisTool.
            */
            inline const util::GaloisTool *galoisTool() const noexcept
            {
                return galois_tool_.get();
            }

            /**
            Return a pointer to BFV "Delta", i.e. coefficient modulus divided by
            plaintext modulus.
            */
            inline const util::MultiplyUIntModOperand *coeffDivPlainModulus() const noexcept
            {
                return coeff_div_plain_modulus_.get();
            }

            /**
            Return the threshold for the upper half of integers modulo plain_modulus.
            This is simply (plain_modulus + 1) / 2.
            */
            inline std::uint64_t plainUpperHalfThreshold() const noexcept
            {
                return plain_upper_half_threshold_;
            }

            /**
            Return a pointer to the plaintext upper half increment, i.e. coeff_modulus
            minus plain_modulus. The upper half increment is represented as an integer
            for the full product coeff_modulus if using_fast_plain_lift is false and is
            otherwise represented modulo each of the coeff_modulus primes in order.
            */
            inline const std::uint64_t *plainUpperHalfIncrement() const noexcept
            {
                return plain_upper_half_increment_.get();
            }

            /**
            Return a pointer to the upper half threshold with respect to the total
            coefficient modulus. This is needed in CKKS decryption.
            */
            inline const std::uint64_t *upperHalfThreshold() const noexcept
            {
                return upper_half_threshold_.get();
            }

            /**
            Return a pointer to the upper half increment used for computing Delta*m
            and converting the coefficients to modulo coeff_modulus. For example,
            t-1 in plaintext should change into
            q - Delta = Delta*t + r_t(q) - Delta
            = Delta*(t-1) + r_t(q)
            so multiplying the message by Delta is not enough and requires also an
            addition of r_t(q). This is precisely the upper_half_increment. Note that
            this operation is only done for negative message coefficients, i.e. those
            that exceed plain_upper_half_threshold.
            */
            inline const std::uint64_t *upperHalfIncrement() const noexcept
            {
                return upper_half_increment_.get();
            }

            /**
            Return the non-RNS form of upper_half_increment which is q mod t.
            */
            inline std::uint64_t coeffModulusModPlainModulus() const noexcept
            {
                return coeff_modulus_mod_plain_modulus_;
            }

            /**
            Returns a shared_ptr to the context data corresponding to the previous parameters
            in the modulus switching chain. If the current data is the first one in the
            chain, then the result is nullptr.
            */
            inline std::shared_ptr<const ContextData> prevContextData() const noexcept
            {
                return prev_context_data_.lock();
            }

            /**
            Returns a shared_ptr to the context data corresponding to the next parameters
            in the modulus switching chain. If the current data is the last one in the
            chain, then the result is nullptr.
            */
            inline std::shared_ptr<const ContextData> nextContextData() const noexcept
            {
                return next_context_data_;
            }

            /**
            Returns the index of the parameter set in a chain. The initial parameters
            have index 0 and the index increases sequentially in the parameter chain.
            */
            inline std::size_t chainIndex() const noexcept
            {
                return chain_index_;
            }

        private:
            ContextData(EncryptionParameters parms) : parms_(parms)
            {
            }

            EncryptionParameters parms_;

            EncryptionParameterQualifiers qualifiers_;

            util::HostObject<util::RNSTool> rns_tool_;

            util::HostArray<util::NTTTables> small_ntt_tables_;

            util::HostArray<util::NTTTables> plain_ntt_tables_;

            util::HostObject<util::GaloisTool> galois_tool_;

            util::HostArray<std::uint64_t> total_coeff_modulus_;

            int total_coeff_modulus_bit_count_ = 0;

            util::HostArray<util::MultiplyUIntModOperand> coeff_div_plain_modulus_;

            std::uint64_t plain_upper_half_threshold_ = 0;

            util::HostArray<std::uint64_t> plain_upper_half_increment_;

            util::HostArray<std::uint64_t> upper_half_threshold_;

            util::HostArray<std::uint64_t> upper_half_increment_;

            std::uint64_t coeff_modulus_mod_plain_modulus_ = 0;

            std::weak_ptr<const ContextData> prev_context_data_;

            std::shared_ptr<const ContextData> next_context_data_{ nullptr };

            std::size_t chain_index_ = 0;
        };

        /**
        Creates an instance of SEALContext and performs several pre-computations
        on the given EncryptionParameters.

        @param[in] parms The encryption parameters
        @param[in] expand_mod_chain Determines whether the modulus switching chain
        should be created
        @param[in] sec_level Determines whether a specific security level should be
        enforced according to HomomorphicEncryption.org security standard
        */
        SEALContext(
            EncryptionParameters parms, bool expand_mod_chain = true,
            SecurityLevel sec_level = SecurityLevel::tc128);

        /**
        Creates a new SEALContext by copying a given one.

        @param[in] copy The SEALContext to copy from
        */
        SEALContext(const SEALContext &copy) = default;

        /**
        Creates a new SEALContext by moving a given one.

        @param[in] source The SEALContext to move from
        */
        SEALContext(SEALContext &&source) = default;

        /**
        Copies a given SEALContext to the current one.

        @param[in] assign The SEALContext to copy from
        */
        SEALContext &operator=(const SEALContext &assign) = default;

        /**
        Moves a given SEALContext to the current one.

        @param[in] assign The SEALContext to move from
        */
        SEALContext &operator=(SEALContext &&assign) = default;

        /**
        Returns the ContextData corresponding to encryption parameters with a given
        parms_id. If parameters with the given parms_id are not found then the
        function returns nullptr.

        @param[in] parms_id The parms_id of the encryption parameters
        */
        inline std::shared_ptr<const ContextData> getContextData(ParmsID parms_id) const
        {
            auto data = context_data_map_.find(parms_id);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns the ContextData corresponding to encryption parameters that are
        used for keys.
        */
        inline std::shared_ptr<const ContextData> keyContextData() const
        {
            auto data = context_data_map_.find(key_parms_id_);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns the ContextData corresponding to the first encryption parameters
        that are used for data.
        */
        inline std::shared_ptr<const ContextData> firstContextData() const
        {
            auto data = context_data_map_.find(first_parms_id_);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns the ContextData corresponding to the last encryption parameters
        that are used for data.
        */
        inline std::shared_ptr<const ContextData> lastContextData() const
        {
            auto data = context_data_map_.find(last_parms_id_);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns whether the first_context_data's encryption parameters are valid.
        */
        inline bool parametersSet() const
        {
            return firstContextData() ? firstContextData()->qualifiers_.parametersSet() : false;
        }

        /**
        Returns the name of encryption parameters' error.
        */
        inline const char *parameterErrorName() const
        {
            return firstContextData() ? firstContextData()->qualifiers_.parameterErrorName()
                                        : "SEALContext is empty";
        }

        /**
        Returns a comprehensive message that interprets encryption parameters' error.
        */
        inline const char *parameterErrorMessage() const
        {
            return firstContextData() ? firstContextData()->qualifiers_.parameterErrorMessage()
                                        : "SEALContext is empty";
        }

        /**
        Returns a ParmsID corresponding to the set of encryption parameters
        that are used for keys.
        */
        inline const ParmsID &keyParmsID() const noexcept
        {
            return key_parms_id_;
        }

        /**
        Returns a ParmsID corresponding to the first encryption parameters
        that are used for data.
        */
        inline const ParmsID &firstParmsID() const noexcept
        {
            return first_parms_id_;
        }

        /**
        Returns a ParmsID corresponding to the last encryption parameters
        that are used for data.
        */
        inline const ParmsID &lastParmsID() const noexcept
        {
            return last_parms_id_;
        }

        /**
        Returns whether the coefficient modulus supports keyswitching. In practice,
        support for keyswitching is required by Evaluator::relinearize,
        Evaluator::apply_galois, and all rotation and conjugation operations. For
        keyswitching to be available, the coefficient modulus parameter must consist
        of at least two prime number factors.
        */
        inline bool using_keyswitching() const noexcept
        {
            return using_keyswitching_;
        }

    private:
        // /**
        // Creates an instance of SEALContext, and performs several pre-computations
        // on the given EncryptionParameters.

        // @param[in] parms The encryption parameters
        // @param[in] expand_mod_chain Determines whether the modulus switching chain
        // should be created
        // @param[in] sec_level Determines whether a specific security level should be
        // enforced according to HomomorphicEncryption.org security standard
        // @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        // @throws std::invalid_argument if pool is uninitialized
        // */
        // SEALContext(EncryptionParameters parms, bool expand_mod_chain, SecurityLevel sec_level);

        ContextData validate(EncryptionParameters parms);

        /**
        Create the next context_data by dropping the last element from coeff_modulus.
        If the new encryption parameters are not valid, returns parms_id_zero.
        Otherwise, returns the parms_id of the next parameter and appends the next
        context_data to the chain.
        */
        ParmsID createNextContextData(const ParmsID &prev_parms);

        ParmsID key_parms_id_;

        ParmsID first_parms_id_;

        ParmsID last_parms_id_;

        std::unordered_map<ParmsID, std::shared_ptr<const ContextData>, std::TroyHashParmsID> context_data_map_{};

        /**
        Is HomomorphicEncryption.org security standard enforced?
        */
        SecurityLevel sec_level_;

        /**
        Is keyswitching supported by the encryption parameters?
        */
        bool using_keyswitching_;
    };
}