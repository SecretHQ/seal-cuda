#pragma once 

#include "encryptionparams.h"
#include "utils/devicearray.cuh"

namespace troy {

    class EncryptionParametersCuda {

        friend struct std::hash<troy::EncryptionParametersCuda>;
        
    public:
        
        EncryptionParametersCuda(SchemeType scheme = SchemeType::none) : scheme_(scheme), cpu(scheme) {
            computeParmsID();
        }
    
        EncryptionParametersCuda(const EncryptionParametersCuda &copy) = default;
        //     std::cout << "EncryptionParametersCuda copy constructor\n";
        //     scheme_ = copy.scheme_;
        //     poly_modulus_degree_ = copy.poly_modulus_degree_;
        //     coeff_modulus_ = copy.coeff_modulus_;
        //     std::cout << "EncryptionParametersCuda copy constructor\n";
        //     random_generator_ = copy.random_generator_;
        //     std::cout << "EncryptionParametersCuda copy constructor\n";
        //     plain_modulus_ = copy.plain_modulus_;
        //     std::cout << "EncryptionParametersCuda copy constructor\n";
        //     plain_modulus_cuda_ = copy.plain_modulus_cuda_;
        //     std::cout << "EncryptionParametersCuda copy constructor\n";
        //     parms_id_ = copy.parms_id_;
        //     cpu = copy.cpu;
        //     std::cout << "EncryptionParametersCuda copy constructor done\n";
        // }
        EncryptionParametersCuda &operator=(const EncryptionParametersCuda &assign) = default;
        
        EncryptionParametersCuda(EncryptionParametersCuda &&source) = default;
        EncryptionParametersCuda &operator=(EncryptionParametersCuda &&assign) = default;

        EncryptionParametersCuda(const EncryptionParameters& host) {
            cpu = host;
            scheme_ = host.scheme();
            poly_modulus_degree_ = host.polyModulusDegree();
            util::HostArray<Modulus> copied_moduli(host.coeffModulus());
            coeff_modulus_ = std::move(util::DeviceArray(copied_moduli));
            random_generator_ = host.randomGenerator();
            plain_modulus_ = host.plainModulus();
            parms_id_ = host.parmsID();
            setPlainModulusCuda();
        }

        /**
        Sets the degree of the polynomial modulus parameter to the specified value.
        The polynomial modulus directly affects the number of coefficients in
        plaintext polynomials, the size of ciphertext elements, the computational
        performance of the scheme (bigger is worse), and the security level (bigger
        is better). In Microsoft SEAL the degree of the polynomial modulus must be
        a power of 2 (e.g.  1024, 2048, 4096, 8192, 16384, or 32768).

        @param[in] poly_modulus_degree The new polynomial modulus degree
        @throws std::logic_error if a valid scheme is not set and poly_modulus_degree
        is non-zero
        */
        inline void setPolyModulusDegree(std::size_t poly_modulus_degree)
        {
            if (scheme_ == SchemeType::none && poly_modulus_degree)
            {
                throw std::logic_error("poly_modulus_degree is not supported for this scheme");
            }

            // Set the degree
            // std::cout << "reset polydeg " <<  poly_modulus_degree_ << " -> " << poly_modulus_degree << std::endl;
            poly_modulus_degree_ = poly_modulus_degree;
            cpu.setPolyModulusDegree(poly_modulus_degree);
            // Re-compute the parms_id
            computeParmsID();
        }

        

        /**
        Sets the coefficient modulus parameter. The coefficient modulus consists
        of a list of distinct prime numbers, and is represented by a vector of
        Modulus objects. The coefficient modulus directly affects the size
        of ciphertext elements, the amount of computation that the scheme can
        perform (bigger is better), and the security level (bigger is worse). In
        Microsoft SEAL each of the prime numbers in the coefficient modulus must
        be at most 60 bits, and must be congruent to 1 modulo 2*poly_modulus_degree.

        @param[in] coeff_modulus The new coefficient modulus
        @throws std::logic_error if a valid scheme is not set and coeff_modulus is
        is non-empty
        @throws std::invalid_argument if size of coeff_modulus is invalid
        */
        inline void setCoeffModulus(const std::vector<Modulus> &coeff_modulus)
        {
            // Check that a scheme is set
            if (scheme_ == SchemeType::none)
            {
                if (!coeff_modulus.empty())
                {
                    throw std::logic_error("coeff_modulus is not supported for this scheme");
                }
            }
            else if (coeff_modulus.size() > SEAL_COEFF_MOD_COUNT_MAX || coeff_modulus.size() < SEAL_COEFF_MOD_COUNT_MIN)
            {
                throw std::invalid_argument("coeff_modulus is invalid");
            }

            util::HostArray<Modulus> copied_moduli(coeff_modulus);
            coeff_modulus_ = std::move(util::DeviceArray(copied_moduli));
            cpu.setCoeffModulus(coeff_modulus);
            // Re-compute the parms_id
            computeParmsID();
        }

        /**
        Sets the plaintext modulus parameter. The plaintext modulus is an integer
        modulus represented by the Modulus class. The plaintext modulus
        determines the largest coefficient that plaintext polynomials can represent.
        It also affects the amount of computation that the scheme can perform
        (bigger is worse). In Microsoft SEAL the plaintext modulus can be at most
        60 bits long, but can otherwise be any integer. Note, however, that some
        features (e.g. batching) require the plaintext modulus to be of a particular
        form.

        @param[in] plain_modulus The new plaintext modulus
        @throws std::logic_error if scheme is not SchemeType::BFV and plain_modulus
        is non-zero
        */
        inline void setPlainModulus(const Modulus &plain_modulus)
        {
            // Check that scheme is BFV
            if (scheme_ != SchemeType::bfv && scheme_ != SchemeType::bgv && !plain_modulus.isZero())
            {
                throw std::logic_error("plain_modulus is not supported for this scheme");
            }

            // std::cout << "hello there 2" << std::endl;

            plain_modulus_ = plain_modulus;
            setPlainModulusCuda();
            cpu.setPlainModulus(plain_modulus);
            // Re-compute the parms_id
            computeParmsID();
        }

        
        /**
        Sets the plaintext modulus parameter. The plaintext modulus is an integer
        modulus represented by the Modulus class. This constructor instead
        takes a std::uint64_t and automatically creates the Modulus object.
        The plaintext modulus determines the largest coefficient that plaintext
        polynomials can represent. It also affects the amount of computation that
        the scheme can perform (bigger is worse). In Microsoft SEAL the plaintext
        modulus can be at most 60 bits long, but can otherwise be any integer. Note,
        however, that some features (e.g. batching) require the plaintext modulus
        to be of a particular form.

        @param[in] plain_modulus The new plaintext modulus
        @throws std::invalid_argument if plain_modulus is invalid
        */
        inline void setPlainModulus(std::uint64_t plain_modulus)
        {
            setPlainModulus(Modulus(plain_modulus));
        }

        

        /**
        Returns the encryption scheme type.
        */
        inline SchemeType scheme() const noexcept
        {
            return scheme_;
        }

        /**
        Returns the degree of the polynomial modulus parameter.
        */
        inline std::size_t polyModulusDegree() const noexcept
        {
            return poly_modulus_degree_;
        }

        
        /**
        Returns a const reference to the currently set coefficient modulus parameter.
        */
        inline const util::DeviceArray<Modulus>& coeffModulus() const noexcept
        {
            return coeff_modulus_;
        }

        

        /**
        Returns a const reference to the currently set plaintext modulus parameter.
        */
        inline const Modulus &plainModulus() const noexcept
        {
            return plain_modulus_;
        }

        inline const Modulus* plainModulusCuda() const noexcept {
            return plain_modulus_cuda_.get();
        }

        /**
        Returns a pointer to the random number generator factory to use for encryption.
        */
        inline std::shared_ptr<UniformRandomGeneratorFactory> randomGenerator() const noexcept
        {
            return random_generator_;
        }

        /**
        Returns a const reference to the parms_id of the current parameters.
        */
        inline const ParmsID &parmsID() const noexcept
        {
            return parms_id_;
        }

        /**
        Compares a given set of encryption parameters to the current set of
        encryption parameters. The comparison is performed by comparing the
        parms_ids of the parameter sets rather than comparing the parameters
        individually.

        @parms[in] other The EncryptionParameters to compare against
        */
        inline bool operator==(const EncryptionParametersCuda &other) const noexcept
        {
            return (parms_id_ == other.parms_id_);
        }

        /**
        Compares a given set of encryption parameters to the current set of
        encryption parameters. The comparison is performed by comparing
        parms_ids of the parameter sets rather than comparing the parameters
        individually.

        @parms[in] other The EncryptionParameters to compare against
        */
        inline bool operator!=(const EncryptionParametersCuda &other) const noexcept
        {
            return (parms_id_ != other.parms_id_);
        }

        inline const EncryptionParameters& host() const noexcept {
            return cpu;
        }

    private:
    
        void computeParmsID();

        /**
        Helper function to determine whether given std::uint8_t represents a valid
        value for SchemeType. The return value will be false is the scheme is set
        to SchemeType::none.
        */
        bool isValidScheme(std::uint8_t scheme) const noexcept
        {
            switch (scheme)
            {
            case static_cast<std::uint8_t>(SchemeType::none):
                /* fall through */

            case static_cast<std::uint8_t>(SchemeType::bfv):
                /* fall through */

            case static_cast<std::uint8_t>(SchemeType::ckks):
                /* fall through */

            case static_cast<std::uint8_t>(SchemeType::bgv):
                return true;
            }
            return false;
        }

        void setPlainModulusCuda() {
            Modulus* p = KernelProvider::malloc<Modulus>(1);
            KernelProvider::copy(p, &plain_modulus_, 1);
            plain_modulus_cuda_ = util::DeviceObject(p);
            // printf("set plain modulus cuda done\n");
        }

        SchemeType scheme_;

        std::size_t poly_modulus_degree_ = 0;

        util::DeviceArray<Modulus> coeff_modulus_; 

        std::shared_ptr<UniformRandomGeneratorFactory> random_generator_{ nullptr };

        Modulus plain_modulus_{};

        util::DeviceObject<Modulus> plain_modulus_cuda_;

        ParmsID parms_id_ = parmsIDZero;

        EncryptionParameters cpu;

    };

}

namespace std
{

    template <>
    struct hash<troy::EncryptionParametersCuda>
    {
        std::size_t operator()(const troy::EncryptionParametersCuda &parms) const
        {
            TroyHashParmsID parms_id_hash;
            return parms_id_hash(parms.parms_id_);
        }
    };
} // namespace std
