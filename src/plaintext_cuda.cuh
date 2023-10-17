// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "plaintext.h"
#include "utils/devicearray.cuh"

namespace troy
{
    class PlaintextCuda
    {
    public:
        using pt_coeff_type = std::uint64_t;
        PlaintextCuda() : data_()
        {}

        explicit PlaintextCuda(std::size_t coeff_count)
            : coeff_count_(coeff_count), data_(coeff_count_)
        {}

        explicit PlaintextCuda(
            std::size_t capacity, std::size_t coeff_count)
            : coeff_count_(coeff_count), data_(capacity, coeff_count_)
        {}

        PlaintextCuda(const Plaintext& copy):
            parms_id_(copy.parmsID()),
            coeff_count_(copy.coeffCount()),
            scale_(copy.scale()),
            data_(copy.dynArray()) {}

        Plaintext cpu() const {
            Plaintext ret;
            ret.parms_id_ = parms_id_;
            ret.coeff_count_ = coeff_count_;
            ret.scale_ = scale_;
            ret.data_ = std::move(data_.toHost());
            return ret;
        }

        Plaintext toHost() const {return cpu();}

        std::string to_string() const {return cpu().to_string();}

        
        inline bool isZero() const {return cpu().isZero();}

        PlaintextCuda(const std::string &hex_poly)
            : data_()
        {
            operator=(hex_poly);
        }

        PlaintextCuda(const PlaintextCuda &copy) = default;

        PlaintextCuda(PlaintextCuda &&source) = default;

        void reserve(std::size_t capacity)
        {
            if (isNttForm())
            {
                throw std::logic_error("cannot reserve for an NTT transformed Plaintext");
            }
            data_.reserve(capacity);
            coeff_count_ = data_.size();
        }

        inline void shrinkToFit()
        {
            data_.shrinkToFit();
        }
        inline void release() noexcept
        {
            parms_id_ = parmsIDZero;
            coeff_count_ = 0;
            scale_ = 1.0;
            data_.release();
        }

        inline void resize(std::size_t coeff_count)
        {
            if (isNttForm())
            {
                throw std::logic_error("cannot reserve for an NTT transformed Plaintext");
            }
            data_.resize(coeff_count);
            coeff_count_ = coeff_count;
        }

        PlaintextCuda &operator=(const PlaintextCuda &assign) = default;

        PlaintextCuda &operator=(PlaintextCuda &&assign) = default;

        PlaintextCuda &operator=(const std::string &hex_poly) {
            Plaintext p = hex_poly;
            operator=(PlaintextCuda(p));
            return *this;
        }

        // Plaintext &operator=(pt_coeff_type const_coeff)
        // {
        //     data_.resize(1);
        //     data_[0] = const_coeff;
        //     coeff_count_ = 1;
        //     parms_id_ = parmsIDZero;
        //     return *this;
        // }

        bool operator==(const PlaintextCuda& a) const {
            Plaintext p = this->cpu();
            Plaintext q = a.cpu();
            return p == q;
        }

        uint64_t operator[](size_t i) const {
            uint64_t ret;
            KernelProvider::retrieve(&ret, data_.get() + i, 1);
            return ret;
        }

        PlaintextCuda &operator=(uint64_t const_coeff)
        {
            Plaintext r; r = const_coeff;
            return operator=(r);
        }

        inline void setZero(std::size_t start_coeff, std::size_t length)
        {
            if (!length)
            {
                return;
            }
            if (start_coeff + length - 1 >= coeff_count_)
            {
                throw std::out_of_range(
                    "length must be non-negative and start_coeff + length - 1 must be within [0, coeff_count)");
            }
            KernelProvider::memsetZero<uint64_t>(data_.get() + start_coeff, length);
        }

        /**
        Sets the plaintext polynomial coefficients to zero starting at a given index.

        @param[in] start_coeff The index of the first coefficient to set to zero
        @throws std::out_of_range if start_coeff is not within [0, coeff_count)
        */
        inline void setZero(std::size_t start_coeff)
        {
            if (start_coeff >= coeff_count_)
            {
                throw std::out_of_range("start_coeff must be within [0, coeff_count)");
            }
            KernelProvider::memsetZero<uint64_t>(data_.get() + start_coeff, data_.size() - start_coeff);
        }

        /**
        Sets the plaintext polynomial to zero.
        */
        inline void setZero()
        {
            KernelProvider::memsetZero<uint64_t>(data_.get(), data_.size());
        }

        /**
        Returns a reference to the backing DynArray object.
        */
        inline const auto &dynArray() const noexcept
        {
            return data_;
        }

        /**
        Returns a pointer to the beginning of the plaintext polynomial.
        */
        inline pt_coeff_type *data()
        {
            return data_.get();
        }

        /**
        Returns a const pointer to the beginning of the plaintext polynomial.
        */
        inline const pt_coeff_type *data() const
        {
            return data_.get();
        }
        /**
        Returns a pointer to a given coefficient of the plaintext polynomial.

        @param[in] coeff_index The index of the coefficient in the plaintext polynomial
        @throws std::out_of_range if coeff_index is not within [0, coeff_count)
        */
        inline pt_coeff_type *data(std::size_t coeff_index)
        {
            if (!coeff_count_)
            {
                return nullptr;
            }
            if (coeff_index >= coeff_count_)
            {
                throw std::out_of_range("coeff_index must be within [0, coeff_count)");
            }
            return data_.get() + coeff_index;
        }

        /**
        Returns a const pointer to a given coefficient of the plaintext polynomial.

        @param[in] coeff_index The index of the coefficient in the plaintext polynomial
        */
        inline const pt_coeff_type *data(std::size_t coeff_index) const
        {
            if (!coeff_count_)
            {
                return nullptr;
            }
            if (coeff_index >= coeff_count_)
            {
                throw std::out_of_range("coeff_index must be within [0, coeff_count)");
            }
            return data_.get() + coeff_index;
        }

        // /**
        // Returns a const reference to a given coefficient of the plaintext polynomial.

        // @param[in] coeff_index The index of the coefficient in the plaintext polynomial
        // @throws std::out_of_range if coeff_index is not within [0, coeff_count)
        // */
        // inline const pt_coeff_type &operator[](std::size_t coeff_index) const
        // {
        //     return data_.at(coeff_index);
        // }

        // /**
        // Returns a reference to a given coefficient of the plaintext polynomial.

        // @param[in] coeff_index The index of the coefficient in the plaintext polynomial
        // @throws std::out_of_range if coeff_index is not within [0, coeff_count)
        // */
        // inline pt_coeff_type &operator[](std::size_t coeff_index)
        // {
        //     return data_.at(coeff_index);
        // }

        /**

        /**
        Returns the capacity of the current allocation.
        */
        inline std::size_t capacity() const noexcept
        {
            return data_.capacity();
        }

        /**
        Returns the coefficient count of the current plaintext polynomial.
        */
        inline std::size_t coeffCount() const noexcept
        {
            return coeff_count_;
        }

        /**
        Returns the significant coefficient count of the current plaintext polynomial.
        */
        // inline std::size_t significantCoeffCount() const
        // {
        //     if (!coeff_count_)
        //     {
        //         return 0;
        //     }
        //     return util::getSignificantUint64CountUint(data_.cbegin(), coeff_count_);
        // }

        // /**
        // Returns the non-zero coefficient count of the current plaintext polynomial.
        // */
        // inline std::size_t nonzeroCoeffCount() const
        // {
        //     if (!coeff_count_)
        //     {
        //         return 0;
        //     }
        //     return util::getNonzeroUint64CountUint(data_.cbegin(), coeff_count_);
        // }

        /**
        Returns a human-readable string description of the plaintext polynomial.

        The returned string is of the form "7FFx^3 + 1x^1 + 3" with a format
        summarized by the following:
        1. Terms are listed in order of strictly decreasing exponent
        2. Coefficient values are non-negative and in hexadecimal format (hexadecimal
        letters are in upper-case)
        3. Exponents are positive and in decimal format
        4. Zero coefficient terms (including the constant term) are omitted unless
        the polynomial is exactly 0 (see rule 9)
        5. Term with the exponent value of one is written as x^1
        6. Term with the exponent value of zero (the constant term) is written as
        just a hexadecimal number without x or exponent
        7. Terms are separated exactly by <space>+<space>
        8. Other than the +, no other terms have whitespace
        9. If the polynomial is exactly 0, the string "0" is returned

        @throws std::invalid_argument if the plaintext is in NTT transformed form
        */
        // inline std::string to_string() const
        // {
        //     if (isNttForm())
        //     {
        //         throw std::invalid_argument("cannot convert NTT transformed plaintext to string");
        //     }
        //     return util::polyToHexString(data_.cbegin(), coeff_count_, 1);
        // }

        // /**
        // Returns an upper bound on the size of the plaintext, as if it was written
        // to an output stream.

        // @param[in] compr_mode The compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the size does not fit in the return type
        // */
        // inline std::streamoff save_size(
        //     compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     std::size_t members_size = Serialization::ComprSizeEstimate(
        //         util::add_safe(
        //             sizeof(parms_id_),
        //             sizeof(std::uint64_t), // coeff_count_
        //             sizeof(scale_), util::safe_cast<std::size_t>(data_.save_size(compr_mode_type::none))),
        //         compr_mode);

        //     return util::safe_cast<std::streamoff>(util::add_safe(sizeof(Serialization::SEALHeader), members_size));
        // }

        // /**
        // Saves the plaintext to an output stream. The output is in binary format
        // and not human-readable. The output stream must have the "binary" flag set.

        // @param[out] stream The stream to save the plaintext to
        // @param[in] compr_mode The desired compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the data to be saved is invalid, or if
        // compression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff save(
        //     std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Save(
        //         std::bind(&Plaintext::save_members, this, _1), save_size(compr_mode_type::none), stream, compr_mode,
        //         false);
        // }

        // /**
        // Loads a plaintext from an input stream overwriting the current plaintext.
        // No checking of the validity of the plaintext data against encryption
        // parameters is performed. This function should not be used unless the
        // plaintext comes from a fully trusted source.

        // @param[in] context The SEALContext
        // @param[in] stream The stream to load the plaintext from
        // @throws std::invalid_argument if the encryption parameters are not valid
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff unsafe_load(const SEALContext &context, std::istream &stream)
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Load(std::bind(&Plaintext::load_members, this, context, _1, _2), stream, false);
        // }

        // /**
        // Loads a plaintext from an input stream overwriting the current plaintext.
        // The loaded plaintext is verified to be valid for the given SEALContext.

        // @param[in] context The SEALContext
        // @param[in] stream The stream to load the plaintext from
        // @throws std::invalid_argument if the encryption parameters are not valid
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(const SEALContext &context, std::istream &stream)
        // {
        //     Plaintext new_data(pool());
        //     auto in_size = new_data.unsafe_load(context, stream);
        //     if (!is_valid_for(new_data, context))
        //     {
        //         throw std::logic_error("Plaintext data is invalid");
        //     }
        //     std::swap(*this, new_data);
        //     return in_size;
        // }

        // /**
        // Saves the plaintext to a given memory location. The output is in binary
        // format and not human-readable.

        // @param[out] out The memory location to write the plaintext to
        // @param[in] size The number of bytes available in the given memory location
        // @param[in] compr_mode The desired compression mode
        // @throws std::invalid_argument if out is null or if size is too small to
        // contain a SEALHeader, or if the compression mode is not supported
        // @throws std::logic_error if the data to be saved is invalid, or if
        // compression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff save(
        //     seal_byte *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Save(
        //         std::bind(&Plaintext::save_members, this, _1), save_size(compr_mode_type::none), out, size, compr_mode,
        //         false);
        // }

        // /**
        // Loads a plaintext from a given memory location overwriting the current
        // plaintext. No checking of the validity of the plaintext data against
        // encryption parameters is performed. This function should not be used
        // unless the plaintext comes from a fully trusted source.

        // @param[in] context The SEALContext
        // @param[in] in The memory location to load the plaintext from
        // @param[in] size The number of bytes available in the given memory location
        // @throws std::invalid_argument if the encryption parameters are not valid
        // @throws std::invalid_argument if in is null or if size is too small to
        // contain a SEALHeader
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff unsafe_load(const SEALContext &context, const seal_byte *in, std::size_t size)
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Load(std::bind(&Plaintext::load_members, this, context, _1, _2), in, size, false);
        // }

        // /**
        // Loads a plaintext from an input stream overwriting the current plaintext.
        // The loaded plaintext is verified to be valid for the given SEALContext.

        // @param[in] context The SEALContext
        // @param[in] in The memory location to load the PublicKey from
        // @param[in] size The number of bytes available in the given memory location
        // @throws std::invalid_argument if the encryption parameters are not valid
        // @throws std::invalid_argument if in is null or if size is too small to
        // contain a SEALHeader
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(const SEALContext &context, const seal_byte *in, std::size_t size)
        // {
        //     Plaintext new_data(pool());
        //     auto in_size = new_data.unsafe_load(context, in, size);
        //     if (!is_valid_for(new_data, context))
        //     {
        //         throw std::logic_error("Plaintext data is invalid");
        //     }
        //     std::swap(*this, new_data);
        //     return in_size;
        // }

        /**
        Returns whether the plaintext is in NTT form.
        */
        inline bool isNttForm() const noexcept
        {
            return (parms_id_ != parmsIDZero);
        }

        /**
        Returns a reference to parms_id. The parms_id must remain zero unless the plaintext polynomial is in NTT form.

        @see EncryptionParameters for more information about parms_id.
        */
        inline ParmsID &parmsID() noexcept
        {
            return parms_id_;
        }

        /**
        Returns a const reference to parms_id. The parms_id must remain zero unless the plaintext polynomial is in NTT
        form.

        @see EncryptionParameters for more information about parms_id.
        */
        inline const ParmsID &parmsID() const noexcept
        {
            return parms_id_;
        }

        /**
        Returns a reference to the scale. This is only needed when using the CKKS encryption scheme. The user should
        have little or no reason to ever change the scale by hand.
        */
        inline double &scale() noexcept
        {
            return scale_;
        }

        /**
        Returns a constant reference to the scale. This is only needed when using the CKKS encryption scheme.
        */
        inline const double &scale() const noexcept
        {
            return scale_;
        }

        /**
        Enables access to private members of seal::Plaintext for SEAL_C.
        */
        struct PlaintextPrivateHelper;

        void save(std::ostream& stream) const;
        void load(std::istream& stream);

    private:
        // void save_members(std::ostream &stream) const;

        // void load_members(const SEALContext &context, std::istream &stream, SEALVersion version);

        ParmsID parms_id_ = parmsIDZero;

        std::size_t coeff_count_ = 0;

        double scale_ = 1.0;

        util::DeviceDynamicArray<pt_coeff_type> data_;

        // SecretKey needs access to save_members/load_members
        friend class SecretKey;
    };
} // namespace seal
