// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "relinkeys.h"
#include "kswitchkeys_cuda.cuh"

namespace troy
{
    class RelinKeysCuda : public KSwitchKeysCuda
    {
    public:
        /**
        Returns the index of a relinearization key in the backing KSwitchKeys
        instance that corresponds to the given secret key power, assuming that
        it exists in the backing KSwitchKeys.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if key_power is less than 2
        */
        inline static std::size_t getIndex(std::size_t key_power)
        {
            if (key_power < 2)
            {
                throw std::invalid_argument("key_power cannot be less than 2");
            }
            return key_power - 2;
        }

        /**
        Returns whether a relinearization key corresponding to a given power of
        the secret key exists.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if key_power is less than 2
        */
        inline bool hasKey(std::size_t key_power) const
        {
            std::size_t index = getIndex(key_power);
            return data().size() > index && !data()[index].empty();
        }

        /**
        Returns a const reference to a relinearization key. The returned
        relinearization key corresponds to the given power of the secret key.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if the key corresponding to key_power does not exist
        */
        inline auto &key(std::size_t key_power) const
        {
            return KSwitchKeysCuda::data(getIndex(key_power));
        }

        RelinKeysCuda(const RelinKeys& copy):
            KSwitchKeysCuda(static_cast<const KSwitchKeys&>(copy)) {}

        RelinKeysCuda() {}
    };
} // namespace seal
