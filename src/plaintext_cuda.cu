#include "plaintext_cuda.cuh"
#include "serialize.h"

namespace troy {
    

    void PlaintextCuda::save(std::ostream& stream) const {
        savet(stream, &parms_id_);
        savet(stream, &coeff_count_);
        savet(stream, &scale_);
        auto r = data_.toHost();
        size_t dataSize = r.size();
        savet(stream, &dataSize);
        stream.write(reinterpret_cast<char*>(r.begin()), sizeof(pt_coeff_type) * r.size());
    }

    void PlaintextCuda::load(std::istream& stream) {
        loadt(stream, &parms_id_);
        loadt(stream, &coeff_count_);
        loadt(stream, &scale_);
        size_t dataSize;
        loadt(stream, &dataSize);
        util::HostArray<pt_coeff_type> host(dataSize);
        stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(pt_coeff_type));
        data_.ensure(dataSize);
        KernelProvider::copy(data_.get(), host.get(), dataSize);
    }

}