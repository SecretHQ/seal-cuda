#include <iostream>
#include <vector>
#include "utils/hostarray.h"
#include "modulus.h"
#include "encryptionparams.h"

namespace troy {

    inline std::ostream& operator <<(std::ostream& o, const Modulus& m) {
        o << m.value(); return o;
    }

    template<typename T>
    inline std::ostream& operator <<(std::ostream& o, const std::vector<T>& m) {
        o << "["; bool first = true;
        for (auto& iter: m) {
            if (!first) o << ", ";
            o << (iter); first = false;
        }
        o << "]";
        return o;
    }

    template<typename T>
    inline std::ostream& operator <<(std::ostream& o, const util::HostArray<T>& m) {
        int n = m.length();
        o << "["; bool first = true;
        for (int i=0; i<n; i++) {
            if (!first) o << ", ";
            o << (m[i]); first = false;
        }
        o << "]";
        return o;
    }

    inline std::ostream& operator <<(std::ostream& o, const SchemeType& s) {
        if (s == SchemeType::none) {
            o << "[none]";
        } else if (s == SchemeType::ckks) {
            o << "[ckks]";
        } else if (s == SchemeType::bfv) {
            o << "[bfv]";
        } else if (s == SchemeType::bgv) {
            o << "[bgv]";
        }
        return o;
    }

    inline std::ostream& operator <<(std::ostream& o, const ParmsID& p) {
        for (size_t i = 0; i < p.size(); i++) {
            std::cout << std::hex << p[i];
            if (i!=p.size()-1) std::cout << "-";
        }
        std::cout << std::dec;
        return o;
    }

    inline std::ostream& operator <<(std::ostream& o, const EncryptionParameters& p) {
        o << p.scheme();
        o << " " << p.parmsID() << " {\n";
        o << "    plain modulus: " << p.plainModulus() << "\n";
        o << "    coeff moduli : " << p.coeffModulus() << "\n";
        o << "} ";
        return o;
    }

}