#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <pybind11/complex.h>
#include <pybind11/numpy.h>

#include "../src/troy_cuda.cuh"
#include "../app/LinearHelper.cuh"
#include <iostream>
#include <memory.h>
#include <ctime>

PYBIND11_MAKE_OPAQUE(std::vector<double>);
PYBIND11_MAKE_OPAQUE(std::vector<int64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<uint64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<std::complex<double>>);

namespace py = pybind11;

using namespace troyn;
using std::vector;
using std::complex;
using std::stringstream;
using std::istringstream;
using std::ostringstream;
using std::string;

using namespace LinearHelper;

#define SAVE_MACRO ostringstream stream; p.save(stream); return py::bytes(stream.str());
#define LOAD_MACRO istringstream stream(str); self.load(stream);

class Smoke {
public:
    int t;
    Smoke(int i) {t=i;}
    Smoke() {t=19991111;}
    void print() {std::cout << "Hello I am Smoking ... " << t << std::endl;}
};

void initializeKernel() {
    KernelProvider::initialize();
}

std::vector<double> getVectorFromBuffer(py::array_t<double>& values) {
    py::buffer_info buf = values.request();
    double *ptr = (double *)buf.ptr;
    std::vector<double> vec(buf.shape[0]);
    for (auto i = 0; i < buf.shape[0]; i++)
        vec[i] = ptr[i];
    return vec;
}

std::vector<int64_t> getVectorFromBuffer(py::array_t<int64_t>& values) {
    py::buffer_info buf = values.request();
    int64_t *ptr = (int64_t *)buf.ptr;
    std::vector<int64_t> vec(buf.shape[0]);
    for (auto i = 0; i < buf.shape[0]; i++)
        vec[i] = ptr[i];
    return vec;
}

std::vector<uint64_t> getVectorFromBuffer(py::array_t<uint64_t>& values) {
    py::buffer_info buf = values.request();
    uint64_t *ptr = (uint64_t *)buf.ptr;
    std::vector<uint64_t> vec(buf.shape[0]);
    for (auto i = 0; i < buf.shape[0]; i++)
        vec[i] = ptr[i];
    return vec;
}

uint64_t* getPtrFromBuffer(py::array_t<uint64_t>& values) {
    py::buffer_info buf = values.request();
    uint64_t *ptr = (uint64_t *)buf.ptr;
    return ptr;
}

std::vector<std::complex<double>> getVectorFromBuffer(py::array_t<std::complex<double>>& values) {
    py::buffer_info buf = values.request();
    std::complex<double> *ptr = (std::complex<double> *)buf.ptr;
    std::vector<std::complex<double>> vec(buf.shape[0]);
    for (auto i = 0; i < buf.shape[0]; i++)
        vec[i] = ptr[i];
    return vec;
}

py::array_t<double> getBufferFromVector(const std::vector<double>& vec) {
    py::array_t<double> values(vec.size());
    py::buffer_info buf = values.request();
    double *ptr = (double *)buf.ptr;
    for (auto i = 0; i < buf.shape[0]; i++)
        ptr[i] = vec[i];
    return values;
}

py::array_t<int64_t> getBufferFromVector(const std::vector<int64_t>& vec) {
    py::array_t<int64_t> values(vec.size());
    py::buffer_info buf = values.request();
    int64_t *ptr = (int64_t *)buf.ptr;
    for (auto i = 0; i < buf.shape[0]; i++)
        ptr[i] = vec[i];
    return values;
}

py::array_t<uint64_t> getBufferFromVector(const std::vector<uint64_t>& vec) {
    py::array_t<uint64_t> values(vec.size());
    py::buffer_info buf = values.request();
    uint64_t *ptr = (uint64_t *)buf.ptr;
    for (auto i = 0; i < buf.shape[0]; i++)
        ptr[i] = vec[i];
    return values;
}

py::array_t<std::complex<double>> getBufferFromVector(const std::vector<std::complex<double>>& vec) {
    py::array_t<std::complex<double>> values(vec.size());
    py::buffer_info buf = values.request();
    std::complex<double> *ptr = (std::complex<double> *)buf.ptr;
    for (auto i = 0; i < buf.shape[0]; i++)
        ptr[i] = vec[i];
    return values;
}

inline double getTime() {
    timeval t; gettimeofday(&t, 0);
    auto d = t.tv_sec * 1000.0;
    d += t.tv_usec / 1000.0;
    return d;
}


template<typename T>
std::vector<T> hostArrayToVector(const troy::util::HostArray<T>& from) {
    std::vector<T> ret; ret.reserve(from.size());
    for (size_t i = 0; i < from.size(); i++)
        ret.push_back(from[i]);
    return ret;
}

template<typename T>
std::vector<T> deviceArrayToVector(const troy::util::DeviceArray<T>& from) {
    return hostArrayToVector(from.toHost());
}

PYBIND11_MODULE(pytroy, m) {

    m.def("initialize_kernel", &initializeKernel);
    
    py::class_<Smoke>(m, "Smoke")
        .def(py::init<>())
        .def(py::init<int>())
        .def("hello", &Smoke::print);

    py::enum_<SchemeType>(m, "SchemeType")
        .value("none", SchemeType::none)
        .value("bfv", SchemeType::bfv)
        .value("bgv", SchemeType::bgv)
        .value("ckks", SchemeType::ckks);

    py::enum_<SecurityLevel>(m, "SecurityLevel")
        .value("none", SecurityLevel::none)
        .value("tc128", SecurityLevel::tc128)
        .value("tc192", SecurityLevel::tc192)
        .value("tc256", SecurityLevel::tc256)
        ;

    py::class_<Modulus>(m, "Modulus")
        .def(py::init<uint64_t>())
        .def("is_prime", &Modulus::isPrime)
        .def("value", &Modulus::value)
        ;

    py::class_<CoeffModulus>(m, "CoeffModulus")
        .def_static("max_bit_count", &CoeffModulus::MaxBitCount, 
            py::arg("poly_modulus_degree"), py::arg("sec_level") = SecurityLevel::tc128)
        .def_static("bfv_default", &CoeffModulus::BFVDefault, 
            py::arg("poly_modulus_degree"), py::arg("sec_level") = SecurityLevel::tc128)
        .def_static("create", py::overload_cast<size_t, std::vector<int>>(&CoeffModulus::Create))
        .def_static("create", py::overload_cast<size_t, const Modulus&, std::vector<int>>(&CoeffModulus::Create))
        ;

    py::class_<PlainModulus>(m, "PlainModulus")
        .def_static("batching", py::overload_cast<size_t, int>(&PlainModulus::Batching))
        .def_static("batching", py::overload_cast<size_t, std::vector<int>>(&PlainModulus::Batching))
        ;

    py::class_<ParmsID>(m, "ParmsID")
        .def("vec", [](const ParmsID& p){
            std::vector<uint64_t> ret;
            ret.reserve(troy::util::HashFunction::hash_block_uint64_count);
            for (size_t i = 0; i < ret.size(); i++) {
                ret.push_back(p[i]);
            }
            return ret;
        });

    py::class_<EncryptionParameters>(m, "EncryptionParameters")
        .def(py::init<SchemeType>())
        .def("set_poly_modulus_degree", &EncryptionParameters::setPolyModulusDegree)
        .def("set_coeff_modulus", &EncryptionParameters::setCoeffModulus)
        .def("set_plain_modulus", py::overload_cast<uint64_t>(&EncryptionParameters::setPlainModulus))
        .def("set_plain_modulus", py::overload_cast<const Modulus&>(&EncryptionParameters::setPlainModulus))
        .def("scheme", &EncryptionParameters::scheme)
        .def("poly_modulus_degree", &EncryptionParameters::polyModulusDegree)
        .def("coeff_modulus", [](const EncryptionParameters& self) {
            return deviceArrayToVector(self.coeffModulus());
        })
        .def("parms_id", &EncryptionParameters::parmsID)
        ;

    py::class_<SEALContext::ContextDataCuda, std::shared_ptr<SEALContext::ContextDataCuda>>(m, "ContextData")
        .def("parms", &SEALContext::ContextDataCuda::parms)
        .def("parms_id", &SEALContext::ContextDataCuda::parmsID)
        .def("chain_index", &SEALContext::ContextDataCuda::chainIndex)
        .def("prev_context_data", &SEALContext::ContextDataCuda::prevContextData)
        .def("next_context_data", &SEALContext::ContextDataCuda::nextContextData)
        ;

    py::class_<SEALContext>(m, "SEALContext")
        .def(py::init<EncryptionParameters, bool, SecurityLevel>(),
            py::arg("parms"),
            py::arg("expand_mod_chain") = true, py::arg("sec_level") = SecurityLevel::tc128)
        .def("get_context_data", &SEALContext::getContextData)
        .def("first_context_data", &SEALContext::firstContextData)
        .def("last_context_data", &SEALContext::lastContextData)
        .def("key_context_data", &SEALContext::keyContextData)
        .def("first_parms_id", &SEALContext::firstParmsID)
        .def("last_parms_id", &SEALContext::lastParmsID)
        .def("key_parms_id", &SEALContext::keyParmsID)
        .def("using_keyswitching", &SEALContext::using_keyswitching)
        ;
    
    py::class_<Plaintext>(m, "Plaintext")
        .def(py::init<>())
        .def("set_zero", py::overload_cast<>(&Plaintext::setZero))
        .def("coeff_count", &Plaintext::coeffCount)
        .def("is_ntt_form", &Plaintext::isNttForm)
		.def("parms_id", py::overload_cast<>(&Plaintext::parmsID, py::const_), py::return_value_policy::reference)
        .def("set_parms_id", [](Plaintext& self, const ParmsID& p) {
            self.parmsID() = p;
        })
        .def("scale", py::overload_cast<>(&Plaintext::scale, py::const_))
        .def("set_scale", [](Plaintext& self, double s) {
            self.scale() = s;
        })
        .def("copy", [](const Plaintext& p) {
            return Plaintext(p);
        })
        .def("save", [](const Plaintext& p) {
            SAVE_MACRO
        })
        .def("load", [](Plaintext& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<Ciphertext>(m, "Ciphertext")
        .def(py::init<>())
        .def(py::init<const SEALContext&>())
        .def(py::init<const SEALContext&, ParmsID>())
        .def(py::init<const SEALContext&, ParmsID, size_t>())
        .def("correction_factor", py::overload_cast<>(&Ciphertext::correctionFactor, py::const_))
        .def("set_correction_factor", [](Ciphertext& self, uint64_t c) {
            self.correctionFactor() = c;
        })
        .def("resize", py::overload_cast<size_t>(&Ciphertext::resize))
        .def("reserve", py::overload_cast<size_t>(&Ciphertext::reserve))
		.def("parms_id", py::overload_cast<>(&Ciphertext::parmsID, py::const_), py::return_value_policy::reference)
        .def("set_parms_id", [](Ciphertext& self, const ParmsID& p) {
            self.parmsID() = p;
        })
        .def("scale", py::overload_cast<>(&Ciphertext::scale, py::const_))
        .def("set_scale", [](Ciphertext& self, double s) {
            self.scale() = s;
        })
        .def("is_ntt_form", py::overload_cast<>(&Ciphertext::isNttForm, py::const_))
        .def("coeff_modulus_size", &Ciphertext::coeffModulusSize)
        .def("poly_modulus_degree", &Ciphertext::polyModulusDegree)
        .def("copy", [](const Ciphertext& p) {
            return Ciphertext(p);
        })
        .def("save", [](const Ciphertext& p) {
            SAVE_MACRO
        })
        .def("save_terms", [](const Ciphertext& p, Evaluator& evaluator, py::array_t<size_t> terms){
            ostringstream stream; p.saveTerms(stream, evaluator, getVectorFromBuffer(terms)); return py::bytes(stream.str());
        })
        .def("load", [](Ciphertext& self, const py::bytes& str) {
            LOAD_MACRO
        })
        .def("load", [](Ciphertext& self, const py::bytes& str, const SEALContext& context){
            istringstream stream(str); self.load(stream, context);
        })
        .def("load_terms", [](Ciphertext& self, const py::bytes& str, Evaluator& evaluator, py::array_t<size_t> terms){
            istringstream stream(str); self.loadTerms(stream, evaluator, getVectorFromBuffer(terms));
        })
        ;

    py::class_<KeyGenerator>(m, "KeyGenerator")
        .def(py::init<const SEALContext&>())
        .def("secret_key", &KeyGenerator::secretKey)
        .def("create_public_key", py::overload_cast<PublicKey&>(
            &KeyGenerator::createPublicKey, py::const_
        ))
        .def("create_public_key", py::overload_cast<>(
            &KeyGenerator::createPublicKey, py::const_
        ))
        .def("create_relin_keys", py::overload_cast<RelinKeys&>(
            &KeyGenerator::createRelinKeys
        ))
        .def("create_relin_keys", py::overload_cast<>(
            &KeyGenerator::createRelinKeys
        ))
        .def("create_galois_keys", py::overload_cast<GaloisKeys&>(
            &KeyGenerator::createGaloisKeys
        ))
        .def("create_galois_keys", py::overload_cast<>(
            &KeyGenerator::createGaloisKeys
        ))
        .def("create_galois_keys", py::overload_cast<const vector<int>&, GaloisKeys&>(
            &KeyGenerator::createGaloisKeys
        ))
        .def("create_galois_keys", py::overload_cast<const vector<int>&, >(
            &KeyGenerator::createGaloisKeys
        ))
        ;

    py::class_<SecretKey>(m, "SecretKey")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&SecretKey::parmsID, py::const_))
        .def("save", [](const SecretKey& p) {
            SAVE_MACRO
        })
        .def("load", [](SecretKey& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<PublicKey>(m, "PublicKey")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&PublicKey::parmsID, py::const_))
        .def("save", [](const PublicKey& p) {
            SAVE_MACRO
        })
        .def("load", [](PublicKey& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<KSwitchKeys>(m, "KSwitchKeys")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&KSwitchKeys::parmsID, py::const_))
        .def("save", [](const KSwitchKeys& p) {
            SAVE_MACRO
        })
        .def("load", [](KSwitchKeys& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<RelinKeys>(m, "RelinKeys")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&RelinKeys::parmsID, py::const_))
        .def("save", [](const RelinKeys& p) {
            SAVE_MACRO
        })
        .def("load", [](RelinKeys& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<GaloisKeys>(m, "GaloisKeys")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&GaloisKeys::parmsID, py::const_))
        .def("save", [](const GaloisKeys& p) {
            SAVE_MACRO
        })
        .def("load", [](GaloisKeys& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<BatchEncoder>(m, "BatchEncoder")
        .def(py::init<const SEALContext&>())
        .def("encode_int64", [](const BatchEncoder& self, py::array_t<int64_t> t, Plaintext& p){
            self.encode(getVectorFromBuffer(t), p);
        })
        .def("encode", [](const BatchEncoder& self, py::array_t<uint64_t> t, Plaintext& p){
            self.encode(getVectorFromBuffer(t), p);
        })
        .def("encode_int64", [](const BatchEncoder& self, py::array_t<int64_t> t) {
            Plaintext p; self.encode(getVectorFromBuffer(t), p); return p;
        })
        .def("encode", [](const BatchEncoder& self, py::array_t<uint64_t> t) {
            Plaintext p; self.encode(getVectorFromBuffer(t), p); return p;
        })
        .def("encode_polynomial", [](const BatchEncoder& self, py::array_t<uint64_t> t) {
            Plaintext p; self.encodePolynomial(getVectorFromBuffer(t), p); return p;
        })
        .def("decode_int64", [](const BatchEncoder& self, const Plaintext& plain) {
            vector<int64_t> ret; self.decode(plain, ret); return getBufferFromVector(ret);
        })
        .def("decode", [](const BatchEncoder& self, const Plaintext& plain) {
            vector<uint64_t> ret; self.decode(plain, ret); return getBufferFromVector(ret);
        })
        .def("decode_polynomial", [](const BatchEncoder& self, const Plaintext& plain) {
            vector<uint64_t> ret; self.decodePolynomial(plain, ret); return getBufferFromVector(ret);
        })
        .def("slot_count", &BatchEncoder::slotCount)
        ;

    py::class_<CKKSEncoder>(m, "CKKSEncoder")
        .def(py::init<const SEALContext&>())
        .def("encode", [](CKKSEncoder& self, py::array_t<complex<double>> v, double scale, Plaintext& p){
            self.encode(getVectorFromBuffer(v), scale, p);
        })
        .def("encode", [](CKKSEncoder& self, py::array_t<complex<double>> v, ParmsID parms_id, double scale, Plaintext& p){
            self.encode(getVectorFromBuffer(v), parms_id, scale, p);
        })
        .def("encode_polynomial", [](CKKSEncoder& self, py::array_t<double> v, double scale, Plaintext& p){
            self.encodePolynomial(getVectorFromBuffer(v), scale, p);
        })
        .def("encode_polynomial", [](CKKSEncoder& self, py::array_t<double> v, ParmsID parms_id, double scale, Plaintext& p){
            self.encodePolynomial(getVectorFromBuffer(v), parms_id, scale, p);
        })
        .def("encode", py::overload_cast<complex<double>, double, Plaintext&>(&CKKSEncoder::encode))
        .def("encode", py::overload_cast<complex<double>, ParmsID, double, Plaintext&>(&CKKSEncoder::encode))
        .def("encode", [](CKKSEncoder& self, py::array_t<complex<double>> v, double scale) {
            Plaintext p; self.encode(getVectorFromBuffer(v), scale, p); return p;
        })
        .def("encode", [](CKKSEncoder& self, py::array_t<complex<double>> v, ParmsID parms_id, double scale) {
            Plaintext p; self.encode(getVectorFromBuffer(v), parms_id, scale, p); return p;
        })
        .def("encode_polynomial", [](CKKSEncoder& self, py::array_t<double> values, double scale) {
            Plaintext p; 
            self.encodePolynomial(getVectorFromBuffer(values), scale, p); 
            return p;
        })
        .def("encode_polynomial", [](CKKSEncoder& self, py::array_t<double> v, ParmsID parms_id, double scale) {
            Plaintext p; self.encodePolynomial(getVectorFromBuffer(v), parms_id, scale, p); return p;
        })
        .def("encode", [](CKKSEncoder& self, complex<double> v, double scale) {
            Plaintext p; self.encode(v, scale, p); return p;
        })
        .def("encode", [](CKKSEncoder& self, complex<double> v, ParmsID parms_id, double scale) {
            Plaintext p; self.encode(v, parms_id, scale, p); return p;
        })
        .def("decode", [](CKKSEncoder& self, const Plaintext& plain) {
            vector<complex<double>> ret; self.decode(plain, ret); return getBufferFromVector(ret);
        })
        .def("decode_polynomial", [](CKKSEncoder& self, const Plaintext& plain) {
            vector<double> ret; self.decodePolynomial(plain, ret); return getBufferFromVector(ret);
        })
        .def("slot_count", &CKKSEncoder::slotCount)
        ;

    py::class_<Encryptor>(m, "Encryptor")
        .def(py::init<const SEALContext&, const PublicKey&>())
        .def(py::init<const SEALContext&, const SecretKey&>())
        .def(py::init<const SEALContext&, const PublicKey&, const SecretKey&>())
        .def("set_public_key", &Encryptor::setPublicKey)
        .def("set_secret_key", &Encryptor::setSecretKey)

        .def("encrypt", py::overload_cast<const Plaintext&, Ciphertext&>(&Encryptor::encrypt, py::const_))
        .def("encrypt_zero", py::overload_cast<Ciphertext&>(&Encryptor::encryptZero, py::const_))
        .def("encrypt_zero", py::overload_cast<ParmsID, Ciphertext&>(&Encryptor::encryptZero, py::const_))
        .def("encrypt_symmetric", py::overload_cast<const Plaintext&, Ciphertext&>(&Encryptor::encryptSymmetric, py::const_))
        .def("encrypt_zero_symmetric", py::overload_cast<Ciphertext&>(&Encryptor::encryptZeroSymmetric, py::const_))
        .def("encrypt_zero_symmetric", py::overload_cast<ParmsID, Ciphertext&>(&Encryptor::encryptZeroSymmetric, py::const_))

        .def("encrypt", [](const Encryptor& self, const Plaintext& plain) {
            Ciphertext ret; self.encrypt(plain, ret); return ret;
        })
        .def("encrypt_zero", [](const Encryptor& self) {
            Ciphertext ret; self.encryptZero(ret); return ret;
        })
        .def("encrypt_zero", [](const Encryptor& self, ParmsID parms_id) {
            Ciphertext ret; self.encryptZero(parms_id, ret); return ret;
        })
        .def("encrypt_symmetric", [](const Encryptor& self, const Plaintext& plain) {
            Ciphertext ret; self.encryptSymmetric(plain, ret); return ret;
        })
        .def("encrypt_zero_symmetric", [](const Encryptor& self) {
            Ciphertext ret; self.encryptZeroSymmetric(ret); return ret;
        })
        .def("encrypt_zero_symmetric", [](const Encryptor& self, ParmsID parms_id) {
            Ciphertext ret; self.encryptZeroSymmetric(parms_id, ret); return ret;
        })

        ;

    py::class_<Decryptor>(m, "Decryptor")
        .def(py::init<const SEALContext&, const SecretKey&>())
        .def("decrypt", &Decryptor::decrypt)
        .def("decrypt", [](Decryptor& self, const Ciphertext& cipher) {
            Plaintext p; self.decrypt(cipher, p); return p;
        })
        ;

    py::class_<Evaluator>(m, "Evaluator")
        .def(py::init<const SEALContext&>())

        .def("negate_inplace",             &Evaluator::negateInplace)
        .def("negate", [](const Evaluator& self, const Ciphertext& c) {
            Ciphertext ret; self.negate(c, ret); return ret;
        })
        .def("negate",                     &Evaluator::negate)

        .def("add_inplace",                &Evaluator::addInplace)
        .def("add", [](const Evaluator& self, const Ciphertext& c1, const Ciphertext& c2) {
            Ciphertext ret; self.add(c1, c2, ret); return ret;
        })
        .def("add",                        &Evaluator::add)

        .def("add_many",                   &Evaluator::addMany)
        .def("add_many", [](const Evaluator& self, const vector<Ciphertext>& c) {
            Ciphertext ret; self.addMany(c, ret); return ret;
        })

        .def("sub_inplace",                &Evaluator::subInplace)
        .def("sub", [](const Evaluator& self, const Ciphertext& c1, const Ciphertext& c2) {
            Ciphertext ret; self.sub(c1, c2, ret); return ret;
        })
        .def("sub",                        &Evaluator::sub)

        .def("multiply_inplace",           &Evaluator::multiplyInplace)
        .def("multiply", [](const Evaluator& self, const Ciphertext& c1, const Ciphertext& c2) {
            Ciphertext ret; self.multiply(c1, c2, ret); return ret;
        })
        .def("multiply",                   &Evaluator::multiply)

        .def("square_inplace",             &Evaluator::squareInplace)
        .def("square", [](const Evaluator& self, const Ciphertext& c) {
            Ciphertext ret; self.square(c, ret); return ret;
        })
        .def("square",                     &Evaluator::square)

        .def("relinearize_inplace",        &Evaluator::relinearizeInplace)
        .def("relinearize",                &Evaluator::relinearize)
        .def("relinearize", [](const Evaluator& self, const Ciphertext& c, const RelinKeys& relin_keys) {
            Ciphertext ret; self.relinearize(c, relin_keys, ret); return ret;
        })

        .def("mod_switch_to_next_inplace", py::overload_cast<Ciphertext&>(
            &Evaluator::modSwitchToNextInplace, py::const_
        ))
        .def("mod_switch_to_next_inplace", py::overload_cast<Plaintext&>(
            &Evaluator::modSwitchToNextInplace, py::const_
        ))
        .def("mod_switch_to_next", py::overload_cast<const Ciphertext&, Ciphertext&>(
            &Evaluator::modSwitchToNext, py::const_
        ))
        .def("mod_switch_to_next", [](const Evaluator& self, const Ciphertext& c) {
            Ciphertext ret; self.modSwitchToNext(c, ret); return ret;
        })
        .def("mod_switch_to_next", py::overload_cast<const Plaintext&, Plaintext&>(
            &Evaluator::modSwitchToNext, py::const_
        ))
        .def("mod_switch_to_next", [](const Evaluator& self, const Plaintext& p) {
            Plaintext ret; self.modSwitchToNext(p, ret); return ret;
        })

        .def("mod_switch_to_inplace", py::overload_cast<Ciphertext&, ParmsID>(
            &Evaluator::modSwitchToInplace, py::const_
        ))
        .def("mod_switch_to_inplace", py::overload_cast<Plaintext&, ParmsID>(
            &Evaluator::modSwitchToInplace, py::const_
        ))
        .def("mod_switch_to", py::overload_cast<const Ciphertext&, ParmsID, Ciphertext&>(
            &Evaluator::modSwitchTo, py::const_
        ))
        .def("mod_switch_to", [](const Evaluator& self, ParmsID parms_id, const Ciphertext& c) {
            Ciphertext ret; self.modSwitchTo(c, parms_id, ret); return ret;
        })
        .def("mod_switch_to", py::overload_cast<const Plaintext&, ParmsID, Plaintext&>(
            &Evaluator::modSwitchTo, py::const_
        ))
        .def("mod_switch_to", [](const Evaluator& self, ParmsID parms_id, const Plaintext& p) {
            Plaintext ret; self.modSwitchTo(p, parms_id, ret); return ret;
        })

        .def("rescale_to_next_inplace", &Evaluator::rescaleToNextInplace)
        .def("rescale_to_next", &Evaluator::rescaleToNext)
        .def("rescale_to_next", [](const Evaluator& self, const Ciphertext& c) {
            Ciphertext ret; self.rescaleToNext(c, ret); return ret;
        })

        .def("rescale_to_inplace", &Evaluator::rescaleToInplace)
        .def("rescale_to", &Evaluator::rescaleTo)
        .def("rescale_to", [](const Evaluator& self, ParmsID parms_id, const Ciphertext& c) {
            Ciphertext ret; self.rescaleTo(c, parms_id, ret); return ret;
        })

        .def("multiply_many",          &Evaluator::multiplyMany)
        .def("multiply_many", [](const Evaluator& self, const vector<Ciphertext>& c, const RelinKeys&relin_keys) {
            Ciphertext ret; self.multiplyMany(c, relin_keys, ret); return ret;
        })
        .def("exponentiate_inplace",   &Evaluator::exponentiateInplace)
        .def("exponentiate",           &Evaluator::exponentiate)
        .def("exponentiate", [](const Evaluator& self, const Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys) {
            Ciphertext ret; self.exponentiate(encrypted, exponent, relin_keys, ret); return ret;
        })

        .def("add_plain_inplace",      &Evaluator::addPlainInplace)
        .def("add_plain", [](const Evaluator& self, const Ciphertext& c1, const Plaintext& p2) {
            Ciphertext ret; self.addPlain(c1, p2, ret); return ret;
        })
        .def("add_plain",              &Evaluator::addPlain)

        .def("sub_plain_inplace",      &Evaluator::subPlainInplace)
        .def("sub_plain", [](const Evaluator& self, const Ciphertext& c1, const Plaintext& p2) {
            Ciphertext ret; self.subPlain(c1, p2, ret); return ret;
        })
        .def("sub_plain",              &Evaluator::subPlain)

        .def("multiply_plain_inplace", &Evaluator::multiplyPlainInplace)
        .def("multiply_plain", [](const Evaluator& self, const Ciphertext& c1, const Plaintext& p2) {
            Ciphertext ret; 
            // double p = getTime();
            self.multiplyPlain(c1, p2, ret); 
            // printf("time = %lf\n", getTime() - p);
            return ret;
        })
        .def("multiply_plain_1000", [](const Evaluator& self, const Ciphertext& c1, const Plaintext& p2) {
            Ciphertext ret; 
            // double p = getTime();
            for (size_t i = 0; i < 1000; i++) self.multiplyPlain(c1, p2, ret); 
            // printf("time = %lf\n", getTime() - p);
            return ret;
        })
        .def("multiply_batch", [](const Evaluator& self, const vector<Ciphertext>& c1, const vector<Plaintext>& p2) {
            vector<Ciphertext> ret(c1.size());
            for (size_t i = 0; i < c1.size(); i++) self.multiplyPlain(c1[i], p2[i], ret[i]);
            return ret;
        })

        .def("multiply_plain",         &Evaluator::multiplyPlain)

        .def("transform_to_ntt_inplace", py::overload_cast<Plaintext&, ParmsID>(
            &Evaluator::transformToNttInplace, py::const_
        ))
        .def("transform_to_ntt_inplace", py::overload_cast<Ciphertext&>(
            &Evaluator::transformToNttInplace, py::const_
        ))

        .def("transform_to_ntt", py::overload_cast<const Plaintext&, ParmsID, Plaintext&>(
            &Evaluator::transformToNtt, py::const_
        ))
        .def("transform_to_ntt", [](const Evaluator& self, const Plaintext& plaintext, ParmsID parms_id) {
            Plaintext ret; self.transformToNtt(plaintext, parms_id, ret); return ret;
        })
        .def("transform_to_ntt", py::overload_cast<const Ciphertext&, Ciphertext&>(
            &Evaluator::transformToNtt, py::const_
        ))
        .def("transform_to_ntt", [](const Evaluator& self, const Ciphertext& cipher) {
            Ciphertext ret; self.transformToNtt(cipher, ret); return ret;
        })

        .def("transform_from_ntt_inplace", py::overload_cast<Ciphertext&>(
            &Evaluator::transformFromNttInplace, py::const_
        ))
        .def("transform_from_ntt", py::overload_cast<const Ciphertext&, Ciphertext&>(
            &Evaluator::transformFromNtt, py::const_
        ))
        .def("transform_to_ntt", [](const Evaluator& self, const Ciphertext& cipher) {
            Ciphertext ret; self.transformFromNtt(cipher, ret); return ret;
        })

        .def("apply_galois_inplace", &Evaluator::applyGaloisInplace)
        .def("apply_galois", &Evaluator::applyGalois)
        .def("apply_galois", [](const Evaluator& self, const Ciphertext& cipher, std::uint32_t galois_elt, const GaloisKeys &galois_keys) {
            Ciphertext ret; self.applyGalois(cipher, galois_elt, galois_keys, ret); return ret;
        })

        .def("rotate_rows_inplace", &Evaluator::rotateRowsInplace)
        .def("rotate_rows", &Evaluator::rotateRows)
        .def("rotate_rows", [](const Evaluator& self, const Ciphertext& cipher, int steps, const GaloisKeys &galois_keys) {
            Ciphertext ret; self.rotateRows(cipher, steps, galois_keys, ret); return ret;
        })

        .def("rotate_columns_inplace", &Evaluator::rotateColumnsInplace)
        .def("rotate_columns", &Evaluator::rotateColumns)
        .def("rotate_rows", [](const Evaluator& self, const Ciphertext& cipher, const GaloisKeys &galois_keys) {
            Ciphertext ret; self.rotateColumns(cipher, galois_keys, ret); return ret;
        })

        .def("rotate_vector_inplace", &Evaluator::rotateVectorInplace)
        .def("rotate_vector", &Evaluator::rotateVector)
        .def("rotate_vector", [](const Evaluator& self, const Ciphertext& cipher, int steps, const GaloisKeys &galois_keys) {
            Ciphertext ret; self.rotateVector(cipher, steps, galois_keys, ret); return ret;
        })

        .def("complex_conjugate_inplace", &Evaluator::complexConjugateInplace)
        .def("complex_conjugate", &Evaluator::complexConjugate)
        .def("complex_conjugate", [](const Evaluator& self, const Ciphertext& cipher, const GaloisKeys &galois_keys) {
            Ciphertext ret; self.complexConjugate(cipher, galois_keys, ret); return ret;
        })
        
        ;

    py::class_<Cipher2d>(m, "Cipher2d")
        .def(py::init<>())
        .def("save", [](const Cipher2d& p){
            ostringstream stream; p.save(stream); return py::bytes(stream.str());
        })
        .def("load", [](Cipher2d& self, const py::bytes& str) {
            LOAD_MACRO
        })
        .def("load", [](Cipher2d& self, const py::bytes& str, const SEALContext& context){
            istringstream stream(str); self.load(stream, context);
        })
        .def("add_inplace", [](Cipher2d& self, const Evaluator& evaluator, const Cipher2d& x){
            self.addInplace(evaluator, x);
        })
        .def("add_plain_inplace", [](Cipher2d& self, const Evaluator& evaluator, const Plain2d& x){
            self.addPlainInplace(evaluator, x);
        })
        .def("add_plain", [](const Cipher2d& self, const Evaluator& evaluator, Plain2d& x){
            return self.addPlain(evaluator, x);
        })
        .def("mod_switch_to_next", [](Cipher2d& self, const Evaluator& evaluator){
            self.modSwitchToNext(evaluator);
        })
        ;

    py::class_<Plain2d>(m, "Plain2d")
        .def("encrypt", [](const Plain2d& self, const Encryptor& encryptor){
            return self.encrypt(encryptor);
        })
        ;

    /*

    py::class_<MatmulHelper>(m, "MatmulHelper")
        .def(py::init<size_t, size_t, size_t, size_t>())
        .def("encode_weights", [](MatmulHelper& self, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> weights, double scale){
            self.encodeWeights(encoder, parmsID, getVectorFromBuffer(weights), scale);
        })
        .def("encode_inputs", [](MatmulHelper& self, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> inputs, double scale){
            return self.encodeInputs(encoder, parmsID, getVectorFromBuffer(inputs), scale);
        })
        .def("encrypt_inputs", [](MatmulHelper& self, const Encryptor& encryptor, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> inputs, double scale){
            return self.encryptInputs(encryptor, encoder, parmsID, getVectorFromBuffer(inputs), scale);
        })
        .def("matmul", [](MatmulHelper& self, const Evaluator& evaluator, const Cipher2d& a){
            return self.matmul(evaluator, a);
        })
        .def("encode_outputs", [](MatmulHelper& self, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> outputs, double scale){
            return self.encodeOutputs(encoder, parmsID, getVectorFromBuffer(outputs), scale);
        })
        .def("add_plain_inplace", [](MatmulHelper& self, const Evaluator& evaluator, Cipher2d& y, const Plain2d& x) {
            self.addPlainInplace(evaluator, y, x);
        })
        .def("decrypt_outputs", [](MatmulHelper& self, CKKSEncoder& encoder, Decryptor& decryptor, const Cipher2d& outputs) {
            return getBufferFromVector(self.decryptOutputs(encoder, decryptor, outputs));
        })
        .def("serialize_outputs", [](MatmulHelper& self, Evaluator& evaluator, const Cipher2d& x) {
            ostringstream stream; self.serializeOutputs(evaluator, x, stream);
            return py::bytes(stream.str());
        })
        .def("deserialize_outputs", [](MatmulHelper& self, Evaluator& evaluator, const py::bytes& str) {
            istringstream stream(str);
            return self.deserializeOutputs(evaluator, stream);
        })
        ;

    py::class_<Conv2dHelper>(m, "Conv2dHelper")
        .def(py::init<size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t>())
        .def("encode_weights", [](Conv2dHelper& self, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> weights, double scale){
            self.encodeWeights(encoder, parmsID, getVectorFromBuffer(weights), scale);
        })
        .def("encode_inputs", [](Conv2dHelper& self, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> inputs, double scale){
            return self.encodeInputs(encoder, parmsID, getVectorFromBuffer(inputs), scale);
        })
        .def("encrypt_inputs", [](Conv2dHelper& self, const Encryptor& encryptor, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> inputs, double scale){
            return self.encryptInputs(encryptor, encoder, parmsID, getVectorFromBuffer(inputs), scale);
        })
        .def("conv2d", [](Conv2dHelper& self, const Evaluator& evaluator, const Cipher2d& a){
            return self.conv2d(evaluator, a);
        })
        .def("encode_outputs", [](Conv2dHelper& self, CKKSEncoder& encoder, ParmsID parmsID, py::array_t<double> outputs, double scale){
            return self.encodeOutputs(encoder, parmsID, getVectorFromBuffer(outputs), scale);
        })
        .def("add_plain_inplace", [](Conv2dHelper& self, const Evaluator& evaluator, Cipher2d& y, const Plain2d& x) {
            self.addPlainInplace(evaluator, y, x);
        })
        .def("add_inplace", [](Conv2dHelper& self, const Evaluator& evaluator, Cipher2d& y, const Cipher2d& x) {
            self.addInplace(evaluator, y, x);
        })
        .def("decrypt_outputs", [](Conv2dHelper& self, CKKSEncoder& encoder, Decryptor& decryptor, const Cipher2d& outputs) {
            return getBufferFromVector(self.decryptOutputs(encoder, decryptor, outputs));
        })
        .def("serialize_outputs", [](Conv2dHelper& self, Evaluator& evaluator, const Cipher2d& x) {
            ostringstream stream; self.serializeOutputs(evaluator, x, stream);
            return py::bytes(stream.str());
        })
        .def("deserialize_outputs", [](Conv2dHelper& self, Evaluator& evaluator, const py::bytes& str) {
            istringstream stream(str);
            return self.deserializeOutputs(evaluator, stream);
        })
        ;

    */
    
    py::class_<MatmulHelper>(m, "MatmulHelper")
        .def(py::init<size_t, size_t, size_t, size_t>())
        .def("encode_weights", [](MatmulHelper& self, BatchEncoder& encoder, py::array_t<uint64_t> weights){
            return self.encodeWeights(encoder, getPtrFromBuffer(weights));
        })
        .def("encode_inputs", [](MatmulHelper& self, BatchEncoder& encoder, py::array_t<uint64_t> inputs){
            return self.encodeInputs(encoder, getPtrFromBuffer(inputs));
        })
        .def("encrypt_inputs", [](MatmulHelper& self, const Encryptor& encryptor, BatchEncoder& encoder, py::array_t<uint64_t> inputs){
            return self.encryptInputs(encryptor, encoder, getPtrFromBuffer(inputs));
        })
        .def("matmul", [](MatmulHelper& self, const Evaluator& evaluator, const Cipher2d& a, const Plain2d& weights){
            return self.matmul(evaluator, a, weights);
        })
        .def("matmul", [](MatmulHelper& self, const Evaluator& evaluator, const Cipher2d& a, const Cipher2d& weights){
            return self.matmulCipher(evaluator, a, weights);
        })
        .def("matmul", [](MatmulHelper& self, const Evaluator& evaluator, const Plain2d& a, const Cipher2d& weights){
            return self.matmulReverse(evaluator, a, weights);
        })
        .def("encode_outputs", [](MatmulHelper& self, BatchEncoder& encoder, py::array_t<uint64_t> outputs){
            return self.encodeOutputs(encoder, getPtrFromBuffer(outputs));
        })
        .def("decrypt_outputs", [](MatmulHelper& self, BatchEncoder& encoder, Decryptor& decryptor, const Cipher2d& outputs) {
            return getBufferFromVector(self.decryptOutputs(encoder, decryptor, outputs));
        })
        .def("serialize_outputs", [](MatmulHelper& self, Evaluator& evaluator, const Cipher2d& x) {
            ostringstream stream; self.serializeOutputs(evaluator, x, stream);
            return py::bytes(stream.str());
        })
        .def("deserialize_outputs", [](MatmulHelper& self, Evaluator& evaluator, const py::bytes& str) {
            istringstream stream(std::move(str));
            return self.deserializeOutputs(evaluator, stream);
        })
        .def("serialize_encoded_weights", [](MatmulHelper& self, const Plain2d& x) {
            ostringstream stream; self.serializeEncodedWeights(x, stream);
            return py::bytes(stream.str());
        })
        .def("deserialize_encoded_weights", [](MatmulHelper& self, const py::bytes& str) {
            istringstream stream(std::move(str));
            return self.deserializeEncodedWeights(stream);
        })
        ;

    py::class_<Conv2dHelper>(m, "Conv2dHelper")
        .def(py::init<size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t>())
        .def("encode_weights", [](Conv2dHelper& self, BatchEncoder& encoder, py::array_t<uint64_t> weights){
            return self.encodeWeights(encoder, getVectorFromBuffer(weights));
        })
        .def("encode_inputs", [](Conv2dHelper& self, BatchEncoder& encoder, py::array_t<uint64_t> inputs){
            return self.encodeInputs(encoder, getVectorFromBuffer(inputs));
        })
        .def("encrypt_inputs", [](Conv2dHelper& self, const Encryptor& encryptor, BatchEncoder& encoder, py::array_t<uint64_t> inputs){
            return self.encryptInputs(encryptor, encoder, getVectorFromBuffer(inputs));
        })
        .def("conv2d", [](Conv2dHelper& self, const Evaluator& evaluator, const Cipher2d& a, const Plain2d& weights){
            return self.conv2d(evaluator, a, weights);
        })
        .def("conv2d", [](Conv2dHelper& self, const Evaluator& evaluator, const Cipher2d& a, const Cipher2d& weights){
            return self.conv2dCipher(evaluator, a, weights);
        })
        .def("conv2d", [](Conv2dHelper& self, const Evaluator& evaluator, const Plain2d& a, const Cipher2d& weights){
            return self.conv2dReverse(evaluator, a, weights);
        })
        .def("encode_outputs", [](Conv2dHelper& self, BatchEncoder& encoder, py::array_t<uint64_t> outputs){
            return self.encodeOutputs(encoder, getVectorFromBuffer(outputs));
        })
        .def("decrypt_outputs", [](Conv2dHelper& self, BatchEncoder& encoder, Decryptor& decryptor, const Cipher2d& outputs) {
            return getBufferFromVector(self.decryptOutputs(encoder, decryptor, outputs));
        })
        .def("serialize_outputs", [](Conv2dHelper& self, Evaluator& evaluator, const Cipher2d& x) {
            ostringstream stream; self.serializeOutputs(evaluator, x, stream);
            return py::bytes(stream.str());
        })
        .def("deserialize_outputs", [](Conv2dHelper& self, Evaluator& evaluator, const py::bytes& str) {
            istringstream stream(str);
            return self.deserializeOutputs(evaluator, stream);
        })
        ;

}