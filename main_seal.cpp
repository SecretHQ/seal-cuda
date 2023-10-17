
#include <vector>
#include <string>
#include <sys/time.h>
#include <cassert>
#include <map>
#include <complex>
#include <iostream>
#include <iomanip>

#include <seal/seal.h>

using std::vector;
using std::complex;

using namespace seal;

namespace troytest {
    
    class Timer {
    public:
        std::vector<timeval> times;
        std::vector<double> accumulated; // ms
        std::vector<std::string> names;
        Timer() {}
        long registerTimer(std::string name = "") {
            times.push_back(timeval()); 
            accumulated.push_back(0);
            int ret = times.size() - 1;
            names.push_back(name);
            return ret;
        }
        void tick(long i = 0) {
            if (times.size() < 1) registerTimer();
            assert(i < times.size());
            gettimeofday(&times[i], 0);
        }
        double tock(long i = 0) {
            assert(i < times.size());
            timeval s; gettimeofday(&s, 0);
            auto timeElapsed = (s.tv_sec - times[i].tv_sec) * 1000.0;
            timeElapsed += (s.tv_usec - times[i].tv_usec) / 1000.0;
            accumulated[i] += timeElapsed;
            return accumulated[i];
        }
        
        void clear() {
            times.clear();
            accumulated.clear();
            names.clear();
        }

        std::map<std::string, double> gather(double divisor = 1) {
            std::map<std::string, double> p;
            for (long i=0; i<times.size(); i++) {
                p[names[i]] = accumulated[i] / divisor;
            }
            clear();
            return p;
        }
    };

    class TimeTest {
        
    protected:
        Timer tim;
        Encryptor* encryptor;
        Decryptor* decryptor;
        Evaluator* evaluator;
        SEALContext* context;
        RelinKeys rlk;
        PublicKey pk;
        GaloisKeys gk;
        KeyGenerator* keygen;

    public:
        TimeTest() {
            tim.clear();
            encryptor = nullptr;
            evaluator = nullptr;
            context = nullptr;
            decryptor = nullptr;
        }

        ~TimeTest() {
            if (encryptor) delete encryptor;
            if (evaluator) delete evaluator;
            if (context) delete context;
            if (decryptor) delete decryptor;
            if (keygen) delete keygen;
        }

        virtual Plaintext randomPlaintext() = 0;
        virtual Ciphertext randomCiphertext() = 0;
        // virtual void testEncode() = 0;

        void testEncrypt(int repeatCount = 1000) {
            auto p1 = randomPlaintext();
            Ciphertext c2;
            Plaintext p2;
            auto t1 = tim.registerTimer("Encrypt");
            auto t2 = tim.registerTimer("Decrypt");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                encryptor->encrypt(p1, c2);
                tim.tock(t1);
                tim.tick(t2);
                decryptor->decrypt(c2, p2);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void printTimer(std::map<std::string, double> r) {
            for (auto& p: r) {
                std::cout << std::setw(25) << std::right << p.first << ":";
                std::cout << std::setw(10) << std::right << std::fixed << std::setprecision(3)
                    << p.second << std::endl;
            }
        }

        void testAdd(int repeatCount = 1000) {
            auto c1 = randomCiphertext();
            auto c2 = randomCiphertext();
            Ciphertext c3;
            auto t1 = tim.registerTimer("Add-assign");
            auto t2 = tim.registerTimer("Add-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->add(c1, c2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->add_inplace(c3, c1);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testAddPlain(int repeatCount = 1000) {
            auto c1 = randomCiphertext();
            auto p2 = randomPlaintext();
            Ciphertext c3;
            auto t1 = tim.registerTimer("AddPlain-assign");
            auto t2 = tim.registerTimer("AddPlain-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->add_plain(c1, p2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->add_plain_inplace(c3, p2);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testMultiplyPlain(int repeatCount = 1000) {
            auto c1 = randomCiphertext();
            auto p2 = randomPlaintext();
            Ciphertext c3;
            auto t1 = tim.registerTimer("MultiplyPlain-assign");
            auto t2 = tim.registerTimer("MultiplyPlain-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->multiply_plain(c1, p2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->multiply_plain_inplace(c3, p2);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testSquare(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            Ciphertext c2;
            Ciphertext c3;
            auto t1 = tim.registerTimer("Square-assign");
            auto t2 = tim.registerTimer("Square-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->square(c1, c2);
                tim.tock(t1);
                c3 = c1;
                tim.tick(t2);
                evaluator->square_inplace(c3);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

    };

    class TimeTestCKKS: public TimeTest {

        CKKSEncoder* encoder;
        size_t slotCount;
        int dataBound;
        double delta;
    
    public:

        TimeTestCKKS(size_t polyModulusDegree, vector<int> qs, int dataBound = 1<<6, double delta=static_cast<double>(1<<16)) {
            slotCount = polyModulusDegree / 2;
            this->dataBound = dataBound;
            this->delta = delta;
            EncryptionParameters parms(scheme_type::ckks);
            parms.set_poly_modulus_degree(polyModulusDegree);
            parms.set_coeff_modulus(CoeffModulus::Create(polyModulusDegree, qs));
            context = new SEALContext(parms);
            keygen = new KeyGenerator(*context);
            keygen->create_public_key(pk);
            keygen->create_relin_keys(rlk);
            keygen->create_galois_keys(gk);
            encoder = new CKKSEncoder(*context);
            encryptor = new Encryptor(*context, pk);
            decryptor = new Decryptor(*context, keygen->secret_key());
            evaluator = new Evaluator(*context);
        }

        ~TimeTestCKKS() {
            if (encoder) delete encoder;
        }
        
        static vector<complex<double>> randomVector(size_t count, int data_bound) {
            vector<complex<double>> input(count, 0.0);
            for (size_t i = 0; i < count; i++)
            {
                input[i] = static_cast<double>(rand() % data_bound);
            }
            return input;
        }

        Plaintext randomPlaintext() override {
            auto p = randomVector(slotCount, dataBound);
            Plaintext ret; encoder->encode(p, delta, ret);
            return std::move(ret);
        }

        Ciphertext randomCiphertext() override {
            auto r = randomPlaintext();
            Ciphertext ret; encryptor->encrypt(r, ret);
            return std::move(ret);
        }

        void testEncode(int repeatCount = 1000) {
            auto m1 = randomVector(slotCount, dataBound);
            auto m2 = randomVector(slotCount, dataBound);
            Plaintext p1;
            auto t1 = tim.registerTimer("Encode");
            auto t2 = tim.registerTimer("Decode");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                encoder->encode(m1, delta, p1);
                tim.tock(t1);
                tim.tick(t2);
                encoder->decode(p1, m2);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testMultiplyRescale(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            auto c2 = randomCiphertext();
            Ciphertext c3, c4;
            Ciphertext c5;
            auto t1 = tim.registerTimer("Multiply-assign");
            auto t2 = tim.registerTimer("Relinearize-assign");
            auto t3 = tim.registerTimer("Multiply-inplace");
            auto t4 = tim.registerTimer("Relinearize-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->multiply(c1, c2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->rescale_to_next(c3, c4);
                tim.tock(t2);
                c5 = c1;
                tim.tick(t3);
                evaluator->multiply_inplace(c5, c2);
                tim.tock(t3);
                tim.tick(t4);
                evaluator->rescale_to_next_inplace(c5);
                tim.tock(t4);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testRotateVector(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            Ciphertext c2;
            auto t1 = tim.registerTimer("Rotate-assign");
            auto t2 = tim.registerTimer("Rotate-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->rotate_vector(c1, 1, gk, c2);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->rotate_vector_inplace(c1, 1, gk);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testAll() {
            this->testEncode();
            this->testEncrypt();
            this->testAdd();
            this->testAddPlain();
            this->testMultiplyRescale();
            this->testMultiplyPlain();
            this->testSquare();
            this->testRotateVector();
        }

    };

    class TimeTestBFVBGV: public TimeTest {

        BatchEncoder* encoder;
        size_t slotCount;
        int dataBound;
        double delta;
    
    public:

        TimeTestBFVBGV(bool bgv, size_t polyModulusDegree, uint64_t plainModulusBitSize, vector<int> qs, int dataBound = 1<<6) {
            slotCount = polyModulusDegree / 2;
            this->dataBound = dataBound;
            this->delta = delta;
            EncryptionParameters parms(bgv ? scheme_type::bgv : scheme_type::bfv);
            parms.set_poly_modulus_degree(polyModulusDegree);
            parms.set_plain_modulus(PlainModulus::Batching(polyModulusDegree, plainModulusBitSize));
            // parms.setCoeffModulus(CoeffModulus::BFVDefault(polyModulusDegree));
            parms.set_coeff_modulus(CoeffModulus::Create(polyModulusDegree, qs));
            context = new SEALContext(parms);
            keygen = new KeyGenerator(*context);
            keygen->create_public_key(pk);
            keygen->create_relin_keys(rlk);
            keygen->create_galois_keys(gk);
            encoder = new BatchEncoder(*context);
            encryptor = new Encryptor(*context, pk);
            decryptor = new Decryptor(*context, keygen->secret_key());
            evaluator = new Evaluator(*context);
        }

        ~TimeTestBFVBGV() {
            if (encoder) delete encoder;
        }
        
        static vector<int64_t> randomVector(size_t count, int data_bound) {
            vector<int64_t> input(count, 0.0);
            for (size_t i = 0; i < count; i++)
            {
                input[i] = rand() % data_bound;
            }
            return input;
        }

        Plaintext randomPlaintext() override {
            auto p = randomVector(slotCount, dataBound);
            Plaintext ret; encoder->encode(p, ret);
            return std::move(ret);
        }

        Ciphertext randomCiphertext() override {
            auto r = randomPlaintext();
            Ciphertext ret; encryptor->encrypt(r, ret);
            return std::move(ret);
        }


        void testEncode(int repeatCount = 1000) {
            auto m1 = randomVector(slotCount, dataBound);
            auto m2 = randomVector(slotCount, dataBound);
            Plaintext p1;
            auto t1 = tim.registerTimer("Encode");
            auto t2 = tim.registerTimer("Decode");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                encoder->encode(m1, p1);
                tim.tock(t1);
                tim.tick(t2);
                encoder->decode(p1, m2);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testMultiplyRescale(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            auto c2 = randomCiphertext();
            Ciphertext c3, c4;
            Ciphertext c5;
            auto t1 = tim.registerTimer("Multiply-assign");
            auto t2 = tim.registerTimer("Relinearize-assign");
            auto t3 = tim.registerTimer("Multiply-inplace");
            auto t4 = tim.registerTimer("Relinearize-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->multiply(c1, c2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->mod_switch_to_next(c3, c4);
                tim.tock(t2);
                c5 = c1;
                tim.tick(t3);
                evaluator->multiply_inplace(c5, c2);
                tim.tock(t3);
                tim.tick(t4);
                evaluator->mod_switch_to_next_inplace(c5);
                tim.tock(t4);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testRotateVector(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            Ciphertext c2;
            auto t1 = tim.registerTimer("RotateRows-assign");
            auto t2 = tim.registerTimer("RotateRows-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->rotate_rows(c1, 1, gk, c2);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->rotate_rows_inplace(c1, 1, gk);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testAll() {
            this->testEncode();
            this->testEncrypt();
            this->testAdd();
            this->testAddPlain();
            this->testMultiplyRescale();
            this->testMultiplyPlain();
            this->testSquare();
            this->testRotateVector();
        }

    };

}

int main() {
    std::cout << "----- CKKS -----\n";
    troytest::TimeTestCKKS test(4096, {50, 50}, 10, 1<<15);
    test.testMultiplyPlain();

    // std::cout << "----- BFV -----\n";
    // troytest::TimeTestBFVBGV test2(false, 8192, 20, {40, 40, 40});
    // test2.testAll();

    // std::cout << "----- BGV -----\n";
    // troytest::TimeTestBFVBGV test3(true, 8192, 20, {40, 40, 40});
    // test3.testAll();
    return 0;
}