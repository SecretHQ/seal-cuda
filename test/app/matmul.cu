#include "../../app/matmul.cuh"

#include <iostream>
#include <iomanip>

using namespace std;
using namespace troyn;

class MatmulTest {

    SEALContext* context;
    Encryptor* encryptor;
    Evaluator* evaluator; 
    Decryptor* decryptor;
    CKKSEncoder* encoder;
    size_t slotCount;
    int dataBound;
    double delta;
    RelinKeys rlk;
    PublicKey pk;
    GaloisKeys gk;
    KeyGenerator* keygen;
    
public:
    MatmulTest(int polyModulusDegree, vector<int> qs, int dataBound = 1<<6, double delta=static_cast<double>(1<<16)) {
        KernelProvider::initialize();
        slotCount = polyModulusDegree / 2;
        this->dataBound = dataBound;
        this->delta = delta;
        EncryptionParameters parms(SchemeType::ckks);
        parms.setPolyModulusDegree(polyModulusDegree);
        parms.setCoeffModulus(CoeffModulus::Create(polyModulusDegree, qs));
        context = new SEALContext(parms);
        keygen = new KeyGenerator(*context);
        keygen->createPublicKey(pk);
        keygen->createRelinKeys(rlk);
        keygen->createGaloisKeys(gk);
        encoder = new CKKSEncoder(*context);
        encryptor = new Encryptor(*context, pk);
        decryptor = new Decryptor(*context, keygen->secretKey());
        evaluator = new Evaluator(*context);
    }

    ~MatmulTest() {
        if (encoder) delete encoder;
        if (encryptor) delete encryptor;
        if (evaluator) delete evaluator;
        if (context) delete context;
        if (decryptor) delete decryptor;
        if (keygen) delete keygen;
    }

    vector<complex<double>> randomVector(size_t count) {
        vector<complex<double>> input(count, 0.0);
        for (size_t i = 0; i < count; i++) {
            input[i] = static_cast<double>(rand() % dataBound);
        }
        return input;
    }

    vector<vector<complex<double>>> randomMatrix(int height, int width) {
        vector<vector<complex<double>>> ret;
        for (size_t i = 0; i < height; i++)
            ret.push_back(randomVector(width));
        return ret;
    }

    vector<complex<double>> multiplyPlain(
        const vector<vector<complex<double>>> w,
        const vector<complex<double>> v)
    {
        assert(w[0].size() == v.size());
        vector<complex<double>> ret; ret.resize(w.size());
        for (int i=0; i<w.size(); i++) {
            complex<double> r = 0;
            for (int j=0; j<v.size(); j++)
                r += w[i][j] * v[j];
            ret[i] = r;
        }
        return ret;
    }

    void printVector(const vector<complex<double>>& r, bool onlyreal = false, bool full = false) {
        std::cout << "[";
        for (size_t i = 0; i < r.size(); i++) {
            if (r.size() > 8 && !full && i == 4) {
                std::cout << " ...";
                i = r.size() - 4;
            }
            if (i!=0) std::cout << ", ";
            if (!onlyreal) {
                std::cout << "("; 
                std::cout << std::setprecision(3) << std::fixed << r[i].real();
                std::cout << ", ";
                std::cout << std::setprecision(3) << std::fixed << r[i].imag();
                std::cout << ")";
            } else {
                std::cout << std::setprecision(3) << std::fixed << r[i].real();
                if (r[i].imag() > 0.05) assert(false);
            }
        }
        std::cout << "]" << std::endl;
    }

    void test(int height, int width) {
        MatmulHelper helper(height, width, slotCount);
        auto input = randomVector(height);
        auto weight = randomMatrix(height, width);
        helper.encode(weight, *encoder, delta);
        auto inputPlaintext = helper.prepareInput(input, *encoder, delta);
        Ciphertext inputCiphertext = encryptor->encrypt(inputPlaintext);
        auto result = helper.multiply(inputCiphertext, *evaluator, gk, false);
        Plaintext deciphered;
        decryptor->decrypt(result, deciphered);
        auto product = helper.decodeResult(deciphered, *encoder);
        auto plainProduct = multiplyPlain(weight, input);
        printVector(product);
        printVector(plainProduct);
    }

};

int main() {
    MatmulTest test(8192, {60, 40, 40, 60}, 64, (double)(1ull<<40));
    test.test(3, 3);
    return 0;
}