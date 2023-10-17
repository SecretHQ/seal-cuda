#include "../../app/LinearHelper.cuh"
#include "sys/time.h"
#include <iomanip>

using namespace troyn;
using namespace std;

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

class LinearTest {

    Encryptor* encryptor;
    Decryptor* decryptor;
    Evaluator* evaluator;
    SEALContext* context;
    RelinKeys rlk;
    PublicKey pk;
    GaloisKeys gk;
    KeyGenerator* keygen;
    EncryptionParameters parms;

    vector<ParmsID> parmIDs;

    BatchEncoder* encoder;
    size_t slotCount;
    int dataBound;
    double delta;
    uint64_t modulus;

public:

    // Plaintext decryptp(const Ciphertext& c) {
    //     Plaintext p; decryptor->decrypt(c, p);
    //     return p;
    // }

    // vector<double> decrypt(const Plaintext& p) {
    //     vector<double> ret; encoder->decodePolynomial(p, ret);
    //     return ret;
    // }

    // vector<double> decrypt(const Ciphertext& c) {
    //     return decrypt(decryptp(c));
    // }

    void printVector(const vector<double>& r, bool full = false) {
        std::cout << "[";
        for (size_t i = 0; i < r.size(); i++) {
            if (r.size() > 8 && !full && i == 4) {
                std::cout << " ...";
                i = r.size() - 4;
            }
            if (i!=0) std::cout << ", ";
            std::cout << std::setprecision(1) << std::fixed << r[i];
        }
        std::cout << "]" << std::endl;
    }

    void printVector(const vector<double>& r, size_t terms) {
        std::cout << "[";
        for (size_t i = 0; i < std::min(r.size(), terms); i++) {
            if (i!=0) std::cout << ", ";
            std::cout << std::setprecision(1) << std::fixed << r[i];
        }
        std::cout << "]" << std::endl;
    }

    void printVector(const vector<uint64_t>& r) {
        std::cout << "[";
        for (size_t i = 0; i < r.size(); i++) {
            if (i!=0) std::cout << ", ";
            std::cout << r[i];
        }
        std::cout << "]" << std::endl;
    }

    void printVector(const vector<uint64_t>& r, size_t terms) {
        std::cout << "[";
        for (size_t i = 0; i < std::min(r.size(), terms); i++) {
            if (i!=0) std::cout << ", ";
            std::cout << r[i];
        }
        std::cout << "]" << std::endl;
    }

    vector<double> randomRealVector(size_t count = 0, int data_bound = 0) {
        if (count == 0) count = slotCount;
        if (data_bound == 0) data_bound = dataBound;
        vector<double> input(count, 0.0);
        for (size_t i = 0; i < count; i++)
        {
            input[i] = (static_cast<double>(rand()) / RAND_MAX - 0.5) * 2 * data_bound;
        }
        return input;
    }

    vector<uint64_t> randomVector(size_t count = 0, uint64_t data_bound = 0) {
        if (count == 0) count = slotCount;
        if (data_bound == 0) data_bound = dataBound;
        vector<uint64_t> input(count, 0.0);
        for (size_t i = 0; i < count; i++)
        {
            input[i] = ((((uint64_t)(rand())) << 32) + ((uint64_t)(rand()))) % data_bound;
        }
        return input;
    }

    void printTimer(std::map<std::string, double> r) {
        for (auto& p: r) {
            std::cout << std::setw(25) << std::right << p.first << ":";
            std::cout << std::setw(10) << std::right << std::fixed << std::setprecision(3)
                << p.second << std::endl;
        }
    }

    LinearTest(size_t polyModulusDegree, vector<int> qs, int dataBound, uint64_t plainModulus, uint64_t scale) {
        KernelProvider::initialize();
        slotCount = polyModulusDegree;
        this->dataBound = dataBound;
        this->delta = scale;
        parms = EncryptionParameters(SchemeType::bfv);
        parms.setPolyModulusDegree(polyModulusDegree);
        parms.setPlainModulus(plainModulus);
        modulus = plainModulus;
        parms.setCoeffModulus(CoeffModulus::Create(polyModulusDegree, qs));
        context = new SEALContext(parms);
        keygen = new KeyGenerator(*context);
        keygen->createPublicKey(pk);
        keygen->createRelinKeys(rlk);
        keygen->createGaloisKeys(gk);
        encoder = new BatchEncoder(*context);
        encryptor = new Encryptor(*context, pk);
        encryptor->setSecretKey(keygen->secretKey());
        decryptor = new Decryptor(*context, keygen->secretKey());
        evaluator = new Evaluator(*context);

        parmIDs.clear();
        std::shared_ptr<const SEALContext::ContextDataCuda> cd = context->firstContextData();
        while (cd) {
            parmIDs.push_back(cd->parmsID());
            cd = cd->nextContextData();
        }
    }

    vector<uint64_t> getUint64(const vector<double>& r) {
        uint64_t modulus = context->firstContextData()->parms().plainModulus().value();
        vector<uint64_t> x(r.size());
        int64_t half = modulus >> 1;
        for (size_t i = 0; i < r.size(); i++) {
            int64_t xi = static_cast<int64_t>(r[i] * delta);
            assert((xi < half) && (xi > -half));
            x[i] = (xi < 0) ? (modulus + xi) : xi;
        }
        return x;
    }

    vector<double> getDouble(const vector<uint64_t>& r, double m = 0) {
        uint64_t modulus = context->firstContextData()->parms().plainModulus().value();
        vector<double> x(r.size());
        int64_t half = modulus >> 1;
        if (m==0) m = delta;
        for (size_t i = 0; i < r.size(); i++) {
            assert(r[i] < modulus);
            if (r[i] > half) x[i] = -(static_cast<double>(modulus - r[i])) / m;
            else x[i] = static_cast<double>(r[i]) / m;
        }
        return x;
    }

    // void testMatmul(size_t batchSize, size_t inputDims, size_t outputDims) {
        
    //     // generate data
    //     auto weights = randomRealVector(inputDims * outputDims);
    //     auto x = randomRealVector(batchSize * inputDims);
    //     auto scaledX1 = getUint64(x);
        
    //     vector<uint64_t> scaledX2(scaledX1.size());
    //     for (size_t i = 0; i < scaledX2.size(); i++) {
    //         scaledX2[i] = rand() % modulus;
    //         scaledX1[i] = (scaledX1[i] + modulus - scaledX2[i]) % modulus;
    //     }

    //     auto lastParmsID = context->lastParmsID();

    //     // initialize helper
    //     LinearHelper::MatmulHelper helper(batchSize, inputDims, outputDims, slotCount);
    //     printf("Matmul helper created\n");
    //     auto encodedWeights = helper.encodeWeights(*encoder, getUint64(weights));
    //     printf("Weight encoded\n");
        

    //     // interaction
    //     auto x1Enc = helper.encryptInputs(*encryptor, *encoder, scaledX1);
    //     auto x2Enc = helper.encryptInputs(*encryptor, *encoder, scaledX2);
    //     // { // serialize
    //     //     ostringstream sout; xEnc.save(sout);
    //     //     auto p = sout.str(); std::cout << "xEnc length = " << p.size() << std::endl;
    //     //     istringstream sin(p); xEnc = LinearHelper::Cipher2d();
    //     //     xEnc.load(sin, *context);
    //     // }
    //     printf("x encoded\n");
    //     auto yEnc1 = helper.matmul(*evaluator, x1Enc, encodedWeights);  
    //     yEnc1.modSwitchToNext(*evaluator);
    //     auto yEnc2 = helper.matmul(*evaluator, x2Enc, encodedWeights);   
    //     yEnc2.modSwitchToNext(*evaluator);
    //     yEnc1.addInplace(*evaluator, yEnc2);
    //     // { // serialize
    //     //     ostringstream sout; helper.serializeOutputs(*evaluator, yEnc, sout);
    //     //     auto p = sout.str(); std::cout << "yEnc length = " << p.size() << std::endl;
    //     //     istringstream sin(p); 
    //     //     yEnc = helper.deserializeOutputs(*evaluator, sin);
    //     // }
    //     printf("Matmul done\n");

    //     // dec
    //     auto yDec = getDouble(helper.decryptOutputs(*encoder, *decryptor, yEnc1), delta*delta);
    //     printf("Decrypted\n");
        
    //     // plaintext computation
    //     vector<double> y(batchSize * outputDims, 0);
    //     for (size_t i = 0; i < batchSize; i++) {
    //         for (size_t j = 0; j < inputDims; j++) {
    //             for (size_t k = 0; k < outputDims; k++) {
    //                 y[i * outputDims + k] += x[i * inputDims + j] * weights[j * outputDims + k];
    //             }
    //         }
    //     }

    //     // comparison
    //     double diff = 0;
    //     double reldiff = 0;
    //     for (size_t i = 0; i < batchSize * outputDims; i++) {
    //         double d = std::abs(y[i] - yDec[i]);
    //         double reld = d / std::abs(y[i]);
    //         if (d > diff) diff = d;
    //         if (reld > reldiff) reldiff = reld;
    //     }
    //     std::cout << "Difference = " << diff << " relative = " << reldiff << std::endl;
        
    // }



    void testMatmulInts(size_t batchSize, size_t inputDims, size_t outputDims) {
        
        auto mod = parms.plainModulus().value();
        auto w = randomVector(inputDims * outputDims, mod);
        auto x = randomVector(inputDims * batchSize, mod);
        auto s = randomVector(batchSize * outputDims, mod);
        auto lastParmsID = context->lastParmsID();

        // initialize helper
        LinearHelper::MatmulHelper helper(batchSize, inputDims, outputDims, slotCount);
        // printf("Matmul helper created\n");

        auto wEncoded = helper.encodeWeights(*encoder, w.data());
        
        std::cout << "weight plaintext coeffcount = " << wEncoded[0][0].coeffCount() << std::endl;

        // interaction
        auto timer = Timer();
        auto t = timer.registerTimer("Matmul"); timer.tick(t);
        auto xEncoded = helper.encodeInputs(*encoder, x.data());
        auto xEnc = xEncoded.encrypt(*encryptor);
        auto yEnc = helper.matmul(*evaluator, xEnc, wEncoded);  
        yEnc.modSwitchToNext(*evaluator); 
        // printf("Matmul done\n");

        auto yDec = helper.decryptOutputs(*encoder, *decryptor, yEnc);
        timer.tock(t);
        printTimer(timer.gather());

        // printf("Decrypted\n");
        
        // plaintext computation
        vector<uint64_t> y(batchSize * outputDims, 0);
        for (size_t i = 0; i < batchSize; i++) {
            for (size_t j = 0; j < inputDims; j++) {
                for (size_t k = 0; k < outputDims; k++) {
                    y[i * outputDims + k] += x[i * inputDims + j] * w[j * outputDims + k];
                    y[i * outputDims + k] %= mod;
                    
                }
            }
        }

        // printVector(y);
        // printVector(yDec);

        // comparison
        uint64_t diff = 0;
        for (size_t i = 0; i < batchSize * outputDims; i++) {
            uint64_t d = std::abs<long long>(y[i] - yDec[i]);
            if (d > diff) diff = d;
        }
        std::cout << "Difference = " << diff << std::endl;
        
    }

    void testConv2d(size_t batchSize, size_t inputChannels, size_t outputChannels, size_t imageHeight, size_t imageWidth, size_t kernelHeight, size_t kernelWidth) {
        
        // generate data
        auto weights = randomRealVector(inputChannels * outputChannels * kernelHeight * kernelWidth);
        auto x = randomRealVector(batchSize * inputChannels * imageHeight * imageWidth);
        auto lastParmsID = context->lastParmsID();

        // initialize helper
        LinearHelper::Conv2dHelper helper(batchSize, imageHeight, imageWidth, kernelHeight, kernelWidth, inputChannels, outputChannels, slotCount);
        auto encodedWeights = helper.encodeWeights(*encoder, getUint64(weights));

        auto tim = Timer();
        tim.registerTimer();
        tim.tick();
        // interaction
        auto xEnc = helper.encryptInputs(*encryptor, *encoder, getUint64(x));
        { // serialize
            ostringstream sout; xEnc.save(sout);
            auto p = sout.str(); std::cout << "xEnc length = " << p.size() << std::endl;
            istringstream sin(p); xEnc = LinearHelper::Cipher2d();
            xEnc.load(sin, *context);
        }
        auto yEnc = helper.conv2d(*evaluator, xEnc, encodedWeights);
        { // serialize
            ostringstream sout; helper.serializeOutputs(*evaluator, yEnc, sout);
            auto p = sout.str(); std::cout << "yEnc length = " << p.size() << std::endl;
            istringstream sin(p); 
            yEnc = helper.deserializeOutputs(*evaluator, sin);
        }

        // dec
        auto yDec = getDouble(helper.decryptOutputs(*encoder, *decryptor, yEnc), delta*delta);
        tim.tock();

        printTimer(tim.gather());

        printf("Plain...\n");
        
        // plaintext computation
        size_t yh = imageHeight - kernelHeight + 1, yw = imageWidth - kernelWidth + 1;
        vector<double> y(batchSize * outputChannels * yh * yw, 0);
        for (size_t b = 0; b < batchSize; b++) {
            for (size_t oc = 0; oc < outputChannels; oc++) {
                for (size_t yi = 0; yi < yh; yi++) {
                    for (size_t yj = 0; yj < yw; yj++) {
                        double element = 0;
                        for (size_t ic = 0; ic < inputChannels; ic++) {
                            for (size_t xi = yi; xi < yi + kernelHeight; xi++) {
                                for (size_t xj = yj; xj < yj + kernelWidth; xj++) {
                                    size_t xIndex = ((b * inputChannels + ic) * imageHeight + xi) * imageWidth + xj;
                                    size_t wIndex = ((oc * inputChannels + ic) * kernelHeight + (xi - yi)) * kernelWidth + (xj - yj);
                                    element += x[xIndex] * weights[wIndex];
                                }
                            }
                        }
                        y[((b * outputChannels + oc) * yh + yi) * yw + yj] = element;
                    }
                }
            }
        }

        // printVector(y);
        // printVector(yDec);

        // comparison
        double diff = 0;
        double reldiff = 0;
        for (size_t i = 0; i < y.size(); i++) {
            double d = std::abs(y[i] - yDec[i]);
            double reld = d / std::abs(y[i]);
            if (d > diff) diff = d;
            if (reld > reldiff) {
                reldiff = reld;
            }
        }
        std::cout << "Difference = " << diff << " relative = " << reldiff << std::endl;
        
    }

};

int main() {
    KernelProvider::initialize();
    srand(0);
    LinearTest test(8192, {60, 60, 60}, 16, 1ul<<41, 1ul<<12);
    printf("Setup\n");
    // test.testMatmulInts(4, 6, 8);
    test.testMatmulInts(128, 2048, 1001);
    // test.testConv2d(1, 64, 256, 56, 56, 3, 3);
}