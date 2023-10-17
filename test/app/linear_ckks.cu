#include "../../app/LinearHelperCKKS.cuh"
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

    vector<ParmsID> parmIDs;

    CKKSEncoder* encoder;
    size_t slotCount;
    int dataBound;
    double delta;

public:

    Plaintext decryptp(const Ciphertext& c) {
        Plaintext p; decryptor->decrypt(c, p);
        return p;
    }

    vector<double> decrypt(const Plaintext& p) {
        vector<double> ret; encoder->decodePolynomial(p, ret);
        return ret;
    }

    vector<double> decrypt(const Ciphertext& c) {
        return decrypt(decryptp(c));
    }

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

    vector<double> randomRealVector(size_t count = 0, int data_bound = 0) {
        if (count == 0) count = slotCount;
        if (data_bound == 0) data_bound = dataBound;
        vector<double> input(count, 0.0);
        for (size_t i = 0; i < count; i++)
        {
            input[i] = static_cast<double>(rand() % data_bound);
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

    LinearTest(size_t polyModulusDegree, vector<int> qs, int dataBound = 1<<6, double delta=static_cast<double>(1<<16)) {
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

    void testMatmul(size_t batchSize, size_t inputDims, size_t outputDims) {
        
        // generate data
        auto weights = randomRealVector(inputDims * outputDims);
        auto x = randomRealVector(batchSize * inputDims);
        auto lastParmsID = context->lastParmsID();

        // initialize helper
        LinearHelperCKKS::MatmulHelper helper(batchSize, inputDims, outputDims, slotCount);
        helper.encodeWeights(*encoder, lastParmsID, weights, delta);

        // interaction
        auto xEnc = helper.encryptInputs(*encryptor, *encoder, lastParmsID, x, delta);
        auto yEnc = helper.matmul(*evaluator, xEnc);

        // dec
        auto yDec = helper.decryptOutputs(*encoder, *decryptor, yEnc);
        
        // plaintext computation
        vector<double> y(batchSize * outputDims, 0);
        for (size_t i = 0; i < batchSize; i++) {
            for (size_t j = 0; j < inputDims; j++) {
                for (size_t k = 0; k < outputDims; k++) {
                    y[i * outputDims + k] += x[i * inputDims + j] * weights[j * outputDims + k];
                }
            }
        }

        // comparison
        double diff = 0;
        for (size_t i = 0; i < batchSize * outputDims; i++) {
            double d = std::abs(y[i] - yDec[i]);
            if (d > diff) diff = d;
        }
        std::cout << "Difference = " << diff << std::endl;
        
    }

    void testFullMatmul(size_t batchSize, size_t inputDims, size_t outputDims) {

        Timer tim;
        auto t1 = tim.registerTimer("TOTAL");
        auto t2 = tim.registerTimer("Server encode");
        auto t3 = tim.registerTimer("Client encrypt");
        auto t4 = tim.registerTimer("Add x plain");
        auto t5 = tim.registerTimer("Mul");
        auto t6 = tim.registerTimer("Add r plain");
        auto t7 = tim.registerTimer("Decrypt");

        // generate data
        auto weights = randomRealVector(inputDims * outputDims);
        auto xClient = randomRealVector(batchSize * inputDims);
        auto xServer = randomRealVector(batchSize * inputDims);
        auto lastParmsID = context->lastParmsID();

        // initialize helper
        LinearHelperCKKS::MatmulHelper helper(batchSize, inputDims, outputDims, slotCount);
        helper.encodeWeights(*encoder, lastParmsID, weights, delta);

        // encode
        tim.tick(t1);
        tim.tick(t2);
        auto r = randomRealVector(batchSize * outputDims);
        auto xServerEncoded = helper.encodeInputs(*encoder, lastParmsID, xServer, delta);
        auto rEncoded = helper.encodeOutputs(*encoder, lastParmsID, r, delta * delta);
        tim.tock(t2);

        // interaction
        tim.tick(t3);
        auto xEnc = helper.encryptInputs(*encryptor, *encoder, lastParmsID, xClient, delta);
        { // serialize
            ostringstream sout; xEnc.save(sout);
            auto p = sout.str(); std::cout << "xEnc length = " << p.size() << std::endl;
            istringstream sin(p); xEnc = LinearHelperCKKS::Cipher2d();
            xEnc.load(sin, *context);
        }
        tim.tock(t3);
        tim.tick(t4);
        helper.addPlainInplace(*evaluator, xEnc, xServerEncoded);
        tim.tock(t4);
        tim.tick(t5);
        auto yEnc = helper.matmul(*evaluator, xEnc);
        tim.tock(t5);
        tim.tick(t6);
        helper.addPlainInplace(*evaluator, yEnc, rEncoded);      
        { // serialize
            ostringstream sout; helper.serializeOutputs(*evaluator, yEnc, sout);
            auto p = sout.str(); std::cout << "yEnc length = " << p.size() << std::endl;
            istringstream sin(p); 
            yEnc = helper.deserializeOutputs(*evaluator, sin);
        }
        tim.tock(t6);
        // dec
        tim.tick(t7);
        auto yDec = helper.decryptOutputs(*encoder, *decryptor, yEnc);
        for (size_t i = 0; i < batchSize * outputDims; i++) {
            yDec[i] -= r[i];
        }
        tim.tock(t7);
        tim.tock(t1);
        
        // plaintext computation
        vector<double> y(batchSize * outputDims, 0);
        for (size_t i = 0; i < batchSize; i++) {
            for (size_t j = 0; j < inputDims; j++) {
                for (size_t k = 0; k < outputDims; k++) {
                    double x = xClient[i * inputDims + j] + xServer[i * inputDims + j];
                    double w = weights[j * outputDims + k];
                    y[i * outputDims + k] += x * w;
                }
            }
        }

        // comparison
        double diff = 0;
        for (size_t i = 0; i < batchSize * outputDims; i++) {
            double d = std::abs(y[i] - yDec[i]);
            if (d > diff) diff = d;
        }
        std::cout << "Difference = " << diff << std::endl;
        printTimer(tim.gather());

    }

    void testConv2d(size_t batchSize, size_t inputChannels, size_t outputChannels, size_t imageHeight, size_t imageWidth, size_t kernelHeight, size_t kernelWidth) {
        
        // generate data
        auto weights = randomRealVector(inputChannels * outputChannels * kernelHeight * kernelWidth);
        auto x = randomRealVector(batchSize * inputChannels * imageHeight * imageWidth);
        auto lastParmsID = context->lastParmsID();

        // initialize helper
        LinearHelperCKKS::Conv2dHelper helper(batchSize, imageHeight, imageWidth, kernelHeight, kernelWidth, inputChannels, outputChannels, slotCount);
        helper.encodeWeights(*encoder, lastParmsID, weights, delta);

        // interaction
        auto xEnc = helper.encryptInputs(*encryptor, *encoder, lastParmsID, x, delta);
        auto yEnc = helper.conv2d(*evaluator, xEnc);

        // dec
        auto yDec = helper.decryptOutputs(*encoder, *decryptor, yEnc);
        
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

        // comparison
        double diff = 0;
        for (size_t i = 0; i < y.size(); i++) {
            double d = std::abs(y[i] - yDec[i]);
            if (d > diff) diff = d;
        }
        std::cout << "Difference = " << diff << std::endl;
        
    }


    void testFullConv2d(size_t batchSize, size_t inputChannels, size_t outputChannels, size_t imageHeight, size_t imageWidth, size_t kernelHeight, size_t kernelWidth) {

        Timer tim;
        auto t1 = tim.registerTimer("TOTAL");
        auto t2 = tim.registerTimer("Server encode");
        auto t3 = tim.registerTimer("Client encrypt");
        auto t4 = tim.registerTimer("Add x plain");
        auto t5 = tim.registerTimer("Mul");
        auto t6 = tim.registerTimer("Add r plain");
        auto t7 = tim.registerTimer("Decrypt");

        // generate data
        auto weights = randomRealVector(inputChannels * outputChannels * kernelHeight * kernelWidth);
        auto xClient = randomRealVector(batchSize * inputChannels * imageHeight * imageWidth);
        auto xServer = randomRealVector(batchSize * inputChannels * imageHeight * imageWidth);
        auto lastParmsID = context->lastParmsID();

        // initialize helper
        LinearHelperCKKS::Conv2dHelper helper(batchSize, imageHeight, imageWidth, kernelHeight, kernelWidth, inputChannels, outputChannels, slotCount);
        helper.encodeWeights(*encoder, lastParmsID, weights, delta);

        // encode
        tim.tick(t1);
        tim.tick(t2);
        size_t yh = imageHeight - kernelHeight + 1, yw = imageWidth - kernelWidth + 1;
        auto r = randomRealVector(batchSize * outputChannels * yh * yw);
        auto xServerEncoded = helper.encodeInputs(*encoder, lastParmsID, xServer, delta);
        auto rEncoded = helper.encodeOutputs(*encoder, lastParmsID, r, delta * delta);
        tim.tock(t2);

        // interaction
        tim.tick(t3);
        auto xEnc = helper.encryptInputs(*encryptor, *encoder, lastParmsID, xClient, delta);
        { // serialize
            ostringstream sout; xEnc.save(sout);
            auto p = sout.str(); std::cout << "xEnc length = " << p.size() << std::endl;
            istringstream sin(p); xEnc = LinearHelperCKKS::Cipher2d();
            xEnc.load(sin, *context);
        }
        tim.tock(t3);
        tim.tick(t4);
        helper.addPlainInplace(*evaluator, xEnc, xServerEncoded);
        tim.tock(t4);
        tim.tick(t5);
        auto yEnc = helper.conv2d(*evaluator, xEnc);
        tim.tock(t5);
        tim.tick(t6);
        helper.addPlainInplace(*evaluator, yEnc, rEncoded);      
        { // serialize
            ostringstream sout; helper.serializeOutputs(*evaluator, yEnc, sout);
            auto p = sout.str(); std::cout << "yEnc length = " << p.size() << std::endl;
            istringstream sin(p); 
            yEnc = helper.deserializeOutputs(*evaluator, sin);
        }
        tim.tock(t6);
        // dec
        tim.tick(t7);
        auto yDec = helper.decryptOutputs(*encoder, *decryptor, yEnc);
        for (size_t i = 0; i < r.size(); i++) {
            yDec[i] -= r[i];
        }
        tim.tock(t7);
        tim.tock(t1);
        
        // plaintext computation
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
                                    element += (xClient[xIndex] + xServer[xIndex]) * weights[wIndex];
                                }
                            }
                        }
                        y[((b * outputChannels + oc) * yh + yi) * yw + yj] = element;
                    }
                }
            }
        }

        // comparison
        double diff = 0;
        for (size_t i = 0; i < y.size(); i++) {
            double d = std::abs(y[i] - yDec[i]);
            if (d > diff) diff = d;
        }
        std::cout << "Difference = " << diff << std::endl;
        printTimer(tim.gather());

    }


};

int main() {
    srand(0);
    LinearTest test(4096, {50, 50}, 10, 1<<15);
    // test.testFullMatmul(1, 2048, 1001);
    test.testFullConv2d(1, 256, 64, 56, 56, 1, 1);
}