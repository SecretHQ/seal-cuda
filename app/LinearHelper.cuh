#pragma once

#include "../src/troy_cuda.cuh"
#include <iomanip>
#include <sys/time.h>

namespace LinearHelper {

    template <typename T>
    inline void savet(std::ostream& stream, const T* obj) {
        stream.write(reinterpret_cast<const char*>(obj), sizeof(T));
    }
    
    template <typename T>
    inline void loadt(std::istream& stream, T* obj) {
        stream.read(reinterpret_cast<char*>(obj), sizeof(T));
    }

    class Cipher2d;

    class Plain2d {
        
        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;
    
    public:
        
        std::vector<std::vector<Plaintext>> data;
        std::vector<Plaintext>& operator[] (size_t id) {
            return data[id];
        }
        const std::vector<Plaintext>& operator[] (size_t id) const {
            return data[id];
        }
        Plain2d() {}

        
        Cipher2d encrypt(const troyn::Encryptor& encryptor) const;

    };

    class Cipher2d {

        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;

    public:

        std::vector<std::vector<Ciphertext>> data;
        std::vector<Ciphertext>& operator[] (size_t id) {
            return data[id];
        }
        const std::vector<Ciphertext>& operator[] (size_t id) const {
            return data[id];
        }
        Cipher2d() {}

        void save(std::ostream& stream) const {
            size_t n = data.size();
            if (n == 0) return;
            size_t m = data[0].size();
            for (size_t i = 1; i < n; i++) {
                if (data[i].size() != m) {
                    throw std::invalid_argument("Not a rectangle Conv2d.");
                }
            }
            savet(stream, &n);
            savet(stream, &m);
            for (size_t i = 0; i < n; i++) {
                for (size_t j = 0; j < m; j++) {
                    data[i][j].save(stream);
                }
            }
        }

        void load(std::istream& stream) {
            size_t n, m;
            loadt(stream, &n);
            loadt(stream, &m);
            data.clear(); data.reserve(n);
            for (size_t i = 0; i < n; i++) {
                std::vector<Ciphertext> k(m);
                for (size_t j = 0; j < m; j++) {
                    k[j].load(stream);
                }
                data.push_back(std::move(k));
            }
        }

        void load(std::istream& stream, const troyn::SEALContext& context) {
            size_t n, m;
            loadt(stream, &n);
            loadt(stream, &m);
            data.clear(); data.reserve(n);
            for (size_t i = 0; i < n; i++) {
                std::vector<Ciphertext> k(m);
                for (size_t j = 0; j < m; j++) {
                    k[j].load(stream, context);
                }
                data.push_back(std::move(k));
            }
        }

        void modSwitchToNext(const troyn::Evaluator& evaluator) {
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.modSwitchToNextInplace(data[i][j]);
                }
            }
        }

        void addInplace(
            const troyn::Evaluator& evaluator,
            const Cipher2d& x
        ) {
            if (data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                if (data[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.addInplace(data[i][j], x[i][j]);
                }
            }
        }

        void addPlainInplace(
            const troyn::Evaluator& evaluator,
            const Plain2d& x
        ) {
            if (data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                if (data[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.addPlainInplace(data[i][j], x[i][j]);
                }
            }
        }

        Cipher2d addPlain(
            const troyn::Evaluator& evaluator,
            const Plain2d& x
        ) const {
            if (data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = data.size();
            Cipher2d ret; ret.data.reserve(n);
            for (size_t i = 0; i < n; i++) {
                if (data[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = data[i].size();
                std::vector<Ciphertext> row; row.resize(m);
                for (size_t j = 0; j < m; j++) {
                    evaluator.addPlain(data[i][j], x[i][j], row[j]);
                }
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

    };

    Cipher2d Plain2d::encrypt(const troyn::Encryptor& encryptor) const {
        Cipher2d ret; ret.data.reserve(data.size());
        size_t n = data.size();
        for (size_t i = 0; i < n; i++) {
            size_t m = data[i].size();
            std::vector<Ciphertext> row; row.reserve(m);
            for (size_t j = 0; j < m; j++) {
                row.push_back(encryptor.encryptSymmetric(data[i][j]));
            }
            ret.data.push_back(std::move(row));
        }
        return ret;
    }


    inline static size_t ceilDiv(size_t a, size_t b) {
        if (a%b==0) return a/b;
        return a/b+1;
    }

    class MatmulHelper {

        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;

        size_t batchSize, inputDims, outputDims;
        size_t slotCount;
        size_t batchBlock, inputBlock, outputBlock;

        void determineBlock() {
            size_t bBest = 0, iBest = 0, oBest = 0;
            size_t cBest = 2147483647;
            for (size_t b = batchSize; b >= 1; b--) {
                size_t bc = ceilDiv(batchSize, b);
                if (b >= slotCount) continue;
                if (bc * 2 > cBest) continue;
                for (size_t i = 1; i < slotCount / b; i++) {
                    size_t o = slotCount / b / i;
                    if (o > outputDims) o = outputDims;
                    if (i > inputDims) continue;
                    if (o < 1) continue;
                    size_t c = bc * (ceilDiv(inputDims, i) + ceilDiv(outputDims, o));
                    if (c >= cBest) continue;
                    bBest = b; iBest = i; oBest = o; cBest = c;
                }
            }
            batchBlock = bBest;
            inputBlock = iBest;
            outputBlock = oBest;
            // printf("batchBlock=%zu inputBlock=%zu outputBlock=%zu\n", batchBlock, inputBlock, outputBlock);
        }

        Plaintext encodeWeightSmall(
            troyn::BatchEncoder& encoder,
            const uint64_t* weights,
            size_t li, size_t ui, size_t lj, size_t uj
        ) {
            size_t slots = slotCount;
            std::vector<uint64_t> vec(inputBlock * outputBlock, 0);
            for (size_t j = lj; j < uj; j++) {
                for (size_t i = li; i < ui; i++) {
                    size_t r = (j-lj) * inputBlock + inputBlock - (i-li) - 1;
                    assert(r < slots);
                    vec[r] = weights[i * outputDims + j];
                }
            }
            Plaintext ret;
            encoder.encodePolynomial(vec, ret);
            return ret;
        }

    public:

        // Plain2d encodedWeights;

        MatmulHelper(size_t batchSize, size_t inputDims, size_t outputDims, size_t slotCount):
            batchSize(batchSize), inputDims(inputDims), outputDims(outputDims),
            slotCount(slotCount)
        {
            determineBlock();
        }

        Plain2d encodeWeights(
            troyn::BatchEncoder& encoder,
            const uint64_t* weights
        ) {
            // if (weights.size() != inputDims * outputDims) {
            //     throw std::invalid_argument("Weight size incorrect.");
            // }
            size_t height = inputDims, width = outputDims;
            size_t h = inputBlock, w = outputBlock;
            Plain2d encodedWeights;
            encodedWeights.data.clear();
            encodedWeights.data.reserve(ceilDiv(height, h));
            for (size_t li = 0; li < height; li += h) {
                size_t ui = (li + h > height) ? height : (li + h);
                std::vector<Plaintext> encodedRow; encodedRow.reserve(ceilDiv(width, w));
                for (size_t lj = 0; lj < width; lj += w) {
                    size_t uj = (lj + w > width) ? width : (lj + w);
                    encodedRow.push_back(
                        encodeWeightSmall(encoder, weights, li, ui, lj, uj)
                    );
                }
                encodedWeights.data.push_back(std::move(encodedRow));
            }
            return encodedWeights;
        }

        Plain2d encodeInputs(
            troyn::BatchEncoder& encoder,
            const uint64_t* inputs
        ) {
            // if (inputs.size() != inputDims * batchSize) {
            //     throw std::invalid_argument("Input size incorrect.");
            // }
            size_t vecsize = inputBlock;
            Plain2d ret;
            ret.data.reserve(batchSize);
            for (size_t li = 0; li < batchSize; li += batchBlock) {
                size_t ui = (li + batchBlock > batchSize) ? batchSize : li + batchBlock;
                std::vector<Plaintext> encodedRow;
                encodedRow.reserve(ceilDiv(inputDims, vecsize));
                for (size_t lj = 0; lj < inputDims; lj += vecsize) {
                    size_t uj = (lj + vecsize > inputDims) ? inputDims : lj + vecsize;
                    std::vector<uint64_t> vec(slotCount, 0);
                    for (size_t i = li; i < ui; i++)
                        for (size_t j = lj; j < uj; j++)
                            vec[(i - li) * inputBlock * outputBlock + (j - lj)] = inputs[i * inputDims + j];
                    Plaintext encoded;
                    encoder.encodePolynomial(vec, encoded);
                    encodedRow.push_back(std::move(encoded));
                }
                ret.data.push_back(std::move(encodedRow));
            }
            return ret;
        }

        Cipher2d encryptInputs(
            const troyn::Encryptor& encryptor,
            troyn::BatchEncoder& encoder, 
            const uint64_t* inputs
        ) {
            Plain2d plain = encodeInputs(encoder, inputs);
            return plain.encrypt(encryptor);
        }

        Cipher2d matmul(const troyn::Evaluator& evaluator, const Cipher2d& a, const Plain2d& w) {
            Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
            size_t outputVectorCount = ceilDiv(outputDims, outputBlock);
            if (a.data.size() != ceilDiv(batchSize, batchBlock)) {
                throw std::invalid_argument("Input batchsize incorrect.");
            }
            if (w.data.size() != ceilDiv(inputDims, inputBlock)) {
                throw std::invalid_argument("Weight input dimension incorrect.");
            }
            for (size_t b = 0; b < ceilDiv(batchSize, batchBlock); b++) {
                std::vector<Ciphertext> outVecs(outputVectorCount);
                for (size_t i = 0; i < w.data.size(); i++) {
                    for (size_t j = 0; j < w[i].size(); j++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(a[b][i], w[i][j], prod);
                        if (i==0) outVecs[j] = std::move(prod);
                        else {
                            evaluator.addInplace(outVecs[j], prod);
                        }
                    }
                }
                ret.data.push_back(std::move(outVecs));
            }
            return ret;
        }

        Cipher2d matmulCipher(const troyn::Evaluator& evaluator, const Cipher2d& a, const Cipher2d& w) {
            Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
            size_t outputVectorCount = ceilDiv(outputDims, outputBlock);
            if (a.data.size() != ceilDiv(batchSize, batchBlock)) {
                throw std::invalid_argument("Input batchsize incorrect.");
            }
            if (w.data.size() != ceilDiv(inputDims, inputBlock)) {
                throw std::invalid_argument("Weight input dimension incorrect.");
            }
            for (size_t b = 0; b < ceilDiv(batchSize, batchBlock); b++) {
                std::vector<Ciphertext> outVecs(outputVectorCount);
                for (size_t i = 0; i < w.data.size(); i++) {
                    for (size_t j = 0; j < w[i].size(); j++) {
                        Ciphertext prod;
                        evaluator.multiply(a[b][i], w[i][j], prod);
                        if (i==0) outVecs[j] = std::move(prod);
                        else {
                            evaluator.addInplace(outVecs[j], prod);
                        }
                    }
                }
                ret.data.push_back(std::move(outVecs));
            }
            return ret;
        }

        Cipher2d matmulReverse(const troyn::Evaluator& evaluator, const Plain2d& a, const Cipher2d& w) {
            Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
            size_t outputVectorCount = ceilDiv(outputDims, outputBlock);
            if (a.data.size() != ceilDiv(batchSize, batchBlock)) {
                throw std::invalid_argument("Input batchsize incorrect.");
            }
            if (w.data.size() != ceilDiv(inputDims, inputBlock)) {
                throw std::invalid_argument("Weight input dimension incorrect.");
            }
            for (size_t b = 0; b < ceilDiv(batchSize, batchBlock); b++) {
                std::vector<Ciphertext> outVecs(outputVectorCount);
                for (size_t i = 0; i < w.data.size(); i++) {
                    for (size_t j = 0; j < w[i].size(); j++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(w[i][j], a[b][i], prod);
                        if (i==0) outVecs[j] = std::move(prod);
                        else {
                            evaluator.addInplace(outVecs[j], prod);
                        }
                    }
                }
                ret.data.push_back(std::move(outVecs));
            }
            return ret;
        }

        Plain2d encodeOutputs(
            troyn::BatchEncoder& encoder, 
            const uint64_t* outputs
        ) {
            std::vector<uint64_t> dec(batchSize * outputDims);
            size_t vecsize = outputBlock;
            Plaintext pt;
            Plain2d ret; ret.data.reserve(batchSize);
            for (size_t li = 0; li < batchSize; li += batchBlock) {
                size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                std::vector<Plaintext> encodedRow;
                encodedRow.reserve(ceilDiv(outputDims, vecsize));
                for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                    size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                    std::vector<uint64_t> buffer(slotCount, 0);
                    for (size_t i = li; i < ui; i++)
                        for (size_t j = lj; j < uj; j++) 
                            buffer[(i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1] = outputs[i * outputDims + j];
                    encoder.encodePolynomial(buffer, pt);
                    encodedRow.push_back(std::move(pt));
                }
                ret.data.push_back(std::move(encodedRow));
            }
            return ret;
        }

        std::vector<uint64_t> decryptOutputs(
            troyn::BatchEncoder& encoder,
            troyn::Decryptor& decryptor,
            const Cipher2d& outputs
        ) {
            std::vector<uint64_t> dec(batchSize * outputDims);
            size_t vecsize = outputBlock;
            std::vector<uint64_t> buffer(slotCount);
            Plaintext pt;
            size_t di = 0;
            for (size_t li = 0; li < batchSize; li += batchBlock) {
                size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                size_t dj = 0;
                for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                    size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                    decryptor.decrypt(outputs[di][dj], pt);
                    encoder.decodePolynomial(pt, buffer);
                    for (size_t i = li; i < ui; i++)
                        for (size_t j = lj; j < uj; j++) 
                            dec[i * outputDims + j] = buffer[(i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1];
                    dj += 1;
                }
                di += 1;
            }
            return dec;
        }

        void serializeEncodedWeights(const Plain2d& w, std::ostream& stream) {
            size_t rows = w.data.size();
            size_t cols = w[0].size();
            if (rows == 0) throw std::invalid_argument("No rows in weight matrix.");
            if (cols == 0) throw std::invalid_argument("No columns in weight matrix.");
            for (size_t i=0; i<rows; i++) {
                if (w[i].size() != cols) throw std::invalid_argument("Weight matrix is not rectangular.");
            }
            savet(stream, &rows);
            savet(stream, &cols);
            for (size_t i = 0; i < rows; i++) {
                for (size_t j = 0; j < cols; j++) {
                    w[i][j].save(stream);
                }
            }
        }

        Plain2d deserializeEncodedWeights(std::istream& stream) {
            size_t rows, cols;
            loadt(stream, &rows);
            loadt(stream, &cols);
            Plain2d ret; ret.data.reserve(rows);
            for (size_t i = 0; i < rows; i++) {
                std::vector<Plaintext> row; row.reserve(cols);
                for (size_t j = 0; j < cols; j++) {
                    Plaintext pt;
                    pt.load(stream);
                    row.push_back(std::move(pt));
                }
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

        void serializeOutputs(troy::EvaluatorCuda &evaluator, const Cipher2d& x, std::ostream& stream) {
            size_t vecsize = outputBlock;
            Plaintext pt;
            size_t di = 0;
            for (size_t li = 0; li < batchSize; li += batchBlock) {
                size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                size_t dj = 0;
                for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                    size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                    std::vector<size_t> required((ui - li) * (uj - lj)); size_t rid = 0;
                    for (size_t i = li; i < ui; i++)
                        for (size_t j = lj; j < uj; j++) 
                            required[rid++] = (i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1;
                    x[di][dj].saveTerms(stream, evaluator, required);
                    dj += 1;
                }
                di += 1;
            }
        }

        Cipher2d deserializeOutputs(troy::EvaluatorCuda &evaluator, std::istream& stream) {
            size_t vecsize = outputBlock;
            Plaintext pt;
            Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
            for (size_t li = 0; li < batchSize; li += batchBlock) {
                size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                std::vector<Ciphertext> row; row.reserve(ceilDiv(outputDims, vecsize));
                for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                    size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                    std::vector<size_t> required((ui - li) * (uj - lj)); size_t rid = 0;
                    for (size_t i = li; i < ui; i++)
                        for (size_t j = lj; j < uj; j++) 
                            required[rid++] = (i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1;
                    Ciphertext c;
                    c.loadTerms(stream, evaluator, required);
                    row.push_back(std::move(c));
                }
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

    };

    class Conv2dHelper {

        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;

        size_t batchSize;
        size_t blockHeight, blockWidth, kernelHeight, kernelWidth;
        size_t imageHeight, imageWidth;
        size_t inputChannels, outputChannels;
        size_t slotCount;
        bool blocked;

    public:



        // class Timer {
        // public:
        //     std::vector<timeval> times;
        //     std::vector<double> accumulated; // ms
        //     std::vector<std::string> names;
        //     Timer() {}
        //     long registerTimer(std::string name = "") {
        //         times.push_back(timeval()); 
        //         accumulated.push_back(0);
        //         int ret = times.size() - 1;
        //         names.push_back(name);
        //         return ret;
        //     }
        //     void tick(long i = 0) {
        //         if (times.size() < 1) registerTimer();
        //         assert(i < times.size());
        //         gettimeofday(&times[i], 0);
        //     }
        //     double tock(long i = 0) {
        //         assert(i < times.size());
        //         timeval s; gettimeofday(&s, 0);
        //         auto timeElapsed = (s.tv_sec - times[i].tv_sec) * 1000.0;
        //         timeElapsed += (s.tv_usec - times[i].tv_usec) / 1000.0;
        //         accumulated[i] += timeElapsed;
        //         return accumulated[i];
        //     }
            
        //     void clear() {
        //         times.clear();
        //         accumulated.clear();
        //         names.clear();
        //     }

        //     std::map<std::string, double> gather(double divisor = 1) {
        //         std::map<std::string, double> p;
        //         for (long i=0; i<times.size(); i++) {
        //             p[names[i]] = accumulated[i] / divisor;
        //         }
        //         clear();
        //         return p;
        //     }
        // };

        
        // void printTimer(std::map<std::string, double> r) {
        //     for (auto& p: r) {
        //         std::cout << std::setw(25) << std::right << p.first << ":";
        //         std::cout << std::setw(10) << std::right << std::fixed << std::setprecision(3)
        //             << p.second << std::endl;
        //     }
        // }


        Conv2dHelper(
            size_t batchSize, 
            size_t imageHeight, size_t imageWidth, 
            size_t kernelHeight, size_t kernelWidth,
            size_t inputChannels, size_t outputChannels,
            size_t slotCount
        ):
            batchSize(batchSize),
            imageHeight(imageHeight), 
            imageWidth(imageWidth), 
            kernelHeight(kernelHeight), 
            kernelWidth(kernelWidth),
            inputChannels(inputChannels),
            outputChannels(outputChannels),
            slotCount(slotCount)
        {
            size_t maxSize = std::sqrt(slotCount);
            if (imageHeight > maxSize || imageWidth > maxSize) {
                blockHeight = maxSize; blockWidth = maxSize;
                blocked = true;
            } else {
                blockHeight = imageHeight; blockWidth = imageWidth;
                blocked = false;
            }
        }

        Plain2d encodeWeights(
            troyn::BatchEncoder& encoder, 
            std::vector<uint64_t> weights
        ) {
            if (weights.size() != inputChannels * outputChannels * kernelHeight * kernelWidth) {
                throw std::invalid_argument("Weights shape incorrect.");
            }
            size_t blockSize = blockHeight * blockWidth;
            size_t channelSlots = (slotCount) / blockSize;
            Plain2d encodedWeights;
            encodedWeights.data.clear();
            encodedWeights.data.reserve(outputChannels);
            for (size_t oc = 0; oc < outputChannels; oc++) {
                std::vector<Plaintext> currentChannel;
                currentChannel.reserve(ceilDiv(inputChannels, channelSlots));
                for (size_t lic = 0; lic < inputChannels; lic += channelSlots) {
                    size_t uic = lic + channelSlots;
                    if (uic > inputChannels) uic = inputChannels;
                    std::vector<uint64_t> spread(channelSlots * blockHeight * blockWidth, 0);
                    for (size_t j = lic; j < uic; j++) {
                        for (size_t ki = 0; ki < kernelHeight; ki++) {
                            for (size_t kj = 0; kj < kernelWidth; kj++) {
                                // spread[channel_slots - 1 - (j - lic), :k_h, :k_w] = np.flip(weight[oc, j])
                                size_t spreadIndex = (channelSlots - 1 - (j - lic)) * blockSize + ki * blockWidth + kj;
                                size_t weightIndex = ((oc * inputChannels) + j) * (kernelHeight * kernelWidth) + (kernelHeight - ki - 1) * kernelWidth + (kernelWidth - kj - 1);
                                spread[spreadIndex] = weights[weightIndex];
                            }
                        }
                    }
                    Plaintext pt; encoder.encodePolynomial(spread, pt);
                    currentChannel.push_back(std::move(pt));
                }
                encodedWeights.data.push_back(std::move(currentChannel));
            }
            return encodedWeights;
        }

        size_t getTotalBatchSize() {
            if (!blocked) { // copy the elements
                return batchSize;
            } else { // split x into smaller blocks
                size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
                size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
                size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
                return batchSize * sh * sw;
            }
        }

        Plain2d encodeInputs(
            troyn::BatchEncoder& encoder, 
            const std::vector<uint64_t>& inputs
        ) {
            if (inputs.size() != batchSize * inputChannels * imageHeight * imageWidth) {
                throw std::invalid_argument("Inputs shape incorrect.");
            }
            size_t totalBatchSize = getTotalBatchSize();
            std::vector<uint64_t> splitInputs;
            if (!blocked) { // copy the elements
                splitInputs = inputs;
            } else { // split x into smaller blocks
                size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
                size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
                size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
                assert(totalBatchSize == batchSize * sh * sw);
                splitInputs.resize(batchSize * sh * sw * inputChannels * blockHeight * blockWidth, 0);
                size_t blockSize = blockHeight * blockWidth;
                size_t imageSize = imageHeight * imageWidth;
                for (size_t b = 0; b < batchSize; b++) {
                    for (size_t i = 0; i < sh; i++) {
                        for (size_t j = 0; j < sw; j++) {
                            size_t bid = b * sh * sw + i * sw + j;
                            size_t si = i * (blockHeight - kh);
                            size_t sj = j * (blockWidth - kw);
                            size_t ui = (si + blockHeight >= imageHeight) 
                                ? imageHeight : (si + blockHeight);
                            size_t uj = (sj + blockWidth >= imageWidth)
                                ? imageWidth : (sj + blockWidth);
                            // split_x[b_id, :, :ui-si, :uj-sj] = x[b, :, si:ui, sj:uj]
                            for (size_t tc = 0; tc < inputChannels; tc++) {
                                for (size_t ti = 0; ti < ui-si; ti++) {
                                    for (size_t tj = 0; tj < uj-sj; tj++) {
                                        size_t splitIndex = bid * blockSize * inputChannels + tc * blockSize + ti * blockWidth + tj;
                                        size_t originalIndex = b * imageSize * inputChannels + tc * imageSize + (si + ti) * imageWidth + (sj + tj);
                                        splitInputs[splitIndex] = inputs[originalIndex];
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // encode inputs
            size_t interval = blockWidth * blockHeight;
            size_t slots = slotCount;
            size_t channelSlots = slots / interval;
            Plain2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Plaintext> group; group.reserve(ceilDiv(inputChannels, channelSlots));
                for (size_t c = 0; c < inputChannels; c += channelSlots) {
                    size_t upper = c + channelSlots;
                    if (upper > inputChannels) upper = inputChannels;
                    std::vector<uint64_t> plain(slots, 0);
                    for (size_t k = 0; k < upper-c; k++) {
                        // plain[k*interval:k*interval+h*w] = sample[c+k].flatten()
                        for (size_t i = 0; i < blockHeight; i++) {
                            for (size_t j = 0; j < blockWidth; j++) {
                                plain[k * interval + i * blockWidth + j] = 
                                    splitInputs[b * inputChannels * interval + (c + k) * interval + i * blockWidth + j];
                            }
                        }
                    }
                    Plaintext pt; encoder.encodePolynomial(plain, pt);
                    group.push_back(std::move(pt));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        Cipher2d encryptInputs(
            const troyn::Encryptor& encryptor,
            troyn::BatchEncoder& encoder, 
            const std::vector<uint64_t>& inputs
        ) {
            Plain2d plain = encodeInputs(encoder, inputs);
            return plain.encrypt(encryptor);
        }

        Cipher2d conv2d(const troyn::Evaluator& evaluator, const Cipher2d& a, const Plain2d& encodedWeights) {

            // Timer tim; auto t1 = tim.registerTimer("muladds");
            // size_t muladds = 0;

            size_t totalBatchSize = getTotalBatchSize();
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Ciphertext> group; group.reserve(outputChannels);
                for (size_t oc = 0; oc < outputChannels; oc++) {
                    Ciphertext cipher;
                    for (size_t i = 0; i < a[b].size(); i++) {
                        Ciphertext prod;
                        // tim.tick(t1);
                        evaluator.multiplyPlain(a[b][i], encodedWeights[oc][i], prod);
                        // muladds ++;
                        // tim.tock(t1);
                        if (i==0) cipher = std::move(prod);
                        else evaluator.addInplace(cipher, prod);
                    }
                    group.push_back(std::move(cipher));
                }
                ret.data.push_back(std::move(group));
            }
            // printTimer(tim.gather(muladds));
            return ret;
        }

        Cipher2d conv2dCipher(const troyn::Evaluator& evaluator, const Cipher2d& a, const Cipher2d& encodedWeights) {
            size_t totalBatchSize = getTotalBatchSize();
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Ciphertext> group; group.reserve(outputChannels);
                for (size_t oc = 0; oc < outputChannels; oc++) {
                    Ciphertext cipher;
                    for (size_t i = 0; i < a[b].size(); i++) {
                        Ciphertext prod;
                        evaluator.multiply(a[b][i], encodedWeights[oc][i], prod);
                        if (i==0) cipher = std::move(prod);
                        else evaluator.addInplace(cipher, prod);
                    }
                    group.push_back(std::move(cipher));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        Cipher2d conv2dReverse(const troyn::Evaluator& evaluator, const Plain2d& a, const Cipher2d& encodedWeights) {
            size_t totalBatchSize = getTotalBatchSize();
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Ciphertext> group; group.reserve(outputChannels);
                for (size_t oc = 0; oc < outputChannels; oc++) {
                    Ciphertext cipher;
                    for (size_t i = 0; i < a[b].size(); i++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(encodedWeights[oc][i], a[b][i], prod);
                        if (i==0) cipher = std::move(prod);
                        else evaluator.addInplace(cipher, prod);
                    }
                    group.push_back(std::move(cipher));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        Plain2d encodeOutputs(
            troyn::BatchEncoder& encoder,
            const std::vector<uint64_t>& outputs
        ) {
            size_t interval = blockWidth * blockHeight;
            size_t channelSlots = (slotCount) / interval;
            std::vector<uint64_t> mask(channelSlots * interval, 0);
            auto totalBatchSize = getTotalBatchSize();
            size_t yh = blockHeight - kernelHeight + 1;
            size_t yw = blockWidth  - kernelWidth  + 1;
            size_t oyh = imageHeight - kernelHeight + 1;
            size_t oyw = imageWidth - kernelWidth + 1;
            if (outputs.size() != batchSize * outputChannels * oyh * oyw) {
                throw std::invalid_argument("Outputs shape incorrect.");
            }
            Plain2d ret; ret.data.reserve(totalBatchSize);
            size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
            size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
            size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
            assert(totalBatchSize == batchSize * sh * sw);
            for (size_t b = 0; b < totalBatchSize; b++) {
                size_t ob = b / (sh * sw);
                size_t si = (b % (sh * sw)) / sw;
                size_t sj = b % sw;
                std::vector<Plaintext> group; group.reserve(outputChannels);
                for (size_t c = 0; c < outputChannels; c++) {
                    for (size_t i = 0; i < yh; i++) {
                        for (size_t j = 0; j < yw; j++) {
                            size_t maskIndex = (channelSlots - 1) * interval + (blockHeight - yh + i) * blockWidth + (blockWidth - yw + j);
                            size_t originalIndex = ob * outputChannels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                            if (si * yh + i < oyh && sj * yw + j < oyw)  mask[maskIndex] = outputs[originalIndex];
                        }
                    }
                    Plaintext encoded; encoder.encodePolynomial(mask, encoded);
                    group.push_back(std::move(encoded));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        void addPlainInplace(
            const troyn::Evaluator& evaluator, 
            Cipher2d& y, const Plain2d& x
        ) {
            if (y.data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = y.data.size();
            for (size_t i = 0; i < n; i++) {
                if (y[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = y[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.addPlainInplace(y[i][j], x[i][j]);
                }
            }
        }

        void addInplace(
            const troyn::Evaluator& evaluator, 
            Cipher2d& y, const Cipher2d& x
        ) {
            if (y.data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = y.data.size();
            for (size_t i = 0; i < n; i++) {
                if (y[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = y[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.addInplace(y[i][j], x[i][j]);
                }
            }
        }


        std::vector<uint64_t> decryptOutputs(
            troyn::BatchEncoder& encoder,
            troyn::Decryptor& decryptor,
            const Cipher2d& outputs
        ) {
            size_t interval = blockWidth * blockHeight;
            size_t channelSlots = (slotCount) / interval;
            auto totalBatchSize = getTotalBatchSize();
            size_t yh = blockHeight - kernelHeight + 1;
            size_t yw = blockWidth  - kernelWidth  + 1;
            size_t oyh = imageHeight - kernelHeight + 1;
            size_t oyw = imageWidth - kernelWidth + 1;
            std::vector<uint64_t> ret(batchSize * outputChannels * oyh * oyw);
            size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
            size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
            size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
            assert(totalBatchSize == batchSize * sh * sw);
            Plaintext encoded;
            std::vector<uint64_t> buffer;
            for (size_t b = 0; b < totalBatchSize; b++) {
                size_t ob = b / (sh * sw);
                size_t si = (b % (sh * sw)) / sw;
                size_t sj = b % sw;
                std::vector<Plaintext> group; group.reserve(outputChannels);
                for (size_t c = 0; c < outputChannels; c++) {
                    decryptor.decrypt(outputs[b][c], encoded);
                    encoder.decodePolynomial(encoded, buffer);
                    for (size_t i = 0; i < yh; i++) {
                        for (size_t j = 0; j < yw; j++) {
                            size_t maskIndex = (channelSlots - 1) * interval + (blockHeight - yh + i) * blockWidth + (blockWidth - yw + j);
                            size_t originalIndex = ob * outputChannels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                            if (si * yh + i < oyh && sj * yw + j < oyw) {
                                ret[originalIndex] = buffer[maskIndex];
                            }
                        }
                    }
                }
            }
            return ret;
        }

        void serializeOutputs(troy::EvaluatorCuda &evaluator, const Cipher2d& x, std::ostream& stream) {
            auto totalBatchSize = getTotalBatchSize();
            size_t interval = blockWidth * blockHeight;
            size_t channelSlots = (slotCount) / interval;
            std::vector<size_t> required(interval);
            size_t st = (channelSlots - 1) * interval;
            for (size_t i = st; i < st + interval; i++) required[i-st] = i;
            for (size_t b = 0; b < totalBatchSize; b++) {
                for (size_t oc = 0; oc < outputChannels; oc++) 
                    x[b][oc].saveTerms(stream, evaluator, required);
            }
        }

        Cipher2d deserializeOutputs(troy::EvaluatorCuda &evaluator, std::istream& stream) {
            auto totalBatchSize = getTotalBatchSize();
            size_t interval = blockWidth * blockHeight;
            size_t channelSlots = (slotCount) / interval;
            std::vector<size_t> required(interval);
            size_t st = (channelSlots - 1) * interval;
            for (size_t i = st; i < st + interval; i++) required[i-st] = i;
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Ciphertext> row(outputChannels);
                for (size_t oc = 0; oc < outputChannels; oc++) 
                    row[oc].loadTerms(stream, evaluator, required);
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

    };

}