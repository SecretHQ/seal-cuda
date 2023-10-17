#pragma once

#include "../src/troy_cuda.cuh"

namespace LinearHelperCKKS {

    template <typename T>
    inline void savet(std::ostream& stream, const T* obj) {
        stream.write(reinterpret_cast<const char*>(obj), sizeof(T));
    }
    
    template <typename T>
    inline void loadt(std::istream& stream, T* obj) {
        stream.read(reinterpret_cast<char*>(obj), sizeof(T));
    }

    class Plain2d {
        
        using Plaintext = troyn::Plaintext;
    
    public:
        
        std::vector<std::vector<Plaintext>> data;
        std::vector<Plaintext>& operator[] (size_t id) {
            return data[id];
        }
        const std::vector<Plaintext>& operator[] (size_t id) const {
            return data[id];
        }
        Plain2d() {}

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

    };


    inline static size_t ceilDiv(size_t a, size_t b) {
        if (a%b==0) return a/b;
        return a/b+1;
    }

    class MatmulHelper {

        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;

        size_t batchSize, inputDims, outputDims;
        size_t slotCount;
        size_t blockHeight, blockWidth;

        void determineBlock() {
            size_t height = inputDims, width = outputDims;
            size_t slots = slotCount * 2;
            blockHeight = 0; blockWidth = 0;
            size_t bt = height + width + 1;
            for (size_t i = 1; i < height + 1; i++) {
                size_t w = std::min(slots / i, width);
                size_t t = ceilDiv(height, i) + ceilDiv(width, w);
                if (t < bt) {blockHeight = i; blockWidth = w; bt = t;}
            }
        }

        Plaintext encodeWeightSmall(
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID,
            const std::vector<double>& weights, double scale,
            size_t li, size_t ui, size_t lj, size_t uj
        ) {
            size_t slots = slotCount * 2;
            std::vector<double> vec(slots, 0);
            for (size_t j = lj; j < uj; j++) {
                for (size_t i = li; i < ui; i++) {
                    size_t r = (j-lj) * blockHeight + blockHeight - (i-li) - 1;
                    vec[r] = weights[i * outputDims + j];
                }
            }
            Plaintext ret;
            encoder.encodePolynomial(vec, parmsID, scale, ret);
            return ret;
        }

    public:

        Plain2d encodedWeights;

        MatmulHelper(size_t batchSize, size_t inputDims, size_t outputDims, size_t slotCount):
            batchSize(batchSize), inputDims(inputDims), outputDims(outputDims),
            slotCount(slotCount)
        {
            determineBlock();
        }

        void encodeWeights(
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            const std::vector<double>& weights,
            double scale
        ) {
            if (weights.size() != inputDims * outputDims) {
                throw std::invalid_argument("Weight size incorrect.");
            }
            size_t height = inputDims, width = outputDims;
            size_t h = blockHeight, w = blockWidth;
            encodedWeights.data.clear();
            encodedWeights.data.reserve(ceilDiv(height, h));
            for (size_t li = 0; li < height; li += h) {
                size_t ui = (li + h > height) ? height : (li + h);
                std::vector<Plaintext> encodedRow; encodedRow.reserve(ceilDiv(width, w));
                for (size_t lj = 0; lj < width; lj += w) {
                    size_t uj = (lj + w > width) ? width : (lj + w);
                    encodedRow.push_back(
                        encodeWeightSmall(encoder, parmsID, weights, scale, li, ui, lj, uj)
                    );
                }
                encodedWeights.data.push_back(std::move(encodedRow));
            }
        }

        Plain2d encodeInputs(
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            const std::vector<double>& inputs,
            double scale
        ) {
            if (inputs.size() != inputDims * batchSize) {
                throw std::invalid_argument("Input size incorrect.");
            }
            size_t vecsize = blockHeight;
            Plain2d ret;
            ret.data.reserve(batchSize);
            for (size_t i = 0; i < batchSize; i++) {
                std::vector<Plaintext> encodedRow;
                encodedRow.reserve(ceilDiv(inputDims, vecsize));
                for (size_t lj = 0; lj < inputDims; lj += vecsize) {
                    size_t uj = (lj + vecsize > inputDims) ? inputDims : lj + vecsize;
                    std::vector<double> vec; vec.reserve(uj - lj);
                    for (size_t j = lj; j < uj; j++)
                        vec.push_back(inputs[i * inputDims + j]);
                    Plaintext encoded;
                    encoder.encodePolynomial(vec, parmsID, scale, encoded);
                    encodedRow.push_back(std::move(encoded));
                }
                ret.data.push_back(std::move(encodedRow));
            }
            return ret;
        }

        Cipher2d encryptInputs(
            const troyn::Encryptor& encryptor,
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            const std::vector<double>& inputs,
            double scale
        ) {
            Plain2d plain = encodeInputs(encoder, parmsID, inputs, scale);
            Cipher2d ret; ret.data.reserve(plain.data.size());
            size_t n = plain.data.size();
            for (size_t i = 0; i < n; i++) {
                size_t m = plain[i].size();
                std::vector<Ciphertext> row; row.reserve(m);
                for (size_t j = 0; j < m; j++) {
                    row.push_back(encryptor.encryptSymmetric(plain[i][j]));
                }
                ret.data.push_back(row);
            }
            return ret;
        }

        Cipher2d matmul(const troyn::Evaluator& evaluator, const Cipher2d& a) {
            size_t width = outputDims;
            size_t w = blockWidth;
            size_t outputVectorCount = ceilDiv(width, w);
            Cipher2d ret; ret.data.reserve(batchSize);
            if (a.data.size() != batchSize) {
                throw std::invalid_argument("Input batchsize incorrect.");
            }
            for (size_t b = 0; b < batchSize; b++) {
                std::vector<Ciphertext> outVecs(outputVectorCount);
                for (size_t i = 0; i < encodedWeights.data.size(); i++) {
                    for (size_t j = 0; j < encodedWeights[i].size(); j++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(a[b][i], encodedWeights[i][j], prod);
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
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            const std::vector<double>& outputs,
            double scale
        ) {
            size_t interval = blockHeight, vecsize = blockWidth;
            if (outputs.size() != batchSize * outputDims) {
                throw std::invalid_argument("Output size incorrect.");
            }
            size_t slots = slotCount * 2;
            Plain2d ret; ret.data.reserve(batchSize);
            for (size_t i = 0; i < batchSize; i++) {
                std::vector<Plaintext> encodedRow;
                encodedRow.reserve(ceilDiv(outputDims, vecsize));
                for (size_t li = 0; li < outputDims; li += vecsize) {
                    size_t ui = (li + vecsize > outputDims) ? outputDims : (li + vecsize);
                    std::vector<double> vec(slots);
                    for (size_t t = li; t < ui; t++) {
                        vec[(t-li) * interval + interval - 1] = outputs[i * outputDims + t];
                    }
                    Plaintext encoded;
                    encoder.encodePolynomial(vec, parmsID, scale, encoded);
                    encodedRow.push_back(std::move(encoded));
                }
                ret.data.push_back(std::move(encodedRow));
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

        std::vector<double> decryptOutputs(
            troyn::CKKSEncoder& encoder,
            troyn::Decryptor& decryptor,
            const Cipher2d& outputs
        ) {
            std::vector<double> dec(batchSize * outputDims);
            size_t interval = blockHeight, vecsize = blockWidth;
            std::vector<double> buffer;
            Plaintext pt;
            for (size_t i = 0; i < batchSize; i++) {
                size_t cid = 0;
                for (size_t li = 0; li < outputDims; li += vecsize) {
                    size_t ui = (li + vecsize > outputDims) ? outputDims : (li + vecsize);
                    decryptor.decrypt(outputs[i][cid], pt);
                    encoder.decodePolynomial(pt, buffer);
                    for (size_t j = li; j < ui; j++) {
                        dec[i * outputDims + j] = buffer[(j - li + 1) * interval - 1];
                    }
                    cid += 1;
                }
            }
            return dec;
        }

        void serializeOutputs(troy::EvaluatorCuda &evaluator, const Cipher2d& x, std::ostream& stream) {
            size_t interval = blockHeight;
            size_t vecsize = blockWidth;
            for (size_t i = 0; i < batchSize; i++) {
                size_t cid = 0;
                for (size_t li = 0; li < outputDims; li += vecsize) {
                    size_t ui = li + vecsize;
                    if (ui > outputDims) ui = outputDims;
                    std::vector<size_t> required(ui - li);
                    for (size_t j = li; j < ui; j++) required[j - li] = (j - li + 1) * interval - 1;
                    x[i][cid].saveTerms(stream, evaluator, required);
                    cid += 1;
                }
            }
        }

        Cipher2d deserializeOutputs(troy::EvaluatorCuda &evaluator, std::istream& stream) {
            size_t interval = blockHeight;
            size_t vecsize = blockWidth;
            Cipher2d ret; ret.data.reserve(batchSize);
            for (size_t i = 0; i < batchSize; i++) {
                std::vector<Ciphertext> row; row.reserve(ceilDiv(outputDims, vecsize));
                for (size_t li = 0; li < outputDims; li += vecsize) {
                    size_t ui = li + vecsize;
                    if (ui > outputDims) ui = outputDims;
                    std::vector<size_t> required(ui - li);
                    for (size_t j = li; j < ui; j++) required[j - li] = (j - li + 1) * interval - 1;
                    Ciphertext c;
                    c.loadTerms(stream, evaluator, required);
                    row.push_back(c);
                }
                ret.data.push_back(row);
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

        Plain2d encodedWeights;

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
            size_t maxSize = std::sqrt(slotCount * 2);
            if (imageHeight > maxSize || imageWidth > maxSize) {
                blockHeight = maxSize; blockWidth = maxSize;
                blocked = true;
            } else {
                blockHeight = imageHeight; blockWidth = imageWidth;
                blocked = false;
            }
        }

        void encodeWeights(
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            std::vector<double> weights,
            double scale
        ) {
            if (weights.size() != inputChannels * outputChannels * kernelHeight * kernelWidth) {
                throw std::invalid_argument("Weights shape incorrect.");
            }
            size_t blockSize = blockHeight * blockWidth;
            size_t channelSlots = (slotCount * 2) / blockSize;
            encodedWeights.data.clear();
            encodedWeights.data.reserve(outputChannels);
            for (size_t oc = 0; oc < outputChannels; oc++) {
                std::vector<Plaintext> currentChannel;
                currentChannel.reserve(ceilDiv(inputChannels, channelSlots));
                for (size_t lic = 0; lic < inputChannels; lic += channelSlots) {
                    size_t uic = lic + channelSlots;
                    if (uic > inputChannels) uic = inputChannels;
                    std::vector<double> spread(channelSlots * blockHeight * blockWidth, 0);
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
                    Plaintext pt; encoder.encodePolynomial(spread, parmsID, scale, pt);
                    currentChannel.push_back(std::move(pt));
                }
                encodedWeights.data.push_back(std::move(currentChannel));
            }
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
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            const std::vector<double>& inputs,
            double scale
        ) {
            if (inputs.size() != batchSize * inputChannels * imageHeight * imageWidth) {
                throw std::invalid_argument("Inputs shape incorrect.");
            }
            size_t totalBatchSize = getTotalBatchSize();
            std::vector<double> splitInputs;
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
            size_t slots = slotCount * 2;
            size_t channelSlots = slots / interval;
            Plain2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Plaintext> group; group.reserve(ceilDiv(inputChannels, channelSlots));
                for (size_t c = 0; c < inputChannels; c += channelSlots) {
                    size_t upper = c + channelSlots;
                    if (upper > inputChannels) upper = inputChannels;
                    std::vector<double> plain(slots, 0);
                    for (size_t k = 0; k < upper-c; k++) {
                        // plain[k*interval:k*interval+h*w] = sample[c+k].flatten()
                        for (size_t i = 0; i < blockHeight; i++) {
                            for (size_t j = 0; j < blockWidth; j++) {
                                plain[k * interval + i * blockWidth + j] = 
                                    splitInputs[b * inputChannels * interval + (c + k) * interval + i * blockWidth + j];
                            }
                        }
                    }
                    Plaintext pt; encoder.encodePolynomial(plain, parmsID, scale, pt);
                    group.push_back(std::move(pt));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        Cipher2d encryptInputs(
            const troyn::Encryptor& encryptor,
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            const std::vector<double>& inputs,
            double scale
        ) {
            Plain2d plain = encodeInputs(encoder, parmsID, inputs, scale);
            Cipher2d ret; ret.data.reserve(plain.data.size());
            size_t n = plain.data.size();
            for (size_t i = 0; i < n; i++) {
                size_t m = plain[i].size();
                std::vector<Ciphertext> row; row.reserve(m);
                for (size_t j = 0; j < m; j++) {
                    row.push_back(encryptor.encryptSymmetric(plain[i][j]));
                }
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

        Cipher2d conv2d(const troyn::Evaluator& evaluator, const Cipher2d& a) {
            size_t totalBatchSize = getTotalBatchSize();
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Ciphertext> group; group.reserve(outputChannels);
                for (size_t oc = 0; oc < outputChannels; oc++) {
                    Ciphertext cipher;
                    for (size_t i = 0; i < a[b].size(); i++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(a[b][i], encodedWeights[oc][i], prod);
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
            troyn::CKKSEncoder& encoder, troyn::ParmsID parmsID, 
            const std::vector<double>& outputs,
            double scale
        ) {
            size_t interval = blockWidth * blockHeight;
            size_t channelSlots = (slotCount * 2) / interval;
            std::vector<double> mask(channelSlots * interval, 0);
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
                    Plaintext encoded; encoder.encodePolynomial(mask, parmsID, scale, encoded);
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


        std::vector<double> decryptOutputs(
            troyn::CKKSEncoder& encoder,
            troyn::Decryptor& decryptor,
            const Cipher2d& outputs
        ) {
            size_t interval = blockWidth * blockHeight;
            size_t channelSlots = (slotCount * 2) / interval;
            auto totalBatchSize = getTotalBatchSize();
            size_t yh = blockHeight - kernelHeight + 1;
            size_t yw = blockWidth  - kernelWidth  + 1;
            size_t oyh = imageHeight - kernelHeight + 1;
            size_t oyw = imageWidth - kernelWidth + 1;
            std::vector<double> ret(batchSize * outputChannels * oyh * oyw);
            size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
            size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
            size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
            assert(totalBatchSize == batchSize * sh * sw);
            Plaintext encoded;
            std::vector<double> buffer;
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
            size_t channelSlots = (slotCount * 2) / interval;
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
            size_t channelSlots = (slotCount * 2) / interval;
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