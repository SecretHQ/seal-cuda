#pragma once

#include "../src/troy_cuda.cuh"

class MatmulHelper {

    using complex = std::complex<double>;

private:

    std::vector<troyn::Plaintext> encoded;
    std::vector<bool> isZero;
    size_t height, width;
    size_t slotCount, packNum, cipherCount;
    inline int nextPow2(int val) { return pow(2, ceil(log(val) / log(2))); }

public:

    troyn::Plaintext prepareInput(const std::vector<complex>& input, troyn::CKKSEncoder& encoder, double scale) {
        if (input.size() != width) {
            throw std::invalid_argument("Input size should equal Width.");
        }
        std::vector<complex> ct; ct.resize(slotCount);
        size_t sizePow2 = nextPow2(width);
        for (int col = 0; col < width; col++) {
            for (int idx = 0; idx < packNum; idx++) {
                ct[col + sizePow2 * idx] = input[col];
            }
        }
        troyn::Plaintext plaintext; 
        encoder.encode(ct, scale, plaintext);
        return plaintext;
    }

    std::vector<complex> decodeResult(const troyn::Plaintext& plaintext, troyn::CKKSEncoder& encoder) {
        std::vector<complex> dec; encoder.decode(plaintext, dec);
        std::vector<complex> ret; ret.resize(height);
        int npw = nextPow2(width);
        for (int i=0; i<height; i++) {
            int cur = i / cipherCount;
            ret[i] = dec[(i % cipherCount) + npw * cur];
        }
        return ret;
    }

    void encode(const std::vector<std::vector<complex>>& matrix, troyn::CKKSEncoder& encoder, double scale) {

        std::vector<std::vector<complex>> mat_pack(cipherCount,
                                            std::vector<complex>(slotCount, 0ULL));
        for (int row = 0; row < height; row++) {
            int ct_idx = row / cipherCount;
            for (int col = 0; col < width; col++) 
            mat_pack[row % cipherCount][col + nextPow2(width) * ct_idx] = matrix[row][col];
        }
        
        // Take the packed ciphertexts above and repack them in a diagonal ordering.
        int mod_mask = (cipherCount - 1);
        int wrap_thresh = nextPow2(width);
        // int wrap_thresh = next_pow2(filter_w);
        int wrap_mask = wrap_thresh - 1;
        std::vector<std::vector<complex>> mat_diag(cipherCount,
                                            std::vector<complex>(slotCount, 0ULL));
        for (int ct = 0; ct < cipherCount; ct++) {
            for (int col = 0; col < slotCount; col++) {
            int ct_diag_l = (col - ct) & wrap_mask & mod_mask;
            int ct_diag_h = (col ^ ct) & slotCount & mod_mask;
            int ct_diag = (ct_diag_h + ct_diag_l);

            int col_diag_l = (col - ct_diag_l) & wrap_mask;
            int col_diag_h = wrap_thresh * (col / wrap_thresh) ^ ct_diag_h;
            int col_diag = col_diag_h + col_diag_l;

            mat_diag[ct_diag][col_diag] = mat_pack[ct][col];
            }
        }

        encoded.clear();
        for (size_t i = 0; i < cipherCount; i++) {
            bool is_zero = true;
            for (int j=0; j<mat_diag[i].size(); j++) {
                auto p = mat_diag[i][j];
                auto r = p.real() * p.real() + p.imag() * p.imag();
                if (r > 1e-6) is_zero = false;
            }
            troyn::Plaintext plain;
            encoder.encode(mat_diag[i], scale, plain);
            encoded.push_back(std::move(plain));
            isZero.push_back(is_zero);
        }
    }

    MatmulHelper(size_t height, size_t width, size_t slot_count): height(height), width(width) {
        slotCount = slot_count;
        packNum = slotCount / nextPow2(width);
        cipherCount = ceil((float)(nextPow2(height)) / packNum); 
    }

    troyn::Ciphertext multiply(const troyn::Ciphertext& repeatedVector, const troyn::Evaluator& evaluator, const troyn::GaloisKeys& galoisKeys, bool rescale) {
        if (encoded.size() == 0) {
            throw std::logic_error("Encoded matrix not set.");
        }
        troyn::Ciphertext tmp, result;
        for (int i = 0; i < cipherCount; i++) {
            if (isZero[i]) continue;
            evaluator.rotateVector(repeatedVector, i, galoisKeys, tmp);
            evaluator.multiplyPlainInplace(tmp, encoded[i]);
            if (i==0) {
                result = std::move(tmp);
            } else {
                evaluator.addInplace(result, tmp);
            }
        }
        if (rescale) {
            evaluator.rescaleToNextInplace(result);
        }
        for (int rot = cipherCount; rot < nextPow2(width); rot *= 2) {
            evaluator.rotateVector(result, rot, galoisKeys, tmp);
            evaluator.addInplace(result, tmp);
        }
        return result;
    }

};
