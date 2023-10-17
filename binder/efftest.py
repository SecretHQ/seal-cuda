import math
import numpy as np
import time
import seal
import pytroy

pytroy.initialize_kernel()

class Timer:

    def __init__(self):
        pass

    def tick(self):
        self.start = time.time()

    def tock(self, div=1, prompt=None):
        t = time.time() - self.start
        t = t / div * 1000
        if prompt is not None:
            print("{0:<10}: {1:.6f}".format(prompt, t))
        return t

class Tom:

    def __init__(self, 
        gpu=True, 
        poly_modulus_degree=4096, 
        q_bits=(50, 50), 
        log_scale=15
    ):

        self.gpu = gpu

        if gpu:
            self.ckks_params = pytroy.EncryptionParameters(pytroy.SchemeType.ckks)
            self.ckks_params.set_poly_modulus_degree(poly_modulus_degree)
            self.ckks_params.set_coeff_modulus(pytroy.CoeffModulus.create(poly_modulus_degree, q_bits))
            self.ckks_context = pytroy.SEALContext(self.ckks_params)
            self.keygen = pytroy.KeyGenerator(self.ckks_context)
            self.secret_key = self.keygen.secret_key()
            self.public_key = self.keygen.create_public_key()
            self.relin_key = self.keygen.create_relin_keys()
            self.encryptor = pytroy.Encryptor(self.ckks_context, self.public_key)
            self.decryptor = pytroy.Decryptor(self.ckks_context, self.secret_key)
            self.evaluator = pytroy.Evaluator(self.ckks_context)
            self.encoder = pytroy.CKKSEncoder(self.ckks_context)
            self.gal_key = self.keygen.create_galois_keys()
            self.slot_count = self.encoder.slot_count()
        else:
            self.ckks_params = seal.EncryptionParameters(seal.scheme_type.ckks)
            self.ckks_params.set_poly_modulus_degree(poly_modulus_degree)
            self.ckks_params.set_coeff_modulus(seal.CoeffModulus.Create(poly_modulus_degree, q_bits))
            self.ckks_context = seal.SEALContext(self.ckks_params)
            self.keygen = seal.KeyGenerator(self.ckks_context)
            self.secret_key = self.keygen.secret_key()
            self.public_key = self.keygen.create_public_key()
            self.relin_key = self.keygen.create_relin_keys()
            self.encryptor = seal.Encryptor(self.ckks_context, self.public_key)
            self.decryptor = seal.Decryptor(self.ckks_context, self.secret_key)
            self.evaluator = seal.Evaluator(self.ckks_context)
            self.encoder = seal.CKKSEncoder(self.ckks_context)
            self.gal_key = self.keygen.create_galois_keys()
            self.slot_count = self.encoder.slot_count()

        self.scale = math.pow(2, log_scale)
        self.encryptor.set_secret_key(self.secret_key)

        self.parms_ids = []
        cont = self.ckks_context.first_context_data()
        while cont:
            self.parms_ids.append(cont.parms_id())
            cont = cont.next_context_data()

    def random_vector(self):
        return np.random.randn(self.slot_count * 2)

    def encode(self, v):
        return self.encoder.encode_polynomial(v, self.scale)

    def decode(self, v):
        return self.encoder.decode_polynomial(v)

    def encrypt(self, p):
        return self.encryptor.encrypt(p)

    def test_encode(self, times = 100):
        tim = Timer()
        tim.tick()
        for _ in range(times):
            x = self.encode(self.random_vector())
        tim.tock(times, "Encode")
        tim.tick()
        for _ in range(times):
            y = self.decode(x)
        tim.tock(times, "Decode")

    def test_multiply_plain(self, times = 1000):
        p = self.encode(self.random_vector())
        c = self.encrypt(self.encode(self.random_vector()))
        tim = Timer()
        tim.tick()
        for _ in range(times):
            x = self.evaluator.multiply_plain(c, p)
        tim.tock(times, "MulPlain")

        tim.tick()
        x = self.evaluator.multiply_plain_1000(c, p)
        tim.tock(1000, "Mul1000")

        tim.tick();
        p = [self.encode(self.random_vector()) for _ in range(times)]
        c = [self.encrypt(self.encode(self.random_vector())) for _ in range(times)]
        tim = Timer()
        tim.tick()
        x = self.evaluator.multiply_batch(c, p)
        print(len(x))
        tim.tock(times, "MulBatched")
        

    def test_add_plain(self, times = 1000):
        p = self.encode(self.random_vector())
        c = self.encrypt(self.encode(self.random_vector()))
        tim = Timer()
        tim.tick()
        for _ in range(times):
            x = self.evaluator.add_plain(c, p)
        tim.tock(times, "AddPlain")


if __name__ == "__main__":

    poly_degree = 4096
    qs = (50, 50)

    gpu = Tom(       poly_modulus_degree=poly_degree, q_bits=qs)
    cpu = Tom(False, poly_modulus_degree=poly_degree, q_bits=qs)

    print("--- GPU ---")
    gpu.test_encode()
    gpu.test_multiply_plain()
    gpu.test_add_plain()
    # print("")
    # print("--- CPU ---")
    # # cpu.test_encode()
    # cpu.test_multiply_plain()