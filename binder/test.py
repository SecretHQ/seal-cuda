import pytroy

poly_modulus_degree = 1<<14
coeff_modulus_bits = [40, 40, 40, 40, 40, 40]


class Alice:
    
    def __init__(self):
        parameters = pytroy.EncryptionParameters(pytroy.SchemeType.ckks)
        parameters.set_poly_modulus_degree(poly_modulus_degree)
        parameters.set_coeff_modulus(pytroy.CoeffModulus.create(poly_modulus_degree, coeff_modulus_bits))
        self.parameters = parameters
        context = pytroy.SEALContext(parameters)
        self.context = context
        self.encoder = pytroy.CKKSEncoder(context)
        self.keygen = pytroy.KeyGenerator(context)
        public_key = self.keygen.create_public_key()
        self.public_key = public_key
        self.encryptor = pytroy.Encryptor(context, public_key)
        self.decryptor = pytroy.Decryptor(context, self.keygen.secret_key())
        self.evaluator = pytroy.Evaluator(context)

    def get_public_key(self):
        relin_keys = self.keygen.create_relin_keys()
        galois_keys = self.keygen.create_galois_keys()
        relin_keys.load(relin_keys.save())
        self.relin_keys = relin_keys
        return self.public_key.save(), relin_keys.save(), galois_keys.save()

    def get_ciphers(self):
        m1 = [1,2,3,4]
        m2 = [0.5, 0.6, 0.7, 0.8]
        p1 = pytroy.Plaintext()
        p2 = pytroy.Plaintext()
        self.encoder.encode(m1, 1<<40, p1)
        self.encoder.encode(m2, 1<<40, p2)
        c1 = pytroy.Ciphertext()
        c2 = pytroy.Ciphertext()
        self.encryptor.encrypt(p1, c1)
        self.encryptor.encrypt(p2, c2)
        ret = (c1.save(), c2.save())
        self.evaluator.multiply_inplace(c1, c2)
        self.evaluator.relinearize_inplace(c1, self.relin_keys)
        print(self.decrypt(c1.save())[:4])
        return ret

    def decrypt(self, c_s):
        c = pytroy.Ciphertext()
        c.load(c_s)
        p = pytroy.Plaintext()
        self.decryptor.decrypt(c, p)
        return self.encoder.decode(p)


class Bob:
    
    def __init__(self):
        parameters = pytroy.EncryptionParameters(pytroy.SchemeType.ckks)
        parameters.set_poly_modulus_degree(poly_modulus_degree)
        parameters.set_coeff_modulus(pytroy.CoeffModulus.create(poly_modulus_degree, coeff_modulus_bits))
        self.parameters = parameters
        context = pytroy.SEALContext(parameters)
        self.context = context
        self.encoder = pytroy.CKKSEncoder(context)

    def receive_public_key(self, keys):
        s_public_key, s_relin_keys, s_galois_keys = keys
        self.public_key = pytroy.PublicKey()
        self.public_key.load(s_public_key)
        self.encryptor = pytroy.Encryptor(self.context, self.public_key)
        self.evaluator = pytroy.Evaluator(self.context)
        self.relin_keys = pytroy.RelinKeys()
        self.relin_keys.load(s_relin_keys)
        self.galois_keys = pytroy.GaloisKeys()
        self.galois_keys.load(s_galois_keys)

    def evaluate(self, c1_s, c2_s):
        c1 = pytroy.Ciphertext()
        c2 = pytroy.Ciphertext()
        c1.load(c1_s)
        c2.load(c2_s)
        self.evaluator.multiply_inplace(c1, c2)
        self.evaluator.relinearize_inplace(c1, self.relin_keys)
        self.evaluator.rescale_to_next_inplace(c1)
        return c1.save()


if __name__ == "__main__":
    pytroy.initialize_kernel()
    alice = Alice()
    pp = alice.get_public_key()
    bob = Bob()
    bob.receive_public_key(pp)
    
    c1_s, c2_s = alice.get_ciphers()
    c3_s = bob.evaluate(c1_s, c2_s)

    p = alice.decrypt(c3_s)
    print(p[:4])