from random import random
import pytroy
import time

class Timer:
    
    def __init__(self):
        self.times = []
        self.accumulated = []
        self.names = []

    def registerTimer(self, name: str = ""):
        self.times.append(time.time())
        self.accumulated.append(0)
        self.names.append(name)
        return len(self.names) - 1
    
    def tick(self, i = 0):
        if len(self.times) < 1: self.tim.registerTimer()
        assert(i < len(self.times))
        self.times[i] = time.time()

    def tock(self, i = 0):
        assert(i < len(self.times))
        s = time.time()
        timeElapsed = s - self.times[i]
        self.accumulated[i] += timeElapsed
        return self.accumulated[i]

    def clear(self):
        self.times = []
        self.accumulated = []
        self.names = []

    def gather(self, divisor):
        p = {}
        for i in range(len(self.times)):
            p[self.names[i]] = self.accumulated[i] / divisor * 1000
        self.clear()
        return p
        

class TimeTest:

    def __init__(self):
        self.tim = Timer()

    def printTimer(self, repeat):
        gathered = self.tim.gather(repeat)
        for k, v in gathered.items():
            print("{0:25} {1:10.6f}".format(k, v))

    def testAdd(self, repeatCount = 1000):
        c1 = self.randomCiphertext()
        c2 = self.randomCiphertext()
        c3 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("Add-assign")
        t2 = self.tim.registerTimer("Add-inplace")
        t3 = self.tim.registerTimer("Add-create")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.add(c1, c2, c3)
            self.tim.tock(t1)
            self.tim.tick(t2)
            self.evaluator.add_inplace(c3, c1)
            self.tim.tock(t2)
            self.tim.tick(t3)
            c4 = self.evaluator.add(c1, c3)
            self.tim.tock(t3)
        self.printTimer(repeatCount)

    def testAddPlain(self, repeatCount = 1000):
        c1 = self.randomCiphertext()
        p2 = self.randomPlaintext()
        c3 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("AddPlain-assign")
        t2 = self.tim.registerTimer("AddPlain-inplace")
        t3 = self.tim.registerTimer("AddPlain-create")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.add_plain(c1, p2, c3)
            self.tim.tock(t1)
            self.tim.tick(t2)
            self.evaluator.add_plain_inplace(c3, p2)
            self.tim.tock(t2)
            self.tim.tick(t3)
            c4 = self.evaluator.add_plain(c3, p2)
            self.tim.tock(t3)
        self.printTimer(repeatCount)

    def testMultiplyPlain(self, repeatCount = 1000):
        c1 = self.randomCiphertext()
        p2 = self.randomPlaintext()
        c3 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("MultiplyPlain-assign")
        t2 = self.tim.registerTimer("MultiplyPlain-inplace")
        t3 = self.tim.registerTimer("MultiplyPlain-create")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.multiply_plain(c1, p2, c3)
            self.tim.tock(t1)
            self.tim.tick(t2)
            self.evaluator.multiply_plain_inplace(c3, p2)
            self.tim.tock(t2)
            self.tim.tick(t3)
            c4 = self.evaluator.multiply_plain(c1, p2)
            self.tim.tock(t3)
        self.printTimer(repeatCount)

    def testSquare(self, repeatCount = 1000):
        c1 = self.randomCiphertext()
        c2 = pytroy.Ciphertext()
        c3 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("Square-assign")
        t2 = self.tim.registerTimer("Square-inplace")
        t3 = self.tim.registerTimer("Square-create")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.square(c1, c2)
            self.tim.tock(t1)
            c3 = c1.copy()
            self.tim.tick(t2)
            self.evaluator.square_inplace(c3)
            self.tim.tock(t2)
            self.tim.tick(t3)
            c4 = self.evaluator.square(c1)
            self.tim.tock(t3)
        
        self.printTimer(repeatCount)
    

    def testMemoryPool(self, repeatCount = 1000):
        t1 = self.tim.registerTimer("Preallocate")
        t2 = self.tim.registerTimer("Allocate")
        self.tim.tick(t1)
        c1 = self.randomCiphertext()
        c2 = pytroy.Ciphertext()
        for t in range(repeatCount):
            self.evaluator.square(c1, c2)
        
        self.tim.tock(t1)
        self.tim.tick(t2)
        for t in range(repeatCount):
            c3 = pytroy.Ciphertext()
            self.evaluator.square(c1, c3)
        
        self.tim.tock(t2)
        self.printTimer(repeatCount)
    



class TimeTestCKKS(TimeTest):


    def __init__(self, polyModulusDegree, qs, dataBound = 1<<6, delta=(1<<16)):
        super().__init__()
        pytroy.initialize_kernel()
        self.slotCount = polyModulusDegree // 2
        self.dataBound = dataBound
        self.delta = delta
        parms = pytroy.EncryptionParameters(pytroy.SchemeType.ckks)
        parms.set_poly_modulus_degree(polyModulusDegree)
        parms.set_coeff_modulus(pytroy.CoeffModulus.create(polyModulusDegree, qs))
        self.parms = parms
        context = pytroy.SEALContext(parms)
        self.context = context
        keygen = pytroy.KeyGenerator(context)
        self.pk = pytroy.PublicKey()
        self.rlk = pytroy.RelinKeys()
        self.gk = pytroy.GaloisKeys()
        keygen.create_public_key(self.pk)
        keygen.create_relin_keys(self.rlk)
        keygen.create_galois_keys(self.gk)
        self.keygen = keygen
        encoder = pytroy.CKKSEncoder(context)
        encryptor = pytroy.Encryptor(context, self.pk)
        decryptor = pytroy.Decryptor(context, keygen.secret_key())
        evaluator = pytroy.Evaluator(context)
        self.encoder = encoder
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.evaluator = evaluator

    
    def randomVector(self, count, data_bound):
        x = []
        for i in range(count):
            x.append(random() * data_bound * 2 - data_bound)
        return x
    

    def randomPlaintext(self):
        p = self.randomVector(self.slotCount, self.dataBound)
        ret = pytroy.Plaintext()
        self.encoder.encode(p, self.delta, ret)
        return ret

    def randomCiphertext(self):
        r = self.randomPlaintext()
        ret = pytroy.Ciphertext()
        self.encryptor.encrypt(r, ret)
        return ret
    

    def testMultiplyRescale(self, repeatCount = 100):
        c1 = self.randomCiphertext()
        c2 = self.randomCiphertext()
        c3 = pytroy.Ciphertext()
        c4 = pytroy.Ciphertext()
        c5 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("Multiply-assign")
        t2 = self.tim.registerTimer("Relinearize-assign")
        t3 = self.tim.registerTimer("Multiply-inplace")
        t4 = self.tim.registerTimer("Relinearize-inplace")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.multiply(c1, c2, c3)
            self.tim.tock(t1)
            self.tim.tick(t2)
            self.evaluator.rescale_to_next(c3, c4)
            self.tim.tock(t2)
            c5 = c1.copy()
            self.tim.tick(t3)
            self.evaluator.multiply_inplace(c5, c2)
            self.tim.tock(t3)
            self.tim.tick(t4)
            self.evaluator.rescale_to_next_inplace(c5)
            self.tim.tock(t4)
        
        self.printTimer(repeatCount)
    

    def testRotateVector(self, repeatCount = 100):
        c1 = self.randomCiphertext()
        c2 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("Rotate-assign")
        t2 = self.tim.registerTimer("Rotate-inplace")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.rotate_vector(c1, 1, self.gk, c2)
            self.tim.tock(t1)
            self.tim.tick(t2)
            self.evaluator.rotate_vector_inplace(c1, 1, self.gk)
            self.tim.tock(t2)
        
        self.printTimer(repeatCount)
    

    def testAll(self):
        self.testAdd()
        self.testAddPlain()
        self.testMultiplyRescale()
        self.testMultiplyPlain()
        self.testSquare()
        self.testRotateVector()
        self.testMemoryPool()

class TimeTestBFVBGV(TimeTest):


    def __init__(self, bgv, polyModulusDegree, plainModulusBitSize, qs, dataBound = 1<<6):
        super().__init__()
        pytroy.initialize_kernel()
        self.slotCount = polyModulusDegree
        self.dataBound = dataBound
        parms = pytroy.EncryptionParameters(pytroy.SchemeType.bgv if bgv else pytroy.SchemeType.bfv)
        parms.set_poly_modulus_degree(polyModulusDegree)
        # parms.set_plain_modulus(pytroy.PlainModulus.batching(polyModulusDegree, plainModulusBitSize))
        parms.set_plain_modulus(1 << plainModulusBitSize)
        parms.set_coeff_modulus(pytroy.CoeffModulus.create(polyModulusDegree, qs))
        self.parms = parms
        context = pytroy.SEALContext(parms)
        self.context = context
        keygen = pytroy.KeyGenerator(context)
        self.pk = pytroy.PublicKey()
        self.rlk = pytroy.RelinKeys()
        # self.gk = pytroy.GaloisKeys()
        keygen.create_public_key(self.pk)
        keygen.create_relin_keys(self.rlk)
        # keygen.create_galois_keys(self.gk)
        self.keygen = keygen
        encoder = pytroy.BatchEncoder(context)
        encryptor = pytroy.Encryptor(context, self.pk)
        decryptor = pytroy.Decryptor(context, keygen.secret_key())
        evaluator = pytroy.Evaluator(context)
        self.encoder = encoder
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.evaluator = evaluator
    
    def randomVector(self, count, data_bound):
        input = []
        for i in range(count):
            input.append(int(random() * data_bound) % data_bound)
        return input
    

    def randomPlaintext(self):
        p = self.randomVector(self.slotCount, self.dataBound)
        ret = self.encoder.encode_polynomial(p)
        return ret

    def randomCiphertext(self):
        r = self.randomPlaintext()
        ret = pytroy.Ciphertext()
        self.encryptor.encrypt(r, ret)
        return ret
    

    def testMultiplyRescale(self, repeatCount = 100):
        c1 = self.randomCiphertext()
        c2 = self.randomCiphertext()
        c3 = pytroy.Ciphertext()
        c4 = pytroy.Ciphertext()
        c5 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("Multiply-assign")
        t2 = self.tim.registerTimer("Relinearize-assign")
        t3 = self.tim.registerTimer("Multiply-inplace")
        t4 = self.tim.registerTimer("Relinearize-inplace")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.multiply(c1, c2, c3)
            self.tim.tock(t1)
            self.tim.tick(t2)
            self.evaluator.mod_switch_to_next(c3, c4)
            self.tim.tock(t2)
            c5 = c1.copy()
            self.tim.tick(t3)
            self.evaluator.multiply_inplace(c5, c2)
            self.tim.tock(t3)
            self.tim.tick(t4)
            self.evaluator.mod_switch_to_next_inplace(c5)
            self.tim.tock(t4)
        
        self.printTimer(repeatCount)
    

    def testRotateVector(self, repeatCount = 100):
        c1 = self.randomCiphertext()
        c2 = pytroy.Ciphertext()
        t1 = self.tim.registerTimer("RotateRows-assign")
        t2 = self.tim.registerTimer("RotateRows-inplace")
        for t in range(repeatCount):
            self.tim.tick(t1)
            self.evaluator.rotate_rows(c1, 1, self.gk, c2)
            self.tim.tock(t1)
            self.tim.tick(t2)
            self.evaluator.rotate_rows_inplace(c1, 1, self.gk)
            self.tim.tock(t2)
        
        self.printTimer(repeatCount)
    

    def testAll(self):
        self.testAdd()
        self.testAddPlain()
        self.testMultiplyRescale()
        self.testMultiplyPlain()
        self.testSquare()
        # self.testRotateVector()
        self.testMemoryPool()
    


if __name__ == "__main__":

    test = TimeTestBFVBGV(False, 8192, 41, (60, 50, 60))
    test.testAll()