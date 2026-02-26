import time
import numpy as np
from seal import *
from seal_helper import print_example_banner


def bench_bfv(iter_count=10):
    print_example_banner("Example: Performance / BFV")

    parms = EncryptionParameters(scheme_type.bfv)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    encryptor = Encryptor(context, keygen.create_public_key())
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, keygen.secret_key())
    batch_encoder = BatchEncoder(context)
    relin_keys = keygen.create_relin_keys()

    slot_count = batch_encoder.slot_count()
    data = np.arange(slot_count, dtype=np.uint64)

    t0 = time.perf_counter()
    for _ in range(iter_count):
        plain = batch_encoder.encode(data)
    t1 = time.perf_counter()

    plain = batch_encoder.encode(data)
    t2 = time.perf_counter()
    for _ in range(iter_count):
        encrypted = encryptor.encrypt(plain)
    t3 = time.perf_counter()

    encrypted = encryptor.encrypt(plain)
    t4 = time.perf_counter()
    for _ in range(iter_count):
        decryptor.decrypt(encrypted)
    t5 = time.perf_counter()

    ct = encryptor.encrypt(plain)
    t6 = time.perf_counter()
    for _ in range(iter_count):
        tct = evaluator.square(ct)
        evaluator.relinearize_inplace(tct, relin_keys)
    t7 = time.perf_counter()

    print(f"encode avg: {(t1 - t0) / iter_count * 1000:.3f} ms")
    print(f"encrypt avg: {(t3 - t2) / iter_count * 1000:.3f} ms")
    print(f"decrypt avg: {(t5 - t4) / iter_count * 1000:.3f} ms")
    print(f"square+relin avg: {(t7 - t6) / iter_count * 1000:.3f} ms")
    print(f"memory pool allocated bytes: {MemoryManager.GetPool().alloc_byte_count()}")


def bench_ckks(iter_count=10):
    print_example_banner("Example: Performance / CKKS")

    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    encryptor = Encryptor(context, keygen.create_public_key())
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, keygen.secret_key())
    encoder = CKKSEncoder(context)
    relin_keys = keygen.create_relin_keys()

    values = np.linspace(0, 1, 16)
    scale = 2.0 ** 40

    t0 = time.perf_counter()
    for _ in range(iter_count):
        plain = encoder.encode(values, scale)
    t1 = time.perf_counter()

    plain = encoder.encode(values, scale)
    t2 = time.perf_counter()
    for _ in range(iter_count):
        encrypted = encryptor.encrypt(plain)
    t3 = time.perf_counter()

    encrypted = encryptor.encrypt(plain)
    t4 = time.perf_counter()
    for _ in range(iter_count):
        decryptor.decrypt(encrypted)
    t5 = time.perf_counter()

    ct = encryptor.encrypt(plain)
    t6 = time.perf_counter()
    for _ in range(iter_count):
        tct = evaluator.square(ct)
        evaluator.relinearize_inplace(tct, relin_keys)
        evaluator.rescale_to_next_inplace(tct)
    t7 = time.perf_counter()

    print(f"encode avg: {(t1 - t0) / iter_count * 1000:.3f} ms")
    print(f"encrypt avg: {(t3 - t2) / iter_count * 1000:.3f} ms")
    print(f"decrypt avg: {(t5 - t4) / iter_count * 1000:.3f} ms")
    print(f"square+relin+rescale avg: {(t7 - t6) / iter_count * 1000:.3f} ms")


if __name__ == "__main__":
    bench_bfv()
    bench_ckks()
