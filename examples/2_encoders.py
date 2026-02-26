import numpy as np
from seal import *
from seal_helper import print_example_banner, print_parameters, print_vector


def bfv_batch_encoder_example():
    print_example_banner("Example: Encoders / BFV Batching")

    parms = EncryptionParameters(scheme_type.bfv)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

    context = SEALContext(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    encryptor = Encryptor(context, keygen.create_public_key())
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, keygen.secret_key())
    batch_encoder = BatchEncoder(context)

    slot_count = batch_encoder.slot_count()
    pod_matrix = [0] * slot_count
    pod_matrix[0:8] = [0, 1, 2, 3, 4, 5, 6, 7]

    plain_matrix = batch_encoder.encode(pod_matrix)
    encrypted_matrix = encryptor.encrypt(plain_matrix)

    pod_matrix2 = [((i & 1) + 1) for i in range(slot_count)]
    plain_matrix2 = batch_encoder.encode(pod_matrix2)

    encrypted_matrix = evaluator.add_plain(encrypted_matrix, plain_matrix2)
    evaluator.square_inplace(encrypted_matrix)
    evaluator.relinearize_inplace(encrypted_matrix, keygen.create_relin_keys())

    plain_result = decryptor.decrypt(encrypted_matrix)
    pod_result = batch_encoder.decode(plain_result)
    print_vector(pod_result.astype(np.float64), 8, 0)


def ckks_encoder_example():
    print_example_banner("Example: Encoders / CKKS")

    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [40, 40, 40, 40, 40]))
    context = SEALContext(parms)

    encoder = CKKSEncoder(context)
    keygen = KeyGenerator(context)
    encryptor = Encryptor(context, keygen.create_public_key())
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, keygen.secret_key())
    relin_keys = keygen.create_relin_keys()

    input_vec = [0.0, 1.1, 2.2, 3.3]
    scale = 2.0 ** 30
    plain = encoder.encode(input_vec, scale)
    encrypted = encryptor.encrypt(plain)

    evaluator.square_inplace(encrypted)
    evaluator.relinearize_inplace(encrypted, relin_keys)

    output_plain = decryptor.decrypt(encrypted)
    output = encoder.decode(output_plain)
    print_vector(output, 4, 4)


if __name__ == "__main__":
    bfv_batch_encoder_example()
    ckks_encoder_example()
