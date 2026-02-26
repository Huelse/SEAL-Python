from seal import *
from seal_helper import print_example_banner, print_parameters, print_vector


def bfv_rotation():
    print_example_banner("Example: Rotation / BFV")

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
    galois_keys = keygen.create_galois_keys()

    slot_count = batch_encoder.slot_count()
    pod_matrix = [0] * slot_count
    pod_matrix[0:8] = [0, 1, 2, 3, 4, 5, 6, 7]

    plain_matrix = batch_encoder.encode(pod_matrix)
    encrypted_matrix = encryptor.encrypt(plain_matrix)

    evaluator.rotate_rows_inplace(encrypted_matrix, 3, galois_keys)
    print_vector(batch_encoder.decode(decryptor.decrypt(encrypted_matrix)).astype(float), 8, 0)

    evaluator.rotate_columns_inplace(encrypted_matrix, galois_keys)
    print_vector(batch_encoder.decode(decryptor.decrypt(encrypted_matrix)).astype(float), 8, 0)


def ckks_rotation():
    print_example_banner("Example: Rotation / CKKS")

    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))

    context = SEALContext(parms)
    encoder = CKKSEncoder(context)
    keygen = KeyGenerator(context)
    encryptor = Encryptor(context, keygen.create_public_key())
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, keygen.secret_key())
    galois_keys = keygen.create_galois_keys()

    input_vec = [float(i) for i in range(8)]
    plain = encoder.encode(input_vec, 2.0 ** 40)
    encrypted = encryptor.encrypt(plain)

    rotated = evaluator.rotate_vector(encrypted, 2, galois_keys)
    result = encoder.decode(decryptor.decrypt(rotated))
    print_vector(result, 8, 3)


if __name__ == "__main__":
    bfv_rotation()
    ckks_rotation()
