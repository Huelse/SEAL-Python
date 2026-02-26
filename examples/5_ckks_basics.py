import math
from seal import *
from seal_helper import print_example_banner, print_parameters, print_vector


def ckks_basics():
    print_example_banner("Example: CKKS Basics")

    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))

    context = SEALContext(parms)
    print_parameters(context)

    encoder = CKKSEncoder(context)
    keygen = KeyGenerator(context)
    encryptor = Encryptor(context, keygen.create_public_key())
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, keygen.secret_key())
    relin_keys = keygen.create_relin_keys()

    scale = 2.0 ** 40
    input_vec = [0.0, 0.4, 0.8, 1.2]
    x_plain = encoder.encode(input_vec, scale)
    x1_encrypted = encryptor.encrypt(x_plain)
    x2_encrypted = evaluator.square(x1_encrypted)
    evaluator.relinearize_inplace(x2_encrypted, relin_keys)
    evaluator.rescale_to_next_inplace(x2_encrypted)

    plain_coeff3 = encoder.encode(3.14159265, scale)
    plain_coeff1 = encoder.encode(0.4, scale)
    plain_coeff0 = encoder.encode(1.0, scale)

    evaluator.mod_switch_to_inplace(plain_coeff3, x2_encrypted.parms_id())
    x3_encrypted = evaluator.multiply_plain(x2_encrypted, plain_coeff3)
    evaluator.rescale_to_next_inplace(x3_encrypted)

    x1_encrypted_linear = evaluator.multiply_plain(x1_encrypted, plain_coeff1)
    evaluator.rescale_to_next_inplace(x1_encrypted_linear)
    evaluator.mod_switch_to_inplace(x1_encrypted_linear, x3_encrypted.parms_id())

    evaluator.mod_switch_to_inplace(plain_coeff0, x3_encrypted.parms_id())

    x3_encrypted.scale(scale)
    x1_encrypted_linear.scale(scale)
    encrypted_result = evaluator.add(x3_encrypted, x1_encrypted_linear)
    encrypted_result = evaluator.add_plain(encrypted_result, plain_coeff0)

    plain_result = decryptor.decrypt(encrypted_result)
    result = encoder.decode(plain_result)

    expected = [3.14159265 * (x * x) + 0.4 * x + 1.0 for x in input_vec]
    print("expected:")
    print_vector(expected, 4, 6)
    print("computed:")
    print_vector(result, 4, 6)


if __name__ == "__main__":
    ckks_basics()
