from seal import *
from seal_helper import print_example_banner, print_parameters


def bfv_basics():
    print_example_banner("Example: BFV Basics")

    parms = EncryptionParameters(scheme_type.bfv)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(1024)

    context = SEALContext(parms)
    print_parameters(context)
    print(f"parameter validation: {context.parameter_error_message()}")

    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.create_public_key()
    relin_keys = keygen.create_relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    x = 6
    x_plain = Plaintext(str(x))
    x_encrypted = encryptor.encrypt(x_plain)
    print(f"fresh ciphertext size: {x_encrypted.size()}")
    print(f"fresh noise budget: {decryptor.invariant_noise_budget(x_encrypted)} bits")

    x_squared = evaluator.square(x_encrypted)
    evaluator.relinearize_inplace(x_squared, relin_keys)

    one = Plaintext("1")
    x_sq_plus_one = evaluator.add_plain(x_squared, one)

    x_plus_one = evaluator.add_plain(x_encrypted, one)
    x_plus_one_sq = evaluator.square(x_plus_one)
    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys)

    four = Plaintext("4")
    evaluator.multiply_plain_inplace(x_sq_plus_one, four)
    encrypted_result = evaluator.multiply(x_sq_plus_one, x_plus_one_sq)
    evaluator.relinearize_inplace(encrypted_result, relin_keys)

    plain_result = decryptor.decrypt(encrypted_result)
    print("decrypted 4(x^2+1)(x+1)^2 (hex):", plain_result.to_string())
    print(f"result noise budget: {decryptor.invariant_noise_budget(encrypted_result)} bits")


if __name__ == "__main__":
    bfv_basics()
