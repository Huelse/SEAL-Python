from seal import *
from seal_helper import print_example_banner, print_parameters


def levels_example():
    print_example_banner("Example: Levels")

    parms = EncryptionParameters(scheme_type.bfv)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [50, 30, 30, 50, 50]))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

    context = SEALContext(parms)
    print_parameters(context)

    context_data = context.key_context_data()
    print("modulus switching chain:")
    while context_data is not None:
        print(f"  chain index: {context_data.chain_index()}, coeff modulus count: {len(context_data.parms().coeff_modulus())}")
        context_data = context_data.next_context_data()

    keygen = KeyGenerator(context)
    encryptor = Encryptor(context, keygen.create_public_key())
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, keygen.secret_key())

    plain = Plaintext("1x^3 + 2x^2 + 3x^1 + 4")
    encrypted = encryptor.encrypt(plain)

    print("noise budget while switching levels:")
    while True:
        print(f"  {decryptor.invariant_noise_budget(encrypted)} bits")
        try:
            evaluator.mod_switch_to_next_inplace(encrypted)
        except ValueError:
            break

    decrypted = decryptor.decrypt(encrypted)
    print("decrypted after switching:", decrypted.to_string())


if __name__ == "__main__":
    levels_example()
