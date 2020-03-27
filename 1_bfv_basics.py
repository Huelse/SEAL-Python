from seal import *
from tests.seal_helper import *


def example_bfv_basics():
    print_example_banner("Example: BFV Basics")
    parms = EncryptionParameters(scheme_type.BFV)

    poly_modulus_degree = 4096
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(256)

    context = SEALContext.Create(parms)

    print("-" * 50)
    print("Set encryption parameters and print")
    print_parameters(context)
    print("~~~~~~ A naive way to calculate 2(x^2+1)(x+1)^2. ~~~~~~")

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()

    encryptor = Encryptor(context, public_key)

    evaluator = Evaluator(context)

    decryptor = Decryptor(context, secret_key)

    print("-" * 50)
    x = "6"
    x_plain = Plaintext(x)
    print("Express x = " + x + " as a plaintext polynomial 0x" +
          x_plain.to_string() + ".")

    print("-" * 50)
    x_encrypted = Ciphertext()
    print("Encrypt x_plain to x_encrypted.")
    encryptor.encrypt(x_plain, x_encrypted)

    print('-'*100)
    x_encrypted.save('cipher.bin')
    print('-'*100)
    print("    + size of freshly encrypted x: " + str(x_encrypted.size()))

    print("    + noise budget in freshly encrypted x: " +
          str(decryptor.invariant_noise_budget(x_encrypted)) + " bits")

    print('-'*100)
    loads = Ciphertext()
    loads.load(context, 'cipher.bin')
    print('-'*100)

    x_decrypted = Plaintext()
    print("    + decryption of x_encrypted: ", end="")
    decryptor.decrypt(loads, x_decrypted)
    print("0x" + x_decrypted.to_string() + " ...... Correct.")


if __name__ == '__main__':
    example_bfv_basics()
