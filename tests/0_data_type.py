from seal import *
from seal_helper import *
import numpy as np


def example_data_type():
    a = [0.1, 0.3, 1.01, 0.2]
    b = DoubleVector(a)
    print(a)  # [0.1, 0.3, 1.01, 0.2]
    c = np.array(b)
    print(c)  # [0.1  0.3  1.01 0.2 ]

    d = IntVector([0]*10)
    print(len(d))  # 10
    d[4] = 1
    e = np.array(d)
    print(e)  # [0 0 0 0 1 0 0 0 0 0]


def example_serialize():
    print_example_banner("Example: save & load")
    parms = EncryptionParameters(scheme_type.BFV)

    poly_modulus_degree = 4096
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(256)

    parms.save("parms")
    parms_loaded = EncryptionParameters(scheme_type.BFV)
    parms_loaded.load("parms")

    context = SEALContext.Create(parms_loaded)

    print("-" * 50)
    print("Set encryption parameters and print")
    print_parameters(context)

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
    x_save = Ciphertext()
    print("Encrypt x_plain to x_save.")
    encryptor.encrypt(x_plain, x_save)

    print("\nx_save scale: %.1f" % x_save.scale())
    print("x_save parms_id: ", end="")
    print(x_save.parms_id())

    x_save.save("temp")
    x_read = Ciphertext()
    x_read.load(context, "temp")

    print("\nx_read scale: %.1f" % x_read.scale())
    print("x_read parms_id: ", end="")
    print(x_read.parms_id())


if __name__ == '__main__':
    example_data_type()
    example_serialize()
