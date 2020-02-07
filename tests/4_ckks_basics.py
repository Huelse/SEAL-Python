import math
from seal import *
from seal_helper import *


def example_ckks_basics():
    print_example_banner("Example: CKKS Basics")

    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [60, 40, 40, 60]))

    scale = pow(2.0, 40)
    context = SEALContext.Create(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    encoder = CKKSEncoder(context)
    slot_count = encoder.slot_count()
    print("Number of slots: " + str(slot_count))

    inputs = DoubleVector()
    curr_point = 0.0
    step_size = 1.0 / (slot_count - 1)

    for i in range(slot_count):
        inputs.append(curr_point)
        curr_point += step_size

    print("Input vector: ")
    print_vector(inputs, 3, 7)

    print("Evaluating polynomial PI*x^3 + 0.4x + 1 ...")

    '''
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    '''
    plain_coeff3 = Plaintext()
    plain_coeff1 = Plaintext()
    plain_coeff0 = Plaintext()
    encoder.encode(3.14159265, scale, plain_coeff3)
    encoder.encode(0.4, scale, plain_coeff1)
    encoder.encode(1.0, scale, plain_coeff0)

    x_plain = Plaintext()
    print("-" * 50)
    print("Encode input vectors.")
    encoder.encode(inputs, scale, x_plain)
    x1_encrypted = Ciphertext()
    encryptor.encrypt(x_plain, x1_encrypted)

    x3_encrypted = Ciphertext()
    print("-" * 50)
    print("Compute x^2 and relinearize:")
    evaluator.square(x1_encrypted, x3_encrypted)
    evaluator.relinearize_inplace(x3_encrypted, relin_keys)
    print("    + Scale of x^2 before rescale: " +
          "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")

    print("-" * 50)
    print("Rescale x^2.")
    evaluator.rescale_to_next_inplace(x3_encrypted)
    print("    + Scale of x^2 after rescale: " +
          "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")

    print("-" * 50)
    print("Compute and rescale PI*x.")
    x1_encrypted_coeff3 = Ciphertext()
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3)
    print("    + Scale of PI*x before rescale: " +
          "%.0f" % math.log(x1_encrypted_coeff3.scale(), 2) + " bits")
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3)
    print("    + Scale of PI*x after rescale: " +
          "%.0f" % math.log(x1_encrypted_coeff3.scale(), 2) + " bits")

    print("-" * 50)
    print("Compute, relinearize, and rescale (PI*x)*x^2.")
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3)
    evaluator.relinearize_inplace(x3_encrypted, relin_keys)
    print("    + Scale of PI*x^3 before rescale: " +
          "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")
    evaluator.rescale_to_next_inplace(x3_encrypted)
    print("    + Scale of PI*x^3 after rescale: " +
          "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")

    print("-" * 50)
    print("Compute and rescale 0.4*x.")
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1)
    print("    + Scale of 0.4*x before rescale: " +
          "%.0f" % math.log(x1_encrypted.scale(), 2) + " bits")
    evaluator.rescale_to_next_inplace(x1_encrypted)
    print("    + Scale of 0.4*x after rescale: " +
          "%.0f" % math.log(x1_encrypted.scale(), 2) + " bits")
    print()

    print("-" * 50)
    print("Parameters used by all three terms are different.")
    print("    + Modulus chain index for x3_encrypted: " +
          str(context.get_context_data(x3_encrypted.parms_id()).chain_index()))
    print("    + Modulus chain index for x1_encrypted: " +
          str(context.get_context_data(x1_encrypted.parms_id()).chain_index()))
    print("    + Modulus chain index for x1_encrypted: " +
          str(context.get_context_data(plain_coeff0.parms_id()).chain_index()))
    print()

    print("-" * 50)
    print("The exact scales of all three terms are different:")
    print("    + Exact scale in PI*x^3: " + "%.10f" % x3_encrypted.scale())
    print("    + Exact scale in  0.4*x: " + "%.10f" % x1_encrypted.scale())
    print("    + Exact scale in      1: " + "%.10f" % plain_coeff0.scale())

    print("-" * 50)
    print("Normalize scales to 2^40.")

    # set_scale() this function should be add to seal/ciphertext.h line 632
    x3_encrypted.set_scale(pow(2.0, 40))
    x1_encrypted.set_scale(pow(2.0, 40))

    '''
    We still have a problem with mismatching encryption parameters. This is easy
        to fix by using traditional modulus switching (no rescaling). CKKS supports
        modulus switching just like the BFV scheme, allowing us to switch away parts
        of the coefficient modulus when it is simply not needed.
    '''
    print("-" * 50)
    print("Normalize encryption parameters to the lowest level.")
    last_parms_id = x3_encrypted.parms_id()
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id)
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id)

    '''
    All three ciphertexts are now compatible and can be added.
    '''
    print("-" * 50)
    print("Compute PI*x^3 + 0.4*x + 1.")

    encrypted_result = Ciphertext()
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result)
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0)

    '''
    First print the true result.
    '''
    plain_result = Plaintext()
    print("-" * 50)
    print("Decrypt and decode PI*x^3 + 0.4x + 1.")
    print("    + Expected result:")
    true_result = []
    for x in inputs:
        true_result.append((3.14159265 * x * x + 0.4) * x + 1)
    print_vector(true_result, 3, 7)

    '''
    Decrypt, decode, and print the result.
    '''

    decryptor.decrypt(encrypted_result, plain_result)
    result = DoubleVector()
    encoder.decode(plain_result, result)
    print("    + Computed result ...... Correct.")
    print_vector(result, 3, 7)

    '''
    While we did not show any computations on complex numbers in these examples,
        the CKKSEncoder would allow us to have done that just as easily. Additions
        and multiplications of complex numbers behave just as one would expect.
    '''


if __name__ == '__main__':
    example_ckks_basics()
