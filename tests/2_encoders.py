import math
from seal import *
from seal_helper import *


def example_integer_encoder():
    print_example_banner("Example: Encoders / Integer Encoder")
    parms = EncryptionParameters(scheme_type.BFV)
    poly_modulus_degree = 4096
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(512)
    context = SEALContext.Create(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)
    encoder = IntegerEncoder(context)
    value1 = 5
    plain1 = Plaintext(encoder.encode(value1))
    print("-" * 50)
    print("Encode " + str(value1) + " as polynomial " +
          plain1.to_string() + " (plain1),")
    value2 = -7
    plain2 = Plaintext(encoder.encode(value2))
    print("encode " + str(value2) + " as polynomial " +
          plain2.to_string() + " (plain2).")

    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()
    print("-" * 50)
    print("Encrypt plain1 to encrypted1 and plain2 to encrypted2.")
    encryptor.encrypt(plain1, encrypted1)
    encryptor.encrypt(plain2, encrypted2)
    print("    + Noise budget in encrypted1: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted1) + " bits")
    print("    + Noise budget in encrypted2: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted2) + " bits")

    encryptor.encrypt(plain2, encrypted2)
    encrypted_result = Ciphertext()
    print("-" * 50)
    print("Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2.")
    evaluator.negate(encrypted1, encrypted_result)
    evaluator.add_inplace(encrypted_result, encrypted2)
    evaluator.multiply_inplace(encrypted_result, encrypted2)
    print("    + Noise budget in encrypted_result: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted_result) + " bits")
    plain_result = Plaintext()
    print("-" * 50)
    print("Decrypt encrypted_result to plain_result.")
    decryptor.decrypt(encrypted_result, plain_result)
    print("    + Plaintext polynomial: " + plain_result.to_string())
    print("-" * 50)
    print("Decode plain_result.")
    print("    + Decoded integer: " +
          str(encoder.decode_int32(plain_result)) + "...... Correct.")


def example_batch_encoder():
    print_example_banner("Example: Encoders / Batch Encoder")
    parms = EncryptionParameters(scheme_type.BFV)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
    context = SEALContext.Create(parms)
    print_parameters(context)

    qualifiers = context.first_context_data().qualifiers()
    print("Batching enabled: " + str(qualifiers.using_batching))

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    batch_encoder = BatchEncoder(context)
    slot_count = batch_encoder.slot_count()
    row_size = int(slot_count / 2)
    print("Plaintext matrix row size: " + str(row_size))

    pod_matrixs = [0] * slot_count
    pod_matrixs[0] = 0
    pod_matrixs[1] = 1
    pod_matrixs[2] = 2
    pod_matrixs[3] = 3
    pod_matrixs[row_size] = 4
    pod_matrixs[row_size + 1] = 5
    pod_matrixs[row_size + 2] = 6
    pod_matrixs[row_size + 3] = 7

    pod_matrix = uIntVector(pod_matrixs)

    print("Input plaintext matrix:")
    print_matrix(pod_matrix, row_size)

    plain_matrix = Plaintext()
    print("-" * 50)
    print("Encode plaintext matrix:")
    batch_encoder.encode(pod_matrix, plain_matrix)

    pod_result = uIntVector()
    print("    + Decode plaintext matrix ...... Correct.")

    batch_encoder.decode(plain_matrix, pod_result)
    print_matrix(pod_result, row_size)

    encrypted_matrix = Ciphertext()
    print("-" * 50)
    print("Encrypt plain_matrix to encrypted_matrix.")
    encryptor.encrypt(plain_matrix, encrypted_matrix)
    print("    + Noise budget in encrypted_matrix: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted_matrix) + " bits")

    pod_matrix2 = uIntVector()
    for i in range(slot_count):
        pod_matrix2.append((i % 2) + 1)

    plain_matrix2 = Plaintext()
    batch_encoder.encode(pod_matrix2, plain_matrix2)
    print("Second input plaintext matrix:")
    print_matrix(pod_matrix2, row_size)

    print("-" * 50)
    print("Sum, square, and relinearize.")
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2)
    evaluator.square_inplace(encrypted_matrix)
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys)

    print("    + Noise budget in result: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted_matrix) + " bits")

    plain_result = Plaintext()
    print("-" * 50)
    print("Decrypt and decode result.")
    decryptor.decrypt(encrypted_matrix, plain_result)
    batch_encoder.decode(plain_result, pod_result)
    print("    + Result plaintext matrix ...... Correct.")
    print_matrix(pod_result, row_size)


def example_ckks_encoder():
    print_example_banner("Example: Encoders / CKKS Encoder")

    '''
    [CKKSEncoder] (For CKKS scheme only)

    In this example we demonstrate the Cheon-Kim-Kim-Song (CKKS) scheme for
    computing on encrypted real or complex numbers. We start by creating
    encryption parameters for the CKKS scheme. There are two important
    differences compared to the BFV scheme:

        (1) CKKS does not use the plain_modulus encryption parameter;
        (2) Selecting the coeff_modulus in a specific way can be very important
            when using the CKKS scheme. We will explain this further in the file
            `ckks_basics.cpp'. In this example we use CoeffModulus::Create to
            generate 5 40-bit prime numbers.
    '''

    parms = EncryptionParameters(scheme_type.CKKS)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [40, 40, 40, 40, 40]))

    '''
    We create the SEALContext as usual and print the parameters.
    '''

    context = SEALContext.Create(parms)
    print_parameters(context)

    '''
    Keys are created the same way as for the BFV scheme.
    '''

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()

    '''
    We also set up an Encryptor, Evaluator, and Decryptor as usual.
    '''

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    '''
    To create CKKS plaintexts we need a special encoder: there is no other way
    to create them. The IntegerEncoder and BatchEncoder cannot be used with the
    CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
    Plaintext objects, which can subsequently be encrypted. At a high level this
    looks a lot like what BatchEncoder does for the BFV scheme, but the theory
    behind it is completely different.
    '''

    encoder = CKKSEncoder(context)

    '''
    In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes
    one real or complex number. This should be contrasted with BatchEncoder in
    the BFV scheme, where the number of slots is equal to poly_modulus_degree
    and they are arranged into a matrix with two rows.
    '''

    slot_count = encoder.slot_count()
    print("Number of slots: " + str(slot_count))

    '''
    We create a small vector to encode; the CKKSEncoder will implicitly pad it
    with zeros to full size (poly_modulus_degree / 2) when encoding.
    '''

    inputs = DoubleVector([0.0, 1.1, 2.2, 3.3])

    print("Input vector: ")
    print_vector(inputs)

    '''
    Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
    will be scaled up by the parameter `scale'. This is necessary since even in
    the CKKS scheme the plaintext elements are fundamentally polynomials with
    integer coefficients. It is instructive to think of the scale as determining
    the bit-precision of the encoding; naturally it will affect the precision of
    the result.

    In CKKS the message is stored modulo coeff_modulus (in BFV it is stored modulo
    plain_modulus), so the scaled message must not get too close to the total size
    of coeff_modulus. In this case our coeff_modulus is quite large (218 bits) so
    we have little to worry about in this regard. For this simple example a 30-bit
    scale is more than enough.
    '''

    plain = Plaintext()
    scale = pow(2.0, 30)
    print("-" * 50)

    print("Encode input vector.")
    encoder.encode(inputs, scale, plain)

    '''
    We can instantly decode to check the correctness of encoding.
    '''

    output = DoubleVector()
    print("    + Decode input vector ...... Correct.")
    encoder.decode(plain, output)
    print_vector(output)

    '''
    The vector is encrypted the same was as in BFV.
    '''

    encrypted = Ciphertext()
    print("-" * 50)
    print("Encrypt input vector, square, and relinearize.")
    encryptor.encrypt(plain, encrypted)

    '''
    Basic operations on the ciphertexts are still easy to do. Here we square the
    ciphertext, decrypt, decode, and print the result. We note also that decoding
    returns a vector of full size (poly_modulus_degree / 2); this is because of
    the implicit zero-padding mentioned above.
    '''

    evaluator.square_inplace(encrypted)
    evaluator.relinearize_inplace(encrypted, relin_keys)

    '''
    We notice that the scale in the result has increased. In fact, it is now the
    square of the original scale: 2^60.
    '''

    print("    + Scale in squared input: " + str(encrypted.scale()), end="")
    print(" (" + "%.0f" % math.log(encrypted.scale(), 2) + " bits)")

    print("-" * 50)
    print("Decrypt and decode.")
    decryptor.decrypt(encrypted, plain)
    encoder.decode(plain, output)
    print("    + Result vector ...... Correct.")
    print_vector(output)

    '''
    The CKKS scheme allows the scale to be reduced between encrypted computations.
    This is a fundamental and critical feature that makes CKKS very powerful and
    flexible. We will discuss it in great detail in `3_levels.cpp' and later in
    `4_ckks_basics.cpp'.
    '''


if __name__ == '__main__':
    print_example_banner("Example: Encoders")

    example_integer_encoder()
    example_batch_encoder()
    example_ckks_encoder()
