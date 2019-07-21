import math
from seal import *


def print_example_banner(title, ch='*', length=78):
    spaced_text = ' %s ' % title
    print(spaced_text.center(length, ch))


def print_parameters(context):
    context_data = context.key_context_data()
    if context_data.parms().scheme() == scheme_type.BFV:
        scheme_name = "BFV"
    elif context_data.parms().scheme() == scheme_type.CKKS:
        scheme_name = "CKKS"
    else:
        scheme_name = "unsupported scheme"
    print("/")
    print("| Encryption parameters:")
    print("| scheme: " + scheme_name)
    print("| poly_modulus_degree: " +
          str(context_data.parms().poly_modulus_degree()))
    print("| coeff_modulus size: (", end="")
    coeff_modulus = context_data.parms().coeff_modulus()
    for i in range(len(coeff_modulus) - 1):
        print(str(coeff_modulus[i].bit_count()) + " + ", end="")
    print(str(coeff_modulus[-1].bit_count()) + ") bits")
    if context_data.parms().scheme() == scheme_type.BFV:
        print("| plain_modulus: " +
              str(context_data.parms().plain_modulus().value()))
    print("\\")


def print_matrix(matrix, row_size):
    print()
    print_size = 5
    current_line = "    ["
    for i in range(print_size):
        current_line += ((str)(matrix[i]) + ", ")
    current_line += ("..., ")
    for i in range(row_size - print_size, row_size):
        current_line += ((str)(matrix[i]))
        if i != row_size - 1:
            current_line += ", "
        else:
            current_line += "]"
    print(current_line)

    current_line = "    ["
    for i in range(row_size, row_size + print_size):
        current_line += ((str)(matrix[i]) + ", ")
    current_line += ("..., ")
    for i in range(2 * row_size - print_size, 2 * row_size):
        current_line += ((str)(matrix[i]))
        if i != 2 * row_size - 1:
            current_line += ", "
        else:
            current_line += "]"
    print(current_line)
    print()


def print_vector(vector, print_size=4, prec=3):
    slot_count = len(vector)
    if slot_count <= 2 * print_size:
        print()
        print("    [ ", end="")
        for i in range(slot_count - 1):
            print(str(vector[i]) + ", ", end="")
        print(str(vector[-1]) + " ]")
        print()
    else:
        print()
        print("    [ ", end="")
        for i in range(4):
            print(str(vector[i]) + ", ", end="")
        print(" ..., ", end="")
        for j in range(4):
            print(str(vector[j - 4]) + ", ", end="")
        print(str(vector[-1]) + " ]")
        print()


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
    print('-' * 50)
    print("Encode " + str(value1) + " as polynomial " +
          plain1.to_string() + " (plain1),")
    value2 = -7
    plain2 = Plaintext(encoder.encode(value2))
    print("encode " + str(value2) + " as polynomial " +
          plain2.to_string() + " (plain2).")

    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()
    print('-' * 50)
    print("Encrypt plain1 to encrypted1 and plain2 to encrypted2.")
    encryptor.encrypt(plain1, encrypted1)
    encryptor.encrypt(plain2, encrypted2)
    print("    + Noise budget in encrypted1: " +
          str(decryptor.invariant_noise_budget(encrypted1)) + " bits")
    print("    + Noise budget in encrypted2: " +
          str(decryptor.invariant_noise_budget(encrypted2)) + " bits")

    pool = MemoryPoolHandle().New(False)
    encryptor.encrypt(plain2, encrypted2)
    encrypted_result = Ciphertext()
    print('-' * 50)
    print("Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2.")
    evaluator.negate(encrypted1, encrypted_result)
    evaluator.add_inplace(encrypted_result, encrypted2)
    evaluator.multiply_inplace(encrypted_result, encrypted2, pool)
    print("    + Noise budget in encrypted_result: " +
          str(decryptor.invariant_noise_budget(encrypted_result)) + " bits")
    plain_result = Plaintext()
    print('-' * 50)
    print("Decrypt encrypted_result to plain_result.")
    decryptor.decrypt(encrypted_result, plain_result)
    print("    + Plaintext polynomial: " + plain_result.to_string())
    print('-' * 50)
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

    pod_matrix = [0] * slot_count
    pod_matrix[0] = 0
    pod_matrix[1] = 1
    pod_matrix[2] = 2
    pod_matrix[3] = 3
    pod_matrix[row_size] = 4
    pod_matrix[row_size + 1] = 5
    pod_matrix[row_size + 2] = 6
    pod_matrix[row_size + 3] = 7

    print("Input plaintext matrix:")
    print_matrix(pod_matrix, row_size)

    plain_matrix = Plaintext()
    print('-' * 50)
    print("Encode plaintext matrix:")
    batch_encoder.encode(pod_matrix, plain_matrix)
    print("    + Decode plaintext matrix ...... Correct.")
    pod_result = pod_matrix
    # pod_result = [plain_matrix.data(i) for i in range(plain_matrix.coeff_count())]

    pool = MemoryPoolHandle().New(False)
    batch_encoder.decode(plain_matrix, pod_result, pool)
    print_matrix(pod_result, row_size)

    encrypted_matrix = Ciphertext()
    print('-' * 50)
    print("Encrypt plain_matrix to encrypted_matrix.")
    encryptor.encrypt(plain_matrix, encrypted_matrix)
    print("    + Noise budget in encrypted_matrix: " +
          str(decryptor.invariant_noise_budget(encrypted_matrix)) + " bits")

    pod_matrix2 = [0] * slot_count
    for i in range(slot_count):
        pod_matrix2[i] = (i % 2) + 1

    plain_matrix2 = Plaintext()
    batch_encoder.encode(pod_matrix2, plain_matrix2)
    print("Second input plaintext matrix:")
    print_matrix(pod_matrix2, row_size)

    print('-' * 50)
    print("Sum, square, and relinearize.")
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2)
    evaluator.square_inplace(encrypted_matrix, pool)
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys, pool)

    print("    + Noise budget in result: " +
          str(decryptor.invariant_noise_budget(encrypted_matrix)) + " bits")

    plain_result = Plaintext()
    print('-' * 50)
    print("Decrypt and decode result.")
    decryptor.decrypt(encrypted_matrix, plain_result)
    batch_encoder.decode(plain_result, pod_result, pool)
    print("    + Result plaintext matrix ...... Correct.")
    print_matrix(pod_result, row_size)


def example_ckks_encoder():
    print_example_banner("Example: Encoders / CKKS Encoder")
    parms = EncryptionParameters(scheme_type.CKKS)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [40] * 5))

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
    inputs = [0.0, 1.1, 2.2, 3.3]
    print('-' * 50)
    print("Input vector: ")
    print_vector(inputs)

    plain = Plaintext()
    scale = 2.0**30
    #pool = MemoryPoolHandle().New(False)
    pool = MemoryManager.GetPool()
    print("Encode input vector.")
    encoder.encode(inputs, scale, plain, pool)

    output = inputs
    print("    + Decode input vector ...... Correct.")
    encoder.decode(plain, output, pool)
    print_vector(output)

    encrypted = Ciphertext()
    print('-' * 50)
    print("Encrypt input vector, square, and relinearize.")
    encryptor.encrypt(plain, encrypted)
    evaluator.square_inplace(encrypted, pool)
    evaluator.relinearize_inplace(encrypted, relin_keys, pool)

    print("    + Scale in squared input: " + str(encrypted.scale()), end="")
    print(" (" + str(math.log(encrypted.scale(), 2)) + " bits)")

    print('-' * 50)
    print("Decrypt and decode.")
    decryptor.decrypt(encrypted, plain)
    encoder.decode(plain, output, pool)
    print("    + Result vector ...... Correct.")
    print_vector(output)


if __name__ == '__main__':
    example_integer_encoder()
    example_batch_encoder()
    example_ckks_encoder()
