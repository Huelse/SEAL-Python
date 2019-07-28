from seal import *


def print_example_banner(title):
    title_length = len(title)
    banner_length = title_length + 2 * 10
    banner_top = "+" + "-" * (banner_length - 2) + "+"
    banner_middle = "|" + ' ' * 9 + title + ' ' * 9 + "|"
    print(banner_top)
    print(banner_middle)
    print(banner_top)


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
    print("| coeff_modulus size: ", end="")
    coeff_modulus = context_data.parms().coeff_modulus()
    coeff_modulus_sum = 0
    for j in coeff_modulus:
        coeff_modulus_sum += j.bit_count()
    print(str(coeff_modulus_sum) + "(", end="")
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
    current_line = "    [ "
    for i in range(print_size):
        current_line += ((str)(matrix[i]) + ", ")
    current_line += ("..., ")
    for i in range(row_size - print_size, row_size):
        current_line += ((str)(matrix[i]))
        if i != row_size-1:
            current_line += ", "
        else:
            current_line += " ]"
    print(current_line)

    current_line = "    [ "
    for i in range(row_size, row_size + print_size):
        current_line += ((str)(matrix[i]) + ", ")
    current_line += ("..., ")
    for i in range(2*row_size - print_size, 2*row_size):
        current_line += ((str)(matrix[i]))
        if i != 2*row_size-1:
            current_line += ", "
        else:
            current_line += " ]"
    print(current_line)
    print()


def print_vector(vec, print_size=4, prec=3):
    slot_count = len(vec)
    print()
    if slot_count <= 2*print_size:
        print("    [", end="")
        for i in range(slot_count):
            print(" " + (f"%.{prec}f" % vec[i]) + ("," if (i != slot_count - 1) else " ]\n"), end="")
    else:
        print("    [", end="")
        for i in range(print_size):
            print(" " + (f"%.{prec}f" % vec[i]) + ",", end="")
        if len(vec) > 2*print_size:
            print(" ...,", end="")
        for i in range(slot_count - print_size, slot_count):
            print(" " + (f"%.{prec}f" % vec[i]) + ("," if (i != slot_count - 1) else " ]\n"), end="")
    print()


def example_rotation_bfv():
    print_example_banner("Example: Rotation / Rotation in BFV")
    parms = EncryptionParameters(scheme_type.BFV)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

    context = SEALContext.Create(parms)
    print_parameters(context)
    print("-" * 50)

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

    pod_matrix = uIntVector()
    for i in range(slot_count):
        pod_matrix.push_back(pod_matrixs[i])

    print("Input plaintext matrix:")
    print_matrix(pod_matrix, row_size)

    '''
	First we use BatchEncoder to encode the matrix into a plaintext. We encrypt
    	the plaintext as usual.
	'''
    plain_matrix = Plaintext()
    print("-" * 50)
    print("Encode and encrypt.")
    batch_encoder.encode(pod_matrix, plain_matrix)
    encrypted_matrix = Ciphertext()
    encryptor.encrypt(plain_matrix, encrypted_matrix)
    print("    + Noise budget in fresh encryption: " +
          str(decryptor.invariant_noise_budget(encrypted_matrix)) + " bits")

    '''
	Rotations require yet another type of special key called `Galois keys'. These
    	are easily obtained from the KeyGenerator.
	'''
    gal_keys = keygen.galois_keys()
    '''
	Now rotate both matrix rows 3 steps to the left, decrypt, decode, and print.
	'''
    print("-" * 50)
    print("Rotate rows 3 steps left.")

    evaluator.rotate_rows_inplace(encrypted_matrix, 3, gal_keys)
    plain_result = Plaintext()
    print("    + Noise budget after rotation: " +
          str(decryptor.invariant_noise_budget(encrypted_matrix)) + " bits")
    print("    + Decrypt and decode ...... Correct.")
    decryptor.decrypt(encrypted_matrix, plain_result)
    batch_encoder.decode(plain_result, pod_matrix)
    print_matrix(pod_matrix, row_size)

    '''
    We can also rotate the columns, i.e., swap the rows.
    '''
    print("-" * 50)
    print("Rotate columns.")
    evaluator.rotate_columns_inplace(encrypted_matrix, gal_keys)
    print("    + Noise budget after rotation: " +
          str(decryptor.invariant_noise_budget(encrypted_matrix)) + " bits")
    print("    + Decrypt and decode ...... Correct.")
    decryptor.decrypt(encrypted_matrix, plain_result)
    batch_encoder.decode(plain_result, pod_matrix)
    print_matrix(pod_matrix, row_size)

    '''
    Finally, we rotate the rows 4 steps to the right, decrypt, decode, and print.
    '''
    print("-" * 50)
    print("Rotate rows 4 steps right.")
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, gal_keys)
    print("    + Noise budget after rotation: " +
          str(decryptor.invariant_noise_budget(encrypted_matrix)) + " bits")
    print("    + Decrypt and decode ...... Correct.")
    decryptor.decrypt(encrypted_matrix, plain_result)
    batch_encoder.decode(plain_result, pod_matrix)
    print_matrix(pod_matrix, row_size)

    '''
    Note that rotations do not consume any noise budget. However, this is only
    the case when the special prime is at least as large as the other primes. The
    same holds for relinearization. Microsoft SEAL does not require that the
    special prime is of any particular size, so ensuring this is the case is left
    for the user to do.
    '''


def example_rotation_ckks():
    print_example_banner("Example: Rotation / Rotation in CKKS")
    parms = EncryptionParameters(scheme_type.CKKS)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [40, 40, 40, 40, 40]))
    context = SEALContext.Create(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    gal_keys = keygen.galois_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    print("Number of slots: " + str(slot_count))
    # inputer = [0] * slot_count
    inputs = DoubleVector()
    curr_point = 0.0
    step_size = 1.0 / (slot_count - 1)

    for i in range(slot_count):
        inputs.push_back(curr_point)
        curr_point += step_size

    print("Input vector:")
    print_vector(inputs, 3, 7)

    scale = pow(2.0, 50)

    print("-" * 50)
    print("Encode and encrypt.")
    plain = Plaintext()

    ckks_encoder.encode(inputs, scale, plain)
    encrypted = Ciphertext()
    encryptor.encrypt(plain, encrypted)

    rotated = Ciphertext()
    print("-" * 50)
    print("Rotate 2 steps left.")
    evaluator.rotate_vector(encrypted, 2, gal_keys, rotated)
    print("    + Decrypt and decode ...... Correct.")
    decryptor.decrypt(rotated, plain)
    result = DoubleVector()
    ckks_encoder.decode(plain, result)
    print_vector(result, 3, 7)

    '''
    With the CKKS scheme it is also possible to evaluate a complex conjugation on
    a vector of encrypted complex numbers, using Evaluator::complex_conjugate.
    This is in fact a kind of rotation, and requires also Galois keys.
    '''


if __name__ == '__main__':
    print_example_banner("Example: Rotation")

    example_rotation_bfv()
    example_rotation_ckks()
