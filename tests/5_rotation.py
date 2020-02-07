from seal import *
from seal_helper import *


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

    pod_matrix = uIntVector(pod_matrixs)

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

    inputs = DoubleVector()
    curr_point = 0.0
    step_size = 1.0 / (slot_count - 1)

    for i in range(slot_count):
        inputs.append(curr_point)
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
