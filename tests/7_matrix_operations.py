import time
import numpy as np
from seal import *
from seal_helper import *


def get_diagonal(position, matrix_u):
    n = matrix_u.shape[0]
    diagonal = np.zeros(n)

    k = 0
    i = 0
    j = position
    while i < n-position and j < n:
        diagonal[k] = matrix_u[i][j]
        i += 1
        j += 1
        k += 1
    i = n - position
    j = 0
    while i < n and j < position:
        diagonal[k] = matrix_u[i][j]
        i += 1
        j += 1
        k += 1

    return diagonal


def get_u_transpose(shape):
    u_transpose = np.zeros((shape[0]**2, shape[1]**2))
    n = shape[0]
    k = 0
    i = 0
    for row in u_transpose:
        row[k+i] = 1
        k += n
        if k >= n*n:
            k = 0
            i += 1

    return u_transpose


def get_transposed_diagonals(u_transposed):
    transposed_diagonals = np.zeros(u_transposed.shape)
    for i in range(u_transposed.shape[0]):
        a = np.diagonal(u_transposed, offset=i)
        b = np.diagonal(u_transposed, offset=u_transposed.shape[0]-i)
        transposed_diagonals[i] = np.concatenate([a, b])

    return transposed_diagonals


def linear_transform_plain(cipher_matrix, plain_u_diag, galois_keys, evaluator):
    ct_rot = Ciphertext()
    evaluator.rotate_vector(
        cipher_matrix, -len(plain_u_diag), galois_keys, ct_rot)
    ct_new = Ciphertext()
    evaluator.add(cipher_matrix, ct_rot, ct_new)
    temp = Ciphertext()
    ct_result = []
    evaluator.multiply_plain(ct_new, plain_u_diag[0], temp)
    ct_result.append(temp)

    i = 1
    while i < len(plain_u_diag):
        temp_rot = Ciphertext()
        evaluator.rotate_vector(ct_new, i, galois_keys, temp_rot)
        temp = Ciphertext()
        evaluator.multiply_plain(temp_rot, plain_u_diag[i], temp)
        ct_result.append(temp)
        i += 1

    ct_prime = Ciphertext()
    evaluator.add_many(ct_result, ct_prime)

    return ct_prime


def matrix_transpose_test(n=4):
    parms = EncryptionParameters(scheme_type.CKKS)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [60, 40, 40, 60]))
    scale = 2.0**40
    context = SEALContext.Create(parms)
    print_parameters(context)

    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    print("Number of slots: {}".format(slot_count))

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    # relin_keys = keygen.relin_keys()
    galois_keys = keygen.galois_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    # ---------------------------------------------------------
    # n = 4
    # matrix = np.random.rand(n, n)
    matrix = np.arange(1, n*n+1).reshape(n, n)
    print(matrix)

    u_transposed = get_u_transpose(matrix.shape)
    u_transposed_diagonals = get_transposed_diagonals(u_transposed)
    u_transposed_diagonals += 0.00000001  # Prevent is_transparent

    # ---------------------------------------------------------
    plain_u_diag = []
    for row in u_transposed_diagonals:
        plain_u_diag.append(ckks_encoder.encode(row, scale))

    plain_matrix = ckks_encoder.encode(matrix.flatten(), scale)
    cipher_matrix = encryptor.encrypt(plain_matrix)

    # ---------------------------------------------------------
    start = time.time()
    cipher_result = linear_transform_plain(
        cipher_matrix, plain_u_diag, galois_keys, evaluator)
    end = time.time()

    p1 = decryptor.decrypt(cipher_result)
    vec = ckks_encoder.decode(p1)
    print(vec[:n**2].reshape(n, n))
    print('Time:{:.3f}s'.format(end-start))


if __name__ == "__main__":
    matrix_transpose_test(4)
