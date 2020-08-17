import sys
import time
import math
import numpy as np
from seal import *
from seal_helper import *


def get_diagonal(position, matrix):
    n = matrix.shape[0]
    diagonal = np.zeros(n)

    k = 0
    i = 0
    j = position
    while i < n-position and j < n:
        diagonal[k] = matrix[i][j]
        i += 1
        j += 1
        k += 1

    i = n - position
    j = 0
    while i < n and j < position:
        diagonal[k] = matrix[i][j]
        i += 1
        j += 1
        k += 1

    return diagonal


def get_all_diagonals(matrix):
    matrix_diagonals = []
    for i in range(matrix.shape[0]):
        matrix_diagonals.append(get_diagonal(i, matrix))
    return np.array(matrix_diagonals)


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


def linear_transform_plain(cipher_matrix, plain_diags, galois_keys, evaluator):
    ct_rot = Ciphertext()
    evaluator.rotate_vector(
        cipher_matrix, -len(plain_diags), galois_keys, ct_rot)
    ct_new = Ciphertext()
    evaluator.add(cipher_matrix, ct_rot, ct_new)
    temp = Ciphertext()
    ct_result = []
    evaluator.multiply_plain(ct_new, plain_diags[0], temp)
    ct_result.append(temp)

    i = 1
    while i < len(plain_diags):
        temp_rot = Ciphertext()
        evaluator.rotate_vector(ct_new, i, galois_keys, temp_rot)
        temp = Ciphertext()
        evaluator.multiply_plain(temp_rot, plain_diags[i], temp)
        ct_result.append(temp)
        i += 1

    ct_prime = Ciphertext()
    evaluator.add_many(ct_result, ct_prime)

    return ct_prime


def get_u_sigma(shape):
    u_sigma_ = np.zeros(shape)
    indices_diagonal = np.diag_indices(shape[0])
    u_sigma_[indices_diagonal] = 1.

    for i in range(shape[0]-1):
        u_sigma_ = np.pad(u_sigma_, (0, shape[0]), 'constant')
        temp = np.zeros(shape)
        j = np.arange(0, shape[0])
        temp[j, j-(shape[0]-1-i)] = 1.
        temp = np.pad(temp, ((i+1)*shape[0], 0), 'constant')
        u_sigma_ += temp

    return u_sigma_

def get_u_tau(shape):
    u_tau_ = np.zeros((shape[0], shape[0]**2))
    index = np.arange(shape[0])
    for i in range(shape[0], 0, -1):
        idx = np.concatenate([index[i:], index[:i]], axis=0)
        row = np.zeros(shape)
        for j in range(shape[0]):
            temp = np.zeros(shape)
            temp[idx[j], idx[j]] = 1.
            if j == 0:
                row += temp
            else:
                row = np.concatenate([row, temp], axis=1)

        if i == shape[0]:
            u_tau_ += row
        else:
            u_tau_ = np.concatenate([u_tau_, row], axis=0)

    return u_tau_


def get_v_k(shape):
    v_k_ = []
    index = np.arange(0, shape[0])
    for j in range(1, shape[0]):
        temp = np.zeros(shape)
        temp[index, index-(shape[0]-j)] = 1.
        mat = temp
        for i in range(shape[0]-1):
            mat = np.pad(mat, (0, shape[0]), 'constant')
            temp2 = np.pad(temp, ((i+1)*shape[0], 0), 'constant')
            mat += temp2

        v_k_.append(mat)

    return v_k_


def get_w_k(shape):
    w_k_ = []
    index = np.arange(shape[0]**2)
    for i in range(shape[0]-1):
        temp = np.zeros((shape[0]**2, shape[1]**2))
        temp[index-(i+1)*shape[0], index] = 1.
        w_k_.append(temp)

    return w_k_


def matrix_multiplication(n, cm1, cm2, sigma, tau, v, w, galois_keys, evaluator):
    cipher_result1 = []
    cipher_result2 = []

    cipher_result1.append(linear_transform_plain(cm1, sigma, galois_keys, evaluator))
    cipher_result2.append(linear_transform_plain(cm2, tau, galois_keys, evaluator))
    

    for i in range(1, n):
        cipher_result1.append(linear_transform_plain(cipher_result1[0], v[i-1], galois_keys, evaluator))
        cipher_result2.append(linear_transform_plain(cipher_result2[0], w[i-1], galois_keys, evaluator))
    
    for i in range(1, n):
        evaluator.rescale_to_next_inplace(cipher_result1[i])
        evaluator.rescale_to_next_inplace(cipher_result2[i])
    
    cipher_mult = Ciphertext()
    evaluator.multiply(cipher_result1[0], cipher_result2[0], cipher_mult)
    evaluator.mod_switch_to_next_inplace(cipher_mult)

    for i in range(1, n):
        cipher_result1[i].scale(pow(2, int(math.log2(cipher_result1[i].scale()))))
        cipher_result2[i].scale(pow(2, int(math.log2(cipher_result2[i].scale()))))

    for i in range(1, n):
        temp = Ciphertext()
        evaluator.multiply(cipher_result1[i], cipher_result2[i], temp)
        evaluator.add_inplace(cipher_mult, temp)

    return cipher_mult


def matrix_mult_test(n=4):
    parms = EncryptionParameters(scheme_type.CKKS)
    poly_modulus_degree = 16384
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [60, 40, 40, 40, 40, 60]))
    scale = 2.0**40
    context = SEALContext.Create(parms)
    print_parameters(context)

    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    print(f'Number of slots: {slot_count}')

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    # relin_keys = keygen.relin_keys()
    galois_keys = keygen.galois_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    # ---------------------------------------------------------
    u_sigma = get_u_sigma((n,n))
    u_tau = get_u_tau((n,n))
    v_k = get_v_k((n, n))
    w_k = get_w_k((n, n))

    u_sigma_diagonals = get_all_diagonals(u_sigma)
    u_sigma_diagonals += 0.00000001  # Prevent is_transparent
    
    u_tau_diagonals = get_all_diagonals(u_tau)
    u_tau_diagonals += 0.00000001
    
    v_k_diagonals = []
    for v in v_k:
        diags = get_all_diagonals(v)
        diags += 0.00000001
        v_k_diagonals.append(diags)

    w_k_diagonals = []
    for w in w_k:
        diags = get_all_diagonals(w)
        diags += 0.00000001
        w_k_diagonals.append(diags)

    plain_u_sigma_diagonals = []
    plain_u_tau_diagonals = []
    plain_v_k_diagonals = []
    plain_w_k_diagonals = []

    # ---------------------------------------------------------
    for i in range(n**2):
        plain_u_sigma_diagonals.append(ckks_encoder.encode(u_sigma_diagonals[i], scale))
        plain_u_tau_diagonals.append(ckks_encoder.encode(u_tau_diagonals[i], scale))
    
    for i in range(n-1):
        temp1 = []
        temp2 = []
        for j in range(n**2):
            temp1.append(ckks_encoder.encode(v_k_diagonals[i][j], scale))
            temp2.append(ckks_encoder.encode(w_k_diagonals[i][j], scale))
        
        plain_v_k_diagonals.append(temp1)
        plain_w_k_diagonals.append(temp2)
    
    # matrix1 = np.random.rand(n, n)
    matrix1 = np.arange(1, n*n+1).reshape(n, n)
    matrix2 = matrix1
    print(np.dot(matrix1, matrix2))
    
    plain_matrix1 = ckks_encoder.encode(matrix1.flatten(), scale)
    plain_matrix2 = ckks_encoder.encode(matrix2.flatten(), scale)
    cipher_matrix1 = encryptor.encrypt(plain_matrix1)
    cipher_matrix2 = encryptor.encrypt(plain_matrix2)

    # ---------------------------------------------------------
    start = time.time()
    cipher_result = matrix_multiplication(n, cipher_matrix1, cipher_matrix2, plain_u_sigma_diagonals, plain_u_tau_diagonals, plain_v_k_diagonals, plain_w_k_diagonals, galois_keys, evaluator)
    end = time.time()

    # ---------------------------------------------------------
    plain = decryptor.decrypt(cipher_result)
    vec = ckks_encoder.decode(plain)
    print(vec[:n**2].reshape(n, n))
    print('Mult Time: {:.3f}s'.format(end-start))


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

    # ---------------------------------------------------------
    p1 = decryptor.decrypt(cipher_result)
    vec = ckks_encoder.decode(p1)
    print(vec[:n**2].reshape(n, n))
    print('Trans Time: {:.3f}s'.format(end-start))


if __name__ == "__main__":
    args = sys.argv[1:]
    n = int(args[0]) if args else 4
    print(f'n: {n}')
    print("Matrix Transpose:")
    matrix_transpose_test(n)

    print("Matrix Multiplication:")
    matrix_mult_test(n)
