from seal import *
import numpy as np

def print_vector(vector):
    print('[ ', end='')
    for i in range(0, 8):
        print(vector[i], end=', ')
    print('... ]')


def example_bgv_basics():
    parms = EncryptionParameters (scheme_type.bgv)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
    context = SEALContext(parms)

    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.create_public_key()
    relin_keys = keygen.create_relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    batch_encoder = BatchEncoder(context)
    slot_count = batch_encoder.slot_count()
    row_size = slot_count / 2
    print(f'Plaintext matrix row size: {row_size}')

    pod_matrix = [0] * slot_count
    pod_matrix[0] = 1
    pod_matrix[1] = 2
    pod_matrix[2] = 3
    pod_matrix[3] = 4

    x_plain = batch_encoder.encode(pod_matrix)

    x_encrypted = encryptor.encrypt(x_plain)
    print(f'noise budget in freshly encrypted x: {decryptor.invariant_noise_budget(x_encrypted)}')
    print('-'*50)

    x_squared = evaluator.square(x_encrypted)
    print(f'size of x_squared: {x_squared.size()}')
    evaluator.relinearize_inplace(x_squared, relin_keys)
    print(f'size of x_squared (after relinearization): {x_squared.size()}')
    print(f'noise budget in x_squared: {decryptor.invariant_noise_budget(x_squared)} bits')
    decrypted_result = decryptor.decrypt(x_squared)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-'*50)

    x_4th = evaluator.square(x_squared)
    print(f'size of x_4th: {x_4th.size()}')
    evaluator.relinearize_inplace(x_4th, relin_keys)
    print(f'size of x_4th (after relinearization): { x_4th.size()}')
    print(f'noise budget in x_4th: {decryptor.invariant_noise_budget(x_4th)} bits')
    decrypted_result = decryptor.decrypt(x_4th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-'*50)

    x_8th = evaluator.square(x_4th)
    print(f'size of x_8th: {x_8th.size()}')
    evaluator.relinearize_inplace(x_8th, relin_keys)
    print(f'size of x_8th (after relinearization): { x_8th.size()}')
    print(f'noise budget in x_8th: {decryptor.invariant_noise_budget(x_8th)} bits')
    decrypted_result = decryptor.decrypt(x_8th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('run out of noise budget')
    print('-'*100)

    x_encrypted = encryptor.encrypt(x_plain)
    print(f'noise budget in freshly encrypted x: {decryptor.invariant_noise_budget(x_encrypted)}')
    print('-'*50)

    x_squared = evaluator.square(x_encrypted)
    print(f'size of x_squared: {x_squared.size()}')
    evaluator.relinearize_inplace(x_squared, relin_keys)
    evaluator.mod_switch_to_next_inplace(x_squared)
    print(f'noise budget in x_squared (with modulus switching): {decryptor.invariant_noise_budget(x_squared)} bits')
    decrypted_result = decryptor.decrypt(x_squared)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-'*50)

    x_4th = evaluator.square(x_squared)
    print(f'size of x_4th: {x_4th.size()}')
    evaluator.relinearize_inplace(x_4th, relin_keys)
    evaluator.mod_switch_to_next_inplace(x_4th)
    print(f'size of x_4th (after relinearization): { x_4th.size()}')
    print(f'noise budget in x_4th (with modulus switching): {decryptor.invariant_noise_budget(x_4th)} bits')
    decrypted_result = decryptor.decrypt(x_4th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)
    print('-'*50)

    x_8th = evaluator.square(x_4th)
    print(f'size of x_8th: {x_8th.size()}')
    evaluator.relinearize_inplace(x_8th, relin_keys)
    evaluator.mod_switch_to_next_inplace(x_8th)
    print(f'size of x_8th (after relinearization): { x_8th.size()}')
    print(f'noise budget in x_8th (with modulus switching): {decryptor.invariant_noise_budget(x_8th)} bits')
    decrypted_result = decryptor.decrypt(x_8th)
    pod_result = batch_encoder.decode(decrypted_result)
    print_vector(pod_result)


if __name__ == "__main__":
    example_bgv_basics()
