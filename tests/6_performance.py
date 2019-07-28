import time
import random
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


def rand_int():
    return int(random.random()*(10**10))


def bfv_performance_test(context):
    print_parameters(context)

    parms = context.first_context_data().parms()
    plain_modulus = parms.plain_modulus()
    poly_modulus_degree = parms.poly_modulus_degree()

    print("Generating secret/public keys: ", end="")
    keygen = KeyGenerator(context)
    print("Done")

    secret_key = keygen.secret_key()
    public_key = keygen.public_key()
    relin_keys = RelinKeys()
    gal_keys = GaloisKeys()

    if context.using_keyswitching():
        # Generate relinearization keys.
        print("Generating relinearization keys: ", end="")
        time_start = time.time()
        relin_keys = keygen.relin_keys()
        time_end = time.time()
        print("Done [" + "%.0f" %
              ((time_end-time_start)*1000000) + " microseconds]")

        if not context.key_context_data().qualifiers().using_batching:
            print("Given encryption parameters do not support batching.")
            return 0

        print("Generating Galois keys: ", end="")
        time_start = time.time()
        gal_keys = keygen.galois_keys()
        time_end = time.time()
        print("Done [" + "%.0f" %
              ((time_end-time_start)*1000000) + " microseconds]")

    encryptor = Encryptor(context, public_key)
    decryptor = Decryptor(context, secret_key)
    evaluator = Evaluator(context)
    batch_encoder = BatchEncoder(context)
    encoder = IntegerEncoder(context)

    # These will hold the total times used by each operation.
    time_batch_sum = 0
    time_unbatch_sum = 0
    time_encrypt_sum = 0
    time_decrypt_sum = 0
    time_add_sum = 0
    time_multiply_sum = 0
    time_multiply_plain_sum = 0
    time_square_sum = 0
    time_relinearize_sum = 0
    time_rotate_rows_one_step_sum = 0
    time_rotate_rows_random_sum = 0
    time_rotate_columns_sum = 0

    # How many times to run the test?
    count = 10

    # Populate a vector of values to batch.
    slot_count = batch_encoder.slot_count()
    pod_vector = uIntVector()
    for i in range(slot_count):
        pod_vector.push_back(rand_int() % plain_modulus.value())
    print("Running tests ", end="")

    for i in range(count):
        '''
        [Batching]
        There is nothing unusual here. We batch our random plaintext matrix
        into the polynomial. Note how the plaintext we create is of the exactly
        right size so unnecessary reallocations are avoided.
        '''
        plain = Plaintext(parms.poly_modulus_degree(), 0)
        time_start = time.time()
        batch_encoder.encode(pod_vector, plain)
        time_end = time.time()
        time_batch_sum += (time_end-time_start)*1000000

        '''
        [Unbatching]
        We unbatch what we just batched.
        '''
        pod_vector2 = uIntVector()
        time_start = time.time()
        batch_encoder.decode(plain, pod_vector2)
        time_end = time.time()
        time_unbatch_sum += (time_end-time_start)*1000000
        for j in range(slot_count):
            if pod_vector[j] != pod_vector2[j]:
                raise Exception("Batch/unbatch failed. Something is wrong.")

        '''
        [Encryption]
        We make sure our ciphertext is already allocated and large enough
        to hold the encryption with these encryption parameters. We encrypt
        our random batched matrix here.
        '''
        encrypted = Ciphertext()
        time_start = time.time()
        encryptor.encrypt(plain, encrypted)
        time_end = time.time()
        time_encrypt_sum += (time_end-time_start)*1000000

        '''
        [Decryption]
        We decrypt what we just encrypted.
        '''
        plain2 = Plaintext(poly_modulus_degree, 0)
        time_start = time.time()
        decryptor.decrypt(encrypted, plain2)
        time_end = time.time()
        time_decrypt_sum += (time_end-time_start)*1000000
        if plain.to_string() != plain2.to_string():
            raise Exception("Encrypt/decrypt failed. Something is wrong.")

        '''
        [Add]
        We create two ciphertexts and perform a few additions with them.
        '''
        encrypted1 = Ciphertext()
        encryptor.encrypt(encoder.encode(i), encrypted1)
        encrypted2 = Ciphertext(context)
        encryptor.encrypt(encoder.encode(i + 1), encrypted2)
        time_start = time.time()
        evaluator.add_inplace(encrypted1, encrypted1)
        evaluator.add_inplace(encrypted2, encrypted2)
        evaluator.add_inplace(encrypted1, encrypted2)
        time_end = time.time()
        time_add_sum += (time_end-time_start)*1000000

        '''
        [Multiply]
        We multiply two ciphertexts. Since the size of the result will be 3,
        and will overwrite the first argument, we reserve first enough memory
        to avoid reallocating during multiplication.
        '''
        encrypted1.reserve(3)
        time_start = time.time()
        evaluator.multiply_inplace(encrypted1, encrypted2)
        time_end = time.time()
        time_multiply_sum += (time_end-time_start)*1000000

        '''
        [Multiply Plain]
        We multiply a ciphertext with a random plaintext. Recall that
        multiply_plain does not change the size of the ciphertext so we use
        encrypted2 here.
        '''
        time_start = time.time()
        evaluator.multiply_plain_inplace(encrypted2, plain)
        time_end = time.time()
        time_multiply_plain_sum += (time_end-time_start)*1000000

        '''
        [Square]
        We continue to use encrypted2. Now we square it; this should be
        faster than generic homomorphic multiplication.
        '''
        time_start = time.time()
        evaluator.square_inplace(encrypted2)
        time_end = time.time()
        time_square_sum += (time_end-time_start)*1000000

        if context.using_keyswitching():
            '''
            [Relinearize]
            Time to get back to encrypted1. We now relinearize it back
            to size 2. Since the allocation is currently big enough to
            contain a ciphertext of size 3, no costly reallocations are
            needed in the process.
            '''
            time_start = time.time()
            evaluator.relinearize_inplace(encrypted1, relin_keys)
            time_end = time.time()
            time_relinearize_sum += (time_end-time_start)*1000000

            '''
            [Rotate Rows One Step]
            We rotate matrix rows by one step left and measure the time.
            '''
            time_start = time.time()
            evaluator.rotate_rows_inplace(encrypted, 1, gal_keys)
            evaluator.rotate_rows_inplace(encrypted, -1, gal_keys)
            time_end = time.time()
            time_rotate_rows_one_step_sum += (time_end-time_start)*1000000

            '''
            [Rotate Rows Random]
            We rotate matrix rows by a random number of steps. This is much more
            expensive than rotating by just one step.
            '''
            row_size = batch_encoder.slot_count() / 2
            random_rotation = int(rand_int() % row_size)
            time_start = time.time()
            evaluator.rotate_rows_inplace(
                encrypted, random_rotation, gal_keys)
            time_end = time.time()
            time_rotate_rows_random_sum += (time_end-time_start)*1000000

            '''
            [Rotate Columns]
            Nothing surprising here.
            '''
            time_start = time.time()
            evaluator.rotate_columns_inplace(encrypted, gal_keys)
            time_end = time.time()
            time_rotate_columns_sum += (time_end-time_start)*1000000

        # Print a dot to indicate progress.
        print(".", end="")
    print(" Done")
    avg_batch = time_batch_sum / count
    avg_unbatch = time_unbatch_sum / count
    avg_encrypt = time_encrypt_sum / count
    avg_decrypt = time_decrypt_sum / count
    avg_add = time_add_sum / (3 * count)
    avg_multiply = time_multiply_sum / count
    avg_multiply_plain = time_multiply_plain_sum / count
    avg_square = time_square_sum / count
    avg_relinearize = time_relinearize_sum / count
    avg_rotate_rows_one_step = time_rotate_rows_one_step_sum / (2 * count)
    avg_rotate_rows_random = time_rotate_rows_random_sum / count
    avg_rotate_columns = time_rotate_columns_sum / count
    print("Average batch: " + "%.0f" % avg_batch + " microseconds")
    print("Average unbatch: " + "%.0f" % avg_unbatch + " microseconds")
    print("Average encrypt: " + "%.0f" % avg_encrypt + " microseconds")
    print("Average decrypt: " + "%.0f" % avg_decrypt + " microseconds")
    print("Average add: " + "%.0f" % avg_add + " microseconds")
    print("Average multiply: " + "%.0f" % avg_multiply + " microseconds")
    print("Average multiply plain: " + "%.0f" %
          avg_multiply_plain + " microseconds")
    print("Average square: " + "%.0f" % avg_square + " microseconds")
    if context.using_keyswitching():
        print("Average relinearize: " + "%.0f" %
              avg_relinearize + " microseconds")
        print("Average rotate rows one step: " + "%.0f" %
              avg_rotate_rows_one_step + " microseconds")
        print("Average rotate rows random: " + "%.0f" %
              avg_rotate_rows_random + " microseconds")
        print("Average rotate columns: " + "%.0f" %
              avg_rotate_columns + " microseconds")


def ckks_performance_test(context):
    return 0


def example_bfv_performance_default():
    print_example_banner(
        "BFV Performance Test with Degrees: 4096, 8192, and 16384")

    parms = EncryptionParameters(scheme_type.BFV)
    poly_modulus_degree = 4096
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(786433)
    bfv_performance_test(SEALContext.Create(parms))

    print()
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(786433)
    bfv_performance_test(SEALContext.Create(parms))

    print()
    poly_modulus_degree = 16384
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    parms.set_plain_modulus(786433)
    bfv_performance_test(SEALContext.Create(parms))

    # Comment out the following to run the biggest example.


def example_bfv_performance_custom():
    return 0


def example_ckks_performance_default():
    return 0


def example_ckks_performance_custom():
    return 0


if __name__ == '__main__':
    print_example_banner("Example: Performance Test")

    example_bfv_performance_default()
    # Building
