import time
import math
import random
from seal import *
from seal_helper import *


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
        pod_vector.append(rand_int() % plain_modulus.value())
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
        print(".", end="", flush=True)
    print(" Done", flush=True)

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

    print("Average batch: " + "%.0f" % avg_batch + " microseconds", flush=True)
    print("Average unbatch: " + "%.0f" %
          avg_unbatch + " microseconds", flush=True)
    print("Average encrypt: " + "%.0f" %
          avg_encrypt + " microseconds", flush=True)
    print("Average decrypt: " + "%.0f" %
          avg_decrypt + " microseconds", flush=True)
    print("Average add: " + "%.0f" % avg_add + " microseconds", flush=True)
    print("Average multiply: " + "%.0f" %
          avg_multiply + " microseconds", flush=True)
    print("Average multiply plain: " + "%.0f" %
          avg_multiply_plain + " microseconds", flush=True)
    print("Average square: " + "%.0f" %
          avg_square + " microseconds", flush=True)
    if context.using_keyswitching():
        print("Average relinearize: " + "%.0f" %
              avg_relinearize + " microseconds", flush=True)
        print("Average rotate rows one step: " + "%.0f" %
              avg_rotate_rows_one_step + " microseconds", flush=True)
        print("Average rotate rows random: " + "%.0f" %
              avg_rotate_rows_random + " microseconds", flush=True)
        print("Average rotate columns: " + "%.0f" %
              avg_rotate_columns + " microseconds", flush=True)


def ckks_performance_test(context):
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
    ckks_encoder = CKKSEncoder(context)

    time_encode_sum = 0
    time_decode_sum = 0
    time_encrypt_sum = 0
    time_decrypt_sum = 0
    time_add_sum = 0
    time_multiply_sum = 0
    time_multiply_plain_sum = 0
    time_square_sum = 0
    time_relinearize_sum = 0
    time_rescale_sum = 0
    time_rotate_one_step_sum = 0
    time_rotate_random_sum = 0
    time_conjugate_sum = 0

    # How many times to run the test?
    count = 10

    # Populate a vector of floating-point values to batch.
    pod_vector = DoubleVector()
    slot_count = ckks_encoder.slot_count()
    for i in range(slot_count):
        pod_vector.append(1.001 * float(i))

    print("Running tests ", end="")
    for i in range(count):
        '''
        [Encoding]
        For scale we use the square root of the last coeff_modulus prime
        from parms.
        '''
        plain = Plaintext(parms.poly_modulus_degree() *
                          len(parms.coeff_modulus()), 0)

        # [Encoding]
        scale = math.sqrt(parms.coeff_modulus()[-1].value())
        time_start = time.time()
        ckks_encoder.encode(pod_vector, scale, plain)
        time_end = time.time()
        time_encode_sum += (time_end-time_start)*1000000

        # [Decoding]
        pod_vector2 = DoubleVector()
        time_start = time.time()
        ckks_encoder.decode(plain, pod_vector2)
        time_end = time.time()
        time_decode_sum += (time_end-time_start)*1000000

        # [Encryption]
        encrypted = Ciphertext(context)
        time_start = time.time()
        encryptor.encrypt(plain, encrypted)
        time_end = time.time()
        time_encrypt_sum += (time_end-time_start)*1000000

        # [Decryption]
        plain2 = Plaintext(poly_modulus_degree, 0)
        time_start = time.time()
        decryptor.decrypt(encrypted, plain2)
        time_end = time.time()
        time_decrypt_sum += (time_end-time_start)*1000000

        # [Add]
        encrypted1 = Ciphertext(context)
        ckks_encoder.encode(i + 1, plain)
        encryptor.encrypt(plain, encrypted1)
        encrypted2 = Ciphertext(context)
        ckks_encoder.encode(i + 1, plain2)
        encryptor.encrypt(plain2, encrypted2)
        time_start = time.time()
        evaluator.add_inplace(encrypted1, encrypted1)
        evaluator.add_inplace(encrypted2, encrypted2)
        evaluator.add_inplace(encrypted1, encrypted2)
        time_end = time.time()
        time_add_sum += (time_end-time_start)*1000000

        # [Multiply]
        encrypted1.reserve(3)
        time_start = time.time()
        evaluator.multiply_inplace(encrypted1, encrypted2)
        time_end = time.time()
        time_multiply_sum += (time_end-time_start)*1000000

        # [Multiply Plain]
        time_start = time.time()
        evaluator.multiply_plain_inplace(encrypted2, plain)
        time_end = time.time()
        time_multiply_plain_sum += (time_end-time_start)*1000000

        # [Square]
        time_start = time.time()
        evaluator.square_inplace(encrypted2)
        time_end = time.time()
        time_square_sum += (time_end-time_start)*1000000

        if context.using_keyswitching():

            # [Relinearize]
            time_start = time.time()
            evaluator.relinearize_inplace(encrypted1, relin_keys)
            time_end = time.time()
            time_relinearize_sum += (time_end-time_start)*1000000

            # [Rescale]
            time_start = time.time()
            evaluator.rescale_to_next_inplace(encrypted1)
            time_end = time.time()
            time_rescale_sum += (time_end-time_start)*1000000

            # [Rotate Vector]
            time_start = time.time()
            evaluator.rotate_vector_inplace(encrypted, 1, gal_keys)
            evaluator.rotate_vector_inplace(encrypted, -1, gal_keys)
            time_end = time.time()
            time_rotate_one_step_sum += (time_end-time_start)*1000000

            # [Rotate Vector Random]
            random_rotation = int(rand_int() % ckks_encoder.slot_count())
            time_start = time.time()
            evaluator.rotate_vector_inplace(
                encrypted, random_rotation, gal_keys)
            time_end = time.time()
            time_rotate_random_sum += (time_end-time_start)*1000000

            # [Complex Conjugate]
            time_start = time.time()
            evaluator.complex_conjugate_inplace(encrypted, gal_keys)
            time_end = time.time()
            time_conjugate_sum += (time_end-time_start)*1000000
        print(".", end="", flush=True)

    print(" Done\n", flush=True)

    avg_encode = time_encode_sum / count
    avg_decode = time_decode_sum / count
    avg_encrypt = time_encrypt_sum / count
    avg_decrypt = time_decrypt_sum / count
    avg_add = time_add_sum / (3 * count)
    avg_multiply = time_multiply_sum / count
    avg_multiply_plain = time_multiply_plain_sum / count
    avg_square = time_square_sum / count
    avg_relinearize = time_relinearize_sum / count
    avg_rescale = time_rescale_sum / count
    avg_rotate_one_step = time_rotate_one_step_sum / (2 * count)
    avg_rotate_random = time_rotate_random_sum / count
    avg_conjugate = time_conjugate_sum / count

    print("Average encode: " + "%.0f" %
          avg_encode + " microseconds", flush=True)
    print("Average decode: " + "%.0f" %
          avg_decode + " microseconds", flush=True)
    print("Average encrypt: " + "%.0f" %
          avg_encrypt + " microseconds", flush=True)
    print("Average decrypt: " + "%.0f" %
          avg_decrypt + " microseconds", flush=True)
    print("Average add: " + "%.0f" % avg_add + " microseconds", flush=True)
    print("Average multiply: " + "%.0f" %
          avg_multiply + " microseconds", flush=True)
    print("Average multiply plain: " + "%.0f" %
          avg_multiply_plain + " microseconds", flush=True)
    print("Average square: " + "%.0f" %
          avg_square + " microseconds", flush=True)
    if context.using_keyswitching():
        print("Average relinearize: " + "%.0f" %
              avg_relinearize + " microseconds", flush=True)
        print("Average rescale: " + "%.0f" %
              avg_rescale + " microseconds", flush=True)
        print("Average rotate vector one step: " + "%.0f" %
              avg_rotate_one_step + " microseconds", flush=True)
        print("Average rotate vector random: " + "%.0f" %
              avg_rotate_random + " microseconds", flush=True)
        print("Average complex conjugate: " + "%.0f" %
              avg_conjugate + " microseconds", flush=True)


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
    # poly_modulus_degree = 32768


def example_bfv_performance_custom():
    print("\nSet poly_modulus_degree (1024, 2048, 4096, 8192, 16384, or 32768): ")
    poly_modulus_degree = input("Input the poly_modulus_degree: ").strip()

    if len(poly_modulus_degree) < 4 or not poly_modulus_degree.isdigit():
        print("Invalid option.")
        return 0

    poly_modulus_degree = int(poly_modulus_degree)

    if poly_modulus_degree < 1024 or poly_modulus_degree > 32768 or (poly_modulus_degree & (poly_modulus_degree - 1) != 0):
        print("Invalid option.")
        return 0

    print("BFV Performance Test with Degree: " + str(poly_modulus_degree))

    parms = EncryptionParameters(scheme_type.BFV)
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    if poly_modulus_degree == 1024:
        parms.set_plain_modulus(12289)
    else:
        parms.set_plain_modulus(786433)
    bfv_performance_test(SEALContext.Create(parms))


def example_ckks_performance_default():
    print_example_banner(
        "CKKS Performance Test with Degrees: 4096, 8192, and 16384")

    parms = EncryptionParameters(scheme_type.CKKS)
    poly_modulus_degree = 4096
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    ckks_performance_test(SEALContext.Create(parms))

    print()
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    ckks_performance_test(SEALContext.Create(parms))

    poly_modulus_degree = 16384
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    ckks_performance_test(SEALContext.Create(parms))

    # Comment out the following to run the biggest example.
    # poly_modulus_degree = 32768


def example_ckks_performance_custom():
    print("\nSet poly_modulus_degree (1024, 2048, 4096, 8192, 16384, or 32768): ")
    poly_modulus_degree = input("Input the poly_modulus_degree: ").strip()

    if len(poly_modulus_degree) < 4 or not poly_modulus_degree.isdigit():
        print("Invalid option.")
        return 0

    poly_modulus_degree = int(poly_modulus_degree)

    if poly_modulus_degree < 1024 or poly_modulus_degree > 32768 or (poly_modulus_degree & (poly_modulus_degree - 1) != 0):
        print("Invalid option.")
        return 0

    print("CKKS Performance Test with Degree: " + str(poly_modulus_degree))

    parms = EncryptionParameters(scheme_type.CKKS)
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    ckks_performance_test(SEALContext.Create(parms))


if __name__ == '__main__':
    print_example_banner("Example: Performance Test")

    example_bfv_performance_default()
    example_bfv_performance_custom()
    example_ckks_performance_default()
    example_ckks_performance_custom()
