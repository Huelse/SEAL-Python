from seal import *
import pickle
import time


def get_seal():
    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))
    scale = 2.0 ** 40

    context = SEALContext(parms)
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()

    keygen = KeyGenerator(context)
    public_key = keygen.create_public_key()
    secret_key = keygen.secret_key()

    encryptor = Encryptor(context, public_key)
    # evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    data = [3.1415926] * slot_count
    plain = ckks_encoder.encode(data, scale)
    cipher = encryptor.encrypt(plain)

    return cipher, context, ckks_encoder, decryptor


def serialization_example():
    print('serialization example')
    print('-' * 70)
    cipher2, context2, ckks_encoder2, decryptor2 = get_seal()
    cipher2.save('cipher2.bin')
    print('save cipher2 data success')

    time.sleep(.5)

    cipher3 = Ciphertext()
    cipher3.load(context2, 'cipher2.bin')
    print('load cipher2 data success')
    plain3 = decryptor2.decrypt(cipher3)
    data3 = ckks_encoder2.decode(plain3)
    print(data3)
    print('-' * 70)


def pickle_example():
    print('pickle example')
    print('-' * 70)
    cipher1, context1, ckks_encoder1, decryptor1 = get_seal()
    with open('cipher1.bin', 'wb') as f:
        pickle.dump(cipher1.to_string(), f)
        print('write cipher1 data success')

    time.sleep(.5)

    with open('cipher1.bin', 'rb') as f:
        temp = pickle.load(f)
        cipher2 = context1.from_cipher_str(temp)
        plain2 = decryptor1.decrypt(cipher2)
        data = ckks_encoder1.decode(plain2)
        print('read cipher1 data success')
        print(data)

    print('-' * 70)


if __name__ == "__main__":
    serialization_example()
    pickle_example()
