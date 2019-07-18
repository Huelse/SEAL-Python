import seal
from seal import EncryptionParameters, SEALContext, CoeffModulus, KeyGenerator, scheme_type, Encryptor, Evaluator, Decryptor, Plaintext, Ciphertext, MemoryPoolHandle


parms = EncryptionParameters(scheme_type.BFV)

poly_modulus_degree = 4096
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(256)
print(type(parms))
#print(dir(parms))
#print(parms.coeff_modulus())
#print(parms.plain_modulus())
context = SEALContext.Create(parms)
print(type(context))

context_data = context.key_context_data()

print(context_data.parms().scheme())

keygen = KeyGenerator(context)

secret_key = keygen.secret_key()
public_key = keygen.public_key()
relin_keys = keygen.relin_keys()

encryptor = Encryptor(context, public_key)

evaluator = Evaluator(context)

decryptor = Decryptor(context, secret_key)

x_plain = Plaintext("6")
#print(x_plain.to_string())
x_encrypted = Ciphertext()

encryptor.encrypt(x_plain, x_encrypted)
print(x_encrypted.size())
print(decryptor.invariant_noise_budget(x_encrypted))
x_decrypted = Plaintext()
decryptor.decrypt(x_encrypted, x_decrypted)
print(x_decrypted.to_string())
print('-'*50)
pool = MemoryPoolHandle().New(False)
x_sq_plus_one = Ciphertext()
evaluator.square(x_encrypted, x_sq_plus_one, pool)
plain_one = Plaintext("1")
evaluator.add_plain_inplace(x_sq_plus_one, plain_one)
print(x_sq_plus_one.size())
print(decryptor.invariant_noise_budget(x_sq_plus_one))
print('-'*50)
x_decrypted = Plaintext()
decryptor.decrypt(x_encrypted, x_decrypted)
print(x_decrypted.to_string())
print('-'*50)
x_sq_plus_one = Ciphertext()
evaluator.square(x_encrypted, x_sq_plus_one, pool)
plain_one = Plaintext("1")
evaluator.add_plain_inplace(x_sq_plus_one, plain_one)
print(x_sq_plus_one.size())
print(decryptor.invariant_noise_budget(x_sq_plus_one))
print('-'*50)
decrypted_result = Plaintext()
decryptor.decrypt(x_sq_plus_one, decrypted_result)
print(decrypted_result.to_string())
print('-'*50)
x_plus_one_sq = Ciphertext()
evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq)
evaluator.square_inplace(x_plus_one_sq, pool)
print(x_plus_one_sq.size())
print(decryptor.invariant_noise_budget(x_plus_one_sq))
decryptor.decrypt(x_plus_one_sq, decrypted_result)
print(decrypted_result.to_string())
print('-'*50)
encrypted_result = Ciphertext()
plain_two = Plaintext("2")
evaluator.multiply_plain_inplace(x_sq_plus_one, plain_two, pool)
evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result, pool)
print(encrypted_result.size())
print(decryptor.invariant_noise_budget(encrypted_result))
print('-'*50)
relin_keys = keygen.relin_keys();
x_squared = Ciphertext()
evaluator.square(x_encrypted, x_squared, pool)
print(x_squared.size())
evaluator.relinearize_inplace(x_squared, relin_keys, pool)
print(x_squared.size())
evaluator.add_plain(x_squared, plain_one, x_sq_plus_one)
print(decryptor.invariant_noise_budget(x_sq_plus_one))
decryptor.decrypt(x_sq_plus_one, decrypted_result)
print(decrypted_result.to_string())
print('-'*50)
x_plus_one = Ciphertext()
evaluator.add_plain(x_encrypted, plain_one, x_plus_one)
evaluator.square(x_plus_one, x_plus_one_sq, pool)
print(x_plus_one_sq.size())
evaluator.relinearize_inplace(x_plus_one_sq, relin_keys, pool)
print(decryptor.invariant_noise_budget(x_plus_one_sq))
decryptor.decrypt(x_plus_one_sq, decrypted_result)
print(decrypted_result.to_string())
print('-'*50)
evaluator.multiply_plain_inplace(x_sq_plus_one, plain_two, pool)
evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result, pool)
print(encrypted_result.size())
evaluator.relinearize_inplace(encrypted_result, relin_keys, pool)
print(encrypted_result.size())
print(decryptor.invariant_noise_budget(encrypted_result))
print('-'*50)
decryptor.decrypt(encrypted_result, decrypted_result)
print(decrypted_result.to_string())








