import seal
from seal import EncryptionParameters, SEALContext, CoeffModulus, KeyGenerator, scheme_type, Encryptor, Evaluator, Decryptor, Plaintext, Ciphertext


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

print(context_data.parms())
print(context_data.parms().scheme()==scheme_type.BFV)


keygen = KeyGenerator(context)
print(type(keygen))
secret_key = keygen.secret_key()
public_key = keygen.public_key()
relin_keys = keygen.relin_keys()
print(type(secret_key))
print(type(public_key))
print(type(relin_keys))
encryptor = Encryptor(context, public_key)
print(encryptor)
evaluator = Evaluator(context)
print(evaluator)
decryptor = Decryptor(context, secret_key)
print(decryptor)
x_plain = Plaintext("6")
#print(x_plain.to_string())
x_encrypted = Ciphertext()
print(type(x_plain))
print(type(x_encrypted))
encryptor.encrypt(x_plain, x_encrypted)
print(x_encrypted.size())
