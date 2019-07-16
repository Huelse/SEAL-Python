import seal
from seal import EncryptionParameters, SEALContext, CoeffModulus, KeyGenerator, scheme_type


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

#context_data = context.key_context_data()

#print(type(context_data))
#print(context_data.parms().scheme())


keygen = KeyGenerator(context)
print(type(keygen))
secret_key = keygen.secret_key()
public_key = keygen.public_key()
print(type(secret_key))
print(type(public_key))

