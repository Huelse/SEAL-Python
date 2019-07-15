import seal
from seal import EncryptionParameters, SEALContext, CoeffModulus, KeyGenerator


parms = EncryptionParameters(1)

poly_modulus_degree = 4096
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(256)

context = SEALContext.Create(parms)
print(type(parms))
#print(dir(parms))
print(type(context))

#print(context.key_context_data().parms())


keygen = KeyGenerator(context)
print(type(keygen))
secret_key = keygen.secret_key()
public_key = keygen.public_key()
print(context)
