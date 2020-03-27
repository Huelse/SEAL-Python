from seal import *
from seal_helper import *


def print_parms_id(parms_id):
    for item in parms_id:
        print(str(hex(item)) + " ", end="")
    print()


def example_levels():
    print_example_banner("Example: Levels")
    parms = EncryptionParameters(scheme_type.BFV)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)

    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [50, 30, 30, 50, 50]))
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
    context = SEALContext.Create(parms)
    print_parameters(context)

    print("-" * 50)
    print("Print the modulus switching chain.")

    """
	First print the key level parameter information.
	"""
    context_data = context.key_context_data()
    print("----> Level (chain index): " +
          str(context_data.chain_index()), end="")
    print(" ...... key_context_data()")
    print("      parms_id: ", end="")
    print_parms_id(context_data.parms_id())
    print("      coeff_modulus primes: ", end="")
    for item in context_data.parms().coeff_modulus():
        print(str(hex(item.value())) + " ", end="")
    print("\n\\\n \\-->", end="")

    """
	Next iterate over the remaining (data) levels.
	"""
    context_data = context.first_context_data()
    while context_data:
        print(" Level (chain index): " + str(context_data.chain_index()), end="")
        if context_data.parms_id() == context.first_parms_id():
            print(" ...... first_context_data()")
        elif context_data.parms_id() == context.last_parms_id():
            print(" ...... last_context_data()")
        else:
            print()
        print("      parms_id: ", end="")
        print_parms_id(context_data.parms_id())
        print("      coeff_modulus primes: ", end="")
        for item in context_data.parms().coeff_modulus():
            print(str(hex(item.value())) + " ", end="")
        print("\n\\\n \\-->", end="")
        # Step forward in the chain.
        context_data = context_data.next_context_data()
    print(" End of chain reached\n")

    """
	We create some keys and check that indeed they appear at the highest level.
	"""
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    galois_keys = keygen.galois_keys()
    print("-" * 50)
    print("Print the parameter IDs of generated elements.")
    print("    + public_key:  ", end="")
    print_parms_id(public_key.parms_id())
    print("    + secret_key:  ", end="")
    print_parms_id(secret_key.parms_id())
    print("    + relin_keys:  ", end="")
    print_parms_id(relin_keys.parms_id())
    print("    + galois_keys: ", end="")
    print_parms_id(galois_keys.parms_id())

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    """
	In the BFV scheme plaintexts do not carry a parms_id, but ciphertexts do. Note
    how the freshly encrypted ciphertext is at the highest data level.
	"""
    plain = Plaintext("1x^3 + 2x^2 + 3x^1 + 4")
    encrypted = Ciphertext()
    encryptor.encrypt(plain, encrypted)
    print("    + plain:       ", end="")
    print_parms_id(plain.parms_id())
    print(" (not set in BFV)")
    print("    + encrypted:   ", end="")
    print_parms_id(encrypted.parms_id())

    print("-" * 50)
    print("Perform modulus switching on encrypted and print.")
    context_data = context.first_context_data()
    print("---->", end="")

    while context_data.next_context_data():
        print(" Level (chain index): " + str(context_data.chain_index()))
        print("      parms_id of encrypted: ", end="")
        print_parms_id(encrypted.parms_id())
        print("      Noise budget at this level: " +
              "%.0f" % decryptor.invariant_noise_budget(encrypted) + " bits")
        print("\\\n \\-->", end="")
        evaluator.mod_switch_to_next_inplace(encrypted)
        context_data = context_data.next_context_data()
    print(" Level (chain index): " + str(context_data.chain_index()))
    print("      parms_id of encrypted: ", end="")
    print_parms_id(encrypted.parms_id())
    print("      Noise budget at this level: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted) + " bits")
    print("\\\n \\--> End of chain reached\n")

    """
	At this point it is hard to see any benefit in doing this: we lost a huge
    amount of noise budget (i.e., computational power) at each switch and seemed
    to get nothing in return. Decryption still works.
	"""
    print("-" * 50)
    print("Decrypt still works after modulus switching.")
    decryptor.decrypt(encrypted, plain)
    print("    + Decryption of encrypted: " +
          plain.to_string() + " ...... Correct.\n")

    print("Computation is more efficient with modulus switching.")
    print("-" * 50)
    print("Compute the fourth power.")
    encryptor.encrypt(plain, encrypted)
    print("    + Noise budget before squaring:         " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted) + " bits")
    evaluator.square_inplace(encrypted)
    evaluator.relinearize_inplace(encrypted, relin_keys)
    print("    + Noise budget after squaring:          " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted) + " bits")

    """
    	Surprisingly, in this case modulus switching has no effect at all on the
    	noise budget.
    	"""
    evaluator.mod_switch_to_next_inplace(encrypted)
    print("    + Noise budget after modulus switching: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted) + " bits")

    evaluator.square_inplace(encrypted)
    print("    + Noise budget after squaring:          " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted) + " bits")
    evaluator.mod_switch_to_next_inplace(encrypted)
    print("    + Noise budget after modulus switching: " +
          "%.0f" % decryptor.invariant_noise_budget(encrypted) + " bits")
    decryptor.decrypt(encrypted, plain)

    print("    + Decryption of fourth power (hexadecimal) ...... Correct.")
    print("    " + plain.to_string() + "\n")

    """
    In BFV modulus switching is not necessary and in some cases the user might
    not want to create the modulus switching chain, except for the highest two
    levels. This can be done by passing a bool `false' to SEALContext::Create.
    """
    context = SEALContext.Create(parms, False)
    print("Optionally disable modulus switching chain expansion.")
    print("-" * 50)
    print("Print the modulus switching chain.\n---->", end="")
    context_data = context.key_context_data()
    while context_data:
        print(" Level (chain index): " + str(context_data.chain_index()))
        print("      parms_id: ", end="")
        print_parms_id(context_data.parms_id())
        print("      coeff_modulus primes: ", end="")
        for item in context_data.parms().coeff_modulus():
            print(str(hex(item.value())) + " ", end="")
        print("\n\\\n \\-->", end="")
        context_data = context_data.next_context_data()
    print(" End of chain reached")


if __name__ == '__main__':
    example_levels()
