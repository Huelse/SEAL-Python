#!/usr/bin/env python3

# @Author: GeorgeRaven <archer>
# @Date:   2020-05-29T12:14:30+01:00
# @Last modified by:   archer
# @Last modified time: 2020-05-29T13:59:27+01:00
# @License: please see LICENSE file in project root


import unittest
import copy


class seal_tests(unittest.TestCase):
    """Unit test class aggregating all tests for the seal class."""

    def test_deepcopy_encryptionparams_bfv(self):
        """Testing ability to serialise via copy.deepcopy on params object."""

        import seal

        # create params object
        parms = seal.EncryptionParameters(seal.scheme_type.BFV)
        poly_modulus_degree = 4096
        parms.set_poly_modulus_degree(poly_modulus_degree)
        parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(
            poly_modulus_degree))
        parms.set_plain_modulus(256)
        parms_copy = copy.deepcopy(parms)
        # check that some values are the same
        self.assertEqual(parms_copy.poly_modulus_degree(),
                         parms.poly_modulus_degree())
        self.assertEqual(parms_copy.scheme(), parms.scheme())
        # passing back copy to check they are functional
        return parms_copy

    def test_deepcopy_context_bfv(self):
        """Testing ability to serialise via copy.deepcopy on context object."""

        import seal

        # create params object
        parms = self.test_deepcopy_encryptionparams_bfv()
        # create the context from parms object
        context = seal.SEALContext.Create(parms)
        context_copy = copy.deepcopy(context)
        # passing back copy to check they are functional
        return context_copy

    def test_deepcopy_keys_bfv(self):
        """Testing ability to serialise via copy.deepcopy on key objects."""

        import seal

        context = self.test_deepcopy_context_bfv()
        keys = seal.KeyGenerator(context)
        keys_copy = copy.deepcopy(keys)
        # passing back copy to check they are functional
        return (keys_copy, context)

    def test_workers_bfv(self):
        "Testing ability to serialise via copy.deepcopy the helper objects"

        import seal

        keys, context = self.test_deepcopy_keys_bfv()
        encryptor = seal.Encryptor(context, keys.public_key())
        evaluator = seal.Evaluator(context)
        decryptor = seal.Decryptor(context, keys.secret_key())
        encryptor_copy = copy.deepcopy(encryptor)
        evaluator_copy = copy.deepcopy(evaluator)
        decryptor_copy = copy.deepcopy(decryptor)
        # passing back copy to check they are functional
        return (encryptor_copy, evaluator_copy, decryptor_copy)

    def test_deepcopy_ciphertext_bfv(self):
        "Testing ability to serialise via copy.deepcopy the ciphertext object"

        import seal

        encryptor, evaluator, decryptor = self.test_workers_bfv()
        x = 1447
        plaintext = seal.Plaintext(x)
        ciphertext = seal.Ciphertext()
        encryptor.encrypt(plaintext, ciphertext)
        ciphertext_copy = copy.deepcopy(ciphertext)
        return ciphertext_copy


if __name__ == "__main__":
    # run all the unit-tests
    unittest.main()
