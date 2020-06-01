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

    def get_encryption_params_bfv(self):
        """Create parameter object."""
        import seal

        parms = seal.EncryptionParameters(seal.scheme_type.BFV)
        poly_modulus_degree = 4096
        parms.set_poly_modulus_degree(poly_modulus_degree)
        parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(
            poly_modulus_degree))
        parms.set_plain_modulus(256)

        return parms

    def test_encryption_params_bfv(self):
        import seal
        parms = self.get_encryption_params_bfv()
        self.assertIsInstance(parms, seal.EncryptionParameters)

    def test_deepcopy_encryptionparams_bfv(self):
        """Testing ability to serialise via copy.deepcopy on params object."""

        # create params object
        parms = self.get_encryption_params_bfv()
        parms_copy = copy.deepcopy(parms)
        # check that some values are the same
        self.assertEqual(parms_copy.poly_modulus_degree(),
                         parms.poly_modulus_degree())
        self.assertEqual(parms_copy.scheme(), parms.scheme())
        # passing back copy to check they are functional
        return parms_copy

    def get_context(self, parms):
        """Get context object given parameters."""
        import seal
        context = seal.SEALContext.Create(parms)
        return context

    def test_context_bfv(self):
        """Test ability to create context object."""
        import seal
        parms = self.get_encryption_params_bfv()
        context = self.get_context(parms)
        self.assertIsInstance(context, seal.SEALContext)

    def test_deepcopy_context_bfv(self):
        """Testing ability to serialise via copy.deepcopy on context object."""

        # create params object
        parms = self.get_encryption_params_bfv()
        context = self.get_context(parms)
        context_copy = copy.deepcopy(context)
        # passing back copy to check they are functional
        return context_copy

    def get_keys_bfv(self):
        import seal
        parms = self.get_encryption_params_bfv()
        context = self.get_context(parms)
        keys = seal.KeyGenerator(context)
        return (keys, context)

    def test_keys_bfv(self):
        """Test ability to create bfv related key objects."""
        import seal
        keys, _ = self.get_keys_bfv()
        key_dict = {
            "public": keys.public_key(),
            "secret": keys.secret_key(),
        }
        self.assertIsInstance(key_dict["public"], seal.PublicKey)
        self.assertIsInstance(key_dict["secret"], seal.SecretKey)

    def test_deepcopy_keys_bfv(self):
        """Testing ability to serialise via copy.deepcopy on key objects."""

        keys, context = self.get_keys_bfv()
        keys_copy = copy.deepcopy(keys)
        # passing back copy to check they are functional
        return (keys_copy, context)

    def get_workers_bfv(self):
        import seal

        keys, context = self.get_keys_bfv()
        encryptor = seal.Encryptor(context, keys.public_key())
        evaluator = seal.Evaluator(context)
        decryptor = seal.Decryptor(context, keys.secret_key())
        return (encryptor, evaluator, decryptor)

    def test_workers_bfv(self):
        """Test ability to create worker objects"""
        import seal
        encryptor, evaluator, decryptor = self.get_workers_bfv()
        self.assertIsInstance(encryptor, seal.Encryptor)
        self.assertIsInstance(evaluator, seal.Evaluator)
        self.assertIsInstance(decryptor, seal.Decryptor)

    def test_deepcopy_workers_bfv(self):
        "Testing ability to serialise via copy.deepcopy the helper objects"

        encryptor, evaluator, decryptor = self.get_workers_bfv()
        encryptor_copy = copy.deepcopy(encryptor)
        evaluator_copy = copy.deepcopy(evaluator)
        decryptor_copy = copy.deepcopy(decryptor)
        # passing back copy to check they are functional
        return (encryptor_copy, evaluator_copy, decryptor_copy)

    def get_ciphertext_bfv(self):
        import seal

        encryptor, evaluator, decryptor = self.get_workers_bfv()
        x = 1447
        plaintext = seal.Plaintext(x)
        ciphertext = seal.Ciphertext()
        encryptor.encrypt(plaintext, ciphertext)
        return ciphertext

    def test_ciphertext_bfv(self):
        """Test ability to create ciphertext object."""
        import seal
        ciphertext = self.get_ciphertext_bfv()
        self.assertIsInstance(ciphertext, seal.Ciphertext)

    def test_deepcopy_ciphertext_bfv(self):
        "Testing ability to serialise via copy.deepcopy the ciphertext object"

        ciphertext = self.get_ciphertext_bfv()
        ciphertext_copy = copy.deepcopy(ciphertext)
        return ciphertext_copy


if __name__ == "__main__":
    # run all the unit-tests
    unittest.main()
