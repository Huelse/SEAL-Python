#!/usr/bin/env python3

# @Author: GeorgeRaven <archer>
# @Date:   2020-05-29T12:14:30+01:00
# @Last modified by:   archer
# @Last modified time: 2020-05-29T12:24:26+01:00
# @License: please see LICENSE file in project root


import unittest
import copy


class seal_tests(unittest.TestCase):
    """Unit test class aggregating all tests for the seal class."""

    def test_deepcopy_encryptionparams(self):
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


if __name__ == "__main__":
    # run all the unit-tests
    unittest.main()
