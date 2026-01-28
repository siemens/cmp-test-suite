# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.hybrid_key_factory import HybridKeyFactory
from pq_logic.keys.composite_kem import (
    CompositeKEMPrivateKey,
)
from resources.keyutils import generate_key


class TestCompositeMLKEM(unittest.TestCase):

    def setUp(self):
        # RSA-based composite keys
        self.private_key_rsa_1: CompositeKEMPrivateKey = generate_key("composite-kem", pq_name="ml-kem-768", trad_name="rsa")

        # EC-based composite keys
        self.private_key_ec_1: CompositeKEMPrivateKey = generate_key("composite-kem", pq_name="ml-kem-768", curve="secp384r1")
        self.private_key_ec_2 = generate_key("ecc", curve="secp384r1")

        # X-based composite keys
        self.private_key_x_1: CompositeKEMPrivateKey = generate_key("composite-kem",pq_name="ml-kem-768", trad_name="x25519")
        self.private_key_x_2 =  generate_key("x25519")

    def test_encaps_and_decaps_rsa(self):
        """
        GIVEN an RSA-based composite key.
        WHEN encapsulating and decapsulating is performed.
        THEN should the shared secret be equal.
        """
        shared_secret, ct_vals = self.private_key_rsa_1.public_key().encaps()
        decaps_ss = self.private_key_rsa_1.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for RSA-based keys.")

    def test_encaps_and_decaps_ec(self):
        """
        GIVEN an EC-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN should the shared secret be equal.
        """
        shared_secret, ct_vals = self.private_key_ec_1.public_key().encaps(self.private_key_ec_2)
        decaps_ss = self.private_key_ec_1.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for EC-based keys.")

    def test_encaps_and_decaps_x25519(self):
        """
        GIVEN a X25519-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        shared_secret, ct_vals = self.private_key_x_1.public_key().encaps(self.private_key_x_2)
        decaps_ss = self.private_key_x_1.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for X25519-based keys.")

    def test_encaps_and_decaps_x448(self):
        """
        GIVEN a X448-based composite key, generated using the HybridKeyFactory.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        comp_key = HybridKeyFactory.generate_hybrid_key(algorithm="composite-kem",   # type: ignore
                                                        pq_name="ml-kem-1024", trad_name="x448")

        comp_key: CompositeKEMPrivateKey
        key2 = generate_key("x448")
        shared_secret, ct_vals = comp_key.public_key().encaps(key2)
        decaps_ss = comp_key.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for X448-based keys.")


if __name__ == '__main__':
    unittest.main()
