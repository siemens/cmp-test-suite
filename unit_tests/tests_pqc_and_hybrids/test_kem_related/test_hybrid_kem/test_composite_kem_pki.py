# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_kem_pki import (
    CompositeMLKEMECPrivateKey,
    CompositeMLKEMRSAPrivateKey,
    CompositeMLKEMXPrivateKey,
    get_oid_composite,
    id_MLKEM768_RSA2048,
)


class TestCompositeMLKEM(unittest.TestCase):

    def setUp(self):
        # RSA-based composite keys
        self.private_key_rsa_1 = CompositeMLKEMRSAPrivateKey.generate(pq_name="ml-kem-768", trad_param=2048)
        self.private_key_rsa_2 = CompositeMLKEMRSAPrivateKey.generate(pq_name="ml-kem-768", trad_param=2048)

        # EC-based composite keys
        self.private_key_ec_1 = CompositeMLKEMECPrivateKey.generate(pq_name="ml-kem-768", trad_param="secp384r1")
        self.private_key_ec_2 = CompositeMLKEMECPrivateKey.generate(pq_name="ml-kem-768", trad_param="secp384r1")

        # X-based composite keys
        self.private_key_x_1 = CompositeMLKEMXPrivateKey.generate(pq_name="ml-kem-768",
                                                                  trad_param="x25519")
        self.private_key_x_2 = CompositeMLKEMXPrivateKey.generate(pq_name="ml-kem-768",
                                                                  trad_param="x25519")

    def test_get_oid_composite_valid(self):
        """
        GIVEN a valid composite key.
        WHEN the OID is requested.
        THEN the OID should not be None.
        """
        oid = get_oid_composite("ml-kem-768", self.private_key_rsa_1.trad_key)
        self.assertEqual(oid, id_MLKEM768_RSA2048,"OID should not be None for valid inputs.")



    def test_encaps_and_decaps_rsa(self):
        """
        GIVEN two RSA-based composite keys.
        WHEN encapsulating and decapsulating the keys.
        THEN the shared secret should be equal to the expected shared secret.
        """
        shared_secret, ct_vals = self.private_key_rsa_1.encaps(self.private_key_rsa_2.public_key())
        decaps_ss = self.private_key_rsa_2.decaps(ct_vals=ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for RSA-based keys.")

    def test_encaps_and_decaps_ec(self):
        """
        GIVEN two EC-based composite keys.
        WHEN encapsulating and decapsulating the keys.
        THEN the shared secret should be equal to the expected shared secret.
        """
        shared_secret, ct_vals = self.private_key_ec_1.encaps(self.private_key_ec_2.public_key())
        decaps_ss = self.private_key_ec_2.decaps(ct_vals=ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for EC-based keys.")

    def test_encaps_and_decaps_x25519(self):
        """
        GIVEN two X25519-based composite keys.
        WHEN encapsulating and decapsulating the keys.
        THEN the shared secret should be equal to the expected shared secret.
        """
        shared_secret, ct_vals = self.private_key_x_1.encaps(self.private_key_x_2.public_key())
        decaps_ss = self.private_key_x_2.decaps(ct_vals=ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for X25519-based keys.")

    def test_encaps_and_decaps_x448(self):
        """
        GIVEN two X448-based composite keys.
        WHEN encapsulating and decapsulating the keys.
        THEN the shared secret should be equal to the expected shared secret.
        """
        key1 = CompositeMLKEMXPrivateKey.generate(pq_name="ml-kem-1024", trad_param="x448")
        key2 = CompositeMLKEMXPrivateKey.generate(pq_name="ml-kem-1024", trad_param="x448")
        shared_secret, ct_vals = key1.encaps(key2.public_key())
        decaps_ss = key2.decaps(ct_vals=ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for X448-based keys.")
