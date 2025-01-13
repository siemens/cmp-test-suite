# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_key_factory import HybridKeyFactory
from pq_logic.keys.composite_kem_pki import (
    CompositeMLKEMECPrivateKey,
    CompositeMLKEMRSAPrivateKey,
    CompositeMLKEMXPrivateKey,
    CompositeDHKEMRFC9180PrivateKey,
)
from pq_logic.tmp_mapping import get_oid_composite
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.tmp_oids import id_MLKEM768_RSA2048
from resources.keyutils import generate_key


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


    def test_encaps_and_decaps_frodokem_x25519(self):
        """
        GIVEN two FrodoKEM X25519-based composite keys.
        WHEN encapsulating and decapsulating the keys.
        THEN the shared secret should be equal to the expected shared secret.
        """
        key1 = HybridKeyFactory.generate_comp_kem_key(
            pq_name="frodokem-976-aes", trad_name="x25519")

        key2 = HybridKeyFactory.generate_comp_kem_key(
            pq_name="frodokem-976-aes", trad_name="x25519")

        shared_secret, ct_vals = key1.encaps(key2.public_key())
        decaps_ss = key2.decaps(ct_vals=ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for FrodoKEM X25519-based keys.")


    def test_encaps_and_decaps_mlkem768_dhkemrfc9180_x25519(self):
        trad_key1 = generate_key("x25519")
        trad_key2 = generate_key("x25519")

        pq_key1 = PQKeyFactory.generate_pq_key("ml-kem-768")
        pq_key2 = PQKeyFactory.generate_pq_key("ml-kem-768")

        key1 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key1, trad_key=trad_key1)
        key2 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key2, trad_key=trad_key2)

        ss, ct = key1.encaps(key2.public_key())

        ss2 = key2.decaps(ct)
        self.assertEqual(ss, ss2)

    def test_encaps_and_decaps_frodokem_976_aes_dhkemrfc9180_x25519(self):
        trad_key1 = generate_key("x25519")
        trad_key2 = generate_key("x25519")

        pq_key1 = PQKeyFactory.generate_pq_key("frodokem-976-aes")
        pq_key2 = PQKeyFactory.generate_pq_key("frodokem-976-aes")

        key1 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key1, trad_key=trad_key1)
        key2 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key2, trad_key=trad_key2)

        ss, ct = key1.encaps(key2.public_key())

        ss2 = key2.decaps(ct)
        self.assertEqual(ss, ss2)