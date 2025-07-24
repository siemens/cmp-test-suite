# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280

from pq_logic.keys.composite_sig07 import CompositeSig07PrivateKey
from resources import keyutils


class TestLoadCompSig07(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        rsa_key = keyutils.generate_key("rsa", length=2048)
        mldsa_key = keyutils.generate_key("ml-dsa-44")
        cls.comp_rsa_key = CompositeSig07PrivateKey(mldsa_key, rsa_key)
        ed_key = keyutils.generate_key("ed448")
        mldsa_key = keyutils.generate_key("ml-dsa-87")
        cls.comp_ed_key = CompositeSig07PrivateKey(mldsa_key, ed_key)

        ecc_key = keyutils.generate_key("ecdsa")
        mldsa_key = keyutils.generate_key("ml-dsa-65")
        cls.comp_ecc_key = CompositeSig07PrivateKey(mldsa_key, ecc_key)

    def test_export_and_load_private_key_rsa(self):
        """
        GIVEN a composite signature RSA private key in version 7.
        WHEN exporting the public key and loading it back.
        THEN the loaded key is the same as the exported key.
        """
        spki = self.comp_rsa_key.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        obj, rest = decoder.decode(spki, rfc5280.SubjectPublicKeyInfo())
        self.assertEqual(rest, b"")
        public_key = keyutils.load_public_key_from_spki(obj)
        self.assertEqual(public_key, self.comp_rsa_key.public_key())


    def test_export_and_load_private_key_ed(self):
        """
        GIVEN a composite signature Ed private key in version 7.
        WHEN exporting the public key and loading it back.
        THEN the loaded key is the same as the exported key.
        """
        spki = self.comp_ed_key.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        obj, rest = decoder.decode(spki, rfc5280.SubjectPublicKeyInfo())
        self.assertEqual(rest, b"")
        public_key = keyutils.load_public_key_from_spki(obj)
        self.assertEqual(public_key, self.comp_ed_key.public_key())

    def test_export_and_load_private_key_ecc(self):
        """
        GIVEN a composite signature ECC private key in version 7.
        WHEN exporting the public key and loading it back.
        THEN the loaded key is the same as the exported key.
        """
        spki = self.comp_ecc_key.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        obj, rest = decoder.decode(spki, rfc5280.SubjectPublicKeyInfo())
        self.assertEqual(rest, b"")
        public_key = keyutils.load_public_key_from_spki(obj)
        self.assertEqual(public_key, self.comp_ecc_key.public_key())

