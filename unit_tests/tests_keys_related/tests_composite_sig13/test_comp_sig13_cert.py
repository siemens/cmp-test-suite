# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.exceptions import InvalidSignature

from pq_logic.keys.composite_sig import CompositeSigPrivateKey
from resources.certbuildutils import build_certificate
from resources.certutils import verify_cert_signature
from resources.exceptions import InvalidKeyCombination
from resources.keyutils import generate_key, load_private_key_from_file


class TestCompositeSig13Cert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bad_rsa_key = generate_key("bad_rsa_key")
        cls.ml_dsa_44_key = generate_key("ml-dsa-44")
        cls.comp_bad_key = CompositeSigPrivateKey(trad_key=cls.bad_rsa_key, pq_key=cls.ml_dsa_44_key)

    def test_cert_comp_sig_pure_bad_rsa_with_pk(self):
        """
        GIVEN a composite rsa signature key.
        WHEN generating a certificate,
        THEN the signature is valid.
        """
        with self.assertRaises(InvalidKeyCombination):
            _ = build_certificate(self.comp_bad_key)

    def test_cert_comp_sig_pure_rsa(self):
        """
        GIVEN a composite rsa signature key.
        WHEN generating a certificate,
        THEN the signature is valid.
        """
        rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        comp_key = CompositeSigPrivateKey(trad_key=rsa_key, pq_key=self.ml_dsa_44_key)
        cert, _ = build_certificate(comp_key)
        verify_cert_signature(cert, comp_key.public_key())


    def test_cert_comp_sig_pure_rsa_bad_sig(self):
        """
        GIVEN a composite rsa signature key.
        WHEN generating a certificate,
        THEN the signature is valid.
        """
        rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        comp_key = CompositeSigPrivateKey(trad_key=rsa_key, pq_key=self.ml_dsa_44_key)
        cert, _ = build_certificate(comp_key, bad_sig=True)
        with self.assertRaises(InvalidSignature):
            verify_cert_signature(cert, comp_key.public_key())
