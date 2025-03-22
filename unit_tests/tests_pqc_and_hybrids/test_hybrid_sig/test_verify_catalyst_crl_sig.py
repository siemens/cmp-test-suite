# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_sig.catalyst_logic import sign_crl_catalyst
from resources.certutils import parse_certificate
from pq_logic.py_verify_logic import verify_crl_signature
from resources.exceptions import InvalidAltSignature
from resources.keyutils import load_private_key_from_file
from resources.utils import load_crl_from_file, load_and_decode_pem_file


class TestVerifyCatalystCRL(unittest.TestCase):


    @classmethod
    def setUpClass(cls):
        cls.ca_private_key = load_private_key_from_file(
            "data/keys/private-key-rsa.pem", password=None
        )
        cls.ca_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/bare_certificate.pem")
        )
        cls.alt_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")


    def test_valid_crl_signature(self):
        """
        GIVEN a catalyst CRL
        WHEN verifying the signature,
        THEN it should pass if the signature is valid.
        """
        crl = load_crl_from_file("data/unittest/test_verify_crl.crl")
        crl = sign_crl_catalyst(crl,
                                ca_private_key=self.ca_private_key,
                                alt_private_key=self.alt_key,
                                hash_alg="sha256",
                                alt_hash_alg="sha512",
                                )

        verify_crl_signature(
            crl=crl,
            ca_cert=self.ca_cert,
            alt_public_key=self.alt_key.public_key(),
        )

    def test_invalid_catalyst_signature(self):
        """
        GIVEN a catalyst CRL
        WHEN verifying the signature,
        THEN it should pass if the signature is valid.
        """
        crl = load_crl_from_file("data/unittest/test_verify_crl.crl")
        crl = sign_crl_catalyst(crl,
                                ca_private_key=self.ca_private_key,
                                alt_private_key=self.alt_key,
                                hash_alg="sha256",
                                alt_hash_alg="sha512",
                                bad_alt_sig=True,
                                )

        with self.assertRaises(InvalidAltSignature):
            verify_crl_signature(
                crl=crl,
                ca_cert=self.ca_cert,
                alt_public_key=self.alt_key.public_key(),
            )









