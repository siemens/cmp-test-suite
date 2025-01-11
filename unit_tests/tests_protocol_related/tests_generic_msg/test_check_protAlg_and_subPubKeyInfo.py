# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480
from resources.checkutils import check_protection_alg_conform_to_spki
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage

from unit_tests.utils_for_test import build_pkimessage


class TestCheckProtectionAlgAndSubKey(unittest.TestCase):
    @classmethod
    def setUp(cls):
        """Set up a valid PKI message for both signature-based and MAC-based protection."""
        cls.unprotected_pki_message = build_pkimessage()

    def test_correct_protAlg_and_subPubKeyInfo_ed448(self):
        """
        GIVEN a PKI message protected with an Ed448 private key and a valid protection algorithm
        WHEN the PKI message is signed and protected using the Ed448 private key
        THEN the protection algorithm should conform to the subjectPublicKeyInfo field in the CMP certificate.
        """
        ed448_private_key = generate_key("ed448")
        protected_message = protect_pkimessage(
            pki_message=self.unprotected_pki_message, private_key=ed448_private_key, protection="signature"
        )
        asn1_cert: rfc9480.CMPCertificate = protected_message["extraCerts"][0]
        alg_id = protected_message["header"]["protectionAlg"]
        self.assertTrue(check_protection_alg_conform_to_spki(alg_id, asn1_cert))

    def test_correct_protAlg_and_subPubKeyInfo_ed25519(self):
        """
        GIVEN a PKI message protected with an Ed25519 private key and a valid protection algorithm
        WHEN the PKI message is signed and protected using the Ed25519 private key
        THEN the protection algorithm should conform to the subjectPublicKeyInfo field in the CMP certificate.
        """
        ed25519_private_key = generate_key("ed25519")
        protected_message = protect_pkimessage(
            pki_message=self.unprotected_pki_message, private_key=ed25519_private_key, protection="signature"
        )
        asn1_cert: rfc9480.CMPCertificate = protected_message["extraCerts"][0]
        alg_id = protected_message["header"]["protectionAlg"]
        self.assertTrue(check_protection_alg_conform_to_spki(alg_id, asn1_cert))

    def test_correct_protAlg_and_subPubKeyInfo_ecdsa(self):
        """
        GIVEN a PKI message protected with an ECDSA private key and a valid protection algorithm
        WHEN the PKI message is signed and protected using the ECDSA private key
        THEN the protection algorithm should conform to the subjectPublicKeyInfo field in the CMP certificate.
        """
        ecdsa_private_key = generate_key("ecdsa")
        protected_message = protect_pkimessage(
            pki_message=self.unprotected_pki_message, private_key=ecdsa_private_key, protection="signature"
        )
        asn1_cert: rfc9480.CMPCertificate = protected_message["extraCerts"][0]
        alg_id = protected_message["header"]["protectionAlg"]
        self.assertTrue(check_protection_alg_conform_to_spki(alg_id, asn1_cert))

    def test_correct_protAlg_and_subPubKeyInfo_rsa(self):
        """
        GIVEN a PKI message protected with an RSA private key and a valid protection algorithm
        WHEN the PKI message is signed and protected using the RSA private key
        THEN the protection algorithm should conform to the subjectPublicKeyInfo field in the CMP certificate.
        """
        rsa_private_key = generate_key("rsa")
        protected_message = protect_pkimessage(
            pki_message=self.unprotected_pki_message, private_key=rsa_private_key, protection="signature"
        )
        asn1_cert: rfc9480.CMPCertificate = protected_message["extraCerts"][0]
        alg_id = protected_message["header"]["protectionAlg"]
        self.assertTrue(check_protection_alg_conform_to_spki(alg_id, asn1_cert))
