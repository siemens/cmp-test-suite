# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1utils import encode_to_der
from resources.certbuildutils import generate_certificate, generate_signed_csr
from resources.certutils import parse_certificate
from resources.cmputils import build_p10cr_from_csr, prepare_extra_certs
from resources.keyutils import generate_key
from resources.protectionutils import add_cert_to_pkimessage_used_by_protection

from unit_tests.utils_for_test import compare_pyasn1_objects


class TestPrepareCertPKIMessageProtection(unittest.TestCase):
    @classmethod
    def setUp(cls):
        csr, private_key = generate_signed_csr(common_name="CN=Hans", return_as_pem=False)
        pki_message = build_p10cr_from_csr(csr)

        cls.certificate = generate_certificate(private_key=private_key, common_name="CN=Hans")
        cls.pki_message = pki_message
        cls.private_key = private_key

    def test_without_certificate_and_empty_extraCerts(self):
        """
        GIVEN a PKIMessage with no existing certificates and a `cryptography.PrivateKey`.
        WHEN `add_cert_to_pkimessage_used_by_protection` is called without providing a certificate.
        THEN the function should add a generated certificate to the `extraCerts` field, and the field
        should contain one certificate.
        """
        add_cert_to_pkimessage_used_by_protection(self.pki_message, self.private_key, cert=None)
        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(len(self.pki_message["extraCerts"]) == 1)

    def test_with_certificate_and_empty_extraCerts(self):
        """
        GIVEN a PKIMessage with no existing certificates and a provided certificate.
        WHEN `add_cert_to_pkimessage_used_by_protection` is called with the provided certificate.
        THEN the function should add the certificate to the `extraCerts` field, and the field should contain exactly
        one certificate, and the added certificate should match the provided one.
        """
        """Test if a provided certificate can be added to a `rfc9480.PKIMessage` for protection."""
        add_cert_to_pkimessage_used_by_protection(self.pki_message, self.private_key, self.certificate)
        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(len(self.pki_message["extraCerts"]) == 1)
        raw = encode_to_der(self.certificate)
        certificate = parse_certificate(raw)
        self.assertTrue(compare_pyasn1_objects(self.pki_message["extraCerts"][0], certificate))

    def test_with_certificate_and_same_extraCerts(self):
        """
        GIVEN a PKIMessage that already contains a certificate in `extraCerts`.
        WHEN `add_cert_to_pkimessage_used_by_protection` is called with the same certificate.
        THEN the function should not duplicate the certificate, and the `extraCerts` field should still contain
        exactly one certificate and the existing certificate in `extraCerts`
        should match the provided one.
        """
        self.assertTrue(len(self.pki_message["extraCerts"]) == 0)
        raw = encode_to_der(self.certificate)
        certificate = parse_certificate(raw)
        self.pki_message["extraCerts"] = prepare_extra_certs([certificate])

        add_cert_to_pkimessage_used_by_protection(self.pki_message, self.private_key, cert=self.certificate)

        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(
            len(self.pki_message["extraCerts"]) == 1,
            f"Length of PKIMessage ExtraCerts is : {len(self.pki_message['extraCerts'])}",
        )

        self.assertTrue(compare_pyasn1_objects(self.pki_message["extraCerts"][0], self.certificate))

    def test_extraCerts_and_wrong_private_key(self):
        """
        GIVEN a PKIMessage with a certificate in `extraCerts` and a private key that does not
        match the public key of the certificate.
        WHEN `add_cert_to_pkimessage_used_by_protection` is called with the mismatched private key.
        THEN a `ValueError` should be raised, indicating that the private key does not correspond
        to the CMP protection certificate
        inside the `extraCerts` field.
        """
        self.pki_message["extraCerts"] = prepare_extra_certs([self.certificate])
        # Generate a new key so that the public key of the
        # certificate does not match the private key.
        private_key = generate_key()

        with self.assertRaises(ValueError):
            add_cert_to_pkimessage_used_by_protection(self.pki_message, private_key, cert=None)


if __name__ == "__main__":
    unittest.main()
