# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc9480
from resources.certbuildutils import build_certificate, generate_certificate, prepare_tbs_certificate
from resources.certutils import check_is_cert_signer, verify_cert_signature
from resources.keyutils import generate_key, load_private_key_from_file


class TestPrepareCertTemplate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.key2 = load_private_key_from_file("data/keys/private-key-ed25519.pem")

    def test_prepare_tbs_certificate(self):
        """
        GIVEN a subject name, a public key, a signing key, and a serial number.
        WHEN prepare_tbs_certificate is called to create a TBS (To Be Signed) certificate structure.
        THEN the resulting TBS certificate should contain the correct serial number, and successfully decode to the
        expected ASN.1 TBSCertificate structure.
        """
        key = generate_key("rsa")
        tbs_cert = prepare_tbs_certificate(
            subject="CN=Hans the tester", public_key=key.public_key(), signing_key=key, serial_number=10
        )
        decoded_cert, rest = decoder.decode(encoder.encode(tbs_cert), asn1Spec=rfc5280.TBSCertificate())
        self.assertEqual(rest, b"")
        self.assertEqual(tbs_cert["serialNumber"], 10)

    def test_prepare_certificate(self):
        """
        GIVEN a signing key, common name, private key, and serial number.
        WHEN generate_certificate is called to create a certificate.
        THEN the certificate should decode to a CMPCertificate structure and have the correct serial number,
        and the certificate's signature should be valid.
        """
        cert = generate_certificate(
            signing_key=self.signing_key, common_name="CN=hans", private_key=self.signing_key, serial_number=10
        )
        decoded_cert, rest = decoder.decode(encoder.encode(cert), asn1Spec=rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        self.assertEqual(cert["tbsCertificate"]["serialNumber"], 10)
        verify_cert_signature(cert=cert)

    def test_build_certificate_ext(self):
        """
        GIVEN a common name and key usage extensions.
        WHEN build_certificate is called to create a certificate with these parameters.
        THEN the certificate should decode to a CMPCertificate structure, and the signature should be valid.
        """
        cert, key = build_certificate(
            common_name="CN=Root",
            key_usage="digitalSignature,keyCertSign",
        )
        decoded_cert, rest = decoder.decode(encoder.encode(cert), asn1Spec=rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        verify_cert_signature(cert=cert)

    def test_signing_cert(self):
        """
        GIVEN a root certificate and a child certificate signed by this root.
        WHEN check_is_cert_signer is called with the child and root certificates.
        THEN the function should verify that the root certificate is indeed the issuer of the child certificate.
        """
        cert = generate_certificate(common_name="CN=Root", private_key=self.signing_key, serial_number=10)
        cert2 = generate_certificate(
            signing_key=self.signing_key,
            issuer_cert=cert,
            common_name="CN=CA 1",
            private_key=self.key2,
            serial_number=11,
        )
        check_is_cert_signer(cert=cert2, poss_issuer=cert)

if __name__ == "__main__":
    unittest.main()
