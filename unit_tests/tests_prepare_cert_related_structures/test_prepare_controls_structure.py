# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc4211, rfc5280
from resources.certbuildutils import build_certificate, generate_certificate
from resources.cmputils import prepare_controls_structure, prepare_old_cert_id_control
from resources.keyutils import generate_key
from resources.utils import get_openssl_name_notation


class TestPrepareStructure(unittest.TestCase):
    def setUp(self):
        self.serial_number = 123456789
        self.issuer = "CN=issuer@example.com"
        self.key = generate_key()
        self.cert = generate_certificate(private_key=self.key)

    def test_prepare_structure_encode_decode(self):
        """
        GIVEN a serial number and issuer
        WHEN prepare_controls_structure is called,
        THEN the encoded structure should correctly decode back into `Controls` and contain
             the expected `OldCertId` fields, verifying the issuer name and serial number.
        """
        controls_structure = prepare_controls_structure(serial_number=self.serial_number, issuer=self.issuer)

        encoded_data = encode(controls_structure)
        decoded_controls, rest = decode(encoded_data, rfc4211.Controls())
        self.assertEqual(rest, b"")
        old_id_obj, rest = decode(decoded_controls[0]["value"], asn1Spec=rfc4211.OldCertId())
        self.assertEqual(rest, b"")

        self.assertIsInstance(old_id_obj["issuer"], rfc5280.GeneralName)
        issuer_str = get_openssl_name_notation(old_id_obj["issuer"]["directoryName"])
        self.assertEqual(issuer_str, self.issuer)
        self.assertEqual(old_id_obj["serialNumber"], self.serial_number)

    def test_prepare_structure_controls(self):
        """
        GIVEN a certificate object
        WHEN prepare_controls_structure is called with the certificate,
        THEN the encoded structure should correctly decode into `Controls` with no remaining bytes.
        """
        controls_structure = prepare_controls_structure(cert=self.cert)
        encoded_data = encode(controls_structure)
        decoded_controls, rest = decode(encoded_data, asn1Spec=rfc4211.Controls())
        self.assertEqual(rest, b"")

    def test_old_cert_id_keeps_multi_rdn_issuer(self):
        """
        GIVEN a certificate whose issuer has several RDNs
        WHEN prepare_old_cert_id_control is called with the certificate,
        THEN the issuer of the `OldCertId` must be DER-identical to the issuer of the certificate.
        """
        cert, _ = build_certificate(common_name="CN=Test CA,O=Test Org,C=DE")
        control = prepare_old_cert_id_control(cert=cert)
        self.assertEqual(
            encode(control["value"]["issuer"]["directoryName"]["rdnSequence"]),
            encode(cert["tbsCertificate"]["issuer"]["rdnSequence"]),
        )

    def test_old_cert_id_does_not_share_issuer_with_cert(self):
        """
        GIVEN a certificate
        WHEN prepare_old_cert_id_control is called with the certificate and the issuer of the control is changed,
        THEN the issuer of the certificate must stay unchanged.
        """
        cert, _ = build_certificate(common_name="CN=Test CA,O=Test Org,C=DE")
        issuer_der = encode(cert["tbsCertificate"]["issuer"]["rdnSequence"])
        control = prepare_old_cert_id_control(cert=cert)
        control["value"]["issuer"]["directoryName"]["rdnSequence"].clear()
        self.assertEqual(encode(cert["tbsCertificate"]["issuer"]["rdnSequence"]), issuer_der)


if __name__ == "__main__":
    unittest.main()
