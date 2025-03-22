# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc4211, rfc5280
from resources.certbuildutils import generate_certificate
from resources.cmputils import prepare_controls_structure
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


if __name__ == "__main__":
    unittest.main()
