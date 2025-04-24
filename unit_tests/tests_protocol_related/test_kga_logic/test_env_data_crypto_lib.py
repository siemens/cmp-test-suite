# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from pyasn1.codec.der import encoder

from resources.certbuildutils import build_certificate
from resources.keyutils import generate_key
from unit_tests.utils_for_test import parse_cms_env_data
from unit_tests.tests_protocol_related.test_support_messages.test_build_genm_strutcure import convert_to_asn1cert
from resources.ca_kga_logic import validate_enveloped_data

class TestPKCS7Envelope(unittest.TestCase):

    def test_pkcs7_envelope(self):
        """
        GIVEN a `EnvelopedData` structure.
        WHEN the structure is validated.
        THEN the data is decrypted and returned.
        """
        cert, key = build_certificate(generate_key("rsa"), "CN=CMP-Test-Suite")
        der_data = encoder.encode(cert)

        cert = x509.load_der_x509_certificate(der_data)
        options = [pkcs7.PKCS7Options.Binary]

        enveloped_data = (
            pkcs7.PKCS7EnvelopeBuilder()
            .set_data(b"data to encrypt")
            .add_recipient(cert)
            .encrypt(serialization.Encoding.DER, options)
        )

        env_data = parse_cms_env_data(enveloped_data)
        env_data["recipientInfos"][0]["ktri"]["version"] = 2

        cert = convert_to_asn1cert(cert)
        out = validate_enveloped_data(env_data,
                                      cmp_protection_cert=cert,
                                      ee_key=key,
                                      expected_raw_data=True,
                                      allow_rsa_null=True,
                                      )
        self.assertEqual(out, b"data to encrypt")

if __name__ == '__main__':
    unittest.main()