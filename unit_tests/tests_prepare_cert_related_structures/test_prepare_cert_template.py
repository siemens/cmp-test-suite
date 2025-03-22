# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc9481
from resources.certbuildutils import prepare_cert_template
from resources.utils import get_openssl_name_notation


class TestPrepareCertTemplate(unittest.TestCase):
    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.subject = "CN=Test Subject"
        self.issuer = "CN=Test Issuer"
        self.serial_number = 123456789
        self.version = rfc5280.Version(2).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        self.extensions = rfc5280.Extensions()

    def test_cert_template_with_subject_and_issuer(self):
        """
        GIVEN a subject and issuer
        WHEN prepare_certtemplate is called with these fields
        THEN the resulting certificate template should correctly contain the provided subject and issuer.
        """
        cert_template = prepare_cert_template(key=self.public_key, subject=self.subject, issuer=self.issuer)

        self.assertTrue(cert_template["subject"].isValue)
        self.assertTrue(cert_template["issuer"].isValue)

        subject = get_openssl_name_notation(cert_template["subject"])
        issuer = get_openssl_name_notation(cert_template["issuer"])

        self.assertEqual(subject, self.subject)
        self.assertEqual(issuer, self.issuer)

    def test_cert_template_with_serial_number_and_version(self):
        """
        GIVEN a serial number and version
        WHEN prepare_certtemplate is called with these fields
        THEN the resulting certificate template should correctly contain the provided serial number and version.
        """
        cert_template = prepare_cert_template(
            key=self.public_key, serial_number=self.serial_number, version=self.version
        )

        self.assertTrue(cert_template["serialNumber"].isValue)
        self.assertTrue(cert_template["version"].isValue)
        self.assertEqual(int(cert_template["serialNumber"]), self.serial_number)
        self.assertEqual(int(cert_template["version"]), int(self.version))

    def test_cert_template_with_extensions(self):
        """
        GIVEN an extension to be added to the certificate template
        WHEN prepare_certtemplate is called with the extensions field
        THEN the resulting template should contain the specified extension.
        """
        ext = rfc5280.Extension()
        ext["extnID"] = univ.ObjectIdentifier("1.2.3.4.5.6.7.8.9")
        ext["extnValue"] = univ.OctetString(b"TestExtension")
        self.extensions.append(ext)

        cert_template = prepare_cert_template(key=self.public_key, extensions=self.extensions)

        self.assertTrue(cert_template["extensions"].isValue)
        self.assertEqual(cert_template["extensions"][0]["extnID"], ext["extnID"])

    def test_cert_template_for_kga(self):
        """
        GIVEN a private key and the for_kga flag set to True
        WHEN prepare_certtemplate is called
        THEN the certificate template should contain an empty public key structure
             to be filled by the key generation authority (KGA).
        """
        cert_template = prepare_cert_template(key=self.private_key, for_kga=True)

        self.assertIn("publicKey", cert_template)
        self.assertEqual(cert_template["publicKey"]["algorithm"]["algorithm"], rfc9481.rsaEncryption)
        self.assertEqual(cert_template["publicKey"]["subjectPublicKey"].asOctets(), b"")

    def test_exclude_fields(self):
        """
        GIVEN an exclude_fields parameter with "subject"
        WHEN prepare_certtemplate is called
        THEN the resulting certificate template should omit the subject field but include the issuer field.
        """
        cert_template = prepare_cert_template(
            key=self.public_key, subject=self.subject, issuer=self.issuer, exclude_fields="subject"
        )

        self.assertFalse(cert_template["subject"].isValue)
        self.assertTrue(cert_template["issuer"].isValue)


if __name__ == "__main__":
    unittest.main()
