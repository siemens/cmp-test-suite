# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography import x509
from pyasn1_alt_modules import rfc5280, rfc9480

from resources.certbuildutils import prepare_authority_key_identifier_extension, build_certificate
from resources.certextractutils import get_authority_key_identifier
from resources.keyutils import load_private_key_from_file
from resources.prepareutils import prepare_name
from resources.utils import get_openssl_name_notation


class TestPrepareAKI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", None)

    def _extract(self, extn: rfc5280.Extension) -> rfc5280.AuthorityKeyIdentifier:
        """Extract the SKI extension."""
        cert = rfc9480.CMPCertificate()
        cert['tbsCertificate']['extensions'].append(extn)
        extracted_aki = get_authority_key_identifier(
            cert
        )

        self.assertIsNotNone(
            extracted_aki
        )
        return extracted_aki

    def test_prepare_aki_key(self):

        extn = prepare_authority_key_identifier_extension(
            ca_key=self.key.public_key(),
            critical=False
        )
        self.assertFalse(extn["critical"])
        self.assertEqual(extn["extnID"], rfc5280.id_ce_authorityKeyIdentifier)

        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            self.key.public_key(),
        ).key_identifier
        extracted_aki = self._extract(extn)
        self.assertEqual(aki, extracted_aki["keyIdentifier"].asOctets())

    def test_prepare_aki_with_cert(self):

        cert, _ = build_certificate(
            self.key,
            common_name="CN=Hans the Tester",
            serial_number=123456
        )

        extn = prepare_authority_key_identifier_extension(
            ca_key=self.key.public_key(),
            ca_cert=cert,
            critical=False,
            include_issuer=True,
            include_serial_number=True
        )

        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key=self.key.public_key()).key_identifier
        extracted_aki = self._extract(extn)
        self.assertEqual(aki, extracted_aki["keyIdentifier"].asOctets())

        name = get_openssl_name_notation(
            extracted_aki["authorityCertIssuer"][0]["directoryName"]
        )
        self.assertEqual(
            "CN=Hans the Tester",
            name,
        )
        self.assertEqual(
            123456,
            int(extracted_aki["authorityCertSerialNumber"]),

        )

    def test_invalid_key_id(self):
        """
        GIVEN
        :return:
        """
        extn = prepare_authority_key_identifier_extension(
            ca_key=self.key.public_key(),
            critical=False,
            invalid_key_id=True
        )
        extracted_aki = self._extract(extn)
        computed_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            self.key.public_key()
        ).key_identifier
        self.assertNotEqual(computed_aki, extracted_aki["keyIdentifier"].asOctets())

    def test_include_issuer_missing_info(self):
        with self.assertRaises(ValueError):
            prepare_authority_key_identifier_extension(
                ca_key=self.key.public_key(),
                include_issuer=True
            )

    def test_include_serial_number_missing_ca_cert(self):
        with self.assertRaises(ValueError):
            prepare_authority_key_identifier_extension(
                ca_key=self.key.public_key(),
                include_serial_number=True
            )

    def test_include_issuer_with_ca_name(self):
        extn = prepare_authority_key_identifier_extension(
            ca_key=self.key.public_key(),
            critical=False,
            include_issuer=True,
            ca_name="CN=Test CA"
        )
        extracted_aki = self._extract(extn)
        issuer_name = get_openssl_name_notation(extracted_aki["authorityCertIssuer"][0]["directoryName"])
        self.assertEqual("CN=Test CA", issuer_name)

    def test_include_issuer_with_general_names(self):
        cert, _ = build_certificate(
            self.key,
            common_name="CN=Hans the Tester",
            serial_number=654321
        )
        gn = rfc9480.GeneralName()
        gn["directoryName"]["rdnSequence"] = prepare_name("CN=Extra")["rdnSequence"]
        extn = prepare_authority_key_identifier_extension(
            ca_key=self.key.public_key(),
            ca_cert=cert,
            ca_name="CN=Hans the Tester",
            critical=False,
            include_issuer=True,
            general_names=[gn]
        )
        extracted = self._extract(extn)
        self.assertGreaterEqual(len(extracted["authorityCertIssuer"]), 2)
        issuer1 = get_openssl_name_notation(extracted["authorityCertIssuer"][0]["directoryName"])
        self.assertEqual("CN=Hans the Tester", issuer1)
        issuer2 = get_openssl_name_notation(extracted["authorityCertIssuer"][1]["directoryName"])
        self.assertEqual("CN=Extra", issuer2)

    def test_increase_serial(self):
        cert, _ = build_certificate(
            self.key,
            common_name="CN=Hans the Tester",
            serial_number=1000
        )
        extn = prepare_authority_key_identifier_extension(
            ca_key=self.key.public_key(),
            ca_cert=cert,
            critical=False,
            include_serial_number=True,
            increase_serial=True
        )
        extracted = self._extract(extn)
        self.assertEqual(1001, int(extracted["authorityCertSerialNumber"]))


if __name__ == "__main__":
    unittest.main()







