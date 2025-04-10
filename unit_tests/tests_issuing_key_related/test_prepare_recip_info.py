# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1_alt_modules import rfc5652

from resources.certbuildutils import generate_certificate
from resources.certutils import parse_certificate, load_public_key_from_cert
from resources.envdatautils import prepare_issuer_and_serial_number, prepare_recip_info
from resources.keyutils import generate_key, load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestPrepareRecipInfo(unittest.TestCase):
    def setUp(self):
        self.rsa_private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

        self.rsa_public_key = self.rsa_private_key.public_key()

        self.ec_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ec_public_key = self.ec_private_key.public_key()

        self.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        self.cek = b"\x00" * 32

        self.issuer_and_ser = prepare_issuer_and_serial_number(issuer="CN=Null-DN", serial_number=0)

    def test_prepare_recip_info_rsa(self):
        """
        GIVEN an RSA public key and certificate.
        WHEN preparing the recipient info.
        THEN the recipient info should be correctly prepared.
        """
        recip_info = prepare_recip_info(
            public_key_recip=self.rsa_public_key,
            cert_recip=self.cert,
            cek=self.cek,
            use_rsa_oaep=True,
            issuer_and_ser=self.issuer_and_ser,
        )
        self.assertIsInstance(recip_info, rfc5652.RecipientInfo)

    def test_prepare_recip_info_ec(self):
        """
        GIVEN an EC public key and private key.
        WHEN preparing the recipient info.
        THEN the recipient info should be correctly prepared.
        """
        recip_info = prepare_recip_info(
            public_key_recip=self.ec_public_key,
            private_key=self.ec_private_key,
            cert_recip=self.cert,
            cek=self.cek,
            issuer_and_ser=self.issuer_and_ser,
        )
        self.assertIsInstance(recip_info, rfc5652.RecipientInfo)

    def test_prepare_recip_info_password(self):
        """
        GIVEN a password.
        WHEN preparing the recipient info.
        THEN the recipient info should be correctly prepared.
        """
        recip_info = prepare_recip_info(
            public_key_recip=None, password="testpassword", cek=self.cek, salt=b"\x00" * 32, kdf_name="pbkdf2"
        )
        self.assertIsInstance(recip_info, rfc5652.RecipientInfo)

    def test_prepare_recip_info_kem(self):
        """
        GIVEN a kem certificate.
        WHEN preparing the recipient info.
        THEN the recipient info should be correctly prepared.
        """
        mlkem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768.pem")
        kem_cert = generate_certificate(private_key=mlkem_key, signing_key=self.ec_private_key)


        recip_info = prepare_recip_info(
            public_key_recip=mlkem_key.public_key(),
            cert_recip=kem_cert,
            cek=self.cek,
            issuer_and_ser=self.issuer_and_ser,
            kdf_name="pbkdf2",
        )
        self.assertIsInstance(recip_info, rfc5652.RecipientInfo)


if __name__ == "__main__":
    unittest.main()
