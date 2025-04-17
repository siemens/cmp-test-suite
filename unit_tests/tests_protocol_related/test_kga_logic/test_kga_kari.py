# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9481
from resources.ca_kga_logic import validate_key_agree_recipient_info
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_key_agreement_recipient_info
from resources.utils import load_and_decode_pem_file


class TestValidationKARI(unittest.TestCase):
    def setUp(self):
        self.bare_cmp_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        self.cmp_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ecc_cert_ski.pem"))
        self.header_version = 3
        self.encrypted_key = bytes.fromhex("AA" * 32)
        self.key_agreement_oid = rfc9481.id_alg_ESDH

    def test_kari_valid(self):
        """
        GIVEN a valid KARI structure with a certificate with the ski extension.
        WHEN validate_KeyAgreeRecipientInfo is called.
        THEN no exception should be raised.
        """
        kari = prepare_key_agreement_recipient_info(version=3,
                                                    cmp_cert=self.cmp_cert,
                                                    encrypted_key=self.encrypted_key,
                                                    key_agreement_oid=self.key_agreement_oid,
                                                    )
        validate_key_agree_recipient_info(kari, self.cmp_cert)

    def test_kari_valid_without_ski_extension(self):
        """
        GIVEN a valid KARI structure with a certificate without the ski extension.
        WHEN validate_KeyAgreeRecipientInfo is called.
        THEN no exception should be raised.
        """
        kari = prepare_key_agreement_recipient_info(version=3,
                                                    cmp_cert=self.bare_cmp_cert,
                                                    encrypted_key=self.encrypted_key,
                                                    key_agreement_oid=self.key_agreement_oid,
                                                    )
        validate_key_agree_recipient_info(kari, self.bare_cmp_cert)


    def test_kari_invalid_version(self):
        """
        GIVEN a KARI structure with an invalid version.
        WHEN validate_KeyAgreeRecipientInfo is called.
        THEN it should raise a ValueError indicating the version must be 3.
        """
        kari = prepare_key_agreement_recipient_info(
            version=2, cmp_cert=self.cmp_cert,
            encrypted_key=self.encrypted_key,
            key_agreement_oid=self.key_agreement_oid
        )
        with self.assertRaises(ValueError):
            validate_key_agree_recipient_info(kari, self.cmp_cert)

    def test_kari_missing_recipient_encrypted_key(self):
        """
        GIVEN a KARI structure that is missing recipientEncryptedKeys field.
        WHEN validate_KeyAgreeRecipientInfo is called.
        THEN it should raise a ValueError indicating that recipientEncryptedKeys is absent.
        """
        kari = prepare_key_agreement_recipient_info(
            encrypted_key=None,
            cmp_cert=self.cmp_cert,
            key_agreement_oid=self.key_agreement_oid
        )
        with self.assertRaises(ValueError):
            validate_key_agree_recipient_info(kari, self.cmp_cert)


if __name__ == "__main__":
    unittest.main()
