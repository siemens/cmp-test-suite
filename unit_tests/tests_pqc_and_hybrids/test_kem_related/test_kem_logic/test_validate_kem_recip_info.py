# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.type import univ
from pyasn1_alt_modules import rfc8619, rfc9481, rfc9629
from resources.ca_kga_logic import validate_kem_recip_info_structure
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_recipient_identifier, prepare_kem_recip_info
from resources.exceptions import BadAlg
from resources.oidutils import id_ml_kem_768
from resources.utils import load_and_decode_pem_file



class TestValidateKEMInfo(unittest.TestCase):

    def setUp(self):
        self.server_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/pq_cert_ml_kem_768.pem"))
        rid = prepare_recipient_identifier(self.server_cert)

        self.recipient_info = prepare_kem_recip_info(
            version=0,
            rid=rid,
            kem_oid=id_ml_kem_768,
            kemct=b"kem_ct_mock",
            kdf="hkdf",
            hash_alg="sha256",
            kek_length=16,
            ukm=b"mock_ukm",
            wrap_name="aes128_wrap",
            encrypted_key=b"encrypted_key_mock"
        )

    def test_valid_kemri(self):
        """
        GIVEN a KEMRecipientInfo structure.
        WHEN the structure is validated.
        THEN the structure should be valid.
        """
        result = validate_kem_recip_info_structure(self.recipient_info, self.server_cert)
        self.assertEqual(result["encrypted_key"], b"encrypted_key_mock")
        self.assertEqual(result["kemct"], b"kem_ct_mock")
        self.assertEqual(result["kdf_algorithm"]["algorithm"], rfc8619.id_alg_hkdf_with_sha256)
        self.assertNotEqual(result["ukm"], b"mock_ukm")

    def test_invalid_version_kemri(self):
        """
        GIVEN a KEMRecipientInfo structure.
        WHEN the version field is not equal to 0.
        THEN a ValueError should be raised.
        """
        self.recipient_info["version"] = univ.Integer(1)
        with self.assertRaises(ValueError) as cm:
            validate_kem_recip_info_structure(self.recipient_info, self.server_cert)
        self.assertEqual(str(cm.exception), "The `version` field of the `KEMRecipientInfo` structure must be present and equal to `0`!")

    def test_missing_rid(self):
        """
        GIVEN a KEMRecipientInfo structure.
        WHEN the rid field is missing.
        THEN a ValueError should be raised.
        """
        self.recipient_info["rid"] = rfc9629.RecipientIdentifier()
        with self.assertRaises(ValueError):
            validate_kem_recip_info_structure(self.recipient_info, self.server_cert)

    def test_invalid_kem_oid(self):
        """
        GIVEN a KEMRecipientInfo structure.
        WHEN the kem field is not a valid OID.
        THEN a ValueError should be raised.
        """
        self.recipient_info["kem"]["algorithm"] = rfc9481.rsaEncryption
        with self.assertRaises(BadAlg):
            validate_kem_recip_info_structure(self.recipient_info, self.server_cert)

    def test_missing_encrypted_key(self):
        """
        GIVEN a KEMRecipientInfo structure.
        WHEN the encryptedKey field is missing.
        THEN a ValueError should be raised.
        """
        self.recipient_info["encryptedKey"] = univ.OctetString()
        with self.assertRaises(ValueError):
            validate_kem_recip_info_structure(self.recipient_info, self.server_cert)

if __name__ == "__main__":
    unittest.main()


