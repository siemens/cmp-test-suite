# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.type import univ
from pyasn1_alt_modules import rfc3565, rfc8619, rfc9481, rfc9629
from resources.ca_kga_logic import validate_kem_recip_info_structure
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_recipient_identifier
from resources.exceptions import BadAlg
from resources.oidutils import id_alg_ml_kem_512_oid
from resources.utils import load_and_decode_pem_file

from unit_tests.tests_pqc_and_hybrids.test_kem_related.test_kem_logic.kem_dataclass import KEMRecipientInfo


class TestValidateKEMInfo(unittest.TestCase):

    def setUp(self):
        self.server_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        rid = prepare_recipient_identifier(self.server_cert)
        self.recipient_info = KEMRecipientInfo(
            version=univ.Integer(0),
            rid=rid,
            kem=id_alg_ml_kem_512_oid,
            kemct=univ.OctetString(b"kem_ct_mock"),
            kdf=rfc8619.id_alg_hkdf_with_sha256,
            kekLength=univ.Integer(16),
            ukm=univ.OctetString(b"mock_ukm"),
            wrap=rfc3565.id_aes128_wrap,
            encryptedKey=univ.OctetString(b"encrypted_key_mock")
        )

    def test_valid(self):
        """
        GIVEN a KEMRecipientInfo structure.
        WHEN the structure is validated.
        THEN the structure should be valid.
        """
        result = validate_kem_recip_info_structure(self.recipient_info, self.server_cert)
        self.assertEqual(result["encrypted_key"], b"encrypted_key_mock")
        self.assertEqual(result["kemct"], b"kem_ct_mock")
        self.assertEqual(result["kdf_algorithm"]["algorithm"], rfc8619.id_alg_hkdf_with_sha256)
        self.assertEqual(result["ukm"], b"mock_ukm")

    def test_invalid_version(self):
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
        self.recipient_info["rid"] = univ.Integer(0)
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


