# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import os
import unittest

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5652, rfc9481
from resources.ca_kga_logic import (
    validate_encrypted_content_info,
)
from resources.envdatautils import prepare_encrypted_content_info
from resources.exceptions import BadAsn1Data


class TestValidateEncryptedContentInfo(unittest.TestCase):
    def setUp(self):
        self.content_encryption_key = b"\xaa" * 16

        self.enc_content_info = prepare_encrypted_content_info(
            data_to_protect=os.urandom(32), cek=self.content_encryption_key
        )

    def test_validate_encrypted_content_info_valid(self):
        """
        GIVEN a valid EncryptedContentInfo structure.
        WHEN validate_EncryptedContentInfo is called with correct parameters.
        THEN no exception should be raised, and the encrypted content should be validated.
        """
        validate_encrypted_content_info(self.enc_content_info,
                                        self.content_encryption_key,
                                        )

    def test_invalid_content_type(self):
        """
        GIVEN an EncryptedContentInfo structure with an invalid contentType.
        WHEN validate_EncryptedContentInfo is called.
        THEN a ValueError should be raised indicating an invalid contentType.
        """
        self.enc_content_info["contentType"] = rfc5652.id_data  # Invalid content type
        with self.assertRaises(ValueError) as context:
            validate_encrypted_content_info(self.enc_content_info, self.content_encryption_key)
        self.assertIn("The `contentType` MUST be id-signedData!", str(context.exception))

    def test_invalid_content_encryption_algorithm(self):
        """
        GIVEN an EncryptedContentInfo structure with an invalid contentEncryptionAlgorithm.
        WHEN validate_EncryptedContentInfo is called.
        THEN a ValueError should be raised indicating an invalid encryption algorithm.
        """
        self.enc_content_info["contentEncryptionAlgorithm"]["algorithm"] = rfc9481.id_aes192_CBC
        with self.assertRaises(ValueError):
            validate_encrypted_content_info(self.enc_content_info, self.content_encryption_key)

    def test_missing_iv_parameters(self):
        """
        GIVEN an EncryptedContentInfo structure with missing IV parameters.
        WHEN validate_EncryptedContentInfo is called.
        THEN a ValueError should be raised indicating that the IV is missing.
        """
        self.enc_content_info["contentEncryptionAlgorithm"]["parameters"] = univ.Null("")
        with self.assertRaises(BadAsn1Data):
            validate_encrypted_content_info(self.enc_content_info, self.content_encryption_key)

    def test_invalid_content_encryption_key_size(self):
        """
        GIVEN an EncryptedContentInfo structure with an invalid content encryption key size.
        WHEN validate_EncryptedContentInfo is called.
        THEN a ValueError should be raised indicating a mismatch between the key size and the expected AES key size.
        """
        invalid_key = b"B" * 32  # Invalid AES-256 key for AES-128 CBC encryption
        with self.assertRaises(ValueError):
            validate_encrypted_content_info(self.enc_content_info, invalid_key)


if __name__ == "__main__":
    unittest.main()
