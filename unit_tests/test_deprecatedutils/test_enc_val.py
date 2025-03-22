# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211
from resources.deprecatedutils import prepare_encrypted_value, process_encrypted_value


class TestEncryptionFunctions(unittest.TestCase):

    def setUp(self):
        self.data = b"Some test data to encrypt"
        self.kek = b"A" * 32
        self.cek = b"B" * 32
        self.iv = b"C" * 16
        self.aes_wrap_size = 256
        self.aes_cbc_size = 256
        self.encrypted_value = prepare_encrypted_value(
            data=self.data,
            kek=self.kek,
            cek=self.cek,
            iv=self.iv,
            aes_cbc_size=self.aes_cbc_size,
            aes_wrap_size=self.aes_wrap_size
        )

    def test_prepare_encrypted_value(self):
        """
        GIVEN an `EncryptedValue` object created from some data
        WHEN the object is encoded to DER format and then decoded back
        THEN it should decode without any remaining bytes, and the encoded value should not match the original plaintext data.
        """
        der_data = encoder.encode(self.encrypted_value)
        data, rest = decoder.decode(der_data, rfc4211.EncryptedValue())
        self.assertEqual(rest, b"")
        self.assertNotEqual(self.data, data["encValue"].asOctets())

    def test_process_encrypted_value(self):
        """
        GIVEN an encrypted value and the key encryption key (KEK) used for encryption
        WHEN `process_encrypted_value` is called to decrypt the data
        THEN the decrypted data should match the original plaintext data.
        """
        decrypted_data = process_encrypted_value(self.kek, self.encrypted_value)
        self.assertEqual(decrypted_data, self.data)

    def test_decryption_mismatch(self):
        """
        GIVEN an incorrect key encryption key (KEK) for an encrypted value
        WHEN `process_encrypted_value` is called to decrypt the data
        THEN an `InvalidUnwrap` exception should be raised due to the mismatch.
        """
        kek = b"D" * 32
        with self.assertRaises(InvalidUnwrap):
            process_encrypted_value(kek, self.encrypted_value)



if __name__ == '__main__':
    unittest.main()
