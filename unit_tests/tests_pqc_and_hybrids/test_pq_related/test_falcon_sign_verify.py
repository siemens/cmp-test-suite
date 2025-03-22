# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.exceptions import InvalidSignature
from pq_logic.keys.sig_keys import FalconPrivateKey
from resources.utils import manipulate_first_byte


class TestSignVerifyFalcon(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = b"Hello, World!"

    def test_sign_verify_falcon512(self):
        """
        GIVEN a "falcon512" private key.
        WHEN signing data and verifying the signature,
        THEN the signature is valid.
        """
        key = FalconPrivateKey("falcon-512")
        sig = key.sign(self.data)
        key.public_key().verify(signature=sig, data=self.data)

    def test_sign_verify_falcon1024(self):
        """
        GIVEN a "falcon1024" private key.
        WHEN signing data and verifying the signature,
        THEN the signature is valid.
        """
        key = FalconPrivateKey("falcon-1024")
        sig = key.sign(self.data)
        key.public_key().verify(signature=sig, data=self.data)

    def test_sign_verify_falcon512_invalid_sig(self):
        """
        GIVEN a "falcon512" private key.
        WHEN signing data and verifying an invalid signature,
        THEN an InvalidSignature exception is raised.
        """
        key = FalconPrivateKey("falcon-512")
        sig = key.sign(self.data)
        invalid_sig = manipulate_first_byte(sig)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(signature=invalid_sig, data=self.data)


    def test_sign_verify_falcon1024_invalid_sig(self):
        """
        GIVEN a "falcon1024" private key.
        WHEN signing data and verifying an invalid signature,
        THEN an InvalidSignature exception is raised.
        """
        key = FalconPrivateKey("falcon-1024")
        sig = key.sign(self.data)
        invalid_sig = manipulate_first_byte(sig)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(signature=invalid_sig, data=self.data)
