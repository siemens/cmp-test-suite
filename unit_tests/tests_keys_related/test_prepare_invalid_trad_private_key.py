# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization

from pq_logic.keys.trad_key_factory import prepare_invalid_trad_private_key
from resources.keyutils import generate_key


class TestPrepareInvalidTradPrivateKey(unittest.TestCase):

    def test_prepare_invalid_rsa_key(self):
        """
        GIVEN an invalid RSA private key.
        WHEN the key is prepared,
        THEN the key should be prepared correctly and the loading should raise an exception.
        """
        key = generate_key("rsa")
        der_data = prepare_invalid_trad_private_key(key, invalid_key=True)
        with self.assertRaises(ValueError):
            serialization.load_der_private_key(der_data, password=None)

    def test_prepare_invalid_ecc_key(self):
        """
        GIVEN an invalid ECC private key.
        WHEN the key is prepared,
        THEN the key should be prepared correctly and the loading should raise an exception.
        """
        key = generate_key("ecc")
        der_data = prepare_invalid_trad_private_key(key, invalid_key=True)
        with self.assertRaises(BaseException):
            # pyo3_runtime.PanicException: Is a `Rust` exception and derives from `BaseException`.
            serialization.load_der_private_key(der_data, password=None)
