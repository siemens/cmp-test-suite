# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211, rfc9481
from resources.extra_issuing_logic import prepare_private_key_for_pop
from resources.keyutils import load_private_key_from_file


class TestPreparePrivateKeyForPop(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

    def test_prepare_private_key_for_pop_string(self):
        """
        GIVEN a private key and a sender name.
        WHEN prepare_private_key_for_pop is called with the private key and sender name and use_string is True.
        THEN the data is returned and can be en- and decoded
        """
        data = prepare_private_key_for_pop(private_key=self.key,
                                           sender="CN=Hans the Tester", use_string=True)
        der_data = encoder.encode(data)
        decoded_data, rest = decoder.decode(der_data)
        self.assertEqual(rest, b"")


    def test_prepare_private_key_for_pop_gen_name(self):
        """
        GIVEN a private key and a sender name.
        WHEN prepare_private_key_for_pop is called with the private key and sender name and use_string is False.
        THEN the data is returned and can be en- and decoded.
        """
        data = prepare_private_key_for_pop(private_key=self.key,
                                           sender="CN=Hans the Tester",
                                           use_string=False)
        der_data = encoder.encode(data)
        decoded_data, rest = decoder.decode(der_data, rfc4211.EncKeyWithID())
        self.assertEqual(rest, b"")


    def test_decode_private_key(self):
        """
        GIVEN a private key and a sender name.
        WHEN prepare_private_key_for_pop is called with the private key and sender name and use_string is False.
        THEN the data is returned and can be en- and decoded.
        """
        data = prepare_private_key_for_pop(private_key=self.key, sender="CN=Hans the Tester",
                                           use_string=False)
        der_data = encoder.encode(data)
        decoded_data, _ = decoder.decode(der_data, rfc4211.EncKeyWithID())

        self.assertEqual(str(decoded_data["privateKey"]["privateKeyAlgorithm"]["algorithm"]),
                         str(rfc9481.rsaEncryption))
