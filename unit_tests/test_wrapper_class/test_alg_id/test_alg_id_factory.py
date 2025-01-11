# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from unit_tests.asn1_wrapper_class.wrapper_alg_id import AlgIdFactory, KDF2Params, KDF3Params


class TestAlgIdFactory(unittest.TestCase):
    def test_create_pbkdf2(self):
        """
        GIVEN a PBKDF2 algorithm identifier,
        WHEN the algorithm identifier is encoded and decoded,
        THEN the encoded value should match the original value.
        """
        alg_id = AlgIdFactory.create(
            name="pbkdf2",
            salt=b"example_salt",
            iteration_count=1000,
            key_length=32,
            prf="hmac-sha256"
        )
        encoded = alg_id.encode()
        decoded = AlgIdFactory.from_der(encoded)
        self.assertEqual(encoded, decoded.encode())

    def test_create_pbmac1(self):
        """
        GIVEN a PBMAC1 algorithm identifier,
        WHEN the algorithm identifier is encoded and decoded,
        THEN the encoded value should match the original value.
        """
        alg_id = AlgIdFactory.create(
            name="pbmac1",
        )
        encoded = alg_id.encode()
        decoded = AlgIdFactory.from_der(encoded)
        self.assertEqual(encoded, decoded.encode())

    def test_create_dh_based_mac(self):
        """
        GIVEN a DH-based MAC algorithm identifier,
        WHEN the algorithm identifier is encoded and decoded,
        THEN the encoded value should match the original value.
        """
        alg_id = AlgIdFactory.create(
            name="dh_based_mac",
            hash_alg="sha256",
            mac="hmac-sha256"
        )
        encoded = alg_id.encode()
        decoded = AlgIdFactory.from_der(encoded)
        self.assertEqual(encoded, decoded.encode())

    def test_create_kdf2(self):
        """
        GIVEN a KDF2 algorithm identifier,
        WHEN the algorithm identifier is encoded and decoded,
        THEN the encoded value should match the original value.
        """
        alg_id = AlgIdFactory.create(
            name="kdf2",
            parameters=KDF2Params(algorithm="sha256")
        )
        encoded = alg_id.encode()
        decoded = AlgIdFactory.from_der(encoded)
        self.assertEqual(alg_id, decoded)

    def test_create_kdf3(self):
        """
        GIVEN a KDF3 algorithm identifier,
        WHEN the algorithm identifier is encoded and decoded,
        THEN the encoded value should match the original value.
        """
        alg_id = AlgIdFactory.create(
            name="kdf3",
            parameters=KDF3Params(algorithm="sha256")
        )
        encoded = alg_id.encode()
        decoded = AlgIdFactory.from_der(encoded)
        self.assertEqual(encoded, decoded.encode())

    def test_create_hmac(self):
        """
        GIVEN a hash algorithm, create an HMAC algorithm identifier.
        WHEN the algorithm identifier is encoded and decoded,
        THEN the encoded value should match the original value.
        """
        alg_id = AlgIdFactory.create(name="hmac", hash_alg="sha256")
        encoded = alg_id.encode()
        decoded = AlgIdFactory.from_der(encoded)
        self.assertEqual(encoded, decoded.encode())

    def test_create_sha256(self):
        """
        GIVEN a hash algorithm, create a SHA256 algorithm identifier.
        WHEN the algorithm identifier is encoded and decoded,
        THEN the encoded value should match the original value.
        """
        alg_id = AlgIdFactory.create(name="sha256")
        encoded = alg_id.encode()
        decoded = AlgIdFactory.from_der(encoded)
        self.assertEqual(encoded, decoded.encode())

if __name__ == "__main__":
    unittest.main()
