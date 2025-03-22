# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from unit_tests.asn1_wrapper_class.wrapper_alg_id import (
    AlgorithmIdentifier,
    DHBasedMac,
    DHBMParameter,
    KDF2AlgId,
    KDF2Params,
    KDF3AlgId,
    KDF3Params,
    PBKDF2AlgId,
    PBKDF2Params,
    PBMAC1AlgId,
    PBMAC1Params,
)


class TestAlgorithmIdentifierEncoding(unittest.TestCase):
    def test_pbkdf2(self):
        """
        GIVEN a PBKDF2AlgId object with a PBKDF2Params object as parameters
        WHEN the object is encoded to DER format and then decoded back,
        THEN the decoded object should match the original object.
        """
        params = PBKDF2Params(
            salt=b"example_salt",
            iterationCount=1000,
            keyLength=32,
            prf=AlgorithmIdentifier(algorithm="hmac-sha256")
        )
        alg_id = PBKDF2AlgId(parameters=params)
        encoded = alg_id.encode()
        decoded = PBKDF2AlgId.from_der(encoded)
        self.assertEqual(alg_id, decoded)

    def test_pbmac1(self):
        """
        GIVEN a PBMAC1AlgId object with a PBMAC1Params object as parameters
        WHEN the object is encoded to DER format and then decoded back,
        THEN the decoded object should match the original object.
        """
        params = PBMAC1Params(
            keyDerivationFunc=AlgorithmIdentifier(algorithm="pbkdf2"),
            messageAuthScheme=AlgorithmIdentifier(algorithm="hmac-sha256")
        )
        alg_id = PBMAC1AlgId(parameters=params)
        encoded = alg_id.encode()
        decoded = PBMAC1AlgId.from_der(encoded)
        self.assertEqual(alg_id, decoded)

    def test_dh_based_mac(self):
        """
        GIVEN a DHBasedMac object with a DHBMParameter object as parameters
        WHEN the object is encoded to DER format and then decoded back,
        THEN the decoded object should match the original object.
        """
        params = DHBMParameter(
            owf=AlgorithmIdentifier(algorithm="sha256"),
            mac=AlgorithmIdentifier(algorithm="hmac-sha256")
        )
        alg_id = DHBasedMac(parameters=params)
        encoded = alg_id.encode()
        decoded = DHBasedMac.from_der(encoded)
        self.assertEqual(alg_id, decoded)

    def test_kdf2(self):
        """
        GIVEN a KDF2AlgId object with a KDF2Params object as parameters
        WHEN the object is encoded to DER format and then decoded back,
        THEN the decoded object should match the original object.
        """
        params = KDF2Params(algorithm="sha256")
        alg_id = KDF2AlgId(parameters=params)
        encoded = alg_id.encode()
        decoded = KDF2AlgId.from_der(encoded)
        self.assertEqual(alg_id, decoded)

    def test_kdf3(self):
        """
        GIVEN a KDF3AlgId object with a KDF3Params object as parameters
        WHEN the object is encoded to DER format and then decoded back,
        THEN the decoded object should match the original object.
        """
        params = KDF3Params(algorithm="sha256")
        alg_id = KDF3AlgId(parameters=params)
        encoded = alg_id.encode()
        decoded = KDF3AlgId.from_der(encoded)
        self.assertEqual(alg_id, decoded)
