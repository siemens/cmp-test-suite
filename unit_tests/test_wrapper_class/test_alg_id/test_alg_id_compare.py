# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from unit_tests.asn1_wrapper_class.wrapper_alg_id import AlgorithmIdentifier, PBKDF2Params


class TestAlgorithmIdentifierComparison(unittest.TestCase):


    def test_not_equal_identifiers(self):
        """
        GIVEN two AlgorithmIdentifier instances with different parameters
        WHEN comparing them
        THEN they should not be equal.
        """
        param1 = PBKDF2Params(salt=b"test_salt", iterationCount=1000)
        alg_id1 = AlgorithmIdentifier(algorithm="pbkdf2", parameters=param1)
        param2 = PBKDF2Params(salt=b"different_salt", iterationCount=1000)
        alg_id2 = AlgorithmIdentifier(algorithm="pbkdf2", parameters=param2)
        self.assertFalse(alg_id1.equal(alg_id2), "AlgorithmIdentifiers with different parameters should not be equal.")

    def test_equal_ignore_salt(self):
        """
        GIVEN two AlgorithmIdentifier instances with different salts
        WHEN comparing them while ignoring the salt
        THEN they should be equal.
        """
        param1 = PBKDF2Params(salt=b"test_salt", iterationCount=1000)
        alg_id1 = AlgorithmIdentifier(algorithm="pbkdf2", parameters=param1)
        param2 = PBKDF2Params(salt=b"different_salt", iterationCount=1000)
        alg_id2 = AlgorithmIdentifier(algorithm="pbkdf2", parameters=param2)
        self.assertTrue(alg_id1.equal(alg_id2, exclude_salt=True), "AlgorithmIdentifiers should be equal when ignoring salt.")
