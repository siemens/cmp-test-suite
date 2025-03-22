# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import generate_certificate
from resources.checkutils import check_single_chain_is_ordered
from resources.keyutils import generate_key

from unit_tests.utils_for_test import build_certificate_chain


class TestCheckIfChainInOrder(unittest.TestCase):

    def setUp(self):
        cert_chain, private_keys = build_certificate_chain(length=3)
        self.root_cert = cert_chain[0]
        self.intermediate_cert = cert_chain[1]
        self.ee_cert = cert_chain[2]
        self.root_key = private_keys[0]
        self.intermediate_key = private_keys[1]
        self.ee_key = private_keys[2]

    def test_valid_chain(self):
        """
        GIVEN a valid certificate chain (End Entity, Intermediate CA, Root CA)
        WHEN `check_single_chain_is_ordered` is called with the correctly ordered chain,
        THEN it should return `True` indicating the chain is correctly ordered
        """
        chain = [
            self.ee_cert,
            self.intermediate_cert,
            self.root_cert,
        ]
        extra_certs = [
            self.ee_cert,
            self.intermediate_cert,
            self.root_cert,
        ]
        self.assertTrue(check_single_chain_is_ordered(extra_certs, chain, check_for_issued=False))

    def test_invalid_chain_wrong_order(self):
        """
        GIVEN a certificate chain incorrectly ordered
        WHEN `check_single_chain_is_ordered` is called with the wrong order of the chain,
        THEN it should return `False` indicating the chain is not correctly ordered
        """
        chain = [
            self.ee_cert,
            self.intermediate_cert,
            self.root_cert,
        ]

        extra_certs = [
            self.ee_cert,
            generate_certificate(generate_key()),  # Random extra certificate which is not part of the chain.
            self.intermediate_cert,
            self.root_cert,
        ]
        self.assertFalse(check_single_chain_is_ordered(extra_certs, chain, check_for_issued=False))


if __name__ == "__main__":
    unittest.main()
