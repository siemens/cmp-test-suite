# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import random
import unittest

from resources.asn1utils import encode_to_der
from resources.certbuildutils import generate_certificate
from resources.certutils import (
    build_chain_from_list,
    verify_cert_signature,
)

from unit_tests.utils_for_test import build_certificate_chain


def random_cert_order(certificates: list) -> list:
    """Randomly order a python list."""
    random.shuffle(certificates)
    return certificates


class TestBuildCertChainLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cert_chain, keys = build_certificate_chain()

        cls.root_key = keys[0]
        cls.intermediate_key = keys[1]
        cls.ee_key = keys[2]

        cls.root_cert = cert_chain[0]
        cls.intermediate_cert = cert_chain[1]
        cls.ee_cert = cert_chain[2]

        # signed with `root-key` to make sure the common_name is checked.
        cls.random_certs = [generate_certificate(cls.root_key, f"CN=Random Cert {i}") for i in range(7)]
        cls.all_certs = random_cert_order([cls.root_cert, cls.intermediate_cert, cls.ee_cert] + cls.random_certs)
        cls.path_to_anchors = "data/trustanchors"

    def verify_signatures_are_correct(self):
        """
        GIVEN a set of certificates (Root, Intermediate, and End-Entity)
        WHEN we verify the signatures of these certificates,
        THEN all signatures should be correct and no errors should be thrown
        """
        verify_cert_signature(self.root_cert, self.root_key.public_key())
        verify_cert_signature(self.intermediate_cert, self.root_key.public_key())
        verify_cert_signature(self.ee_cert, self.intermediate_key.public_key())

    def test_no_valid_chain_in_list(self):
        """
        GIVEN a certificate list missing the intermediate certificate
        WHEN we try to build a chain from this incomplete list,
        THEN a ValueError should be raised as the chain cannot be built
        """
        incomplete_cert_list = random_cert_order([self.root_cert, self.ee_cert] + self.random_certs)
        with self.assertRaises(ValueError):
            build_chain_from_list(ee_cert=self.ee_cert, certs=incomplete_cert_list, must_be_self_signed=True)

    def test_valid_chain_in_list(self):
        """
        GIVEN a certificate list containing the complete chain (Root, Intermediate, End-Entity)
        WHEN we attempt to build a chain from this list,
        THEN the chain should be successfully built, containing exactly three certificates (EE, Intermediate, Root)
        """
        complete_cert_list = random_cert_order([self.root_cert, self.intermediate_cert] + self.random_certs)
        found_chain = build_chain_from_list(ee_cert=self.ee_cert, certs=complete_cert_list, must_be_self_signed=True)
        self.assertTrue(len(found_chain) == 3)
        self.assertEqual(encode_to_der(found_chain[0]), encode_to_der(self.ee_cert))
        self.assertEqual(encode_to_der(found_chain[1]), encode_to_der(self.intermediate_cert))
        self.assertEqual(encode_to_der(found_chain[2]), encode_to_der(self.root_cert))
