# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_sig.chameleon_logic import build_paired_csr, verify_paired_csr_signature
from resources.exceptions import BadPOP, BadAltPOP
from resources.keyutils import generate_key

# TODO add doc

class TestChameleonLogic(unittest.TestCase):

    def test_build_and_verify_paired_csr(self):
        """
        GIVEN an EC and RSA private key.
        WHEN building a paired CSR, and verifying the signature.
        THEN the signature is verified correctly.
        """
        delta_ec_key = generate_key("ec")
        rsa_key = generate_key("rsa")

        csr = build_paired_csr(delta_private_key=delta_ec_key, base_private_key=rsa_key)
        verify_paired_csr_signature(csr)

    def test_verify_paired_csr_invalid_signature(self):
        """
        GIVEN an EC and RSA private key.
        WHEN building a paired CSR, and verifying the invalid signature.
        THEN a BadPOP is raised.
        """
        delta_ec_key = generate_key("ec")
        rsa_key = generate_key("rsa")

        csr = build_paired_csr(delta_private_key=delta_ec_key,
                               base_private_key=rsa_key, bad_alt_pop=True)
        with self.assertRaises(BadAltPOP):
            verify_paired_csr_signature(csr)

