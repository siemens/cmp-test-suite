# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_sig.chameleon_logic import build_paired_csrs, verify_paired_csr_signature
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

        csr = build_paired_csrs(delta_private_key=delta_ec_key, base_private_key=rsa_key)
        verify_paired_csr_signature(csr)

