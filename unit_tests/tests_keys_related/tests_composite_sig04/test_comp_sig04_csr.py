# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_sig06 import CompositeSig06PrivateKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey
from resources.certutils import verify_csr_signature
from resources.certbuildutils import build_csr
from resources.exceptions import BadPOP
from resources.keyutils import load_private_key_from_file, generate_key


class TestCompositeSig06CSR(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ecc = generate_key("ed25519")
        cls.ml_dsa_65 = load_private_key_from_file("data/keys/private-key-ml-dsa-65-seed.pem") # type: ignore
        cls.ml_dsa_65: MLDSAPrivateKey

    def test_csr_comp_sig_pure_ecc(self):
        """
        GIVEN a composite ECC signature key.
        WHEN generating a CSR,
        THEN the signature is valid.
        """
        comp_key = CompositeSig06PrivateKey(trad_key=self.ecc, pq_key=self.ml_dsa_65)
        csr = build_csr(comp_key)
        verify_csr_signature(csr)

    def test_csr_comp_sig_pure_ecc_bad_pop(self):
        """
        GIVEN a composite ECC signature key.
        WHEN generating a CSR,
        THEN the signature is valid.
        """
        comp_key = CompositeSig06PrivateKey(trad_key=self.ecc, pq_key=self.ml_dsa_65)
        csr = build_csr(comp_key, bad_pop=True)
        with self.assertRaises(BadPOP):
            verify_csr_signature(csr)