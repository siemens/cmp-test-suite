# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


import unittest

from pq_logic.chempatkem import ChempatMLKEM768PrivateKey


class TestChempatKEM(unittest.TestCase):

    def test_chempat_ml_kem_768_x25519(self):
        """
        GIVEN two ChempatMLKEM768PrivateKey instances.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key1 = ChempatMLKEM768PrivateKey.generate(trad_name="x25519")
        key2 = ChempatMLKEM768PrivateKey.generate(trad_name="x25519")

        ss_1, ct = key1.encaps(key2.public_key())
        ss_2 = key2.decaps(ct)
        self.assertEqual(ss_1, ss_2)

