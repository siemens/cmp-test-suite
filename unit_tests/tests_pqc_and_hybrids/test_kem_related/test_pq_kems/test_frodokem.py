# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.kem_keys import FrodoKEMPrivateKey
from resources.keyutils import generate_key
from resources.utils import manipulate_first_byte


class TestFrodoKEM(unittest.TestCase):

    def test_frodokem_pos(self):
        """
        GIVEN two FrodoKEM key keys.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key1: FrodoKEMPrivateKey = generate_key("frodokem-640-aes")

        ss_1, ct = key1.public_key().encaps()
        ss_2 = key1.decaps(ct)

        self.assertEqual(ss_1, ss_2)

    def test_frodokem_neg(self):
        """
        GIVEN two FrodoKEM key keys.
        WHEN encaps and decaps are called and the ciphertext is manipulated,
        THEN should the shared secret not be equal.
        """
        key: FrodoKEMPrivateKey = generate_key("frodokem-640-aes")

        ss_1, ct = key.public_key().encaps()
        ct_modified = manipulate_first_byte(ct)

        ss_2 = key.decaps(ct_modified)

        self.assertNotEqual(ss_1, ss_2)
