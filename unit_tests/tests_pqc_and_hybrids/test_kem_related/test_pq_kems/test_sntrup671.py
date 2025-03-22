# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.kem_keys import Sntrup761PrivateKey
from resources.utils import manipulate_first_byte


class TestMLKEMKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sntrup761_key = Sntrup761PrivateKey.generate()

    def test_sntrup761_encaps_decaps(self):
        """
        GIVEN a Sntrup761 key pair.
        WHEN the encapsulation and decapsulation functions are called,
        THEN should the shared secret be equal to the original shared secret.
        """
        ss_1, ct = self.sntrup761_key.public_key().encaps()
        ss_2 = self.sntrup761_key.decaps(ct)
        self.assertEqual(ss_1, ss_2)

    def test_sntrup761_encaps_decaps_invalid(self):
        """
        GIVEN a Sntrup761 key pair.
        WHEN the encapsulation and decapsulation functions are called with manipulated ciphertext,
        THEN should the shared secret not be equal to the original shared secret.
        """
        ss_1, ct = self.sntrup761_key.public_key().encaps()
        ct = manipulate_first_byte(ct)
        ss_2 = self.sntrup761_key.decaps(ct)
        self.assertNotEqual(ss_1, ss_2)
