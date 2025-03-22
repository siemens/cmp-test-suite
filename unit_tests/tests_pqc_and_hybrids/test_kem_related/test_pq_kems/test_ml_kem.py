# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.kem_keys import MLKEMPrivateKey
from resources.utils import manipulate_first_byte


class TestMLKEMKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mlkem_key = MLKEMPrivateKey.generate("ml-kem-768")


    def test_mlkem_encaps_decaps(self):
        """
        GIVEN a MLKEM key pair.
        WHEN the encapsulation and decapsulation functions are called,
        THEN should the shared secret be equal to the original shared secret.
        """
        key1 = self.mlkem_key
        ss_1, ct = key1.public_key().encaps()
        ss_2 = key1.decaps(ct)
        self.assertEqual(ss_1.hex(), ss_2.hex())

    def test_invalid_mlkem_decaps(self):
        """
        GIVEN a MLKEM key pair.
        WHEN the encapsulation and decapsulation functions are called with manipulated ciphertext,
        THEN should the shared secret not be equal to the original shared secret.
        """
        key1 = self.mlkem_key
        ss_1, ct = key1.public_key().encaps()
        ct = manipulate_first_byte(ct)
        ss_2 = key1.decaps(ct)
        self.assertNotEqual(ss_1, ss_2)


