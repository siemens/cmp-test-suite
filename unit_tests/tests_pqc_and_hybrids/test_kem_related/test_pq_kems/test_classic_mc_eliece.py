# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.kem_keys import McEliecePrivateKey
from resources.keyutils import generate_key
from resources.utils import manipulate_first_byte


class TestMcEliceKEM(unittest.TestCase):

    def test_mc_eliece_kem_pos(self):
        """
        GIVEN a McElieceKEM instance.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key: McEliecePrivateKey = generate_key("mceliece-348864")

        ss, ct = key.public_key().encaps()

        self.assertEqual(ss, key.decaps(ct))


    def test_mc_eliece_kem_neg(self):
        """
        GIVEN a McElieceKEM instance.
        WHEN encaps and decaps are called and the ciphertext is manipulated.
        THEN the shared secret should not be equal.
        """
        key: McEliecePrivateKey = generate_key("mceliece-348864")

        ss, ct = key.public_key().encaps()
        ct = manipulate_first_byte(ct)
        self.assertNotEqual(ss, key.decaps(ct))
