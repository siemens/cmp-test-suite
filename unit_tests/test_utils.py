# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources import utils


class TestUtils(unittest.TestCase):
    def test_nonces_must_be_unique(self):
        nonces_unique = [b'1234', b'5678', b'12314']
        utils.nonces_must_be_unique(nonces_unique)

        nonces_dupe = [b'1234', b'5678', b'12314', b'1234']
        with self.assertRaises(ValueError):
            utils.nonces_must_be_unique(nonces_dupe)

    def test_nonces_must_be_diverse(self):
        nonces_similar = [b'\x00' * 16, b'\x01' + b'\x00' * 15]
        with self.assertRaises(ValueError):
            utils.nonces_must_be_diverse(nonces_similar)

        nonces_diverse = [b'\x00' * 16, b'\xFF' * 16]
        utils.nonces_must_be_diverse(nonces_diverse)


if __name__ == '__main__':
    unittest.main()
