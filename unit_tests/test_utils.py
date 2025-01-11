# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources import utils


class TestUtils(unittest.TestCase):
    def test_nonces_must_be_unique(self):
        """
        GIVEN a list of nonces.
        WHEN checking if the nonces are unique,
        THEN the nonces must be unique.
        """
        nonces_unique = [b"1234", b"5678", b"12314"]
        utils.nonces_must_be_unique(nonces_unique)

        nonces_dupe = [b"1234", b"5678", b"12314", b"1234"]
        with self.assertRaises(ValueError):
            utils.nonces_must_be_unique(nonces_dupe)

    def test_nonces_must_be_diverse(self):
        """
        GIVEN a list of nonces, which are not diverse.
        WHEN checking if the nonces are diverse,
        THEN an error is raised.
        """
        nonces_similar = [b"\x00" * 16, b"\x01" + b"\x00" * 15]
        with self.assertRaises(ValueError):
            utils.nonces_must_be_diverse(nonces_similar)

        nonces_diverse = [b"\x00" * 16, b"\xff" * 16]
        utils.nonces_must_be_diverse(nonces_diverse)


if __name__ == "__main__":
    unittest.main()
