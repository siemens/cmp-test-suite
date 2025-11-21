# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.hss_validation import validate_hss_key, validate_hss_key_levels
from pq_logic.keys.stateful_sig_keys import HSSPrivateKey
from resources.exceptions import InvalidKeyData


class TestHSSValidation(unittest.TestCase):

    def test_accepts_valid_configuration(self) -> None:
        """
        GIVEN a valid two-level HSS configuration with matching hash families and digest sizes.
        WHEN validating the HSS key configuration,
        THEN no exception should be raised.
        """
        levels = [
            ("lms_sha256_m32_h5", "lmots_sha256_n32_w8"),
            ("lms_sha256_m24_h10", "lmots_sha256_n24_w4"),
        ]
        # Should not raise for a valid two-level configuration.
        validate_hss_key_levels(levels, enforce_lw=True)

    def test_reject_diff_hash_and_output_size_per_level(self) -> None:
        """
        GIVEN a two-level HSS configuration with differing hash families and digest sizes.
        WHEN validating the HSS key configuration without allowing differences,
        THEN an InvalidKeyData exception should be raised with messages about mismatches.
        """
        levels = [
            ("lms_sha256_m32_h5", "lmots_sha256_n32_w8"),
            ("lms_shake_m32_h5", "lmots_shake_n24_w4"),
        ]
        with self.assertRaises(InvalidKeyData) as exc:
            validate_hss_key_levels(levels, enforce_lw=False)

        error_details = str(exc.exception.error_details)
        self.assertIn("Level 1: Digest size mismatch: LMS m=32 bytes, LMOTS n=24 bytes", error_details)
        self.assertIn("Digest size mismatch with level 0", error_details)
        self.assertIn("Hash family mismatch with level 0", error_details)
        self.assertIn("Level 1: Winternitz parameter mismatch with level 0: LMOTS uses w=4 while level 0 uses w=8.", error_details)

    def test_rejects_invalid_level_count(self) -> None:
        """
        GIVEN HSS configurations with invalid level counts (empty or 9 levels).
        WHEN validating the HSS key configuration,
        THEN an InvalidKeyData exception should be raised with a message about invalid level count.
        """
        with self.assertRaises(InvalidKeyData) as exc:
            validate_hss_key_levels([])
        self.assertIn("Invalid number of HSS levels", str(exc.exception))

        with self.assertRaises(InvalidKeyData) as exc:
            validate_hss_key_levels([("lms_sha256_m32_h5", "lmots_sha256_n32_w8")] * 9)
        self.assertIn("Invalid number of HSS levels", str(exc.exception))

    def test_rejects_hash_family_mismatch(self) -> None:
        """
        GIVEN an HSS configuration with mismatched hash families (SHA-256 and SHAKE).
        WHEN validating the HSS key configuration,
        THEN an InvalidKeyData exception should be raised with a message about hash family mismatch.
        """
        with self.assertRaises(InvalidKeyData) as exc:
            validate_hss_key_levels([("lms_sha256_m32_h5", "lmots_shake_n32_w8")])
        self.assertIn("Hash family mismatch", str(exc.exception))

    def test_rejects_digest_size_mismatch(self) -> None:
        """
        GIVEN an HSS configuration with mismatched digest sizes (m32 and n24).
        WHEN validating the HSS key configuration,
        THEN an InvalidKeyData exception should be raised with a message about digest size mismatch.
        """
        with self.assertRaises(InvalidKeyData) as exc:
            validate_hss_key_levels([("lms_sha256_m32_h5", "lmots_sha256_n24_w8")])
        self.assertIn("Digest size mismatch", str(exc.exception))

    def test_validate_hss_key_with_valid_key(self) -> None:
        """
        GIVEN a valid HSS private key with matching LMS/LMOTS parameters.
        WHEN validating the HSS key using validate_hss_key,
        THEN no exception should be raised.
        """
        # Create a valid HSS private key with 2 levels
        private_key = HSSPrivateKey("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=2)
        # Should not raise for a valid key
        validate_hss_key(private_key)

        # Also test with the public key
        public_key = private_key.public_key()
        validate_hss_key(public_key)

    def test_validate_hss_key_with_single_level(self) -> None:
        """
        GIVEN a valid single-level HSS key.
        WHEN validating the HSS key using validate_hss_key,
        THEN no exception should be raised.
        """
        # Create a single-level HSS key
        private_key = HSSPrivateKey("hss_lms_sha256_m32_h10_lmots_sha256_n32_w8", levels=1)
        validate_hss_key(private_key)

    def test_validate_hss_key_with_max_levels(self) -> None:
        """
        GIVEN an HSS key with the maximum allowed 8 levels.
        WHEN validating the HSS key using validate_hss_key,
        THEN no exception should be raised.
        """
        # Create an 8-level HSS key (maximum allowed by RFC 8554)
        private_key = HSSPrivateKey("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=8)
        validate_hss_key(private_key)

    def test_validate_hss_key_with_level_9(self) -> None:
        """
        GIVEN an HSS key with 9 levels (exceeding maximum allowed).
        WHEN validating the HSS key using validate_hss_key,
        THEN an InvalidKeyData exception should be raised about invalid level count.
        """
        # Create a 9-level HSS key (exceeding maximum allowed by RFC 8554)
        private_key = HSSPrivateKey("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=9)
        with self.assertRaises(InvalidKeyData) as exc:
            validate_hss_key(private_key)
        self.assertIn("Invalid number of HSS levels", str(exc.exception))


if __name__ == "__main__":
    unittest.main()
