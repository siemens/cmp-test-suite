# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from cryptography.hazmat.primitives import serialization

from resources.cryptoutils import (
    compute_ansi_x9_63_kdf,
    compute_recipient_ecdh_mqv_one_pass_exchange,
    compute_sender_ecdh_mqv_one_pass_exchange,
)
from resources.keyutils import load_private_key_from_file


class TestComputeEcdhMkv(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir_path = "unit_tests/tests_protocol_related/test_kga_logic/tests_kari_related"
        fpath = os.path.join(cls.dir_path, "sender_private_key.der")
        with open(fpath, "rb") as key_file:
            cls.sender_static_key = serialization.load_der_private_key(
                key_file.read(),
                password=None,
            )

        fpath = "data/keys/private-key-ecdsa.pem"
        cls.recipient_private_key = load_private_key_from_file(fpath)
        eph_key_path = os.path.join(cls.dir_path, "sender_ephemeral_private_key.der")
        with open(eph_key_path, "rb") as key_file:
            cls.sender_eph_key = serialization.load_der_private_key(
                key_file.read(),
                password=None,
            )

    def test_compute_ecdh_mvq_sender(self):
        expected_ss = "b6f9d200858b82664f732e79f035851a0ec18682ea4802ff312af84068d15d2c"

        computed_k = compute_sender_ecdh_mqv_one_pass_exchange(
            static_private_key=self.sender_static_key,
            ephemeral_key=self.sender_static_key,
            recip_public_key=self.recipient_private_key.public_key(),
        )
        out_ss = compute_ansi_x9_63_kdf(
            shared_secret=computed_k,
            key_length=32,
            hash_alg="sha256",
            other_info=b"",
            use_version_2=True,
        )
        self.assertEqual(
            out_ss.hex(),
            expected_ss,
            "Computed MVQ shared secret does not match expected value.",
        )

    def test_compute_ecdh_mvq_recipient(self):
        expected_ss = "b6f9d200858b82664f732e79f035851a0ec18682ea4802ff312af84068d15d2c"

        computed_k = compute_recipient_ecdh_mqv_one_pass_exchange(
            recip_key=self.recipient_private_key,
            ephemeral_pub_key=self.sender_static_key.public_key(),
            static_public_key=self.sender_static_key.public_key(),
        )
        out_ss = compute_ansi_x9_63_kdf(
            shared_secret=computed_k,
            key_length=32,
            hash_alg="sha256",
            other_info=b"",
            use_version_2=True,
        )
        self.assertEqual(
            out_ss.hex(),
            expected_ss,
            "Computed MVQ shared secret does not match expected value.",
        )

    def test_sender_compute_ecdh_mvq2(self):
        expected_ss = "437d0665a9e4c5ea7c885653f7f98df4cb739bc1df4d8f7ec53e9de731af0b9d"

        computed_z = compute_sender_ecdh_mqv_one_pass_exchange(
            static_private_key=self.sender_static_key,
            ephemeral_key=self.sender_eph_key,
            recip_public_key=self.recipient_private_key.public_key(),
        )

        expected_z = "ef6d451ac8d45654f21e877a11e0eef7992dcbf6704422ebd50c8e7c01e0b9b1"
        self.assertEqual(
            computed_z.hex(),
            expected_z,
            "Computed MVQ shared secret does not match expected value.",
        )

        out_ss = compute_ansi_x9_63_kdf(
            shared_secret=computed_z,
            key_length=32,
            hash_alg="sha256",
            other_info=b"",
            use_version_2=True,
        )
        self.assertEqual(
            out_ss.hex(),
            expected_ss,
            "Computed MVQ shared secret does not match expected value.",
        )

    def test_recipient_compute_ecdh_mvq2(self):
        expected_ss = "437d0665a9e4c5ea7c885653f7f98df4cb739bc1df4d8f7ec53e9de731af0b9d"

        computed_k = compute_recipient_ecdh_mqv_one_pass_exchange(
            recip_key=self.recipient_private_key,
            ephemeral_pub_key=self.sender_eph_key.public_key(),
            static_public_key=self.sender_static_key.public_key(),
        )
        out_ss = compute_ansi_x9_63_kdf(
            shared_secret=computed_k,
            key_length=32,
            hash_alg="sha256",
            other_info=b"",
            use_version_2=True,
        )
        self.assertEqual(
            out_ss.hex(),
            expected_ss,
            "Computed MVQ shared secret does not match expected value.",
        )
