# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Tuple, Union

from cryptography.hazmat.primitives import serialization

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.abstract_wrapper_keys import PQPrivateKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey, SLHDSAPrivateKey
from pq_logic.keys.xwing import XWingPrivateKey
from resources.keyutils import generate_key
from resources.suiteenums import KeySaveType

_SEED_KEY_TYPE = Union[
    MLKEMPrivateKey,
    SLHDSAPrivateKey,
    MLDSAPrivateKey,
    XWingPrivateKey,
]

class TestVariousKeySerialization(unittest.TestCase):
    def setUp(self):
        self.pq_alg_names = [
            "ml-dsa-44",
            "ml-kem-512",
            "slh-dsa",
            "xwing",
        ]

        self.liboqs_alg_names = [
            "falcon-512", # is a liboqs key, could be any other liboqs key.
            # because currently does not support key derivation from seed.
        ]

        self.hybrid_alg_names = [
            "composite-sig",
            "composite-kem",
            "chempat",
        ]

    def _compare_seed_key(self, key: _SEED_KEY_TYPE, loaded_key: _SEED_KEY_TYPE, save_type: KeySaveType):
        """Compare the original and loaded PQ keys."""
        self.assertEqual(
            key.private_bytes_raw(),
            loaded_key.private_bytes_raw(),
            f"Private raw bytes mismatch for {key.name}",
        )

        if save_type != KeySaveType.RAW:
            self.assertEqual(
                key.private_numbers(),
                loaded_key.private_numbers(),
                f"Seed mismatch for {key.name}",
            )
        self.assertEqual(
            key.public_key(),
            loaded_key.public_key(),
            f"Public key mismatch for {key.name}",
        )

    @staticmethod
    def _generate_seed_key_and_der(name: str, save_type: KeySaveType) -> \
            Tuple[Union[PQPrivateKey, XWingPrivateKey], bytes]:
        """Generate a PQ key and DER data."""
        key = generate_key(name)
        if not isinstance(key, (PQPrivateKey, XWingPrivateKey)):
            raise ValueError(f"Key is not a PQ key or XWing: {key.name}")

        der_data = CombinedKeyFactory.save_private_key_one_asym_key(
            key,
            save_type=save_type,
            password=None,
            version=0,
        )
        return key, der_data

    def test_key_serialization_and_loading_pq_seed(self):
        with self.subTest(f"Testing PQ keys with save type: Seed"):
            for name in self.pq_alg_names:
                with self.subTest(algorithm=name):
                    key, der_data = self._generate_seed_key_and_der(name, KeySaveType.SEED)
                    loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
                    self._compare_seed_key(key, loaded_key, save_type=KeySaveType.SEED)

    def test_key_serialization_and_loading_pq_seed_and_raw(self):
            with self.subTest(f"Testing PQ keys with save type: Seed and RAW"):
                for name in self.pq_alg_names:
                    with self.subTest(algorithm=name):
                        key, der_data = self._generate_seed_key_and_der(name, KeySaveType.SEED_AND_RAW)
                        loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
                        self._compare_seed_key(key, loaded_key, KeySaveType.SEED_AND_RAW)

    def test_key_serialization_and_loading_pq_raw(self):
        with self.subTest(f"Testing PQ keys with save type: RAW"):
            for name in self.pq_alg_names:
                with self.subTest(algorithm=name):
                    key, der_data = self._generate_seed_key_and_der(name, KeySaveType.RAW)
                    loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
                    self._compare_seed_key(key, loaded_key, KeySaveType.RAW)

    def test_key_serialization_and_loading_hybrid_seed(self):
        """
        GIVEN a list of hybrid algorithms.
        WHEN the keys are generated and serialized to DER format with the pq key as seed.
        THEN the keys should be loaded back successfully and match the original keys.
        """
        for name in self.hybrid_alg_names:
            with self.subTest(algorithm=name):
                key = generate_key(name)
                self.assertIsNotNone(key, f"Failed to generate key for {name}")

                der_data = CombinedKeyFactory.save_private_key_one_asym_key(
                    key,
                    save_type="seed",
                    password=None,
                    version=1,
                )

                loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
                self.assertIsNotNone(loaded_key, f"Failed to load key for {name}")

                original_bytes = key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                loaded_bytes = loaded_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                self.assertEqual(
                    original_bytes,
                    loaded_bytes,
                    f"DER-encoded private key mismatch for {name}",
                )
                self.assertEqual(
                    key.public_key(),
                    loaded_key.public_key(),
                    f"Public key mismatch for {name}",
                )



if __name__ == "__main__":
    unittest.main()
