import unittest

from pq_logic.combined_factory import CombinedKeyFactory
from resources.exceptions import InvalidKeyData
from resources.keyutils import generate_key, prepare_one_asymmetric_key


class TestValidateKeyExportType(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_names = ["xwing", "ml-dsa-44", "ml-kem-512", "slh-dsa"]

    def test_validate_key_export_type_raw(self):
        """
        GIVEN a key name and the export type "raw".
        WHEN the key export is checked,
        THEN the function should pass without raising an exception.
        """
        key_save_type = "raw"
        for key_name in self.key_names:
            with self.subTest(key_name=key_name):
                key = generate_key(key_name)
                one_asym_key = prepare_one_asymmetric_key(private_key=key, key_save_type=key_save_type)
                private_key_bytes = one_asym_key["privateKey"].asOctets()
                CombinedKeyFactory.validate_key_export_type(
                    private_key=key,  # type: ignore
                    private_key_bytes=private_key_bytes,
                    key_save_type=key_save_type,
                )

    def test_validate_key_export_type_seed(self):
        """
        GIVEN a key name and the export type "seed".
        WHEN the key export is checked,
        THEN the function should pass without raising an exception.
        """
        key_save_type = "seed"
        for key_name in self.key_names:
            with self.subTest(key_name=key_name):
                key = generate_key(key_name)
                one_asym_key = prepare_one_asymmetric_key(private_key=key, key_save_type=key_save_type)
                private_key_bytes = one_asym_key["privateKey"].asOctets()
                CombinedKeyFactory.validate_key_export_type(
                    private_key=key,  # type: ignore
                    private_key_bytes=private_key_bytes,
                    key_save_type=key_save_type,
                )

    def test_validate_key_export_type_seed_and_raw(self):
        """
        GIVEN a key name and the export type "seed_and_raw".
        WHEN the key export is checked,
        THEN the function should pass without raising an exception.
        """
        key_save_type = "seed_and_raw"
        for key_name in self.key_names:
            with self.subTest(key_name=key_name):
                key = generate_key(key_name)
                one_asym_key = prepare_one_asymmetric_key(private_key=key, key_save_type=key_save_type)
                private_key_bytes = one_asym_key["privateKey"].asOctets()
                CombinedKeyFactory.validate_key_export_type(
                    private_key=key,  # type: ignore
                    private_key_bytes=private_key_bytes,
                    key_save_type=key_save_type,
                )

    def test_validate_key_export_type_invalid_seed(self):
        """
        GIVEN a key name and invalid key data.
        WHEN the key export is checked,
        THEN the function should pass without raising an exception.
        """
        for key_save_type in ["raw", "seed", "seed_and_raw"]:
            for key_name in self.key_names:
                with self.subTest(key_export_type=key_save_type):
                    with self.subTest(key_name=key_name):
                        key = generate_key(key_name)
                        one_asym_key = prepare_one_asymmetric_key(private_key=key, key_save_type=key_save_type)
                        private_key_bytes = one_asym_key["privateKey"].asOctets() + b"invalid"
                        with self.assertRaises(InvalidKeyData):
                            CombinedKeyFactory.validate_key_export_type(
                                private_key=key,  # type: ignore
                                private_key_bytes=private_key_bytes,
                                key_save_type=key_save_type,
                            )
