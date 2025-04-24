# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
import tempfile
import os

from resources.keyutils import generate_key, load_private_key_from_file, save_key


class TestLoadKeyFromFile(unittest.TestCase):

    def test_ml_dsa44_unencrypted_save_and_load(self):
        """
        GIVEN an ML-DSA-44 key.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("ml-dsa-44")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path)
            loaded_key = load_private_key_from_file(file_path)
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_ml_dsa44_encrypted_save_and_load(self):
        """
        GIVEN an ML-DSA-44 key and a password.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("ml-dsa-44")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password="ml-dsa-secret")
            loaded_key = load_private_key_from_file(file_path, password="ml-dsa-secret")
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_slh_dsa_sha2_192s_unencrypted_save_and_load(self):
        """
        GIVEN an SLH-DSA-SHA2-192S key.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("slh-dsa-sha2-192s")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path)
            loaded_key = load_private_key_from_file(file_path)
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_slh_dsa_sha2_192s_encrypted_save_and_load(self):
        """
        GIVEN an SLH-DSA-SHA2-192S key and a password.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("slh-dsa-sha2-192s")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password="slh-dsa-secret")
            loaded_key = load_private_key_from_file(file_path, password="slh-dsa-secret")
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_ml_kem512_unencrypted_save_and_load(self):
        """
        GIVEN an ML-KEM-512 key.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("ml-kem-512")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path)
            loaded_key = load_private_key_from_file(file_path)
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_ml_kem512_encrypted_save_and_load(self):
        """
        GIVEN an ML-KEM-512 key and a password.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("ml-kem-512")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password="ml-kem-secret")
            loaded_key = load_private_key_from_file(file_path, password="ml-kem-secret")
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_xwing_unencrypted_save_and_load(self):
        """
        GIVEN an XWING key.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("xwing")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path)
            loaded_key = load_private_key_from_file(file_path)
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_xwing_encrypted_save_and_load(self):
        """
        GIVEN an XWING key and a password.
        WHEN the key is saved and loaded from a file.
        THEN the loaded key is the same as the original key.
        """
        private_key = generate_key("xwing")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password="xwing-secret")
            loaded_key = load_private_key_from_file(file_path, password="xwing-secret")
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

if __name__ == "__main__":
    unittest.main()
