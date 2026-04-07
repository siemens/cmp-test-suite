# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from resources.keyutils import generate_key, load_private_key_from_file, save_key

def _to_pkcs8(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def _compare_hybrid_private_keys(private_key, loaded_key) -> bool:
    return _to_pkcs8(private_key.trad_key) == _to_pkcs8(loaded_key.trad_key) and \
              _to_pkcs8(private_key.pq_key) == _to_pkcs8(loaded_key.pq_key)



class TestKeyRoundTrip(unittest.TestCase):
    def test_composite_sig_unencrypted_round_trip(self):
        private_key = generate_key("composite-sig")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password=None)
            loaded_key = load_private_key_from_file(file_path, password=None)
            self.assertTrue(_compare_hybrid_private_keys(private_key, loaded_key))
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_composite_sig_encrypted_round_trip_password(self):
        private_key = generate_key("composite-sig")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password="sig-secret")
            loaded_key = load_private_key_from_file(file_path, password="sig-secret")
            self.assertTrue(_compare_hybrid_private_keys(private_key, loaded_key))
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_composite_kem_unencrypted_round_trip(self):
        private_key = generate_key("composite-kem")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password=None)
            loaded_key = load_private_key_from_file(file_path, password=None)
            self.assertTrue(_compare_hybrid_private_keys(private_key, loaded_key))
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_composite_kem_encrypted_round_trip_password(self):
        private_key = generate_key("composite-kem")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password="kem-secret")
            loaded_key = load_private_key_from_file(file_path, password="kem-secret")
            self.assertTrue(_compare_hybrid_private_keys(private_key, loaded_key))
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)

    def test_chempat_unencrypted_round_trip(self):
        private_key = generate_key("chempat")
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

    def test_chempat_encrypted_round_trip_password(self):
        private_key = generate_key("chempat")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            file_path = tmp.name
        try:
            save_key(private_key, file_path, password="chempat-secret")
            loaded_key = load_private_key_from_file(file_path, password="chempat-secret")
            self.assertEqual(loaded_key.private_bytes_raw(), private_key.private_bytes_raw())
            self.assertEqual(loaded_key.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
        except Exception as e:
            self.fail(f"Exception: {e}")
        finally:
            os.remove(file_path)
