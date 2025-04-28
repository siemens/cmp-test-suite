import unittest

from pq_logic.combined_factory import CombinedKeyFactory
from resources.exceptions import InvalidKeyData, MissMatchingKey
from resources.keyutils import load_private_key_from_file, prepare_one_asymmetric_key


class TestNegPrepareOneAsymKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.xwing = load_private_key_from_file("data/keys/private-key-xwing-seed.pem")
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.keys = {"RSA": cls.rsa_key, "X-Wing": cls.xwing, "MLDSA": cls.mldsa_key}

    def test_missmatching_pub_key(self):
        """
        GIVEN a private key and a public key that do not match.
        WHEN calling prepare_one_asymmetric_key and the structure is validated,
        THEN should a MissMatchingKey exception be raised.
        """
        for name, key in self.keys.items():
            with self.subTest(key_type=name):
                one_asym_key = prepare_one_asymmetric_key(private_key=key, missmatched_key=True)
                with self.assertRaises(MissMatchingKey):
                    CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key)

    def test_unknown_version(self):
        """
        GIVEN a private key and an unknown version.
        WHEN calling prepare_one_asymmetric_key and the structure is validated,
        THEN should an InvalidKeyData exception be raised.
        """
        for name, key in self.keys.items():
            with self.subTest(key_type=name):
                one_asym_key = prepare_one_asymmetric_key(private_key=key, version=99)
                self.assertEqual(int(one_asym_key["version"]), 99)
                with self.assertRaises(InvalidKeyData) as context:
                    CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key)
                self.assertIn("Invalid `OneAsymmetricKey` version", str(context.exception.message))

    def test_invalid_public_key(self):
        """
        GIVEN a private key and a public key that is not valid.
        WHEN calling prepare_one_asymmetric_key and the structure is validated,
        THEN should an InvalidKeyData exception be raised.
        """
        for name, key in self.keys.items():
            with self.subTest(key_type=name):
                one_asym_key = prepare_one_asymmetric_key(private_key=key, invalid_pub_key=True)
                with self.assertRaises(InvalidKeyData) as context:
                    CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key)
