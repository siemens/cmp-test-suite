# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import sys
import unittest

from resources.keyutils import load_private_key_from_file

sys.path.append("./resources")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5652
from resources.ca_kga_logic import compute_key_transport_mechanism
from resources.protectionutils import get_rsa_oaep_padding


class TestRSAOAEPFunctions(unittest.TestCase):
    def setUp(self):
        self.ee_private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

        self.enc_content_key = b"\xaa" * 256
        self.oaep_params = rfc4055.RSAES_OAEP_params()
        self.oaep_params["hashFunc"]["algorithm"] = rfc4055.id_sha384
        self.oaep_params["maskGenFunc"]["algorithm"] = rfc4055.id_mgf1
        self.oaep_params["maskGenFunc"]["parameters"] = encoder.encode(rfc4055.id_sha256)

        self.key_enc_alg_oaep = rfc5652.KeyEncryptionAlgorithmIdentifier()
        self.key_enc_alg_oaep["algorithm"] = rfc4055.id_RSAES_OAEP
        self.key_enc_alg_oaep["parameters"] = encoder.encode(self.oaep_params)

    def test_get_rsa_oaep_padding(self):
        """
        GIVEN OAEP parameters (hash function and MGF1 parameters).
        WHEN get_rsa_oaep_padding is called.
        THEN it should return a properly configured OAEP padding object with the correct hash
        and mask generation functions.
        """
        padding_val = get_rsa_oaep_padding(self.oaep_params)

        self.assertIsInstance(padding_val, padding.OAEP)
        self.assertIsInstance(padding_val.algorithm, hashes.SHA384)
        self.assertIsInstance(padding_val.mgf._algorithm, hashes.SHA256)

    def test_rsa_pkcs1v15_decryption(self):
        """
        GIVEN an RSA private key and ciphertext encrypted using PKCS1v1.5.
        WHEN compute_key_transport_mechanism is called with the PKCS1v1.5-encrypted ciphertext.
        THEN it should successfully decrypt the ciphertext and return the original plaintext.
        """
        plaintext = b"test data"
        ciphertext = self.ee_private_key.public_key().encrypt(plaintext, PKCS1v15())

        key_enc_alg = rfc5652.KeyEncryptionAlgorithmIdentifier()
        key_enc_alg["algorithm"] = rfc4055.rsaEncryption
        key_enc_alg["parameters"] = univ.Null()

        result = compute_key_transport_mechanism(
            ee_private_key=self.ee_private_key, key_enc_alg_id=key_enc_alg, encrypted_key=ciphertext
        )

        self.assertEqual(result, plaintext)

    def test_rsa_oaep_decryption(self):
        """
        GIVEN an RSA private key and ciphertext encrypted using OAEP with SHA-256 and MGF1(SHA-384).
        WHEN compute_key_transport_mechanism is called with the OAEP-encrypted ciphertext.
        THEN it should successfully decrypt the ciphertext and return the original plaintext.
        """
        plaintext = b"test data"
        ciphertext = self.ee_private_key.public_key().encrypt(
            plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA384(), label=None)
        )

        result = compute_key_transport_mechanism(
            ee_private_key=self.ee_private_key, key_enc_alg_id=self.key_enc_alg_oaep, encrypted_key=ciphertext
        )

        self.assertEqual(result, plaintext)


if __name__ == "__main__":
    unittest.main()
