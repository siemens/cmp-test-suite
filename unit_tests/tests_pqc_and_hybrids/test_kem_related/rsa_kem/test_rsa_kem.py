# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


from pq_logic.kem_mechanism import RSAKem
from pyasn1_alt_modules.rfc9481 import id_aes128_wrap
from resources import keyutils
from resources.cryptoutils import compute_aes_cbc, compute_ansi_x9_63_kdf


def _load_b64(path: str):
    """

    :param path:
    :return:
    """
    with open(path, "r") as file:
        base64_string = file.read().strip()
    return base64.b64decode(base64_string)

import base64
import unittest

from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc5990


def _load_b64(path: str):
    """
    Load and decode a Base64-encoded file.
    """
    with open(path, "r") as file:
        base64_string = file.read().strip()
    return base64.b64decode(base64_string)


def _prepare_algorithm_identifier():
    """Prepares the RSA-KEM structure AlgorithmIdentifier."""
    rsa_kem_parameters = rfc5990.RsaKemParameters()
    rsa_kem_parameters['kdf']['algorithm'] = rfc5990.id_kdf_kdf3
    rsa_kem_parameters['kdf']['hashFunction']['algorithm'] = rfc5990.id_sha256
    rsa_kem_parameters['kdf']['keyLength'] = 16  # AES-128 key length
    rsa_kem_parameters['wrapAlgorithm'] = id_aes128_wrap

    generic_hybrid_params = rfc5990.GenericHybridParameters()
    generic_hybrid_params['kem']['algorithm'] = rfc5990.id_kem_rsa
    generic_hybrid_params['kem']['parameters'] = rsa_kem_parameters

    alg_id = rfc5990.AlgorithmIdentifier()
    alg_id['algorithm'] = rfc5990.id_rsa_kem
    alg_id['parameters'] = generic_hybrid_params

    return alg_id


class TestRSAKEM(unittest.TestCase):

    def setUp(self):
        self.kid = bytes.fromhex("9eeb67c9b95a74d44d2f16396680e801b5cba49c")
        self.ss = bytes.fromhex("3cf82ec41b54ed4d37402bbd8f805a52")
        self.ciphertext_hex = bytes.fromhex(
            "9c126102a5c1c0354672a3c2f19fc9ddea988f815e1da812c7bd4f8eb082bdd1"
            "4f85a7f7c2f1af11d5333e0d6bcb375bf855f208da72ba27e6fb0655f2825aa6"
            "2b93b1f9bbd3491fed58f0380fa0de36430e3a144d569600bd362609be5b9481"
            "0875990b614e406fa6dff500043cbca95968faba61f795096a7fb3687a51078c"
            "4ca2cb663366b0bea0cd9cccac72a25f3f4ed03deb68b4453bba44b943f4367b"
            "67d6cd10c8ace53f545aac50968fc3c6ecc80f3224b64e37038504e2d2c0e2b2"
            "9d45e46c62826d96331360e4c17ea3ef89a9efc5fac99eda830e81450b6534dc"
            "0bdf042b8f3b706649c631fe51fc2445cc8d447203ec2f41f79cdfea16de1ce6"
        )
        self.private_key = keyutils.load_private_key_from_file("test_rsa_private_key.pem", password=None)
        self.public_key = keyutils.load_public_key_from_file("test_rsa_public_key.pem")
        self.secret = 0x123456  # Example integer value for the shared secret

    def test_rsa_kem_op(self):
        """
        GIVEN an RSA private key.
        WHEN the encapsulation and decapsulation operations are performed,
        THEN the shared secret is correctly computed.
        """
        kem_method = RSAKem()
        pub_num = self.public_key.public_numbers()
        e, n = pub_num.e, pub_num.n
        ct = pow(self.secret, e, n)
        self.assertEqual(self.ciphertext_hex, ct.to_bytes((ct.bit_length() + 7) // 8, byteorder='big'))

        ss = kem_method.decaps(self.private_key, ct.to_bytes((ct.bit_length() + 7) // 8))
        self.assertEqual(self.ss, ss)

        alg_id_encoded = encoder.encode(_prepare_algorithm_identifier())
        kek = compute_ansi_x9_63_kdf(shared_secret=ss, key_length=16, hash_algorithm=hashes.SHA256(), der_other_info=alg_id_encoded)

        expected_kek = bytes.fromhex("e6dc9d62ff2b469bef604c617b018718")
        self.assertEqual(kek, expected_kek)

        content_encryption_key = bytes.fromhex("77f2a84640304be7bd42670a84a1258b")
        iv = bytes.fromhex("480ccafebabefacedbaddecaf8887781")
        ciphertext = bytes.fromhex("c6ca65db7bdd76b0f37e2fab6264b66d")
        decrypted_content = compute_aes_cbc(key=content_encryption_key,
                                            iv=iv, data=ciphertext,
                                            decrypt=True)

        padded_plaintext = bytes.fromhex("48656c6c6f2c20776f726c6421030303")
        self.assertEqual(decrypted_content, padded_plaintext.rstrip(b"\x03"))

        expected_plaintext = "Hello, world!"
        self.assertEqual(decrypted_content.rstrip(b"\x03").decode('utf-8'), expected_plaintext)
