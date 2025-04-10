# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pyasn1.type import univ
from resources.ca_kga_logic import process_kem_recip_info
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_kem_recip_info
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestProcessKEMInfo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server_key = PQKeyFactory.generate_pq_key(algorithm="ml-kem-1024")

        cls.server_cert, _ = build_certificate(private_key=cls.server_key,
                                               ca_key=PQKeyFactory.generate_pq_key("ml-dsa-87"))

        cls.content_encryption_key = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        cls.user_keying_material = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

    def test_process_kem_info_valid(self):
        """
        GIVEN an valid KEM recipient info.
        WHEN processing the KEM recipient info,
        THEN the derived content encryption key is equal to the original content encryption key.
        """
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=self.server_cert,
            cek=self.content_encryption_key,
            ukm=self.user_keying_material,
            wrap_name="aes256-wrap",
            kdf_name="hkdf",
            hash_alg="sha256",
        )


        derived_cek = process_kem_recip_info(kem_recip_info, self.server_cert, self.server_key)
        self.assertEqual(derived_cek, self.content_encryption_key)

    def test_process_kem_info_invalid_kemct(self):
        """
        GIVEN an invalid KEM ciphertext.
        WHEN processing the KEM recipient info,
        THEN an InvalidUnwrap exception is raised.
        """
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=self.server_cert,
            cek=self.content_encryption_key,
            ukm=self.user_keying_material,
            wrap_name="aes256-wrap",
            kdf_name="hkdf",
            hash_alg="sha256",
        )
        kem_recip_info["kemct"] = univ.OctetString(b"invalid_kem_ct")

        with self.assertRaises(Exception) as context:
            process_kem_recip_info(kem_recip_info, self.server_cert, self.server_key)

        # Note: The exception raised may vary depending on whether liboqs or Python is in use.
        self.assertIsInstance(context.exception, (InvalidUnwrap, ValueError))

    def test_process_kem_info_invalid_encrypted_key(self):
        """
        GIVEN an invalid encrypted key.
        WHEN processing the KEM recipient info,
        THEN an InvalidUnwrap exception is raised.
        """
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=self.server_cert,
            cek=self.content_encryption_key,
            ukm=self.user_keying_material,
            wrap_name="aes256-wrap",
            kdf_name="hkdf",
            hash_alg="sha256",
            encrypted_key=univ.OctetString(b"invalid_encrypted_key")
        )
        with self.assertRaises(InvalidUnwrap):
            process_kem_recip_info(kem_recip_info, self.server_cert, self.server_key)

    def test_process_xwing_kem_recip_info(self):
        """
        GIVEN an XWing KEM recipient info.
        WHEN processing the KEM recipient info,
        THEN the derived content encryption key is equal to the original content encryption key.
        """
        client_key = load_private_key_from_file("data/keys/private-key-xwing.pem")
        server_key = load_private_key_from_file("data/keys/private-key-xwing-other.pem")
        server_cert = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing_other.pem"))
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=server_cert,
            cek=self.content_encryption_key,
            ukm=None,
            wrap_name="aes256-wrap",
            kdf_name="hkdf",
            hash_alg="sha256",
            hybrid_key_recip=client_key,
        )

        derived_cek = process_kem_recip_info(kem_recip_info=kem_recip_info,
                                             server_cert=server_cert, private_key=server_key, for_pop=True)
        self.assertEqual(derived_cek, self.content_encryption_key)


if __name__ == "__main__":
    unittest.main()
