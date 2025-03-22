# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc5280, rfc9481
from resources.ca_kga_logic import process_kari
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_ecc_cms_shared_info, prepare_mqv_user_keying_material
from resources.keyutils import generate_key, load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestProcessKari(unittest.TestCase):
    def setUp(self):
        self.cmp_prot_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ecc_cert_ski.pem"))
        self.ee_private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_process_kari_ecdh(self):
        """
        GIVEN a valid ECDH Key Agreement with AES-256 key wrapping.
        WHEN process_kari is called with the correct key encryption algorithm identifier and keys.
        THEN a derived key of correct length (32 bytes) should be returned, and the wrapping
        algorithm should be AES-256.
        """
        key_enc_alg_id = rfc5280.AlgorithmIdentifier()
        key_enc_alg_id["algorithm"] = rfc9481.id_alg_ESDH
        key_enc_alg_id["parameters"] = encoder.encode(
            prepare_ecc_cms_shared_info(key_wrap_oid=rfc9481.id_aes256_wrap,
                                        entity_u_info=None, supp_pub_info=32)
        )

        derived_key= process_kari(
            key_enc_alg_id, self.ee_private_key, ukm=None, cmp_prot_cert=self.cmp_prot_cert
        )
        self.assertEqual(len(derived_key), 32)

    def test_process_kari_supp_pub_info_size_mismatch(self):
        """
        GIVEN an ECDH Key Agreement with mismatching `supp_pub_info` size.
        WHEN process_kari is called with a `supp_pub_info` size that doesn't match the expected length.
        THEN a ValueError should be raised due to the size mismatch.
        """
        key_enc_alg_id = rfc5280.AlgorithmIdentifier()
        key_enc_alg_id["algorithm"] = rfc9481.id_alg_ESDH
        key_enc_alg_id["parameters"] = encoder.encode(
            prepare_ecc_cms_shared_info(key_wrap_oid=rfc9481.id_aes256_wrap, entity_u_info=None, supp_pub_info=16)
        )
        with self.assertRaises(ValueError):
            process_kari(key_enc_alg_id, self.ee_private_key, ukm=None, cmp_prot_cert=self.cmp_prot_cert)

    def test_process_kari_mqv(self):
        """
        GIVEN an ECDH Key Agreement using MQV (Menezes–Qu–Vanstone) user keying material and
        AES-256 key wrapping.
        WHEN `process_kari` is called with the key encryption algorithm identifier, the endpoint's private key,
        the encoded MQV user keying material, and the CMP protection certificate.
        THEN a derived key of length 32 bytes should be returned, and the key wrapping algorithm should be
        `id_aes256_wrap`.
        """
        key_enc_alg_id = rfc5280.AlgorithmIdentifier()
        key_enc_alg_id["algorithm"] = rfc9481.id_alg_ESDH
        key_enc_alg_id["parameters"] = encoder.encode(
            prepare_ecc_cms_shared_info(key_wrap_oid=rfc9481.id_aes256_wrap,
                                        entity_u_info=None, supp_pub_info=32)
        )

        mqv_ukm = prepare_mqv_user_keying_material(generate_key("ec"))
        derived_key = process_kari(
            key_enc_alg_id, self.ee_private_key, ukm=encoder.encode(mqv_ukm), cmp_prot_cert=self.cmp_prot_cert
        )
        self.assertEqual(len(derived_key), 32)


if __name__ == "__main__":
    unittest.main()
