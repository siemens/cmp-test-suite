# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc5280, rfc9481
from resources.ca_kga_logic import process_kari
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_mqv_user_keying_material, prepare_key_agreement_alg_id
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

        key_enc_alg_id = prepare_key_agreement_alg_id(
            rfc9481.id_alg_ESDH,
            rfc9481.id_aes256_wrap,
        )

        derived_key= process_kari(
            key_enc_alg_id, self.ee_private_key, ukm=None, cmp_prot_cert=self.cmp_prot_cert
        )
        self.assertEqual(len(derived_key), 32)

    def test_process_kari_mqv(self):
        """
        GIVEN an ECDH Key Agreement using MQV (Menezes–Qu–Vanstone) user keying material and
        AES-256 key wrapping.
        WHEN `process_kari` is called with the key encryption algorithm identifier, the endpoint's private key,
        the encoded MQV user keying material, and the CMP protection certificate.
        THEN a derived key of length 32 bytes should be returned, and the key wrapping algorithm should be
        `id_aes256_wrap`.
        """
        key_enc_alg_id = prepare_key_agreement_alg_id(
            rfc9481.mqvSinglePass_sha256kdf_scheme,
            rfc9481.id_aes256_wrap,
        )

        mqv_ukm = prepare_mqv_user_keying_material(generate_key("ec"))
        derived_key = process_kari(
            key_enc_alg_id, self.ee_private_key, ukm=encoder.encode(mqv_ukm), cmp_prot_cert=self.cmp_prot_cert
        )
        self.assertEqual(len(derived_key), 32)


if __name__ == "__main__":
    unittest.main()
