# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_kem_pki import CompositeMLKEMRSAPrivateKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211
from resources.ca_kga_logic import validate_enveloped_data
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.extra_issuing_logic import prepare_kem_env_data_for_popo
from resources.keyutils import generate_key, load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestValidateEnvDataPOP(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.kem_key: MLKEMPrivateKey = load_private_key_from_file("data/keys/private-key-ml-kem-768.pem")
        cls.x25519 = load_private_key_from_file("data/keys/private-key-x25519.pem", key_type="x25519")
        cls.kem_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/pq_cert_ml_kem_768.pem"))

        cls.enc_key_sender = "CN=Hans the Tester"
        cls.mock_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)


        cls.xwing_key = load_private_key_from_file("data/keys/private-key-xwing.pem")
        cls.xwing_cert = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing.pem"))
        cls.xwing_key_other = load_private_key_from_file("data/keys/private-key-xwing-other.pem")

        cls.private_key_rsa_1 = CompositeMLKEMRSAPrivateKey.generate(pq_name="ml-kem-768", trad_param=2048)
        cls.private_key_rsa_2 = CompositeMLKEMRSAPrivateKey.generate(pq_name="ml-kem-768", trad_param=2048)

        cls.comp_cert = build_certificate(private_key=cls.private_key_rsa_2, signing_key=generate_key("rsa"))[0]

    def test_prepare_kem_env_data_for_popo(self):
        """
        GIVEN parameters for prepare_kem_env_data_for_popo
        WHEN prepare_kem_env_data_for_popo is called,
        THEN the result should be decrypted data.
        """
        popo_structure = prepare_kem_env_data_for_popo(
            ca_cert=self.kem_cert,
            data=b"AAAAAAAAA",
            client_key=self.xwing_key,
            rid_sender="Null-DN",
            cert_req_id=0,
            enc_key_sender=self.enc_key_sender,
            key_encipherment=True,
        )

        # To simulate, send over the wire, because ori uses ANS.1 Any.
        der_data = encoder.encode(popo_structure)
        decoded, _ = decoder.decode(der_data, rfc4211.ProofOfPossession())
        env_data = decoded["keyEncipherment"]["encryptedKey"]

        secure_data = validate_enveloped_data(env_data=env_data, for_pop=True, ee_key=self.kem_key)
        self.assertEqual(secure_data, b"AAAAAAAAA")

    def test_prepare_env_data_with_xwing(self):
        """
        GIVEN a XWingPrivateKey and a certificate
        WHEN prepare_kem_env_data_for_popo is called,
        THEN the result should be decrypted data.
        """
        popo_structure = prepare_kem_env_data_for_popo(
            ca_cert=self.xwing_cert,
            data=b"AAAAAAAAA",
            client_key=self.mock_key,
            rid_sender="Null-DN",
            cert_req_id=0,
            enc_key_sender=self.enc_key_sender,
            key_encipherment=True,
            hybrid_key_recip=self.xwing_key_other,
        )

        # To simulate, send over the wire, because ori uses ANS.1 Any.
        der_data = encoder.encode(popo_structure)
        decoded, _ = decoder.decode(der_data, rfc4211.ProofOfPossession())
        env_data = decoded["keyEncipherment"]["encryptedKey"]

        secure_data = validate_enveloped_data(env_data=env_data, for_pop=True, ee_key=self.xwing_key)
        self.assertEqual(secure_data, b"AAAAAAAAA")


    def test_prepare_env_data_with_composite_kem(self):
        """
        GIVEN a CompositeMLKEMRSAPrivateKey and a certificate
        WHEN prepare_kem_env_data_for_popo is called,
        THEN the result should be decrypted data.
        """
        popo_structure = prepare_kem_env_data_for_popo(
            ca_cert=self.comp_cert,
            data=b"AAAAAAAAA",
            client_key=self.mock_key,
            rid_sender="Null-DN",
            cert_req_id=0,
            cek=B"A" * 32,
            enc_key_sender="CN=Null-DN",
            key_encipherment=True,
            hybrid_key_recip=self.private_key_rsa_1,
        )

        der_data = encoder.encode(popo_structure)
        decoded, _ = decoder.decode(der_data, rfc4211.ProofOfPossession())
        env_data = decoded["keyEncipherment"]["encryptedKey"]

        secure_data = validate_enveloped_data(env_data=env_data, for_pop=True, ee_key=self.private_key_rsa_2)
        self.assertEqual(secure_data, b"AAAAAAAAA")
