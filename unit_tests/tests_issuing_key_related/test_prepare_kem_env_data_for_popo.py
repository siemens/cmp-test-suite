# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211

from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.xwing import XWingPrivateKey
from resources.certutils import parse_certificate
from resources.extra_issuing_logic import prepare_enc_key_with_id, prepare_kem_env_data_for_popo
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestPrepareKemEnvDataForPopo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kem_key: MLKEMPrivateKey = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")
        cls.x25519 = load_private_key_from_file("data/keys/private-key-x25519.pem")
        cls.kem_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_cert_ml_kem_768.pem"))
        cls.xwing_key = XWingPrivateKey(pq_key=cls.kem_key, trad_key=cls.x25519)
        cls.enc_key_sender = "CN=Hans the Tester"

    def test_prepare_kem_env_data_for_popo(self):
        """
        GIVEN a KEM certificate, a KEM private key, a recipient identifier, and an encryption key.
        WHEN the data is prepared for a proof of possession,
        THEN should the data be correctly encoded and decoded.
        """
        popo_structure = prepare_kem_env_data_for_popo(
            ca_cert=self.kem_cert,
            client_key=self.xwing_key,
            rid_sender="Null-DN",
            cert_req_id=0,
            enc_key_sender=self.enc_key_sender,
        )

        der_data = encoder.encode(popo_structure)
        popo_structure2, rest = decoder.decode(der_data, rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")

    def test_prepare_kem_env_data_with_data(self):
        """
        GIVEN a KEM certificate, a KEM private key, a recipient identifier, an encryption key, and data.
        WHEN the data is prepared for a proof of possession,
        THEN should the data be correctly encoded and decoded.
        """
        data = prepare_enc_key_with_id(private_key=self.xwing_key, sender=self.enc_key_sender, key_save_type="raw")
        popo_structure = prepare_kem_env_data_for_popo(
            ca_cert=self.kem_cert,
            client_key=self.xwing_key,
            rid_sender="Null-DN",
            data=data,
            cert_req_id=0,
            enc_key_sender=self.enc_key_sender,
        )

        der_data = encoder.encode(popo_structure)
        popo_structure2, rest = decoder.decode(der_data, rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")
