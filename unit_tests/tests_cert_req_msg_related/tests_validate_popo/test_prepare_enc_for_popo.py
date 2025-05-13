# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc4211

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.ca_kga_logic import validate_enveloped_data
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_enc_key_for_popo, prepare_recipient_identifier
from resources.extra_issuing_logic import prepare_enc_key_with_id
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import patch_sender_and_sender_kid
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPrepareEncKeyForPOPO(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")

        cls.ca_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

        cls.client_cert, cls.client_key = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem")
        ), load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_prepare_enc_key(self):
        """
        GIVEN a private key
        WHEN the key is prepared for POPO,
        THEN the key should be prepared for POPO
        """
        enc_key_with_id = prepare_enc_key_with_id(
            self.key,
            "CN=Hans the Tester",
        )
        rid = prepare_recipient_identifier(
            cert=self.ca_cert,
        )
        popo = prepare_enc_key_for_popo(
            enc_key_with_id=enc_key_with_id,
            rid=rid,
            ca_cert=self.ca_cert,
        )
        der_data = try_encode_pyasn1(popo)
        dec_popo, rest = try_decode_pyasn1(der_data, rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")

    def test_prepare_valid_enc_key_popo(self):
        """
        GIVEN a valid private key
        WHEN the key is prepared for POPO,
        THEN the key should be prepared for POPO
        """
        enc_key_with_id = prepare_enc_key_with_id(
            self.key,
            "CN=Hans the Tester",
        )
        # The recipient identifier is the client certificate,
        # because it MUST be the RID associated with the CMP-protection certificate.
        rid = prepare_recipient_identifier(
            cert=self.client_cert,
        )
        # So it must be parsed manually.
        popo = prepare_enc_key_for_popo(
            enc_key_with_id=enc_key_with_id,
            rid=rid,
            ca_cert=self.ca_cert,
            for_agreement=False,
        )

        env_data = popo["keyEncipherment"]["encryptedKey"]

        pki_message = PKIMessageTMP()
        pki_message["extraCerts"].append(self.client_cert)
        pki_message = patch_sender_and_sender_kid(do_patch=True,
                                                  pki_message=pki_message,
                                                  cert=self.client_cert)

        raw_data = validate_enveloped_data(
            env_data=env_data,
            pki_message=pki_message,
            ee_key=self.ca_key,
            expected_raw_data=True,
            cmp_protection_cert=self.client_cert
        )

        der_data = try_encode_pyasn1(enc_key_with_id)
        self.assertTrue(raw_data, der_data)
