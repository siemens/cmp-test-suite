# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from resources.asn1_structures import PKIMessageTMP
from resources.ca_kga_logic import validate_not_local_key_gen
from resources.ca_ra_utils import build_kga_cmp_response
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key, get_cmp_message_type
from resources.keyutils import load_private_key_from_file, generate_key
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import load_ca_cert_and_key, load_kari_certs


class TestBuildKGAForKari(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Load CA certificate and key.
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        # Load KGA certificate and key.
        cls.kga_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ra_kga_cert_ecdsa.pem"))
        cls.kga_cert_chain = [cls.kga_cert, cls.ca_cert]
        cls.kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        # Load KARI certificates and keys.
        cls.kari_data = load_kari_certs()
        cls.new_key = generate_key("rsa")

    def _build_kga_request(self, key_type: str = "x25519") -> PKIMessageTMP:
        """Build a KGA request for the tests."""

        ir = build_ir_from_key(self.new_key,
                               pvno=3,
                               for_kga=True,
                               exclude_fields="sender,senderKID"
                               )

        ir = protect_pkimessage(
            ir,
            protection="dh",
            private_key=self.kari_data[f"{key_type}_key"],
            cert=self.kari_data[f"{key_type}_cert"],
            shared_secret=os.urandom(32),
        )
        return ir

    def test_build_kga_response_ecc(self):
        """
        GIVEN a KGA request with an ECC certificate and key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        ir = self._build_kga_request("ecc")

        response, _ = build_kga_cmp_response(
            request=ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            kga_cert_chain=self.kga_cert_chain,
            kga_key=self.kga_key,
            ec_priv_key=self.kga_key,
            cmp_protection_cert=self.kga_cert_chain[0],
            **self.kari_data
        )

        response["extraCerts"].append(self.kari_data["ecc_cert"])

        out_key = validate_not_local_key_gen(response, ee_key=self.kari_data["ecc_key"], expected_type="kari")
        out = get_cmp_message_type(response)

        self.assertEqual(out, "ip", response.prettyPrint())
        self.assertIsInstance(out_key, RSAPrivateKey)

    def test_build_kga_response_x25519(self):
        """
        GIVEN a KGA request with a x25519 certificate and key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        ir = self._build_kga_request("x25519")

        response, _ = build_kga_cmp_response(
            request=ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            kga_cert_chain=self.kga_cert_chain,
            kga_key=self.kga_key,
            ec_priv_key=self.kga_key,
            cmp_protection_cert=self.kga_cert_chain[0],
            **self.kari_data
        )

        response["extraCerts"].append(self.kari_data["x25519_cert"])

        out_key = validate_not_local_key_gen(response, ee_key=self.kari_data["x25519_key"], expected_type="kari")
        out = get_cmp_message_type(response)

        self.assertEqual(out, "ip", response.prettyPrint())
        self.assertIsInstance(out_key, RSAPrivateKey)

    def test_build_kga_response_x448(self):
        """
        GIVEN a KGA request with a x448 certificate and key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        ir = self._build_kga_request("x448")

        response, _ = build_kga_cmp_response(
            request=ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            kga_cert_chain=self.kga_cert_chain,
            kga_key=self.kga_key,
            ec_priv_key=self.kga_key,
            cmp_protection_cert=self.kga_cert_chain[0],
            **self.kari_data
        )

        response["extraCerts"].append(self.kari_data["x448_cert"])

        out_key = validate_not_local_key_gen(response, ee_key=self.kari_data["x448_key"], expected_type="kari")
        out = get_cmp_message_type(response)

        self.assertEqual(out, "ip", response.prettyPrint())
        self.assertIsInstance(out_key, RSAPrivateKey)