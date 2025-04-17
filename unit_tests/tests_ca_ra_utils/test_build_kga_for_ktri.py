# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.ca_kga_logic import validate_not_local_key_gen
from resources.ca_ra_utils import build_kga_cmp_response
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import load_ca_cert_and_key, load_env_data_certs


class TestBuildKGAForKTRI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Load CA certificate and key.
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        # Load KGA certificate and key.
        cls.kga_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ra_kga_cert_ecdsa.pem"))
        cls.kga_cert_chain = [cls.kga_cert, cls.ca_cert]
        cls.kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        # Load KARI certificates and keys.
        cls.kga_data = load_env_data_certs()
        cls.new_key = generate_key("x448")
        cls.cmp_prot_cert = cls.kga_data["encr_rsa_cert"]
        cls.cmp_prot_key = cls.kga_data["encr_rsa_key"]

    def _build_kga_request(self) -> PKIMessageTMP:
        """Build a KGA request for the tests."""
        ir = build_ir_from_key(self.new_key,
                               pvno=3,
                               for_kga=True,
                               exclude_fields="sender,senderKID"
                               )

        ir = protect_pkimessage(
            ir,
            protection="signature",
            private_key=self.cmp_prot_key,
            cert=self.cmp_prot_cert,
        )
        return ir

    def test_build_kga_response(self):
        """
        GIVEN a KGA request with an RSA certificate and key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        ir = self._build_kga_request()

        response, _ = build_kga_cmp_response(
            request=ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            kga_cert_chain=self.kga_cert_chain,
            kga_key=self.kga_key,
            ec_priv_key=self.kga_key,
            cmp_protection_cert=self.ca_cert,
            **self.kga_cert
        )
        response["extraCerts"].append(self.ca_cert)

        validate_not_local_key_gen(response, ee_key=self.cmp_prot_key, expected_type="ktri")
