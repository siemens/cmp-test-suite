# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Tuple, List

from pyasn1_alt_modules import rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_cp_cmp_message, build_pki_conf_from_cert_conf
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.cmputils import build_cr_from_key, build_cert_conf_from_resp
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestBuildPkiConfFromCertConf(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")

    def _build_request(self):
        """Helper method to build a new PKIMessage request."""
        return build_cr_from_key(
            signing_key=self.comp_key,
            pvno=2,
        )

    def build_ca_response(self, ca_key, ca_cert) -> Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]:
        """Helper method to build a new CA response."""
        pki_message = self._build_request()
        response, certs = build_cp_cmp_message(
            request=pki_message,
            ca_key=ca_key,
            ca_cert=ca_cert,
            cert_index=0,
        )
        response["extraCerts"].append(ca_cert)
        return response, certs

    def test_valid_ml_dsa_cert_conf(self):
        """
        GIVEN a valid certificate confirmation.
        WHEN building a pkiConf from the certificate confirmation,
        THEN the pkiConf is built correctly.
        """

        ca_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

        response, certs = self.build_ca_response(ca_key, ca_cert)
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            pvno=2,
        )
        pki_conf = build_pki_conf_from_cert_conf(
            request=cert_conf,
            issued_certs=certs,
            hash_alg="sha512"
        )
        self.assertEqual(pki_conf["body"].getName(), "pkiconf")

    def test_valid_slh_dsa_cert_conf(self):
        """
        GIVEN a valid ML-DSA certificate confirmation.
        WHEN building a pkiConf from the certificate confirmation,
        THEN the pkiConf is built correctly.
        """

        ca_key = load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-256f-seed.pem")
        ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_slh_dsa_sha2_256f.pem"))

        response, certs = self.build_ca_response(ca_key, ca_cert)
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            pvno=2,
        )
        pki_conf = build_pki_conf_from_cert_conf(
            request=cert_conf,
            issued_certs=certs,
            hash_alg="sha512"
        )
        self.assertEqual(pki_conf["body"].getName(), "pkiconf")


    def test_valid_slh_dsa_sha2_192f_cert_conf(self):
        """
        GIVEN a valid SLH-DSA certificate confirmation.
        WHEN building a pkiConf from the certificate confirmation,
        THEN the pkiConf is built correctly.
        """

        ca_key = load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-192f-seed.pem")

        ca_cert, _ = build_certificate(
            private_key=ca_key,
            common_name="CN=Test Root CA SLH DSA SHA2 192f",
        )

        response, certs = self.build_ca_response(ca_key, ca_cert)
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            pvno=2,
        )
        pki_conf = build_pki_conf_from_cert_conf(
            request=cert_conf,
            issued_certs=certs,
            hash_alg="sha512"
        )
        self.assertEqual(pki_conf["body"].getName(), "pkiconf")


    def test_valid_slh_dsa_sha2_128f_cert_conf(self):
        """
        GIVEN a valid SLH-DSA certificate confirmation.
        WHEN building a pkiConf from the certificate confirmation,
        THEN the pkiConf is built correctly.
        """

        ca_key = load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-128f-seed.pem")

        ca_cert, _ = build_certificate(
            private_key=ca_key,
            common_name="CN=Test Root CA SLH DSA SHA2 128f",
        )

        response, certs = self.build_ca_response(ca_key, ca_cert)
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            pvno=2,
        )
        pki_conf = build_pki_conf_from_cert_conf(
            request=cert_conf,
            issued_certs=certs,
            hash_alg="sha256"
        )
        self.assertEqual(pki_conf["body"].getName(), "pkiconf")