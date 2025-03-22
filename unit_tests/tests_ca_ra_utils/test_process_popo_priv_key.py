# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480, rfc4211

from resources.ca_ra_utils import process_popo_priv_key
from resources.certutils import parse_certificate
from resources.cmputils import prepare_popo, prepare_popo_challenge_for_non_signing_key, prepare_cert_req_msg, \
    prepare_cert_request
from resources.exceptions import BadRequest, BadPOP
from resources.extra_issuing_logic import prepare_key_agreement_popo
from resources.keyutils import generate_key, load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestProcessPopoPrivKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.xwing_key = load_private_key_from_file("data/keys/private-key-xwing.pem")
        cls.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ec_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ecc_cert_ski.pem"))

    def test_process_popo_priv_key_xwing(self):
        """
        GIVEN a certificate request message with an X-Wing private key
        WHEN processing the POPO private key,
        THEN the private key is accepted for `keyEncipherment`.
        """
        popo = prepare_popo_challenge_for_non_signing_key(
            use_encr_cert=True,
            use_key_enc=True,
        )
        cert_req_msg = prepare_cert_req_msg(
            common_name="CN=Hans the Tester",
            popo_structure=popo,
            private_key=generate_key("xwing"),
        )
        process_popo_priv_key(
            cert_req_msg=cert_req_msg,
            ca_key=self.ca_key,
        )

    def test_process_popo_priv_key_ec(self):
        """
        GIVEN a certificate request message with an EC private key
        WHEN processing the POPO private key,
        THEN the private key is accepted for `KeyAgreement`.
        """
        popo = prepare_popo_challenge_for_non_signing_key(
            use_encr_cert=True,
            use_key_enc=False,
        )
        cert_req_msg = prepare_cert_req_msg(
            common_name="CN=Hans the Tester",
            popo_structure=popo,
            private_key=self.ec_key,
        )
        process_popo_priv_key(
            cert_req_msg=cert_req_msg,
            ca_key=self.ca_key,
        )

    def test_invalid_xwing_and_keyEnc(self):
        """
        GIVEN a certificate request message with an X-Wing private key
        WHEN processing the POPO private key,
        THEN the private key is not accepted for `keyEncipherment`.
        """
        popo = prepare_popo_challenge_for_non_signing_key(
            use_encr_cert=True,
            use_key_enc=False,
        )
        cert_req_msg = prepare_cert_req_msg(
            common_name="CN=Hans the Tester",
            popo_structure=popo,
            private_key=generate_key("xwing"),
        )
        with self.assertRaises(BadRequest):
            process_popo_priv_key(
                cert_req_msg=cert_req_msg,
                ca_key=self.ca_key,
            )

    def test_invalid_ec_and_keyEnc(self):
        """
        GIVEN a certificate request message with an EC private key
        WHEN processing the POPO private key,
        THEN the private key is not accepted for `keyEncipherment`.
        """
        popo = prepare_popo_challenge_for_non_signing_key(
            use_encr_cert=True,
            use_key_enc=True,
        )
        cert_req_msg = prepare_cert_req_msg(
            common_name="CN=Hans the Tester",
            popo_structure=popo,
            private_key=generate_key("ecdsa"),
        )
        with self.assertRaises(BadRequest):
            process_popo_priv_key(
                cert_req_msg=cert_req_msg,
                ca_key=self.ca_key,
            )


    def test_valid_agreeMac(self):
        """
        GIVEN a certificate request message with an EC private key
        and `agreeMAC` as POPO method.
        WHEN processing the POPO private key,
        THEN the Proof-of-Possession is successfully accepted.
        """

        cert_request = prepare_cert_request(
            common_name="CN=Hans the Tester",
            key=self.ec_key,
        )
        popo = prepare_key_agreement_popo(
            client_key=self.ec_key,
            ca_cert=self.ec_cert,
            cert_request=cert_request,
        )
        cert_req_msg = rfc4211.CertReqMsg()
        cert_req_msg['certReq'] = cert_request
        cert_req_msg['popo'] = popo

        process_popo_priv_key(
            cert_req_msg=cert_req_msg,
            ca_key=self.ec_key,
        )

    def test_invalid_agreeMac(self):
        """
        GIVEN a certificate request message with an EC private key
        and `agreeMAC` as POPO method.
        WHEN processing the POPO private key,
        THEN the Proof-of-Possession is not accepted.
        """
        cert_request = prepare_cert_request(
            common_name="CN=Hans the Tester",
            key=self.ec_key,
        )
        popo = prepare_key_agreement_popo(
            client_key=self.ec_key,
            ca_cert=self.ec_cert,
            cert_request=cert_request,
            bad_pop=True,
        )
        cert_req_msg = rfc4211.CertReqMsg()
        cert_req_msg['certReq'] = cert_request
        cert_req_msg['popo'] = popo
        with self.assertRaises(BadPOP):
            process_popo_priv_key(
                cert_req_msg=cert_req_msg,
                ca_key=self.ec_key,
            )


