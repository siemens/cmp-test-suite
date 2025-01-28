# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc9480

from resources.ca_ra_utils import build_cp_cmp_message
from resources.certutils import parse_certificate
from resources.cmputils import parse_csr, build_cr_from_key, build_cr_from_csr, prepare_cert_request, \
    prepare_cert_req_msg
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestBuildCpCmpMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        cls.mldsa_key2 = load_private_key_from_file("data/keys/private-key-ml-dsa-65.pem")
        cls.mldsa_key3 = load_private_key_from_file("data/keys/private-key-ml-dsa-87.pem")

    def test_build_cp_cmp_message(self):
        """
        GIVEN a Composite Signature Private Key, build a `cr` message.
        WHEN the `cp` response message is built.
        THEN the CMP message is built correctly.
        """
        pki_message = build_cr_from_key(
            signing_key=self.comp_key
        )

        response, certs = build_cp_cmp_message(
            request=pki_message,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            cert_index=0,
        )

        self.assertEqual(len(certs), 1)

        der_data = encoder.encode(pki_message)
        decoded_response, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")


    def test_build_cp_cmp_message_2(self):
        """
        GIVEN Certificate Request Messages and `cr` Message.
        WHEN the `cp` response message is built.
        THEN the CMP message is built correctly.
        """
        cert_req_msg1 = prepare_cert_req_msg(
            private_key=self.mldsa_key,
            common_name="CN=Test ML DSA 44",
        )
        cert_req_msg2 = prepare_cert_req_msg(
            private_key=self.mldsa_key2,
            common_name="CN=Test ML DSA 65",
        )
        cert_req_msg3 = prepare_cert_req_msg(
            private_key=self.mldsa_key3,
            common_name="CN=Test ML DSA 87",
        )

        cert_req_msgs = [cert_req_msg1, cert_req_msg2, cert_req_msg3]
        pki_message = build_cr_from_key(
            signing_key=None,
            cert_req_msg=cert_req_msgs,
        )

        response, certs = build_cp_cmp_message(
            request=pki_message,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
        )

        self.assertEqual(len(certs), 3)

        der_data = encoder.encode(pki_message)
        decoded_response, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
