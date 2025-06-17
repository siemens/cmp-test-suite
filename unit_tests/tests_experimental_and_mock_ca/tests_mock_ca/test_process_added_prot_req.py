# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler
from mock_ca.nested_handler import NestedHandler
from pyasn1_alt_modules import rfc9481

from resources.asn1utils import is_bit_set
from resources.certutils import parse_certificate
from resources.cmputils import (
    add_general_info_values,
    build_ir_from_key,
    build_nested_pkimessage,
    parse_pkimessage,
    prepare_orig_pki_message, get_pkistatusinfo, prepare_popo,
)
from resources.exceptions import BadMessageCheck
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage, verify_pkimessage_protection
from resources.utils import display_pki_status_info, load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestProcessAddedProtReq(unittest.TestCase):

    def setUp(self):
        self.key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        self.trusted_dir = "./data/trusted_ras"
        self.ra_key = self.key
        self.ra_cert = parse_certificate(load_and_decode_pem_file("./data/trusted_ras/ra_cms_cert_ecdsa.pem"))
        self.cm = "CN=Hans the Tester"
        self.password = b"SiemensIT"
        self.ca_handler = CAHandler(pre_shared_secret=self.password)

    def test_process_added_prot_req(self):
        """
        GIVEN a request with added protection.
        WHEN the request is processed by the CA handler,
        THEN the response should be a valid IP with PBMAC1 protection.
        """
        ir = build_ir_from_key(
            self.key,
            sender=self.cm,
            common_name=self.cm,
            for_mac=True,
        )
        ir = protect_pkimessage(
            pki_message=ir,
            password=self.password,
            protection="pbmac1",
        )
        nested = build_nested_pkimessage(
            other_messages=ir,
            for_added_protection=True,
        )
        nested = protect_pkimessage(
            pki_message=nested,
            protection="signature",
            cert=self.ra_cert,
            private_key=self.ra_key,
        )

        response = self.ca_handler.process_normal_request(nested)

        self.assertEqual(response["body"].getName(), "ip", display_pki_status_info(response))
        self.assertEqual(response["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)
        verify_pkimessage_protection(pki_message=response, password=self.password)

    def test_process_added_prot_req_ra_verified(self):
        """
        GIVEN a request with added protection and RA verified.
        WHEN the request is processed by the CA handler,
        THEN the response should be a Valid IP with PBMAC1 protection, with
        the failInfo badPOP set.
        """
        popo = prepare_popo(
            ra_verified=True
        )
        ir = build_ir_from_key(
            self.key,
            common_name=self.cm,
            popo=popo,
            for_mac=True,
            sender=self.cm,
        )
        ir = protect_pkimessage(
            pki_message=ir,
            password=self.password,
            protection="pbmac1",
        )
        nested = build_nested_pkimessage(
            other_messages=ir,
            for_added_protection=True,
        )
        nested = protect_pkimessage(
            pki_message=nested,
            protection="signature",
            cert=self.ra_cert,
            private_key=self.ra_key,
        )

        response = self.ca_handler.process_normal_request(nested)
        self.assertIsNotNone(response)

        self.assertEqual(response["body"].getName(), "ip")
        self.assertEqual(response["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)
        verify_pkimessage_protection(pki_message=response, password=self.password)
        status = get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "rejection", display_pki_status_info(response))
        result = is_bit_set(
            status["failInfo"],"notAuthorized", exclusive=True
        )
        self.assertTrue(result, f"The failInfo notAuthorized is not set in the response. {display_pki_status_info(response)}")

    def test_nested_handler(self):
        """
        GIVEN a request with added protection.
        WHEN the request is processed by the NestedHandler,
        THEN the response should be a valid IP with PBMAC1 protection.
        """
        nested_handler = NestedHandler(
            cert_req_handler=self.ca_handler.cert_req_handler,
            cert_conf_handler=self.ca_handler.cert_conf_handler,
            allow_inner_unprotected=True,
        )

        ir = build_ir_from_key(
            self.key,
            common_name=self.cm,
            ra_verified=True,
            for_mac=True,
            sender=self.cm,
        )
        ir = protect_pkimessage(
            pki_message=ir,
            password=self.password,
            protection="pbmac1",
        )
        nested = build_nested_pkimessage(
            other_messages=ir,
            for_added_protection=True,
        )

        nested = protect_pkimessage(
            pki_message=nested,
            protection="signature",
            cert=self.ra_cert,
            private_key=self.ra_key,
        )

        response = nested_handler.process_nested_request(
            request=nested, prot_handler=self.ca_handler.protection_handler
        )
        self.assertEqual(response["body"].getName(), "ip", display_pki_status_info(response))
        self.assertEqual(response["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)
        verify_pkimessage_protection(pki_message=response, password=self.password)

    def test_invalid_orig_message(self):
        """
        GIVEN an invalid original message.
        WHEN the message is validated,
        THEN must the message be rejected.
        """
        ir = build_ir_from_key(
            self.key,
            common_name=self.cm,
            ra_verified=True,
            for_mac=True,
            sender=self.cm,
        )

        der_data = try_encode_pyasn1(ir)
        ir2 = parse_pkimessage(der_data)
        prot_ir = protect_pkimessage(
            pki_message=ir2,
            password=self.password,
            protection="pbmac1",
        )

        bad_ir = protect_pkimessage(
            pki_message=ir,
            password=self.password,
            protection="pbmac1",
            bad_message_check=True,
        )

        nested = build_nested_pkimessage(
            other_messages=prot_ir,
            for_added_protection=True,
        )

        orig_msg = prepare_orig_pki_message(bad_ir)
        nested = add_general_info_values(nested, orig_msg)
        self.assertEqual(len(nested["header"]["generalInfo"]), 1)

        nested = protect_pkimessage(
            pki_message=nested,
            protection="signature",
            cert=self.ra_cert,
            private_key=self.ra_key,
        )

        nested_handler = NestedHandler(
            cert_req_handler=self.ca_handler.cert_req_handler,
            cert_conf_handler=self.ca_handler.cert_conf_handler,
            allow_inner_unprotected=True,
        )

        der_data = try_encode_pyasn1(nested)
        nested = parse_pkimessage(der_data)

        with self.assertRaises(BadMessageCheck) as context:
            _ = nested_handler.process_nested_request(request=nested, prot_handler=self.ca_handler.protection_handler)
        self.assertEqual(str(context.exception), "The original `PKIMessage` protection is invalid.")
