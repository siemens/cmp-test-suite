# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9481

from mock_ca.nested_handler import NestedHandler
from mock_ca.mock_fun import CAOperationState
from mock_ca.nestedutils import validate_added_protection_request
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key, build_nested_pkimessage, add_general_info_values, \
    prepare_orig_pki_message, parse_pkimessage
from resources.exceptions import BadMessageCheck
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage, verify_pkimessage_protection
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestProcessAddedProtReq(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        cls.trusted_dir = "./data/trusted_ras"
        cls.ra_key = cls.key
        cls.ra_cert = parse_certificate(load_and_decode_pem_file("./data/trusted_ras/ra_cms_cert_ecdsa.pem"))
        cls.cm = "CN=Hans the Tester"
        cls.password = b"password"

    def test_process_added_prot_req(self):

        ir = build_ir_from_key(
            self.key,
            common_name=self.cm,
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

        response = validate_added_protection_request(
            request=nested,
            ca_cert=self.ra_cert,
            ca_key=self.ra_key,
            extensions=None,
            mac_protection=self.password,
        )

        self.assertEqual(response["body"].getName(), "ip")
        self.assertEqual(response["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)
        verify_pkimessage_protection(
            pki_message=response,
            password=self.password
        )

    def test_process_added_prot_req_ra_verified(self):

        ir = build_ir_from_key(
            self.key,
            common_name=self.cm,
            ra_verified=True,
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

        with self.assertLogs(level='INFO') as cm:
            response = validate_added_protection_request(
                request=nested,
                ca_cert=self.ra_cert,
                ca_key=self.ra_key,
                extensions=None,
                mac_protection=self.password,
            )
        self.assertTrue(any("Skipping `raVerified` verification." in message for message in cm.output))
        self.assertIsNotNone(response)

        self.assertEqual(response["body"].getName(), "ip")
        self.assertEqual(response["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)
        verify_pkimessage_protection(
            pki_message=response,
            password=self.password
        )


    def test_nested_handler(self):
        ca_operation_state = CAOperationState(
            ca_cert=self.ra_cert,
            ca_key=self.ra_key,
            pre_shared_secret=self.password,
            extensions=None,
        )
        nested_handler = NestedHandler(
            ca_operation_state=ca_operation_state,
            allow_inner_unprotected=True,
        )

        ir = build_ir_from_key(
            self.key,
            common_name=self.cm,
            ra_verified=True,
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
            request=nested
        )
        self.assertEqual(response["body"].getName(), "ip")
        self.assertEqual(response["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)
        verify_pkimessage_protection(
            pki_message=response,
            password=self.password
        )


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
        )
        bad_ir = protect_pkimessage(
            pki_message=ir,
            password=self.password,
            protection="pbmac1",
            bad_message_check=True,
        )

        nested = build_nested_pkimessage(
            other_messages=bad_ir,
            for_added_protection=True,
        )

        nested = protect_pkimessage(
            pki_message=nested,
            protection="signature",
            cert=self.ra_cert,
            private_key=self.ra_key,
        )
        orig_msg = prepare_orig_pki_message(bad_ir)
        nested = add_general_info_values(nested, orig_msg)
        self.assertEqual(len(nested["header"]["generalInfo"]), 1)

        ca_operation_state = CAOperationState(
            ca_cert=self.ra_cert,
            ca_key=self.ra_key,
            pre_shared_secret=self.password,
            extensions=None,
        )
        nested_handler = NestedHandler(
            ca_operation_state=ca_operation_state,
            allow_inner_unprotected=True,
        )

        der_data = try_encode_pyasn1(nested)
        nested = parse_pkimessage(der_data)

        with self.assertRaises(BadMessageCheck) as context:
            nested_handler.process_nested_request(
                request=nested
            )

        self.assertEqual(str(context.exception), "The original `PKIMessage` protection is invalid.")





