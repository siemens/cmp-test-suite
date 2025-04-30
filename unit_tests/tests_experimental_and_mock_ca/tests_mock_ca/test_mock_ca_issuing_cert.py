# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler
from pyasn1_alt_modules import rfc9480

from resources.asn1utils import is_bit_set
from resources.cmputils import (
    build_cert_conf_from_resp,
    build_ir_from_key,
    find_oid_in_general_info,
    get_cert_from_pkimessage,
    get_pkistatusinfo,
    parse_pkimessage,
)
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage
from resources.utils import display_pki_status_info
from unit_tests.utils_for_test import load_ca_cert_and_key, try_encode_pyasn1


class TestMockCAIssuing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.ca_handler = CAHandler(ca_cert=cls.ca_cert, ca_key=cls.ca_key)

    def test_issue_cert_with_implicit_confirm(self):
        """
        GIVEN a certificate request.
        WHEN a certificate is issued.
        THEN the certificate is issued.
        """
        key = generate_key("ecc")
        ir = build_ir_from_key(
            key, common_name="CN=Hans the Tester", sender="CN=Hans the Tester", implicit_confirm=True, for_mac=True
        )
        prot_ir = protect_pkimessage(ir, "pbmac1", password="SiemensIT")
        der_data = try_encode_pyasn1(prot_ir)
        request = parse_pkimessage(der_data)
        response = self.ca_handler.process_normal_request(request)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())
        result = find_oid_in_general_info(response, str(rfc9480.id_it_implicitConfirm))
        self.assertTrue(result)

    def test_issue_cert_without_implicit_confirm(self):
        """
        GIVEN a certificate request without implicit confirmation.
        WHEN a certificate is issued.
        THEN the certificate is not issued.
        """
        key = generate_key("ecc")
        ir = build_ir_from_key(
            key, common_name="CN=Hans the Tester", sender="CN=Hans the Tester", implicit_confirm=False, for_mac=True
        )
        prot_ir = protect_pkimessage(ir, "pbmac1", password="SiemensIT")
        der_data = try_encode_pyasn1(prot_ir)
        request = parse_pkimessage(der_data)
        response = self.ca_handler.process_normal_request(request)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())
        result = find_oid_in_general_info(response, str(rfc9480.id_it_implicitConfirm))
        self.assertFalse(result)
        cert = get_cert_from_pkimessage(response)

        # Certificate Confirmation
        # Set to version 3 because the signing key is an Ed25519 key.
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            cert=cert,
            pvno=3,
            sender="CN=Hans the Tester",
            recipient="CN=Mock CA",
            for_mac=True,
            exclude_fields=None,
            hash_alg="sha256",
        )

        prot_cert_conf = protect_pkimessage(cert_conf, "pbmac1", password="SiemensIT")
        response = self.ca_handler.process_normal_request(prot_cert_conf)
        self.assertEqual(response["body"].getName(), "pkiconf")

    def test_issue_cert_without_implicit_confirm_no_announcement(self):
        """
        GIVEN a certificate request without implicit confirmation,
        WHEN a certificate is issued then is the certificate not published until confirmed.
        THEN the certificate is issued.
        """
        key = generate_key("ecc")
        ir = build_ir_from_key(
            key, common_name="CN=Hans the Tester", sender="CN=Hans the Tester",
            implicit_confirm=False,
            for_mac=True
        )
        prot_ir = protect_pkimessage(ir, "pbmac1", password="SiemensIT")
        der_data = try_encode_pyasn1(prot_ir)
        request = parse_pkimessage(der_data)
        response = self.ca_handler.process_normal_request(request)
        status = get_pkistatusinfo(response)

        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())
        result = find_oid_in_general_info(response, str(rfc9480.id_it_implicitConfirm))
        self.assertFalse(result)
        cert = get_cert_from_pkimessage(response)

        key2 = generate_key("ecc")
        ir2 = build_ir_from_key(
            key2,
            common_name="CN=Hans the Tester2",
            exclude_fields="sender,senderKID",
        )
        prot_ir2 = protect_pkimessage(ir2, "signature", private_key=key, cert=cert, certs_dir="data/unittest/")
        response = self.ca_handler.process_normal_request(prot_ir2)
        self.assertEqual(response["body"].getName(), "error", get_pkistatusinfo(response))
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "rejection", status.prettyPrint())
        text = str(status["statusString"][0])
        self.assertTrue(is_bit_set(status["failInfo"], "notAuthorized"), status.prettyPrint())
        self.assertTrue("confirmed" in text.lower(), text)

    def test_issue_cert_with_already_confirmed(self):
        """
        GIVEN a certificate request with implicit confirmation,
        WHEN a certificate is issued and confirmed.
        THEN the certificate is issued.
        """
        key = generate_key("ecc")
        ir = build_ir_from_key(
            key, common_name="CN=Hans the Tester",
            sender="CN=Hans the Tester",
            implicit_confirm=True,
            for_mac=True
        )
        prot_ir = protect_pkimessage(ir, "pbmac1", password="SiemensIT")
        der_data = try_encode_pyasn1(prot_ir)
        request = parse_pkimessage(der_data)
        response = self.ca_handler.process_normal_request(request)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "ip", display_pki_status_info(response))
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())
        result = find_oid_in_general_info(response, str(rfc9480.id_it_implicitConfirm))
        self.assertTrue(result)
        cert = get_cert_from_pkimessage(response)

        # Certificate Confirmation
        # Set to version 3 because the signing key is an Ed25519 key.
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            cert=cert,
            pvno=3,
            sender="CN=Hans the Tester",
            recipient="CN=Mock CA",
            for_mac=True,
            exclude_fields=None,
            hash_alg="sha256",
        )
        prot_cert_conf = protect_pkimessage(cert_conf, "pbmac1", password="SiemensIT")
        response = self.ca_handler.process_normal_request(prot_cert_conf)
        self.assertEqual(response["body"].getName(), "error", display_pki_status_info(response))
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "rejection", status.prettyPrint())
        self.assertTrue(is_bit_set(status["failInfo"], "certConfirmed"), status.prettyPrint())
