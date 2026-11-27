# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import os
import unittest

from mock_ca.ca_handler import CAHandler
from pyasn1_alt_modules import rfc9480

from mock_ca.db_config_vars import CertConfConfigVars
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
        cert_conf_cf = CertConfConfigVars(must_be_fresh_nonce=True)
        cls.ca_handler.set_config_vars(cert_conf_handler=cert_conf_cf)

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
            sender_nonce=os.urandom(16),
            sender="CN=Hans the Tester",
            recipient="CN=Mock CA",
            for_mac=True,
            exclude_fields=None,
            hash_alg="sha256",
        )

        prot_cert_conf = protect_pkimessage(cert_conf, "pbmac1", password="SiemensIT")
        response = self.ca_handler.process_normal_request(prot_cert_conf)
        self.assertEqual(response["body"].getName(), "pkiconf")

    def test_cert_conf_rejects_missing_and_unknown_transaction_ids(self) -> None:
        """GIVEN an enrollment awaiting explicit confirmation.

        WHEN a protected certConf omits the transactionID or supplies an unknown one.
        THEN the Mock CA rejects with badDataFormat for omission and badRequest for an unknown ID.
        """
        sender = "CN=Certificate Confirmation Transaction Test"
        password = self.ca_handler.pre_shared_secret
        ir = build_ir_from_key(
            generate_key("ecc"), common_name=sender, sender=sender, implicit_confirm=False, for_mac=True
        )
        ir = protect_pkimessage(ir, "pbmac1", password=password)
        response = self.ca_handler.process_normal_request(parse_pkimessage(try_encode_pyasn1(ir)))
        self.assertEqual(response["body"].getName(), "ip")
        self.assertEqual(get_pkistatusinfo(response)["status"].prettyPrint(), "accepted")
        cert = get_cert_from_pkimessage(response)
        transaction_id = response["header"]["transactionID"].asOctets()
        unknown_id = bytes([transaction_id[0] ^ 1]) + transaction_id[1:]

        # RFC 9483 Section 3.5: "The transactionID MUST be present. (failInfo bit: badDataFormat)"
        for requested_id, failinfo in ((None, "badDataFormat"), (unknown_id, "badRequest")):
            with self.subTest(failinfo=failinfo):
                cert_conf = build_cert_conf_from_resp(
                    response,
                    cert=cert,
                    sender=sender,
                    recipient="CN=Mock CA",
                    for_mac=True,
                    pvno=3,
                    hash_alg="sha256",
                    transaction_id=requested_id,
                    exclude_fields="transactionID" if requested_id is None else None,
                )
                cert_conf = protect_pkimessage(cert_conf, "pbmac1", password=password)
                request = parse_pkimessage(try_encode_pyasn1(cert_conf))
                self.assertEqual(request["header"]["transactionID"].isValue, requested_id is not None)
                error = self.ca_handler.process_normal_request(request)
                self.assertEqual(error["body"].getName(), "error")
                status = get_pkistatusinfo(error)
                self.assertEqual(status["status"].prettyPrint(), "rejection")
                self.assertTrue(is_bit_set(status["failInfo"], failinfo, exclusive=True), status.prettyPrint())

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
