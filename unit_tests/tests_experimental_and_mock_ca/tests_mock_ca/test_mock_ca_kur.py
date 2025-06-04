# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pyasn1_alt_modules import rfc9480

from mock_ca.ca_handler import CAHandler
from mock_ca.client import build_example_rsa_mac_request
from resources.asn1utils import is_bit_set
from resources.cmputils import (
    build_cert_conf_from_resp,
    build_key_update_request,
    get_cert_from_pkimessage,
    get_cmp_message_type,
    get_pkistatusinfo,
    find_oid_in_general_info,
)
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage
from resources.utils import display_pki_status_info


class TestKeyUpdateTest(unittest.TestCase):


    def setUp(self):
        """Set up the test environment."""
        self.ca_handler = CAHandler()

    def test_key_update_and_confirmation_flow(self):
        """
        GIVEN a CA handler and an initial request,
        WHEN a KeyUpdateRequest (KUR) is sent with a new key,
        THEN the CA should process the request, update the key, and return a PKIConf message.
        """

        request, key = build_example_rsa_mac_request()

        response = self.ca_handler.process_normal_request(request)
        cert = get_cert_from_pkimessage(response)

        new_key = generate_key("rsa")
        # The tx is just set for debugging purposes.
        kur = build_key_update_request(
            new_key, exclude_fields="sender,senderKID", transaction_id=b"A" * 16
        )

        prot_kur = protect_pkimessage(kur, "signature", private_key=key, cert=cert)
        response = self.ca_handler.process_normal_request(prot_kur)
        status = get_pkistatusinfo(response)

        self.assertFalse(
            find_oid_in_general_info(response, str(rfc9480.id_it_implicitConfirm)),
            "Response should not contain id-it-implicitConfirm"
        )
        self.assertEqual(
            status["status"].prettyPrint(), "accepted",
            display_pki_status_info(response)
        )

        _ = get_cert_from_pkimessage(response)
        cert_conf = build_cert_conf_from_resp(response, sender="Mock-CA")

        prot_cert_conf = protect_pkimessage(cert_conf, "signature", private_key=key, cert=cert)
        pkiconf = self.ca_handler.process_normal_request(prot_cert_conf)

        self.assertEqual(
            get_cmp_message_type(pkiconf), "pkiconf",
            f"Expected PKIConf message, got: {pkiconf['body'].prettyPrint()}"
        )

    def test_key_update_implicit_confirm(self):
        """
        GIVEN a CA handler and an initial request,
        WHEN a KeyUpdateRequest (KUR) is sent with implicit confirmation,
        THEN the CA should process the request and return a PKIConf message.
        """

        request, key = build_example_rsa_mac_request()

        response = self.ca_handler.process_normal_request(request)
        cert = get_cert_from_pkimessage(response)

        new_key = generate_key("rsa")
        kur = build_key_update_request(
            new_key, exclude_fields="sender,senderKID", transaction_id=b"A" * 16,
            implicit_confirm=True
        )

        prot_kur = protect_pkimessage(kur, "signature", private_key=key, cert=cert)
        response = self.ca_handler.process_normal_request(prot_kur)
        status = get_pkistatusinfo(response)

        self.assertTrue(
            find_oid_in_general_info(response, str(rfc9480.id_it_implicitConfirm)),
            "Response should contain id-it-implicitConfirm"
        )
        self.assertEqual(
            status["status"].prettyPrint(), "accepted",
            display_pki_status_info(response)
        )

        _ = get_cert_from_pkimessage(response)
        cert_conf = build_cert_conf_from_resp(response, sender="Mock-CA")


        prot_cert_conf = protect_pkimessage(cert_conf, "signature", private_key=key, cert=cert)
        error = self.ca_handler.process_normal_request(prot_cert_conf)

        self.assertEqual(
            get_cmp_message_type(error), "error",
            f"Expected Error message, got: {error['body'].prettyPrint()}"
        )
        status = get_pkistatusinfo(error)
        result = is_bit_set(status["failInfo"], "certRevoked,certConfirmed", exclusive=False)
        self.assertTrue(
            result,
            f"Expected certRevoked failInfo, got: {display_pki_status_info(error)}"
        )


if __name__ == "__main__":
    unittest.main()

