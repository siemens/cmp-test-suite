# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc4211

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.ca_ra_utils import get_cert_req_msg_from_pkimessage
from resources.cmputils import build_ir_from_key, add_reg_info_to_pkimessage, \
    prepare_pki_publication_information_control, prepare_single_publication_info
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPublicationInfoControl(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_prepare_publication_info_control(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN add_reg_info_to_pkimessage is called,
        THEN the PKIMessage should contain the new entry in the regInfo field
        and be a valid PKIMessage.
        """
        ir = build_ir_from_key(self.key, implicit_confirm=True)
        entry = prepare_pki_publication_information_control("pleasePublish")
        ir = add_reg_info_to_pkimessage(ir, entry)
        cert_req_msg = get_cert_req_msg_from_pkimessage(ir)
        self.assertEqual(cert_req_msg["regInfo"][0]["type"], rfc4211.id_regCtrl_pkiPublicationInfo)

        der_data = try_encode_pyasn1(ir)
        obj, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")

    def test_prepare_publication_info_control_with_uri(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN add_reg_info_to_pkimessage is called,
        THEN the PKIMessage should contain the new entry in the regInfo field
        and be a valid PKIMessage.
        """
        ir = build_ir_from_key(self.key, implicit_confirm=True)
        entry = prepare_pki_publication_information_control("pleasePublish", pub_method="x500",
                                                            pub_location="https://example.com")
        ir = add_reg_info_to_pkimessage(ir, entry)
        cert_req_msg = get_cert_req_msg_from_pkimessage(ir)
        self.assertEqual(cert_req_msg["regInfo"][0]["type"], rfc4211.id_regCtrl_pkiPublicationInfo)

        der_data = try_encode_pyasn1(ir)
        obj, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")

    def test_prepare_publication_control_with_values(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN add_reg_info_to_pkimessage is called,
        THEN the PKIMessage should contain the new entry in the regInfo field
        and be a valid PKIMessage.
        """
        ir = build_ir_from_key(self.key, implicit_confirm=True)
        entry1 =prepare_single_publication_info(
            pub_method="web",
            pub_location="https://example.com",

        )
        entry2 = prepare_single_publication_info(
            pub_method="ldap",
            pub_location="ldap://example.com",

        )
        entry = prepare_pki_publication_information_control("pleasePublish", entries=[entry1, entry2])
        ir = add_reg_info_to_pkimessage(ir, entry)
        cert_req_msg = get_cert_req_msg_from_pkimessage(ir)
        self.assertEqual(cert_req_msg["regInfo"][0]["type"], rfc4211.id_regCtrl_pkiPublicationInfo)

        der_data = try_encode_pyasn1(ir)
        obj, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")