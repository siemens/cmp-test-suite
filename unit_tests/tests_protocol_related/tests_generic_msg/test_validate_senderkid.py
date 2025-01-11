# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources.asn1utils import encode_to_der
from resources.certbuildutils import build_certificate, generate_signed_csr
from resources.certextractutils import get_subject_key_identifier
from resources.checkutils import validate_senderkid_for_cmp_protection
from resources.cmputils import (
    build_p10cr_from_csr,
    parse_csr,
    patch_senderkid,
    prepare_general_name,
)
from resources.protectionutils import protect_pkimessage
from resources.utils import decode_pem_string

from unit_tests.utils_for_test import build_pkimessage, de_and_encode_pkimessage


class TestValidateSenderKID(unittest.TestCase):


    def setUp(self):
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        pki_message = build_p10cr_from_csr(csr)
        self.pki_message = pki_message
        self.private_key = private_key
        self.common_name = "C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann"

    def test_check_senderKID_without_protection(self):
        """
        GIVEN a PKIMessage without any signature- or mac-protection
        WHEN the sender key identifier (KID) is checked for CMP protection,
        THEN the check should pass without any issues, as no protection is applied
        """
        validate_senderkid_for_cmp_protection(pki_message=self.pki_message)

    def test_check_sig_senderKID_without_ski(self):
        """
        GIVEN a PKIMessage protected by a signature but using a certificate without a SubjectKeyIdentifier (SKI)
        WHEN the sender key identifier (senderKID) is checked for CMP protection,
        THEN the check should pass since no SubjectKeyIdentifier is present in the certificate
        """
        # default certificate has no SubjectKeyIdentifier
        cert, key = build_certificate(ski=False)
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=cert,
            private_key=key,
            protection="signature",
            password=None,
            exclude_cert=False,
        )
        # simulates send over wire.
        der_data = encode_to_der(protected_msg)
        received_pki_msg, _ = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        validate_senderkid_for_cmp_protection(pki_message=received_pki_msg)

    def test_check_sig_senderKID_with_invalid_ski(self):
        """
        GIVEN a PKIMessage protected by a signature but using a certificate with an invalid SubjectKeyIdentifier (SKI).
        WHEN the sender key identifier (senderKID) is checked for CMP protection,
        THEN a ValueError should be raised because the SKI is invalid
        """
        cert, key = build_certificate(ski=True)

        # default certificate has no SubjectKeyIdentifier
        self.pki_message = patch_senderkid(self.pki_message, os.urandom(6))
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=cert,
            private_key=key,
            protection="signature",
            password=None,
            exclude_cert=False,
            no_patch=True
        )



        with self.assertRaises(ValueError):
            validate_senderkid_for_cmp_protection(pki_message=protected_msg)

    def test_check_sig_senderKID_with_valid_ski(self):
        """
        GIVEN a `PKIMessage` protected by a signature and using a certificate with a valid SubjectKeyIdentifier (SKI).
        WHEN the sender key identifier (senderKID) is checked for CMP protection,
        THEN the check should pass since the SKI is valid and correctly included in the PKIMessage.
        """
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        asn1cert, key = build_certificate(ski=True)

        pki_message = build_p10cr_from_csr(csr, sender_kid=get_subject_key_identifier(asn1cert))

        protected_msg = protect_pkimessage(
            pki_message=pki_message,
            cert=asn1cert,
            private_key=key,
            protection="signature",
            exclude_cert=False,
        )
        self.assertNotEqual(get_subject_key_identifier(asn1cert), None)
        self.assertTrue(protected_msg["header"]["senderKID"].isValue)

        validate_senderkid_for_cmp_protection(pki_message=protected_msg, must_be_protected=True)

    def test_check_senderKID_with_mac_but_not_cm_name_set(self):
        """
        GIVEN a PKIMessage protected with MAC-based protection but without the sender's
        common name set in the senderKID.
        WHEN check_senderkid_for_cmp_protection is called with `allow_mac_failure=False`,
        THEN a ValueError should be raised due to the missing common name in the senderKID field.
        """
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message, protection="pbmac1", password="PASSWORD", exclude_cert=False
        )

        protected_msg = de_and_encode_pkimessage(protected_msg)

        with self.assertRaises(ValueError):
            validate_senderkid_for_cmp_protection(pki_message=protected_msg, allow_mac_failure=False)

    def test_check_mac_protected_valid_senderKID_and_sender(self):
        """
        GIVEN a PKIMessage protected with MAC-based protection and with a valid senderKID and sender.
        WHEN check_senderkid_for_cmp_protection is called,
        THEN the check should pass without any issues since the senderKID and sender are valid for MAC-based protection
        (values are Equal and the sender is of type `directoryName`)
        """
        common_name = "C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann"
        sender = prepare_general_name("directoryName", name_str=common_name)
        pki_message = build_pkimessage(sender_kid=b"CN=Joe Mustermann", sender=sender)
        protected_msg = protect_pkimessage(
            pki_message=pki_message, protection="password_based_mac", password="PASSWORD", exclude_cert=False
        )
        protected_msg = de_and_encode_pkimessage(protected_msg)
        validate_senderkid_for_cmp_protection(pki_message=protected_msg, allow_mac_failure=False)

    def test_check_mac_protected_invalid_senderKID_and_sender(self):
        """
        GIVEN a PKIMessage protected with MAC-based protection and with an invalid senderKID
        and a valid sender.
        WHEN check_senderkid_for_cmp_protection is called,
        THEN a ValueError should be raised due to the missing sender and the senderKID field.
        """
        common_name = "C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann"
        sender = prepare_general_name("directoryName", name_str=common_name)
        pki_message = build_pkimessage(sender_kid=b"CN=Hans1", sender=sender)
        protected_msg = protect_pkimessage(
            pki_message=pki_message, protection="pbmac1", password="PASSWORD", exclude_cert=False
        )

        protected_msg = de_and_encode_pkimessage(protected_msg)

        with self.assertRaises(ValueError):
            validate_senderkid_for_cmp_protection(pki_message=protected_msg, allow_mac_failure=False)
