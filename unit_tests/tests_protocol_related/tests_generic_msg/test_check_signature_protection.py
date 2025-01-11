# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources.asn1utils import encode_to_der
from resources.certbuildutils import generate_certificate, generate_signed_csr
from resources.checkutils import check_pkimessage_signature_protection
from resources.cmputils import build_p10cr_from_csr, parse_csr, patch_extra_certs, prepare_general_name
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import decode_pem_string

from unit_tests.utils_for_test import build_pkimessage


class TestCheckSignatureProtection(unittest.TestCase):
    @classmethod
    def setUp(cls):
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        pki_message = build_p10cr_from_csr(csr)

        cls.pki_message = pki_message
        cls.private_key = private_key

    def test_check_valid_protection(self):
        """
        GIVEN a valid PKIMessage and a private key for signing.
        WHEN the PKIMessage is protected using a signature-based method.
        THEN the signature verification should succeed without any exceptions.
        """
        private_key = generate_key()

        sender = prepare_general_name("directoryName", "CN=Hans")
        pki_message = build_pkimessage(sender=sender)

        protected_msg = protect_pkimessage(
            pki_message=pki_message,
            cert=None,
            private_key=private_key,
            protection="signature",
            password=None,
            exclude_cert=False,
        )
        # This is intended to be used for data transmission over the wire.
        # The difference lies in the name structure. If not transmitted, the values contain the actual string inside,
        # but they need to include the ASN.1 tag and size.
        der_data = encode_to_der(protected_msg)
        protected_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())

        check_pkimessage_signature_protection(pki_message=protected_msg, check_sender_kid=False)

    def test_check_sig_without_extra_cert(self):
        """
        GIVEN a valid PKIMessage protected with a signature but without extra certificates.
        WHEN the signature is verified without including any extra certificates.
        THEN the function should raise a ValueError due to the missing certificate.
        """
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="signature",
            password=None,
            exclude_cert=True,
        )

        # This is intended to be used for data transmission over the wire.
        # The difference lies in the name structure. If not transmitted, the values contain the actual string inside,
        # but they need to include the ASN.1 tag and size.
        der_data = encode_to_der(protected_msg)
        protected_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())

        with self.assertRaises(ValueError):
            check_pkimessage_signature_protection(pki_message=protected_msg, check_sender_kid=False)

    def test_check_sig_with_wrong_extra_cert_pos(self):
        """
        GIVEN a valid PKIMessage protected with a signature and a list of extra certificates,
              where the correct certificate is not in the first position.
        WHEN the signature is verified with the incorrect order of certificates.
        THEN the function should raise a ValueError due to the incorrect certificate positioning.
        """
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="signature",
            password=None,
            exclude_cert=True,
        )

        correct_cert = generate_certificate(private_key=private_key)
        # add random cert at the beginning, because the CMP-protection certificate has to be at the first position.
        extra_certs = [generate_certificate(private_key=generate_key("ecdsa")), correct_cert]
        protected_msg = patch_extra_certs(protected_msg, certs=extra_certs, swap_certs=False)

        # This is intended to be used for data transmission over the wire.
        # The difference lies in the name structure. If not transmitted, the values contain the actual string inside,
        # but they need to include the ASN.1 tag and size.
        der_data = encode_to_der(protected_msg)
        protected_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())

        with self.assertRaises(ValueError):
            check_pkimessage_signature_protection(pki_message=protected_msg, check_sender_kid=False)
