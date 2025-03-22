# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5652
from resources import utils
from resources.ca_kga_logic import validate_not_local_key_gen
from resources.certutils import parse_certificate
from resources.cmputils import patch_extra_certs
from resources.envdatautils import (
    _prepare_pbkdf2,
    prepare_pwri_structure,
    wrap_key_password_based_key_management_technique,
)
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_ca_response import build_complete_envelope_data_ca_msg
from unit_tests.utils_for_test import (
    private_key_to_pkcs8,
)


class TestCAMessageWithEnvelopeDataPWRI(unittest.TestCase):
    def setUp(self):
        self.trustanchors = "data/unittest"
        self.content_encryption_key = b"\xaa" * 16
        self.trusted_root = parse_certificate(utils.load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

        self.kga_certificate = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/kga_cert_kari_ecdsa.pem"))
        self.kga_signing_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

        # prepares a valid structure, because the password is the same the structure can
        # be prepared for all test cases.
        self.password = "TEST_PASSWORD"
        encrypted_key = wrap_key_password_based_key_management_technique(
            password=self.password,
            key_to_wrap=self.content_encryption_key,
            parameters=_prepare_pbkdf2()
        )

        pwri = prepare_pwri_structure(encrypted_key=encrypted_key)
        recip_info = rfc5652.RecipientInfo()
        self.recip_info = recip_info.setComponentByName("pwri", pwri)



    def test_valid_envelope_data_with_pwri_for_ecc(self):
        """
        GIVEN a valid password-based key wrap using PWRI and a valid content encryption key and a valid EC private key
        WHEN the PKIMessage is built and the envelope data is prepared with PWRI and content encryption.
        THEN validate_envelopeData should validate the envelope data without raising errors and
        extract the correct RSA Key.
        """
        new_key_ecc = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        issued_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))

        # version MUST be 0 for pwri.
        ca_message = build_complete_envelope_data_ca_msg(kga_certificate=self.kga_certificate,
                                                         kga_signing_key=self.kga_signing_key,
                                                         version=0,
                                                         kga_cert_chain=[self.kga_certificate, self.trusted_root],
                                                         recipient_infos=[self.recip_info],
                                                         private_keys=[new_key_ecc],
                                                         content_encryption_key=self.content_encryption_key,
                                                         issued_cert=issued_cert,
                                                         extra_certs=[self.trusted_root]
                                                         )

        # MUST be protected by the same password.
        ca_message = protect_pkimessage(ca_message, password=self.password, protection="password_based_mac")
        # extraCerts must contain the cert chain, of the newly issued cert chain.
        ca_message = patch_extra_certs(pki_message=ca_message, certs=[self.trusted_root])
        extracted_private_key = validate_not_local_key_gen(
            ca_message, trustanchors="data/unittest", password=self.password
        )

        extracted_private_key_bytes = private_key_to_pkcs8(extracted_private_key)
        new_key_bytes = private_key_to_pkcs8(new_key_ecc)

        self.assertEqual(extracted_private_key.public_key(), new_key_ecc.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)

        self.assertEqual(extracted_private_key.public_key(), new_key_ecc.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)

    def test_valid_envelope_data_with_pwri_valis_but_use_diff_password_for_cmp_protection(self):
        """
        GIVEN a valid password-based key wrap using PWRI and a valid content encryption key and a valid EC private key
        WHEN the PKIMessage is built and the envelope data is prepared with PWRI and content encryption.
        THEN validate_envelopeData should validate the envelope data without raising errors and
        extract the correct RSA Key.
        """
        new_key_ecc = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        issued_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))

        # version MUST be 0 for pwri.
        ca_message = build_complete_envelope_data_ca_msg(kga_certificate=self.kga_certificate,
                                                         kga_signing_key=self.kga_signing_key, version=0,
                                                         kga_cert_chain=[self.kga_certificate, self.trusted_root],
                                                         recipient_infos=[self.recip_info],
                                                         private_keys=[new_key_ecc],
                                                         content_encryption_key=self.content_encryption_key,
                                                         issued_cert=issued_cert,
                                                         extra_certs=[self.trusted_root])

        # MUST be protected by the same password.
        ca_message = protect_pkimessage(ca_message, password="TEST PASSWORD2", protection="password_based_mac")

        with self.assertRaises(ValueError):
             validate_not_local_key_gen(
                ca_message, trustanchors="data/unittest", password=self.password
            )



if __name__ == "__main__":
    unittest.main()
