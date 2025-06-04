# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
from pyasn1.codec.der import encoder
from pyasn1.type import tag
from pyasn1_alt_modules import rfc5652
from resources import utils
from resources.ca_kga_logic import validate_enveloped_data
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.cmputils import patch_extra_certs
from resources.envdatautils import (
    prepare_asymmetric_key_package,
    prepare_enveloped_data,
    prepare_signed_data,
    wrap_key_password_based_key_management_technique, prepare_password_recipient_info,
)
from resources.keyutils import generate_key, load_private_key_from_file
from resources.oid_mapping import sha_alg_name_to_oid
from resources.protectionutils import protect_pkimessage

from unit_tests.utils_for_test import (
    build_pkimessage,
    de_and_encode_pkimessage, _prepare_pbkdf2, prepare_pwri_structure,
)


class TestValidateEnvelopeData(unittest.TestCase):
    def setUp(self):
        self.content_encryption_key = b"\xaa" * 16
        self.trusted_root = parse_certificate(utils.load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        self.root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        self.kga_certificate, self.key = build_certificate(
            common_name="CN=Hans the Tester",
            key="ec",
            include_ski=True,
            eku="cmKGA",
            ca_cert=self.trusted_root,
            ca_key=self.root_key,
        )
        # Set up valid SignerInfo structure for tests
        self.dig_alg_id = sha_alg_name_to_oid("sha256")
        self.new_key_rsa = generate_key("rsa")
        self.eContent_data = encoder.encode(prepare_asymmetric_key_package(private_keys=[self.new_key_rsa]))
        signed_data = prepare_signed_data(
            signing_key=self.key,
            cert=self.kga_certificate,
            e_content=self.eContent_data,
            sig_hash_name="sha256",
            cert_chain=[self.kga_certificate, self.trusted_root],
        )
        self.signed_data_der = encoder.encode(signed_data)
        self.password = "TEST_PASSWORD"

    def test_valid_envelope_data_with_pwri_for_rsa(self):
        """
        GIVEN a valid password-based key wrap using PWRI and a valid content encryption key and a valid RSAPrivateKey
        WHEN the PKIMessage is built and the envelope data is prepared with PWRI and content encryption.
        THEN validate_envelopeData should validate the envelope data without raising errors and
        extract the correct RSA Key.
        """

        pwri = prepare_password_recipient_info(
            password=self.password,
            cek=self.content_encryption_key,
        )

        recip_info = rfc5652.RecipientInfo()
        recip_info = recip_info.setComponentByName("pwri", pwri)

        pki_message = build_pkimessage()
        pki_message = protect_pkimessage(pki_message, password=self.password, protection="password_based_mac")
        pki_message = patch_extra_certs(pki_message, certs=[self.kga_certificate, self.trusted_root])
        pki_message = de_and_encode_pkimessage(pki_message)

        # version MUST be 0 for pwri.
        envelope_data = prepare_enveloped_data(
            [recip_info],
            data_to_protect=self.signed_data_der,
            cek=self.content_encryption_key,
            version=0,
        )

        data = validate_enveloped_data(
            envelope_data, password=self.password, pki_message=pki_message,
        )

        self.assertEqual(self.signed_data_der, data)

    def test_invalid_password_for_envelope_data_with_pwri(self):
        """
        GIVEN a PWRI structure that uses a different password from the original key encryption process.
        WHEN the validate_envelopeData function is called.
        THEN it should raise InvalidUnwrap because the decryption key is incorrect.
        """
        encrypted_key = wrap_key_password_based_key_management_technique(
            password=self.password + "_Different", key_to_wrap=self.content_encryption_key, parameters=_prepare_pbkdf2()
        )
        pwri = prepare_pwri_structure(encrypted_key=encrypted_key)

        recip_info = rfc5652.RecipientInfo()
        recip_info = recip_info.setComponentByName("pwri", pwri)

        pki_message = build_pkimessage()
        pki_message = protect_pkimessage(pki_message, password=self.password, protection="password_based_mac")
        pki_message = de_and_encode_pkimessage(pki_message)

        # version MUST be 0 for pwri.
        envelope_data = prepare_enveloped_data(
            [recip_info],
            data_to_protect=self.signed_data_der,
            cek=self.content_encryption_key,
            version=0,
        )
        with self.assertRaises(InvalidUnwrap):
            validate_enveloped_data(
                envelope_data, password=self.password,
                pki_message=pki_message
            )

    def test_invalid_version_for_pwri_envelope_data(self):
        """
        GIVEN a PWRI structure with an incorrect version (must be 0).
        WHEN the validate_envelopeData function is called with an invalid version.
        THEN it should raise a ValueError due to the incorrect version.
        """
        pwri = prepare_pwri_structure()
        recip_info = rfc5652.RecipientInfo()
        recip_info["pwri"] = pwri.subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))

        pki_message = build_pkimessage()
        pki_message = protect_pkimessage(pki_message, password=self.password, protection="password_based_mac")
        pki_message = de_and_encode_pkimessage(pki_message)

        # version MUST be 0 for pwri.
        envelope_data = prepare_enveloped_data(
            [recip_info],
            data_to_protect=self.signed_data_der,
            cek=self.content_encryption_key,
            version=2,
        )

        with self.assertRaises(ValueError):
            validate_enveloped_data(
                envelope_data, password=self.password, pki_message=pki_message,
            )
