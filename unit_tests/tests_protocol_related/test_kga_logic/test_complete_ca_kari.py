# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5652, rfc9480, rfc9481
from resources import utils, envdatautils
from resources.ca_kga_logic import (
    validate_not_local_key_gen,
)
from resources.certextractutils import get_field_from_certificate
from resources.certutils import parse_certificate
from resources.cryptoutils import compute_ansi_x9_63_kdf, perform_ecdh
from resources.envdatautils import (
    prepare_ecc_cms_shared_info,
    prepare_key_agreement_recipient_info,
    perform_sender_ecdh_one_pass_mqv,
)
from resources.keyutils import load_private_key_from_file
from resources.typingutils import ECDHPrivateKey, ECDHPublicKey
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_ca_response import build_complete_envelope_data_ca_msg
from unit_tests.utils_for_test import private_key_to_pkcs8


class TestCAMessageWithEnvelopeDataKARI(unittest.TestCase):

    def setUp(self):
        self.trustanchors = "data/unittest"
        self.content_encryption_key = os.urandom(32)
        self.trusted_root = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem")
        )

        # Load KGA certificate and key
        self.kga_certificate = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/kga_cert_kari_ecdsa.pem")
        )
        self.kga_signing_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

        # Load CMP protection certificate
        self.cmp_prot_cert = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/kga_cert_kari_ecdsa.pem")
        )

        # Load server's X25519 key and certificate
        self.server_x25519_key = load_private_key_from_file(
            "data/keys/private-key-x25519.pem"
        )
        self.server_x25519_cert = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/cmp_prot_kari_x25519.pem")
        )

    def _prepare_kari(self, ee_pub_key: ECDHPublicKey,
                      key_agreement_oid: univ.ObjectIdentifier,
                      exchange_cert: rfc9480.CMPCertificate,
                      server_private_key: ECDHPrivateKey):
        """Prepare a KeyAgreeRecipientInfo object for testing.

        :param ee_pub_key: The end-entity's public key.
        :param key_agreement_oid: The OID for the key agreement algorithm.
        :param exchange_cert: The certificate used for key exchange.
        :param server_private_key: The server's private key for key agreement.
        :return: A RecipientInfo object containing KeyAgreeRecipientInfo.
        """
        ecc_cms_info = encoder.encode(
            prepare_ecc_cms_shared_info(
                key_wrap_oid=rfc9481.id_aes256_wrap,
                ukm=None,
                supp_pub_info=256,
            )
        )

        shared_secret = perform_ecdh(server_private_key, ee_pub_key)
        k = compute_ansi_x9_63_kdf(shared_secret, 32,
                                   other_info=ecc_cms_info,
                                   use_version_2=True)
        encrypted_key = aes_key_wrap(
            key_to_wrap=self.content_encryption_key,
            wrapping_key=k
        )

        # Version MUST be 3 for KARI.
        kari = prepare_key_agreement_recipient_info(
            version=3,
            cmp_cert=exchange_cert,
            encrypted_key=encrypted_key,
            key_agreement_oid=key_agreement_oid,
            key_wrap_oid=rfc9481.id_aes256_wrap,
        )

        recip_info = rfc5652.RecipientInfo()
        recip_info.setComponentByName("kari", kari)
        return recip_info

    def test_kari_with_client_ec_request(self):
        """
        GIVEN a client requesting a key update using an EC key
        WHEN processing the KeyAgreeRecipientInfo in the CMP message
        THEN the extracted private key should match the newly generated key
        """
        new_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        issued_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )

        # Client's EC private key requesting a new key
        ee_key = load_private_key_from_file("data/keys/client-key-ec.pem")
        ee_pub_key = ee_key.public_key()

        recip_info = self._prepare_kari(
            ee_pub_key=ee_pub_key,
            key_agreement_oid=rfc9481.id_alg_ESDH,
            exchange_cert=self.cmp_prot_cert,
            server_private_key=self.kga_signing_key,
        )

        sender_kid = get_field_from_certificate(self.cmp_prot_cert, extension="ski")
        ca_message = build_complete_envelope_data_ca_msg(
            kga_certificate=self.kga_certificate,
            kga_signing_key=self.kga_signing_key,
            version=2,
            kga_cert_chain=[self.kga_certificate, self.trusted_root],
            recipient_infos=[recip_info],
            private_keys=[new_key],
            content_encryption_key=self.content_encryption_key,
            issued_cert=issued_cert,
            extra_certs=[self.cmp_prot_cert, self.trusted_root],
            sender_kid=sender_kid,
        )

        extracted_private_key = validate_not_local_key_gen(
            ca_message, trustanchors="data/unittest", ee_key=ee_key,
        )

        extracted_private_key_bytes = private_key_to_pkcs8(extracted_private_key)
        new_key_bytes = private_key_to_pkcs8(new_key)

        self.assertEqual(extracted_private_key.public_key(), new_key.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)

    def test_kari_with_client_x25519_request(self):
        """
        GIVEN a client requesting a key update using an X25519 key
        WHEN processing the KeyAgreeRecipientInfo in the CMP message
        THEN the extracted private key should match the newly generated key
        """
        new_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        issued_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )

        # Client's X25519 private key requesting a new key
        ee_key = load_private_key_from_file("data/keys/client-key-x25519.pem")
        ee_pub_key = ee_key.public_key()

        recip_info = self._prepare_kari(
            ee_pub_key=ee_pub_key,
            key_agreement_oid=rfc9481.id_X25519,
            exchange_cert=self.server_x25519_cert,
            server_private_key=self.server_x25519_key,
        )

        sender_kid = get_field_from_certificate(self.server_x25519_cert, extension="ski")
        ca_message = build_complete_envelope_data_ca_msg(
            kga_certificate=self.kga_certificate,
            kga_signing_key=self.kga_signing_key,
            version=2,
            kga_cert_chain=[self.kga_certificate, self.trusted_root],
            recipient_infos=[recip_info],
            private_keys=[new_key],
            content_encryption_key=self.content_encryption_key,
            issued_cert=issued_cert,
            extra_certs=[self.server_x25519_cert, self.cmp_prot_cert, self.trusted_root],
            sender_kid=sender_kid,
        )

        extracted_private_key = validate_not_local_key_gen(
            ca_message, trustanchors="data/unittest", ee_key=ee_key,
        )

        extracted_private_key_bytes = private_key_to_pkcs8(extracted_private_key)
        new_key_bytes = private_key_to_pkcs8(new_key)

        self.assertEqual(extracted_private_key.public_key(), new_key.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)

    def test_kari_with_ecc_mvq(self):
        """
        GIVEN a client requesting a key update using EC keys with MQV (Menezes-Qu-Vanstone) key agreement
        WHEN processing the KeyAgreeRecipientInfo with MQV in the CMP message
        THEN the extracted private key should match the newly generated key
        """
        new_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        issued_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )

        # Client's EC private key requesting a new key
        ee_key = load_private_key_from_file("data/keys/client-key-ec.pem")

        kek, mqv_ukm = perform_sender_ecdh_one_pass_mqv(
            sender_static_key=self.kga_signing_key,
            ephemeral_key=None,
            recipient_key=ee_key.public_key(),
            key_wrap_oid=rfc9481.id_aes256_wrap,
            hash_alg="sha256",
        )

        encrypted_key = aes_key_wrap(
            wrapping_key=kek,
            key_to_wrap=self.content_encryption_key
        )

        # Version MUST be 3 for KARI.
        kari = prepare_key_agreement_recipient_info(
            version=3,
            ukm=mqv_ukm,
            cmp_cert=self.cmp_prot_cert,
            encrypted_key=encrypted_key,
            key_agreement_oid=rfc9481.mqvSinglePass_sha256kdf_scheme,
        )
        recip_info = rfc5652.RecipientInfo()
        recip_info.setComponentByName("kari", kari)

        sender_kid = get_field_from_certificate(self.cmp_prot_cert, extension="ski")
        ca_message = build_complete_envelope_data_ca_msg(
            kga_certificate=self.kga_certificate,
            kga_signing_key=self.kga_signing_key,
            version=2,
            kga_cert_chain=[self.kga_certificate, self.trusted_root],
            recipient_infos=[recip_info],
            private_keys=[new_key],
            content_encryption_key=self.content_encryption_key,
            issued_cert=issued_cert,
            extra_certs=[self.cmp_prot_cert, self.trusted_root],
            sender_kid=sender_kid,
        )

        extracted_private_key = validate_not_local_key_gen(
            ca_message, trustanchors="data/unittest", ee_key=ee_key,
        )

        extracted_private_key_bytes = private_key_to_pkcs8(extracted_private_key)
        new_key_bytes = private_key_to_pkcs8(new_key)

        self.assertEqual(extracted_private_key.public_key(), new_key.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)

    def test_kari_with_ecc_mvq2(self):
        """
        GIVEN a client requesting a key update using EC keys with MQV (Menezes-Qu-Vanstone) key agreement
        WHEN processing the KeyAgreeRecipientInfo with MQV in the CMP message
        THEN the extracted private key should match the newly generated key
        """

        new_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        issued_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )

        # Client's EC private key requesting a new key
        ee_key = load_private_key_from_file("data/keys/client-key-ec.pem")

        kari = envdatautils.prepare_kari(
            sender_private_key=self.kga_signing_key,
            public_key=ee_key.public_key(),
            cmp_protection_cert=self.cmp_prot_cert,
            key_wrap_oid=rfc9481.id_aes256_wrap,
            use_mvq=True,
            hash_alg="sha256",
            ukm=os.urandom(16),
            cek=self.content_encryption_key,
        )

        self.assertEqual(kari["keyEncryptionAlgorithm"]["algorithm"],
                         rfc9481.mqvSinglePass_sha256kdf_scheme)

        recip_info = rfc5652.RecipientInfo()
        recip_info.setComponentByName("kari", kari)

        sender_kid = get_field_from_certificate(self.cmp_prot_cert, extension="ski")
        ca_message = build_complete_envelope_data_ca_msg(
            kga_certificate=self.kga_certificate,
            kga_signing_key=self.kga_signing_key,
            version=2,
            kga_cert_chain=[self.kga_certificate, self.trusted_root],
            recipient_infos=[recip_info],
            private_keys=[new_key],
            content_encryption_key=self.content_encryption_key,
            issued_cert=issued_cert,
            extra_certs=[self.cmp_prot_cert, self.trusted_root],
            sender_kid=sender_kid,
        )

        extracted_private_key = validate_not_local_key_gen(
            ca_message, trustanchors="data/unittest", ee_key=ee_key,
        )

        extracted_private_key_bytes = private_key_to_pkcs8(extracted_private_key)
        new_key_bytes = private_key_to_pkcs8(new_key)

        self.assertEqual(extracted_private_key.public_key(), new_key.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)


if __name__ == '__main__':
    unittest.main()
