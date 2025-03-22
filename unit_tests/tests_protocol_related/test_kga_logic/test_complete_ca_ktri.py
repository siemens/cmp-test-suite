# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc4055, rfc5280, rfc5652, rfc9481
from resources import utils
from resources.ca_kga_logic import validate_not_local_key_gen
from resources.certextractutils import get_field_from_certificate
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_key_transport_recipient_info
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import get_rsa_oaep_padding
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_ca_response import build_complete_envelope_data_ca_msg
from unit_tests.utils_for_test import private_key_to_pkcs8


def _get_alg_id(use_rsa_oaep: bool) -> rfc5652.KeyEncryptionAlgorithmIdentifier:
    """Prepare the KeyEncryptionAlgorithmIdentifier based on whether RSA-OAEP is used.

    :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5.
    :return: A KeyEncryptionAlgorithmIdentifier object configured accordingly.
    """
    key_enc_alg_oaep = rfc5652.KeyEncryptionAlgorithmIdentifier()
    if not use_rsa_oaep:
        key_enc_alg_oaep["algorithm"] = rfc9481.rsaEncryption
        return key_enc_alg_oaep

    oaep_params = rfc4055.RSAES_OAEP_params()
    oaep_params["hashFunc"]["algorithm"] = rfc4055.id_sha384
    oaep_params["maskGenFunc"]["algorithm"] = rfc4055.id_mgf1
    oaep_params["maskGenFunc"]["parameters"] = encoder.encode(rfc4055.id_sha256)

    key_enc_alg_oaep["algorithm"] = rfc4055.id_RSAES_OAEP
    key_enc_alg_oaep["parameters"] = oaep_params
    return key_enc_alg_oaep


def _encrypt_rsa_oaep(key: rsa.RSAPrivateKey, alg_id: rfc5280.AlgorithmIdentifier, content_enc_key):
    """Encrypt the content encryption key using RSA encryption with specified padding.

    :param key: The RSA private key used for encryption.
    :param alg_id: The AlgorithmIdentifier specifying the encryption algorithm and parameters.
    :param content_enc_key: The content encryption key to be encrypted.
    :return: The encrypted content encryption key.
    """
    if alg_id["parameters"].isValue:
        padding_val = get_rsa_oaep_padding(alg_id["parameters"])
    else:
        padding_val = padding.PKCS1v15()

    return key.public_key().encrypt(plaintext=content_enc_key, padding=padding_val)


class TestCAMessageWithEnvelopeDataKTRI(unittest.TestCase):

    def setUp(self):
        self.trustanchors = "data/unittest"
        self.content_encryption_key = b"\xaa" * 16
        self.trusted_root = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem")
        )

        # Load KGA certificate and key
        self.kga_certificate = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/kga_cert_kari_ecdsa.pem")
        )
        self.kga_signing_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

        # Load CMP protection certificate (does not need to be the same as KGA)
        self.cmp_prot_cert = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem")
        )

        # End-entity's RSA private key (client requesting a new private key)
        self.ee_key: rsa.RSAPrivateKey = load_private_key_from_file(
            "data/keys/private-key-rsa.pem", password=None
        )

    def _prepare_ktri(self, use_rsa_oaep: bool):
        """
        Prepare a KeyTransRecipientInfo object for testing.

        :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5 padding.
        :return: A RecipientInfo object containing the KeyTransRecipientInfo.
        """
        key_enc_alg_id = _get_alg_id(use_rsa_oaep=use_rsa_oaep)
        encrypted_key = _encrypt_rsa_oaep(self.ee_key, key_enc_alg_id, self.content_encryption_key)

        # Version MUST be 2 for KTRI.
        ktri = prepare_key_transport_recipient_info(
            version=2,
            key_enc_alg_id=key_enc_alg_id,
            cert=self.kga_certificate,
            encrypted_key=encrypted_key,
        )

        recip_info = rfc5652.RecipientInfo()
        recip_info.setComponentByName("ktri", ktri)
        return recip_info

    def test_valid_envelope_data_with_ktri_for_ecc_with_rsa(self):
        """
        GIVEN a valid KTRI using RSA PKCS#1 v1.5 padding and a content encryption key
        WHEN the CMP message is built and the envelope data is prepared
        THEN validate_not_local_key_gen should validate the envelope data without errors and
        extract the correct RSA private key.
        """
        new_key_ecc = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        issued_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )

        sender_kid = get_field_from_certificate(self.cmp_prot_cert, extension="ski")
        ca_message = build_complete_envelope_data_ca_msg(
            kga_certificate=self.kga_certificate,
            kga_signing_key=self.kga_signing_key,
            version=2,
            kga_cert_chain=[self.kga_certificate, self.trusted_root],
            recipient_infos=[self._prepare_ktri(use_rsa_oaep=False)],
            private_keys=[new_key_ecc],
            content_encryption_key=self.content_encryption_key,
            issued_cert=issued_cert,
            extra_certs=[self.cmp_prot_cert, self.trusted_root],
            sender_kid=sender_kid,
        )

        extracted_private_key = validate_not_local_key_gen(
            ca_message, trustanchors="data/unittest", ee_key=self.ee_key,
        )

        extracted_private_key_bytes = private_key_to_pkcs8(extracted_private_key)
        new_key_bytes = private_key_to_pkcs8(new_key_ecc)

        self.assertEqual(extracted_private_key.public_key(), new_key_ecc.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)

    def test_valid_envelope_data_with_ktri_for_ecc_with_rsa_oaep(self):
        """
        GIVEN a valid KTRI using RSA-OAEP padding and a content encryption key
        WHEN the CMP message is built and the envelope data is prepared
        THEN validate_not_local_key_gen should validate the envelope data without errors and
        extract the correct RSA private key.
        """
        new_key_ecc = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        issued_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )

        sender_kid = get_field_from_certificate(self.cmp_prot_cert, extension="ski")
        ca_message = build_complete_envelope_data_ca_msg(
            kga_certificate=self.kga_certificate,
            kga_signing_key=self.kga_signing_key,
            version=2,
            kga_cert_chain=[self.kga_certificate, self.trusted_root],
            recipient_infos=[self._prepare_ktri(use_rsa_oaep=True)],
            private_keys=[new_key_ecc],
            content_encryption_key=self.content_encryption_key,
            issued_cert=issued_cert,
            extra_certs=[self.cmp_prot_cert, self.trusted_root],
            sender_kid=sender_kid,
        )

        extracted_private_key = validate_not_local_key_gen(
            ca_message, trustanchors="data/unittest", ee_key=self.ee_key,
        )

        extracted_private_key_bytes = private_key_to_pkcs8(extracted_private_key)
        new_key_bytes = private_key_to_pkcs8(new_key_ecc)

        self.assertEqual(extracted_private_key.public_key(), new_key_ecc.public_key())
        self.assertEqual(extracted_private_key_bytes, new_key_bytes)


if __name__ == "__main__":
    unittest.main()
