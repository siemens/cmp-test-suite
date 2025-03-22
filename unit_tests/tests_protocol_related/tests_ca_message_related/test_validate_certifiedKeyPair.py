# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources import cmputils
from resources.certutils import parse_certificate
from resources.checkutils import validate_certified_key_pair_structure
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_ca_response import build_ca_pki_message
from unit_tests.utils_for_test import prepare_default_pwri_env_data


class TestCheckCaPubs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    def test_valid_validate_certifiedKeyPair_pvno(self):
        """
        GIVEN a CA PKI message with a protocol version set to 3 and a valid `envelopeData`
        structure set as the `privateKey`
        WHEN validate_certifiedKeyPair_pvno is called with local_key_gen set to False.
        THEN it should validate the message without raising any exceptions.
        """
        # must have ALL mandatory value!
        # cannot set an empty structure, will be deleted while assigned to EncryptedKey.
        env_data = prepare_default_pwri_env_data()

        ca_message = build_ca_pki_message(pvno=3, private_key=env_data, cert=self.root_cert)
        validate_certified_key_pair_structure(ca_message, local_key_gen=False)

    def test_invalid_validate_certifiedKeyPair_local_key_gen(self):
        """
        GIVEN a CA PKI message with a protocol version set to 3 and a valid `envelopeData`
        structure set as the `privateKey`
        WHEN validate_certifiedKeyPair_pvno is called with local_key_gen set to `True`.
        THEN it should raise a ValueError due to the local key generation, which means that the
        `privateKey` field must be absent.
        """
        # must have ALL mandatory value!
        # cannot set an empty structure, will be deleted while assigned to EncryptedKey.
        env_data = prepare_default_pwri_env_data()

        ca_message = build_ca_pki_message(pvno=3, private_key=env_data, cert=self.root_cert)
        with self.assertRaises(ValueError):
            validate_certified_key_pair_structure(ca_message, local_key_gen=True)

    def test_invalid_validate_certifiedKeyPair_pvno_private_key(self):
        """
        GIVEN a CA PKI message with a protocol version set to 2 and a valid `envelopeData`
        structure set as the `privateKey`
        WHEN validate_certifiedKeyPair_pvno is called with local_key_gen set to True.
        THEN it should raise a ValueError due to protocol version mismatch.
        """
        # must have ALL mandatory value!
        # cannot set an empty structure, will be deleted while assigned to EncryptedKey.
        env_data = prepare_default_pwri_env_data()

        ca_message = build_ca_pki_message(pvno=2, private_key=env_data, cert=self.root_cert)
        cert_response = cmputils.get_cert_response_from_pkimessage(ca_message, response_index=0)

        self.assertTrue(cert_response["certifiedKeyPair"]["privateKey"].isValue,
                        "The prepare function failed to create a structure to test.")
        self.assertEqual(cert_response["certifiedKeyPair"]["privateKey"].getName(), "envelopedData",
                         "The prepare function failed to create a structure to test.")

        with self.assertRaises(ValueError):
            validate_certified_key_pair_structure(ca_message, local_key_gen=True)

    def test_invalid_validate_certifiedKeyPair_pvno_enc_cert(self):
        """
        GIVEN a CA PKI message with a protocol version set to 2 and a valid `envelopeData` structure
        set as the encrypted certificate.
        WHEN validate_certifiedKeyPair_pvno is called,
        THEN it should raise a ValueError due to protocol version mismatch.
        """
        # must have ALL mandatory value!
        # cannot set an empty structure, will be deleted while assigned to EncryptedKey.
        env_data = prepare_default_pwri_env_data()

        ca_message = build_ca_pki_message(pvno=2, enc_cert=env_data)
        with self.assertRaises(ValueError):
            validate_certified_key_pair_structure(ca_message)
