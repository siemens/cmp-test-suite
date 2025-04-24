# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import prepare_new_root_ca_certificate
from resources.announcement import build_cmp_ckuann_message
from resources.certbuildutils import build_certificate
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestBuildCmpCkuann(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.new_key = load_private_key_from_file(
            "data/keys/private-key-ml-dsa-44.pem",
        )

    def _build_old_cert(self) -> rfc9480.CMPCertificate:
        """Prepare an old certificate."""
        old_cert, _ = build_certificate(
            self.old_key,
            common_name="CN=Root CA OLD",
        )
        return old_cert

    def test_build_cmp_ckuann_with_structure(self):
        """
        Given a Root CA certificate, build a CMP CKUANN message.
        WHEN the Root CA certificate is updated with a new key,
        THEN a CMP `ckuann` message is built correctly.
        """
        root_ca = prepare_new_root_ca_certificate(
            old_cert=self._build_old_cert(),
            old_priv_key=self.old_key,
            new_priv_key=self.new_key,
        )
        pki_message = build_cmp_ckuann_message(root_ca_key_update=root_ca)
        der_data = try_encode_pyasn1(pki_message)
        decoded_pki_message, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())
        self.assertEqual(rest, b"")

    def test_build_cmp_ckuann(self):
        """
        Given a Root CA certificate, build a CMP CKUANN message.
        WHEN the Root CA certificate is updated with a new key,
        THEN a CMP `ckuann` message is built correctly.
        """
        pki_message = build_cmp_ckuann_message(
            old_cert=self._build_old_cert(),
            new_cert=self._build_old_cert(),
            old_key=self.old_key,
            new_key=self.new_key,
        )
        der_data = try_encode_pyasn1(pki_message)
        decoded_pki_message, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())
        self.assertEqual(rest, b"")
