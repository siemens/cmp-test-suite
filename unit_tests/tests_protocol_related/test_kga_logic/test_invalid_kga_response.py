# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.ca_kga_logic import validate_not_local_key_gen
from resources.ca_ra_utils import build_kga_cmp_response
from resources.cmputils import build_ir_from_key
from resources.exceptions import InvalidKeyData, MismatchingKey
from resources.protectionutils import protect_pkimessage
from resources.suiteenums import InvalidOneAsymKeyType
from unit_tests.utils_for_test import load_ca_cert_and_key, load_kga_cert_chain_and_key


class TestInvalidKeyKGAResponse(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.kga_cert_chain = [cls.ca_cert]
        cls.kga_cert_chain, cls.kga_key = load_kga_cert_chain_and_key()


    @staticmethod
    def _get_ir_request() -> PKIMessageTMP:
        """Returns a fresh KGA request."""
        ir = build_ir_from_key(
            None,
            pvno=3,
            for_kga=True,
            for_mac=False,
        )
        protected_ir = protect_pkimessage(
            ir,
            protection="pbmac1",
            password="SiemensIT"
        )
        return protected_ir

    def _build_invalid_kga_response(self,
            invalid_kga_operation: str,
            default_key_type: str = "rsa",
                                    ) -> PKIMessageTMP:
        """Build a KGA response with an invalid kga operation."""


        ip, _ = build_kga_cmp_response(
            password="SiemensIT",
            request=self._get_ir_request(),
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            kga_cert_chain=self.kga_cert_chain,
            kga_key=self.kga_key,
            default_key_type=default_key_type,
            invalid_kga_operation=invalid_kga_operation,
        )
        protected_ip = protect_pkimessage(
            ip,
            protection="pbmac1",
            password="SiemensIT"
        )
        return protected_ip

    def test_mis_matching_key_pair(self):
        """
        GIVEN a KGA request with an invalid rsa key pair.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        response = self._build_invalid_kga_response(InvalidOneAsymKeyType.INVALID_KEY_PAIR.value)
        with self.assertRaises(InvalidKeyData):
            validate_not_local_key_gen(
                response,
                password="SiemensIT",
                expected_type="pwri"
            )

    def test_mis_matching_key_pair_cert(self):
        """
        GIVEN a KGA request with an valid rsa key pair, but the public key inside the certificate is different.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        response = self._build_invalid_kga_response(InvalidOneAsymKeyType.INVALID_KEY_PAIR_CERT.value)
        with self.assertRaises(MismatchingKey):
            validate_not_local_key_gen(
                response,
                password="SiemensIT",
                expected_type="pwri"
            )

    def test_kga_invalid_private_key(self):
        """
        GIVEN a KGA request with an invalid rsa private key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        response = self._build_invalid_kga_response(
            InvalidOneAsymKeyType.INVALID_PRIVATE_KEY_SIZE.value,
            default_key_type="rsa",
        )
        with self.assertRaises(InvalidKeyData):
            validate_not_local_key_gen(
                response,
                password="SiemensIT",
                expected_type="pwri"
            )

    def test_kga_invalid_public_key(self):
        """
        GIVEN a KGA request with an invalid ml-dsa-44 public key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        response = self._build_invalid_kga_response(
            InvalidOneAsymKeyType.INVALID_PUBLIC_KEY_SIZE.value,
            default_key_type="ml-dsa-44",
        )
        with self.assertRaises(InvalidKeyData):
            validate_not_local_key_gen(
                response,
                password="SiemensIT",
                expected_type="pwri"
            )

    def test_kga_invalid_version_v1(self):
        """
        GIVEN a KGA request with the public key present in version 1.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        response = self._build_invalid_kga_response(
            InvalidOneAsymKeyType.INVALID_VERSION_V1.value,
            default_key_type="ml-dsa-44",
        )
        with self.assertRaises(InvalidKeyData):
            validate_not_local_key_gen(
                response,
                password="SiemensIT",
                expected_type="pwri"
            )

    def test_kga_invalid_version(self):
        """
        GIVEN a KGA request with an invalid version number 3.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        response = self._build_invalid_kga_response(
            InvalidOneAsymKeyType.INVALID_VERSION.value,
            default_key_type="ml-dsa-44",
        )
        with self.assertRaises(InvalidKeyData):
            validate_not_local_key_gen(
                response,
                password="SiemensIT",
                expected_type="pwri"
            )
