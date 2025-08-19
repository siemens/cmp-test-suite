# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import List, Tuple

from pyasn1_alt_modules import rfc9480

from pq_logic.keys.sig_keys import MLDSAPrivateKey
from resources.asn1_structures import PKIMessageTMP
from resources.ca_kga_logic import validate_not_local_key_gen
from resources.ca_ra_utils import build_kga_cmp_response
from resources.certbuildutils import (
    build_certificate,
    prepare_authority_key_identifier_extension,
    prepare_extensions,
    prepare_ski_extension,
)
from resources.cmputils import build_ir_from_key
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage
from unit_tests.utils_for_test import load_ca_cert_and_key, print_extensions


class TestMLDSAKGASigner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.pre_shared_secret = "SiemensIT"

    def _generate_kga_extensions(self, key: MLDSAPrivateKey) -> rfc9480.Extensions:
        """Generate KGA extensions for the given key."""
        extensions = prepare_extensions(
            key_usage="keyAgreement",
            eku="cmKGA",
            critical=False,
        )
        # Must be set to not critical for OpenSSL.
        extn = prepare_ski_extension(key, critical=False)
        # Must be set to not critical for OpenSSL.
        extn2 = prepare_authority_key_identifier_extension(ca_key=self.ca_key.public_key(), critical=False)

        extensions.append(extn)
        extensions.append(extn2)
        return extensions

    def _generate_kga_cert(self, key: MLDSAPrivateKey) -> rfc9480.CMPCertificate:
        """Generate a KGA certificate for the given key."""
        extensions = self._generate_kga_extensions(key)
        cert, _ = build_certificate(
            key,
            extensions=extensions,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            serial_number=1,
            common_name="CN=ML-DSA KGA Test Key",
        )
        return cert

    def _build_kga_cmp_response(
        self,
        ir: PKIMessageTMP,
        kga_key: MLDSAPrivateKey,
    ) -> Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]:
        """Build a CMP response for KGA certificate generation."""
        kga_cert = self._generate_kga_cert(kga_key)

        response, issued_certs = build_kga_cmp_response(
            ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            kga_key=kga_key,
            kga_cert_chain=[self.ca_cert, kga_cert],
            password=self.pre_shared_secret,
        )
        response = protect_pkimessage(response, "password_based_mac", self.pre_shared_secret)
        return response, issued_certs

    def _generate_kga_request(self) -> PKIMessageTMP:
        """Generate a KGA request IR."""
        key = generate_key("rsa")
        ir = build_ir_from_key(key, for_kga=True, pvno=3)
        return protect_pkimessage(ir, "password_based_mac", self.pre_shared_secret)

    def test_mldsa_44_lwcmp_signer(self):
        """
        GIVEN a MLDSA-44 KGA signer for LwCMP.
        WHEN the KGA response is generated,
        THEN it should return a valid PKIMessageTMP response.
        """
        kga_key = generate_key("ml-dsa-44")
        ir = self._generate_kga_request()
        response, issued_certs = self._build_kga_cmp_response(ir, kga_key)
        self.assertIsInstance(response, PKIMessageTMP)
        validate_not_local_key_gen(response, password=self.pre_shared_secret, expected_type="pwri")

    def test_mldsa_65_lwcmp_signer(self):
        """
        GIVEN a MLDSA-65 KGA signer for LwCMP.
        WHEN the KGA response is generated,
        THEN it should return a valid PKIMessageTMP response.
        """
        kga_key = generate_key("ml-dsa-65")
        ir = self._generate_kga_request()
        response, issued_certs = self._build_kga_cmp_response(ir, kga_key)
        self.assertIsInstance(response, PKIMessageTMP)
        validate_not_local_key_gen(response, password=self.pre_shared_secret, expected_type="pwri")

    def test_mldsa_87_lwcmp_signer(self):
        """
        GIVEN a MLDSA-87 KGA signer for LwCMP.
        WHEN the KGA response is generated,
        THEN it should return a valid PKIMessageTMP response.
        """
        kga_key = generate_key("ml-dsa-87")
        ir = self._generate_kga_request()
        response, issued_certs = self._build_kga_cmp_response(ir, kga_key)
        self.assertIsInstance(response, PKIMessageTMP)
        validate_not_local_key_gen(response, password=self.pre_shared_secret, expected_type="pwri")
