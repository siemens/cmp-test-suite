# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import List, Tuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pyasn1_alt_modules import rfc9480

from pq_logic.keys.composite_sig07 import CompositeSig07PrivateKey
from resources.asn1_structures import PKIMessageTMP
from resources.ca_kga_logic import validate_not_local_key_gen
from resources.ca_ra_utils import build_kga_cmp_response
from resources.certbuildutils import (
    build_certificate,
    prepare_authority_key_identifier_extension,
    prepare_extensions,
    prepare_ski_extension,
)
from resources.certutils import load_public_key_from_cert
from resources.cmputils import build_ir_from_key
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestCompositeSigKGASigner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.pre_shared_secret = "SiemensIT"

    def _generate_kga_extensions(self, key: CompositeSig07PrivateKey) -> rfc9480.Extensions:
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

    def _generate_kga_cert(self, key: CompositeSig07PrivateKey) -> rfc9480.CMPCertificate:
        """Generate a KGA certificate for the given key."""
        extensions = self._generate_kga_extensions(key)
        cert, _ = build_certificate(
            key,
            extensions=extensions,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            serial_number=1,
            common_name="CN=Composite KGA Test Key",
        )
        return cert

    def _build_kga_cmp_response(
        self,
        ir: PKIMessageTMP,
        kga_key: CompositeSig07PrivateKey,
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

    def test_kga_with_composite_sig_key(self):
        """
        GIVEN a Composite-signature KGA signer with RSA as the traditional key.
        WHEN the KGA response is generated,
        THEN it should return a valid PKIMessageTMP response.
        """
        prot_ir = self._generate_kga_request()
        kga_key = generate_key("composite-sig", trad_name="rsa")
        response, issued_certs = self._build_kga_cmp_response(prot_ir, kga_key)
        self.assertIsInstance(response, PKIMessageTMP)
        public_key = load_public_key_from_cert(issued_certs[0])
        self.assertIsInstance(public_key, RSAPublicKey)
        validate_not_local_key_gen(response, password=self.pre_shared_secret, expected_type="pwri")

    def test_kga_with_composite_ecdsa_key(self):
        """
        GIVEN a Composite-signature KGA signer with ECDSA as the traditional key.
        WHEN the KGA response is generated,
        THEN it should return a valid PKIMessageTMP response.
        """
        prot_ir = self._generate_kga_request()
        kga_key = generate_key("composite-sig", trad_name="ecdsa")
        response, issued_certs = self._build_kga_cmp_response(prot_ir, kga_key)
        self.assertIsInstance(response, PKIMessageTMP)
        public_key = load_public_key_from_cert(issued_certs[0])
        self.assertIsInstance(public_key, RSAPublicKey)
        validate_not_local_key_gen(response, password=self.pre_shared_secret, expected_type="pwri")

    def test_kga_with_composite_sig_ed25519_key(self):
        """
        GIVEN a Composite-signature KGA signer with Ed25519 as the traditional key.
        WHEN the KGA response is generated,
        THEN it should return a valid PKIMessageTMP response.
        """
        prot_ir = self._generate_kga_request()
        kga_key = generate_key("composite-sig", trad_name="ed25519")
        response, issued_certs = self._build_kga_cmp_response(prot_ir, kga_key)
        self.assertIsInstance(response, PKIMessageTMP)
        public_key = load_public_key_from_cert(issued_certs[0])
        self.assertIsInstance(public_key, RSAPublicKey)
        validate_not_local_key_gen(response, password=self.pre_shared_secret, expected_type="pwri")


if __name__ == "__main__":
    unittest.main(verbosity=2, failfast=True)
