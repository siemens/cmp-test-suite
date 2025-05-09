# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480

from resources.ca_ra_utils import build_ccp_from_ccr
from resources.certbuildutils import prepare_cert_template, prepare_extensions, default_validity
from resources.prepare_alg_ids import prepare_sig_alg_id
from resources.cmputils import build_ccr_from_key, prepare_signature_popo
from resources.exceptions import BadCertTemplate, BadPOP, BadRequest
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestBuildCppFromCrr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ml_kem_key = load_private_key_from_file("data/keys/private-key-ml-kem-512-seed.pem")
        cls.sender = "CN=Hans the CA Tester"

    def _generate_valid_ccr_template(self) -> rfc9480.CertTemplate:
        """Generate a valid certificate template."""

        alg_id = prepare_sig_alg_id(
            signing_key=self.ca_key,
        )
        return prepare_cert_template(
            subject="CN=Test",
            key=self.rsa_key,
            issuer="CN=Test",
            validity=default_validity(),
            version="v3",
            include_fields="version,issuer,subject,validity,publicKey,signingAlg",
            sign_alg=alg_id,
        )

    def test_build_ccp_from_crr(self):
        """
        GIVEN a CRR and a CA certificate and key.
        WHEN the CRR is used to build a CPP.
        THEN the CPP should be successfully built.
        """
        cert_template = self._generate_valid_ccr_template()
        ccr = build_ccr_from_key(self.rsa_key, sender="CN=Hans the CA Tester",
                                 common_name="CN=Hans the CA Tester 2", cert_template=cert_template,
                                 exclude_fields=None,
                                 )
        ccp, certs = build_ccp_from_ccr(ccr, ca_cert=self.ca_cert, ca_key=self.ca_key)
        self.assertEqual(len(certs), 1)
        self.assertEqual(len(ccp["body"]["ccp"]["response"]), 1)
        self.assertEqual(str(ccp["header"]["recipient"]["rfc822Name"]), "CN=Hans the CA Tester")

    def test_build_ccp_from_crr_valid_ku(self):
        """
        GIVEN a CRR with a valid Key Usage extension including 'keyCertSign' and 'digitalSignature'.
        WHEN the CRR is used to build a CPP.
        THEN the CPP should be successfully built and contain the correct recipient and response structure.
        """
        cert_template = self._generate_valid_ccr_template()
        extns = prepare_extensions(
            key_usage="keyCertSign,digitalSignature",
        )
        cert_template["extensions"].extend(extns)
        ccr = build_ccr_from_key(
            self.rsa_key,
            sender="CN=Hans the CA Tester",
            common_name="CN=Hans the CA Tester 2",
            extensions=extns,
            cert_template=cert_template,
            exclude_fields=None,
        )
        ccp, certs = build_ccp_from_ccr(ccr, ca_cert=self.ca_cert, ca_key=self.ca_key)
        self.assertEqual(len(certs), 1)
        self.assertEqual(len(ccp["body"]["ccp"]["response"]), 1)
        self.assertEqual(str(ccp["header"]["recipient"]["rfc822Name"]), "CN=Hans the CA Tester")

    def test_build_ccp_from_crr_invalid_popo(self):
        """
        GIVEN a CRR with an invalid Proof of Possession (PoP).
        WHEN the CRR is used to build a CPP.
        THEN the function should raise a BadPOP exception.
        """
        ccr = build_ccr_from_key(
            self.rsa_key,
            sender="CN=Hans the CA Tester",
            common_name="CN=Hans the CA Tester",
            bad_pop=True,
            exclude_fields=None,
        )

        with self.assertRaises(BadPOP):
            build_ccp_from_ccr(ccr, ca_cert=self.ca_cert, ca_key=self.ca_key)

    def test_build_ccp_from_crr_invalid_for_kga(self):
        """
        GIVEN a CRR that is marked for Key Generation Authority (KGA).
        WHEN the CRR is used to build a CPP with an incompatible CA key.
        THEN the function should raise a `BadCertTemplate` exception.
        """
        ccr = build_ccr_from_key(
            self.rsa_key, for_kga=True, sender="CN=Hans the CA Tester",
            common_name="CN=Hans the CA Tester",exclude_fields=None,
        )

        with self.assertRaises(BadCertTemplate):
            build_ccp_from_ccr(ccr, ca_cert=self.ca_cert, ca_key=self.ml_kem_key)

    def test_build_ccp_from_crr_invalid_cert_req_id(self):
        """
        GIVEN a CRR with an invalid certificate request ID.
        WHEN the CRR is used to build a CPP.
        THEN the function should raise a BadRequest exception.
        """
        ccr = build_ccr_from_key(
            self.rsa_key,
            sender="CN=Hans the CA Tester",
            common_name="CN=Hans the CA Tester",
            cert_req_id=2,
            exclude_fields=None,
        )
        with self.assertRaises(BadRequest):
            build_ccp_from_ccr(ccr, ca_cert=self.ca_cert, ca_key=self.ca_key)

    def test_build_ccp_from_crr_invalid_key_usage(self):
        """
        GIVEN a CRR with an invalid Key Usage extension that does not include 'keyCertSign'.
        WHEN the CRR is used to build a CPP.
        THEN the function should raise a BadCertTemplate exception.
        """
        extensions = prepare_extensions(
            key_usage="keyEncipherment",
        )
        ccr = build_ccr_from_key(
            self.rsa_key,
            sender=self.sender,
            common_name=self.sender,
            extensions=extensions,
            exclude_fields=None,
        )
        with self.assertRaises(BadCertTemplate):
            build_ccp_from_ccr(ccr, ca_cert=self.ca_cert, ca_key=self.ca_key)