# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import logging
import unittest

from mock_ca.ca_handler import CAHandler
from pkilint import loader, report
from pkilint.pkix import certificate, extension, name
from pkilint.validation import ValidationFindingSeverity
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480

from resources import convertutils
from resources.certbuildutils import build_certificate, prepare_extensions
from resources.certutils import parse_certificate, validate_certificate_pkilint
from resources.cmputils import build_ir_from_key, get_cert_from_pkimessage
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file


def _validate_cert_without_crl_and_ocsp_url(data: rfc9480.CMPCertificate) -> None:
    """Validate a certificate without CRL and OCSP URL.

    Raise an error only if all issues are related to invalid URI syntax in CRL or OCSP URLs.

    :param data: The certificate data to validate.
    :return: None
    """
    # Deep copy and encode certificate
    data = convertutils.copy_asn1_certificate(data)
    encoded_cert = encoder.encode(data)

    # Set up the certificate validator
    doc_validator = certificate.create_pkix_certificate_validator_container(
        certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
        [
            certificate.create_issuer_validator_container([]),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container([]),
            certificate.create_extensions_validator_container([]),
        ],
    )

    # Load and validate certificate
    cert = loader.load_certificate(encoded_cert, "dynamic-cert")
    results = doc_validator.validate(cert.root)

    # Generate report
    report_generator = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.WARNING)

    # Collect all findings
    findings = []
    for val_result in report_generator.results:
        for finding in val_result.finding_descriptions:
            message = finding.message
            if message is None:
                continue

            findings.append(
                {
                    "severity": finding.finding.severity,
                    "message": finding.message,
                    "code": finding.finding.code,
                    "node_path": val_result.node.path,
                }
            )

    if not findings:
        return  # No warnings, validation passed

    # Identify non-CRL/OCSP URI syntax issues
    non_crl_ocsp_uri_issues = [
        f
        for f in findings
        if not (
            f["code"] == "pkix.invalid_uri_syntax"
            and ("authorityInfoAccess" in f["node_path"] or "cRLDistributionPoints" in f["node_path"])
        )
    ]

    if not non_crl_ocsp_uri_issues:
        logging.info("Validation failed only due to invalid URI syntax in CRL or OCSP URLs.")
    else:
        messages = "\n".join(f"{f['code']} @ {f['node_path']}: {f['message']}" for f in non_crl_ocsp_uri_issues)
        raise ValueError(f"Validation failed due to other issues:\n{messages}")


class TestMockCaIssueCertLint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ecdsa_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.ed_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        cls.root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    def test_issue_cert_ecdsa(self):
        """
        GIVEN valid extensions and a build ECDSA certificate.
        WHEN the certificate is validated,
        THEN should the certificate be accepted.
        """
        extensions = prepare_extensions(key=self.ecdsa_key, ca_key=self.ecdsa_key.public_key(), critical=False)
        cert, key = build_certificate(self.ecdsa_key, extensions=extensions)
        validate_certificate_pkilint(cert)

    def test_issue_cert_rsa(self):
        """
        GIVEN valid extensions and a build RSA certificate.
        WHEN the certificate is validated,
        THEN should the certificate be accepted.
        """
        extensions = prepare_extensions(key=self.rsa_key, ca_key=self.rsa_key.public_key(), critical=False)
        cert, key = build_certificate(self.rsa_key, extensions=extensions, ra_verified=True, use_rsa_pss=False)
        validate_certificate_pkilint(cert)

    def test_issue_cert_rsa_pss(self):
        """
        GIVEN valid extensions and a build RSA-PSS certificate.
        WHEN the certificate is validated,
        THEN should the certificate be accepted.
        """
        extensions = prepare_extensions(key=self.rsa_key, ca_key=self.rsa_key.public_key(), critical=False)
        cert, key = build_certificate(self.rsa_key, extensions=extensions, ra_verified=True, use_rsa_pss=True)
        validate_certificate_pkilint(cert)

    def test_issue_with_mock_ca(self):
        """
        GIVEN valid extensions and an IR.
        WHEN the MOCK-CA processes the certificate request,
        THEN should a valid certificate be created.
        """
        handler = CAHandler(ca_cert=self.root_cert, ca_key=self.ed_key, config={}, pre_shared_secret=b"SiemensIT")
        ir = build_ir_from_key(self.rsa_key, for_mac=True, sender="CN=Hans the Tester")
        prot_ir = protect_pkimessage(ir, "pbmac1", password=b"SiemensIT")
        response = handler.process_normal_request(prot_ir)
        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        cert = get_cert_from_pkimessage(pki_message=response)
        _validate_cert_without_crl_and_ocsp_url(cert)
