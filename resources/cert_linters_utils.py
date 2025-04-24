# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Linters for CRLs and OCSP responses using the pkilint tool."""

import logging
from typing import Union

import pyasn1
from cryptography.hazmat.primitives import serialization
from cryptography.x509.ocsp import OCSPResponse
from pkilint import loader, report
from pkilint.pkix import crl, ocsp
from pkilint.pkix.crl import crl_validator
from pkilint.validation import ValidationFindingSeverity
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc6960, rfc8954
from robot.api.deco import keyword

# TODO include other linters.


@keyword(name="Validate CRL Pkilint")
def validate_crl_pkilint(  # noqa D417 undocumented-param
    data: Union[bytes, rfc5280.CertificateList],
) -> None:
    """Validate a CRL using the pkilint tool.

    Arguments:
    ---------
       - ´data´: The CRL data to validate.

    Raises:
    ------
       - ValueError: If the CRL is not valid.

    Examples:
    --------
    | Validate CRL Pkilint | ${crl_data} |

    """
    doc_validator = crl.create_pkix_crl_validator_container(
        [],
        validators=[
            crl_validator.VersionPresenceValidator(),
            crl_validator.SignatureAlgorithmMatchValidator(),
            crl_validator.CorrectVersionValidator(),
        ],
    )

    if isinstance(data, rfc5280.CertificateList):
        data = encoder.encode(data)

    loaded_crl = loader.load_der_crl(data, "dynamic-crl")  # type: ignore
    results = doc_validator.validate(loaded_crl.root)

    # should be `WARNING`, because empty CRL raises an error.

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.WARNING)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.WARNING).generate()
        raise ValueError(issues)

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.INFO)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.INFO).generate()
        logging.info("Findings for INFO: %s", issues)


def _parse_ocsp_response(der_data: bytes) -> rfc8954.BasicOCSPResponse:
    """Parse an OCSP response."""
    decoded = decoder.decode(der_data, asn1Spec=rfc8954.OCSPResponse())[0]
    resp_data = decoded["responseBytes"]
    resp_oid = resp_data["responseType"]
    resp_data = resp_data["response"]

    if rfc8954.id_pkix_ocsp_basic != resp_oid:
        raise ValueError("The response type is not `BasicOCSPResponse`.")

    ocsp_resp = decoder.decode(resp_data, asn1Spec=rfc8954.BasicOCSPResponse())[0]
    return ocsp_resp


def _validate_ocsp_resp_nonce(der_data: bytes) -> None:
    """Validate the nonce in an OCSP response."""
    decoded = _parse_ocsp_response(der_data)
    val = None
    if decoded["tbsResponseData"]["responseExtensions"].isValue:
        for ext in decoded["tbsResponseData"]["responseExtensions"]:
            if ext["extnID"] == rfc8954.id_pkix_ocsp_nonce:
                val = ext["extnValue"].asOctets()
                break

    if val is None:
        logging.info("No nonce found in the OCSP response")
        return
    try:
        _ = decoder.decode(val, asn1Spec=rfc8954.Nonce())
    except pyasn1.type.error.ValueConstraintError:  # type: ignore
        raise ValueError(  # pylint: disable=raise-missing-from
            "The OCSP response nonce is not in the allowed range of 1-32 bytes.According to RFC rfc8954."
        )


@keyword(name="Validate OCSP Pkilint")
def validate_ocsp_pkilint(  # noqa D417 undocumented-param
    data: Union[bytes, rfc8954.BasicOCSPResponse, OCSPResponse],
) -> None:
    """Validate an OCSP response using the pkilint tool.

    Arguments:
    ---------
       - data: The OCSP response data to validate. This can be either the DER-encoded
               bytes of an OCSP response or an OCSP response object (e.g. from rfc6960).

    Raises:
    ------
       - ValueError: If the OCSP response is not valid (i.e. if warnings are found).

    Examples:
    --------
    | Validate OCSP Pkilint | ${ocsp_data} |

    """
    if isinstance(data, rfc6960.BasicOCSPResponse):
        data = encoder.encode(data)

    elif isinstance(data, OCSPResponse):
        data = data.public_bytes(serialization.Encoding.DER)

    loaded_ocsp = loader.load_ocsp_response(data, "dynamic-ocsp")

    doc_validator = ocsp.create_pkix_ocsp_response_validator_container(
        [],
        validators=[
            ocsp.ocsp_response.OCSPResponseStatusValidator(),
            ocsp.ocsp_response.OCSPResponseIsBasicValidator(),
            ocsp.ocsp_basic_response.OCSPBasicResponseCertsNotPresentValidator(),
            ocsp.ocsp_validity.OCSPSaneValidityPeriodValidator(),
        ],
    )

    results = doc_validator.validate(loaded_ocsp.root)

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.WARNING)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.WARNING).generate()
        raise ValueError(issues)

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.INFO)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.INFO).generate()
        logging.info("Findings for INFO: %s", issues)

    _validate_ocsp_resp_nonce(data)  # type: ignore
