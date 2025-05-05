# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for extracting information from certificates and CSRs.

Like the SubjectKeyIdentifier, KeyUsage, and ExtendedKeyUsage extensions.
The SubjectKeyIdentifier is extracted from a certificate, because this extension needs to be the same
as the `senderKID` for the `PKIHeader` or inside the recipient identifier in the `RecipientInfo` for the `EnvelopedData`
structure, which is used to securely exchange data between two parties.
"""

import logging
from typing import Optional, Union

from pyasn1.codec.der import decoder
from pyasn1.type import base, univ
from pyasn1_alt_modules import rfc5280, rfc6402, rfc9480
from pyasn1_alt_modules.rfc5652 import Attribute
from robot.api.deco import not_keyword

from resources import asn1utils
from resources.exceptions import BadAsn1Data
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import EXTENSION_NAME_2_OID, EXTENSION_OID_2_SPECS

# TODO refactor.


def cert_contains_extension(  # noqa D417 undocumented-param
    cert_or_extn: Union[rfc9480.CMPCertificate, rfc9480.Extensions],
    name_or_oid: str,
    must_be_non_crit: Optional[bool] = None,
    must_be_crit: Optional[bool] = None,
) -> None:
    """Check if a certificate or extensions object contains the given extension.

    Arguments:
    ---------
        - `cert_or_extn`: The certificate or extensions object to search.
        - `name_or_oid`: The OID or name of the extension.
        - `must_be_non_crit`: If `True`, ensure the extension is non-critical. Defaults to `disabled`.
        - `must_be_crit`: If `True`, ensure the extension is critical. Defaults to `disabled`.

    Raises:
    ------
        - `ValueError`: If the extension is not found.
        - `ValueError`: If the extension is critical and `must_be_non_crit` is `True`.
        - `ValueError`: If the extension is non-critical and `must_be_crit` is `True`.
        - `KeyError`: If the extension name is not found in the mapping.

    Examples:
    --------
    | Cert Contains Extension | ${certificate} | key_usage | must_be_non_crit=${True} |
    | Cert Contains Extension | ${extension} | eku | must_be_crit=${True} |
    | Cert Contains Extension | ${cert_template["extensions"]} | 1.2.840.113549.1.9.14 |

    """
    if "." in name_or_oid:
        oid = univ.ObjectIdentifier(name_or_oid)
    elif name_or_oid in EXTENSION_NAME_2_OID:
        oid = EXTENSION_NAME_2_OID[name_or_oid]
    else:
        raise KeyError(
            f"Extension name not found: {name_or_oid}, a"
            "please have a look at the OID mapping `EXTENSION_NAME_2_OID`."
            f"Currently supported extension names are: {list(EXTENSION_NAME_2_OID.keys())}"
        )

    if isinstance(cert_or_extn, rfc9480.CMPCertificate):
        cert_or_extn = cert_or_extn["tbsCertificate"]["extensions"]

    out = get_extension(
        cert_or_extn,  # type: ignore
        oid,
        must_be_non_crit=must_be_non_crit,
        must_be_crit=must_be_crit,
    )

    if out is None:
        name = may_return_oid_to_name(oid)
        raise ValueError(f"Extension {name}:{oid} is not present.")


def extension_must_be_non_critical(  # noqa D417 undocumented-param
    cert_or_extn: Union[rfc9480.CMPCertificate, rfc9480.Extensions], name_or_oid: str
) -> None:
    """Ensure that the extension with the given OID or name is non-critical.

    Arguments:
    ---------
        - `cert_or_extn`: The certificate or extensions object to search.
        - `name_or_oid`: The OID or name of the extension.

    Raises:
    ------
        - `ValueError`: If the extension is critical.

    Examples:
    --------
    | Extension Must Be Non Critical | ${certificate} | key_usage |
    | Extension Must Be Non Critical | ${extension} | 1.2.840.113549.1.9.14 |

    """
    if "." in name_or_oid:
        oid = univ.ObjectIdentifier(name_or_oid)
    else:
        oid = EXTENSION_NAME_2_OID[name_or_oid]

    extn = get_extension(cert_or_extn["tbsCertificate"]["extensions"], oid, must_be_non_crit=True)

    if extn is None:
        name = may_return_oid_to_name(oid)
        raise ValueError(f"Extension {name}:{oid} is not present.")


@not_keyword
def get_extension(
    extensions: rfc9480.Extensions,
    oid: univ.ObjectIdentifier,
    must_be_non_crit: Optional[bool] = None,
    must_be_crit: Optional[bool] = None,
) -> Optional[rfc5280.Extension]:
    """Extract an extension with the given Object Identifier (OID).

    :param extensions: List of extensions to search.
    :param oid: The OID of the desired extension.
    :param must_be_non_crit: If True, ensure the extension is non-critical. Defaults to disabled.
    :param must_be_crit: If True, ensure the extension is critical. Defaults to disabled.
    :return: The matching extension, or None if not found.
    """
    if not extensions.isValue:
        logging.info("No `extensions` found in the certificate.")
        return None

    for ext in extensions:
        if ext["extnID"] == oid:
            if must_be_non_crit and ext["critical"] and must_be_non_crit is not None:
                raise ValueError("Extension must be non-critical but is critical.")
            if must_be_crit and not ext["critical"] and must_be_crit is not None:
                raise ValueError("Extension must be critical but is non-critical.")
            return ext
    return None


@not_keyword
def get_subject_key_identifier(cert: rfc9480.CMPCertificate) -> Optional[bytes]:
    """Extract the subjectKeyIdentifier from a pyasn1 `CMPCertificate`, if present.

    :param cert: The certificate to extract the extension from.
    :return: `None` if not present. Else digest `Bytes`.
    :raises: `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.
    """
    extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_subjectKeyIdentifier)
    if extn_val is None:
        return None
    ski, _ = decoder.decode(extn_val["extnValue"], asn1Spec=rfc5280.SubjectKeyIdentifier())
    return ski.asOctets()


@not_keyword
def get_authority_key_identifier(cert: rfc9480.CMPCertificate) -> Optional[rfc5280.AuthorityKeyIdentifier]:
    """Extract the subjectKeyIdentifier from a pyasn1 `CMPCertificate`, if present.

    :param cert: The certificate to extract the extension from.
    :return: `None` if not present. Else digest `Bytes`.
    :raises: `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.
    """
    extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_authorityKeyIdentifier)
    if extn_val is None:
        return None
    return decoder.decode(extn_val["extnValue"], asn1Spec=rfc5280.AuthorityKeyIdentifier())[0]


@not_keyword
def get_extension_decoded_value(
    cert: rfc9480.CMPCertificate,
    extension_name: str,
    strict_decode: bool = True,
) -> Optional[base.Asn1Type]:
    """Get the decoded value of a specific extension from a certificate.

    :param cert: The certificate to extract the extension from.
    :param extension_name: The name of the extension to retrieve (e.g., "key_usage").
    :param strict_decode: If `True`, the decoder will raise an error if the value
    has a remainder. If `False`, it will ignore the remainder.
    :return: The decoded value of the extension, or `None` if not present.
    """
    extn_oid = EXTENSION_NAME_2_OID[extension_name]
    spec_tmp = EXTENSION_OID_2_SPECS[extn_oid]

    extn_val = get_extension(cert["tbsCertificate"]["extensions"], extn_oid)
    if extn_val is None:
        return None
    spec, rest = decoder.decode(extn_val["extnValue"].asOctets(), asn1Spec=spec_tmp())
    if strict_decode and rest:
        raise BadAsn1Data(f"{type(spec_tmp)}: {rest.hex()} left over after decoding `{extension_name}`", overwrite=True)
    return spec


def get_field_from_certificate(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate, query: Optional[str] = None, extension: Optional[str] = None
) -> Union[bytes, None, base.Asn1Type]:
    """Retrieve a value from a `pyasn1` CMPCertificate using a specified query or extension.

    Extracts a value from a certificate based on a pyasn1 query or a named certificate
    extension. The default query starts from `tbsCertificate`. If accessing attributes like `serialNumber`,
    it can be parsed directly.

    Note:
    ----
        - The function uses pyasn1 notation (e.g., `serialNumber`)

    Arguments:
    ---------
        - `cert`: The certificate object from which to retrieve the value.
        - `query`: An optional string specifying the field to query in the certificate using pyasn1 notation.
        The path to the value you want to extract, given as a dot-notation.
        - `extension`: An optional string specifying the extension to retrieve from the certificate.

    Supported Extensions:
    --------------------
        - "ski": SubjectKeyIdentifier
        - "key_usage": KeyUsage
        - "eku": ExtendedKeyUsage
        - "aki": AuthorityKeyIdentifier
        - "basic_constraints": BasicConstraints
        - "san": SubjectAltName
        - "ian": IssuerAltName

    Returns:
    -------
        - Either an A `pyasn1` object representing the value from the certificate if found, or bytes if "ski" is \
        present or `None` if the extension is not present.

    Raises:
    ------
        - `ValueError`: If neither `query` nor `extension` is provided.
        - `NotImplementedError`: If the specified `extension` is not supported by the function.
        - `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.

    Examples:
    --------
    | ${serial_number}= | Get Field From Certificate | ${certificate} | query="serialNumber" |
    | ${ski}= | Get Field From Certificate | ${certificate} | extension="ski" |
    | ${key_usage}= | Get Field From Certificate | ${certificate} | extension="key_usage" |

    """
    if not (query or extension):
        raise ValueError("Either 'query' or 'extension' must be provided to retrieve a field from the certificate.")

    if cert is None:
        raise ValueError("The parsed `cert` had no value!")

    if query is not None:
        out = asn1utils.get_asn1_value(cert, query="tbsCertificate." + query)  # type: ignore
        if not out.isValue:  # type: ignore
            raise ValueError(f"Field '{query}' was not set in the certificate.")
        return out  # type: ignore

    # Choose to directly return the value of the digests as bytes.
    if extension == "ski":
        return get_subject_key_identifier(cert)

    if extension in ["key_usage", "eku", "basic_constraints", "ian", "san", "aki", "aia"]:
        return get_extension_decoded_value(cert, extension)

    raise NotImplementedError(f"Extension name not supported: {extension}")


@not_keyword
def extract_extensions_from_csr(csr: rfc6402.CertificationRequest) -> Optional[rfc9480.Extensions]:
    """Extract extensions from a CertificationRequest object if present.

    :param csr: The CSR object from which to extract extensions, if possible.
    :return: The extracted extensions, but only from the first index.
    """
    if not csr["certificationRequestInfo"]["attributes"].isValue:
        return None

    ext_oid = univ.ObjectIdentifier("1.2.840.113549.1.9.14")
    attr: Attribute

    for attr in csr["certificationRequestInfo"]["attributes"]:
        if attr["attrType"] == ext_oid:
            extn, _ = decoder.decode(attr["attrValues"][0].asOctets(), asn1Spec=rfc9480.Extensions())
            return extn

    return None


@not_keyword
def get_crl_dpn(
    cert: Union[rfc9480.CMPCertificate, rfc5280.CertificateList],
) -> Union[rfc5280.CRLDistributionPoints, None]:
    """Get the `CRLDistributionPoints` extension, DER-encoded, from a `rfc9480.CMPCertificate` object.

    :param cert: The object to get the extension from.
    :return: `None` if the extension is not present, else the `rfc5280.CRLDistributionPoints` structure.
    :raises: `BadAsn1Data` if the extension value cannot be decoded.
    """
    if isinstance(cert, rfc9480.CMPCertificate):
        extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_cRLDistributionPoints)
    else:
        extn_val = get_extension(cert["tbsCertList"]["crlExtensions"], rfc5280.id_ce_cRLDistributionPoints)
    if extn_val is None:
        return None
    crl_dp_pyasn1, _ = asn1utils.try_decode_pyasn1(
        extn_val["extnValue"].asOctets(),  # type: ignore
        rfc5280.CRLDistributionPoints(),
    )
    crl_dp_pyasn1: rfc5280.CRLDistributionPoints
    return crl_dp_pyasn1


@not_keyword
def get_issuing_distribution_point(
    cert: Union[rfc9480.CMPCertificate, rfc5280.CertificateList],
) -> Union[rfc5280.IssuingDistributionPoint, None]:
    """Get and decode the Issuing Distribution Point extension from a pyasn1 certificate object.

    :param cert: The certificate to extract the extension from.
    :return: `None` if the extension is not present, else the `rfc5280.IssuingDistributionPoint` structure.
    :raises: `BadAsn1Data` if the extension value cannot be decoded.
    """
    if isinstance(cert, rfc9480.CMPCertificate):
        extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_issuingDistributionPoint)
    else:
        extn_val = get_extension(cert["tbsCertList"]["crlExtensions"], rfc5280.id_ce_issuingDistributionPoint)

    if extn_val is None:
        return None
    idp_pyasn1, _ = asn1utils.try_decode_pyasn1(
        extn_val["extnValue"].asOctets(),  # type: ignore
        rfc5280.IssuingDistributionPoint(),
    )
    idp_pyasn1: rfc5280.IssuingDistributionPoint
    return idp_pyasn1
