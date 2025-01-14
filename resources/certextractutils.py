# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for extracting information from certificates and CSRs.

Like the SubjectKeyIdentifier, KeyUsage, and ExtendedKeyUsage extensions.
The SubjectKeyIdentifier is extracted from a certificate, because this extension needs to be the same
as the `senderKID` for the `PKIHeader` or inside the recipient identifier in the `RecipientInfo` for the `EnvelopedData`
structure, which is used to securely exchange data between two parties.
"""

from typing import Optional, Union

from pyasn1.codec.der import decoder
from pyasn1.type import base, univ
from pyasn1_alt_modules import rfc5280, rfc6402, rfc9480
from robot.api.deco import not_keyword

from resources import asn1utils

# TODO refactor.


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
    for ext in extensions:
        if ext["extnID"] == oid:
            if must_be_non_crit and ext["critical"] and must_be_non_crit is not None:
                raise ValueError("Extension must be non-critical but is critical.")
            if must_be_crit and not ext["critical"] and must_be_crit is not None:
                raise ValueError("Extension must be critical but is non-critical.")
            return ext
    return None


@not_keyword
def get_subject_key_identifier(cert: rfc9480.CMPCertificate) -> Union[None, bytes]:
    """Extract the subjectKeyIdentifier from a pyasn1 `CMPCertificate`.

    :param cert: A certificate object from which to extract the subjectKeyIdentifier.
    :return: `None` if not present. Else digest `Bytes`.
    """
    extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_subjectKeyIdentifier)

    if extn_val is None:
        return None

    ski, _ = decoder.decode(extn_val["extnValue"], asn1Spec=rfc5280.SubjectKeyIdentifier())
    return ski.asOctets()


def _get_key_usage(cert: rfc9480.CMPCertificate) -> Union[None, rfc5280.KeyUsage]:
    """Extract the KeyUsage extension from an `pyasn1` certificate object, if present.

    :param cert: A certificate object from which to extract the `KeyUsage`.
    :return: The `KeyUsage` object if the `KeyUsage` extension is found, otherwise `None`.
    """
    if cert["tbsCertificate"]["extensions"].isValue:
        extensions = cert["tbsCertificate"]["extensions"]

        for ext in extensions:
            ext_id = ext["extnID"]
            ext_value = ext["extnValue"]

            if ext_id == rfc5280.id_ce_keyUsage:
                key_usage, _ = decoder.decode(ext_value, asn1Spec=rfc5280.KeyUsage())
                return key_usage

    return None


def _get_extended_key_usage(cert) -> Union[rfc5280.ExtKeyUsageSyntax, None]:
    """Extract the `ExtendedKeyUsage` (EKU) extension from a certificate, if present.

    :param cert: The certificate object to may extract the extension.
    :return: The `ExtKeyUsageSyntax` object if the EKU extension is found, or `None` if not present.
    """
    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] == rfc5280.id_ce_extKeyUsage:
            eku_val, _ = decoder.decode(ext["extnValue"], rfc5280.ExtKeyUsageSyntax())
            return eku_val

    return None


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
                                       Supported extensions include:
                                         - "ski": SubjectKeyIdentifier
                                         - "key_usage": KeyUsage
                                         - "eku": ExtendedKeyUsage

    Returns:
    -------
        - Either an A `pyasn1` object representing the value from the certificate if found, or bytes if "ski" is \
        present or `None` if the extension is not present.

    Raises:
    ------
        - `ValueError`: If neither `query` nor `extension` is provided.
        - `NotImplementedError`: If the specified `extension` is not supported by the function.

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
        return asn1utils.get_asn1_value(cert, query="tbsCertificate." + query)

    if extension == "ski":
        return get_subject_key_identifier(cert)

    if extension == "key_usage":
        return _get_key_usage(cert)

    if extension == "eku":
        return _get_extended_key_usage(cert)

    raise NotImplementedError(f"Extension name not supported: {extension}")


@not_keyword
def extract_extension_from_csr(csr: rfc6402.CertificationRequest) -> Union[rfc9480.Extensions, None]:
    """Extract extensions from a CertificationRequest object if present.

    :param csr: The CSR object from which to extract extensions, if possible.
    :return: The extracted extensions, but only from the first index.
    """
    if not csr["certificationRequestInfo"]["attributes"].isValue:
        return None

    ext_oid = univ.ObjectIdentifier("1.2.840.113549.1.9.14")
    for attr in csr["certificationRequestInfo"]["attributes"]:
        if attr["attrType"] == ext_oid:
            for value in attr["attrValues"]:
                extn, _ = decoder.decode(value, rfc9480.Extensions())
                return extn

    return None
