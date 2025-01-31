# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains functionality to compare pyasn1 objects.

Additionally contains logic to check if the wished certificate was issued, based on the `CertTemplate` structure.

"""

import logging
from typing import Optional

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc6402, rfc9480
from robot.api.deco import keyword

from resources import certutils, cmputils, convertutils, copyasn1utils, suiteenums, utils
from resources.certextractutils import extract_extension_from_csr
from resources.oid_mapping import may_return_oid_to_name


@keyword(name="Compare ASN1 Names")
def compare_pyasn1_names(  # noqa D417 undocumented-param
    name1: rfc9480.Name, name2: rfc9480.Name, mode: str = "without_tag"
) -> bool:
    """Compare two `rfc9480.Name` objects using the specified comparison mode.

    Arguments:
    ---------
        - `name1`: The first `pyasn1` Name object to compare.
        - `name2`: The second `pyasn1` Name object to compare against the first.
        - `mode`: A string specifying the comparison mode. Valid options are:
          - `strict`: Compares the entire Name structure, including tags, if some are set.
          - `without_tag`: Compares the `rdnSequence` of the Name objects, ignoring tags.
          - `contains`: Checks if all attributes in `name2` are present in `name1`.
          - `contains_seq`: Checks if all attributes in `name2` are present in `name1`, ensuring the sequence is the
          same order.
          Defaults to `"without_tag"`.

    Returns:
    -------
        - `True` if the comparison succeeds based on the specified mode, `False` otherwise.

    Raises:
    ------
        - `ValueError`: If the provided mode is not a valid `NameCompareTypes`.

    Examples:
    --------
    | ${result}= | Compare ASN1 Names | name1=${name1} | name2=${name2} | mode=STRICT |
    | ${result}= | Compare ASN1 Names | name1=${name1} | name2=${name2} | mode=CONTAINS |

    """
    mode_type = suiteenums.NameCompareTypes(mode)

    if mode_type == suiteenums.NameCompareTypes.WITHOUT_TAG:
        der_gen_name = encoder.encode(name1["rdnSequence"])
        der_name = encoder.encode(name2["rdnSequence"])
        return der_name == der_gen_name

    if mode_type == suiteenums.NameCompareTypes.STRICT:
        der_gen_name = encoder.encode(name1)
        der_name = encoder.encode(name2)
        return der_name == der_gen_name

    if mode_type == suiteenums.NameCompareTypes.CONTAINS:
        name2_attributes = set()
        for rdn in name2["rdnSequence"]:
            for attr in rdn:
                name2_attributes.add((attr["type"], attr["value"]))

        for rdn in name1["rdnSequence"]:
            for attr in rdn:
                if (attr["type"], attr["value"]) not in name2_attributes:
                    return False
        return True

    # contains_seq
    name2_attributes = set()
    for rdn_index, rdn in enumerate(name2["rdnSequence"]):
        for attr in rdn:
            name2_attributes.add((rdn_index, attr["type"], attr["value"]))

    for rdn_index, rdn in enumerate(name1["rdnSequence"]):
        for attr in rdn:
            if (rdn_index, attr["type"], attr["value"]) not in name2_attributes:
                return False

    return True


def _compare_validity_template_and_cert(
    cert_template: rfc4211.CertTemplate, issued_cert: rfc9480.CMPCertificate, exclude: bool
) -> bool:
    """Compare `validity` of a `CertTemplate` with an issued `CMPCertificate`.

    Used to indicate whether a difference between the issued certificate and the template is found, to verify if the
    Server correctly returned grantedWithMods.

    :param cert_template: The CertTemplate structure to check.
    :param issued_cert: The issued certificate to check against.
    :param exclude: A boolean Flag used to exclude this check.
    :return: Bool indicating if the cert template has different values set than the certificate.
    Returns `True`, if check is excluded or value is not present.
    """
    if exclude or not cert_template["validity"].isValue:
        return True

    tbs_cert = issued_cert["tbsCertificate"]

    if cert_template["validity"]["notBefore"].isValue:
        date_obj = convertutils.pyasn1_time_obj_to_py_datetime(cert_template["validity"]["notBefore"])
        date_obj_issued = convertutils.pyasn1_time_obj_to_py_datetime(tbs_cert["validity"]["notBefore"])
        if date_obj != date_obj_issued:
            return False
    if cert_template["validity"]["notAfter"].isValue:
        date_obj = convertutils.pyasn1_time_obj_to_py_datetime(cert_template["validity"]["notAfter"])
        date_obj_issued = convertutils.pyasn1_time_obj_to_py_datetime(tbs_cert["validity"]["notAfter"])
        if date_obj != date_obj_issued:
            return False
    return True


def _compare_public_key_template_and_cert(
    cert_template: rfc4211.CertTemplate, issued_cert: rfc9480.CMPCertificate, exclude: bool
) -> bool:
    """Compare the `publicKey` between a `CertTemplate` and an issued `CMPCertificate`.

    :param cert_template: The CertTemplate structure to check.
    :param issued_cert: The issued certificate to check against.
    :param exclude: A boolean Flag used to exclude this check.
    :return: Bool indicating if the cert template has different values set than the certificate.
    Returns `True`, if check is excluded or value is not present.
    """
    if exclude or not cert_template["publicKey"].isValue:
        return True

    spki_template = rfc5280.SubjectPublicKeyInfo()
    # not deserialize able.
    spki_template = copyasn1utils.copy_subject_public_key_info(spki_template, cert_template["publicKey"])

    if cert_template["publicKey"]["subjectPublicKey"] != univ.BitString(""):
        spki_template_der = encoder.encode(spki_template)
        public_key_cert = certutils.load_public_key_from_cert(issued_cert)
        public_key_cert_der: bytes = public_key_cert.public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        if public_key_cert_der != spki_template_der:
            logging.info("Public key mismatch between the template and the issued certificate.")
            return False

    else:
        cert_spki = issued_cert["tbsCertificate"]["subjectPublicKeyInfo"]
        if not cert_template["publicKey"]["algorithm"] == cert_spki["algorithm"]:
            template_oid_may_name = may_return_oid_to_name(cert_template["publicKey"]["algorithm"])
            cert_oid_may_name = may_return_oid_to_name(cert_spki["algorithm"])
            logging.info("We asked for a key with the oid: %s but got: %s", template_oid_may_name, cert_oid_may_name)
            return False

    return True


def _compare_extensions_subject_template_and_cert(
    cert_template: rfc4211.CertTemplate, issued_cert: rfc9480.CMPCertificate, exclude: bool
) -> bool:
    """Compare the `extensions` between a `CertTemplate` and an issued `CMPCertificate`.

    :param cert_template: The CertTemplate structure to check.
    :param issued_cert: The issued certificate to check against.
    :param exclude: A boolean Flag used to exclude this check.
    :return: Bool indicating if the cert template has different values set than the certificate.
    Returns `True`, if check is excluded or value is not present.
    """
    if exclude or not cert_template["extensions"].isValue:
        return True

    for extension in cert_template["extensions"]:
        if not cmputils.contains_extension(issued_cert, extension["extnID"]):
            logging.info("The issued certificate did not contain the extension: %s", extension.prettyPrint())
            return False

    return True


def _compare_uids_template_and_cert(
    cert_template: rfc4211.CertTemplate, issued_cert: rfc9480.CMPCertificate, exclude: list
) -> bool:
    """Compare the `issuerUID` and `subjectUID` between a `CertTemplate` and an issued `CMPCertificate`.

    Used to indicate whether a difference between the issued certificate and the template is found, to verify if the
    Server correctly returned grantedWithMods.

    :param cert_template: The CertTemplate structure to check.
    :param issued_cert: The issued certificate to check against.
    :param exclude: A list of strings to check if the values should not be compared.
    :return: Bool indicating if the cert template has different values set than the certificate.
    if not, set or values should be excluded, returns `True`
    """
    tbs_cert = issued_cert["tbsCertificate"]

    if cert_template["issuerUID"].isValue and "issuerUID" not in exclude:
        if tbs_cert["issuerUniqueID"].isValue:
            if cert_template["issuerUID"].asOctets() != tbs_cert["issuerUniqueID"].asOctets():
                return False
        else:
            return False

    if cert_template["subjectUID"].isValue and "subjectUID" not in exclude:
        if tbs_cert["subjectUniqueID"].isValue:
            if cert_template["subjectUID"].asOctets() != tbs_cert["subjectUniqueID"].asOctets():
                return False
        else:
            return False

    return True


def _compare_issuer_and_subject_template_and_cert(
    cert_template: rfc4211.CertTemplate,
    issued_cert: rfc9480.CMPCertificate,
    exclude: list,
    strict_subject_validation: bool,
) -> bool:
    """Compare the `issuer` and `subject` between a `CertTemplate` and an issued `CMPCertificate`.

    Used to indicate whether a difference between the issued certificate and the template is found, to verify if the
    Server correctly returned grantedWithMods.

    :param cert_template: The CertTemplate structure to check.
    :param issued_cert: The issued certificate to check against.
    :param exclude: A list of strings to check if the values should not be compared.
    :param strict_subject_validation: A bool indicating if the subject is valid with `in` or
    has to be the same.
    :return: A boolean indicating if the cert template has different values set than the certificate.
    if not, set or values should be excluded, returns `True`
    """
    if cert_template["issuer"].isValue and "issuer" not in exclude:
        is_eq = compare_pyasn1_names(cert_template["issuer"], issued_cert["tbsCertificate"]["issuer"], "without_tag")
        if not is_eq:
            template_issuer_name = utils.get_openssl_name_notation(cert_template["issuer"], oids=None)
            issuer_name = utils.get_openssl_name_notation(
                issued_cert["tbsCertificate"]["issuer"],  # type: ignore
                oids=None,
            )
            logging.info("Issuer name mismatch: Template=%s, Issued=%s", template_issuer_name, issuer_name)
            return False

    if cert_template["subject"].isValue and "subject" not in exclude:
        template_subject_name = utils.get_openssl_name_notation(cert_template["subject"], oids=None)
        subject_name = utils.get_openssl_name_notation(
            issued_cert["tbsCertificate"]["subject"],  # type: ignore
            oids=None,
        )

        if strict_subject_validation:
            is_eq = compare_pyasn1_names(
                cert_template["subject"], issued_cert["tbsCertificate"]["subject"], "without_tag"
            )
            if not is_eq:
                logging.info("Subject name mismatch: Template=%s, Issued=%s", template_subject_name, subject_name)
                return False

        else:
            is_eq = compare_pyasn1_names(cert_template["subject"], issued_cert["tbsCertificate"]["subject"], "contains")
            if not is_eq:
                logging.info("Subject name mismatch: Template=%s, Issued=%s", template_subject_name, subject_name)
                return False

    return True


# TODO maybe change to only Py.


@keyword(name="Compare CertTemplate And Cert")
def compare_cert_template_and_cert(  # noqa D417 undocumented-param
    cert_template: rfc4211.CertTemplate,
    issued_cert: rfc9480.CMPCertificate,
    include_fields: Optional[str] = None,
    exclude_fields: Optional[str] = None,
    strict_subject_validation: bool = False,
) -> bool:
    """Compare the attributes of a `CertTemplate` with an issued `CMPCertificate`.

    Verifies that the issued certificate matches the requested certificate template by comparing key fields such as
    `serialNumber`, `issuer`, `subject`, `extensions`, `publicKey`, and `validity`.
    Is useful for confirming that the server-issued certificate meets the requested specifications and correctly
    returns the status `grantedWithMods` if necessary modifications were applied.

    Notes:
    -----
        - Strictly enforces matching of `validity`.
        - Excludes checks for `signingAlg` and `version`.

    Arguments:
    ---------
        - `cert_template`: The template used to request the certificate, containing expected attribute values.
        - `issued_cert`: The certificate issued by the server, to be compared against the template.
        - `include_fields`: Optional comma-separated string of fields to include in the comparison.
        - `exclude_fields`: Optional comma-separated string of fields to exclude from the comparison.
        - `strict_subject_validation`: If `True`, requires the subject to match exactly rather than just
        containing the `subject` field of the issued certificate.

    Returns:
    -------
        - `True` if all specified attributes match between the template and issued certificate; `False` otherwise.

    Raises:
    ------
        - `pyasn1.error.PyAsn1Error`: If a field cannot be properly compared or is missing in the certificate.

    Examples:
    --------
    | ${result}= | Compare Cert Template And Cert | ${cert_template} | ${issued_cert} |

    """
    exclude: list = utils.filter_options(
        options=list(rfc4211.CertTemplate().keys()), exclude=exclude_fields, include=include_fields
    )

    if cert_template["serialNumber"].isValue and not "serialNumber" not in exclude:
        if int(cert_template["serialNumber"]) != int(issued_cert["tbsCertificate"]["serialNumber"]):
            return False

    if not _compare_extensions_subject_template_and_cert(cert_template, issued_cert, "extensions" in exclude):
        return False

    if not _compare_issuer_and_subject_template_and_cert(
        cert_template=cert_template,
        issued_cert=issued_cert,
        exclude=exclude,
        strict_subject_validation=strict_subject_validation,
    ):
        return False

    if not _compare_public_key_template_and_cert(cert_template, issued_cert, "publicKey" in exclude):
        return False

    if not _compare_validity_template_and_cert(cert_template, issued_cert, "validity" in exclude):
        return False

    if not _compare_uids_template_and_cert(cert_template, issued_cert, exclude):
        return False

    logging.info("Fields `signingAlg, version` are not supported!")
    return True


@keyword(name="Compare CSR And Cert")
def compare_csr_and_cert(
    csr: rfc6402.CertificationRequest, issued_cert: rfc9480.CMPCertificate, subject_strict: bool = False
) -> bool:
    """Compare a CSR and the newly issued certificate to check if the server returned the correct status.

    :param csr: The Certificate Signing Request (CSR) to compare.
    :param issued_cert: The issued certificate to compare against.
    :param subject_strict: A boolean flag to indicate if the comparison should be strict,
    for the `subject` field, which means it must be equal.
    :return: Whether the CSR and the issued certificate match.
    """
    extracted_subject = csr["certificationRequestInfo"]["subject"]
    cert_subject = issued_cert["tbsCertificate"]["subject"]
    if subject_strict:
        is_eq = compare_pyasn1_names(extracted_subject, cert_subject, "without_tag")
    else:
        is_eq = compare_pyasn1_names(extracted_subject, cert_subject, "contains")
    if not is_eq:
        return False

    csr_spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]
    cert_spki = issued_cert["tbsCertificate"]["subjectPublicKeyInfo"]
    if encoder.encode(csr_spki) != encoder.encode(cert_spki):
        return False

    if csr["certificationRequestInfo"]["attributes"].isValue:
        if len(csr["certificationRequestInfo"]["attributes"]) == 0:
            return True

        if len(csr["certificationRequestInfo"]["attributes"]) > 1:
            raise NotImplementedError("Attributes are not yet supported.")

        csr_extensions = extract_extension_from_csr(csr)

        if csr_extensions is None:
            raise NotImplementedError("Attributes are not yet supported.")

        new_obj = rfc9480.Extensions()
        new_obj.extend(issued_cert["tbsCertificate"]["extensions"])

        if encoder.encode(csr_extensions) != encoder.encode(new_obj):
            return False

    return True


def compare_alg_id_without_tag(first: rfc9480.AlgorithmIdentifier, second: rfc9480.AlgorithmIdentifier) -> bool:
    """Compare `AlgorithmIdentifier` without considering the tag.

    :param first: The first `AlgorithmIdentifier` to compare.
    :param second: The second `AlgorithmIdentifier` to compare.
    :return: `True` if both the OID and parameters match, `False` otherwise.
    """
    oid_first, params_first = first["algorithm"], first["parameters"]
    oid_second, params_second = second["algorithm"], second["parameters"]
    if oid_first != oid_second:
        return False

    if sum([params_first.isValue, params_second.isValue]) in [0, 2]:
        return params_first == params_second
    else:
        return False
