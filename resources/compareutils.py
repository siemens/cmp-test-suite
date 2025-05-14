# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains functionality to compare pyasn1 objects.

Which can be used to verify if the server returned the correct status, `grantedWithMods`, when issuing a certificate.
"""

import logging
from typing import Optional, Union

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

from resources import certextractutils, certutils, cmputils, convertutils, copyasn1utils, keyutils, suiteenums, utils
from resources.oid_mapping import may_return_oid_by_name, may_return_oid_to_name
from resources.typingutils import PrivateKey, PublicKey


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
def compare_csr_and_cert(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest, issued_cert: rfc9480.CMPCertificate, subject_strict: bool = False
) -> bool:
    """Compare a CSR and the newly issued certificate to check if the server returned the correct status.

    Arguments:
    ---------
       - `csr`: The Certificate Signing Request (CSR) to compare.
       - `issued_cert`: The issued certificate to compare against.
       - `subject_strict`: Whether the `subject` field should be equal or just contain the `subject`
       value. Defaults to `False`.

    Returns:
    -------
        - `True` if the CSR and the issued certificate match; `False` otherwise.

    Examples:
    --------
    | ${result}= | Compare CSR And Cert | ${csr} | ${issued_cert} |
    | ${result}= | Compare CSR And Cert | ${csr} | ${issued_cert} | subject_strict=True |

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

        csr_extensions = certextractutils.extract_extensions_from_csr(csr)

        if csr_extensions is None:
            raise NotImplementedError("Attributes are not yet supported.")

        new_obj = rfc9480.Extensions()
        new_obj.extend(issued_cert["tbsCertificate"]["extensions"])

        if encoder.encode(csr_extensions) != encoder.encode(new_obj):
            return False

    return True


@keyword(name="Compare AlgID Without Tag")
def compare_alg_id_without_tag(  # noqa D417 undocumented-param
    first: rfc9480.AlgorithmIdentifier, second: rfc9480.AlgorithmIdentifier
) -> bool:
    """Compare `AlgorithmIdentifier` without considering the tag.

    Arguments:
    ---------
        - `first`: The first `AlgorithmIdentifier` to compare.
        - `second`: The second `AlgorithmIdentifier` to compare.

    Returns:
    -------
        - `True` if both the OID and parameters match, `False` otherwise.

    Examples:
    --------
    | ${result}= | Compare Alg ID Without Tag | ${first} | ${second} |

    """
    oid_first, params_first = first["algorithm"], first["parameters"]
    oid_second, params_second = second["algorithm"], second["parameters"]
    if oid_first != oid_second:
        return False

    if sum([params_first.isValue, params_second.isValue]) in [0, 2]:
        # is allowed because if both values are schema objects, it is allowed to compare them.
        # which means that if both are not set, they are equal.
        return params_first == params_second

    return False


@keyword(name="Compare GeneralName And Name")
def compare_general_name_and_name(  # noqa D417 # undocumented-param
    general_name: rfc5280.GeneralName, name: rfc5280.Name, url: Optional[str] = None
) -> bool:
    """Compare a `pyasn1` GeneralName with a `pyasn1` Name.

    Compares a `GeneralName` object (which may be of type `directoryName` or `rfc822Name`) with a
    `Name` object. It checks if they match based on the specified naming convention.

    Note:
    ----
        - For `directoryName`, it performs a direct comparison.
        - For `rfc822Name`, it converts the `Name` object into an OpenSSL-style string and then compares it.

    Arguments:
    ---------
        - `general_name`: The `pyasn1` GeneralName object to compare.
        - `name`: The `pyasn1` Name object to compare with the GeneralName.
        - `url`: Optional URL string for `uniformResourceIdentifier` comparison. Defaults to `None`.

    Returns:
    -------
        - `True` if the `GeneralName` and `Name` match, `False` otherwise.

    Raises:
    ------
        - `NotImplementedError`: If the `GeneralName` is of another type than `directoryName` or `rfc822Name`.
        - `ValueError`: If the `url` is required but not provided for `uniformResourceIdentifier` comparison.

    Examples:
    --------
    | ${result}= | Compare GeneralName and Name | ${general_name} | ${name} |

    """
    if general_name.getName() == "directoryName":
        return compare_pyasn1_names(general_name["directoryName"], name, "without_tag")

    if general_name.getName() == "rfc822Name":
        str_name = utils.get_openssl_name_notation(name, oids=None)
        if str_name is None:
            return False
        return str_name == str(general_name[general_name.getName()])

    if general_name.getName() == "uniformResourceIdentifier":
        if url is None:
            raise ValueError("URL must be provided for uniformResourceIdentifier comparison.")
        return url == str(general_name[general_name.getName()])

    raise NotImplementedError(
        f"GeneralName type '{general_name.getName()}' is not supported. Supported types are: "
        "'directoryName' and 'rfc822Name'."
    )


@keyword(name="Find Name Inside GeneralNames")
def find_name_inside_general_names(  # noqa D417 # undocumented-param
    gen_names: rfc9480.GeneralNames, name: rfc5280.Name, url: Optional[str] = None
) -> bool:
    """Find a `Name` object inside a `GeneralNames`.

    Arguments:
    ---------
        - `gen_names`: The `GeneralNames` object to search.
        - `name`: The `Name` object to search for.
        - `url`: Optional URL string for `uniformResourceIdentifier` comparison. Defaults to `None`.

    Returns:
    -------
        - `True` if the `Name` object is found inside the `GeneralNames`, `False` otherwise.

    Examples:
    --------
    | ${result}= | Find Name Inside General Names | ${gen_names} | ${name} |

    """
    for gen_name in gen_names:
        if compare_general_name_and_name(gen_name, name, url):
            return True
    return False


@keyword(name="Find RelativeDistinguishedName in Name")
def find_rel_dis_name_in_name(  # noqa D417 # undocumented-param
    rdn: rfc5280.RelativeDistinguishedName, name: rfc5280.Name
) -> bool:
    """Find a `RelativeDistinguishedName` inside a `Name`.

    Arguments:
    ---------
        - `rdn`: The `RelativeDistinguishedName` to search for.
        - `name`: The `Name` object to search in.

    Returns:
    -------
        - `True` if the `RelativeDistinguishedName` is found inside the `Name`, `False` otherwise.

    Examples:
    --------
    | ${result}= | Find RelativeDistinguishedName in Name | ${rdn} | ${name} |

    """
    der_name = encoder.encode(rdn)

    for rdn_seq in name["rdnSequence"]:
        if der_name == encoder.encode(rdn_seq):
            return True
    return False


@keyword(name="Is NULL DN")
def is_null_dn(name: rfc5280.Name) -> bool:  # noqa D417 # undocumented-param
    """Check if the given Name is a NULL-DN, meaning it has no RDNs.

    Allows also tagged names to be checked (e.g., `CertTemplate` `subject`).

    Arguments:
    ---------
        - `name`: The `Name` object to check.

    Returns:
    -------
        - `True` if the `Name` is a NULL-DN, `False` otherwise.

    Raises:
    ------
        - `pyasn1.error.PyAsn1Error`: If the `Name` object cannot be properly compared.

    Examples:
    --------
    | ${result}= | Is NULL DN | ${name} |

    """
    copy_name = rfc5280.Name()
    copy_name["rdnSequence"] = name["rdnSequence"]
    return encoder.encode(copy_name) == b"\x30\x00"


@not_keyword
def check_if_alg_id_parameters_is_absent(alg_id: rfc9480.AlgorithmIdentifier, allow_null: bool = False) -> bool:
    """Check if the `parameters` field of the `AlgorithmIdentifier` is absent."""
    params = alg_id["parameters"]

    if not params.isValue:
        return True

    if allow_null and params == univ.Null(""):
        return True

    if isinstance(params, univ.Any):
        if params.asOctets() == b"\x05\x00":
            return True

    return False


def _verify_spki_alg_id(
    cert: rfc9480.CMPCertificate,
    public_key: PublicKey,
    spki: Optional[rfc5280.SubjectPublicKeyInfo],
    key_name: Optional[str] = None,
) -> None:
    """Verify if the algorithm identifier in the issued certificate matches the expected algorithm identifier.

    :param cert: The issued certificate to check.
    :param public_key: The public key to compare against.
    :param spki: The SubjectPublicKeyInfo to compare against.
    :param key_name: The name of the key to validate against the public key in the certificate.
    """
    loaded_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if public_key != loaded_key:
        raise ValueError(
            "Public key mismatch between the expected and issued certificate."
            f"Expected: {keyutils.get_key_name(public_key)}. Got: {keyutils.get_key_name(loaded_key)}"  # type: ignore
        )

    if type(public_key) is not type(loaded_key):
        raise ValueError(
            "Public key type mismatch between the expected and issued certificate."
            f"Expected: {type(public_key)}. Got: {type(loaded_key)}"
        )

    cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
    if key_name is not None:
        key_oid = may_return_oid_by_name(key_name)
        if key_oid != cert_oid:
            cert_name = may_return_oid_to_name(cert_oid)
            raise ValueError(
                f"Algorithm ID mismatch between the expected and issued certificate."
                f"Expected: {key_name}. Got: {cert_name}"
            )

    if spki is not None:
        spki_oid = spki["algorithm"]["algorithm"]
        if cert_oid != spki_oid:
            cert_name = may_return_oid_to_name(cert_oid)
            spki_name = may_return_oid_to_name(spki_oid)
            raise ValueError(
                f"Algorithm ID mismatch between the expected and issued certificate."
                f"Expected: {spki_name}. Got: {cert_name}"
            )


def validate_certificate_public_key(  # noqa D417 # undocumented-param
    cert: rfc9480.CMPCertificate,
    key: Union[PrivateKey, PublicKey, rfc5280.SubjectPublicKeyInfo],
    key_name: Optional[str] = None,
) -> None:
    """Check if the public key in the issued certificate matches the expected public key.

    Arguments:
    ---------
        - `cert`: The issued certificate to check.
        - `key`: The private key or public key to compare against.
        - `key_name`: The name of the key to validate against the public key in the certificate.
        (e.g., "rsa", "ml-dsa-44-sha512") Defaults to `None`.

    Raises:
    ------
        - `ValueError`: If the public key in the issued certificate does not match the expected public key.

    Examples:
    --------
    | Validate If Correct Public Key In Issued Cert | ${cert} | ${key} | ${spki} |
    | Validate If Correct Public Key In Issued Cert | ${cert} | ${key} | key_name=${key_name} |
    | Validate If Correct Public Key In Issued Cert | ${cert} | ${key} |

    """
    if isinstance(key, PrivateKey):
        public_key = key.public_key()

    elif isinstance(key, rfc5280.SubjectPublicKeyInfo):
        public_key = keyutils.load_public_key_from_spki(key)
    else:
        public_key = key

    spki = None if not isinstance(key, rfc5280.SubjectPublicKeyInfo) else key

    _verify_spki_alg_id(public_key=public_key, cert=cert, spki=spki, key_name=key_name)
