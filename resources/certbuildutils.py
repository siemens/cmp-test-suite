# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Logic to build and modify `CertTemplate`, `CMPCertificate` or CSR objects."""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Sequence, Set, Tuple, Union

import pyasn1.error
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ, useful
from pyasn1.type.base import Asn1Item, Asn1Type
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5480, rfc5652, rfc6402, rfc8954, rfc9480, rfc9481
from pyasn1_alt_modules.rfc2459 import AttributeValue
from robot.api.deco import keyword, not_keyword

from pq_logic.keys.abstract_wrapper_keys import AbstractCompositePrivateKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey
from pq_logic.keys.trad_kem_keys import RSAEncapKey
from pq_logic.pq_utils import is_kem_public_key
from pq_logic.tmp_oids import COMPOSITE_SIG03_HASH_OID_2_NAME, COMPOSITE_SIG04_HASH_OID_2_NAME, id_rsa_kem_spki
from resources import (
    asn1utils,
    certextractutils,
    certutils,
    cmputils,
    compareutils,
    convertutils,
    copyasn1utils,
    cryptoutils,
    keyutils,
    prepare_alg_ids,
    prepareutils,
    typingutils,
    utils,
)
from resources.asn1utils import get_all_asn1_named_value_names, get_set_bitstring_names
from resources.convertutils import subject_public_key_info_from_pubkey
from resources.copyasn1utils import copy_name
from resources.exceptions import BadAsn1Data, BadCertTemplate
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import (
    CMP_EKU_OID_2_NAME,
    EXTENSION_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
)
from resources.prepare_alg_ids import prepare_alg_id, prepare_sig_alg_id  # noqa: F401
from resources.prepareutils import _GeneralNamesType, parse_to_general_names
from resources.typingutils import CRLFullNameType, ExtensionsType, PrivateKey, PublicKey, SignKey, Strint, VerifyKey


# TODO verify if `utcTime` is allowed for CertTemplate, because is not allowed
# for CMPCertificate.
def prepare_validity(  # noqa D417 undocumented-param
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
    before_use_utc: bool = True,
    after_use_utc: bool = True,
) -> rfc5280.Validity:
    """Prepare a `Validity` object for use in a certificate.

    Can be used to ask for a specified time interval for the newly issued certificate.

    Arguments:
    ---------
        - `not_before`: A `datetime` object indicating when the certificate's validity begins.
                        If `None`, the `notBefore` field will remain unset.
        - `not_after`: A `datetime` object indicating when the certificate's validity ends.
                       If `None`, the `notAfter` field will remain unset.
        - `before_use_utc`: A boolean indicating whether the `notBefore` field should use
                            the "utcTime" format (`True`) or "generalTime" format (`False`).
                            Defaults to `True`.
        - `after_use_utc`: A boolean indicating whether the `notAfter` field should use
                           the "utcTime" format (`True`) or "generalTime" format (`False`).
                           Defaults to `True`.

    Returns:
    -------
        - The populated `rfc5280.Validity` object.

    Raises:
    ------
        - `ValueError`: If an invalid datetime or unsupported format is specified.

    Examples:
    --------
    | ${validity}= | Prepare Validity | not_before=${start_date} | not_after=${end_date} |
    | ${validity}= | Prepare Validity | not_before=${start_date} | before_use_utc=False |

    """
    validity = rfc5280.Validity()
    not_before_obj = rfc5280.Time()
    not_after_obj = rfc5280.Time()

    if not_before is not None:
        before_type = "utcTime" if before_use_utc else "generalTime"
        validity["notBefore"][before_type] = not_before_obj[before_type].fromDateTime(not_before)

    if not_after is not None:
        after_type = "utcTime" if after_use_utc else "generalTime"
        validity["notAfter"][after_type] = not_after_obj[after_type].fromDateTime(not_after)

    return validity


@keyword(name="Sign CSR")
def sign_csr(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest,
    signing_key: SignKey,
    hash_alg: Optional[str] = "sha256",
    other_key: Optional[SignKey] = None,
    bad_pop: bool = False,
    **kwargs,
):
    """Sign a `pyasn1` `CertificationRequest` (CSR).

    The `signatureAlgorithm` and the signature will be populated. The signature algorithm is populated based on the
    signing key and provided hash algorithm. So if the signature should be wrong, another key of the
    same instance needs to be provided.

    Arguments:
    ---------
        - `csr`: The CSR to sign.
        - `signing_key`: The private key to sign the CSR if `other_key` is not provided.
        - `extensions`: Optional extensions to include in the CSR. Defaults to `None`.
        - `hash_alg`: The hash algorithm used for signing the CSR. Defaults to `"sha256"`.
        - `other_key`: Optional private key to sign the CSR.
        Will be ignored if Ed25519 and Ed448 are used.

        - `bad_pop`: Whether to manipulate the signature for negative testing. Defaults to `False`.

    **kwargs:
    --------
        - `sig_alg_id`: The signature algorithm identifier to use. Defaults to `None`.
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature algorithm. Defaults to `False`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.


    Returns:
    -------
        - The signed CSR with the attached `signature` and the `signatureAlgorithm`.

    Raises:
    ------
        - `ValueError`: If the private key cannot be used to sign data.

    Examples:
    --------
    | ${csr}= | Sign CSR | ${csr} | signing_key=${private_key} |
    | ${csr}= | Sign CSR | ${csr} | signing_key=${private_key} | use_rsa_pss=True |
    | ${csr}= | Sign CSR | ${csr} | signing_key=${private_key} | other_key=${private_key} |

    """
    der_data = encoder.encode(csr["certificationRequestInfo"])
    sig_alg_id = kwargs.get("sig_alg_id") or prepare_sig_alg_id(
        signing_key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=kwargs.get("use_rsa_pss", False),
        use_pre_hash=kwargs.get("use_pre_hash", False),
    )

    signature = cryptoutils.sign_data(
        data=der_data,
        key=other_key or signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=kwargs.get("use_rsa_pss", False),
        use_pre_hash=kwargs.get("use_pre_hash", False),
    )
    logging.info("CSR Signature: %s", signature)
    if bad_pop:
        signature = utils.manipulate_bytes_based_on_key(signature, signing_key)
        logging.info("Modified CSR signature: %s", signature)

    csr["signature"] = univ.BitString.fromOctetString(signature)
    csr["signatureAlgorithm"] = sig_alg_id

    # Needs to be en and decoded otherwise is the structure empty.
    der_data = encoder.encode(csr)
    csr, _ = decoder.decode(der_data, asn1Spec=rfc6402.CertificationRequest())

    return csr


@keyword(name="Build CSR")
def build_csr(  # noqa D417 undocumented-param
    signing_key: SignKey,
    common_name: Union[str, rfc9480.Name] = "CN=Hans Mustermann",
    extensions: Optional[rfc9480.Extensions] = None,
    hash_alg: Union[None, str] = "sha256",
    use_rsa_pss: bool = False,
    subjectAltName: Optional[str] = None,
    exclude_signature: bool = False,
    for_kga: bool = False,
    bad_pop: bool = False,
    use_pre_hash: bool = False,
    use_pre_hash_pub_key: Optional[bool] = None,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
) -> rfc6402.CertificationRequest:
    """Build a PKCS#10 Certification Request (CSR) with the given parameters.

    Constructs a CSR using the provided common name, signing key, and optional extensions.
    Optionally includes Subject Alternative Names (SANs) and supports RSA-PSS signatures.

    Arguments:
    ---------
        - `common_name`: The common name for the subject of the CSR.
        - `signing_key`: The private key used to sign the CSR.
        - `extensions`: Optional extensions to include in the CSR. Defaults to `None`.
        - `hash_alg`: The hash algorithm used for signing the CSR. Defaults to `"sha256"`.
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature algorithm. Defaults to `False`.
        - `subjectAltName`: Optional string of subject alternative names, e.g.,
        `"example.com,www.example.com,pki.example.com"`. Defaults to `None`.
        - `exclude_signature`: A flag to indicate if the CSR should be signed or not. Defaults to `False`.
        - `for_kga`: If the CSR is created for non-local key generation. The `signature` and the
        `subjectPublicKey` are set to a zero bit string. And the algorithm identifiers are set to the provided key.
        - `bad_sig`: Whether to manipulate the signature for negative testing.
        - `use_pre_hash`:Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `use_pre_hash_pub_key`: Whether to use the pre-hash version for a composite-sig public key.
        Defaults to `use_pre_hash`.
        - `spki`: Optional `SubjectPublicKeyInfo` object to populate the CSR with. Defaults to `None`.

    Returns:
    -------
       - The constructed `CertificationRequest` object.

    Examples:
    --------
    | ${csr}= | Build CSR | common_name={cm} | signing_key=${private_key} |
    | ${csr}= | Build CSR | common_name={cm} | signing_key=${private_key} | extensions=${exts} |
    | ${csr}= | Build CSR | common_name={cm} | signing_key=${private_key} | subjectAltName=www.example.com |
    | ${csr}= | Build CSR | common_name={cm} | signing_key=${private_key} | hash_alg="sha512" | use_rsa_pss=True |

    """
    csr = rfc6402.CertificationRequest()

    csr["certificationRequestInfo"]["version"] = univ.Integer(0)
    if isinstance(common_name, str):
        common_name = prepareutils.prepare_name(common_name)

    csr["certificationRequestInfo"]["subject"] = common_name

    use_pre_hash_pub_key = use_pre_hash if use_pre_hash_pub_key is None else use_pre_hash_pub_key
    spki = spki or convertutils.subject_public_key_info_from_pubkey(
        public_key=signing_key.public_key(), use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash_pub_key
    )
    if for_kga:
        spki_kga = rfc5280.SubjectPublicKeyInfo()
        spki_kga["algorithm"] = spki["algorithm"]
        spki_kga["subjectPublicKey"] = univ.BitString("")
        csr["certificationRequestInfo"]["subjectPublicKeyInfo"] = spki_kga
    else:
        csr["certificationRequestInfo"]["subjectPublicKeyInfo"] = spki

    if subjectAltName is not None:
        if extensions is None:
            extensions = rfc9480.Extensions()

        extensions.append(prepare_subject_alt_name_extension(subjectAltName))

    if extensions is not None:
        csr = csr_add_extensions(csr=csr, extensions=extensions)

    if not exclude_signature and not for_kga:
        csr = sign_csr(
            csr=csr,
            signing_key=signing_key,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            bad_pop=bad_pop,
            use_pre_hash=use_pre_hash,
        )

    elif for_kga:
        csr["signature"] = univ.BitString("")
        # but must be set to something or define external function dataclass class to then encode the
        # data otherwise the structure will be empty and pyasn1 cannot be used!
        csr["signatureAlgorithm"] = spki["algorithm"]

    if not exclude_signature:
        # Needs to be en and decoded otherwise is the structure empty.
        der_data = encoder.encode(csr)
        csr, _ = decoder.decode(der_data, asn1Spec=rfc6402.CertificationRequest())

    return csr


# TODO remove


@not_keyword
def generate_signed_csr(  # noqa D417 undocumented-param
    common_name: str, key: Union[SignKey, str, None] = None, return_as_pem: bool = True, **params
) -> Tuple[Union[bytes, rfc6402.CertificationRequest], SignKey]:
    """Generate signed CSR for a given common name (CN).

    If a key is not provided, a new RSA key is generated. If a string is provided, it is used as the key generation
    algorithm (e.g., "rsa") with additional parameters. If a `PrivateKey` object is provided, it is used directly.

    Arguments:
    ---------
        - `common_name`: The common name (CN) to include in the CSR.
        - `key`: Optional. The private key to use for signing the CSR. Can be one of:
            - A `PrivateKey` object from the cryptography library.
            - A string representing the key generation algorithm (e.g., "rsa").
            As default will be a new RSA key generated.
        - `return_as_pem`: A flag indicating whether to return the CSR as PEM encoded bytes or the
        `pyasn1` object.
        - `params`: Additional keyword arguments to customize key generation when `key` is a string.

    Returns:
    -------
        - A Tuple the signed CSR in bytes and the corresponding private key.

    Raises:
    ------
        - `ValueError`: If the provided key is neither a valid key generation algorithm string nor
        a `PrivateKey` object which can be used to sign the certificate.

    Examples:
    --------
    | ${csr_signed} ${private_key}= | Generate Signed CSR | CN=${cm} | rsa | length=2048 |
    | ${csr_signed} ${private_key}= | Generate Signed CSR | CN=${cm} | ed25519 |

    """
    if key is None:
        key = keyutils.generate_key(algorithm="rsa")  # type: ignore
    elif isinstance(key, str):
        key = keyutils.generate_key(algorithm=key, **params)  # type: ignore
    elif isinstance(key, typingutils.PrivateKey):
        pass
    else:
        raise ValueError("`key` must be either an algorithm name or a private key")

    key = convertutils.ensure_is_sign_key(key)
    csr = build_csr(common_name=common_name, signing_key=key, exclude_signature=False)

    if return_as_pem:
        return utils.pyasn1_csr_to_pem(csr), key  # type: ignore

    return csr, key  # type: ignore


def _prepare_extended_key_usage(oids: List[univ.ObjectIdentifier], critical: bool = True) -> rfc5280.Extension:
    """Generate pyasn1 `ExtendedKeyUsage` object with the provided list of OIDs.

    :param oids: A list of OIDs (strings) representing the allowed usages.
    :param critical: Whether the extension should be marked as critical. Defaults to `True`.
    :return: Encoded ASN.1 ExtendedKeyUsage object.
    """
    extended_key_usage = rfc5280.ExtKeyUsageSyntax()

    for oid in oids:
        extended_key_usage.append(oid)

    ext = rfc5280.Extension()
    ext["extnID"] = rfc5280.id_ce_extKeyUsage
    ext["critical"] = critical
    ext["extnValue"] = univ.OctetString(encoder.encode(extended_key_usage))

    return ext


@keyword(name="Prepare SubjectKeyIdentifier Extension")
def prepare_ski_extension(  # noqa D417 undocumented-param
    key: Union[typingutils.PrivateKey, typingutils.PublicKey], critical: bool = True, invalid_ski: bool = False
) -> rfc5280.Extension:
    """Prepare a SubjectKeyIdentifier (SKI) extension.

    Used to ask for this extension by the server, or for negative testing, by sending the ski of another key.

    Arguments:
    ---------
        - `key`: The public or private key to prepare the extension for.
        - `critical`: Whether the extension should be marked as critical. Defaults to `True`.
        - `invalid_ski`: Whether to prepare an invalid SKI value. Defaults to `False`.

    Returns:
    -------
        - The populated `Extension` structure.

    Examples:
    --------
    | ${extension}= | Prepare SubjectKeyIdentifier Extension | key=${private_key} |
    | ${extension}= | Prepare SubjectKeyIdentifier Extension | key=${private_key} | invalid_ski=True |

    """
    if isinstance(key, typingutils.PrivateKey):
        key = key.public_key()
    ski: bytes = x509.SubjectKeyIdentifier.from_public_key(key).key_identifier  # type: ignore

    if invalid_ski:
        ski = utils.manipulate_first_byte(ski)

    subject_key_identifier = rfc5280.SubjectKeyIdentifier(ski)

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_subjectKeyIdentifier
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(encoder.encode(subject_key_identifier))
    return extension


@keyword(name="Prepare AuthorityKeyIdentifier Extension")
def prepare_authority_key_identifier_extension(  # noqa D417 undocumented-param
    ca_key: Union[VerifyKey, rfc9480.CMPCertificate],
    critical: bool = True,
    invalid_key_id: bool = False,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    include_issuer: bool = False,
    include_serial_number: bool = False,
    increase_serial: bool = False,
    ca_name: Optional[str] = None,
    general_names: Optional[List[rfc9480.GeneralName]] = None,
) -> rfc5280.Extension:
    """Prepare an `AuthorityKeyIdentifier` extension.

    Used to ask for this extension by the server, or for negative testing, by sending the aki of another key.

    Arguments:
    ---------
        - `ca_key`: The public key or certificate to prepare the extension for.
        - `critical`: Whether the extension should be marked as critical. Defaults to `True`.
        - `invalid_key_id`: Whether to prepare an invalid AKI value. Defaults to `False`.
        - `ca_cert`: The CA certificate to prepare the extension for. (does not include the issuer, \
        if `general_names` is provided) Defaults to `None`.
        - `include_issuer`: Whether to include the issuer in the extension. Defaults to `False`.
        - `include_serial_number`: Whether to include the serial number in the extension. Defaults to `False`.
        - `increase_serial`: Whether to increase the serial number by one. Defaults to `False`.
        - `ca_name`: The name of the CA. Defaults to `None`.
        - `general_names`: The general names to include in the extension. Defaults to `None`.

    Returns:
    -------
        - The populated `Extension` structure.

    Raises:
    ------
        - `ValueError`: If the CA certificate is not provided when including the serial number.
        - `ValueError`: If the CA certificate, name or `general_names` are not provided when including the issuer.

    Examples:
    --------
    | ${extension}= | Prepare AuthorityKeyIdentifier Extension | ca_key=${private_key} |

    """
    if isinstance(ca_key, rfc9480.CMPCertificate):
        ca_key = ca_key["certificationRequestInfo"]["subjectPublicKeyInfo"]
        ca_key = keyutils.load_public_key_from_spki(ca_key)  # type: ignore

    aki = rfc5280.AuthorityKeyIdentifier()
    key_id = x509.SubjectKeyIdentifier.from_public_key(ca_key).key_identifier  # type: ignore
    key_id: bytes
    if invalid_key_id:
        key_id = utils.manipulate_first_byte(key_id)
    aki["keyIdentifier"] = key_id

    if include_issuer and ca_cert is None and general_names is None and ca_name is None:
        raise ValueError("The CA certificate, name or `general_names` must be provided to include the issuer.")

    if include_serial_number and ca_cert is None:
        raise ValueError("The CA certificate must be provided to include the serial number.")

    if include_issuer or ca_name is not None:
        if ca_name is not None:
            issuer = prepareutils.prepare_name(ca_name)
            aki["authorityCertIssuer"][0]["directoryName"]["rdnSequence"] = issuer["rdnSequence"]
        elif ca_cert is not None and general_names is None:
            issuer = ca_cert["tbsCertificate"]["subject"]["rdnSequence"]
            aki["authorityCertIssuer"][0]["directoryName"]["rdnSequence"] = issuer

        if general_names is not None:
            aki["authorityCertIssuer"].extend(general_names)

    if include_serial_number:
        _num = int(ca_cert["tbsCertificate"]["serialNumber"])  # type: ignore
        if increase_serial:
            _num += 1
        aki["authorityCertSerialNumber"] = _num

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_authorityKeyIdentifier
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(encoder.encode(aki))
    return extension


@keyword(name="Prepare BasicConstraints Extension")
def prepare_basic_constraints_extension(  # noqa D417 undocumented-param
    ca: bool = False, path_length: Optional[Strint] = None, critical: bool = True
) -> rfc5280.Extension:
    """Prepare BasicConstraints extension.

    Arguments:
    ---------
        - `ca`: A boolean indicating if the certificate is a CA. Defaults to `False`.
        - `path_length`: The path length, which is allowed to be followed. Defaults to `None`.
        - `critical`: Whether the extension should be marked as critical. Defaults to `True`.

    Returns:
    -------
        - The populated `Extension` structure.

    Raises:
    ------
        - `ValueError`: If the path length is not a valid integer.

    Examples:
    --------
    | ${extension}= | Prepare BasicConstraints Extension | ca=True | path_length=3 |

    """
    basic_constraints = rfc5280.BasicConstraints()
    basic_constraints["cA"] = ca

    if path_length is not None:
        basic_constraints["pathLenConstraint"] = int(path_length)

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_basicConstraints
    extension["critical"] = critical
    extension["extnValue"] = encoder.encode(basic_constraints)
    return extension


@keyword(name="Prepare SubjectAltName Extension")
def prepare_subject_alt_name_extension(  # noqa D417 undocumented-param
    dns_names: Optional[str] = None,
    gen_names: Optional[Union[Sequence[rfc5280.GeneralName], rfc5280.GeneralName]] = None,
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare a `SubjectAltName` extension for a certificate.

    Parses a comma-separated string of DNS names and constructs a `SubjectAltName`.

    Arguments:
    ---------
        - `dns_names`: A comma-separated string of DNS names to include in the extension.
        (e.g., `"example.com,www.example.com,pki.example.com"`).
        - `gen_names`: A single or a list of `GeneralName` objects to include in the extension. Defaults to `None`.
        - `critical`: Whether the extension should be marked as critical. Defaults to `False`.

    Returns:
    -------
        - The populated `Extension` structure.

    Raises:
    ------
        - `ValueError`: If no values are provided for the extension.

    Examples:
    --------
    | ${extension}= | Prepare SubjectAltName Extension | subject_alt_name=example.com,www.example.com |
    | ${extension}= | Prepare SubjectAltName Extension | gen_names=${gen_names} |

    """
    if dns_names is None and gen_names is None:
        raise ValueError("At least one of the parameters must be provided.")

    san = rfc5280.SubjectAltName()

    names = []
    if dns_names is not None:
        items = dns_names.strip().split(",")
        names = [prepareutils.prepare_general_name(name_type="dNSName", name_str=item) for item in items]

    if gen_names is not None:
        if isinstance(gen_names, rfc5280.GeneralName):
            names.append(gen_names)
        else:
            names.extend(gen_names)

    san.extend(names)
    der_data = encoder.encode(san)

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_subjectAltName
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(der_data)
    return extension


@keyword(name="Prepare IssuerAltName Extension")
def prepare_issuer_alt_name_extension(  # noqa D417 undocumented-param
    dns_name: Optional[str] = None,
    gen_names: Optional[Union[Sequence[rfc5280.GeneralName], rfc5280.GeneralName]] = None,
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare an `IssuerAltName` extension for a certificate.

    Parses a comma-separated string of DNS names and constructs an `IssuerAltName`.

    Arguments:
    ---------
        - `dns_name`: A comma-separated string of DNS names to include in the extension.
        (e.g., `"example.com,www.example.com,pki.example.com"`). Defaults to `None`.
        - `gen_names`: A single or a list of `GeneralName` objects to include in the extension. Defaults to `None`.
        - `critical`: Whether the extension should be marked as critical. Defaults to `False`.

    Returns:
    -------
        - The populated `Extension` structure.

    Raises:
    ------
        - `ValueError`: If no values are provided for the extension.

    Examples:
    --------
    | ${extension}= | Prepare IssuerAltName Extension | dns_name=example.com,www.example.com |
    | ${extension}= | Prepare IssuerAltName Extension | gen_names=${gen_names} |

    """
    if dns_name is None and gen_names is None:
        raise ValueError("At least one of the parameters must be provided.")

    entries = rfc5280.IssuerAltName()
    if dns_name is not None:
        items = dns_name.strip().split(",")
        for item in items:
            out = prepareutils.prepare_general_name(name_type="dNSName", name_str=item)

            entries.append(out)

    if isinstance(gen_names, rfc5280.GeneralName):
        entries.append(gen_names)
    elif gen_names is not None:
        entries.extend(gen_names)

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_issuerAltName
    extension["critical"] = critical
    extension["extnValue"] = encoder.encode(entries)
    return extension


def _prepare_policy_constraints_extension(
    require_explicit_policy: Optional[int] = None,
    inhibit_policy_mapping: Optional[int] = None,
    critical: bool = True,
) -> rfc5280.Extension:
    """Prepare a `PolicyConstraints` extension for a certificate.

    :param require_explicit_policy: The maximum number of additional certificates that may be issued.
    :param inhibit_policy_mapping: The maximum number of additional certificates that may be issued.
    :param critical: Whether the extension should be marked as critical. Defaults to `True`.
    :return: The populated `pyasn1` `Extension` structure.
    """
    policy_constraints = rfc5280.PolicyConstraints()

    if require_explicit_policy is not None:
        policy_constraints["requireExplicitPolicy"] = require_explicit_policy

    if inhibit_policy_mapping is not None:
        policy_constraints["inhibitPolicyMapping"] = inhibit_policy_mapping

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_policyConstraints
    extension["critical"] = critical
    extension["extnValue"] = encoder.encode(policy_constraints)
    return extension


@keyword(name="Prepare KeyUsage Extension")
def prepare_key_usage_extension(  # noqa D417 undocumented-param
    key_usage: str, critical: bool = True, invalid_data: bool = False
) -> rfc5280.Extension:
    """Prepare a `KeyUsage` extension for a `CMPCertificate`, `CSR` or `CertTemplate`.

    Arguments:
    ---------
        - `key_usage`: A string specifying the key usage extension, which
          describes the intended purpose of the key (e.g., "digitalSignature", "keyEncipherment").
        - `critical`: Whether the extension should be marked as critical. Defaults to `True`.
        - `invalid_data`: Whether to prepare an invalid key usage value. Defaults to `False`.

    Returns:
    -------
        - The populated `Extension` structure.

    Raises:
    ------
        - `ValueError`: If an invalid key usage value is provided.

    Examples:
    --------
    | ${extension}= | Prepare KeyUsage Extension | key_usage=digitalSignature |

    """
    if not invalid_data:
        try:
            usage = rfc5280.KeyUsage(key_usage)
        except pyasn1.error.PyAsn1Error as e:
            raise ValueError(
                f"Invalid key usage value: `{key_usage}`. Allowed are: {list(rfc5280.KeyUsage.namedValues.keys())}."
            ) from e
        der_key_usage = encoder.encode(usage)
        data = univ.OctetString(der_key_usage)
    else:
        data = univ.OctetString(os.urandom(16))

    key_usage_ext = rfc5280.Extension()
    key_usage_ext["extnID"] = rfc5280.id_ce_keyUsage
    key_usage_ext["critical"] = critical
    key_usage_ext["extnValue"] = data
    return key_usage_ext


def prepare_extensions(  # noqa D417 undocumented-param
    key_usage: Optional[str] = None,
    eku: Optional[str] = None,
    key: Optional[Union[PrivateKey, PublicKey]] = None,
    is_ca: Optional[bool] = None,
    path_length: Optional[Strint] = None,
    invalid_extension: bool = False,
    critical: bool = True,
    ca_key: Optional[Union[VerifyKey, rfc9480.CMPCertificate]] = None,
    SubjectAltName: Optional[str] = None,
) -> rfc9480.Extensions:
    """Prepare a `pyasn1` Extensions structure.

    Used to request extensions that the end entity wants in the newly issued certificate.

    Arguments:
    ---------
        - `key_usage`: A string specifying the key usage extension, which
          describes the intended purpose of the key (e.g., "digitalSignature", "keyEncipherment").
        - `eku`: Comma-seperated CMP related extended key usages. One or all of the following values are allowed: \
        "cmcCA", "cmcRA" or "cmKGA".
        - `key`: Optional public or private key to generate the subjectKeyIdentifier extension.
        - `is_ca`: A boolean indicating, if a certificate is issued for a CA. Defaults to `None`. (not included).
        - `path_length`: The length of the which is allowed to follow after the CA certificate.
        - `negative`: Adds `rsaEncryption` as a critical extension.
        - `is_critical`: Whether the extension(s) should be marked as critical. Defaults to `True`.
        - `ca_key`: The public key or the certificate of the CA.
        Used to generate the authority key identifier extension. Defaults to `None`.
        - `SubjectAltName`: A comma-separated string of DNS names to include in the extension.
        (e.g., `"example.com,www.example.com,pki.example.com"`).

    Returns:
    -------
        - A `Extensions` structure populated with the provided key usage and extended key usage fields.

    Raises:
    ------
        - `ValueError`: If no extension to prepare is specified.
        - `ValueError`: If invalid values are provided for the key usage or extended key usage fields.

    Examples:
    --------
    | ${extensions}= | Prepare Extensions | key_usage=digitalSignature | cm_kga=True |
    | ${extensions}= | Prepare Extensions | eku=cmcCA, cmcRA, cmKGA |
    | ${extensions}= | Prepare Extensions | negative=True |
    | ${extensions}= | Prepare Extensions | key_usage=keyCertSign | is_ca=True | path_length=1 |
    | ${extensions}= | Prepare Extensions | key=${public_key} | key_usage=digitalSignature | is_critical=False |

    """
    extensions = rfc9480.Extensions()

    if key_usage is not None:
        key_usage_ext = prepare_key_usage_extension(key_usage=key_usage, critical=critical)
        extensions.append(key_usage_ext)

    if eku is not None:
        names = set(eku.strip(" ").split(","))
        vals = ["cmcCA", "cmcRA", "cmKGA"]
        not_inside = names - set(vals)
        expected_eku = {oid: name for oid, name in CMP_EKU_OID_2_NAME.items() if name.strip(" ") in names}

        if not expected_eku or not_inside:
            raise ValueError("No CMP extended key usages where provided allowed are: 'cmcCA, cmcRA, cmKGA'")

        ext = _prepare_extended_key_usage(oids=list(expected_eku.keys()), critical=critical)
        extensions.append(ext)

    if key is not None:
        extensions.append(prepare_ski_extension(key, critical=critical))

    if is_ca is not None or path_length is not None:
        is_ca = is_ca if is_ca is not None else False
        extensions.append(prepare_basic_constraints_extension(ca=is_ca, path_length=path_length, critical=critical))

    if SubjectAltName is not None:
        extensions.append(prepare_subject_alt_name_extension(SubjectAltName, critical=critical))

    if invalid_extension:
        extensions.append(_prepare_invalid_extensions()[0])

    if ca_key is not None:
        extensions.append(prepare_authority_key_identifier_extension(ca_key, critical=critical))

    if len(extensions) == 0:
        raise ValueError("No value to set a extension, was provided!")

    return extensions


def modify_cert_extensions(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate,
    extension_oid: Optional[str] = None,
    extension_hex_val: Optional[str] = None,
    include_other_extensions: bool = True,
) -> rfc9480.Extensions:
    """Modify the certificate extensions for negative testing purposes.

    This function creates an `Extensions` structure that modifies or introduces incorrect values
    for testing negative scenarios. It adds a new extension with the provided OID and value and can
    optionally include the extensions from the original certificate.

    Arguments:
    ---------
        - `certificate`: The original certificate in `pyasn1` format from which existing
          extensions can be included.
        - `extension_oid`: The OID for the custom extension to be added. Defaults to the \
        `rsaEncryption` OID
          if not provided.
        - `extension_hex_val`: The hexadecimal string representing the value for the custom extension.
          If not provided, a default value is used.
        - `include_other_extensions`: Whether to include other existing extensions from the original certificate.
          Defaults to `True`.

    Returns:
    -------
        - The modified `pyasn1` `Extensions` structure containing the custom and/or original extensions.

    Examples:
    --------
    | ${modified_extensions}= | Modify Cert Extensions | certificate=${cert} | extension_oid=1.2.840.113549.1.1.5 \
    | extension_hex_val=123456 |
    | ${modified_extensions}= | Modify Cert Extensions | certificate=${cert} | include_other_extensions=False |

    """
    oid = univ.ObjectIdentifier(extension_oid) if extension_oid else rfc9481.rsaEncryption
    extensions = _prepare_invalid_extensions(oid=oid, extension_hex_val=extension_hex_val)

    if include_other_extensions:
        extensions.extend(cert["tbsCertificate"]["extensions"])

    return extensions


def _prepare_invalid_extensions(
    oid=rfc9481.rsaEncryption, extension_hex_val: Optional[str] = None, critical: bool = True
) -> rfc9480.Extensions:
    """Prepare a valid `Extensions` structure with an invalid extension object and a given or randomly generated value.

    :param oid: Optional `ObjectIdentifier` to use as the extension ID. Defaults to `rsaEncryption`.
    :param extension_hex_val: Optional hex string representing the extension value.
    If not provided, a random 16-byte value is generated.
    :param critical: A bool indicating whether the extension should be critical. Defaults to True.
    :return: A `rfc9480.Extensions` object containing the invalid extension.
    """
    extensions = rfc5280.Extensions()
    ext_value = rfc5280.Extension()
    ext_value["extnID"] = oid
    ext_value["critical"] = critical
    extension_hex_val = extension_hex_val or os.urandom(16).hex()
    ext_value["extnValue"] = univ.OctetString().fromHexString(extension_hex_val)
    extensions.append(ext_value)
    return extensions


def sign_cert(  # noqa: D417 Missing argument descriptions in the docstring
    signing_key: SignKey,
    cert: rfc9480.CMPCertificate,
    hash_alg: Optional[str] = "sha256",
    use_rsa_pss: bool = False,
    bad_sig: bool = False,
    use_pre_hash: bool = False,
    patch_sig_fields: bool = True,
) -> rfc9480.CMPCertificate:
    """Sign a `CMPCertificate` object with the provided private key.

    Arguments:
    ---------
        - `signing_key`: The private key used to sign the certificate.
        - `cert`: The certificate to sign.
        - `hash_alg`: The hash algorithm used for signing. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `False`.
        - `modify_signature`: The signature will be modified by changing the first byte.
        - `bad_sig`: The signature will be manipulated to be invalid.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `patch_sig_fields`: Whether to patch the signature and signatureAlgorithm fields in the certificate.
        Defaults to `True`.

    Returns:
    -------
        - The signed `CMPCertificate` object with the attached `signature` and the `signatureAlgorithm`.

    Examples:
    --------
    | ${signed_cert}= | Sign Cert | ${signing_key} | ${cert} |
    | ${signed_cert}= | Sign Cert | ${signing_key} | ${cert} | use_rsa_pss=True |
    | ${signed_cert}= | Sign Cert | ${signing_key} | ${cert} | bad_sig=True |

    """
    if not patch_sig_fields:
        if not cert["tbsCertificate"]["signature"].isValue:
            raise ValueError(
                "The signatureAlgorithm and tbsCertificate signature field must be set to sign the certificate."
            )

    if patch_sig_fields:
        cert["signatureAlgorithm"] = prepare_alg_ids.prepare_sig_alg_id(
            signing_key=signing_key,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            use_pre_hash=use_pre_hash,
        )
        cert["tbsCertificate"]["signature"] = cert["signatureAlgorithm"]

    der_tbs_cert = encoder.encode(cert["tbsCertificate"])

    signature = cryptoutils.sign_data(
        data=der_tbs_cert,
        key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
    )

    logging.info("Certificate signature: %s", signature.hex())

    if bad_sig:
        signature = utils.manipulate_bytes_based_on_key(signature, signing_key)
        logging.info("Modified certificate signature: %s", signature.hex())

    cert["signature"] = univ.BitString.fromOctetString(signature)

    return cert


@not_keyword
def generate_certificate(
    private_key: Union[str, PrivateKey],
    common_name: str = "CN=Hans Mustermann",
    hash_alg: Union[None, str] = "sha256",
    ski: Optional[bool] = False,
    serial_number: Optional[Strint] = None,
    signing_key: Optional[SignKey] = None,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    extensions: Optional[rfc9480.Extensions] = None,
    days: int = 365,
    use_rsa_pss: bool = False,
    bad_sig: bool = False,
) -> rfc9480.CMPCertificate:
    """Generate a complete `CMPCertificate` using specified parameters.

    :param private_key: Private key used to generate the certificate.
    :param common_name: Common name for the subject, in OpenSSL notation.
    :param hash_alg: Hash algorithm for signing (e.g., "sha256"). Defaults to "sha256".
    :param ski: If `True`, includes the SubjectKeyIdentifier extension. Defaults to `False`.
    :param serial_number: Optional serial number for the certificate. Generate a random serial number if not provided.
    :param signing_key: Optional signing key for the certificate. Defaults to `private_key` if not provided.
    :param issuer_cert: Optional issuer certificate; self-signed if not provided.
    :param extensions: Optional `rfc9480.Extensions` to include in the certificate.
    :param use_rsa_pss: Whether to use RSA-PSS for signing. Defaults to `False`.
    :param days: The duration in days for which the certificate remains valid. Defaults to 365 days.
    :param bad_sig: Whether to generate a bad signature. Defaults to `False`.
    :return: `rfc9480.CMPCertificate` object representing the created certificate.
    """
    cert = rfc9480.CMPCertificate()

    if isinstance(private_key, str):
        private_key = keyutils.generate_key(algorithm=private_key)

    if serial_number is None:
        serial_number = x509.random_serial_number()

    signing_key = convertutils.ensure_is_sign_key(signing_key or private_key)

    if extensions is not None and ski:
        extensions = prepare_extensions(key=private_key)

    tbs_cert = prepare_tbs_certificate(
        subject=common_name,
        signing_key=signing_key,
        public_key=private_key.public_key(),
        serial_number=int(serial_number),
        issuer_cert=issuer_cert,
        extensions=extensions,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        days=int(days),
    )
    cert["tbsCertificate"] = tbs_cert
    return sign_cert(
        signing_key=signing_key,
        cert=cert,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        bad_sig=bad_sig,
    )


def build_certificate(  # noqa D417 undocumented-param
    private_key: Optional[Union[str, PrivateKey]] = None,
    common_name: str = "CN=Hans",
    hash_alg: str = "sha256",
    ski: bool = False,
    ca_key: Optional[SignKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    **params,
) -> Tuple[rfc9480.CMPCertificate, PrivateKey]:
    """Build an `pyasn1` `CMPCertificate` that can be customized based on provided parameters.

    Arguments:
    ---------
        - `private_key`: An optional private key object. If not provided, an ECC key will be generated.
        - `common_name`: The common name for the certificate subject, in OpenSSL notation. Defaults to `CN=Hans`.
        - `hash_alg`: The hash algorithm for signing, Defaults to `sha256`. If the key is (ed25519 or ed448),
                      it will be ignored.
        - `ski`: If `True`, includes the SubjectKeyIdentifier (ski) extension in the certificate. Defaults to `False`.
        - `signing_key`: A optional private key used to sign the certificate.
        - `issuer_cert`: The issuer’s certificate. If not provided, the certificate is self-signed.

    **params (Additional optional parameters for customization):
    -----------------------------------------------------------
        - `serial_number` (int, str): The serial number for the certificate. If omitted, a random number is generated.
        - `days` (int, str): Number of days for certificate validity, starting from `not_valid_before`. Defaults to 365.
        - `validity` (rfc5280.Validity): Start date of the certificate’s validity. Defaults to now.
        - `is_ca` (bool): Indicates if the certificate is for a CA (Certificate Authority). Defaults to `False`.
        - `path_length` (int): The maximum path length for CA certificates.
        - `key_alg` (str): Algorithm for key generation (e.g., "ecdsa"). Defaults to `ec`.
        - `key_usage` (str): Specific key usage (e.g., "digitalSignature") to set on the certificate.
        - `eku` (str): Extended key usage to set for the certificate.
        - `bad_sig` (bool): Whether to generate a bad signature. Defaults to `False`.

    Returns:
    -------
        - A tuple containing the generated certificate and the private key.

    Raises:
    ------
        - `ValueError`: If the provided key is not allowed to sign a certificate.

    Examples:
    --------
    | ${certificate} ${private_key}= | Build Certificate | keyAlg=ecdsa |
    | ${certificate} ${private_key}= | Build Certificate | private_key=${key} \
    | serial_number=12345 | days=730 |
    | ${certificate} ${private_key}= | Build Certificate | private_key=${key} \
    | sign_key=${sign_key} | issuer_cert=${cert} |

    """
    if isinstance(private_key, str):
        cert_key = keyutils.generate_key(algorithm=private_key, **params)

    elif private_key is None:
        cert_key = keyutils.generate_key(algorithm="ecc", **params)

    else:
        cert_key = private_key

    ski_key = cert_key.public_key() if ski else None  # type: ignore

    ext = params.get("key_usage") or ski or params.get("eku") or params.get("is_ca") or params.get("path_length")
    extensions = params.get("extensions")
    if ext and extensions is None:
        extensions = prepare_extensions(
            key_usage=params.get("key_usage"),
            key=ski_key,
            eku=params.get("eku"),
            is_ca=params.get("is_ca"),
            path_length=params.get("path_length"),
            critical=params.get("critical", False),
        )

    ca_key = convertutils.ensure_is_sign_key(ca_key or cert_key)
    certificate = generate_certificate(
        common_name=common_name,
        private_key=cert_key,
        hash_alg=hash_alg,
        serial_number=params.get("serial_number"),
        signing_key=ca_key,
        issuer_cert=ca_cert,
        extensions=extensions,  # type: ignore
        use_rsa_pss=params.get("use_rsa_pss", False),
        days=int(params.get("days", 365)),
        bad_sig=params.get("bad_sig", False),
    )
    return certificate, cert_key


def modify_common_name_cert(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate, issuer: bool = True
) -> str:
    """Modify the common name (CN) of either the issuer or subject field of a certificate.

    Arguments:
    ---------
        - `cert`: The `pyasn1` certificate object to modify.
        - `issuer`: A boolean indicating whether to modify the issuer (`True`) or subject (`False`) field.
                    Defaults to `True`.

    Returns:
    -------
        - A string representing the updated Name attribute in OpenSSL notation (e.g., "CN=Example,O=Org,C=US").

    Raises:
    ------
        - `ValueError`: If the certificate does not contain a valid issuer or subject field.

    Examples:
    --------
    | ${updated_name}= | Modify Common Name Cert | cert=${certificate} | issuer=False |
    | ${updated_name}= | Modify Common Name Cert | cert=${certificate} | issuer=True |

    """
    field = "issuer"
    if not issuer:
        field = "subject"

    issuer_name = utils.get_openssl_name_notation(  # type: ignore
        certextractutils.get_field_from_certificate(cert, field),  # type: ignore
        oids=None,
        return_dict=True,
    )
    issuer_name: Optional[dict]
    if not issuer_name:
        utils.log_certificates([cert])
        raise ValueError("The certificate did not contain a value in the `issuer` field.")

    issuer_name["CN"] = cmputils.modify_random_str(issuer_name["CN"], index=-1)
    data = ""
    for x, y in issuer_name.items():
        data += x + "=" + y + ","

    return data[0:-1]


def _prepare_issuer_and_subject(
    cert_template: rfc9480.CertTemplate,
    exclude_list: List[str],
    subject: Optional[str] = None,
    issuer: Optional[str] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc9480.CertTemplate:
    """Populate the issuer and subject fields of a certificate template.

    :param cert_template: The certificate template to modify.
    :param exclude_list: List of field names to exclude from the template (e.g., ["issuer", "subject"]).
    :param subject: Optional string for the subject's distinguished name. In rfc4514 notation.
    :param issuer: Optional string for the issuer's distinguished name. In rfc4514 notation.
    :param cert: Optional certificate object to extract `issuer` and `subject` values if not provided.
    :return: The modified `CertTemplate` object with issuer and subject fields set if applicable.
    """
    if cert is not None:
        issuer = issuer or utils.get_openssl_name_notation(cert["tbsCertificate"]["issuer"])  # type: ignore
        subject = subject or utils.get_openssl_name_notation(cert["tbsCertificate"]["subject"])  # type: ignore

    if subject and "subject" not in exclude_list:
        subject_obj = rfc5280.Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))
        subject_obj = prepareutils.prepare_name(common_name=subject, target=subject_obj)
        cert_template.setComponentByName("subject", subject_obj)

    if issuer and "issuer" not in exclude_list:
        issuer_obj = rfc5280.Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        issuer_obj = prepareutils.prepare_name(common_name=issuer, target=issuer_obj)
        cert_template.setComponentByName("issuer", issuer_obj)

    return cert_template


def _prepare_extensions_for_cert_template(
    cert_template: rfc9480.CertTemplate,
    exclude: bool,
    cert: Optional[rfc9480.CMPCertificate] = None,
    extensions: Optional[rfc9480.Extensions] = None,
    include_cert_extensions: bool = False,
) -> rfc9480.CertTemplate:
    """Add extensions to a certificate template if specified.

    :param cert_template: The certificate template to modify.
    :param exclude: Boolean flag indicating whether to exclude the `extensions` field from the template.
    :param cert: Optional certificate object to extract extensions if none are provided.
    :param extensions: Optional `rfc5280.Extensions` object to use in the template.
    :param include_cert_extensions: Optional `include also extensions from the certificate.
    Defaults to False.
    :return: The modified `CertTemplate` object with the `extensions` field populated if `exclude` is False.
    """
    if cert is not None:
        if extensions is not None:
            if include_cert_extensions:
                extensions.extend(cert["tbsCertificate"]["extensions"])
        else:
            extensions = cert["tbsCertificate"]["extensions"]

    if extensions is None or exclude:
        return cert_template

    extensions_field = rfc5280.Extensions().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))
    for ext in extensions:
        extensions_field.append(ext)
    cert_template.setComponentByName("extensions", extensions_field)
    return cert_template


@keyword(name="Prepare CertTemplate")
def prepare_cert_template(  # noqa D417 undocumented-param
    key: Optional[Union[typingutils.PrivateKey, typingutils.PublicKey]] = None,
    subject: Optional[str] = None,
    issuer: Optional[str] = None,
    include_fields: Optional[str] = None,
    exclude_fields: str = "validity",
    serial_number: Optional[typingutils.Strint] = None,
    version: Optional[typingutils.Strint] = None,
    validity: Optional[rfc5280.Validity] = None,
    extensions: Optional[ExtensionsType] = None,
    for_kga: bool = False,
    sign_alg: Optional[rfc9480.AlgorithmIdentifier] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    include_cert_extensions: bool = True,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
    use_pre_hash: bool = False,
) -> rfc9480.CertTemplate:
    """Prepare a `pyasn1` `CertTemplate` structure for `rr`,`ir`, `cr`, or `kur` `PKIBody` types.

    Constructs a `CertTemplate` object for certificate-related PKI messages. It populates
    the template with specified values such as the key, subject, issuer, serial number, version, and extensions.
    Optionally, fields can be included or excluded to customize the template, and a certificate object
    can be used to extract these values.

    Arguments:
    ---------
        - `key`: The key to include in the certificate. If a private key
          is provided, the public key is extracted. Defaults to `None`.
        - `subject`: The subject name for the certificate in OpenSSL notation. Defaults to `None`.
        - `issuer`: The issuer name for the certificate in OpenSSL notation. Defaults to `None`.
        - `include_fields`: A comma-separated string of fields to include in the template. \
        Defaults to `None`.
        - `exclude_fields`: A comma-separated string of fields to exclude from the template. Defaults to `"validity"`.
        - `serial_number`: The serial number for the certificate. Defaults to `None`.
        - `version`: The version of the certificate. Defaults to `None`.
        - `validity`: The validity of the CertTemplate. excepted to be created with `prepare_validity`.
        Defaults to `None`.
        - `extensions`: Extensions to include in the certificate. Defaults to `None`.
        - `for_kga`: Indicates if the template is for key generation authentication (KGA). Defaults to `False`.
        - `cert`: A certificate object to extract values from. Defaults to `None`.
        - `include_cert_extensions`: Indicates if the extensions from the certificate should be added to the extensions,
        if provided. Defaults to `True`.
        - `spki`: The `SubjectPublicKeyInfo` object to include in the template. Defaults to `None`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.

    Returns:
    -------
        - A `CertTemplate` object populated with the specified or extracted values.

    Raises:
    ------
        - `ValueError`: If required fields are missing or invalid.

    Examples:
    --------
    | ${cert_template}= | Prepare CertTemplate | cert=${cert_path} | exclude_fields=validity |
    | ${cert_template}= | Prepare CertTemplate | cert=${cert_obj} | serial_number=1234 |

    """
    cert_template = rfc4211.CertTemplate()
    add_up = []

    if for_kga and key is None:
        add_up = ["publicKey"]

    # Filter fields to exclude and include
    exclude_list = (
        utils.filter_options(options=list(cert_template.keys()), exclude=exclude_fields, include=include_fields)
        + add_up
    )
    logging.info("exclude_fields: %s", str(exclude_list))

    if cert is not None:
        serial_number = serial_number or int(cert["tbsCertificate"]["serialNumber"])

    cert_template = _prepare_issuer_and_subject(
        cert_template=cert_template, exclude_list=exclude_list, subject=subject, issuer=issuer, cert=cert
    )

    if serial_number is not None and "serialNumber" not in exclude_list:
        serial_number_component = univ.Integer(serial_number).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        cert_template.setComponentByName("serialNumber", serial_number_component)

    if version is not None and "version" not in exclude_list:
        cert_template.setComponentByName("version", version)

    cert_template = _prepare_extensions_for_cert_template(
        cert_template=cert_template,
        exclude="extensions" in exclude_list,
        cert=cert,
        extensions=extensions,  # type: ignore
        include_cert_extensions=include_cert_extensions,
    )

    if "validity" not in exclude_list:
        opt_validity = _prepare_optional_validity(asn1cert=cert, validity=validity)
        if opt_validity is not None:
            cert_template["validity"] = opt_validity

    if "publicKey" not in exclude_list:
        cert_template["publicKey"] = _prepare_public_key_for_cert_template(
            key=key, for_kga=for_kga, cert=cert, use_pre_hash=use_pre_hash, spki=spki
        )

    if sign_alg is not None and "signingAlg" not in exclude_list:
        cert_template["signingAlg"]["algorithm"] = sign_alg["algorithm"]
        cert_template["signingAlg"]["parameters"] = sign_alg["parameters"]

    logging.info("%s", cert_template.prettyPrint())
    return cert_template


def _prepare_optional_validity(
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
    asn1cert: Optional[rfc9480.CMPCertificate] = None,
    validity: Optional[rfc5280.Validity] = None,
) -> Union[None, rfc4211.OptionalValidity]:
    """Prepare an `pyasn1` OptionalValidity object with optional notBefore and notAfter fields.

    :param not_before: Optional start time for the validity period.
    :param not_after: Optional end time for the validity period.
    :param asn1cert: An optional `rfc9480.CMPCertificate` object to extract validity times from, if provided.
    :param validity: An optional `rfc5280.Validity` to convert.
    :return: An `OptionalValidity` object populated with the specified or extracted validity period or `None`,
    if no value is provided.
    """
    if validity is not None:
        return convertutils.validity_to_optional_validity(validity)

    if asn1cert is not None:
        validity_obj = asn1cert["tbsCertificate"]["validity"]
        not_before = not_before or convertutils.pyasn1_time_obj_to_py_datetime(validity_obj["notBefore"])
        not_after = not_after or convertutils.pyasn1_time_obj_to_py_datetime(validity_obj["notAfter"])

    optional_validity = rfc4211.OptionalValidity().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
    )

    if not_before is not None:
        not_before_t_obj = useful.GeneralizedTime().fromDateTime(not_before)
        not_before_obj = rfc5280.Time().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        not_before_obj.setComponentByName("generalTime", not_before_t_obj)
        optional_validity["notBefore"] = not_before_obj

    if not_after is not None:
        not_after_t_obj = useful.GeneralizedTime().fromDateTime(not_after)
        not_after_obj = rfc5280.Time().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        not_after_obj.setComponentByName("generalTime", not_after_t_obj)
        optional_validity["notAfter"] = not_after_obj

    if optional_validity.hasValue():
        return optional_validity

    return None


def _prepare_public_key_for_cert_template(
    key: Optional[Union[PrivateKey, PublicKey]] = None,
    for_kga: bool = False,
    cert: Optional[rfc9480.CMPCertificate] = None,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare the `pyasn1` `SubjectPublicKeyInfo` for the `CertTemplate` structure.

    :param key: A private or public key object. If a private key is provided, the public key will be extracted.
    :param for_kga: Boolean flag indicating whether to prepare the key for non-local-key generation.
    :param cert: Optional `rfc9480.CMPCertificate` object to extract the public key from if no `key` is provided.
    :param use_rsa_pss: Whether to prepare the public key as RSA-PSS. Defaults to `False`.
    :param use_pre_hash: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
    :return: A `SubjectPublicKeyInfo` object ready to be used in a certificate template.
    """
    public_key_obj = rfc5280.SubjectPublicKeyInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
    )

    if spki is not None and not for_kga:
        spki_temp = convertutils.copy_subject_public_key_info(target=public_key_obj, filled_sub_pubkey_info=spki)
        return spki_temp

    if spki is not None and for_kga:
        public_key_obj["algorithm"] = spki["algorithm"]
        public_key_obj["subjectPublicKey"] = univ.BitString("")
        return public_key_obj

    if cert is not None and key is None:
        key = certutils.load_public_key_from_cert(cert=cert)

    elif isinstance(key, PrivateKey):
        key = key.public_key()  # type: ignore

    if key is None and cert is None:
        return rfc5280.SubjectPublicKeyInfo().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))

    public_key_obj = rfc5280.SubjectPublicKeyInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
    )

    if key is None:
        raise ValueError("The key cannot be None, if the `for_kga` is set to `False`!")

    if not for_kga:
        cert_public_key = convertutils.subject_public_key_info_from_pubkey(
            public_key=key, use_pre_hash=use_pre_hash, use_rsa_pss=use_rsa_pss
        )
        public_key_obj = copyasn1utils.copy_subject_public_key_info(
            target=public_key_obj, filled_sub_pubkey_info=cert_public_key
        )
    else:
        cert_public_key = convertutils.subject_public_key_info_from_pubkey(
            public_key=key, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash
        )

        public_key_obj["algorithm"] = cert_public_key["algorithm"]
        public_key_obj["subjectPublicKey"] = univ.BitString("")

    return public_key_obj


@keyword(name="CSR Add Extensions")
def csr_add_extensions(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest, extensions: rfc5280.Extensions
) -> rfc6402.CertificationRequest:
    """Add pyasn1-structured extensions, provided as a list, to a pyasn1 CSR.

    Arguments:
    ---------
       - `csr`: The `CertificationRequest` object to which the extensions will be added.
       - `extensions`: `pyasn1` Extensions structure to add.

    Returns:
    -------
        - The updated `CertificationRequest` with the extensions added.

    Examples:
    --------
    | ${updated_csr}= | CSR Add Extensions | csr=${csr} | extensions=${extensions_list} |

    """
    # the extensions are wrapped in a sequence before they go into the set
    wrapping_sequence = univ.Sequence()
    for index, extension in enumerate(extensions):
        wrapping_sequence[index] = AttributeValue(encoder.encode(extension))

    # rfc2985.pkcs_9_at_extensionRequest
    attribute = prepare_single_value_attr(
        attr_type=univ.ObjectIdentifier("1.2.840.113549.1.9.14"), attr_value=wrapping_sequence
    )

    csr["certificationRequestInfo"]["attributes"].append(attribute)
    return csr


@not_keyword
def prepare_single_value_attr(attr_type: univ.ObjectIdentifier, attr_value: Any) -> rfc5652.Attribute:
    """Prepare an attribute for a CSR.

    :param attr_type: The Object Identifier (OID) for the attribute.
    :param attr_value: The value of the attribute to be encoded.
    :return: The populated `Attribute` structure.
    """
    attr = rfc5652.Attribute()
    attr["attrType"] = attr_type
    attr["attrValues"][0] = encoder.encode(attr_value)
    return attr


# TODO add function to prepare RelativeDistinguishedName structure


@keyword(name="CSR Extend Subject")
def csr_extend_subject(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest, rdn: rfc5280.RelativeDistinguishedName
) -> rfc6402.CertificationRequest:
    """Extend the SubjectName in a pyasn1-structured CSR with a pyasn1 RelativeDistinguishedName structure.

    Arguments:
    ---------
        - `csr`: The `pyasn1` csr object to update.
        - `rdn`: The `RelativeDistinguishedName` structure to update the csr with.

    Returns:
    -------
        - The updated csr.

    Examples:
    --------
    | ${updated_csr}= | CSR Extend Subject | csr=${csr} | rdn=${rdn} |

    """
    original_subject = csr["certificationRequestInfo"]["subject"][0]
    current_length = len(original_subject)
    original_subject[current_length] = rdn
    return csr


@not_keyword
def prepare_cert_template_from_csr(csr: rfc6402.CertificationRequest) -> rfc4211.CertTemplate:
    """Prepare a `CertTemplate` structure from a given Certification Signing Request (CSR).

    Extracts necessary information from a PKCS#10 Certification Request to populate a `CertTemplate`,
    which is used in certificate management operations.

    :param csr: The pyasn1 `CertificationRequest` object representing the CSR.
    :return: A populated `rfc4211.CertTemplate` containing the extracted public key, subject, and extensions.
    """
    der_data = encoder.encode(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])
    public_key = certutils.load_public_key_from_der(der_data)
    extensions = certextractutils.extract_extensions_from_csr(csr)
    subject = utils.get_openssl_name_notation(csr["certificationRequestInfo"]["subject"])  # type: ignore
    subject: str
    return prepare_cert_template(key=public_key, subject=subject, extensions=extensions)


@keyword(name="Prepare SubjectPublicKeyInfo")
def prepare_subject_public_key_info(  # noqa D417 undocumented-param
    key: Optional[Union[PrivateKey, PublicKey]] = None,
    for_kga: bool = False,
    key_name: Optional[str] = None,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
    hash_alg: Optional[str] = None,
    invalid_key_size: bool = False,
    add_params_rand_bytes: bool = False,
    add_null: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare a `SubjectPublicKeyInfo` structure for a `Certificate`, `CSR` or `CertTemplate`.

    For invalid Composite keys must the private key be provided.

    Note: If the key is a CompositeSig key, the `key_name` the private key must be provided,
    if the RSA key has an invalid key size.

    Arguments:
    ---------
        - `key`: The public or private key to use for the `SubjectPublicKeyInfo`.
        - `for_kga`: A flag indicating whether the key is for a key generation authority (KGA).
        - `key_name`: The key algorithm name to use for the `SubjectPublicKeyInfo`.
        (can be set to `rsa_kem`. RFC9690). Defaults to `None`.
        - `use_rsa_pss`: Whether to use RSA-PSS padding. Defaults to `False`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `hash_alg`: The pre-hash algorithm to use for the pq signature key. Defaults to `None`.
        - `invalid_key_size`: A flag indicating whether the key size is invalid. Defaults to `False`.
        - `add_params_rand_bytes`: A flag indicating whether to add random bytes to the key parameters. \
        Defaults to `False`.
        - `add_null`: A flag indicating whether to add a null value to the key parameters. Defaults to `False`.

    Returns:
    -------
        - The populated `SubjectPublicKeyInfo` structure.

    Raises:
    ------
        - `ValueError`: If no key is provided and the for_kga flag is not set.
        - `ValueError`: If both `add_null` and `add_params_rand_bytes` are set.


    Examples:
    --------
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | use_rsa_pss=True |
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | key_name=rsa-kem |
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | for_kga=True |
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | add_null=True |

    """
    if key is None and not for_kga:
        raise ValueError("Either a key has to be provided or the for_kga flag have to be set.")

    if add_null and add_params_rand_bytes:
        raise ValueError("Either `add_null` or `add_params_rand_bytes` can be set, not both.")

    if isinstance(key, AbstractCompositePrivateKey):
        pub_key = key.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.Raw)
        spki = rfc5280.SubjectPublicKeyInfo()
        pub_key = pub_key if not invalid_key_size else pub_key + b"\x00"
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(pub_key)
        if isinstance(key, CompositeSig03PrivateKey):
            oid = key.get_oid(use_pss=use_rsa_pss, pre_hash=use_pre_hash)
        else:
            oid = key.get_oid()
        spki["algorithm"]["algorithm"] = oid

        if add_null:
            spki["algorithm"]["parameters"] = univ.Null("")

        if add_params_rand_bytes:
            spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))

        return spki

    if isinstance(key, PrivateKey):
        key = key.public_key()

    if for_kga:
        return _prepare_spki_for_kga(
            key=key,
            key_name=key_name,
            use_pss=use_rsa_pss,
            use_pre_hash=use_pre_hash,
            add_null=add_null,
            add_params_rand_bytes=add_params_rand_bytes,
        )

    if key_name in ["rsa-kem", "rsa_kem"]:
        key = RSAEncapKey(key)  # type: ignore

    spki = subject_public_key_info_from_pubkey(
        public_key=key,  # type: ignore
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        hash_alg=hash_alg,
    )

    if invalid_key_size:
        tmp = spki["subjectPublicKey"].asOctets() + b"\x00\x00"
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(tmp)

    if add_params_rand_bytes:
        spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))

    return spki


def _prepare_spki_for_kga(
    key: Optional[Union[PrivateKey, PublicKey]] = None,
    key_name: Optional[str] = None,
    use_pss: bool = False,
    use_pre_hash: bool = False,
    add_null: bool = False,
    add_params_rand_bytes: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare a SubjectPublicKeyInfo for KGA usage.

    :param key: A private or public key.
    :param key_name: An optional key algorithm name.
    :param use_pss: Whether to use PSS padding for RSA and a RSA-CompositeKey.
    :param use_pre_hash: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
    :param add_null: Whether to add a null value to the key parameters. Defaults to `False`.
    :param add_params_rand_bytes: Whether to add random bytes to the key parameters. Defaults to `False`.
    :return: The populated `SubjectPublicKeyInfo` structure.
    """
    if add_null and add_params_rand_bytes:
        raise ValueError("Either `add_null` or `add_params_rand_bytes` can be set, not both.")

    spki = rfc5280.SubjectPublicKeyInfo()
    spki["subjectPublicKey"] = univ.BitString("")

    if key is not None:
        if isinstance(key, typingutils.PrivateKey):
            key = key.public_key()

    if key_name and key_name in ["rsa", "dsa", "ecc", "rsa-kem"]:
        names_2_oid = {
            "rsa": univ.ObjectIdentifier("1.2.840.113549.1.1.1"),
            "dsa": univ.ObjectIdentifier("1.2.840.10040.4.1"),
            "ecc": univ.ObjectIdentifier("1.2.840.10045.3.1.7"),
            "rsa-kem": id_rsa_kem_spki,
        }
        spki["algorithm"]["algorithm"] = names_2_oid[key_name]
        if key_name == "ecc":
            spki["algorithm"]["parameters"] = rfc5480.ECParameters()
            spki["algorithm"]["parameters"]["namedCurve"] = rfc5480.secp256r1

    if key_name is not None:
        from pq_logic.combined_factory import CombinedKeyFactory

        key = CombinedKeyFactory.generate_key(key_name).public_key()
        spki_tmp = subject_public_key_info_from_pubkey(public_key=key, use_rsa_pss=use_pss, use_pre_hash=use_pre_hash)
        spki["algorithm"]["algorithm"] = spki_tmp["algorithm"]["algorithm"]

    elif key is not None:
        spki_tmp = subject_public_key_info_from_pubkey(public_key=key, use_rsa_pss=use_pss)
        spki["algorithm"]["algorithm"] = spki_tmp["algorithm"]["algorithm"]

    if add_null:
        spki["algorithm"]["parameters"] = univ.Null("")

    if add_params_rand_bytes:
        spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))

    return spki


@not_keyword
def default_validity(
    days: int = 3650,
    optional_validity: Optional[Union[rfc5280.Validity, rfc4211.OptionalValidity]] = None,
    max_days_before: Optional[Union[int, str]] = 10,
) -> rfc5280.Validity:
    """Prepare a default `Validity` structure for a certificate.

    :param days: The number of days for which the certificate remains valid. Defaults to `3650` days.
    :param optional_validity: Optional `rfc5280.Validity` object to use for the certificate. Defaults to `None`.
    :param max_days_before: Specifies the maximum allowable difference, in days, between
    the `notBefore` date and the current date. Defaults to `10` days.
    :return: The prepared `Validity` structure.
    """
    not_before = datetime.now(timezone.utc)
    if optional_validity is not None:
        # print(cert_template["validity"].isValue)
        # bug in pyasn1-alt-modules, validity is always a value.
        # even if it is not set.
        # if cert_template["validity"].isValue: is always `True`.
        if optional_validity["notBefore"].isValue:
            time_type = optional_validity["notBefore"].getName()
            tmp = optional_validity["notBefore"][time_type].asDateTime

            if max_days_before is not None:
                if tmp < datetime.now(timezone.utc) - timedelta(days=float(max_days_before)):
                    raise BadCertTemplate("The `notBefore` date is too far in the past.")

            not_before = tmp

        if optional_validity["notAfter"].isValue:
            time_type = optional_validity["notAfter"].getName()
            not_after = optional_validity["notAfter"][time_type].asDateTime
        else:
            not_after = not_before + timedelta(days=days)
        return prepare_validity(not_before, not_after)

    # otherwise will OpenSSL say: "certificate is not yet valid"
    not_before = datetime.now() - timedelta(days=1)
    not_after = not_before + timedelta(days=days)
    return prepare_validity(not_before, not_after)


@keyword(name="Build Cert From CertTemplate")
def build_cert_from_cert_template(  # noqa D417 undocumented-param
    cert_template: rfc9480.CertTemplate,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    hash_alg: Optional[str] = "sha256",
    for_crr_request: bool = False,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Build a certificate from a CertTemplate.

    Arguments:
    ---------
        - `cert_template`: The CertTemplate to build the certificate from.
        - `ca_cert`: The CA certificate.
        - `ca_key`: The CA private key.
        - `hash_alg`: The hash algorithm to use (e.g. "sha256"). Defaults to `sha256`.
        - `for_crr_request`: Whether to build the certificate for a cross-certification request.
         Defaults to `False`.

    **kwargs:
    ---------
        - `use_rsa_pss`: Whether to use RSA-PSS or not. Defaults to `True`.
        - `bad_sig`: Whether to create a certificate with an invalid signature. Defaults to `False`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `alt_sign_key`: An alternative key to sign the certificate with. Defaults to `None`.
        - `alt_hash_alg`: The hash algorithm to use with the alternative key. Defaults to `None`.
        - `alt_use_rsa_pss`: Whether to use RSA-PSS with the alternative key. Defaults to `False`.
        - `extensions`: Extensions to include in the certificate. Defaults to `None`.
        (as an example for OCSP, CRL or etc.)

    Returns:
    -------
        - The built certificate.

    Raises:
    ------
        - `BadCertTemplate`: If the `notBefore` date is too far in the past.

    Examples:
    --------
    | ${cert}= | Build Cert From CertTemplate | cert_template=${cert_template} | ca_cert=${ca_cert} | ca_key=${ca_key} |

    """
    tbs_certs = prepare_tbs_certificate_from_template(
        cert_template=cert_template,
        issuer=ca_cert["tbsCertificate"]["subject"],
        ca_key=ca_key,
        hash_alg=hash_alg or "sha256",
        use_rsa_pss=kwargs.get("use_rsa_pss", True),
        use_pre_hash=kwargs.get("use_pre_hash", False),
        include_extensions=False,
        for_crr_request=for_crr_request,
    )

    pub_key = ca_key.public_key()
    pub_key = convertutils.ensure_is_verify_key(pub_key)
    extns = check_extensions(
        cert_template=cert_template, ca_public_key=pub_key, other_extensions=kwargs.get("extensions")
    )

    if extns.isValue:
        tbs_certs["extensions"].extend(extns)

    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_certs
    return _sign_cert(cert=cert, ca_key=ca_key, **kwargs)


def _prepare_shared_tbs_cert(
    subject: Union[str, rfc9480.Name],
    issuer: Union[rfc9480.CMPCertificate, rfc9480.Name],
    serial_number: Optional[Union[str, int]] = None,
    validity: Optional[Union[rfc4211.OptionalValidity, rfc5280.Validity]] = None,
    days: Union[str, int] = 3650,
    public_key: Optional[rfc5280.SubjectPublicKeyInfo] = None,
) -> rfc5280.TBSCertificate:
    """Prepare some attributes of `TBSCertificate` structure, for a certificate.

    :param subject: The subject of the certificate, either a string or a `Name` object.
    :param issuer: The issuer of the certificate, either a `CMPCertificate` or a `Name` object.
    :param serial_number: The serial number for the certificate. Defaults to `None`.
    :param validity: The validity of the certificate. Defaults to `None`.
    :param days: The number of days for which the certificate remains valid. Defaults to `3650` days.
    :return: The populated `TBSCertificate` structure.
    """
    tbs_cert = rfc5280.TBSCertificate()

    if isinstance(subject, rfc9480.Name):
        subject = subject["rdnSequence"]
    else:
        subject = prepareutils.prepare_name(common_name=subject)["rdnSequence"]

    tbs_cert["subject"]["rdnSequence"] = subject

    if isinstance(issuer, rfc9480.CMPCertificate):
        issuer = issuer["tbsCertificate"]["subject"]

    tbs_cert["issuer"] = issuer
    if serial_number is None:
        serial_number = x509.random_serial_number()
    tbs_cert["serialNumber"] = int(serial_number)
    tbs_cert["version"] = rfc5280.Version("v3").subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )

    if public_key is not None:
        tbs_cert["subjectPublicKeyInfo"] = copyasn1utils.copy_subject_public_key_info(
            target=rfc5280.SubjectPublicKeyInfo(), filled_sub_pubkey_info=public_key
        )

    if isinstance(validity, rfc5280.Validity):
        tbs_cert["validity"] = validity
    else:
        tbs_cert["validity"] = default_validity(days=int(days), optional_validity=validity)

    return tbs_cert


@not_keyword
def prepare_tbs_certificate_from_template(
    cert_template: rfc4211.CertTemplate,
    issuer: rfc9480.Name,
    ca_key: SignKey,
    serial_number: Optional[int] = None,
    hash_alg: str = "sha256",
    days: int = 3650,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
    include_extensions: bool = False,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
    for_crr_request: bool = False,
) -> rfc5280.TBSCertificate:
    """Prepare a `TBSCertificate` structure from a `CertTemplate`.

    :param cert_template: The `CertTemplate` to prepare the `TBSCertificate` from.
    :param issuer: The issuer of the certificate.
    :param ca_key: The CA private key.
    :param serial_number: The serial number for the certificate. Defaults to `None`.
    :param hash_alg: The hash algorithm to use. Defaults to `sha256`.
    :param days: The number of days for which the certificate remains valid. Defaults to `3650` days.
    :param use_rsa_pss: Whether to use RSA-PSS or not. Defaults to `False`.
    :param use_pre_hash: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
    :param include_extensions: Whether to include the extensions from the `CertTemplate`. Defaults to `False`.
    :param spki: The `SubjectPublicKeyInfo` object to include in the `TBSCertificate`. Defaults to `None`.
    :param for_crr_request: : Whether to build the certificate for a cross-certification request. Defaults to `False`.
    :return: The prepared `TBSCertificate` structure.
    """
    if serial_number is None:
        if cert_template["serialNumber"].isValue:
            serial_number = int(cert_template["serialNumber"])

    tbs_cert = _prepare_shared_tbs_cert(
        issuer=issuer,
        subject=cert_template["subject"],
        serial_number=serial_number,
        validity=cert_template["validity"],
        days=days,
        public_key=spki or cert_template["publicKey"],
    )

    if not for_crr_request:
        tbs_cert["signature"] = prepare_alg_ids.prepare_sig_alg_id(
            signing_key=ca_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash
        )
    else:
        tbs_cert["signature"]["algorithm"] = cert_template["signingAlg"]["algorithm"]
        tbs_cert["signature"]["parameters"] = cert_template["signingAlg"]["parameters"]

    if spki is not None:
        public_key = keyutils.load_public_key_from_spki(spki)
    else:
        public_key = keyutils.load_public_key_from_spki(tbs_cert["subjectPublicKeyInfo"])

    if include_extensions:
        tbs_cert["extensions"].extend(cert_template["extensions"])

    tbs_cert["extensions"].extend(
        prepare_extensions(
            key=public_key,
            critical=False,
        )
    )

    return tbs_cert


def _sign_cert(
    cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Sign a certificate.

    :param cert: The certificate to sign.
    :param ca_key: The CA private key to sign the certificate with.
    :param kwargs: Additional keyword arguments.
    :return: The signed certificate.
    """
    alt_sign_key = kwargs.get("alt_sign_key")

    if alt_sign_key is not None:
        # so that the catalyst logic can be in the matching file.
        from pq_logic.hybrid_sig.catalyst_logic import sign_cert_catalyst

        alt_sign_key = convertutils.ensure_is_pq_sign_key(alt_sign_key)
        trad_key = convertutils.ensure_is_trad_sign_key(ca_key)

        return sign_cert_catalyst(
            cert=cert,
            trad_key=trad_key,
            pq_key=alt_sign_key,
            hash_alg=kwargs.get("hash_alg", "sha256"),
            critical=kwargs.get("critical", False),
            pq_hash_alg=kwargs.get("alt_hash_alg"),
            use_rsa_pss=kwargs.get("alt_use_rsa_pss", False),
        )

    return sign_cert(
        cert=cert,
        signing_key=ca_key,
        hash_alg=kwargs.get("hash_alg", "sha256"),
        use_rsa_pss=kwargs.get("use_rsa_pss", True),
        use_pre_hash=kwargs.get("use_pre_hash", False),
        bad_sig=kwargs.get("bad_sig", False),
    )


@keyword(name="Build Cert from CSR")
def build_cert_from_csr(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest,
    ca_key: SignKey,
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    validity: Optional[rfc5280.Validity] = None,
    issuer: Optional[rfc9480.Name] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    include_csr_extensions: bool = True,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Build a certificate from a CSR.

    Arguments:
    ---------
        - `csr`: The CSR to build the certificate from.
        - `ca_key`: The CA private key.
        - `extensions`: Optional extensions to include in the certificate. Defaults to `None`.
        - `validity`: Optional validity period for the certificate. Defaults to `None`.
        - `issuer`: The issuer of the certificate. Defaults to `None`.
        - `ca_cert`: The CA certificate. Defaults to `None`.
        - `include_extensions`: Whether to include the extensions from the CSR. Defaults to `True`.

    **kwargs:
    ---------
        - `serial_number`: The serial number for the certificate. Defaults to `None`.
        - `hash_alg`: The hash algorithm to use for signing. Defaults to `sha256`.
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `days`: The number of days for which the certificate remains valid. Defaults to `3650` days.
        - `critical`: Whether the catalyst extensions are critical. Defaults to `False`.
        - `hash_alg`: The hash algorithm to use for signing. Defaults to `sha256`.
        - `alt_hash_alg`: The hash algorithm to use for the alternative signing key. Defaults to `sha256`.
        - `alt_use_rsa_pss`: Whether to use RSA-PSS for the alternative signing key. Defaults to `False`.
        - `alt_sign_key`: Optional alternative signing key to use. Defaults to `None`.

    Returns:
    -------
        - The build certificate.

    Raises:
    ------
        - `ValueError`: If neither the issuer nor the CA certificate is provided.

    Examples:
    --------
    | ${cert}= | Build Cert from CSR | csr=${csr} | ca_key=${ca_key} | ca_cert=${ca_cert} |
    | ${cert}= | Build Cert from CSR | csr=${csr} | ca_key=${ca_key} | ca_cert=${ca_cert} | days=3650 |

    """
    hash_alg = kwargs.get("hash_alg", "sha256")

    if issuer is None and ca_cert is None:
        raise ValueError(
            "Either the issuer or the CA certificate have to be provided.to build a certificate, from a CSR."
        )
    if ca_cert is not None:
        issuer = ca_cert["tbsCertificate"]["subject"]

    if issuer is None:
        raise ValueError("The issuer is not set and can not be derived from the CSR.")

    tbs_cert = _prepare_shared_tbs_cert(
        issuer=issuer,
        subject=csr["certificationRequestInfo"]["subject"],
        serial_number=kwargs.get("serial_number", None),
        validity=validity,
        days=int(kwargs.get("days", 3650)),
        public_key=csr["certificationRequestInfo"]["subjectPublicKeyInfo"],
    )

    tbs_cert["signature"] = prepare_alg_ids.prepare_sig_alg_id(
        signing_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=kwargs.get("use_rsa_pss", True),
        use_pre_hash=kwargs.get("use_pre_hash", False),
    )
    if include_csr_extensions:
        extn = certextractutils.extract_extensions_from_csr(csr=csr)
        if extensions is not None and extn is not None:
            tbs_cert["extensions"].extend(extensions)

    if extensions is not None:
        tbs_cert["extensions"].extend(extensions)

    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_cert
    return _sign_cert(cert=cert, ca_key=ca_key, **kwargs)


@not_keyword
def prepare_tbs_certificate(
    subject: str,
    signing_key: SignKey,
    public_key: typingutils.PublicKey,
    serial_number: Optional[int] = None,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    extensions: Optional[rfc9480.Extensions] = None,
    validity: Optional[rfc5280.Validity] = None,
    days: int = 3650,
    use_rsa_pss: bool = False,
    hash_alg: Optional[str] = "sha256",
    use_pre_hash: bool = False,
    use_rsa_pss_pubkey: bool = False,
    use_pre_hash_pubkey: bool = False,
) -> rfc5280.TBSCertificate:
    """Prepare the `TBSCertificate` structure for a certificate with specified parameters.

    :param subject: The subject's distinguished name in OpenSSL notation (e.g., "C=US, ST=California, L=San Francisco").
    :param signing_key: Private key used for signing.
    :param public_key: Public key associated with the subject.
    :param serial_number: Serial number of the certificate.
    :param issuer_cert: Optional, the issuer's certificate (self-signed if not provided).
    :param extensions: Optional extensions to include in the certificate.
    :param validity: Optional `Validity` object defining the certificate's validity period.
    :param days: Number of days the certificate is valid if `validity` is not provided. Defaults to 365 days.
    :param use_rsa_pss: Whether to use RSA-PSS for signing. Defaults to `False`.
    :param hash_alg: Hash algorithm used for signing (e.g., "sha256"). Defaults to "sha256".
    :param use_pre_hash: Whether to use the pre-hash version for the composite-sig key signature. Defaults to `False`.
    :param use_rsa_pss_pubkey: Whether to use RSA-PSS for the CompositeSigKey public key. Defaults to `False`.
    :param use_pre_hash_pubkey: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
    :return: `rfc5280.TBSCertificate` object configured with the provided parameters.
    """
    subject_obj = prepareutils.prepare_name(subject)
    if issuer_cert is None:
        issuer = subject_obj
    else:
        issuer = copyasn1utils.copy_name(target=rfc9480.Name(), filled_name=issuer_cert["tbsCertificate"]["subject"])

    pub_key = convertutils.subject_public_key_info_from_pubkey(
        public_key=public_key, use_rsa_pss=use_rsa_pss_pubkey, use_pre_hash=use_pre_hash_pubkey
    )
    tbs_cert = _prepare_shared_tbs_cert(
        issuer=issuer,
        subject=subject_obj,
        serial_number=serial_number,
        validity=validity,
        days=days,
        public_key=pub_key,
    )
    if extensions is not None:
        exts = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        for ext in extensions:
            exts.append(ext)
        tbs_cert["extensions"] = exts

    tbs_cert["signature"] = prepare_alg_ids.prepare_sig_alg_id(
        signing_key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
    )
    return tbs_cert


@keyword(name="Prepare OCSPNoCheck Extension")
def prepare_ocsp_nocheck_extension(  # noqa D417 undocumented-param
    critical: bool = False,
    add_rand_val: bool = False,
) -> rfc5280.Extension:
    """Prepare an OCSP No Check extension for a certificate.

    Arguments:
    ---------
        - `critical`: Whether the extension is marked as critical or not. Defaults to `False`.
        - `add_rand_val`: Whether to add a random value to the extension, to create a invalid \
        extension (**MUST** be NULL). Defaults to `False`.


    Returns:
    -------
        - The prepared `OCSPNoCheck` extension.

    Examples:
    --------
    | ${ocsp_nocheck_ext}= | Prepare OCSPNoCheck Extension | True |
    | ${ocsp_nocheck_ext}= | Prepare OCSPNoCheck Extension | critical=True | add_rand_val=True |

    """
    return _prepare_extension(
        oid=rfc8954.id_pkix_ocsp_nocheck,
        critical=critical,
        value=univ.Null(""),
        add_rand_val=add_rand_val,
    )


@keyword(name="Prepare OCSP Extension")
def prepare_ocsp_extension(  # noqa D417 undocumented-param
    ocsp_url: Optional[str],
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare an OCSP extension for a certificate.

    Arguments:
    ---------
        - `ocsp_url`: The URL of the OCSP responder. Defaults to `None`.
        - `critical`: Whether the extension is marked as critical or not. Defaults to `False`.

    Returns:
    -------
        - The populated `Extension` object.

    Examples:
    --------
    | ${ocsp_ext}= | Prepare OCSP Extension | ocsp_url=${ocsp_url} | critical=True |

    """
    authority_info_access = rfc5280.AuthorityInfoAccessSyntax()
    if ocsp_url is not None:
        access_des = rfc5280.AccessDescription()
        access_des["accessMethod"] = rfc5280.id_ad_ocsp
        access_des["accessLocation"] = prepareutils.prepare_general_name(name_type="uri", name_str=ocsp_url)
        authority_info_access.append(access_des)

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_pe_authorityInfoAccess
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(encoder.encode(authority_info_access))
    return extension


def _prepare_extension(
    oid: univ.ObjectIdentifier,
    critical: bool = False,
    value: Optional[Union[bytes, Asn1Item]] = None,
    add_rand_val: bool = False,
) -> rfc5280.Extension:
    """Prepare an extension with the given OID.

    :param oid: The OID of the extension.
    :param critical: Whether the extension is marked as critical or not. Defaults to `False`.
    :param value: The value of the extension. Defaults to `None`.
    :param add_rand_val: Whether to add a random value to the extension. Defaults to `False`.
    """
    if not add_rand_val and value is None:
        raise ValueError("Either a value or the add_rand_val flag must be set.")

    if value is None:
        data = b""
    elif isinstance(value, Asn1Item):
        data = encoder.encode(value)
    else:
        data = value

    if add_rand_val:
        data += os.urandom(16)

    extension = rfc5280.Extension()
    extension["extnID"] = oid
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(data)
    return extension


def _prepare_crl_distribution_points(
    distribution_points: Optional[Union[Sequence[rfc5280.DistributionPoint], rfc5280.DistributionPoint]] = None,
    crl_issuers: Optional[_GeneralNamesType] = None,
    full_name: Optional[CRLFullNameType] = None,
    relative_name: Optional[rfc5280.RelativeDistinguishedName] = None,
) -> rfc5280.CRLDistributionPoints:
    """Prepare a CRL Distribution Point.

    :param distribution_points: A single or list of DistributionPoint objects.
    :param crl_issuers: CRL issuer name.
    :param full_name: List of GeneralName objects for the full name.
    :param relative_name: List of RelativeDistinguishedName objects for the relative name.
    :return: The populated `CRLDistributionPoints` structure.
    """
    crl_distribution_point = rfc5280.CRLDistributionPoints()

    if distribution_points is None:
        if crl_issuers is None and full_name is None and relative_name is None:
            raise ValueError("At least one of `crl_issuers`, `full_name`, or `relative_name` must be provided.")

    if distribution_points is not None:
        if isinstance(distribution_points, rfc5280.DistributionPoint):
            distribution_points = [distribution_points]

        for distribution_point in distribution_points:
            crl_distribution_point.append(distribution_point)

    if crl_issuers is not None or full_name is not None or relative_name is not None:
        distribution_point = prepare_distribution_point(
            crl_issuers=crl_issuers, full_name=full_name, relative_name=relative_name
        )
        crl_distribution_point.append(distribution_point)

    return crl_distribution_point


@keyword(name="Prepare CRLDistributionPoint Extension")
def prepare_crl_distribution_point_extension(  # noqa: D417 undocumented-param
    distribution_points: Optional[Union[Sequence[rfc5280.DistributionPoint], rfc5280.DistributionPoint]] = None,
    crl_issuers: Optional[_GeneralNamesType] = None,
    full_name: Optional[CRLFullNameType] = None,
    relative_name: Optional[rfc5280.RelativeDistinguishedName] = None,
    critical: bool = False,
    add_rand_val: bool = False,
) -> rfc5280.Extension:
    """Prepare a CRL Distribution Point extension.

    Arguments:
    ---------
        - distribution_points: A single or list of DistributionPoint objects.
        - crl_issuers: CRL issuer name.
        - full_name: List of GeneralName objects for the full name.
        - relative_name: A RelativeDistinguishedName objects for the relative name.
        - critical: Whether the extension is critical. Defaults to `False`.
        - add_rand_val: Whether to add a random value to the `extnValue` field. Defaults to `False`.

    Returns:
    -------
        - The populated `Extension` structure for the CRLDistributionPoints.

    Raises:
    ------
        - ValueError: If both `full_name` and `relative_name` are provided.
        - ValueError: If `distribution_points` is not provided and `crl_issuers`, `full_name`, \
        or `relative_name` are not provided.

    Examples:
    --------
    | ${crl_dp_ext} | Prepare CRLDistributionPoint Extension | crl_issuers="CN=Issuer" |
    | ${crl_dp_ext} | Prepare CRLDistributionPoint Extension | full_name="CN=FullName" |

    """
    crl_distribution_point = _prepare_crl_distribution_points(
        distribution_points=distribution_points,
        crl_issuers=crl_issuers,
        full_name=full_name,
        relative_name=relative_name,
    )

    return _prepare_extension(
        oid=rfc5280.id_ce_cRLDistributionPoints,
        critical=critical,
        value=crl_distribution_point,
        add_rand_val=add_rand_val,
    )


def _try_decode_extension_val(
    extensions: rfc9480.Extensions,
    extn_name: str,
    name: str,
) -> Optional[Union[bytes, Asn1Type]]:
    """Try to decode the extension value.

    :param extensions: The extensions to extract the value from.
    :param extn_name: The name of the extension which value to extract (e.g., "ski").
    :param name: The name of the extension (e.g., "SubjectKeyIdentifier").
    """
    try:
        tmp = rfc9480.CMPCertificate()
        tmp["tbsCertificate"]["extensions"].extend(extensions)
        return certextractutils.get_field_from_certificate(tmp, extension=extn_name)
    except pyasn1.error.PyAsn1Error as e:
        raise BadAsn1Data(f"The `{name}` extension could not be decoded.", overwrite=True, error_details=str(e)) from e


ALL_KEY_USAGES = {
    "digitalSignature",  # (0) digitalSignature
    "nonRepudiation",  # (1) nonRepudiation (also known as contentCommitment)
    "keyEncipherment",  # (2) keyEncipherment
    "dataEncipherment",  # (3) dataEncipherment
    "keyAgreement",  # (4) keyAgreement
    "keyCertSign",  # (5) keyCertSign
    "cRLSign",  # (6) cRLSign
    "encipherOnly",  # (7) encipherOnly
    "decipherOnly",  # (8) decipherOnly
}


def _check_sig_key(key_usages: Set[str], name: str):
    """Check the signature key."""
    sig_usages = {"digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"}
    sig_disallowed = {"keyEncipherment", "dataEncipherment", "keyAgreement", "encipherOnly", "decipherOnly"}

    unknown_usages = sig_disallowed - ALL_KEY_USAGES
    if unknown_usages:
        raise ValueError(f"Unknown key usages: {unknown_usages}")

    if not set(key_usages).issubset(sig_usages):
        raise BadCertTemplate(f"The {name} `KeyUsage` must be one of: {sig_usages}")
    if set(key_usages) & sig_disallowed:
        raise BadCertTemplate(f"{name} `KeyUsage` must not include: {sig_disallowed}")


def _check_ecc_key_usage(key_usages: Set[str], name: str):
    """Check the ECC key usage."""
    # RFC 8813 and RFC 5480
    disallowed = {"keyEncipherment", "dataEncipherment"}

    if key_usages & disallowed:
        raise BadCertTemplate(f"{name} `KeyUsage` must not include: {disallowed}")

    # RFC 5480:
    # Check dependencies for encipherOnly and decipherOnly
    if ("encipherOnly" in key_usages or "decipherOnly" in key_usages) and "keyAgreement" not in key_usages:
        raise BadCertTemplate("encipherOnly and decipherOnly require keyAgreement to be set.")

    if key_usages & {"encipherOnly", "decipherOnly"}:
        raise BadCertTemplate(f"The {name} `KeyUsage` can only be: encipherOnly or decipherOnly")


def _check_x_ecc_key_usage(key_usages: Set[str], name: str):
    """Check the X25519/X448 key usage."""
    # RFC 8410 and RFC 9295
    allowed = {"decipherOnly", "encipherOnly", "keyAgreement"}
    disallowed = ALL_KEY_USAGES - allowed

    if key_usages & disallowed:
        raise BadCertTemplate(f"{name} `KeyUsage` must not include: {disallowed}")

    # Check dependencies for encipherOnly and decipherOnly
    if ("encipherOnly" in key_usages or "decipherOnly" in key_usages) and "keyAgreement" not in key_usages:
        raise BadCertTemplate("encipherOnly and decipherOnly require keyAgreement to be set.")

    if key_usages & {"encipherOnly", "decipherOnly"}:
        raise BadCertTemplate(f"The {name} `KeyUsage` can only be: encipherOnly or decipherOnly")


def _verify_key_usage(cert_template: rfc9480.CertTemplate) -> Optional[rfc5280.Extension]:
    """Verify the key usage."""
    key_usage = _try_decode_extension_val(  # type: ignore
        extensions=cert_template["extensions"],
        extn_name="key_usage",
        name="KeyUsage",
    )
    key_usage: Optional[rfc5280.KeyUsage]

    if key_usage is None:
        logging.info("Key usage extension was not present in the parsed certificate.")
        return None

    key_usages = asn1utils.get_set_bitstring_names(key_usage).split(", ")  # type: ignore
    public_key = keyutils.load_public_key_from_cert_template(cert_template)

    if public_key is None:
        raise ValueError(
            "The public key could not be extracted from the certificate template."
            "The `KeyUsage` extension cannot be verified."
        )

    if hasattr(public_key, "name"):
        _name = public_key.name  # type: ignore
        if is_kem_public_key(public_key):
            if set(key_usages) != {"keyEncipherment"}:
                raise BadCertTemplate(f"{_name} keyUsage must only contain: keyEncipherment")
        elif isinstance(public_key, VerifyKey):
            _check_sig_key(set(key_usages), _name)
        else:
            raise ValueError(f"Unknown key type: {_name}, for verifying the key usage.")
    else:
        name = keyutils.get_key_name(public_key)
        if name in ["ed448", "ed25519", "dsa"]:
            _check_sig_key(set(key_usages), name)

        elif name == "ecdsa":
            _check_ecc_key_usage(set(key_usages), "ECC")

        elif name in ["rsa"]:
            pass
        elif name in ["x25519", "x448"]:
            _check_x_ecc_key_usage(set(key_usages), name)

        else:
            raise ValueError(f"Unknown key type: {name}, for verifying the key usage.")

    return prepare_key_usage_extension(
        key_usage=",".join(key_usages),
        critical=True,
    )


def _verify_subject_key_identifier(cert_template: rfc9480.CertTemplate) -> Optional[rfc5280.Extension]:
    """Verify the subject key identifier."""
    tmp = rfc9480.CMPCertificate()
    tmp["tbsCertificate"]["extensions"].extend(cert_template["extensions"])

    ski = _try_decode_extension_val(  # type: ignore
        extensions=cert_template["extensions"],
        extn_name="ski",
        name="SubjectKeyIdentifier",
    )
    ski: bytes

    public_key = keyutils.load_public_key_from_cert_template(cert_template, must_be_present=True)
    if ski is None:
        logging.info("Subject key identifier extension was not present in the parsed certificate.")
        return None

    computed_ski = x509.SubjectKeyIdentifier.from_public_key(public_key)  # type: ignore
    computed_ski = computed_ski.key_identifier

    if computed_ski != ski:
        raise BadCertTemplate("The `SubjectKeyIdentifier` value did not match the computed value.")

    if public_key is None:
        raise ValueError(
            "The public key could not be extracted from the certificate template."
            "The `SubjectKeyIdentifier` extension cannot be computed."
        )

    return prepare_ski_extension(
        key=public_key,
        critical=False,
    )


def _verify_authority_key_identifier(
    cert_template: rfc9480.CertTemplate, ca_public_key: VerifyKey, ca_cert: Optional[rfc9480.CMPCertificate] = None
) -> Optional[rfc5280.Extension]:
    """Verify the authority key identifier."""
    aki = _try_decode_extension_val(  # type: ignore
        extensions=cert_template["extensions"],
        extn_name="aki",
        name="AuthorityKeyIdentifier",
    )
    aki: Optional[rfc5280.AuthorityKeyIdentifier]

    if aki is None:
        logging.info("Authority key identifier extension was not present in the parsed certificate.")
        return None

    if aki["keyIdentifier"].isValue:
        extracted_aki = aki["keyIdentifier"].asOctets()
        computed_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key)  # type: ignore
        computed_aki = computed_aki.key_identifier

        if computed_aki != extracted_aki:
            raise BadCertTemplate("The `AuthorityKeyIdentifier` value did not match the computed value.")

    if ca_cert is None and (aki["authorityCertIssuer"].isValue or aki["authorityCertSerialNumber"].isValue):
        raise ValueError(
            "The CA certificate must be provided to verify the `AuthorityKeyIdentifier` "
            "when the `authorityCertIssuer` or the `authorityCertSerialNumber` choices are present."
        )

    if ca_cert is None:
        return prepare_authority_key_identifier_extension(
            ca_key=ca_public_key,
            critical=False,
        )

    if aki["authorityCertIssuer"].isValue:
        if not compareutils.find_name_inside_general_names(
            gen_names=aki["authorityCertIssuer"],
            name=ca_cert["tbsCertificate"]["subject"],
        ):
            raise BadCertTemplate(
                "The `AuthorityKeyIdentifier` `authorityCertIssuer` did not match the CA certificate's subject."
            )

    if aki["authorityCertSerialNumber"].isValue:
        if int(aki["authorityCertSerialNumber"]) != int(ca_cert["tbsCertificate"]["serialNumber"]):
            raise BadCertTemplate(
                "The `AuthorityKeyIdentifier` `authorityCertSerialNumber` did not match the CA "
                "certificate's serial number."
            )

    return prepare_authority_key_identifier_extension(
        ca_key=ca_public_key,
        critical=False,
    )


def _verify_extended_key_usage(cert_template: rfc9480.CertTemplate) -> Optional[rfc5280.Extension]:
    """Verify the extended key usage.

    Checks if the extended key usage is present and if it is validly built.

    :param cert_template: The certificate template.
    :return: The `ExtendedKeyUsage` extension if present and valid.
    :raises BadCertTemplate: If the `ExtendedKeyUsage` extension is not valid.
    """
    # TODO update to validate the `EKU` OIDs.
    # verifies if the structure is valid.
    _ = _try_decode_extension_val(  # type: ignore
        extensions=cert_template["extensions"],
        extn_name="eku",
        name="ExtendedKeyUsage",
    )

    return certextractutils.get_extension(cert_template["extensions"], rfc5280.id_ce_extKeyUsage)


def verify_ca_basic_constraints(  # noqa D417 undocumented-param
    cert_template: Union[rfc9480.CertTemplate, rfc9480.Extensions], allow_non_crit: bool = True, set_crit: bool = False
) -> Optional[rfc5280.Extension]:
    """Verify the basic constraints for a CA certificate.

    Checks if the basic constraints are present and if they are validly built.

    Arguments:
    ---------
        - `cert_template`: The certificate template or extension to verify.
        - `allow_non_crit`: Whether to allow non-critical extensions. Defaults to `True`.
        - `set_crit`: Whether to set the extension as critical. Defaults to `False`.
        - `allow_non_crit`: Whether to allow non-critical extensions. Defaults to `True`.
        - `set_crit`: Whether to set the extension as critical. Defaults to `False`.

    Returns:
    -------
        - The `BasicConstraints` extension if present and valid.

    Raises:
    ------
        - `BadCertTemplate`: If the `BasicConstraints` extension cannot be decoded.
        - `BadCertTemplate`: If the CA was set to False but pathLenConstraint was not 0 or absent.
        - `BadCertTemplate`: If the CA was set to True but pathLenConstraint was 0 or less.
        - `BadCertTemplate`: If the `BasicConstraints` extension must be marked as critical and was not.

    Examples:
    --------
    | ${basic_con}= | Verify CA Basic Constraints | cert_template=${cert_template} |
    | ${basic_con}= | Verify CA Basic Constraints | cert_template=${cert_template} | set_crit=True |
    | ${basic_con}= | Verify CA Basic Constraints | cert_template=${extensions} | allow_non_crit=False |

    """
    basic_con = _try_decode_extension_val(  # type: ignore
        extensions=cert_template["extensions"], extn_name="basic_constraints", name="BasicConstraints"
    )
    basic_con: Optional[rfc5280.BasicConstraints]

    if basic_con is None:
        logging.info("Basic constraints extension was not present in the parsed certificate.")
        return None

    path_len = 0 if not basic_con["pathLenConstraint"].isValue else int(basic_con["pathLenConstraint"])
    if basic_con["cA"] is False and path_len != 0:
        raise BadCertTemplate(
            "The `BasicConstraints` extension is not valid. CA was set to False but `pathLenConstraint` "
            "was not 0 or absent."
        )

    if basic_con["pathLenConstraint"].isValue:
        path_len = int(basic_con["pathLenConstraint"])
        is_ca = bool(basic_con["cA"])
        if is_ca is True and path_len <= 0:
            raise BadCertTemplate(
                "The `BasicConstraints` extension is not valid. CA was set to True but `pathLenConstraint` "
                "was less than 0."
            )

        if not is_ca and path_len > 0:
            raise BadCertTemplate("A end entity certificate can not have a path length greater 0 set.")

    if isinstance(cert_template, rfc9480.CertTemplate):
        if cert_template["publicKey"].isValue:
            is_ca = bool(basic_con["cA"])
            oid = cert_template["publicKey"]["algorithm"]["algorithm"]
            if oid in PQ_SIG_PRE_HASH_OID_2_NAME:
                if is_ca:
                    _name = may_return_oid_to_name(oid)
                    raise BadCertTemplate(
                        f"A CA certificate can not have a PQ PreHash signature algorithm.OID: {_name}"
                    )

            if oid in COMPOSITE_SIG04_HASH_OID_2_NAME or oid in COMPOSITE_SIG03_HASH_OID_2_NAME:
                if is_ca:
                    _name = may_return_oid_to_name(oid)
                    raise BadCertTemplate(
                        f"A CA certificate can not have a Composite Signature PreHash algorithm.OID: {_name}"
                    )
    extn = certextractutils.get_extension(
        cert_template["extensions"],  # type: ignore
        rfc5280.id_ce_basicConstraints,
    )
    extn: rfc5280.Extension
    if set_crit:
        extn["critical"] = True

    if not allow_non_crit and not extn["critical"]:
        raise BadCertTemplate("The `BasicConstraints` extension must be marked as critical.")

    return certextractutils.get_extension(cert_template["extensions"], rfc5280.id_ce_basicConstraints)


def _verify_subject_alt_name(cert_template: rfc9480.CertTemplate) -> Optional[rfc5280.Extension]:
    """
    Verify the SubjectAltName extension inside a certificate template.

    This function searches for the SubjectAltName extension (identified by the OID
    rfc5280.id_ce_subjectAltName) within the certificate template's extensions.
    If found, it decodes its DER-encoded value using Cryptography's x509.load_der_x509_extension,
    verifies that the extension is a SubjectAlternativeName, and checks that it contains at least
    one DNSName.

    :param cert_template: The certificate template containing the extensions.
    :return: The validated SubjectAltName extension if present and valid, otherwise None.
    :raises BadCertTemplate: If the extension is present but cannot be decoded or
                             does not contain valid DNSName entries.
    """
    result = compareutils.is_null_dn(
        cert_template["subject"],
    )

    sub_alt_name = _try_decode_extension_val(  # type: ignore
        extensions=cert_template["extensions"],
        extn_name="san",
        name="SubjectAltName",
    )
    sub_alt_name: Optional[rfc5280.SubjectAltName]

    if sub_alt_name is None and result:
        raise BadCertTemplate(
            "The `SubjectAltName` extension is not present in the certificate template"
            "and the subject is set to `Null-DN`."
        )

    if sub_alt_name is None:
        logging.info("SubjectAltName extension not present in the certificate template.")
        return None

    # Issue a certificate which will parse linter checks.
    if result:
        return prepare_subject_alt_name_extension(
            gen_names=sub_alt_name,  # type: ignore
            critical=True,
        )

    return prepare_subject_alt_name_extension(
        gen_names=sub_alt_name,  # type: ignore
        critical=False,
    )


def _contains_unknown_extensions(extensions: rfc9480.Extensions) -> bool:
    """Check if the extensions contain unknown extensions.

    :param extensions: The extensions to check.
    :return: `True` if the extensions contain unknown extensions, `False` otherwise.
    """
    if not extensions.isValue:
        return False

    unknown_exts = [str(extn["extnID"]) for extn in extensions if extn["extnID"] not in EXTENSION_OID_2_NAME]
    if unknown_exts:
        logging.warning("Unknown extensions found: %s", unknown_exts)
        return True
    return False


@not_keyword
def check_logic_extensions(cert_template: rfc4211.CertTemplate, for_ee: Optional[bool] = None) -> None:
    """Validate the extensions with some more logic related checks."""
    key_usage = _try_decode_extension_val(  # type: ignore
        extensions=cert_template["extensions"],
        extn_name="key_usage",
        name="KeyUsage",
    )
    key_usage: Optional[rfc5280.KeyUsage]

    if key_usage is not None:
        names = get_set_bitstring_names(key_usage)
        if for_ee is not None and not for_ee:
            if "keyCertSign" in names or "cRLSign" in names:
                raise BadCertTemplate("")

        basic_con = _try_decode_extension_val(  # type: ignore
            extensions=cert_template["extensions"], extn_name="basic_constraints", name="BasicConstraints"
        )
        basic_con: Optional[rfc5280.BasicConstraints]

        if basic_con is not None:
            if not bool(basic_con["cA"]) and "keyCertSign" in names:
                raise BadCertTemplate("")

    elif for_ee:
        basic_con = _try_decode_extension_val(  # type: ignore
            extensions=cert_template["extensions"], extn_name="basic_constraints", name="BasicConstraints"
        )
        basic_con: Optional[rfc5280.BasicConstraints]

        if basic_con is None:
            return

        if basic_con:
            if bool(basic_con["cA"]):
                raise BadCertTemplate("")

        if basic_con["pathLenConstraint"].isValue and int(basic_con["pathLenConstraint"]) != 0:
            raise BadCertTemplate("")


def _contains_extn_id(extn_id: univ.ObjectIdentifier, extensions: Sequence[rfc5280.Extension]) -> bool:
    """Check if the extension ID is present in the extensions.

    :param extn_id: The extension ID to check.
    :param extensions: The list of extensions to check against.
    :return: `True` if the extension ID is present, `False` otherwise.
    """
    for extn in extensions:
        if extn["extnID"] == extn_id:
            return True
    return False


def _get_not_included_extensions(
    validated_extensions: List[rfc5280.Extension], other_extensions: rfc9480.Extensions
) -> List[rfc5280.Extension]:
    """Get the extensions which are not included in the validated extensions.

    :param validated_extensions: The validated extensions.
    :param other_extensions: The other extensions to check against.
    :return: The list of extensions which are not included in the validated extensions.
    """
    not_included = []
    for extn in other_extensions:
        if _contains_extn_id(extn["extnID"], validated_extensions):
            continue
        not_included.append(extn)
    return not_included


# TODO maybe not allow to correct the criticality of the extensions?


def check_extensions(  # noqa D417 undocumented params
    cert_template: rfc4211.CertTemplate,
    ca_public_key: VerifyKey,
    other_extensions: Optional[Union[rfc9480.Extensions, List[rfc5280.Extension]]] = None,
    allow_unknown_extns: bool = False,
    allow_basic_con_non_crit: bool = True,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    for_end_entity: Optional[bool] = None,
) -> rfc5280.Extensions:
    """Validate the correctness of the extensions inside the certificate template.

    Verify that the parsed extensions are valid and that they contain the required extensions.
    The `other_extensions` are used to override the extensions in the certificate template.
    The `other_extensions` are not validated.

    Arguments:
    ---------
        - `cert_template`: The certificate template to check.
        - `ca_public_key`: The public key of the CA.
        - `other_extensions`: Other extensions provided by the user/CA. Defaults to `None`.
        - `allow_unknown_extns`: Whether to allow unknown extensions. Defaults to `True`.
        - `allow_basic_con_non_crit`: Whether to allow non-critical basic constraints. Defaults to `True`.
        - `ca_cert`: The CA certificate to validate the `AuthorityKeyIdentifier` extension. Defaults to `None`.
        - `for_end_entity`:

    Returns:
    -------
        - The validated extensions.

    Raises:
    ------
        - `BadCertTemplate`: If unknown extensions are found in the certificate template and not allowed.
        - `BadA
        - `BadCertTemplate`: If the extensions inside the `CertTemplate` are not valid.
        - `BadCertTemplate`: If the `BasicConstraints` extension is not marked as critical.


    Examples:
    --------
    | ${extns}= | Check Extensions | cert_template=${cert_template} | ca_public_key=${ca_public_key} |
    | ${extns}= | Check Extensions | cert_template=${cert_template} | ca_public_key=${ca_public_key} | \
    allow_unknown_extns=False |
    | ${extns}= | Check Extensions | cert_template=${cert_template} | ca_public_key=${ca_public_key} | \
    ${other_extensions} |

    """
    if _contains_unknown_extensions(cert_template["extensions"]) and not allow_unknown_extns:
        raise BadCertTemplate("Unknown extensions found in the certificate template.")

    check_logic_extensions(cert_template, for_ee=for_end_entity)

    extns = rfc5280.Extensions()

    key_usage = _verify_key_usage(cert_template)
    ski_extn = _verify_subject_key_identifier(cert_template)
    aia_extn = _verify_authority_key_identifier(cert_template, ca_public_key, ca_cert=ca_cert)
    eku = _verify_extended_key_usage(cert_template)
    basic_con = verify_ca_basic_constraints(cert_template, allow_non_crit=allow_basic_con_non_crit)
    san = _verify_subject_alt_name(cert_template)
    extensions_to_check = [
        (rfc5280.id_ce_keyUsage, key_usage),
        (rfc5280.id_ce_subjectKeyIdentifier, ski_extn),
        (rfc5280.id_ce_authorityKeyIdentifier, aia_extn),
        (rfc5280.id_ce_extKeyUsage, eku),
        (rfc5280.id_ce_basicConstraints, basic_con),
        (rfc5280.id_ce_subjectAltName, san),
    ]

    if isinstance(other_extensions, list):
        tmp = rfc9480.Extensions()
        tmp.extend(other_extensions)
        other_extensions = tmp

    if other_extensions is None or len(other_extensions) == 0:
        validated_extensions = [ext for _, ext in extensions_to_check if ext is not None]
    else:
        validated_extensions = []
        for ext_id, ext in extensions_to_check:
            if ext is None and certextractutils.get_extension(other_extensions, ext_id) is None:
                continue

            if ext is None and certextractutils.get_extension(other_extensions, ext_id) is not None:
                validated_extensions.append(certextractutils.get_extension(other_extensions, ext_id))

            elif ext is not None and certextractutils.get_extension(other_extensions, ext_id) is None:
                validated_extensions.append(ext)

            else:
                validated_extensions.append(ext)

        other = _get_not_included_extensions(validated_extensions, other_extensions)
        validated_extensions.extend(other)

    extns.extend(validated_extensions)
    return extns


@keyword(name="Prepare IssuerAndSerialNumber")
def prepare_issuer_and_serial_number(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    modify_serial_number: bool = False,
    modify_issuer: bool = False,
    issuer: Optional[str] = None,
    serial_number: Optional[Union[str, int]] = None,
) -> rfc5652.IssuerAndSerialNumber:
    """Extract issuer and serial number from a certificate.

    Creates an `IssuerAndSerialNumber` structure, which uniquely identifies
    a certificate by its issuer's distinguished name and its serial number. It's used when
    the certificate lacks a SubjectKeyIdentifier extension.

    Arguments:
    ---------
        - `cert`: Certificate from which to extract the issuer and serial number.
        - `modify_serial_number`: If True, increment the serial number by 1. Defaults to `False`.
        - `modify_issuer`: If True, modify the issuer common name. Defaults to `False`.
        - `issuer`: The issuer's distinguished name to use. Defaults to `None`.
        - `serial_number`: The serial number to use. Defaults to `None`.

    Returns:
    -------
        - The populated `IssuerAndSerialNumber` structure.

    Raises:
    ------
        - ValueError: If neither a certificate nor an issuer and serial number is provided.

    Examples:
    --------
    | ${issuer_and_ser}= | Prepare IssuerAndSerialNumber | cert=${cert} | modify_serial_number=True |
    | ${issuer_and_ser}= | Prepare IssuerAndSerialNumber | issuer=${issuer} | serial_number=${serial_number} |

    """
    if cert is None and (issuer is None or serial_number is None):
        raise ValueError("Either a certificate or a issuer and serial number must be provided.")

    iss_ser_num = rfc5652.IssuerAndSerialNumber()

    if issuer:
        iss_ser_num["issuer"] = prepareutils.prepare_name(issuer)
    elif not modify_issuer:
        iss_ser_num["issuer"] = copy_name(
            target=rfc9480.Name(),
            filled_name=cert["tbsCertificate"]["issuer"],  # type: ignore
        )
    else:
        data = modify_common_name_cert(cert, issuer=True)  # type: ignore
        data: str
        iss_ser_num["issuer"] = prepareutils.prepare_name(data)

    if serial_number is None:
        serial_number = int(cert["tbsCertificate"]["serialNumber"])  # type: ignore

    if modify_serial_number:
        serial_number = int(serial_number) + 1
    iss_ser_num["serialNumber"] = rfc5280.CertificateSerialNumber(serial_number)
    return iss_ser_num


@not_keyword
def prepare_distribution_point_name(
    full_name: Optional[CRLFullNameType] = None,
    relative_name: Optional[rfc5280.RelativeDistinguishedName] = None,
) -> rfc5280.DistributionPointName:
    """Prepare a Distribution Point Name.

    :param full_name: List of GeneralName objects for the full name.
    :param relative_name: List of RelativeDistinguishedName objects for the relative name.
    :return: The populated `DistributionPointName` structure.
    """
    if full_name is not None and relative_name is not None:
        raise ValueError(
            "Either `full_name` or `relative_name` must be provided, not both."
            "Can only populate the `DistributionPointName` with one of them."
        )

    distribution_point_name = rfc5280.DistributionPointName()

    if full_name:
        full_names = parse_to_general_names(full_name)
        distribution_point_name["fullName"].extend(full_names)

    if relative_name:
        distribution_point_name["nameRelativeToCRLIssuer"].extend(relative_name)

    return distribution_point_name


def prepare_relative_distinguished_name(
    name: Optional[Union[str, rfc9480.Name, rfc5280.RelativeDistinguishedName]],
) -> Optional[rfc5280.RelativeDistinguishedName]:
    """Prepare a Relative Distinguished Name.

    :param name: The name to prepare.
    :return: The populated `RelativeDistinguishedName` structure.
    """
    if isinstance(name, str):
        name_obj = rfc5280.RelativeDistinguishedName()

        if "=" not in name:
            raise ValueError("Invalid name format. Expected 'key=value'.")

        for item in name.split(","):
            key, value = item.split("=")
        raise NotImplementedError("This function is not implemented yet.")

    elif isinstance(name, rfc9480.Name):
        return name["rdnSequence"][0]

    return name


@keyword(name="Prepare DistributionPoint")
def prepare_distribution_point(  # noqa: D417 undocumented-param
    reason_flags: Optional[str] = None,
    crl_issuers: Optional[_GeneralNamesType] = None,
    full_name: Optional[CRLFullNameType] = None,
    relative_name: Optional[rfc5280.RelativeDistinguishedName] = None,
) -> rfc5280.DistributionPoint:
    """Prepare a Distribution Point.

    Arguments:
    ---------
        - reason_flags: Reason flags for the CRL.
        - crl_issuers: CRL issuer name.
        - crl_issuers: List of CRL issuers names.
        - full_name: List of GeneralName objects for the full name.
        - relative_name: List of RelativeDistinguishedName objects for the relative name.

    Returns:
    -------
        - The populated DistributionPoint structure.

    Raises:
    ------
        - ValueError: If both full_name and relative_name are not `None`.

    Examples:
    --------
    | ${dis_point} | Prepare DistributionPoint | reason_flags="keyCompromise" | crl_issuers="CN=Issuer" |
    | ${dis_point} | Prepare DistributionPoint | full_name="CN=FullName" | relative_name |

    """
    distribution_point = rfc5280.DistributionPoint()

    dis_point_name = rfc5280.DistributionPointName().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )

    distribution_point["distributionPoint"] = dis_point_name
    if reason_flags:
        flags = _prepare_reason_flags(reason_flags)  # type: ignore
        flags: rfc5280.ReasonFlags
        distribution_point["reasons"] = flags.subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))

    if crl_issuers is not None:
        crl_issuers = parse_to_general_names(crl_issuers, gen_type="directoryName")
        distribution_point["cRLIssuer"].extend(crl_issuers)

    if full_name or relative_name:
        distribution_point_name = prepare_distribution_point_name(full_name, relative_name)
        choice_name = distribution_point_name.getName()
        distribution_point["distributionPoint"][choice_name] = distribution_point_name[choice_name]

    return distribution_point


def _prepare_reason_flags(
    reason_flags: Optional[str] = None,
) -> Optional[rfc5280.ReasonFlags]:
    """Prepare ReasonFlags.

    :param reason_flags: Reason flags for the CRL.
    :return: The populated `ReasonFlags` structure, correctly tagged.
    """
    if reason_flags == "all":
        all_options = asn1utils.get_all_asn1_named_value_names(rfc5280.ReasonFlags(), get_keys=True)
        reason_flags = ",".join(all_options)
        return rfc5280.ReasonFlags(reason_flags)

    if reason_flags is not None:
        options = list(rfc5280.ReasonFlags.namedValues.keys())
        for entry in reason_flags.split(","):
            if entry not in options:
                raise ValueError(f"Invalid `ReasonFlags`: {entry}. Must be one of {options}.")

        return rfc5280.ReasonFlags(reason_flags)

    return None


def _prepare_dp_name_for_idp(
    distribution_point: Optional[rfc5280.DistributionPointName] = None,
    full_name: Optional[CRLFullNameType] = None,
    relative_name: Optional[rfc5280.RelativeDistinguishedName] = None,
) -> rfc5280.DistributionPointName:
    """Prepare a Distribution Point for Issuing Distribution Point.

    :param full_name: List of GeneralName objects for the full name.
    :param relative_name: List of RelativeDistinguishedName objects for the relative name.
    :return: The populated `DistributionPoint` structure.
    """
    if distribution_point is not None and (full_name is not None or relative_name is not None):
        raise ValueError(
            "Either `distribution_point` or `full_name` or `relative_name` must be provided, not both."
            "Can only populate the `DistributionPointName` with one of them."
        )

    if distribution_point is None:
        return prepare_distribution_point_name(
            full_name=full_name,
            relative_name=relative_name,
        )
    return distribution_point


@keyword(name="Prepare IssuingDistributionPoint")
def prepare_issuing_distribution_point(  # noqa: D417 undocumented-param
    dis_point_name: Optional[rfc5280.DistributionPointName] = None,
    full_name: Optional[CRLFullNameType] = None,
    relative_name: Optional[rfc5280.RelativeDistinguishedName] = None,
    only_contains_user_certs: bool = False,
    only_contains_ca_certs: bool = False,
    only_some_reasons: Optional[str] = None,
    indirect_crl: bool = False,
    only_contains_attribute_certs: bool = False,
) -> rfc5280.IssuingDistributionPoint:
    """Prepare an Issuing Distribution Point.

    This Extension is used to indicate the distribution point for the CRL. It can specify whether the CRL contains \
    only user certificates, CA certificates, or attribute certificates. It can also specify the reasons for which the \
    CRL is issued (e.g., key compromise, CA key compromise, etc.).

    Arguments:
    ---------
        - dis_point_name: The distribution point name to parse. Defaults to `None`.
        - full_name: List of GeneralName objects for the full name. Defaults to `None`.
        - relative_name: List of RelativeDistinguishedName objects for the relative name. Defaults to `None`.
        - only_contains_user_certs: Indicates if the CRL only contains user certificates. Defaults to `False`.
        - only_contains_ca_certs: Indicates if the CRL only contains CA certificates. Defaults to `False`.
        - only_some_reasons: Specifies the `ReasonFlags` for which the CRL is issued (e.g., `keyCompromise`). \
        Can be `all` or a comma-separated human representation of the `ReasonFlags`. Defaults to `None`.
        - indirect_crl: Indicates if the CRL is an indirect CRL. Defaults to `False`.
        - only_contains_attribute_certs: Indicates if the CRL only contains attribute certificates. Defaults to `False`.

    Returns:
    -------
        - The populated `IssuingDistributionPoint` structure.

    Raises:
    ------
        - ValueError: If both `dis_point_name` and `full_name` are provided or if neither is provided.
        - ValueError: If `issuing_distribution_point` is not provided and `dis_point_name` or \
        `full_name` are not provided.
        - ValueError: If `only_some_reasons` is not a valid `ReasonFlags` value.

    Examples:
    --------
    | ${issuing_dp} | Prepare IssuingDistributionPoint | dis_point_name={dis_point_name} |
    | ${issuing_dp} | Prepare IssuingDistributionPoint | full_name="CN=FullName" |

    """
    issuing_distribution_point = rfc5280.IssuingDistributionPoint()

    if dis_point_name is not None or full_name is not None or relative_name is not None:
        dis_point_name = _prepare_dp_name_for_idp(
            distribution_point=dis_point_name,
            full_name=full_name,
            relative_name=relative_name,
        )
        option = dis_point_name.getName()
        issuing_distribution_point["distributionPoint"][option] = dis_point_name[option]

    issuing_distribution_point["onlyContainsUserCerts"] = only_contains_user_certs
    issuing_distribution_point["onlyContainsCACerts"] = only_contains_ca_certs

    if only_some_reasons is not None:
        reason_flags = _prepare_reason_flags(only_some_reasons)
        names = get_all_asn1_named_value_names(reason_flags)  # type: ignore
        issuing_distribution_point["onlySomeReasons"] = rfc5280.ReasonFlags(names).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
        )

    issuing_distribution_point["indirectCRL"] = indirect_crl
    issuing_distribution_point["onlyContainsAttributeCerts"] = only_contains_attribute_certs

    return issuing_distribution_point


@keyword(name="Prepare IssuingDistributionPoint Extension")
def prepare_issuing_distribution_point_extension(  # noqa: D417 undocumented-param
    iss_dis_point: Optional[rfc5280.IssuingDistributionPoint] = None,
    dis_point_name: Optional[rfc5280.DistributionPointName] = None,
    full_name: Optional[CRLFullNameType] = None,
    add_rand_val: bool = False,
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare an Issuing Distribution Point extension.

    Arguments:
    ---------
        - iss_dis_point: The Issuing Distribution Point to prepare. Defaults to `None`.
        - dis_point_name: The distribution point name to parse. Defaults to `None`.
        - full_name: A single or list of GeneralName objects for the full name. Defaults to `None`.
        - add_rand_val: Whether to add a random value to the `extnValue` field. Defaults to `False`.
        - critical: Whether the extension is critical. Defaults to `False`.

    Returns:
    -------
        - The populated `Extension` structure for the IssuingDistributionPoint.

    Raises:
    ------
        - ValueError: If both `dis_point_name` and `full_name` are provided or if neither is provided.
        - ValueError: If `iss_dis_point` is not provided and `dis_point_name` or `full_name` are not provided.

    Examples:
    --------
    | ${idp_ext} | Prepare IssuingDistributionPoint Extension | full_name="CN=Issuer" |
    | ${idp_ext} | Prepare IssuingDistributionPoint Extension | dis_point_name={dis_point_name} |
    | ${idp_ext} | Prepare IssuingDistributionPoint Extension | iss_dis_point={iss_dis_point} |

    """
    if iss_dis_point is None:
        if dis_point_name is None and full_name is None:
            raise ValueError("At least one of `iss_dis_point`, `dis_point_name`, or `full_name` must be provided.")

        if dis_point_name is not None and full_name is not None:
            raise ValueError("Either `dis_point_name` or `full_name` must be provided, not both.")

        iss_dis_point = prepare_issuing_distribution_point(
            dis_point_name=dis_point_name,
            full_name=full_name,
        )

    return _prepare_extension(
        oid=rfc5280.id_ce_issuingDistributionPoint,
        critical=critical,
        value=iss_dis_point,
        add_rand_val=add_rand_val,
    )
