# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Logic to build and modify `CertTemplate`, `CMPCertificate` or CSR objects."""

import logging
import os
from datetime import datetime, timedelta
from typing import Any, List, Optional, Sequence, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pq_logic.keys.abstract_composite import AbstractCompositeKEMPrivateKey, AbstractCompositeSigPrivateKey
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, get_oid_cms_composite_signature
from pq_logic.tmp_oids import id_rsa_kem_spki
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ, useful
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5652, rfc6402, rfc9480, rfc9481
from pyasn1_alt_modules.rfc2459 import AttributeValue
from robot.api.deco import keyword, not_keyword

from resources import (
    certextractutils,
    certutils,
    cmputils,
    convertutils,
    copyasn1utils,
    cryptoutils,
    keyutils,
    oid_mapping,
    typingutils,
    utils,
)
from resources.certextractutils import extract_extension_from_csr
from resources.convertutils import subjectPublicKeyInfo_from_pubkey
from resources.exceptions import BadCertTemplate
from resources.oidutils import CMP_EKU_OID_2_NAME, RSA_SHA_OID_2_NAME
from resources.prepareutils import prepare_name
from resources.typingutils import PrivateKey, PrivateKeySig, PublicKey


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


def prepare_sig_alg_id(
    signing_key: PrivateKeySig,
    hash_alg: str,
    use_rsa_pss: bool,
    use_pre_hash: bool = False,
) -> rfc9480.AlgorithmIdentifier:
    """Prepare the AlgorithmIdentifier for the signature algorithm based on the key and hash algorithm.

    If `use_rsa_pss` is `True`, configures RSA-PSS; otherwise, it selects the signature OID
    based on the signing key type and hash algorithm.

    :param signing_key: The private key to use for signing the certificate.
    :param hash_alg: The hash algorithm to use (e.g., "sha256").
    :param use_rsa_pss: Boolean flag indicating whether to use RSA-PSS for signing.
    :param use_pre_hash: Boolean flag indicating whether the data is pre-hashed before signing.
    :return: An `rfc9480.AlgorithmIdentifier` for the specified signing configuration.
    """
    alg_id = rfc9480.AlgorithmIdentifier()

    if isinstance(signing_key, CompositeSigCMSPrivateKey):
        # TODO maybe make it better to get the oid from the key itself.
        # Left like this, because unknown how the cryptography library will
        # implement the CompositeSigPrivateKey (Probably for every key a new class).
        domain_oid = get_oid_cms_composite_signature(
            signing_key.pq_key.name, signing_key.trad_key, use_pss=use_rsa_pss, pre_hash=use_pre_hash
        )
        alg_id["algorithm"] = domain_oid

    elif isinstance(signing_key, AbstractCompositeSigPrivateKey):
        # means an expired key is used.
        domain_oid = signing_key.get_oid(used_padding=use_rsa_pss, pre_hash=use_pre_hash)
        alg_id["algorithm"] = domain_oid

    else:
        oid = oid_mapping.get_alg_oid_from_key_hash(key=signing_key, hash_alg=hash_alg, use_pss=use_rsa_pss)
        alg_id["algorithm"] = oid
        if oid in RSA_SHA_OID_2_NAME:
            alg_id["parameters"] = univ.Null("")

    return alg_id


@keyword(name="Sign CSR")
def sign_csr(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest,
    signing_key: PrivateKeySig,
    hash_alg: str = "sha256",
    other_key: Optional[PrivateKeySig] = None,
    use_rsa_pss: bool = False,
    bad_sig: bool = False,
    use_pre_hash: bool = False,
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
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature algorithm. Defaults to `False`.
        - `bad_sig`: Whether to manipulate the signature for negative testing.
        - `use_pre_hash`: Whether to use the pre-hashed version for PQ-keys and CompositeSig-keys.

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
    signature = cryptoutils.sign_data(data=der_data, key=other_key or signing_key, hash_alg=hash_alg)
    logging.info(f"CSR Signature: {signature}")
    if bad_sig:
        if isinstance(signing_key, AbstractCompositeSigPrivateKey):
            signature = utils.manipulate_composite_sig(signature)
        else:
            signature = utils.manipulate_first_byte(signature)
        logging.info(f"Modified CSR signature: {signature}")

    csr["signature"] = univ.BitString.fromOctetString(signature)
    csr["signatureAlgorithm"] = prepare_sig_alg_id(signing_key=signing_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)

    # Needs to be en and decoded otherwise is the structure empty.
    der_data = encoder.encode(csr)
    csr, _ = decoder.decode(der_data, asn1Spec=rfc6402.CertificationRequest())

    return csr


@keyword(name="Build CSR")
def build_csr(  # noqa D417 undocumented-param
    signing_key: PrivateKeySig,
    common_name: str = "CN=Hans Mustermann",
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    hash_alg: Union[None, str] = "sha256",
    use_rsa_pss: bool = False,
    subjectAltName: Optional[str] = None,
    exclude_signature: bool = False,
    for_kga: bool = False,
    bad_sig: bool = False,
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
        `subjectPublicKey` are set to a zero bit string. And the algorithm identifiers are set to key provided.
        - `bad_sig`: Whether to manipulate the signature for negative testing.
        - `use_pre_hash`: Whether to use the pre-hashed version for PQ-keys and CompositeSig-keys.
        - `use_pre_hash_pub_key`: Whether to use the pre-hashed version for the public key.
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
    csr["certificationRequestInfo"]["subject"] = prepare_name(common_name)

    pub_pre_hash = use_pre_hash if use_pre_hash_pub_key is None else use_pre_hash_pub_key
    spki = spki or convertutils.subjectPublicKeyInfo_from_pubkey(
        public_key=signing_key.public_key(), use_rsa_pss=use_rsa_pss, use_pre_hash=pub_pre_hash
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

        extensions.append(_prepare_subject_alt_name_extensions(subjectAltName))

    if extensions is not None:
        csr = csr_add_extensions(csr=csr, extensions=extensions)

    if not exclude_signature and not for_kga:
        csr = sign_csr(
            csr=csr,
            signing_key=signing_key,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            bad_sig=bad_sig,
            use_pre_hash=use_pre_hash,
        )

    elif for_kga:
        csr["signature"] = univ.BitString("")
        # TODO verify if as an example rsa is allowed to be rsaEncryption or must be something else
        # but must be set to something or define external function dataclass class to then encode the
        # data otherwise the structure will be empty and pyasn1 cannot be used!
        csr["signatureAlgorithm"] = spki["algorithm"]

    if not exclude_signature:
        # Needs to be en and decoded otherwise is the structure empty.
        der_data = encoder.encode(csr)
        csr, _ = decoder.decode(der_data, asn1Spec=rfc6402.CertificationRequest())

    return csr


@keyword(name="Generate Signed CSR")
def generate_signed_csr(  # noqa D417 undocumented-param
    common_name: str, key: Union[PrivateKeySig, str, None] = None, return_as_pem: bool = True, **params
) -> Tuple[Union[bytes, rfc6402.CertificationRequest], PrivateKeySig]:
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
        key = keyutils.generate_key(algorithm="rsa")
    elif isinstance(key, str):
        key = keyutils.generate_key(algorithm=key, **params)
    elif isinstance(key, typingutils.PrivateKey):
        pass
    else:
        raise ValueError("`key` must be either an algorithm name or a private key")

    key = convertutils.ensure_is_sign_key(key)
    csr = build_csr(common_name=common_name, signing_key=key, exclude_signature=False)

    if return_as_pem:
        return utils.pyasn1_csr_to_pem(csr), key  # type: ignore

    return csr, key  # type: ignore


def _prepare_extended_key_usage(oids: List[univ.ObjectIdentifier]) -> rfc5280.Extension:
    """Generate pyasn1 `ExtendedKeyUsage` object with the provided list of OIDs.

    :param oids: A list of OIDs (strings) representing the allowed usages.
    :return: Encoded ASN.1 ExtendedKeyUsage object.
    """
    extended_key_usage = rfc5280.ExtKeyUsageSyntax()

    for oid in oids:
        extended_key_usage.append(oid)

    ext = rfc5280.Extension()
    ext["extnID"] = rfc5280.id_ce_extKeyUsage
    ext["extnValue"] = univ.OctetString(encoder.encode(extended_key_usage))

    return ext


def _prepare_ski_extension(key: Union[typingutils.PrivateKey, typingutils.PublicKey]) -> rfc5280.Extension:
    """Prepare a SubjectKeyIdentifier (SKI) extension.

    Used to ask for this extension by the server, or for negative testing, by sending the ski of another key.

    :param key: The public or private key to prepare the extension for.
    :return: The populated `pyasn1` `Extension` structure.
    """
    if isinstance(key, typingutils.PrivateKey):
        key = key.public_key()
    ski: bytes = x509.SubjectKeyIdentifier.from_public_key(key).key_identifier  # type: ignore
    subject_key_identifier = rfc5280.SubjectKeyIdentifier(ski)
    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_subjectKeyIdentifier
    extension["extnValue"] = univ.OctetString(encoder.encode(subject_key_identifier))
    return extension


def _prepare_basic_constraints_extension(ca: bool = False, path_length: Optional[int] = None) -> rfc5280.Extension:
    """Prepare BasicConstraints extension.

    :param ca: A boolean indicating if the certificate is a ca.
    :param path_length: The path length, which is allowed to be followed. Defaults to None.
    :return: The populated `pyasn1` `Extension` structure.
    """
    basic_constraints = rfc5280.BasicConstraints()
    basic_constraints["cA"] = ca

    if path_length is not None:
        basic_constraints["pathLenConstraint"] = path_length

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_basicConstraints
    extension["critical"] = True
    extension["extnValue"] = encoder.encode(basic_constraints)
    return extension


def _prepare_subject_alt_name_extensions(subject_alt_name: str) -> rfc5280.Extension:
    """Prepare a `SubjectAltName` extension for a certificate.

    Parses a comma-separated string of DNS names and constructs a `SubjectAltName`.

    :param subject_alt_name: A comma-separated string of DNS names to include in the extension.
    (e.g., `"example.com,www.example.com,pki.example.com"`)
    :return: An `rfc5280.Extension` object representing the Subject Alternative Name extension.
    """
    items = subject_alt_name.strip().split(",")
    dns_names = [x509.DNSName(item) for item in items]
    der_data = x509.SubjectAlternativeName(dns_names).public_bytes()

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_subjectAltName
    extension["critical"] = True
    extension["extnValue"] = der_data
    return extension


def prepare_extensions(  # noqa D417 undocumented-param
    key_usage: Optional[str] = None,
    eku: Optional[str] = None,
    key: Optional[Union[typingutils.PrivateKey, typingutils.PublicKey]] = None,
    is_ca: Optional[bool] = None,
    path_length: Optional[typingutils.Strint] = None,
    negative: bool = False,
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

    Returns:
    -------
        - A `pyasn1` Extensions structure populated with the provided key usage and extended key usage fields.

    Raises:
    ------
        - `ValueError`: If no extension to prepare is specified.

    Examples:
    --------
    | ${extensions}= | Prepare Extensions | key_usage=digitalSignature | cm_kga=True |
    | ${extensions}= | Prepare Extensions | eku=cmcCA, cmcRA, cmKGA |
    | ${extensions}= | Prepare Extensions | negative=True |

    """
    extensions = rfc9480.Extensions()

    if key_usage is not None:
        der_key_usage = encoder.encode(rfc5280.KeyUsage(key_usage))
        key_usage_ext = rfc5280.Extension()
        key_usage_ext["extnID"] = rfc5280.id_ce_keyUsage
        key_usage_ext["critical"] = True
        key_usage_ext["extnValue"] = univ.OctetString(der_key_usage)
        extensions.append(key_usage_ext)

    if eku is not None:
        names = set(eku.strip(" ").split(","))
        vals = ["cmcCA", "cmcRA", "cmKGA"]
        not_inside = names - set(vals)
        expected_eku = {oid: name for oid, name in CMP_EKU_OID_2_NAME.items() if name.strip(" ") in names}

        if not expected_eku or not_inside:
            raise ValueError("No CMP extended key usages where provided allowed are: 'cmcCA, cmcRA, cmKGA'")

        ext = _prepare_extended_key_usage(oids=list(expected_eku.keys()))
        extensions.append(ext)

    if key is not None:
        extensions.append(_prepare_ski_extension(key))

    if is_ca is not None or path_length is not None:
        extensions.append(_prepare_basic_constraints_extension(ca=is_ca, path_length=path_length))

    if negative:
        extensions.append(_prepare_invalid_extensions()[0])

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


# TODO fix doc
def sign_cert(
    signing_key: typingutils.PrivSignCertKey,
    cert: rfc9480.CMPCertificate,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
    modify_signature: bool = False,
    bad_sig: bool = False,
) -> rfc9480.CMPCertificate:
    """Sign a `CMPCertificate` object with the provided private key.

    :param signing_key: The private key used to sign the certificate.
    :param cert: The certificate to sign.
    :param hash_alg: The hash algorithm used for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use RSA-PSS for signing. Defaults to `False`.
    :param modify_signature: The signature will be modified by changing the first byte.
    :return: The signed `CMPCertificate` object.
    """
    der_tbs_cert = encoder.encode(cert["tbsCertificate"])
    signature = cryptoutils.sign_data(data=der_tbs_cert, key=signing_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)

    logging.info("Certificate signature: %s", signature.hex())

    if modify_signature:
        signature = utils.manipulate_first_byte(signature)
        logging.info("Modified certificate signature: %s", signature.hex())

    if bad_sig:
        if isinstance(signing_key, AbstractCompositeSigPrivateKey):
            signature = utils.manipulate_composite_sig(signature)
        else:
            signature = utils.manipulate_first_byte(signature)

    cert["signature"] = univ.BitString.fromOctetString(signature)
    cert["signatureAlgorithm"] = prepare_sig_alg_id(signing_key=signing_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)

    return cert


@not_keyword
def generate_certificate(
    private_key: Union[str, typingutils.PrivateKey],
    common_name: str = "CN=Hans Mustermann",
    hash_alg: Union[None, str] = "sha256",
    ski: Optional[bool] = False,
    serial_number: Optional[typingutils.Strint] = None,
    signing_key: Optional[typingutils.PrivSignCertKey] = None,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    days: int = 365,
    use_rsa_pss: bool = False,
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
    :return: `rfc9480.CMPCertificate` object representing the created certificate.
    """
    cert = rfc9480.CMPCertificate()

    if serial_number is None:
        serial_number = x509.random_serial_number()

    signing_key = signing_key or private_key

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
    return sign_cert(signing_key=signing_key, cert=cert, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)


def build_certificate(  # noqa D417 undocumented-param
    private_key: Optional[Union[str, typingutils.PrivateKey]] = None,
    common_name: str = "CN=Hans",
    hash_alg: str = "sha256",
    ski: bool = False,
    signing_key: Optional[PrivateKeySig] = None,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    **params,
) -> Tuple[rfc9480.CMPCertificate, typingutils.PrivateKey]:
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
    private_key = private_key or keyutils.generate_key(params.get("key_alg", "ec"))

    ski_key = private_key.public_key() if ski else None  # type: ignore

    ext = params.get("key_usage") or ski or params.get("eku") or params.get("is_ca") or params.get("path_length")
    extensions = params.get("extensions")
    if ext and extensions is None:
        extensions = prepare_extensions(
            key_usage=params.get("key_usage"),
            key=ski_key,
            eku=params.get("eku"),
            is_ca=params.get("is_ca"),
            path_length=params.get("path_length"),
        )

    signing_key = convertutils.ensure_is_sign_key(signing_key or private_key)
    certificate = generate_certificate(
        common_name=common_name,
        private_key=private_key,
        hash_alg=hash_alg,
        serial_number=params.get("serial_number"),
        signing_key=signing_key,
        issuer_cert=issuer_cert,
        extensions=extensions,
        use_rsa_pss=params.get("use_rsa_pss", False),
        days=int(params.get("days", 365)),
    )
    return certificate, private_key


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

    issuer_name: dict = utils.get_openssl_name_notation(
        certextractutils.get_field_from_certificate(cert, field),  # type: ignore
        oids=None,
        return_dict=True,
    )
    if not issuer_name:
        utils.log_certificates([cert])
        raise ValueError("The certificate did not contain a value in the `issuer` field.")

    issuer_name["CN"] = cmputils.modify_random_str(issuer_name["CN"], index=-1)
    data = ""
    for x, y in issuer_name.items():
        data += x + "=" + y + ","

    return data[0:-1]


def generate_different_public_key(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate, algorithm: str
) -> typingutils.PublicKey:
    """Generate a new public key using the specified algorithm, ensuring it differs from the certificate's public key.

    Used to ensure the revocation request sends a different public key but for the same type.

    Arguments:
    ---------
        - `cert`: The certificate from which to extract the existing public key.
        - `algorithm`: The algorithm to use for generating the new key pair (e.g., `"rsa"`, `"ec"`).

    Returns:
    -------
        - The generated public key, guaranteed to be different from the public key in `cert`.

    Examples:
    --------
    | ${new_public_key}= | Generate Different Public Key | cert=${certificate} | algorithm="rsa" |
    | ${new_public_key}= | Generate Different Public Key | cert=${certificate} | algorithm="ec" |

    """
    public_key = certutils.load_public_key_from_cert(cert)
    # just to reduce the extremely slim chance, they are acutely the same.
    while 1:
        pub_key = keyutils.generate_key(algorithm=algorithm).public_key()
        if pub_key != public_key:
            break

    return pub_key


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
        subject_obj = prepare_name(common_name=subject, name=subject_obj)
        cert_template.setComponentByName("subject", subject_obj)

    if issuer and "issuer" not in exclude_list:
        issuer_obj = rfc5280.Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        issuer_obj = prepare_name(common_name=issuer, name=issuer_obj)
        cert_template.setComponentByName("issuer", issuer_obj)

    return cert_template


def _prepare_extensions_for_cert_template(
    cert_template: rfc9480.CertTemplate,
    exclude: bool,
    cert: Optional[rfc9480.CMPCertificate] = None,
    extensions: Optional[rfc5280.Extensions] = None,
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
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    for_kga: bool = False,
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
        - `use_pre_hash`: Whether to prepare the public key as a pre-hash version, for a `CompositeKey`. Defaults to `False`.

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
        extensions=extensions,
        include_cert_extensions=include_cert_extensions,
    )

    if "validity" not in exclude_list:
        validity = _prepare_optional_validity(asn1cert=cert, validity=validity)
        if validity is not None:
            cert_template.setComponentByName("validity", validity)

    if spki is not None and "publicKey" not in exclude_list:
        public_key_obj = rfc5280.SubjectPublicKeyInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
        )
        spki_temp = convertutils.copy_subject_public_key_info(target=public_key_obj, filled_sub_pubkey_info=spki)
        cert_template["publicKey"] = spki_temp
    if "publicKey" not in exclude_list:
        cert_template["publicKey"] = _prepare_public_key_for_cert_template(
            key=key, for_kga=for_kga, asn1cert=cert, use_pre_hash=use_pre_hash
        )

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
    key: Optional[Union[typingutils.PrivateKey, typingutils.PublicKey]] = None,
    for_kga=False,
    asn1cert: Optional[rfc9480.CMPCertificate] = None,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare the `pyasn1` `SubjectPublicKeyInfo` for the `CertTemplate` structure.

    :param key: A private or public key object. If a private key is provided, the public key will be extracted.
    :param for_kga: Boolean flag indicating whether to prepare the key for non-local-key generation.
    :param asn1cert: Optional `rfc9480.CMPCertificate` object to extract the public key from if no `key` is provided.
    :param use_rsa_pss: Whether to prepare the public key as RSA-PSS. Defaults to `False`.
    :param use_pre_hash: Whether to prepare the public key as a pre-hash version, for a `CompositeKey`.
    :return: A `SubjectPublicKeyInfo` object ready to be used in a certificate template.
    """
    if key is None and asn1cert is None:
        raise ValueError("Either a key or a certificate have to be provided!")

    if key is None and asn1cert is not None:
        key = certutils.load_public_key_from_cert(asn1cert=asn1cert)

    elif isinstance(
        key,
        (
            typingutils.PrivateKey,
            AbstractCompositeKEMPrivateKey,
            AbstractHybridRawPrivateKey,
            AbstractCompositeSigPrivateKey,
        ),
    ):
        key = key.public_key()

    if not for_kga:
        cert_public_key = convertutils.subjectPublicKeyInfo_from_pubkey(
            public_key=key, use_pre_hash=use_pre_hash, use_rsa_pss=use_rsa_pss
        )
        public_key_obj = rfc5280.SubjectPublicKeyInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
        )
        public_key_obj = copyasn1utils.copy_subject_public_key_info(
            target=public_key_obj, filled_sub_pubkey_info=cert_public_key
        )
    else:
        cert_public_key = convertutils.subjectPublicKeyInfo_from_pubkey(
            public_key=key, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash
        )
        public_key_obj = rfc5280.SubjectPublicKeyInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
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
    extensions = extract_extension_from_csr(csr)
    subject = utils.get_openssl_name_notation(csr["certificationRequestInfo"]["subject"])
    return prepare_cert_template(key=public_key, subject=subject, extensions=extensions)


@keyword(name="Prepare SubjectPublicKeyInfo")
def prepare_subject_public_key_info(
    key: Union[PrivateKey, PublicKey] = None,
    for_kga: bool = False,
    key_name: Optional[str] = None,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
    hash_alg: Optional[str] = None,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare a `SubjectPublicKeyInfo` structure for a `Certificate`, `CSR` or `CertTemplate`.

    :param key: The public or private key to use for the `SubjectPublicKeyInfo`.
    :param for_kga: A flag indicating whether the key is for key generation authentication (KGA).
    :param key_name: The key algorithm name to use for the `SubjectPublicKeyInfo`.
    (can be set to `rsa_kem`. RFC 5990bis-10). Defaults to `None`.
    :param use_rsa_pss: Whether to use RSA-PSS padding. Defaults to `False`.
    :param use_pre_hash: Whether to use the pre-hash version for a `CompositeKey` and pq signature keys.
    Defaults to `False`.
    :param hash_alg: The pre-hash algorithm to use for the pq signature key. Defaults to `None`.
    :return: The populated `SubjectPublicKeyInfo` structure.
    """
    if key is None and not for_kga:
        raise ValueError("Either a key has to be provided or the for_kga flag have to be set.")

    if key is not None:
        if isinstance(key, PrivateKey):
            key = key.public_key()

    if for_kga:
        return _prepare_spki_for_kga(key=key, key_name=key_name, use_pss=use_rsa_pss, use_pre_hash=use_pre_hash)

    if key_name in ["rsa-kem", "rsa_kem"]:
        spki = rfc5280.SubjectPublicKeyInfo()
        # As of RFC 5990bis-10, currently only Draft.
        spki["algorithm"]["algorithm"] = id_rsa_kem_spki
        der_data = key.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.PKCS1)
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(der_data)

    else:
        spki = subjectPublicKeyInfo_from_pubkey(
            public_key=key, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash, hash_alg=hash_alg
        )

    return spki


def _prepare_spki_for_kga(
    key: Union[PrivateKey, PublicKey] = None,
    key_name: Optional[str] = None,
    use_pss: bool = False,
    use_pre_hash: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare a SubjectPublicKeyInfo for KGA usage.

    :param key: A private or public key.
    :param key_name: An optional key algorithm name.
    :param use_pss: Whether to use PSS padding for RSA and a RSA-CompositeKey.
    :param use_pre_hash: Whether to use the pre-hash version for a CompositeKey.
    :return: The populated `SubjectPublicKeyInfo` structure.
    """
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

    if key_name is not None:
        from pq_logic.combined_factory import CombinedKeyFactory

        key = CombinedKeyFactory.generate_key(key_name).public_key()
        spki_tmp = subjectPublicKeyInfo_from_pubkey(public_key=key, use_rsa_pss=use_pss, use_pre_hash=use_pre_hash)
        spki["algorithm"]["algorithm"] = spki_tmp["algorithm"]["algorithm"]

    elif key is not None:
        spki_tmp = subjectPublicKeyInfo_from_pubkey(public_key=key, use_rsa_pss=use_pss)
        spki["algorithm"]["algorithm"] = spki_tmp["algorithm"]["algorithm"]

    return spki


def _default_validity(
    days: int = 3650,
    optional_validity: Optional[rfc5280.Validity] = None,
    max_days_before: Optional[Union[int, str]] = 10,
) -> rfc5280.Validity:
    """Prepare a default `Validity` structure for a certificate.

    :param days: The number of days for which the certificate remains valid. Defaults to `3650` days.
    :param optional_validity: Optional `rfc5280.Validity` object to use for the certificate. Defaults to `None`.
    :param max_days_before: Specifies the maximum allowable difference, in days, between
    the `notBefore` date and the current date. Defaults to `10` days.
    :return: The prepared `Validity` structure.
    """
    not_before = datetime.now()
    if optional_validity is not None:
        # print(cert_template["validity"].isValue)
        # bug in pyasn1-alt-modules, validity is always a value.
        # even if it is not set.
        # if cert_template["validity"].isValue: is always `True`.
        if optional_validity["notBefore"].isValue:
            time_type = optional_validity["notBefore"].getName()
            tmp = optional_validity["notBefore"][time_type].asDateTime

            if tmp < datetime.now() - timedelta(days=max_days_before):
                raise BadCertTemplate("The `notBefore` date is too far in the past.")

            not_before = tmp

        if optional_validity["notAfter"].isValue:
            time_type = optional_validity["notAfter"].getName()
            not_after = optional_validity["notAfter"][time_type].asDateTime
        else:
            not_after = not_before + timedelta(days=days)
        return prepare_validity(not_before, not_after)

    not_before = datetime.now()
    not_after = not_before + timedelta(days=days)
    return prepare_validity(not_before, not_after)


@keyword(name="Build Cert From CertTemplate")
def build_cert_from_cert_template(
    cert_template: rfc9480.CertTemplate,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: PrivateKey,
    use_rsa_pss: bool = True,
    use_pre_hash: bool = False,
    hash_alg: str = "sha256",
) -> rfc9480.CMPCertificate:
    """Build a certificate from a CertTemplate.

    :param cert_template: The CertTemplate to build the certificate from.
    :param ca_cert: The CA certificate.
    :param ca_key: The CA private key.
    :param use_rsa_pss: Whether to use RSA-PSS or not. Defaults to `True`.
    :param use_pre_hash: Whether to use pre-hash or not. Defaults to `False`.
    :param hash_alg: The hash algorithm to use (e.g. "sha256").
    """
    tbs_certs = prepare_tbs_certificate_from_template(
        cert_template=cert_template,
        issuer=ca_cert["tbsCertificate"]["subject"],
        ca_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
    )
    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_certs
    return sign_cert(
        cert=cert,
        signing_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
    )


def _prepare_shared_tbs_cert(
    subject: Union[str, rfc9480.Name],
    issuer: Union[rfc9480.CMPCertificate, rfc9480.Name],
    serial_number: Optional[int] = None,
    validity: Optional[Union[rfc4211.OptionalValidity, rfc5280.Validity]] = None,
    days: int = 3650,
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
        subject = prepare_name(common_name=subject)["rdnSequence"]

    tbs_cert["subject"]["rdnSequence"] = subject

    if isinstance(issuer, rfc9480.CMPCertificate):
        issuer = issuer["tbsCertificate"]["subject"]

    tbs_cert["issuer"] = issuer
    if serial_number is None:
        serial_number = x509.random_serial_number()
    tbs_cert["serialNumber"] = serial_number
    tbs_cert["version"] = rfc5280.Version("v3").subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )

    tbs_cert["subjectPublicKeyInfo"] = copyasn1utils.copy_subject_public_key_info(
        target=rfc5280.SubjectPublicKeyInfo(), filled_sub_pubkey_info=public_key
    )

    if isinstance(validity, rfc5280.Validity):
        tbs_cert["validity"] = validity
    else:
        tbs_cert["validity"] = _default_validity(days=days, optional_validity=validity)

    return tbs_cert


@not_keyword
def prepare_tbs_certificate_from_template(
    cert_template: rfc4211.CertTemplate,
    issuer: rfc9480.Name,
    ca_key: PrivateKey,
    serial_number: Optional[int] = None,
    hash_alg: str = "sha256",
    days: int = 3650,
    use_rsa_pss: bool = True,
    use_pre_hash: bool = False,
) -> rfc5280.TBSCertificate:
    """Prepare a `TBSCertificate` structure from a `CertTemplate`.

    :param cert_template: The `CertTemplate` to prepare the `TBSCertificate` from.
    :param issuer: The issuer of the certificate.
    :param ca_key: The CA private key.
    :param serial_number: The serial number for the certificate. Defaults to `None`.
    :param hash_alg: The hash algorithm to use. Defaults to `sha256`.
    :param days: The number of days for which the certificate remains valid. Defaults to `3650` days.
    :param use_rsa_pss: Whether to use RSA-PSS or not. Defaults to `True`.
    :param use_pre_hash: Whether to use pre-hash or not. Defaults to `False`.
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
        public_key=cert_template["publicKey"],
    )

    tbs_cert["signature"] = prepare_sig_alg_id(
        signing_key=ca_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash
    )
    # check if the public key is correct.
    _ = keyutils.load_public_key_from_spki(tbs_cert["subjectPublicKeyInfo"])
    return tbs_cert


@keyword(name="Build Cert from CSR")
def build_cert_from_csr(
    csr: rfc6402.CertificationRequest,
    ca_key: PrivateKey,
    extensions: Optional[rfc5280.Extensions] = None,
    serial_number: Optional[Union[str, int]] = None,
    validity: Optional[rfc5280.Validity] = None,
    issuer: Optional[rfc9480.Name] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    hash_alg: str = "sha256",
    include_extensions: bool = True,
    alt_sign_key: Optional[PrivateKeySig] = None,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Build a certificate from a CSR.

    :param csr: The CSR to build the certificate from.
    :param ca_cert: The CA certificate.
    :param ca_key: The CA private key.
    :param extensions: Optional extensions to include in the certificate. Defaults to `None`.
    If set, will exclude the extensions from the CSR.
    :param serial_number: Optional serial number for the certificate. Defaults to `None`.
    :param validity: Optional validity period for the certificate. Defaults to `None`.
    :param issuer: The issuer of the certificate. Defaults to `None`.
    :param hash_alg: The hash algorithm to use for signing. Defaults to `sha256`.
    :param include_extensions: Whether to include the extensions from the CSR. Defaults to `True`.
    :param alt_sign_key: Optional alternative signing key to use. Defaults to `None`.
    :return: The certificate as raw bytes.
    :raises ValueError: If neither the issuer nor the CA certificate is provided.
    """
    if issuer is None and ca_cert is None:
        raise ValueError(
            "Either the issuer or the CA certificate have to be provided.to build a certificate, from a CSR."
        )
    if ca_cert is not None:
        issuer = ca_cert["tbsCertificate"]["subject"]

    tbs_cert = _prepare_shared_tbs_cert(
        issuer=issuer,
        subject=csr["certificationRequestInfo"]["subject"],
        serial_number=serial_number,
        validity=validity,
        days=kwargs.get("days", 3650),
        public_key=csr["certificationRequestInfo"]["subjectPublicKeyInfo"],
    )

    tbs_cert["signature"] = prepare_sig_alg_id(
        signing_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=kwargs.get("use_rsa_pss", True),
        use_pre_hash=kwargs.get("use_pre_hash", False),
    )
    if include_extensions:
        extn = extract_extension_from_csr(csr=csr)
        if extensions is not None and extn is not None:
            tbs_cert["extensions"] = extn
        elif extensions is not None:
            tbs_cert["extensions"] = extensions
    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_cert

    if alt_sign_key is not None:
        # so that the catalyst logic can be in the matching file.
        from pq_logic.hybrid_sig.catalyst_logic import sign_cert_catalyst

        return sign_cert_catalyst(cert=cert, trad_key=ca_key, pq_key=alt_sign_key, hash_alg=hash_alg, **kwargs)

    return sign_cert(cert=cert, signing_key=ca_key, hash_alg=hash_alg, **kwargs)


@not_keyword
def prepare_tbs_certificate(
    subject: str,
    signing_key: PrivateKeySig,
    public_key: typingutils.PublicKey,
    serial_number: Optional[int] = None,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    extensions: Optional[rfc9480.Extensions] = None,
    validity: Optional[rfc5280.Validity] = None,
    days: int = 3650,
    use_rsa_pss: bool = False,
    hash_alg: str = "sha256",
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
    :param use_pre_hash: Whether to use pre-hash for signing. Defaults to `False`.
    :param use_rsa_pss_pubkey: Whether to use RSA-PSS for the CompositeSigKey public key. Defaults to `False`.
    :param use_pre_hash_pubkey: Whether to use pre-hash for the CompositeSigKey public key. Defaults to `False`.
    :return: `rfc5280.TBSCertificate` object configured with the provided parameters.
    """
    subject = prepare_name(subject)  # type: ignore

    if issuer_cert is None:
        issuer = subject
    else:
        issuer = copyasn1utils.copy_name(rfc9480.Name(), issuer_cert["tbsCertificate"]["subject"])

    pub_key = convertutils.subjectPublicKeyInfo_from_pubkey(
        public_key=public_key, use_rsa_pss=use_rsa_pss_pubkey, use_pre_hash=use_pre_hash_pubkey
    )
    tbs_cert = _prepare_shared_tbs_cert(
        issuer=issuer,
        subject=subject,
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

    tbs_cert["signature"] = prepare_sig_alg_id(
        signing_key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
    )
    return tbs_cert
