# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Validate X509 certificates by invoking other software, e.g., OpenSSL, pkilint."""

import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Union

import certifi
import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionNotFound, ReasonFlags, ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID
from pkilint import loader, report
from pkilint.pkix import certificate, extension, name
from pkilint.validation import ValidationFindingSeverity
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

from pq_logic.keys.abstract_pq import PQSignaturePublicKey
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPublicKey
from pq_logic.keys.abstract_wrapper_keys import KEMPublicKey, PQPublicKey
from pq_logic.keys.composite_sig import CompositeSigPublicKey
from pq_logic.pq_utils import is_kem_public_key
from pq_logic.tmp_oids import COMPOSITE_SIG_OID_TO_NAME
from resources import (
    asn1utils,
    certextractutils,
    cmputils,
    compareutils,
    convertutils,
    cryptoutils,
    keyutils,
    oid_mapping,
    protectionutils,
    typingutils,
    utils,
)
from resources.asn1_structures import PKIMessageTMP
from resources.convertutils import ensure_is_kem_pub_key, ensure_is_verify_key
from resources.exceptions import (
    BadAsn1Data,
    BadKeyUsage,
    BadPOP,
    BadSigAlgID,
    CertRevoked,
    SignerNotTrusted,
    UnknownOID,
)
from resources.oid_mapping import get_hash_from_oid, may_return_oid_to_name
from resources.oidutils import (
    CMP_EKU_OID_2_NAME,
    HYBRID_NAME_2_OID,
    HYBRID_OID_2_NAME,
    ML_DSA_OID_2_NAME,
    ML_KEM_OID_2_NAME,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_SIG_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    SLH_DSA_OID_2_NAME,
)
from resources.suiteenums import KeyUsageStrictness
from resources.typingutils import SignKey, Strint, VerifyKey

# for these to integrate smoothly into RF, they have to raise exceptions in case of failure, rather than
# return False


def parse_certificate(data: bytes) -> rfc9480.CMPCertificate:  # noqa D417 undocumented-param
    """Parse a DER-encoded X509 certificate into a pyasn1 object.

    Arguments:
    ---------
        - `data`: DER-encoded certificate.

    Returns:
    -------
        - The decoded certificate object.

    Raises:
    ------
        - `pyasn1.error.PyAsn1Error`: If the parsing fails.

    Examples:
    --------
    | ${cert}= | Parse Certificate | ${der_cert} |

    """
    cert, _ = decoder.decode(data, asn1Spec=rfc9480.CMPCertificate())
    return cert


# TODO maybe change to use direct OpenSSL like in the unittest to check if a file is correctly written.


@keyword(name="Validate Certificate OpenSSL")
def validate_certificate_openssl(data: Union[rfc9480.CMPCertificate, bytes]) -> None:  # noqa D417 undocumented-param
    """Validate a certificate by attempting to load it with the cryptography library, which invokes OpenSSL underneath.

    If loading is successful, the certificate is considered valid.

    Arguments:
    ---------
        - `data`: Either the DER-encoded bytes of a certificate or the certificate object to validate.

    Raises:
    ------
        - `ValueError`: If the certificate fails to load or is not valid, with an error message indicating the reason.

    Examples:
    --------
    | Validate Certificate OpenSSL | ${certificate_data} |

    """
    if isinstance(data, rfc9480.CMPCertificate):
        tmp_cert = convertutils.copy_asn1_certificate(data)
        data = asn1utils.encode_to_der(tmp_cert)

    try:
        _ = x509.load_der_x509_certificate(data)
    except Exception as e:
        message = f"Certificate validation with OpenSSL failed: {e}"
        logging.error(message)
        raise ValueError(message) from e


def validate_certificate_pkilint(data: Union[rfc9480.CMPCertificate, bytes]) -> None:  # noqa D417 undocumented-param
    """Validate a certificate using the pkilint tool.

    Arguments:
    ---------
        - `data`: Either the DER-encoded bytes of a certificate or the certificate object to validate.

    Raises:
    ------
        - `ValueError`: If the certificate has some invalid values set or necessary extensions are missing.
        (e.g., if `SubjectKeyIdentifier` extension is missing, the ValueError will be raised.)

    Examples:
    --------
    | Validate Certificate Pkilint | ${der_cert} |

    """
    if isinstance(data, rfc9480.CMPCertificate):
        data = convertutils.copy_asn1_certificate(data)
        data = encoder.encode(data)

    doc_validator = certificate.create_pkix_certificate_validator_container(
        certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
        [
            certificate.create_issuer_validator_container([]),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container([]),
            certificate.create_extensions_validator_container([]),
        ],
    )

    cert = loader.load_certificate(data, "dynamic-cert")
    results = doc_validator.validate(cert.root)

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.WARNING)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.WARNING).generate()
        raise ValueError(issues)


@not_keyword
def verify_cert_signature(cert: rfc9480.CMPCertificate, issuer_pub_key: Optional[typingutils.VerifyKey] = None):
    """Verify the signature of an X.509 certificate.

    Uses the issuer's public key, or the certificate's own public key if it is self-signed.

    :param cert: The certificate object, which is verified.
    :param issuer_pub_key: Optional PublicKeySig used for verification.
    :raises InvalidSignature: If the certificate's signature is not valid.
    """
    tbs_der = encoder.encode(cert["tbsCertificate"])
    pub_key = issuer_pub_key or load_public_key_from_cert(cert)
    pub_key = ensure_is_verify_key(pub_key)
    protectionutils.verify_signature_with_alg_id(
        public_key=pub_key,
        data=tbs_der,
        signature=cert["signature"].asOctets(),
        alg_id=cert["tbsCertificate"]["signature"],
    )


@not_keyword
def load_os_truststore() -> List[rfc9480.CMPCertificate]:
    """Load the OS truststore with the certifi package.

    :return: The list of the trustanchor certificate objects.
    """
    truststore_path = certifi.where()

    with open(truststore_path, "rb") as truststore_file:
        truststore_data = truststore_file.read()

    certs = truststore_data.split(b"-----END CERTIFICATE-----\n")
    certs = [cert + b"-----END CERTIFICATE-----\n" for cert in certs if cert.strip()]
    certificates = [parse_certificate(utils.decode_pem_string(cert)) for cert in certs]
    # certificates = x509.load_pem_x509_certificates(truststore_data)
    return certificates


def load_truststore(  # noqa D417 undocumented-param
    path: Optional[str] = "./data/trustanchors", allow_os_store: bool = False
) -> List[rfc9480.CMPCertificate]:
    """Load the truststore with a given path and with or without of OS Truststore.

    Arguments:
    ---------
         - `path`: path or directory to load the certificates from. Defaults to "./data/trustanchors".
         - `allow_os_store`: whether to allow the truststore of the Operating System or not.
            Defaults to False.

    Returns:
    -------
        - A list of `pyasn1` certificates, which are trustanchors.

    Examples:
    --------
    | ${certs}= | Load Truststore |
    | ${certs}= | Load Truststore | path=./data/trustanchors | allow_os_store=True |

    """
    certificates = []
    if path is not None:
        certificates = load_certificates_from_dir(path=path)

    if allow_os_store:
        certificates.extend(load_os_truststore())

    return certificates


@not_keyword
def build_chain_from_list(
    ee_cert: rfc9480.CMPCertificate, certs: List[rfc9480.CMPCertificate], must_be_self_signed: bool = False
) -> List[rfc9480.CMPCertificate]:
    """Build a certificate chain starting from the end-entity certificate to the root certificate.

    :param ee_cert: The end-entity `rfc9480.CMPCertificate` to start the chain with.
    :param certs: A list of `rfc9480.CMPCertificate` objects that may contain the intermediate and root certificates.
    :param must_be_self_signed: Boolean indicating if the chain must end with a self-signed root certificate.
    Defaults to `False`.
    :return: A list representing the complete certificate chain from the end-entity to the root certificate.
    :raises ValueError: If a self-signed root certificate is required but not found.
    """
    chain = [ee_cert]
    current_cert = ee_cert

    if check_is_cert_signer(current_cert, current_cert):
        logging.info("The end-entity certificate is self-signed.")
        return chain

    for _ in range(len(certs) + 1):
        for issuer_cert in certs:
            if check_is_cert_signer(cert=current_cert, poss_issuer=issuer_cert):
                chain.append(issuer_cert)
                current_cert = issuer_cert
                break

        current_cert_issuer = encoder.encode(current_cert["tbsCertificate"]["issuer"])
        current_cert_subject = encoder.encode(current_cert["tbsCertificate"]["subject"])
        if current_cert_issuer == current_cert_subject:
            break

    # Check if the last cert is a root (self-signed)
    last_cert_issuer = encoder.encode(chain[-1]["tbsCertificate"]["issuer"])
    last_cert_subject = encoder.encode(chain[-1]["tbsCertificate"]["subject"])
    if last_cert_issuer != last_cert_subject:
        if not must_be_self_signed:
            logging.info("Could not complete the certificate chain. No self-signed certificate found.")
        else:
            raise ValueError("Could not complete the certificate chain. No root certificate found.")

    return chain


@not_keyword
def load_public_key_from_der(spki_der: bytes) -> typingutils.PublicKey:
    """Load a public key from DER-encoded SubjectPublicKeyInfo bytes.

    Is intended to load either a Post-Quantum (PQ) key or a
    public key using the `cryptography` library.

    :param spki_der: The DER-encoded SubjectPublicKeyInfo bytes.
    :return: A `PublicKey` object.
    """
    spki, _ = decoder.decode(spki_der, rfc5280.SubjectPublicKeyInfo())

    return keyutils.load_public_key_from_spki(spki)


def load_public_key_from_cert(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate,
) -> typingutils.PublicKey:
    """Load a public key from a `CMPCertificate`.

    Supposed to be used to load either a pq Key or `cryptography` key.

    Arguments:
    ---------
        - `cert`: The certificate to load the public key from.

    Returns:
    -------
        - The loaded public key.

    Raises:
    ------
        - `ValueError`: If the public key cannot be loaded.
        - `badAlg`: If the algorithm is not supported.

    Examples:
    --------
    | ${public_key}= | Load Public Key From Cert | ${cert} |

    """
    public_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
    return public_key


@not_keyword
def load_kem_key_from_cert(cert: rfc9480.CMPCertificate) -> KEMPublicKey:
    """Load a KEM public key from a `CMPCertificate`.

    :param cert: The certificate to load the KEM public key from.
    :return: The KEM public key object.
    """
    public_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
    return ensure_is_kem_pub_key(public_key)


@not_keyword
def load_verify_key_from_cert(cert: rfc9480.CMPCertificate) -> VerifyKey:
    """Load a Signature public key from a `CMPCertificate`.

    :param cert: The certificate to load the PQ Signature public key from.
    :return: The PQ Signature public key object.
    """
    public_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
    return ensure_is_verify_key(public_key)


@not_keyword
def check_is_cert_signer(cert: rfc9480.CMPCertificate, poss_issuer: rfc9480.CMPCertificate) -> bool:
    """Check if a certificate was signed by another certificate.

    :param cert: The certificate to verify.
    :param poss_issuer: The possible issuer certificate.
    :return: True if the certificate was signed by the possible issuer, otherwise False.
    """
    cert_issuer = encoder.encode(cert["tbsCertificate"]["issuer"])
    issuer_subject = encoder.encode(poss_issuer["tbsCertificate"]["subject"])

    if cert_issuer != issuer_subject:
        return False

    public_key = load_public_key_from_cert(poss_issuer)
    hash_alg = oid_mapping.get_hash_from_oid(cert["signatureAlgorithm"]["algorithm"], only_hash=True)

    try:
        if cert["signatureAlgorithm"]["algorithm"] in RSASSA_PSS_OID_2_NAME:
            if not isinstance(public_key, RSAPublicKey):
                raise ValueError("The public key is not an RSA public key.")

            protectionutils.verify_rsassa_pss_from_alg_id(
                public_key=public_key,
                data=encoder.encode(cert["tbsCertificate"]),
                signature=cert["signature"].asOctets(),
                alg_id=cert["signatureAlgorithm"],
            )
        else:
            public_key = ensure_is_verify_key(public_key)
            cryptoutils.verify_signature(
                public_key=public_key,
                data=encoder.encode(cert["tbsCertificate"]),
                signature=cert["signature"].asOctets(),
                hash_alg=hash_alg,
            )

        return True
    except (ValueError, InvalidSignature, BadSigAlgID) as err:
        logging.info("%s", err)
    return False


@keyword(name="Build CMP Chain From PKIMessage")
def build_cmp_chain_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    ee_cert: Optional[rfc9480.CMPCertificate] = None,
    for_issued_cert: bool = False,
    last_cert_is_self_signed: bool = False,
    cert_number: typingutils.Strint = 0,
) -> List[rfc9480.CMPCertificate]:
    """Build the CMP-Protection certificate chain or the certificate chain for 'ip', 'cp', or 'kur' messages.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure containing the `extraCerts` field, which holds
        the list of certificates that may form the complete chain.
        - `ee_cert`: The end-entity (EE) CMP certificate from which the chain will be built.
        If not provided, the first certificate in the `extraCerts` field of the `pki_message` is used.
        - `for_issued_cert`: If `True`, extracts the newly issued certificate from 'ip', 'cp', or 'kur' messages
        and validates the chain. Defaults to `False`.
        - `last_cert_is_self_signed`: If `True`, requires the last certificate in the chain to be self-signed. \
        Defaults to `False`.
        - `cert_number`: The index of the newly issued certificate to extract from `PKIMessage` to build the chain for.

    Note:
    ----
        - Does not check, if the status is "accepted" or "grantedWithMods".
        - Does not check, if `caPubs` is allowed to be present.

    Returns:
    -------
        - A list of `pyasn1` `CMPCertificate` objects representing the complete certificate chain,
        starting from the EE certificate and ending with the root certificate.

    Raises:
    ------
        - `ValueError`: If the `extraCerts` field is missing in the `pki_message`.
        - `ValueError`: If the last certificate is required to be self-signed, but was not.


    Examples:
    --------
    | ${cert_chain}= | Build CMP Chain From PKIMessage | ${pki_message} | ee_cert=${ee_cert} \
    | for_ca_msg=True |
    | ${cert_chain}= | Build CMP Chain From PKIMessage | ${pki_message} | ee_cert=${ee_cert} |
    | ${cert_chain}= | Build CMP Chain From PKIMessage | ${pki_message} | for_ca_msg=True |

    """
    if not pki_message["extraCerts"].isValue:
        raise ValueError("The `extraCerts` field has no value inside the PKIMessage.")

    cert_list = []
    cert_list.extend(pki_message["extraCerts"])

    if for_issued_cert:
        asn1cert = cmputils.get_cert_from_pkimessage(pki_message, cert_number=cert_number)
        ca_pubs = pki_message["body"][pki_message["body"].getName()]["caPubs"]
        if ca_pubs.isValue:
            cert_list.extend(ca_pubs)

        return build_chain_from_list(asn1cert, cert_list, must_be_self_signed=False)

    if ee_cert is None:
        ee_cert = pki_message["extraCerts"][0]

    if not isinstance(ee_cert, rfc9480.CMPCertificate):
        raise ValueError("The `ee_cert` is not a valid CMPCertificate object.")

    return build_chain_from_list(ee_cert=ee_cert, certs=cert_list, must_be_self_signed=last_cert_is_self_signed)


def build_cert_chain_from_dir(  # noqa D417 undocumented-param
    ee_cert: typingutils.CertObjOrPath,
    cert_chain_dir: str,
    root_dir: str = "./data/trustanchors",
    must_be_complete: bool = False,
) -> List[rfc9480.CMPCertificate]:
    """Build a complete certificate chain starting from an end-entity (EE) certificate.

    Arguments:
    ---------
        - `ee_cert`: The end-entity certificate (EE) for which the chain will be built.
          This can be provided as a certificate object or a file path to a PEM or DER encoded certificate.
        - `cert_dir`: Path to the directory containing intermediate certificates.
        - `root_dir`: Path to the directory containing trusted root certificates. \
        Defaults to `./data/trustanchors`.
        - `must_be_complete`: If `True`, the chain must end with a self-signed root certificate. Defaults to `False`.

    Returns:
    -------
        - A list of `CMPCertificate` objects representing the constructed
        certificate chain, starting with the EE certificate and ending with the root certificate.

    Raises:
    ------
        - `ValueError`: If the last certificate inside the chain is not self-signed, but must be.

    Examples:
    --------
    | ${cert_chain}= | Build Cert Chain From Dir | ${ee_cert} | cert_dir=./path/to/certs \
    | root_dir=/path/to/trustanchors |
    | ${cert_chain}= | Build Cert Chain From Dir | ${ee_cert} | cert_dir=./path/to/certs |

    """
    if isinstance(ee_cert, str):
        der_data = utils.load_and_decode_pem_file(ee_cert)
        ee_cert = parse_certificate(der_data)

    cert_list = load_certificates_from_dir(cert_chain_dir)
    if root_dir is not None:
        cert_list.extend(load_certificates_from_dir(root_dir))
    return build_chain_from_list(ee_cert, cert_list, must_be_self_signed=must_be_complete)


@keyword(name="Validate CMP ExtendedKeyUsage")
def validate_cmp_extended_key_usage(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate, ext_key_usages: str, strictness: Union[str, int]
):
    """Validate the `ExtendedKeyUsage` extension of a provided certificate object.

    Arguments:
    ---------
        - `cert`: The certificate to validate the `ExtendedKeyUsage` extension.
        - `ext_key_usages`: Comma-separated string representation of the expected cmp related `ExtendedKeyUsage` \
        attributes for a certificate. (e.g., "cmcCA, cmcRA, cmKGA")
        - `strictness`: A string representation or integer which determines the level of validation strictness.

    Validation Strictness Levels:
    -----------------------------
        - NONE `0`: Validation is disabled.
        - LAX `1`: The `ExtendedKeyUsage` extension may be present, but if present must \
        contain the provided `ext_key_usages`
        - STRICT `2`: The `ExtendedKeyUsage` extension must be present. And contains the provided `ext_key_usages`.
        - ABS_STRICT `3`: The `ExtendedKeyUsage` extension must exactly match the provided `ext_key_usages`.

    Raises:
    ------
        - `ValueError`: If the `ExtendedKeyUsage` extension is not present in the certificate when \
         `strictness` is set to `STRICT` or `ABS_STRICT`, or if the actual `ExtendedKeyUsage` does not match the \
         expected `ext_key_usages`.

    Examples:
    --------
    | Validate CMP ExtendedKeyUsage | cert=${cert} | ext_key_usage=cmcCA, cmcRA | strictness=2 |
    | Validate CMP ExtendedKeyUsage | cert=${cert} | ext_key_usage=cmcRA | strictness=NONE |

    """
    val_strict = KeyUsageStrictness.get(strictness)
    if val_strict == KeyUsageStrictness.NONE:
        logging.info("ExtendedKeyUsage Check is disabled!")
        return

    cert_eku_obj = certextractutils.get_field_from_certificate(
        cert=cert,  # type: ignore
        extension="eku",
    )
    cert_eku_obj: Optional[rfc5280.ExtKeyUsageSyntax]
    if cert_eku_obj is None:
        if val_strict in [KeyUsageStrictness.ABS_STRICT, KeyUsageStrictness.STRICT]:
            raise ValueError(f"KeyUsage extension was not present in: {cert.prettyPrint()}")
        logging.info("KeyUsage extension was not present")
        return

    oids_allowed = set(ext_key_usages.strip(" ").split(","))
    vals = ["cmcCA", "cmcRA", "cmKGA"]
    not_inside = oids_allowed - set(vals)
    expected_eku = {oid: eku_name for oid, eku_name in CMP_EKU_OID_2_NAME.items() if eku_name in oids_allowed}

    if not expected_eku or not_inside:
        raise ValueError("No CMP extended key usages where provided allowed are: 'cmcCA, cmcRA, cmKGA'")

    found_oids_names = []
    other_oids = []
    for eku_oid in cert_eku_obj:
        if eku_oid in expected_eku:
            found_oids_names.append(CMP_EKU_OID_2_NAME[eku_oid])
        else:
            other_oids.append(CMP_EKU_OID_2_NAME.get(eku_oid, eku_oid))

    if len(expected_eku) != len(found_oids_names):
        raise ValueError(
            f"The CMP EKUs were incorrectly set. Expected: {list(expected_eku.values())}, "
            f"Found: {found_oids_names + other_oids}"
        )

    if val_strict == KeyUsageStrictness.ABS_STRICT:
        if not len(cert_eku_obj) == len(expected_eku):
            raise ValueError(
                "Expected to Only have CMP-related extended key usages should be set."
                f"But found: {found_oids_names + other_oids}"
            )


def _validate_key_usage(expected_usage: str, given_usage: rfc5280.KeyUsage, same_vals: bool) -> bool:
    """Validate if the expected key usage attributes are inside the provided `KeyUsage` object.

    :param expected_usage: The expected key usage attributes, comma-separated in a human-readable format.
    :param given_usage: The found `KeyUsage` object inside a certificate.
    :param same_vals: If set, the attributes must be equal.
    :return: `True` if all expected key usage attributes are set; `False`
    if unequal, but expected to be equal, or if not all attributes are set.
    """
    names = asn1utils.get_set_bitstring_names(given_usage)
    if same_vals:
        # to ensure same names are used.
        expected_usages = rfc5280.KeyUsage(expected_usage)
        expected_names = asn1utils.get_set_bitstring_names(expected_usages)
        return names == expected_names

    vals = [val.strip() for val in expected_usage.split(",")]
    is_set = 0
    for x in vals:
        is_set += asn1utils.is_bit_set(given_usage, x, exclusive=False)

    return len(vals) == is_set


@keyword(name="Validate KeyUsage")
def validate_key_usage(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate, key_usages: str, strictness: Union[str, int]
) -> None:
    """Validate the `KeyUsage` extension of a provided certificate object.

    Arguments:
    ---------
        - `cert`: The certificate to validate the `KeyUsage` extension.
        - `key_usages`: Comma-separated string representation of the expected `KeyUsages` attributes for a certificate.\
         (e.g., "`digitalSignature`")
        - `strictness`: A string representation or integer which determines the level of validation strictness.

    Validation Strictness Levels:
    -----------------------------
        - NONE `0`: Validation is disabled.
        - LAX `1`: The `KeyUsage` extension may be present, but if present must contain the provided `key_usages`
        - STRICT `2`: The `KeyUsage` extension must be present `key_usages`. And contains the provided `key_usages`.
        - ABS_STRICT `3`: The `KeyUsage` extension must exactly match the provided `key_usages`.

    Raises:
    ------
        - `ValueError`: If the `KeyUsage` extension is not present in the certificate when \
         `strictness` is set to `STRICT` or `ABS_STRICT`.
    - `NotAuthorized`: If the `KeyUsage` extension is present but does not match the expected `key_usages`.


    Examples:
    --------
    | Validate KeyUsage | cert=${cert} | key_usages=digitalSignature, keyEncipherment | strictness=2 |
    | Validate KeyUsage | cert=${cert} | key_usages=digitalSignature | strictness=LAX |

    """
    val_strict = KeyUsageStrictness.get(strictness)

    if val_strict == KeyUsageStrictness.NONE:
        logging.info("KeyUsage Check is disabled!")
        return

    usage = certextractutils.get_field_from_certificate(cert=cert, extension="key_usage")  # ignore: type

    if usage is None:
        if val_strict in [KeyUsageStrictness.ABS_STRICT, KeyUsageStrictness.STRICT]:
            raise BadKeyUsage(f"KeyUsage extension was not present in: {cert.prettyPrint()}")
        logging.info("KeyUsage extension was not present")
    else:
        same = False
        if val_strict == KeyUsageStrictness.ABS_STRICT:
            same = True

        if not _validate_key_usage(expected_usage=key_usages, given_usage=usage, same_vals=same):  # type: ignore
            names = asn1utils.get_set_bitstring_names(usage)  # type: ignore
            raise BadKeyUsage(f"KeyUsage Extension was expected to be: {key_usages}, but is {names}")


@keyword(name="Must Not Contain KeyUsage")
def must_not_contain_key_usage(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate, key_usages: str, must_be_present: bool = False
) -> None:
    """Validate that the `KeyUsage` extension of a provided certificate object does not contain specific attributes.

    Arguments:
    ---------
        - `cert`: The certificate to validate the `KeyUsage` extension.
        - `key_usages`: Comma-separated string representation of the expected `KeyUsages` attributes for a certificate.\
         (e.g., "`digitalSignature`")
         - `must_be_present`: If `True`, the `KeyUsage` extension must be present in the certificate.

    Raises:
    ------
        - `BadKeyUsage`: If the `KeyUsage` extension is present in the certificate and contains any of the \
        specified attributes.

    Examples:
    --------
    | Must Not Contain KeyUsage | cert=${cert} | key_usages=digitalSignature, keyEncipherment |

    """
    usage = certextractutils.get_field_from_certificate(cert=cert, extension="key_usage")  # type: ignore
    usage: Optional[rfc5280.KeyUsage]
    if usage is None:
        if must_be_present:
            raise BadKeyUsage(f"KeyUsage extension was not present in: {cert.prettyPrint()}")
        logging.info("KeyUsage extension was not present")
        return

    if _validate_key_usage(expected_usage=key_usages, given_usage=usage, same_vals=False):
        names = asn1utils.get_set_bitstring_names(usage)
        raise BadKeyUsage(f"KeyUsage Extension was expected to not contain: {key_usages}, but is {names}")


@not_keyword
def write_cert_chain_to_file(cert_chain: List[rfc9480.CMPCertificate], path: str):
    """Write a certificate chain to a single PEM file, overwriting the file if it already exists.

    Used to write a parseable file to the OpenSSL command.

    :param cert_chain: List of `pyasn1` `CMPCertificate` objects.
    :param path: Path to the output PEM file.
    """
    with open(path, "w", encoding="utf-8") as pem_file:
        for cert in cert_chain:
            pem_file.write(utils.pyasn1_cert_to_pem(cert))


def _verify_less_then_three_certificates(cert_chain: List[rfc9480.CMPCertificate], dir_fpath: str) -> List[str]:
    """Prepare OpenSSL command arguments for verifying a certificate chain with three or fewer certificates.

    Write the necessary files down to disk, for the OpenSSL verify command.

    :param cert_chain: A list of up to three `rfc9480.CMPCertificate` objects representing the certificate chain.
    The order should start with the end-entity certificate and proceed to the trust anchor.
    :param dir_fpath: Path to the directory where PEM files for certificates will be stored temporarily.
    :return: A list of OpenSSL command arguments required to verify the certificate chain.
    :raises ValueError: If the certificate chain length is not between one and three certificates.
    """
    command = []
    ee_path = os.path.join(dir_fpath, "ee.pem")
    ca_path = os.path.join(dir_fpath, "intermediates.pem")
    anchor = os.path.join(dir_fpath, "trustanchor.pem")

    intermediate_cert = None
    if len(cert_chain) == 1:
        ee_cert = cert_chain[0]
        anchor_cert = cert_chain[0]
    elif len(cert_chain) == 2:
        ee_cert = cert_chain[0]
        anchor_cert = cert_chain[1]
    elif len(cert_chain) == 3:
        ee_cert = cert_chain[0]
        intermediate_cert = cert_chain[1]
        anchor_cert = cert_chain[2]

    else:
        raise ValueError(f"Expected a certificate chain with the length 1 to 3, but got: {len(cert_chain)}")

    if anchor_cert:
        utils.write_cmp_certificate_to_pem(anchor_cert, anchor)
        command.extend(["-CAfile", anchor])

    if intermediate_cert:
        command.extend(["-untrusted", ca_path])
        utils.write_cmp_certificate_to_pem(intermediate_cert, ca_path)

    utils.write_cmp_certificate_to_pem(ee_cert, ee_path)
    command.append(ee_path)

    return command


def _verify_more_certs_than_three(cert_chain: List[rfc9480.CMPCertificate], dir_fpath: str) -> List[str]:
    """Prepare OpenSSL command arguments for verifying a certificate chain with more than three certificates.

    OpenSSL only accepts two files for the untrusted arguments, so more than three certificates have to be written
    into a single PEM file.

    :param cert_chain: A list of `rfc9480.CMPCertificate` objects representing the certificate chain.
    The order starts with the end-entity certificate to trusted certificate.
    :param dir_fpath: Path to the directory where PEM files for certificates will be stored temporarily.
    :return: A list of OpenSSL command arguments required to verify the certificate chain.
    """
    anchor = os.path.join(dir_fpath, "trustanchor.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[-1], anchor)

    ca_path = os.path.join(dir_fpath, "intermediates.pem")
    write_cert_chain_to_file(cert_chain[1:-1], ca_path)

    ee_path = os.path.join(dir_fpath, "ee.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[0], ee_path)

    command = ["-CAfile", anchor, "-untrusted", ca_path, ee_path]

    return command


def _verify_certificate_chain(command: List[str], cert_chain: List[rfc9480.CMPCertificate], timeout: int = 60) -> None:
    """Verify a certificate chain using OpenSSL commands.

    :param command: List of OpenSSL command line arguments to append for verification.
    :param cert_chain: List of `rfc9480.CMPCertificate` objects representing the certificate chain.
                       The chain order should start with the end-entity certificate and end with the root certificate.
    :param timeout: Maximum time in seconds for the OpenSSL verification command to run. Defaults to 60 seconds.

    :raises SignerNotTrusted: If `cert_chain` is empty, or OpenSSL returns a non-zero exit code,
    indicating a validation failure or if the verification process exceeds the specified timeout.
    """
    dir_fpath = "data/tmp_cert_checks"
    os.makedirs(dir_fpath, exist_ok=True)
    if len(cert_chain) == 0:
        raise ValueError("Got a empty chain to validate!")

    if len(cert_chain) <= 3:
        cmds = _verify_less_then_three_certificates(cert_chain, dir_fpath=dir_fpath)
    else:
        cmds = _verify_more_certs_than_three(cert_chain=cert_chain, dir_fpath=dir_fpath)

    command += cmds

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
        logging.debug("OpenSSL verify output: %s", result.stdout)
    except subprocess.CalledProcessError as e:
        # Log full error details from OpenSSL.
        logging.error("OpenSSL verify failed. stdout: %s\nstderr: %s", e.stdout, e.stderr)
        raise SignerNotTrusted(
            f"Validation of the certificate failed!\nstdout: {e.stdout}\nstderr: {e.stderr}", error_details=[str(e)]
        ) from e
    except subprocess.TimeoutExpired as e:
        logging.error("Reached timeout of %d seconds during certificate validation.", timeout)
        raise SignerNotTrusted("Validation of the certificate failed! Timeout!") from e
    except Exception as err:
        logging.error("An unexpected error occurred during certificate validation: %s", err)
        raise SignerNotTrusted(f"Validation of the certificate failed! Error: {err}") from err
    finally:
        if os.path.exists("data/tmp_crl"):
            shutil.rmtree("data/tmp_crl")

        shutil.rmtree(dir_fpath)

    logging.info("Certificate chain verified successfully.")


def _get_crls_from_certs(
    cert_chain: List[rfc9480.CMPCertificate],
    crl_path: Optional[str] = None,
    check_crl_all: bool = False,
) -> List[str]:
    """Get the CRLs from the certificates in the chain.

    :param cert_chain: A list of `rfc9480.CMPCertificate` objects representing the certificate chain.
    :param crl_path: The path to the CRL file to use for verification. Defaults to `None`.
    :return: A list of DER-encoded CRLs.
    """
    if crl_path is not None:
        return [crl_path]

    if check_crl_all:
        tmp_cert_chain = cert_chain
    else:
        tmp_cert_chain = [cert_chain[0]]

    crl_urls = []
    for i, cert in enumerate(tmp_cert_chain):
        urls = _extract_crl_urls_from_cert_pyasn1(cert=cert)
        crl_urls.extend(urls)
        # So that the Root CA does not need to have an CRl-DP set.
        if not urls and check_crl_all and i != len(tmp_cert_chain) - 1:
            raise ValueError(
                f"CRL URLs were not found in the certificate: {cert.prettyPrint()}."
                f"At index {i} of the chain. "
                f"Please provide a valid CRL path or set `check_crl_all` to `False`."
            )

    if not crl_urls:
        raise ValueError("Could not find the CRL URLs in the certificate chain.")
    return crl_urls


def ensure_is_pem_crl(data: bytes) -> bytes:
    """Ensure that the CRL is PEM encoded and returns it PEM encoded.

    :param data: The CRL data in bytes.
    :return: The PEM-encoded CRL data.
    """
    try:
        # Attempt to load as DER
        crl = x509.load_der_x509_crl(data)
        return crl.public_bytes(serialization.Encoding.PEM)
    except ValueError:
        pass

    try:
        _ = x509.load_pem_x509_crl(data)
        return data
    except ValueError:
        raise ValueError("Data is neither valid DER nor PEM format.")  # pylint: disable=raise-missing-from


def _fetch_crls(crl_urls: List[str]) -> List[str]:
    """Download CRL files from the given list of URLs and saves them as temporary files.

    :param crl_urls: List of CRL URLs to download.
    :return: List of paths to the downloaded CRL files.
    """
    downloaded_files = []

    for url in crl_urls:
        try:
            logging.info("Fetching CRL from: %s", url)
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # Create a temporary file with a .crl suffix
            with tempfile.NamedTemporaryFile(dir="data/tmp_crl", mode="wb", delete=False, suffix=".crl") as temp_file:
                data = ensure_is_pem_crl(response.content)
                temp_file.write(data)
                temp_file.flush()
                temp_file.close()

            downloaded_files.append(temp_file.name)
            logging.info("Saved to temporary file: %s", temp_file.name)

        except Exception as e:
            logging.info("Failed to fetch CRL from %s: %s", url, str(e))

    return downloaded_files


def _concatenate_crls(crl_files: Union[None, str, List[str]], filename: str = "combined_crls.crl") -> None:
    """Concatenates multiple CRL files into a single temporary PEM file.

    :param crl_files: List or a single path to CRL files to be concatenated.
    :return: Path to the concatenated temporary CRL file.
    """
    if not crl_files:
        raise ValueError("No CRL files provided for concatenation.")

    if isinstance(crl_files, str):
        crl_files = [crl_files]

    output_dir = Path("data/tmp_crl")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / filename
    with open(output_file, "wb") as outfile:
        for crl_file in crl_files:
            with open(crl_file, "rb") as infile:
                data = ensure_is_pem_crl(infile.read())
                outfile.write(data)


def _get_crl_filepath_for_verification(
    cert_chain: List[rfc9480.CMPCertificate],
    crl_path: Optional[str] = None,
    check_crl_all: bool = False,
) -> None:
    """Get the CRL file path for verification.

    :param cert_chain: A list of `rfc9480.CMPCertificate` objects representing the certificate chain.
    :param crl_path: The path to the CRL file to use for verification. Defaults to `None`.
    :return: The path to the CRL file.
    :raises ValueError: If the CRL file path is not valid or if the CRL URLs are not found in the certificate chain.
    """
    if crl_path is not None:
        if not os.path.isfile(crl_path):
            raise ValueError(f"The provided CRL path does not exist: {crl_path}")
        return

    os.makedirs("data/tmp_crl", exist_ok=True)

    crl_urls = _get_crls_from_certs(crl_path=crl_path, cert_chain=cert_chain, check_crl_all=check_crl_all)

    crl_files = []
    for uri in set(crl_urls):
        if uri.startswith("http://") or uri.startswith("https://"):
            crl_files += _fetch_crls(crl_urls)

    if not crl_files:
        raise ValueError(f"Could not fetch the CRLs form the uri: {crl_urls}.")

    _concatenate_crls(crl_files=crl_files)


@not_keyword
def check_openssl_pqc_support() -> bool:
    """Check if OpenSSL PQC support is enabled.

    Only OpenSSL 3.5 and later versions support PQC.

    :return: `True` if OpenSSL PQC support is enabled, `False` otherwise.
    """
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=True)
        ver_str = result.stdout.strip().split()[1]
        ver_num = ver_str.split("-")[0].split("+")[0]
        version_tuple = tuple(int(part) for part in ver_num.split(".")[:3])
        return version_tuple >= (3, 5, 0)
    except subprocess.CalledProcessError as e:
        logging.error("OpenSSL PQC support check failed: %s", e.stderr)
    except Exception as e:  # pylint: disable=broad-except
        logging.error("An unexpected error occurred while checking OpenSSL PQC support: %s", str(e))
    return False


@not_keyword
def pqc_algs_cannot_be_validated_with_openssl(
    certs: List[rfc9480.CMPCertificate],
) -> bool:
    """Check if the PQ certificate chain can not be validated with OpenSSL.

    OpenSSL only supports ML-DSA, ML-KEM and SLH-DSA signatures, so if the certificate chain contains
    any other signature algorithm, it can not be validated with OpenSSL.

    :param certs: A list of CMPCertificate's.
    :return: `True` if the certificate chain can not be validated with OpenSSL, `False` otherwise.
    """
    for cert in certs:
        spki_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        if spki_oid in COMPOSITE_SIG_OID_TO_NAME:
            return True
        if spki_oid in PQ_SIG_OID_2_NAME:
            if spki_oid not in SLH_DSA_OID_2_NAME and spki_oid not in ML_DSA_OID_2_NAME:
                return True
        elif spki_oid not in ML_KEM_OID_2_NAME:
            return True
    return False


def _get_algs(certs: List[rfc9480.CMPCertificate]) -> str:
    """Get the signature algorithms from the certificate chain.

    :param certs: A list of CMPCertificate's.
    :return: The signature algorithms in a human-readable format.
    """
    algs = []
    for cert in certs:
        spki_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        oid_name = oid_mapping.may_return_oid_to_name(spki_oid)
        subject = utils.get_openssl_name_notation(cert["tbsCertificate"]["subject"])
        algs.append(f"Subject={subject} OID:{oid_name} ")
    return "\n".join(algs)


@keyword(name="Verify Cert Chain OpenSSL PQC")
def verify_cert_chain_openssl_pqc(  # noqa D417 undocumented-param
    cert_chain: List[rfc9480.CMPCertificate],
    crl_check: bool = False,
    verbose: bool = True,
    timeout: typingutils.Strint = 60,
    crl_path: Optional[str] = None,
    crl_check_all: bool = False,
) -> None:
    """Verify a certificate chain using OpenSSL with PQC support.

    The certificate chain has to start from the end-entity certificate and ends with the Root certificate.

    Note:
    ----
    - Should only be used if OpenSSL PQC support is not surely enabled, otherwise \
    use the `Verify Cert Chain OpenSSL` keyword. Because it will skip the certificate \
    checks, if PQC support is not enabled.

    Arguments:
    ---------
        - `cert_chain`: A list of untrusted certificate objects to verify against the root certificate.
        - `crl_check`: Whether to perform CRL checks to verify if any certificate was revoked.
        Defaults to `False`.
        - `verbose`: Whether to use the verbose output flag for the OpenSSL `verify` command.
        Defaults to `True`.
        - `timeout`: The timeout of the verify command in seconds. Defaults to `60`.
        - `crl_path`: The path to the CRL file to use for verification. Defaults to `None`.
        - `crl_check_all`: Whether to check all certificates in the chain against the CRL(s).

    Raises:
    ------
        - `SignerNotTrusted`: If the certificate validation fails, according to the OpenSSL `verify` command.
        - `SignerNotTrusted`: If the verification took too long.

    Examples:
    --------
    | Verify Cert Chain OpenSSL PQC | cert_chain=${cert_chain} |
    | Verify Cert Chain OpenSSL PQC | cert_chain=${cert_chain} | crl_check=True | verbose=False |
    | Verify Cert Chain OpenSSL PQC | cert_chain=${cert_chain} | crl_check_all=True | timeout=120 |

    """
    # TODO: maybe allow or change the setup to use the `oqsprovider` to validate all PQC algorithms.

    if verbose:
        utils.log_certificates(certs=cert_chain, msg_suffix="Untrusted Certificates:\n")

    if not check_openssl_pqc_support():
        logging.warning("OpenSSL PQC support is not enabled.")

    else:
        if pqc_algs_cannot_be_validated_with_openssl(certs=cert_chain):
            raise ValueError(
                "The provided PQC certificate chain can not be validated with OpenSSL."
                "Supported PQC algorithms are: ML-DSA, ML-KEM, SLH-DSA."
                f"Found the following algorithms:\n{_get_algs(certs=cert_chain)}"
            )

        verify_cert_chain_openssl(
            cert_chain=cert_chain,
            crl_check=crl_check,
            verbose=verbose,
            timeout=timeout,
            crl_path=crl_path,
            crl_check_all=crl_check_all,
        )


@keyword(name="Verify Cert Chain OpenSSL")
def verify_cert_chain_openssl(  # noqa D417 undocumented-param
    cert_chain: List[rfc9480.CMPCertificate],
    crl_check: bool = False,
    verbose: bool = True,
    timeout: typingutils.Strint = 60,
    crl_path: Optional[str] = None,
    crl_check_all: bool = False,
) -> None:
    """Verify a certificate chain using OpenSSL.

    The certificate chain has to start from the end-entity certificate and ends with the Root certificate.

    Note:
    ----
      - The OpenSSL command will be executed in a temporary directory. data/tmp_cert_check and data/tmp_crl.
      - The certificates will be written to files in PEM format, as well as the CRL files (For debugging).
      - If cert_check_all is set to `True`, the CRL check will be performed for all certificates in the chain,
      but also expects **every certificate** to have a CRL distribution point set, besides the **root certificate**.

    Arguments:
    ---------
        - `cert_chain`: A list of untrusted certificate objects to verify against the root certificate.
        - `crl_check`: Whether to perform CRL checks to verify if any certificate was revoked.
        Defaults to `False`.
        - `verbose`: Whether to use the verbose output flag for the OpenSSL `verify` command.
        Defaults to `True`.
        - `timeout`: The timeout of the verify command in seconds. Defaults to `60`.
        - `crl_path`: The path to the CRL file to use for verification. Defaults to `None`.
        - `crl_check_all`: Whether to check all certificates in the chain against the CRL(s).

    Raises:
    ------
        - `SignerNotTrusted`: If the certificate validation fails, according to the OpenSSL `verify` command.
        - `SignerNotTrusted`: If the verification took to long.

    Examples:
    --------
    | Verify Cert Chain OpenSSL | cert_chain=${cert_chain} |
    | Verify Cert Chain OpenSSL | cert_chain=${cert_chain} | crl_check=True | verbose=False |
    | Verify Cert Chain OpenSSL | cert_chain=${cert_chain} | crl_check_all=True |

    """
    if verbose:
        utils.log_certificates(certs=cert_chain, msg_suffix="Untrusted Certificates:\n")

    temp_dir = "./data/tmp_cert_check"
    if not os.path.isdir("./data/tmp_cert_check"):
        os.mkdir(temp_dir)

    if not crl_check and not crl_check_all:
        logging.warning("Please Note the CRL check is deactivate!")

    command = ["openssl", "verify"]

    if crl_check or crl_check_all:
        _get_crl_filepath_for_verification(cert_chain=cert_chain, crl_path=crl_path, check_crl_all=crl_check_all)
        crl_path = crl_path or "data/tmp_crl/combined_crls.crl"
        command.extend(["-CRLfile", crl_path])

    if crl_check_all:
        command.append("-crl_check_all")
    if crl_check:
        command.append("-crl_check")

    if not crl_check and not crl_check_all:
        command.append("-no-CApath")

    if verbose:
        command.append("-verbose")

    _verify_certificate_chain(command=command, cert_chain=cert_chain, timeout=int(timeout))


@not_keyword
def cert_in_list(cert: rfc9480.CMPCertificate, cert_list: List[rfc9480.CMPCertificate]) -> bool:
    """Check if a pyasn1 certificate inside a list of pyasn1 certificates.

    `pyasn1` might throw an error, so the key word 'in' is not usable.
    As the validation may not handle schema attribute comparisons.

    :return: True if equal; False otherwise.
    """
    der_cert = encoder.encode(cert)
    for single_cert in cert_list:
        if der_cert == encoder.encode(single_cert):
            return True

    return False


def certificates_are_trustanchors(  # noqa D417 undocumented-param
    certs: Union[rfc9480.CMPCertificate, List[rfc9480.CMPCertificate]],
    trustanchors: Optional[str] = "./data/trustanchors",
    allow_os_store: bool = True,
    verbose: bool = True,
) -> None:
    """Check if the provided certificates are trustanchors.

    Arguments:
    ---------
        - `certs`: A single or a list of pyasn1 `CMPCertificate` objects to check.
        - `trustanchors`: A directory path to load additional trustanchors. Defaults to "./data/trustanchors".
        - `allow_os_store`: Whether to allow the default OS store to be added to the trustanchors. Defaults to `True`.
        - `verbose`: Whether to log all non-trustanchor certificates. Defaults to `True`.
        - `allow_os_store`: Whether to allow the default OS store to be added to the trustanchors. Defaults to `True`.

    Raises:
    ------
        - `SignerNotTrusted`: If the certificates are not allowed/known trustanchors.

    Examples:
    --------
    | Certificates Are Trustanchors | certs=${certs} |
    | Certificates Are Trustanchors | certs=${certs} | trustanchors=./path/to/anchors | allow_os_store=False |

    """
    anchors = load_truststore(path=trustanchors, allow_os_store=allow_os_store)

    if len(anchors) == 0:
        raise ValueError("No trust anchors were found!")

    if isinstance(certs, rfc9480.CMPCertificate):
        certs = [certs]

    none_anchors = []

    for single_cert in certs:
        if not cert_in_list(single_cert, anchors):
            none_anchors.append(single_cert)

    if none_anchors:
        utils.log_cert_chain_subject_and_issuer(none_anchors)
        if verbose:
            utils.log_certificates(none_anchors)

        raise SignerNotTrusted("Certificates are not trust anchors!")


def certificates_must_be_trusted(  # noqa D417 undocumented-param
    cert_chain: List[rfc9480.CMPCertificate],
    trustanchors: Union[None, str] = "./data/trustanchors",
    allow_os_store: bool = True,
    key_usages: str = "digitalSignature",
    key_usage_strict: typingutils.Strint = 1,
    verbose: bool = True,
    crl_check: bool = False,
):
    """Validate a certificate chain against trusted anchors, with optional key usage and CRL checks.

    Verify the chain by checking if the last object in the chain is a trusted certificate and
    optionally performing key usage checks and CRL checks for additional validation.

    Note:
    ----
        - As of Rfc9483 Section 1.2 Conventions and Terminology, If the keyUsage extension is present, \
        it *MUST* include `digitalSignature`.

    Arguments:
    ---------
        - `cert_chain`: A list of `pyasn1 CMPCertificates` forming the chain to validate.
        - `trustanchors`: A directory path to load additional PKI trustanchors. By setting to \
        ${None} can be disabled. Defaults to `./data/trustanchors`.
        - `allow_os_store` Whether to allow the default OS store to be added to the trust anchors.
        Defaults to `True`.
        - `key_usage`: Human-readable representation of the KeyUsage attributes the entity certificate has to \
        have (e.g., "digitalSignature" to check if the EE certificate is allowed to sign data).
        Defaults to `digitalSignature`.
        - `key_usage_strict`: strictness: A string representation or integer which determines
        the level of validation strictness. Defaults to `1`.
        - `crl_check`: Perform CRL checks for certificate revocation. Defaults to `False`.
        - `verbose`: Enable verbose OpenSSL output during validation. Defaults to `True`.

    key_usage_strict:
    ----------------
        - `NONE 0`: Validation is disabled.
        - `LAX 1`: The `KeyUsage` extension may be present, but if present must contain the provided `key_usages`
        - `STRICT 2`: The `KeyUsage` extension must be present `key_usages`. And contains the provided `key_usages`.
        - `ABS_STRICT 3`: The `KeyUsage` extension must exactly match the provided `key_usages`.

    Raises:
    ------
        - `SignerNotTrusted`: If the last certificate inside the certificate chain is not trusted.
        - `ValueError`: If the certificate chain validation fails.
        - `BadKeyUsage`: If key usage validation fails on the EE certificate.

    Examples:
    --------
    | Certificates Must Be Trusted | cert_chain=${cert_chain} | /path/to/anchors |
    | Certificates Must Be Trusted | cert_chain=${cert_chain} | allow_os_store=False |

    """
    anchors: List[rfc9480.CMPCertificate] = []

    if trustanchors is not None:
        anchors = load_truststore(path=trustanchors, allow_os_store=allow_os_store)

    trusted = cert_in_list(cert_chain[-1], anchors)

    if not trusted:
        subject_name = utils.get_openssl_name_notation(cert_chain[-1]["tbsCertificate"]["subject"])
        raise SignerNotTrusted(
            f"Subject={subject_name} is not a trust anchor!\nCertificate:\n{cert_chain[-1].prettyPrint()}"
        )

    if len(cert_chain) == 1:
        logging.info("`certificates_must_be_trusted` got a single cert.")
        return

    verify_cert_chain_openssl(cert_chain, verbose=verbose, crl_check=crl_check)

    # validates the key usage for the ee-certificate,
    # because OpenSSL validates the Usages for the Chain.
    if key_usages is not None:
        validate_key_usage(
            cert=cert_chain[0],
            key_usages=key_usages,
            strictness=int(key_usage_strict),
        )


@not_keyword
def load_certificates_from_dir(path: str) -> List[rfc9480.CMPCertificate]:
    """Load all certificates from the specified directory.

    :param path: The directory path containing the certificate files.
    :return: A list of x509.Certificate objects loaded from the specified directory.
    :raises FileNotFoundError: If the specified directory does not exist.
    :raises ValueError: If any file in the directory cannot be loaded as a valid certificate.
    """
    certs = []
    for filepath in Path(path).glob("./*"):
        path = str(filepath)
        if path.endswith(".crl"):
            continue
        der_data = utils.load_and_decode_pem_file(path)
        cert = parse_certificate(der_data)
        certs.append(cert)

    return certs


@not_keyword
def verify_signature_with_cert(
    asn1cert: rfc9480.CMPCertificate, data: bytes, signature: bytes, hash_alg: Optional[str] = None
) -> None:
    """Verify a signature with a pyasn1 certificate.

    :param asn1cert: The certificate object, to extract the public key from.
    :param data: The data to verify.
    :param signature: The signature to verify against.
    :param hash_alg: The hash algorithm to use for signature verification (e.g., "sha256").
    :raises InvalidSignature: If the signature is invalid.
    """
    pub_key = load_public_key_from_cert(asn1cert)
    pub_key = ensure_is_verify_key(pub_key)
    cryptoutils.verify_signature(
        public_key=pub_key,
        signature=signature,
        data=data,
        hash_alg=hash_alg,
    )


@not_keyword
def parse_crl(der_data: bytes):
    """Parse a CRL from DER-encoded data.

    :param der_data: DER-encoded CRL data.
    :return: Decoded CRL object.
    :raises BadAsn1Data: If the CRL cannot be decoded.
    """
    try:
        crl, _ = decoder.decode(der_data, asn1Spec=rfc5280.CertificateList())
        return crl
    except Exception:
        raise BadAsn1Data("Failed to load CRL from DER data.")  # pylint: disable=raise-missing-from


def _write_crl_to_pem(crl: rfc5280.CertificateList, path: str):
    with open(path, "wb") as crl_file:
        crl_file.write(encoder.encode(crl))


# TODO update
@not_keyword
def verify_openssl_crl(crl_chain: List, timeout: int = 60):
    """Verify a CRL against a trusted CA certificate using OpenSSL.

    We can ask for the currentCRL with a general message and must verify if this is a correct list.

    :param crl_chain: The chain of CRL to verify. Starts with the CRL and ends with the
    CA certificate.
    :param timeout: The timeout in seconds for the verification.Defaults to 60 seconds.
    :return: True if the CRL is verified, False otherwise.
    :raises ValueError: If the CRL is invalid or verification fails.
    """
    dir_fpath = "data/tmp_cert_checks"
    os.makedirs(dir_fpath, exist_ok=True)

    crl_path = f"{dir_fpath}/crl.der"

    if not isinstance(crl_chain[0], rfc5280.CertificateList):
        raise ValueError("The first element of the CRL chain must be a CertificateList object.")

    with open(crl_path, "wb") as crl_file:
        crl_file.write(encoder.encode(crl_chain[0]))

    anchor = f"{dir_fpath}/anchor.pem"

    command = ["openssl", "crl", "-in", crl_path]

    tmp = crl_chain[1:]
    tmp.reverse()

    write_cert_chain_to_file(tmp, anchor)
    command.extend(["-CAfile", anchor, "-verify"])
    try:
        result = subprocess.run(command, capture_output=True, check=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise ValueError(f"Validation of the CRL failed! stdout:{result.stdout}\nerror: {result.stderr}")
        return
    except subprocess.TimeoutExpired:
        logging.warning("Reached time out of for CRL validation. Seconds: %d", timeout)
    except Exception as err:
        logging.warning(err)
    finally:
        shutil.rmtree(dir_fpath)

    raise ValueError("Validation of the CRL failed!")


@keyword(name="Find CRL Signer Cert")
def find_crl_signer_cert(  # noqa D417 undocumented-param
    crl: rfc5280.CertificateList,
    ca_cert_dir: str = "data/cert_logs",
    certs: Optional[List[rfc9480.CMPCertificate]] = None,
) -> rfc9480.CMPCertificate:
    """Find the certificate that signed the CRL.

    Arguments:
    ---------
        - `crl`: The CRL to verify.
        - `ca_cert_dir`: The directory containing the CA certificates. Defaults to "data/cert_logs".
        - `certs`: A list of CA certificates to search through. If provided, will use this list
        instead of loading from the directory.

    Returns:
    -------
        - The certificate that signed the CRL.

    Raises:
    ------
        - `ValueError`: If no matching certificate is found.

    Examples:
    --------
    | ${crl_signer}= | Find CRL Signer Cert | ${crl} | ca_cert_dir=./path/to/certs |
    | ${crl_signer}= | Find CRL Signer Cert | ${crl} | ca_cert_dir=./path/to/certs | certs=${certs} |

    """
    certs = certs or load_certificates_from_dir(ca_cert_dir)

    crl_issuer = crl["tbsCertList"]["issuer"]
    crl_signature = crl["signature"].asOctets()
    crl_tbs = encoder.encode(crl["tbsCertList"])
    hash_oid = crl["signatureAlgorithm"]["algorithm"]
    hash_alg = get_hash_from_oid(hash_oid, only_hash=True)

    for cert in certs:
        cert_subject = cert["tbsCertificate"]["subject"]
        if compareutils.compare_pyasn1_names(crl_issuer, cert_subject, "without_tag"):
            try:
                verify_signature_with_cert(signature=crl_signature, hash_alg=hash_alg, data=crl_tbs, asn1cert=cert)

                return cert
            except (ValueError, InvalidSignature):
                pass

    raise ValueError("No matching certificate found to verify the CRL.")


@keyword(name="Build CRL Chain From List")
def build_crl_chain_from_list(  # noqa D417 undocumented-param
    crl: rfc5280.CertificateList,
    certs: Optional[List[rfc9480.CMPCertificate]] = None,
    cert_dir: str = "./data/trustanchors",
    allow_os_store: bool = True,
) -> List:
    """Build a CRL chain from a list of certificates and verify the CRL's signature.

    Arguments:
    ---------
       - `crl`: The CRL to verify.
       - `certs`: A list of certificates to search through. Defaults to `None`.
       - `cert_dir`: The directory containing the CA certificates. Defaults to "./data/trustanchors".
       - `allow_os_store`: Whether to allow the default OS store to be added to the trustanchors. Defaults to `True`.

    Returns:
    -------
       - The certificate chain starting with the CRL and ending with the root certificate.

    Raises:
    ------
       - `ValueError`: If the CRL was not issued by one of the provided certificates.
       - `ValueError`: If `certs` and `cert_dir` are both `None`.

    Examples:
    --------
    | ${crl_chain}= | Build CRL Chain From List | ${crl} | ${certs} |

    """
    if not certs and not cert_dir:
        raise ValueError("Either `certs` or `cert_dir` must be provided.")

    certs = certs or []
    certs.extend(load_truststore(allow_os_store=allow_os_store, path=cert_dir))

    signer = find_crl_signer_cert(crl, certs=certs)

    chain = build_chain_from_list(signer, certs)
    return [crl] + chain


def _convert_to_crypto_lib_cert(cert: Union[x509.Certificate, rfc9480.CMPCertificate]) -> x509.Certificate:
    """Convert a pyasn1 certificate to a cryptography library certificate.

    :param cert: The pyasn1 certificate to convert.
    :return: The cryptography library certificate.
    """
    if not isinstance(cert, rfc9480.CMPCertificate):
        return cert

    der_data = encoder.encode(cert)
    return x509.load_der_x509_certificate(der_data)


@not_keyword
def get_ocsp_url_from_cert(
    cert: rfc9480.CMPCertificate,
) -> List[str]:
    """Extract the OCSP URL from a certificate's Authority Information Access extension.

    :param cert: The certificate to extract the OCSP URL from.
    :return: The OCSP URLs, if present.
    """
    aia = certextractutils.get_field_from_certificate(cert, extension="aia")  # type: ignore
    aia: Optional[rfc5280.AuthorityInfoAccessSyntax]
    if aia is None:
        return []

    entry: rfc5280.AccessDescription
    ocsp_urls = []
    for entry in aia:
        if str(entry["accessMethod"]) == AuthorityInformationAccessOID.OCSP.dotted_string:
            gen_name: rfc9480.GeneralName = entry["accessLocation"]
            option = gen_name.getName()
            if option == "uniformResourceIdentifier":
                ocsp_urls.append(str(entry["accessLocation"][option]))
            else:
                raise NotImplementedError(
                    f"Not implemented OCSP access method: {option}. Expected 'uniformResourceIdentifier'."
                )

    return ocsp_urls


@not_keyword
def create_ocsp_request(
    cert: rfc9480.CMPCertificate,
    ca_cert: rfc9480.CMPCertificate,
    hash_alg: str = "sha256",
    must_be_present: bool = True,
) -> Tuple[ocsp.OCSPRequest, List[str]]:
    """Create an OCSP request for a certificate.

    :param cert: The certificate to check.
    :param ca_cert: The issuer's certificate.
    :param hash_alg: The hash algorithm to use for the OCSP request. Defaults to "sha256".
    :param must_be_present: Whether the OCSP URLs must be present in the certificate's AIA
    extension. Defaults to `True`.
    :return: The OCSP request and the OCSP URL.
    :raises ExtensionNotFound: If no OCSP URLs are found in the certificate's AIA extension.
    :raises ValueError: If the OCSP request fails.
    """
    crypto_ca_cert = _convert_to_crypto_lib_cert(ca_cert)
    crypto_cert = _convert_to_crypto_lib_cert(cert)

    ocsp_url = get_ocsp_url_from_cert(cert)
    if not ocsp_url and must_be_present:
        raise ExtensionNotFound(
            msg="No OCSP URLs found in the certificate's AIA extension.", oid=AuthorityInformationAccessOID.OCSP
        )

    builder = ocsp.OCSPRequestBuilder()
    hash_instance = oid_mapping.hash_name_to_instance(hash_alg)
    builder = builder.add_certificate(crypto_cert, crypto_ca_cert, hash_instance)
    req = builder.build()
    return req, ocsp_url


def _log_cert_issue_and_subject_and_serial_number(cert: Union[x509.Certificate, rfc9480.CMPCertificate]) -> None:
    """Log the certificate issuer, subject, and serial number.

    :param cert: The certificate to log.
    """
    cert = _convert_to_crypto_lib_cert(cert)
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()
    serial_number = cert.serial_number
    data = f"Subject: {subject}, Issuer: {issuer}, Serial Number: {serial_number}"
    logging.debug(data)


@not_keyword
def check_ocsp_response(
    ocsp_response: ocsp.OCSPResponse,
    cert: rfc9480.CMPCertificate,
    expected_status: str = "revoked",
    allow_unknown_status: bool = False,
) -> None:
    """Check the OCSP response for the certificate.

    :param ocsp_response: The OCSP response to check.
    :param cert: The certificate to check.
    :param expected_status: The expected status of the certificate. Defaults to "revoked".
    :param allow_unknown_status: Whether to treat an unknown status as success. Defaults to `False`.
    :raises ValueError: If the OCSP response is invalid or the request fails.
    """
    if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError(f"OCSP response was not successful. Status: {ocsp_response.response_status}")

    status = ocsp_response.certificate_status

    if status == ocsp.OCSPCertStatus.GOOD:
        state = "good"
    elif status == ocsp.OCSPCertStatus.REVOKED:
        state = "revoked"
    else:
        state = "unknown"

    logging.info("OCSP response status: %s", state)

    if state == "unknown" and allow_unknown_status:
        return

    if state != expected_status:
        _log_cert_issue_and_subject_and_serial_number(cert)
        raise ValueError(f"OCSP response status was `{state}`, but expected `{expected_status}`")


def _post_ocsp_request(
    url: str,
    ocsp_request_data: bytes,
    timeout: int,
    allow_request_failure: bool,
) -> Optional[requests.Response]:
    """Send an OCSP request to a specified OCSP responder.

    :param url: The URL of the OCSP responder.
    :param ocsp_request_data: The OCSP request data.
    :param timeout: The timeout for the request.
    :param allow_request_failure: Whether to allow the request to fail. Defaults to `False`.
    :return: The OCSP response.
    :raises ValueError: If the OCSP response is invalid or the request fails.
    """
    headers = {"Content-Type": "application/ocsp-request"}
    try:
        response = requests.post(url=url, data=ocsp_request_data, headers=headers, timeout=timeout)

    except requests.exceptions.RequestException as err:
        if allow_request_failure:
            logging.warning("Failed to send OCSP request. Error: %s", err, exc_info=True)
            return None
        raise ValueError(f"Failed to send OCSP request. Error: {err}") from err

    if response.status_code != 200 and not allow_request_failure:
        logging.warning("Failed to send OCSP request. Status code: %s", response.status_code)
        logging.debug("Response: %s", response.text)
        raise ValueError(f"Failed to send OCSP request. Status code: {response.status_code}")
    if response.status_code != 200 and allow_request_failure:
        logging.warning("Failed to send OCSP request. Status code: %s", response.status_code)
        logging.debug("Response: %s", response.text)
        return None

    return response


def _handel_single_ocsp_request(
    url: str,
    ocsp_request_data: bytes,
    timeout: int,
    expected_status: str,
    cert: rfc9480.CMPCertificate,
    allow_request_failure: bool = False,
    allow_unknown_status: bool = False,
) -> None:
    """Handle a single OCSP request.

    :param url: The URL of the OCSP responder.
    :param ocsp_request_data: The OCSP request data.
    :param timeout: The timeout for the request.
    :param expected_status: The expected status of the certificate.
    :param cert: The certificate to check.
    :param allow_request_failure: Whether to allow the request to fail. Defaults to `False`.
    :param allow_unknown_status: Whether to treat an unknown status as success. Defaults to `False`.
    :raises ValueError: If the OCSP response is invalid or the request fails.
    """
    response = _post_ocsp_request(
        url=url, ocsp_request_data=ocsp_request_data, allow_request_failure=allow_request_failure, timeout=timeout
    )

    if response is None:
        return

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    check_ocsp_response(ocsp_response, cert, expected_status=expected_status, allow_unknown_status=allow_unknown_status)


@keyword(name="Check OCSP Response For Cert")
def check_ocsp_response_for_cert(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate,
    issuer: rfc9480.CMPCertificate,
    ocsp_url: Optional[str] = None,
    timeout: Strint = 60,
    hash_alg: str = "sha256",
    expected_status: str = "revoked",
    allow_request_failure: bool = False,
    must_be_present: Optional[bool] = None,
    allow_unknown_status: bool = False,
):
    """Send an OCSP request to a specified OCSP responder.

    Arguments:
    ---------
        - `cert`: The certificate to check.
        - `issuer`: The issuer certificate.
        - `ocsp_url`: The URL of the OCSP responder. Defaults to the URL in the certificate's AIA extension.
        - `timeout`: The timeout in seconds for the request. Defaults to `60` seconds.
        - `hash_alg`: The hash algorithm to use for the OCSP request. Defaults to "sha256".
        - `expected_status`: The expected status of the certificate. Defaults to "revoked".
        - `allow_request_failure`: Whether to allow the request to fail. Defaults to `False`.
        - `must_be_present`: Whether the OCSP URLs must be present in the certificate's AIA extension.
        Defaults to `None` (will be set to `True` if no `ocsp_url` is provided, otherwise `False`).
        - `allow_unknown_status`: Whether to treat an unknown status as success. Defaults to `False`.
        (e.g., If set to True, an "unknown" status is returned and expected was either
        "revoked" or "good", the keyword will not raise an error).

    Raises:
    ------
        - `ValueError`: If the OCSP response is invalid or the request fails.
        - `ValueError`: If the expected status is invalid (must be one of "good", "revoked", or "unknown").
        - `ExtensionNotFound`: If no OCSP URL(s) are found in the certificate's AIA extension.

    Examples:
    --------
    | Check OCSP Response For Cert | cert=${cert} | issuer=${issuer} | ocsp_url=${ocsp_url} |
    | Check OCSP Response For Cert | cert=${cert} | issuer=${issuer} | expected_status=good |
    | Check OCSP Response For Cert | cert=${cert} | issuer=${issuer} | expected_status=unknown | timeout=30 |

    """
    if expected_status not in ["good", "revoked", "unknown"]:
        raise ValueError("Invalid expected status. Must be one of 'good', 'revoked', or 'unknown'")

    if must_be_present is None:
        must_be_present = True if ocsp_url is not None else False

    req, ocsp_url_found = create_ocsp_request(
        cert=cert, ca_cert=issuer, hash_alg=hash_alg, must_be_present=must_be_present
    )
    ocsp_request_data = req.public_bytes(serialization.Encoding.DER)
    ocsp_urls = ocsp_url or ocsp_url_found  # type: ignore

    if isinstance(ocsp_url, str):
        ocsp_urls = [ocsp_url]  # type: ignore

    ocsp_urls: List[str]
    for url in ocsp_urls:
        _handel_single_ocsp_request(
            url=url,
            ocsp_request_data=ocsp_request_data,
            timeout=int(timeout),
            expected_status=expected_status,
            cert=cert,
            allow_request_failure=allow_request_failure,
            allow_unknown_status=allow_unknown_status,
        )


def _get_cert_status(status: Optional[str]) -> ocsp.OCSPCertStatus:
    """Get the OCSP certificate status."""
    if status == "good":
        return ocsp.OCSPCertStatus.GOOD
    if status == "revoked":
        return ocsp.OCSPCertStatus.REVOKED
    if status == "unknown":
        return ocsp.OCSPCertStatus.UNKNOWN
    if status is None:
        return ocsp.OCSPCertStatus.UNKNOWN
    raise ValueError(f"Invalid status: {status}")


def _get_reason_flags(reason: Optional[str]) -> Optional[ReasonFlags]:
    """Get the OCSP revocation reason flags."""
    if reason is None:
        return None
    return ReasonFlags(reason)


# TODO add unsuccessful handling.


@not_keyword
def build_ocsp_response(
    cert: rfc9480.CMPCertificate,
    ca_cert: rfc9480.CMPCertificate,
    responder_key: SignKey,
    status: str,
    hash_alg: Optional[str] = "sha256",
    revocation_reason: Optional[str] = None,
    responder_cert: Optional[rfc9480.CMPCertificate] = None,
    responder_hash_alg: str = "sha256",
    revocation_time: Optional[datetime] = None,
    this_update: Optional[datetime] = None,
    build_by_key: bool = True,
    nonce: Optional[bytes] = None,
) -> ocsp.OCSPResponse:
    """Build an OCSP response for a list of certificates.

    :param cert: The certificate to check.
    :param ca_cert: The issuer's certificate.
    :param responder_key: The responder private key.
    :param status: The status of the certificate. **Must** be one of "good", "revoked", or "unknown".
    :param hash_alg: The hash algorithm to use for the OCSP response. Defaults to "sha256".
    :param revocation_reason: The revocation reason for the certificate. Defaults to `None`.
    :param responder_cert: The responder certificate. Defaults to `ca_cert`.
    :param responder_hash_alg: The hash algorithm to use for the responder. Defaults to "sha256".
    :param revocation_time: The revocation time for the certificate. Defaults to `None`.
    (must be present if the certificate is revoked, but will be set to the current time if not provided).
    :param this_update: The time of the OCSP response. Defaults to `None` (now).
    :param build_by_key: Whether to build the OCSP response by hash of the key or name. Defaults to `True`.
    :param nonce: The nonce to include in the OCSP response. Defaults to 16 random bytes.
    :return: The OCSP response.
    :raises ValueError: If the status is invalid.
    """
    crypto_ca_cert = _convert_to_crypto_lib_cert(ca_cert)
    builder = ocsp.OCSPResponseBuilder()
    resp_hash_inst = oid_mapping.hash_name_to_instance(responder_hash_alg)

    crypto_cert = _convert_to_crypto_lib_cert(cert)
    cert_status = _get_cert_status(status)
    reason = _get_reason_flags(revocation_reason)

    if cert_status == ocsp.OCSPCertStatus.REVOKED and revocation_time is None:
        # must be present if the certificate is revoked.
        revocation_time = datetime.now(timezone.utc) - timedelta(seconds=30)

    builder = builder.add_response(
        cert=crypto_cert,
        issuer=crypto_ca_cert,
        algorithm=resp_hash_inst,
        cert_status=cert_status,
        revocation_reason=reason,
        this_update=this_update or datetime.now(tz=timezone.utc),
        next_update=None,
        revocation_time=revocation_time,
    )
    crypto_responder_cert = None if responder_cert is None else _convert_to_crypto_lib_cert(responder_cert)
    crypto_responder_cert = crypto_responder_cert or crypto_ca_cert

    # Set the responder ID; it can be either byName (DER encoded `NAME`) or byKey (hash).
    if build_by_key:
        _encoding = ocsp.OCSPResponderEncoding.HASH
    else:
        _encoding = ocsp.OCSPResponderEncoding.NAME

    builder = builder.responder_id(encoding=_encoding, responder_cert=crypto_responder_cert)

    # Allow range is 1-32 from the RFC 8954.
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)

    if hash_alg is not None:
        hash_inst = oid_mapping.hash_name_to_instance(hash_alg)
    else:
        hash_inst = None

    if isinstance(responder_key, (Ed25519PrivateKey, Ed448PrivateKey)):
        # Use the responder key directly for signing.
        return builder.sign(responder_key, None)

    return builder.sign(responder_key, hash_inst)  # type: ignore


def _extract_crl_urls_from_cert_pyasn1(cert: rfc9480.CMPCertificate) -> List[str]:
    """Extract CRL distribution point URLs from a certificate.

    :param cert: A certificate object.
    :return: List of CRL URLs found in the certificate's CRL Distribution Points extension.
    """
    crl_urls = []
    extn = certextractutils.get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_cRLDistributionPoints)
    if extn is None:
        return []

    crl_dist_points, _ = decoder.decode(extn["extnValue"], asn1Spec=rfc5280.CRLDistributionPoints())
    crl_dist_points: rfc5280.CRLDistributionPoints

    for dist_point in crl_dist_points:
        if dist_point["distributionPoint"]["fullName"].isValue:
            for full_name in dist_point["distributionPoint"]["fullName"]:
                if full_name["uniformResourceIdentifier"].isValue:
                    crl_urls.append(full_name["uniformResourceIdentifier"].prettyPrint())

    return crl_urls


def _parse_crl_and_check_revocation(
    crl_data: bytes,
    serial_number: int,
) -> bool:
    """Parse the CRL data (PEM or DER) and check if the given serial number is in the CRL.

    :param crl_data: The raw CRL bytes.
    :param serial_number: The certificate's serial number to check against the CRL.
    :return: True if the certificate's serial is found in the CRL, False otherwise.
    :raises IOError: If the CRL data cannot be parsed.
    """
    try:
        crl = x509.load_der_x509_crl(crl_data)
    except Exception:
        logging.debug("Failed to load CRL data as DER. Trying to load as PEM.", exc_info=True)
        try:
            crl = x509.load_pem_x509_crl(crl_data)
        except Exception as err2:
            raise IOError(f"Failed to load CRL data: {err2}") from err2

    for revoked_cert in crl:
        if revoked_cert.serial_number == serial_number:
            logging.debug("Certificate with serial %s is in the CRL.", serial_number)
            return True
    return False


@not_keyword
def process_single_crl_check(
    serial_number: int,
    crl_url: Optional[str] = None,
    crl_file_path: Optional[str] = None,
    timeout: int = 10,
) -> bool:
    """Check if a certificate is revoked, by checking against a CRL.

    :param serial_number: Serial number of the certificate to check.
    :param crl_url: The URL of the CRL to check against.
    :param crl_file_path: The file path of the CRL to check against.
    :param timeout: The timeout in seconds for the request. Defaults to `10`.
    :return: Whether the certificate is revoked.
    """
    if crl_url:
        response = requests.get(crl_url, timeout=timeout)
        crl_data = response.content
    elif crl_file_path:
        with open(crl_file_path, "rb") as crl_file:
            crl_data = crl_file.read()
    else:
        raise ValueError("Either `crl_url` or `crl_file_path` must be provided.")

    return _parse_crl_and_check_revocation(crl_data, serial_number)


@keyword(name="Check If Cert Is Revoked CRL")
def check_if_cert_is_revoked_crl(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate,
    crl_url: Optional[str] = None,
    crl_file_path: Optional[str] = None,
    timeout: Strint = 60,
    allow_no_crl_urls: bool = False,
) -> None:
    """Check if a certificate is revoked, by checking against a CRL.

    Arguments:
    ---------
        - `cert`: The certificate to check.
        - `crl_url`: The URL of the CRL to check against.
        - `crl_file_path`: The file path of the CRL to check against.
        - `timeout`: The timeout in seconds for the request. Defaults to `60`.
        - `allow_no_crl_urls`: Whether to allow no CRL URLs to be found in the certificate. Defaults to `False`.

    Raises:
    ------
        - `ValueError`: If the certificate is revoked.
        - `ValueError`: If no CRL URLs are found in the certificate.
        - `IOError`: If the CRL data cannot be loaded.

    Examples:
    --------
    | Check If Cert Is Revoked CRL | cert=${cert} |
    | Check If Cert Is Revoked CRL | cert=${cert} | timeout=30 |
    | Check If Cert Is Revoked CRL | cert=${cert} | crl_url=${crl_url} |
    | Check If Cert Is Revoked CRL | cert=${cert} | crl_file_path=${crl_file_path} |

    """
    serial_number = int(cert["tbsCertificate"]["serialNumber"])
    serial_number = int(serial_number)

    if crl_url or crl_file_path:
        result = process_single_crl_check(
            serial_number=serial_number, crl_url=crl_url, crl_file_path=crl_file_path, timeout=int(timeout)
        )

    else:
        result = None
        crl_urls = _extract_crl_urls_from_cert_pyasn1(cert)
        for url in crl_urls:
            result = process_single_crl_check(serial_number=serial_number, crl_url=url, timeout=int(timeout))
            if result:
                break

    if result:
        raise CertRevoked("Certificate is revoked.")

    if result is None and not allow_no_crl_urls:
        raise ValueError("No CRL URLs found in the certificate.")


@keyword(name="Validate If Certificate Is Revoked")
def validate_if_certificate_is_revoked(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    ocsp_url: Optional[str] = None,
    crl_url: Optional[str] = None,
    crl_file_path: Optional[str] = None,
    ocsp_timeout: Union[str, int] = 20,
    crl_timeout: Union[str, int] = 20,
    allow_request_failure: bool = False,
    allow_ocsp_unknown: bool = False,
    allow_no_crl_urls: bool = False,
    expected_to_be_revoked: bool = False,
) -> None:
    """Validate if a certificate is revoked via OCSP and CRL checks.

    Steps:
    ------
      1. First checks if the certificate is revoked via OCSP.
      2. Perform a CRL check (either with given 'crl_url', 'crl_file_path',
         or from the cert's CRL Distribution Points). If revoked => raise.
      3. If we finish both checks without raising, we conclude the certificate
         is not revoked.

    Arguments:
    ---------
       - `cert`: The certificate to check.
       - `ca_cert`: The issuer certificate. Required for the OCSP check.
       - `ocsp_url`: Explicit OCSP URL (overrides the AIA extension). Defaults to `None`.
       - `crl_url`: Explicit CRL URL (overrides CRL distribution points). Defaults to `None`.
       - `crl_file_path`: CRL file path. Defaults to `None`.
       - `ocsp_timeout`: Timeout for the OCSP request. Defaults to `20` seconds.
       - `crl_timeout`: Timeout for fetching CRL over HTTP(s). Defaults to `20` seconds.
       - `allow_request_failure`: Passed to the OCSP request function to allow or
              disallow request failures.
       - `allow_ocsp_unknown`: Whether to allow OCSP 'unknown' status as non-revoked.
       - `allow_no_crl_urls`: Whether to allow no CRL URLs to be found in the certificate.
       - `expected_to_be_revoked`: Whether the certificate is expected to be revoked.

    Raises:
    ------
        - `ValueError`: If the the ocsp request fails.
        - `ValueError`: If `ca_cert` is not provided and `ocsp_url` is given.
        - `CertRevoked`: If the certificate is revoked.
        - `IOError`: If there's an issue loading or parsing the CRL or OCSP data.
        - `ValueError`: If the OCSP request fails.
        - `ValueError`: If the certificate does not contain any CRL URLs and non was provided.


    Examples:
    --------
    | Validate If Certificate Is Revoked | cert=${cert} | issuer=${issuer} |
    | Validate If Certificate Is Revoked | cert=${cert} | issuer=${issuer} | ocsp_url=${ocsp_url} |
    | Validate If Certificate Is Revoked | cert=${cert} | crl_url=${crl_url} |

    """
    if ca_cert is None and ocsp_url is not None:
        raise ValueError("OCSP URL provided, but no issuer certificate provided. OCSP check cannot be performed.")

    try:
        if ca_cert:
            try:
                check_ocsp_response_for_cert(
                    cert=cert,
                    issuer=ca_cert,
                    ocsp_url=ocsp_url,
                    timeout=ocsp_timeout,
                    expected_status="good",
                    allow_request_failure=allow_request_failure,
                    allow_unknown_status=allow_ocsp_unknown,
                )
            except ValueError as err:
                if "`revoked`" in str(err) or "`unknown`" in str(err):
                    raise CertRevoked("Certificate is revoked (by OCSP check).") from err
                raise

        else:
            logging.debug("No issuer provided; skipping OCSP check and going directly to CRL check.")

        # 2. Check CRL
        check_if_cert_is_revoked_crl(
            cert=cert,
            crl_url=crl_url,
            crl_file_path=crl_file_path,
            timeout=crl_timeout,
            allow_no_crl_urls=allow_no_crl_urls,
        )

        # 3. If we reach this point, neither the OCSP check nor the CRL check
        #    confirmed revocation => conclude "not revoked."
        logging.debug("Certificate does not appear to be revoked by OCSP or CRL.")
    except CertRevoked as err:
        if expected_to_be_revoked:
            logging.debug("Certificate is revoked as expected.")
            return
        raise err

    if expected_to_be_revoked:
        raise ValueError("Certificate is not revoked as expected.")


@keyword(name="Validate Migration Alg ID")
def validate_migration_alg_id(  # noqa: D417 Missing argument descriptions in the docstring
    alg_id: rfc9480.AlgorithmIdentifier,
) -> None:
    """Validate a post-quantum or hybrid algorithm identifier.

    Arguments:
    ---------
        - `alg_id`: The `AlgorithmIdentifier` to validate.

    Raises:
    ------
        - `ValueError`: If the `parameters` field is not absent.

    Examples:
    --------
    | Validate Migration Alg ID | ${alg_id} |

    """
    if alg_id["algorithm"] not in PQ_OID_2_NAME:
        if alg_id["parameters"].isValue:
            alg_name = PQ_OID_2_NAME.get(alg_id["algorithm"])
            alg_name = alg_name or PQ_OID_2_NAME.get(str(alg_id["algorithm"]))
            raise ValueError(
                f"The Post-Quantum algorithm identifier {alg_name} does not `allow` the parameters"
                f" field to be set: {alg_id['parameters']}"
            )

    elif alg_id["algorithm"] in HYBRID_OID_2_NAME:
        if alg_id["parameters"].isValue:
            alg_name = HYBRID_OID_2_NAME.get(alg_id["algorithm"])
            alg_name = alg_name or HYBRID_OID_2_NAME.get(str(alg_id["algorithm"]))
            raise ValueError(
                f"The Hybrid algorithm identifier {alg_name} does not `allow` the parameters"
                f" field to be set: {alg_id['parameters']}"
            )
    else:
        raise UnknownOID(oid=alg_id["algorithm"])


@keyword(name="Validate Migration Certificate KeyUsage")
def validate_migration_certificate_key_usage(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate,
) -> None:
    """Validate the key usage of a certificate with a PQ public key.

    Arguments:
    ---------
        - `cert`: The certificate to validate.

    Raises:
    ------
        - `ValueError`: If the key is a KEM or Hybrid-KEM -key and the key usage is not `keyEncipherment`.
        - `ValueError`: If the key is a PQ signature key and the key usage is not `digitalSignature`.

    Examples:
    --------
    | Validate Migration Certificate Key Usage | ${cert} |


    """
    public_key: PQPublicKey = load_public_key_from_cert(cert)  # type: ignore
    key_usage = certextractutils.get_field_from_certificate(cert, extension="key_usage")

    if key_usage is None:
        logging.info("Key usage extension was not present in the parsed certificate.")
        return

    key_usage = asn1utils.get_set_bitstring_names(key_usage).split(", ")  # type: ignore

    sig_usages = {"digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"}

    if isinstance(public_key, (PQSignaturePublicKey, CompositeSigPublicKey)):
        ml_dsa_disallowed = {"keyEncipherment", "dataEncipherment", "keyAgreement", "encipherOnly", "decipherOnly"}

        if not set(key_usage).issubset(sig_usages):
            raise ValueError(f"The post-quantum {public_key.name} keyUsage must be one of: {sig_usages}")
        if set(key_usage) & ml_dsa_disallowed:
            raise ValueError(f"ML-DSA keyUsage must not include: {ml_dsa_disallowed}")

    if is_kem_public_key(public_key):
        ml_kem_allowed = {"keyEncipherment"}
        if set(key_usage) != ml_kem_allowed:
            raise ValueError(f"ML-KEM keyUsage must only contain: {ml_kem_allowed}.But got {key_usage}")

    else:
        raise ValueError(f"Unsupported public key type: {type(public_key)}")


def _validate_oid_in_cert_stfl(
    alg_name: str,
    cert: rfc9480.CMPCertificate,
) -> None:
    """Validate the OID of the public key in the certificate."""
    loaded_public_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if not isinstance(loaded_public_key, PQHashStatefulSigPublicKey):
        raise ValueError(
            f"The public key in the certificate is not a Stateful Hash Signature key. Got: {type(loaded_public_key)}."
        )

    if alg_name != loaded_public_key.name:
        raise ValueError(
            "The public key algorithm name does not match the expected name."
            f"Expected: {alg_name}, Got: {loaded_public_key.name}"
        )


@keyword(name="Validate Migration OID In Certificate")
def validate_migration_oid_in_certificate(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate, alg_name: str
) -> None:
    """Validate the OID of the public key in the certificate.

    Arguments:
    ---------
        - `cert`: The certificate to validate.
        - `name`: The name of the public key algorithm.

    Raises:
    ------
        - `ValueError`: If the OID does not match the name.
        - `UnknownOID`: If the OID is unknown.
        - `ValueError`: If the name is not supported.

    Examples:
    --------
    | Validate Migration OID In Certificate | ${cert} | ml-dsa-65 |

    """
    pub_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]

    name_oid = PQ_NAME_2_OID.get(alg_name) or HYBRID_NAME_2_OID.get(alg_name)

    if alg_name.startswith("xmss") or alg_name.startswith("xmssmt") or alg_name.startswith("hss"):
        _validate_oid_in_cert_stfl(alg_name, cert)
        return

    if name_oid is None:
        raise ValueError(
            f"The name {alg_name} is not supported."
            f" Supported names are: {list(PQ_NAME_2_OID.keys()) + list(HYBRID_NAME_2_OID.keys())}"
        )

    if PQ_NAME_2_OID.get(alg_name) is not None:
        if str(pub_oid) != str(PQ_NAME_2_OID[alg_name]):
            _add = may_return_oid_to_name(pub_oid)
            if "." not in _add:
                _add = f" ({_add})"
            else:
                _add = ""
            raise ValueError(f"The OID {pub_oid}{_add} does not match the name {alg_name}.")

    elif HYBRID_NAME_2_OID.get(alg_name) is not None:
        if str(pub_oid) != str(HYBRID_NAME_2_OID[alg_name]):
            _add = may_return_oid_to_name(pub_oid)
            if "." not in _add:
                _add = f" ({_add})"
            else:
                _add = ""
            raise ValueError(f"The OID {pub_oid}{_add} does not match the name {alg_name}.")
    else:
        raise UnknownOID(pub_oid)


@keyword(name="Verify CSR Signature")
def verify_csr_signature(  # noqa: D417 Missing argument descriptions in the docstring
    csr: rfc6402.CertificationRequest,
) -> None:
    """Verify a certification request (CSR) signature using the appropriate algorithm.

    Arguments:
    ---------
        - `csr`: The certification request (`CertificationRequest`) to be verified.

    Raises:
    ------
        - `ValueError`: If the algorithm OID in the CSR is unsupported or invalid.
        - `BadPOP`: If the signature verification fails.
        - `ValueError`: If the public key type is unsupported.

    Examples:
    --------
    | Verify CSR Signature | ${csr} |

    """
    spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]

    public_key = keyutils.load_public_key_from_spki(spki)
    verify_key = ensure_is_verify_key(public_key)

    signature = csr["signature"].asOctets()
    alg_id = csr["signatureAlgorithm"]
    data = encoder.encode(csr["certificationRequestInfo"])
    try:
        protectionutils.verify_signature_with_alg_id(
            public_key=verify_key, alg_id=alg_id, signature=signature, data=data
        )
    except InvalidSignature as e:
        raise BadPOP("The signature verification failed.") from e


def _write_temp_cert(cert_to_write: rfc9480.CMPCertificate) -> str:
    """Write a certificate object to a temporary PEM file.

    :param cert_to_write: The certificate object to write.
    :return: The path to the temporary PEM file.
    """
    der_data = encoder.encode(cert_to_write)
    cert_obj = x509.load_der_x509_certificate(der_data)

    with tempfile.NamedTemporaryFile(delete=False, mode="wb", suffix=".pem") as tmp_file:
        tmp_file.write(cert_obj.public_bytes(encoding=Encoding.PEM))
        return tmp_file.name


@keyword(name="Validate OCSP Status OpenSSL")
def validate_ocsp_status_openssl(  # noqa: D417 undocumented-param
    cert: Union[str, rfc9480.CMPCertificate],
    ca_cert: Union[str, rfc9480.CMPCertificate],
    ocsp_url: Optional[str] = None,
    expected_status: str = "good",
    unknown_is_success: bool = False,
    *,
    use_nonce: bool = True,
) -> None:
    """Check the OCSP status of a certificate with OpenSSL.

    Arguments:
    ---------
        - `cert`: The certificate to check. Can be a file path or a certificate object.
        - `ca_cert`: The issuer certificate. Can be a file path or a certificate object.
        - `ocsp_url`: The OCSP URL. If not provided, it will be extracted from the certificate.
        - `expected_status`: The expected OCSP status. Can be "good", "revoked", or "unknown".
        - `unknown_is_success`: If True, treat "unknown" status as a success. Defaults to `False`.
        - `use_nonce`: If True, include a nonce in the OCSP request. Defaults to `True`.

    Raises:
    ------
        - `ValueError`: If the OCSP status does not match the expected status or no OCSP URL is found.
        - `CertRevoked`: If the certificate is revoked and not expected to be revoked.

    Examples:
    --------
    | Validate OCSP Status OpenSSL | ${cert} | ${issuer} | expected_status=revoked |
    | Validate OCSP Status OpenSSL | ${cert_path} | ${issuer_path} | ${ocsp_url} |

    """
    temp_files = []

    # Determine if inputs are file paths or certificate objects
    if isinstance(cert, str):
        cert_path = cert
        der_data = utils.load_and_decode_pem_file(cert_path)
        cert_obj = parse_certificate(der_data)
    else:
        cert_obj = cert
        cert_path = _write_temp_cert(cert)
        temp_files.append(cert_path)

    if isinstance(ca_cert, str):
        issuer_path = ca_cert
    else:
        issuer_path = _write_temp_cert(ca_cert)
        temp_files.append(issuer_path)

    ocsp_urls = ocsp_url or get_ocsp_url_from_cert(cert_obj)

    if not ocsp_urls:
        raise ValueError("No OCSP URL found in the certificate.")

    if isinstance(ocsp_urls, list):
        ocsp_url = ocsp_urls[0]

    cmds = [
        "openssl",
        "ocsp",
        "-issuer",
        issuer_path,
        "-cert",
        cert_path,
        "-url",
        ocsp_url,
        "-CAfile",
        issuer_path,
        "-resp_text",
    ]

    if use_nonce:
        cmds.extend(["-nonce"])

    result = subprocess.run(
        cmds,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logging.error("OCSP check failed.", exc_info=True)
        raise ValueError(f"OCSP check failed (stdout): {result.stdout}")

    logging.info("OCSP check succeeded.\n: %s", result.stdout)
    logging.debug(result.stdout)
    if "Cert Status: revoked" in result.stdout:
        status = "revoked"
    elif "Cert Status: good" in result.stdout:
        status = "good"
    else:
        status = "unknown"

    for file_path in temp_files:
        try:
            os.remove(file_path)
        except OSError:
            logging.error("Error deleting temporary file %s: ", file_path, exc_info=True)

    if expected_status == status:
        return

    if "unknown" == status and unknown_is_success:
        return

    if status == "revoked":
        raise CertRevoked("Certificate is revoked.")

    if status == "good":
        raise ValueError("Certificate is good, but expected revoked status.")

    if status == "unknown":
        raise ValueError(f"Certificate status is unknown, but expected the `{expected_status}` status.")


@not_keyword
def is_ca_cert(cert: rfc9480.CMPCertificate) -> Optional[bool]:
    """Check if the provided certificate is a CA certificate.

    :param cert: The certificate to check.
    :return: `None` if the certificate is not a CA certificate, `True` if it is a CA certificate, or `False`.
    :raises BadAsn1Data: If the BasicConstraints extension is malformed.
    """
    extn = certextractutils.get_extension(
        cert["tbsCertificate"]["extensions"],
        rfc5280.id_ce_basicConstraints,
    )
    if extn is None:
        return None

    basic_constraints, rest = asn1utils.try_decode_pyasn1(  # type: ignore
        extn["extnValue"],
        rfc5280.BasicConstraints(),
    )
    basic_constraints: rfc5280.BasicConstraints
    if rest:
        raise BadAsn1Data("BasicConstraints")

    return basic_constraints["cA"].isValue


def _validate_key_identifiers(
    cross_cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
) -> None:
    """Validate the key identifiers of the cross-signed certificate and the issuer certificate.

    :param cross_cert: The cross-signed certificate to validate.
    :param issuer_cert: The CA Issuer certificate.
    :raises ValueError: If the SKI or AKI are not present, or if they do not match as expected.
    """
    ski_cert = certextractutils.get_field_from_certificate(cross_cert, extension="ski")  # type: ignore
    ski_cert: Optional[bytes]
    ski_issuer_cert = certextractutils.get_field_from_certificate(issuer_cert, extension="ski")  # type: ignore
    ski_issuer_cert: Optional[bytes]
    aki_cert = certextractutils.get_field_from_certificate(cross_cert, extension="aki")  # type: ignore
    aki_cert: rfc5280.AuthorityKeyIdentifier

    if ski_cert is None or ski_issuer_cert is None:
        raise ValueError("The cross-signed certificate or the issuer certificate does not have a SKI.")

    if ski_cert == ski_issuer_cert:
        raise ValueError("The cross-signed certificate has the same SKI as the issuer certificate.")

    if ski_issuer_cert == aki_cert:
        raise ValueError("The SKI of the issuer certificate does not match the AKI of the cross-signed certificate.")


def _validate_cross_signed_cert(
    cross_cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
) -> None:
    """Validate the values of the cross-signed certificate against the issuer certificate.

    :param cross_cert: The cross-signed certificate to validate.
    :param issuer_cert: The CA Issuer certificate.
    :raises ValueError: If the cross-signed certificate is not a CA certificate, or if it has the same Subject
                        and Issuer as the issuer certificate or the SKI and AKI do not match as expected.

    """
    out = is_ca_cert(cross_cert)
    if out is None:
        raise ValueError("The cross-signed certificate does not have a BasicConstraints extension.")

    if not out:
        raise ValueError("The cross-signed certificate is not a CA certificate.")

    out = is_ca_cert(issuer_cert)
    if out is None:
        raise ValueError("The issuer certificate does not have a BasicConstraints extension.")

    if not out:
        raise ValueError("The issuer certificate is not a CA certificate.")

    if compareutils.compare_pyasn1_names(
        cross_cert["tbsCertificate"]["subject"], cross_cert["tbsCertificate"]["issuer"]
    ):
        raise ValueError("The cross-signed certificate has the same Subject and Issuer.")

    if compareutils.compare_pyasn1_names(
        cross_cert["tbsCertificate"]["subject"], issuer_cert["tbsCertificate"]["subject"]
    ):
        cert_name = utils.get_openssl_name_notation(cross_cert["tbsCertificate"]["subject"])
        raise ValueError(f"The Subject of the certificate matches the Subject of the issuer certificate: {cert_name}")

    _validate_key_identifiers(cross_cert=cross_cert, issuer_cert=issuer_cert)

    issuer_key = load_public_key_from_cert(issuer_cert)
    issuer_key = ensure_is_verify_key(issuer_key)

    verify_cert_signature(
        cert=cross_cert,
        issuer_pub_key=issuer_key,
    )


@keyword(name="Validate CA Cross-Signed Certificate")
def validate_ca_cross_signed_cert(  # noqa: D417 undocumented-param
    cross_cert: rfc9480.CMPCertificate, template: rfc9480.CertTemplate, ca_cert: rfc9480.CMPCertificate
) -> None:
    """Validate the newly issued cross-signed CA certificate against the template and the CA Issuer certificate.

    Note:
    ----
      - excludes the signature algorithm check from the template.

    Arguments:
    ---------
       - `cross_cert`: The cross-signed certificate to validate.
       - `template`: The certificate template used for the cross-signed certificate.
       - `ca_cert`: The CA Issuer certificate.

    Raises:
    ------
        - `ValueError`: If the cross-signed certificate does not match the template, or if it is not a valid
          cross-signed certificate.
        - `ValueError`: If the cross-signed certificate is not a CA certificate.
        - `ValueError`: If the cross-signed certificate has the same Subject and Issuer as the issuer certificate,
          or if it has the same public key as the issuer certificate, or if the BasicConstraints extension is missing.

    Examples:
    --------
    | Validate CA Cross-Signed Certificate | cross_cert=${cross_cert} | ${cert_template} | ${ca_cert} |

    """
    _validate_cross_signed_cert(cross_cert=cross_cert, issuer_cert=ca_cert)

    if not compareutils.compare_cert_template_and_cert(
        cert_template=template,
        issued_cert=cross_cert,
        exclude_fields="extensions,signingAlg,issuer",
    ):
        raise ValueError("The cross-signed certificate does not matches the template.")

    logging.debug("Cross-signed certificate extensions comparison is not supported yet.")
    for oid in template["extensions"]:
        if oid not in cross_cert["tbsCertificate"]["extensions"]:
            name_oid = may_return_oid_to_name(oid)
            raise ValueError(f"The cross-signed certificate does not have the extension {name_oid}.")
