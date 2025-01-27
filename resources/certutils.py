# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Validate X509 certificates by invoking other software, e.g., OpenSSL, pkilint."""

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Union

import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from pkilint import loader, report
from pkilint.pkix import certificate, extension, name
from pkilint.validation import ValidationFindingSeverity
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc9480
from robot.api.deco import keyword, not_keyword

import resources.certextractutils
from resources import (
    asn1utils,
    cmputils,
    compareutils,
    convertutils,
    cryptoutils,
    keyutils,
    oid_mapping,
    typingutils,
    utils,
)
from resources.oid_mapping import get_hash_from_oid
from resources.oidutils import CMP_EKU_OID_2_NAME
from resources.suiteenums import KeyUsageStrictness

# for these to integrate smoothly into RF, they have to raise exceptions in case of failure, rather than
# return False


def parse_certificate(data: bytes) -> rfc9480.CMPCertificate:
    """Parse a DER-encoded X509 certificate into a pyasn1 object.

    :param data: DER-encoded X509 certificate.
    :returns: The decoded certificate object.
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
        data = convertutils.copy_asn1_certificate(data)
        data = encoder.encode(data)

    try:
        _certificate = x509.load_der_x509_certificate(data)
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
def verify_cert_signature(cert: rfc9480.CMPCertificate, issuer_pub_key: Optional[typingutils.PublicKeySig] = None):
    """Verify the signature of an X.509 certificate.

    Uses the issuer's public key, or the certificate's own public key if it is self-signed.

    :param cert: The certificate object, which is verified.
    :param issuer_pub_key: Optional PublicKeySig used for verification.
    :raises InvalidSignature: If the certificate's signature is not valid.
    """
    cert_hash_alg = oid_mapping.get_hash_from_oid(cert["signatureAlgorithm"]["algorithm"], only_hash=True)
    tbs_der = encoder.encode(cert["tbsCertificate"])
    pub_key = issuer_pub_key or load_public_key_from_cert(cert)

    cryptoutils.verify_signature(
        public_key=pub_key,
        signature=cert["signature"].asOctets(),
        data=tbs_der,
        hash_alg=cert_hash_alg,
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
         - `path`: path or directory to load the certificates from. Default is "./data/trustanchors".
         - `allow_os_store`: whether to allow the truststore of the Operating System or not.
            Default is False.

    Returns:
    -------
        - A list of `pyasn1` certificates, which are trustanchors.

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


# TODO maybe change to RF


@not_keyword
def load_public_key_from_cert(asn1cert: rfc9480.CMPCertificate) -> typingutils.PublicKey:
    """Load a public key from a `CMPCertificate`.

    Supposed to be used to load either a pq Key or `cryptography` key.

    :param asn1cert: The certificate to load the public key from.
    :return: The public key object.
    """
    public_key = keyutils.load_public_key_from_spki(asn1cert["tbsCertificate"]["subjectPublicKeyInfo"])
    return public_key


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
        tbs_der = encoder.encode(cert["tbsCertificate"])
        cryptoutils.verify_signature(
            public_key=public_key, data=tbs_der, signature=cert["signature"].asOctets(), hash_alg=hash_alg
        )
        return True
    except (ValueError, InvalidSignature) as err:
        logging.info("%s", err)
    return False


@keyword(name="Build CMP Chain From PKIMessage")
def build_cmp_chain_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
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

    return build_chain_from_list(ee_cert, cert_list, must_be_self_signed=last_cert_is_self_signed)


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

    cert_eku_obj = resources.certextractutils.get_field_from_certificate(cert=cert, extension="eku")  # ignore: type
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
        expected_usage = rfc5280.KeyUsage(expected_usage)
        expected_names = asn1utils.get_set_bitstring_names(expected_usage)
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
         `strictness` is set to `STRICT` or `ABS_STRICT`, or if the actual `KeyUsage` does not match the \
         expected `key_usages`.


    Examples:
    --------
    | Validate KeyUsage | cert=${cert} | key_usages=digitalSignature, keyEncipherment | strictness=2 |
    | Validate KeyUsage | cert=${cert} | key_usages=digitalSignature | strictness=LAX |

    """
    val_strict = KeyUsageStrictness.get(strictness)

    if val_strict == KeyUsageStrictness.NONE:
        logging.info("KeyUsage Check is disabled!")
        return

    usage = resources.certextractutils.get_field_from_certificate(cert=cert, extension="key_usage")  # ignore: type

    if usage is None:
        if val_strict in [KeyUsageStrictness.ABS_STRICT, KeyUsageStrictness.STRICT]:
            raise ValueError(f"KeyUsage extension was not present in: {cert.prettyPrint()}")
        logging.info("KeyUsage extension was not present")
    else:
        same = False
        if val_strict == KeyUsageStrictness.ABS_STRICT:
            same = True

        if not _validate_key_usage(expected_usage=key_usages, given_usage=usage, same_vals=same):  # type: ignore
            names = asn1utils.get_set_bitstring_names(usage)  # type: ignore
            raise ValueError(f"KeyUsage Extension was expected to be: {key_usages}, but is {names}")


def _cert_chain_to_file(cert_chain: List[rfc9480.CMPCertificate], path: str):
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
    _cert_chain_to_file(cert_chain[1:-1], ca_path)

    ee_path = os.path.join(dir_fpath, "ee.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[0], ee_path)

    command = ["-CAfile", anchor, "-untrusted", ca_path, ee_path]

    return command


def _verify_certificate_chain(command: list[str], cert_chain: List[rfc9480.CMPCertificate], timeout: int = 60) -> None:
    """Verify a certificate chain using OpenSSL commands.

    :param command: List of OpenSSL command line arguments to append for verification.
    :param cert_chain: List of `rfc9480.CMPCertificate` objects representing the certificate chain.
                       The chain order should start with the end-entity certificate and end with the root certificate.
    :param timeout: Maximum time in seconds for the OpenSSL verification command to run. Defaults to 60 seconds.

    :raises ValueError: If `cert_chain` is empty, or OpenSSL returns a non-zero exit code,
    indicating a validation failure.
    :raises subprocess.TimeoutExpired: If the verification process exceeds the specified timeout.

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
        result = subprocess.run(command, capture_output=True, check=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise ValueError(f"Validation of the certificate failed! stdout:{result.stdout}\nerror: {result.stderr}")
        return
    except subprocess.TimeoutExpired:
        logging.warning("Reached time out of for certificate validation. Seconds: %d", timeout)
    except Exception as err:
        logging.warning(err)
    finally:
        shutil.rmtree(dir_fpath)

    raise ValueError("Validation of the certificate failed!")


@keyword(name="Verify Cert Chain OpenSSL")
def verify_cert_chain_openssl(  # noqa D417 undocumented-param
    cert_chain: List[rfc9480.CMPCertificate],
    crl_check: bool = False,
    verbose: bool = True,
    timeout: typingutils.Strint = 60,
):
    """Verify a certificate chain using OpenSSL.

    The certificate chain has to start from the end-entity certificate and ends with the Root certificate.

    Arguments:
    ---------
        - `cert_chain`: A list of untrusted certificate objects to verify against the root certificate.
        - `crl_check`: Whether to perform CRL checks to verify if any certificate was revoked.
        Defaults to `False`.
        - `verbose`: Whether to use the verbose output flag for the OpenSSL `verify` command.
        Defaults to `True`.
        - `timeout`: The timeout of the verify command in seconds. Defaults to `60`.

    Raises:
    ------
        - `ValueError`: If the certificate validation fails, according to the OpenSSL `verify` command.
        - `TimeoutExpired`: If the verification took to long.

    Examples:
    --------
    | Verify Cert Chain OpenSSL | root_cert=${root_cert} | untrusted=${untrusted} | crl_check=True | verbose=False |
    | Verify Cert Chain OpenSSL | root_cert=${root_cert} | untrusted=${untrusted} | crl_check=False | verbose=True |
    | Verify Cert Chain OpenSSL | untrusted=${untrusted} | crl_check=False | verbose=True |

    """
    if verbose:
        utils.log_certificates(certs=cert_chain, msg_suffix="Untrusted Certificates:\n")

    temp_dir = "./data/tmp_cert_check"
    if not os.path.isdir("./data/tmp_cert_check"):
        os.mkdir(temp_dir)

    if not crl_check:
        logging.warning("Please Note the CRL check is deactivate!")

    command = ["openssl", "verify"]
    if crl_check:
        command.append("-crl_check")
    else:
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
        - `allow_os_store`: Whether to allow the default OS store to be added to the trustanchors. Default is `True`.
        - `verbose`: Whether to log all non-trustanchor certificates. Default is `True`.
        - `allow_os_store`: Whether to allow the default OS store to be added to the trustanchors. Default is `True`.

    Raises:
    ------
        - `ValueError`: If the certificates are not allowed/known trustanchors.

    """
    anchors = load_truststore(path=trustanchors, allow_os_store=allow_os_store)

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

        raise ValueError("Certificates are not trust anchors!")


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
        Default is `True`.
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
        - `ValueError`: If the last certificate inside the certificate chain is not trusted.
        - `ValueError`: If the certificate chain validation fails.
        - `ValueError`: If key usage validation fails on the EE certificate.

    Examples:
    --------
    | Certificates Must Be Trusted | cert_chain=${cert_chain} | /path/to/anchors |
    | Certificates Must Be Trusted | cert_chain=${cert_chain} | allow_os_store=False |

    """
    anchors: List[rfc9480.CMPCertificate] = []

    if trustanchors is not None:
        anchors = load_truststore(path=trustanchors, allow_os_store=allow_os_store)

    trusted = cert_chain[-1] in anchors

    if not trusted:
        subject_name = utils.get_openssl_name_notation(cert_chain[-1]["tbsCertificate"]["subject"])
        raise ValueError(f"Subject={subject_name} is not a trust anchor!\nCertificate:\n{cert_chain[-1].prettyPrint()}")

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
    cryptoutils.verify_signature(
        public_key=pub_key,
        signature=signature,
        data=data,
        hash_alg=hash_alg,
    )


def load_crl_from_der(der_data: bytes):
    """
    Load and parse a CRL from DER-encoded data using pyasn1-alt-modules.

    :param der_data: DER-encoded CRL data.
    :return: Decoded CRL object.
    :raises ValueError: If the CRL cannot be decoded.
    """
    try:
        crl, _ = decoder.decode(der_data, asn1Spec=rfc5280.CertificateList())
        return crl
    except Exception as e:
        raise ValueError(f"Failed to load CRL from DER data: {e}")


def _write_crl_to_pem(crl: rfc5280.CertificateList, path: str):
    with open(path, "wb") as crl_file:
        crl_file.write(encoder.encode(crl))


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

    _cert_chain_to_file(tmp, anchor)
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


def find_crl_signer_cert(
    crl: rfc5280.CertificateList,
    ca_cert_dir: str = "data/cert_logs",
    certs: Optional[List[rfc9480.CMPCertificate]] = None,
) -> rfc9480.CMPCertificate:
    """Find the certificate that signed the CRL.

    :param crl: The CRL to verify.
    :param ca_cert_dir: The directory containing the CA certificates. Defaults to "data/cert_logs".
    :param certs: A list of CA certificates to search through. If provided, will use this list
    instead of loading from the directory.
    :return: The certificate that signed the CRL.
    :raises ValueError: If no matching certificate is found.
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


def build_crl_chain_from_list(crl: rfc5280.CertificateList, certs: List[rfc9480.CMPCertificate]) -> List:
    """Build a CRL chain from a list of certificates and verify the CRL's signature.

    :param crl: Parsed CRL object in pyasn1 format.
    :param certs: List of parsed certificates in pyasn1 format.
    :return: The chain starting with the CRL and ending with the root certificate.
    :raises ValueError: If the CRL was not issued by one of the provided certificates.
    """
    signer = find_crl_signer_cert(crl, certs=certs)

    chain = build_chain_from_list(signer, certs)
    return [crl] + chain
