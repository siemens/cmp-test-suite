# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility for checking values of `PKIHeader` and `PKIBody` structures.

This module includes functions to validate `PKIHeader` values, ensuring the correct bit size is set as specified by
RFC 9483 standards. It also contains functionality to verify that CA message responses contain the newly issued
certificate with the correct chain. Additionally, it checks for the presence and absence of specific fields,
such as `caPubs`, based on the response body requirements.
"""

import copy
import datetime
import logging
from typing import Dict, List, Optional, Tuple, Type, Union

import pyasn1.error
from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, useful
from pyasn1_alt_modules import rfc5280, rfc6664, rfc9480, rfc9481
from pyasn1_alt_modules.rfc2437 import rsaEncryption
from robot.api.deco import keyword, not_keyword

from resources import (
    asn1utils,
    certextractutils,
    certutils,
    cmputils,
    compareutils,
    convertutils,
    protectionutils,
    utils,
)
from resources.asn1_structures import CertProfileValueAsn1, PKIMessageTMP
from resources.exceptions import (
    BadAlg,
    BadAsn1Data,
    BadDataFormat,
    BadMessageCheck,
    BadRecipientNonce,
    BadRequest,
    BadSenderNonce,
    BadTime,
    CMPTestSuiteError,
)
from resources.oid_mapping import (
    get_hash_from_oid,
)
from resources.oidutils import (
    ECDSA_SHA_OID_2_NAME,
    MSG_SIG_ALG,
    RSA_SHA_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    id_KemBasedMac,
)
from resources.suiteenums import ProtectedType
from resources.typingutils import Strint


def check_if_response_contains_private_key(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    key_index: Strint = 0,
) -> bool:
    """Check if the `privateKey` field in the PKIMessage is present.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure to check.
        - `key_index`: Index of the response within the PKIMessage body, to check. Defaults to `0`.

    Returns:
    -------
        - True if the `privateKey` field is present; False otherwise.

    Examples:
    --------
    | ${is_present} | Check If Response Contains Private Key | ${pki_message} |

    """
    der_data = encoder.encode(pki_message)
    der_data2 = copy.deepcopy(der_data)
    comp_message = decoder.decode(der_data2, asn1Spec=PKIMessageTMP())[0]

    cert_response = cmputils.get_cert_response_from_pkimessage(comp_message, response_index=key_index)

    if not cert_response["certifiedKeyPair"].isValue:
        return False

    return cert_response["certifiedKeyPair"]["privateKey"].isValue


def check_if_response_contains_encrypted_cert(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    cert_index: Strint = 0,
) -> bool:
    """Check if the `certOrEncCert` field in the PKIMessage is present and contains an encrypted certificate.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure to check.
        - `cert_index`: Index of the response within the PKIMessage body, to check. Defaults to `0`.

    Returns:
    -------
        - True if the `certOrEncCert` field is present and contains an encrypted certificate; False otherwise.

    Examples:
    --------
    | ${is_present} | Check If Response Contains Encrypted Cert | ${pki_message} |

    """
    der_data = encoder.encode(pki_message)
    der_data2 = copy.deepcopy(der_data)
    comp_message = decoder.decode(der_data2, asn1Spec=PKIMessageTMP())[0]

    cert_response = cmputils.get_cert_response_from_pkimessage(comp_message, response_index=cert_index)
    if not cert_response["certifiedKeyPair"].isValue:
        return False
    if not cert_response["certifiedKeyPair"]["certOrEncCert"].isValue:
        return False

    # MUST be checked this way.
    return cert_response["certifiedKeyPair"]["certOrEncCert"].getName() == "encryptedCert"


@keyword(name="Validate certifiedKeyPair Structure")
def validate_certified_key_pair_structure(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, local_key_gen: bool = True, response_index: Strint = 0
):
    """Check the version field in the PKIMessage when the `certifiedKeyPair` and `EnvelopedData` structures are used.

    Verifies that the version (`pvno`) field in the PKIMessage header is correctly set to version 3 if
    `certifiedKeyPair` and `EnvelopedData` structures are present in the response. And if the `privateKey` is present
     or absent based on the `local_key_gen` parameter.

    Arguments:
    ---------
        - `pki_message` The PKIMessage structure to validate.
        - `local_key_gen`: Indicates whether the private key was generated locally or centrally. Defaults to `True`
        - `response_index`: Index of the response within the PKIMessage body, to check. Defaults to `0`.

    Raises:
    ------
        - `ValueError`: If the message type is not "ip", "cp", or "kup".
        - `ValueError`: If the `privateKey` field has a value but the key was locally generated.
        - `ValueError`: If the `privateKey` field is missing in case of remote generation.
        - `ValueError`: If the version is not set to 3 when the `EnvelopedData` structure is used \
        in cases of central key generation.

    Examples:
    --------
    | Validate certifiedKeyPair | ${pki_message} | local_key_gen=True | response_index=1 |
    | Validate certifiedKeyPair | ${pki_message} | local_key_gen=False |

    """
    version = int(pki_message["header"]["pvno"])
    cert_response = cmputils.get_cert_response_from_pkimessage(pki_message, response_index=response_index)
    cert_key_pair = cert_response["certifiedKeyPair"]

    is_value = cert_key_pair["privateKey"].isValue
    if local_key_gen and is_value:
        raise ValueError("The `privateKey` MUST be absent")

    if not local_key_gen and not is_value:
        raise ValueError("The `privateKey` MUST be present")

    if not local_key_gen:
        if cert_key_pair["privateKey"].isValue:
            if cert_key_pair["privateKey"].getName() == "envelopedData":
                if version != 3:
                    raise ValueError(
                        f"The `EnvelopedData` data structure is used, but version != 3. Got Version: {version}"
                    )
            else:
                logging.info("Supposed to use the `EnvelopedData` data structure, for `privateKey`")

    if cert_key_pair["certOrEncCert"]["encryptedCert"].isValue:
        if cert_key_pair["certOrEncCert"]["encryptedCert"].getName() == "envelopedData":
            if version != 3:
                raise ValueError(
                    f"The `EnvelopedData` data structure is used, but version != 3. Got Version: {version}"
                )
        else:
            logging.info("Supposed to use the `EnvelopedData` data structure, for `encryptedCert`")


@keyword(name="Validate CA Message caPubs Field")
def validate_ca_msg_ca_pubs_field(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    trustanchors: str = "data/trustanchors",
    verbose: bool = True,
    response_index: Strint = 0,
    allow_os_store: bool = True,
    used_p10cr: bool = True,
    crl_check: bool = False,
    used_ir_as_cr: bool = False,
):
    """Check the presence and validity of the `caPubs` field in the given PKI body.

    Validates the `certifiedKeyPair` and the optional `caPubs` field if present.
    If the `caPubs` field is present, it verifies that the provided CA certificates are trustanchors.
    The trust anchors are loaded from a specified directory or file.

    Arguments:
    ---------
         `pki_message`: The PKIMessage to validate, containing a `certifiedKeyPair` and possibly a `caPubs` field.
        - `trustanchors`: Path to the directory or file containing the trusted root certificates. \
        Defaults to "data/trustanchors".
        - `verbose`: If `True`, logs details about non-trust-anchor certificates and certificate chain validation. \
        Defaults to `True`.
        - `response_index`: Index of the response within the PKIMessage body, to check. Defaults to 0.
        - `allow_os_store`: If `True`, allows the use of OS-provided trust anchors along with custom ones. \
        Defaults to `True`.
        - `used_p10cr`: Specifies whether a `p10cr` request was used.
        - `crl_check`: If `True`, performs CRL checks to confirm that no certificate in the chain has been revoked. \
        Defaults to `False`.
        - `used_ir_as_cr`: If `True`, the `caPubs` field must be absent.

    Raises:
    ------
        - `ValueError`: If the `PKIBody` is not of type "ip", "cp", "kup"
        - `ValueError`: If the `certReqID` is not 0 for "ip", "cp", "kup" and not -1, if p10cr was sent.
        - `ValueError`: If the size of the CertResponses is greater than expected.
        - `ValueError`: If the `EnvelopedData` data structure is used but the header version is not 3.
        - `ValueError`: If the `certifiedKeyPair` is present, but the CA certificates inside caPubs are not \
        trustanchors.
        - `ValueError`: The `caPubs` field is used incorrectly for "cp" or "kup" messages.
        - `ValueError`: A valid certification chain cannot be constructed or is invalid for the certificate in \
        `certifiedKeyPair`.
        - `ValueError`: The status is not allowed. \
        (allowed values: "waiting", "rejection", "accepted", "grantedWithMods")
        - `NotImplementedError`: If the status is "waiting".

    Examples:
    --------
    | Validate CA Message CaPubs Field | ${pki_message} | trustanchors="data/trustanchors" | verbose=True \
    | allow_os_store=True |

    Notes:
    -----
    - If `certifiedKeyPair` is present, the `certificate` must be included, and its presence is mandatory.
    - The `caPubs` field:
        - *MAY* be used if the `certifiedKeyPair` field is present.
        - *MUST* contain only trustanchors (e.g., root certificates) of the certificate included in the
        `certifiedKeyPair`.
        - If present without `certifiedKeyPair`, this is considered invalid.

    """
    pki_body = pki_message["body"]
    body_name = pki_body.getName()
    pki_body = pki_body[body_name]
    certified_key_pair: rfc9480.CertifiedKeyPair = pki_body["response"][response_index]["certifiedKeyPair"]
    # The optional caPubs field may be used if certifiedKeyPair is present
    if certified_key_pair.isValue:
        # certificate REQUIRED
        # -- MUST be present when certifiedKeyPair is present
        # -- MUST contain the newly enrolled X.509 certificate. NOTE: oob! for this Test-Suite
        if not certified_key_pair["certOrEncCert"].isValue:
            raise ValueError("`certOrEncCert` must be present, if `certifiedKeyPair` field is present.")

        asn1cert = cmputils.get_cert_from_pkimessage(pki_message)

        if pki_body["caPubs"].isValue:
            if body_name == "cp" or used_ir_as_cr:
                if not used_p10cr:
                    raise ValueError(
                        'As of Section 4.1.2 change 2: "The caPubs field in the '
                        'certificate response message MUST be absent."'
                    )

            if body_name == "kup":
                raise ValueError('As of Section 4.1.3 change 6: "The caPubs field in the kup message MUST be absent."')

            # rfc 9883 section 4.1.1
            # -- MAY be used if the certifiedKeyPair field is present
            # -- If used, it MUST contain only a trust anchor, e.g., root
            # -- certificate, of the certificate contained in certOrEncCert.
            ca_pubs = list(pki_body["caPubs"])
            certutils.certificates_are_trustanchors(
                certs=ca_pubs, trustanchors=trustanchors, verbose=verbose, allow_os_store=allow_os_store
            )
            if verbose:
                logging.info("Issued Certificate: %s", asn1cert.prettyPrint())

            certs = ca_pubs + list(pki_message["extraCerts"])
            cert_chain = certutils.build_chain_from_list(ee_cert=asn1cert, certs=certs)

            if len(cert_chain) == 1:
                raise ValueError("The PKIMessage did not contain a valid certificate chain")

            certutils.verify_cert_chain_openssl(
                cert_chain=cert_chain,  # type: ignore
                verbose=verbose,
                crl_check=crl_check,
            )
            utils.log_certificates(certs=cert_chain)

    else:
        # MAY be present if certifiedKeyPair is present.
        if pki_body["caPubs"].isValue:
            raise ValueError("'caPubs' field should not be present.")


def check_is_protection_present(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    must_be_protected: bool = False,
    lwcmp: bool = False,
) -> bool:
    """Check if the protection is present and correctly set in the PKIMessage structure.

    Validate whether both the `protectionAlg` and `protection` fields are set in the PKIMessage.
    If either field is missing or inconsistent, it raises an error.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure to check for protection.
        - `must_be_protected`: If `True`, raises an exception if protection is not present. Defaults to `False`.
        - `lwcmp`: A boolean flag to indicate if the lwcmp version is checked. for sig: MSG_SIG_ALG as specified in \
        Section 3 of [RFC9481] (in short: RSASSA-PSS, RSA, ECDSA, Ed25519, Ed448.) for mac: "pbmac1" and \
        "password_based_mac"

    Returns:
    -------
        - True if correctly present; False otherwise.

    Raises:
    ------
        - `BadMessageCheck`: If protection is required but missing.
        - `BadMessageCheck`: If only one of the fields (`protectionAlg` or `protection`) is set,\
         causing an inconsistency.

    Examples:
    --------
    | ${is_present} | Check Is Protection Present | ${pki_message} | must_be_protected=True |
    | ${is_present} | Check Is Protection Present | ${pki_message} |

    """
    if not pki_message["protection"].isValue and not pki_message["header"]["protectionAlg"].isValue:
        # Protection is recommended but not required, according to RFC 9480 section 3.1.
        if must_be_protected:
            raise BadMessageCheck("The `PKIMessage` is not protected!")
        return False

    if pki_message["protection"].isValue and not pki_message["header"]["protectionAlg"].isValue:
        raise BadMessageCheck("The PKIMessage has a protection value but no OID for the protectionAlg field.")

    if not pki_message["protection"].isValue and pki_message["header"]["protectionAlg"].isValue:
        raise BadMessageCheck("The PKIMessage has an OID for the protectionAlg field but no protection value.")

    if lwcmp:
        protectionutils.get_protection_type_from_pkimessage(pki_message, lwcmp)

    return True


def _verify_sender_field_for_mac(sender_name: rfc9480.GeneralName, allow_failure: bool = False) -> None:
    """Verify the sender field for MAC-based protection.

    :param sender_name: The sender name to verify.
    :param allow_failure: If True, allows failure without raising an exception. Defaults to False.
    :raises BadMessageCheck: If the sender field is not of type `directoryName` or does not contain a common name.
    """
    if sender_name.getName() != "directoryName":
        if allow_failure:
            logging.info("For MAC protection the sender is supposed to be of type `directoryName`")
            return

        raise BadMessageCheck(
            " For MAC-based protection, the CA "
            "MUST use an identifier in the commonName field of the directoryName choice."
        )

    cm_name = utils.get_openssl_name_notation(name=sender_name["directoryName"], oids=[rfc5280.id_at_commonName])

    if not allow_failure:
        if cm_name is None:
            raise BadMessageCheck(
                " For MAC-based protection, the CA "
                "MUST use an identifier in the commonName field of the directoryName choice."
            )

    logging.info("sender for MAC-based protection is %s", cm_name)


@keyword(name="Check Sender CMP Protection")
def check_sender_cmp_protection(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, must_be_protected=True, allow_failure=True
):
    """Check the validity of the sender field in the PKIMessage as specified in RFC 9483, Section 3.1.

    Validates the sender field in the PKIMessage based on the protection type:
    - Signature-based protection: The subject field inside the CMP protection certificate.
    - MAC-based protection: The sender identifier must be in the `directoryName` format, and the commonName field
      must be used as the identifier.
    - Excludes senderKID check!

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure to validate.
        - `must_be_protected`: A flag indicating whether protection is required for the PKIMessage.
           Defaults to `True`.
        - `allow_failure`: A flag that determines whether the MAC validation failure should be allowed. If `True`, \
        failure logs a warning. If `False`, a `ValueError` is raised. Defaults to `True`.

    Raises:
    ------
        - `BadMessageCheck`: If the sender name does not match the CMP certificate subject DN \
        in signature-based protection.
        - `BadMessageCheck`: If the sender type is invalid for MAC-based protection.
        - `BadMessageCheck`: If the `directoryName` choice does not contain a common name.

    Examples:
    --------
    | Check Sender CMP Protection | ${pki_message} | must_be_protected=True | allow_failure=False |

    """
    sender_name = asn1utils.get_asn1_value(pki_message, query="header.sender")  # type: ignore
    sender_name: rfc9480.GeneralName
    check_is_protection_present(pki_message=pki_message, must_be_protected=must_be_protected)
    protection_type = ProtectedType.get_protection_type(pki_message)

    if protection_type in [ProtectedType.MAC, ProtectedType.KEM]:
        _verify_sender_field_for_mac(sender_name=sender_name, allow_failure=allow_failure)
        return

    cert_name = asn1utils.get_asn1_value(
        pki_message["extraCerts"][0],  # type: ignore
        query="tbsCertificate.subject",
    )
    cert_name: rfc9480.Name
    are_same_names = compareutils.compare_general_name_and_name(general_name=sender_name, name=cert_name)

    if not are_same_names:
        if allow_failure:
            n = sender_name.getName()
            sender_name = f"{n}: {str(sender_name[n])}"  # type: ignore
            logging.warning(
                "The subjectDN should be the same as the sender Name. sender: %s, certificate: %s",
                sender_name,
                cert_name.prettyPrint(),
            )
        else:
            n = sender_name.getName()
            sender_name = f"{n}: {str(sender_name[n])}"  # type: ignore
            raise BadMessageCheck(
                f"The subjectDN should be the same as the sender Name. sender: {sender_name}, "
                f"certificate: {cert_name.prettyPrint()}"
            )


def _check_cmp_protection_for_extra_certs(pki_message: PKIMessageTMP, allow_self_signed: bool) -> None:
    """Verify the CMP protection in a `PKIMessage`, checking for the presence and ordering of extra certificates.

    Ensures that the `PKIMessage` has the required CMP protection certificate. As defined in Rfc9483
    self-signed certificates should be omitted, so, it is allowed to not include it.

    :param pki_message: The `PKIMessageTMP` containing the CMP protection data to verify.
    :param allow_self_signed: If True, allows self-signed certificates in the absence of extra certificates.
    :raises ValueError: If the CMP protection certificate is missing and self-signed certificates are disallowed.
    """
    check_is_protection_present(pki_message, must_be_protected=True)
    extra_certs = pki_message["extraCerts"]

    if not pki_message["extraCerts"].isValue:
        if allow_self_signed:
            logging.info("`PKIMessage` was self-signed and certificate was omitted.")
            return

        raise ValueError("The CMP protection certificate was not present and self-signed certificates are not allowed.")

    if len(extra_certs) == 1:
        logging.info(
            "Self-signed certificates should be omitted from extraCerts and "
            "MUST NOT be trusted based on their inclusion in any case "
        )
        protectionutils.verify_pkimessage_protection(pki_message)
    else:
        protectionutils.verify_pkimessage_protection(pki_message)
        cmp_prot_cert = pki_message["extraCerts"][0]
        cmp_prot_chain = certutils.build_cmp_chain_from_pkimessage(pki_message=pki_message, ee_cert=cmp_prot_cert)
        is_ordered = check_single_chain_is_ordered(
            extra_certs=pki_message["extraCerts"], cert_chain=cmp_prot_chain, check_for_issued=False
        )
        if not is_ordered:
            logging.info("The Certificate chain for CMP protection certificate was not ordered!")


@keyword(name="Validate extraCerts")
def validate_extra_certs(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    cert_number: Strint = 0,
    allow_self_signed: bool = False,
    eku_strictness: str = "LAX",
    expected_eku="cmcCA",
) -> None:
    """Validate the `extraCerts` field in the PKIMessage as per RFC 9480, Section 3.1.

    Ensures that `extraCerts` is present when required for certain message types (e.g., "ip", "cp", and "kup").
    Validates that it contains the required certificate chain and is correctly structured for \
    signature-based-protection.
    Extended Key Usage (EKU) validation can be optionally applied to ensure the issuing CA's compliance.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure to validate.
        - `cert_number`: Index of the issued certificate in the 'response' field to check if the chain is
          present in `extraCerts`. Defaults to `0`.
        - `allow_self_signed`: Whether to allow a self-signed certificate. If the PKIMessage is signed by a self-signed
          certificate, it is allowed to be absent. Defaults to `False`.
        - `eku_strictness`: Strictness level for `ExtendedKeyUsage` validation. Default is `LAX`.
        - `expected_eku`: Expected `ExtendedKeyUsage` for the CA issuing the certificate. Defaults to `"cmcCA"`.

    Raises:
    ------
        - `ValueError`: If `extraCerts` is missing for required message types (e.g., "ip", "cp", "kup").
        - `ValueError`: If the certificate chain for the newly issued certificate is missing.
        - `ValueError`: If `ExtendedKeyUsage` validation fails under specified strictness.
        - `ValueError`: If PKIMessage is signature based protected, caching is not allowed, per specification
        and the `extraCerts` field is absent. (allowed for: "pkiconf", "pollReq", "pollRep")

    Examples:
    --------
    | Validate extraCerts | ${pki_message} |
    | Validate extraCerts | ${pki_message} | allow_self_signed=True |

    """
    # must be present in MUST be present in ip, cp, and kup.
    msg_type = cmputils.get_cmp_message_type(pki_message)
    if msg_type in {"ip", "cp", "kup"}:
        if not pki_message["extraCerts"].isValue:
            raise ValueError(
                "extraCerts MUST be present in ip, cp,"
                " and kup messages and contain the chain of a "
                "newly issued certificate."
            )

        issued_cert = cmputils.get_cert_from_pkimessage(pki_message, cert_number=cert_number)
        ee_cert_chain = certutils.build_cmp_chain_from_pkimessage(pki_message=pki_message, ee_cert=issued_cert)

        if len(ee_cert_chain) == 1:
            raise ValueError("The Certificate chain was not inside the `PKIMessage`.")

        # get the issuing certificate, currently sorted from ee to possible trust anchor.
        certutils.validate_cmp_extended_key_usage(
            ee_cert_chain[1], ext_key_usages=expected_eku, strictness=eku_strictness
        )

        is_ordered = check_single_chain_is_ordered(
            extra_certs=pki_message["extraCerts"], cert_chain=ee_cert_chain, check_for_issued=True
        )
        if not is_ordered:
            logging.info("The Certificate chain for the newly issued certificate was not ordered!")

    if msg_type in {"pkiconf", "pollReq", "pollRep"}:
        if not pki_message["extraCerts"].isValue:
            return

    if protectionutils.get_protection_type_from_pkimessage(pki_message) == "sig":
        _check_cmp_protection_for_extra_certs(pki_message, allow_self_signed)


# TODO ask alex to maybe always has to start with CN=


def _verify_senderkid_for_mac(pki_message: PKIMessageTMP, allow_mac_failure: bool = False) -> None:
    """Verify the `senderKID` and `sender` fields in a PKIMessage for MAC-based protection.

    :param pki_message: The PKIMessage object containing the `sender` and `senderKID` fields to verify.
    :param allow_mac_failure: Boolean flag to allow logging a warning instead of raising an error
                              when a mismatch or issue is detected. Defaults to `False`.
    :raises BadMessageCheck: If the `sender` field is missing, not of type `directoryName`,
                        lacks a common name, or if the `senderKID` does not match the common name,
                        and `allow_mac_failure` is False.

    :return: None
    """
    if not pki_message["header"]["sender"].isValue:
        raise BadMessageCheck("The sender field of PKIMessage must be present for MAC-based protection.")

    sender: rfc9480.GeneralName = pki_message["header"]["sender"]

    if sender.getName() != "directoryName":
        if not allow_mac_failure:
            raise BadMessageCheck(
                f"`Sender` field for MAC protection must be of type: `directoryName` but is `{sender.getName()}`"
            )

        logging.warning(
            "`Sender` field for MAC protection must be of type: `directoryName` but is `%s` \n%s",
            sender.getName(),
            "Please Look at rfc9483 Section 3.1!",
        )
        return

    sender_name = pki_message["header"]["sender"]["directoryName"]
    sender_kid = pki_message["header"]["senderKID"].asOctets().decode("utf-8")
    sender_kid_name = sender_kid.removeprefix("CN=")

    cm_name = utils.get_openssl_name_notation(name=sender_name, oids=[rfc5280.id_at_commonName])

    if not cm_name:
        if not allow_mac_failure:
            raise BadMessageCheck(f"PKIMessage `sender` did not contain a commonName: {sender_name.prettyPrint()}")
        logging.warning("PKIMessage `sender` did not contain a commonName: %s", sender_name.prettyPrint())
        return

    cm_name = cm_name.removeprefix("CN=")  # type: ignore
    if sender_kid_name != cm_name:
        if not allow_mac_failure:
            sender_name_formatted = utils.get_openssl_name_notation(name=sender_name)
            raise BadMessageCheck(
                "PKIMessage Mismatch between the field `sender` and `senderKID` for MAC protection. "
                f"Expected to be equal! senderKID is: {sender_kid} and sender is: {sender_name_formatted}"
            )

        logging.warning(
            "PKIMessage Mismatch between the field `sender` and `senderKID` for MAC protection. "
            "Expected to be equal! senderKID is: %s and sender is: %s",
            sender_kid,
            sender_name,
        )


# TODO add test cases for all algorithms (PQ, Composite, etc.)


@keyword(name="Validate senderKID For CMP Protection")
def validate_senderkid_for_cmp_protection(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    protection_cert: Optional[rfc9480.CMPCertificate] = None,
    must_be_protected: bool = False,
    allow_mac_failure: bool = False,
) -> None:
    """Validate the `senderKID` field in a PKIMessage according to RFC 9480 Section 3.1.

    Checks if the senderKID for MAC-based protection has included a commonName field inside the
    directoryName (GeneralName) choice. For signature-based protection, checks if `senderKID`
    is the subject field in the CMP protection certificate.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure to validate.
        - `protection_cert`: The certificate used for signature-based protection. If not provided, the first \
        certificate in the `extraCerts` field is assumed.
        - `must_be_protected`: If `True`, raises an exception if no protection (signature or MAC) is present.
          Defaults to `False`.
        - `allow_mac_failure`: If `True`, logs warnings instead of raising errors for MAC-based protection
          mismatches. Defaults to `False`.

    Raises:
    ------
        - `BadMessageCheck`: If protection is required but not present.
        - `BadMessageCheck`: If the `senderKID` field is missing.
        - `BadMessageCheck`: If the `senderKID` does not match the SubjectKeyIdentifier for signature-based protection.
        - `BadMessageCheck`: If the `senderKID` does not match the `commonName` for MAC-based protection.

    Examples:
    --------
    | Check SenderKID for CMP Protection | ${pki_message} | must_be_protected=True | allow_mac_failure=False |

    """
    # Check if protection is present, raise error if required but absent
    is_protected = check_is_protection_present(pki_message=pki_message)
    if not is_protected and not must_be_protected:
        return

    if not is_protected and must_be_protected:
        raise BadMessageCheck("PKIMessage protection is not present!")

    if not pki_message["header"]["senderKID"].isValue:
        raise BadMessageCheck("The senderKID field in the PKIHeader must be set if protection is applied!")

    if protection_cert is None:
        protection_cert = pki_message["extraCerts"][0]

    # Determine the type of protection
    protection_type = ProtectedType.get_protection_type(pki_message)
    sender_kid = pki_message["header"]["senderKID"].asOctets()
    if protection_type in [ProtectedType.MAC, ProtectedType.KEM]:
        _verify_senderkid_for_mac(pki_message=pki_message, allow_mac_failure=allow_mac_failure)
    else:
        # For signature-based protection, the senderKID must match the certificate's SubjectKeyIdentifier
        subject_ski = certextractutils.get_subject_key_identifier(protection_cert)  # type: ignore
        if subject_ski is None:
            logging.info("The CMP protection certificate does not contain a SubjectKeyIdentifier.")
            return

        if subject_ski != sender_kid:
            logging.info("senderKID: %s, CMP certificate ski: %s", sender_kid.hex(), subject_ski.hex())
            raise BadMessageCheck(
                "The SubjectKeyIdentifier of the CMP-protection certificate differs from the senderKID."
            )


@keyword(name="Validate PKIMessage Signature Protection")
def check_pkimessage_signature_protection(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, allow_sender_failure: bool = True, check_sender_kid: bool = True
) -> None:
    """Validate the PKIMessage signature and ensure the sender and senderKID fields are correctly set.

    Verifies the signature on the `pki_message` by using the protection certificate
    found in the `extraCerts` field. It ensures that the signature is valid and that the CMP-protection
    certificate is positioned correctly according to RFC 9483 Section 3.3.

    Arguments:
    ---------
        - `pki_message`: The `pyasn1` `PKIMessage` structure to check.
        - `allow_sender_failure`: If `True`, allows the verification to proceed even if the sender validation
        fails. Defaults to `True`.
        - `check_senderkid`: If `True`, ensures that the `senderKID` matches the SubjectKeyIdentifier.
          Defaults to `True`.



    Raises:
    ------
        - `BadMessageCheck`: The signature is invalid.
        - `BadMessageCheck`: The CMP-protection certificate is not correctly positioned as specified in RFC 9483.
        - `BadMessageCheck`: The `extraCerts` field is missing or does not contain certificates.
        - `BadAlg`: The protection algorithm is not supported.

    Examples:
    --------
    | Check PKIMessage Signature Protection | ${pki_message} | allow_sender_failure=True | check_senderkid=True |
    | Check PKIMessage Signature Protection | ${pki_message} | check_senderkid=True |
    | Check PKIMessage Signature Protection | ${pki_message} |

    """
    protection_value: bytes = pki_message["protection"].asOctets()

    prot_alg_id = pki_message["header"]["protectionAlg"]
    protection_type_oid = prot_alg_id["algorithm"]

    encoded: bytes = protectionutils.prepare_protected_part(pki_message)

    if protection_type_oid not in MSG_SIG_ALG:
        raise BadAlg("PKIMessage is not signed by a known signature oid!")

    if not pki_message["extraCerts"].isValue:
        raise BadMessageCheck("PKIMessage is does not contains certificates!")

    # check if values are correctly set.
    check_protection_alg_field(pki_message=pki_message, must_be_protected=True)
    check_sender_cmp_protection(pki_message=pki_message, allow_failure=allow_sender_failure)
    if check_sender_kid:
        validate_senderkid_for_cmp_protection(pki_message, must_be_protected=True)

    alg_id = pki_message["header"]["protectionAlg"]["algorithm"]

    hash_alg = get_hash_from_oid(alg_id)
    hash_alg = None if hash_alg is None else hash_alg.split("-")[1]

    index = find_right_cert_pos(pki_message["extraCerts"], data=encoded, signature=protection_value, hash_alg=hash_alg)
    if index == 0:
        # CMP Protection certificate was at the right position
        protectionutils.verify_pkimessage_protection(pki_message=pki_message)
        return
    if index != -1:
        logging.warning("found the right Certificate at position: %s", str(index))
        raise BadMessageCheck(
            "The first certificate must be the CMP-Protection certificate as specified in RFC 9483, Section 3.3."
        )

    raise BadMessageCheck("CMP-Protection certificate was not present.")


def _prepare_indicies(extra_certs: List[rfc9480.CMPCertificate]) -> Dict[Tuple[str, int], int]:
    """Prepare a mapping from certificate identifiers to their indices in the extra_certs list.

    Creates a dictionary that maps each certificate's unique identifier
    (a tuple of its subject name and serial number) to its index in the provided extra_certs list.
    To have a quick lookup of a certificate's position within the `extraCerts` field.

    :param extra_certs: A list of CMPCertificates from which to build the index mapping.
    :return: The lookup table.
    """
    cert_id_to_index = {}
    # Get the certificate identifier (subject name and serial number)
    for index, cert in enumerate(extra_certs):
        subject = cert["tbsCertificate"]["subject"]
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        subject_name = utils.get_openssl_name_notation(subject)
        cert_id = (subject_name, serial_number)
        if cert_id not in cert_id_to_index:
            cert_id_to_index[cert_id] = index

    return cert_id_to_index


def _get_cert_index(cert: rfc9480.CMPCertificate, cert_id_to_index: Dict[Tuple[str, int], int]) -> int:
    """Retrieve the index of a given certificate in the extra_certs list using the index mapping.

    :param cert: The certificate whose index is to be retrieved
    :param cert_id_to_index: A dictionary mapping certificate identifiers to indices.
    :return: The index of the certificate in the `extraCerts` field.
    :raise KeyError: If the certificate is not found in the cert_id_to_index mapping.
    """
    subject = cert["tbsCertificate"]["subject"]
    subject_name = utils.get_openssl_name_notation(subject)  # type: ignore
    subject_name: str
    serial_number = int(cert["tbsCertificate"]["serialNumber"])
    cert_id = (subject_name, serial_number)
    return cert_id_to_index[cert_id]


def _issuer_was_already_in_cert(
    cert: rfc9480.CMPCertificate, cert_index: int, extra_certs: List[rfc9480.CMPCertificate]
) -> bool:
    """Check if the issuer of a certificate was already present in extra_certs before the current certificate.

    :param cert: The certificate whose issuer is being checked.
    :param cert_index: The index of the current certificate in the extra_certs list.
    :param extra_certs: The list of extra certificates where the issuer may be found.
    :return: True if the issuer certificate was found in extra_certs before the current certificate; False otherwise.
    """
    signer_found = False

    for idx in range(cert_index):
        possible_issuer_cert = extra_certs[idx]
        if certutils.check_is_cert_signer(cert, possible_issuer_cert):
            signer_found = True
            break

    return signer_found


@not_keyword
def check_single_chain_is_ordered(
    extra_certs: List[rfc9480.CMPCertificate], cert_chain: List[rfc9480.CMPCertificate], check_for_issued: bool = False
) -> bool:
    """Verify that a single certificate chain is correctly ordered and valid.

    Assumes that the final certificate in the chain is either self-signed or trusted.

    :param extra_certs: The PKIMessage `extraCerts` field.
    :param cert_chain: The certificate chain to validate, where each certificate is expected to be
    issued by the next one.
    :param check_for_issued: If `True`, the first certificate in cert_chain is assumed to be newly issued.
    Defaults to `False`. Else checks if the certificate is inside the extra_certs, which means,
    if not inside that it was a newly issued certificate.
    :return: `True` if the certificate chain was correctly ordered; False otherwise.
    """
    cert_id_to_index = _prepare_indicies(extra_certs)

    if check_for_issued:
        # Remove the first certificate as it is newly issued and not in extra_certs
        cert_chain_to_check = cert_chain[1:]
    else:
        cert_chain_to_check = cert_chain

    # Ensure all certificates in cert_chain_to_check are in extra_certs
    for cert_i in cert_chain_to_check:
        try:
            _ = _get_cert_index(cert_i, cert_id_to_index)
        except KeyError as err:
            raise ValueError("Certificate not found in extra_certs.") from err

    last_index = _get_cert_index(cert_chain_to_check[0], cert_id_to_index)
    for i in range(len(cert_chain_to_check) - 1):
        cert_issuer = cert_chain_to_check[i + 1]
        issuer_index = _get_cert_index(cert_issuer, cert_id_to_index)
        if not (issuer_index == last_index + 1 or last_index > issuer_index):
            logging.info(
                "Certificate at position %d was not signed by the next certificate and issuer not found before it.", i
            )
            return False
        last_index += 1

    return True


@not_keyword
def find_right_cert_pos(
    extra_certs: List[rfc9480.CMPCertificate], data: bytes, signature: bytes, hash_alg: Optional[str] = None
) -> int:
    """Find the index position of the CMP-protection certificate that matches the signature.

    :param extra_certs: List of CMPCertificate objects.
    :param data: The data that was signed.
    :param signature: The signature to verify.
    :param hash_alg: Optional string specifying the hash algorithm used for the signature, e.g., "sha256".
    :return: Index of the correct CMP-protection certificate. Returns -1 if not found.
    """
    for i, asn1cert in enumerate(extra_certs):
        try:
            certutils.verify_signature_with_cert(asn1cert=asn1cert, data=data, signature=signature, hash_alg=hash_alg)
            return i
        except (ValueError, InvalidSignature):
            # might be incompatible hash alg
            continue

    return -1


@not_keyword
def check_protection_alg_conform_to_spki(
    prot_alg_id: rfc5280.AlgorithmIdentifier, cert: rfc9480.CMPCertificate
) -> bool:
    """Verify if the protectionAlg conforms to the subjectPublicKeyInfo algorithm of the CMP certificate.

    Verify if the algorithm specified in the `prot_alg_id` is consistent with the algorithm
    used in the subject public key info of the provided certificate. The check is performed for various
    public key types, including ECDSA, EdDSA (Ed25519 and Ed448), and RSA.

    :param prot_alg_id: The `AlgorithmIdentifier` of the protection algorithm.
    :param cert: The `CMPCertificate` from which the subject public key info is extracted.
    :return: `True` if the protection algorithm is compatible with the spki algorithm in the certificate,
    `False` otherwise.
    """
    cert_alg_id = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]

    if cert_alg_id["algorithm"] == rfc6664.id_ecPublicKey:
        return prot_alg_id["algorithm"] in ECDSA_SHA_OID_2_NAME

    if cert_alg_id["algorithm"] in {rfc9481.id_Ed25519, rfc9481.id_Ed448}:
        return prot_alg_id["algorithm"] in {rfc9481.id_Ed25519, rfc9481.id_Ed448}

    if cert_alg_id["algorithm"] == rsaEncryption:
        return prot_alg_id["algorithm"] in RSA_SHA_OID_2_NAME or prot_alg_id["algorithm"] in RSASSA_PSS_OID_2_NAME

    if prot_alg_id["algorithm"] in RSA_SHA_OID_2_NAME:
        return cert_alg_id["algorithm"] in RSA_SHA_OID_2_NAME

    try:
        return prot_alg_id == cert_alg_id
    except pyasn1.error.PyAsn1Error:
        # if tried to compare a schema object.
        return False


@keyword(name="Validate protectionAlg Field")
def check_protection_alg_field(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, expected_type: Optional[str] = None, must_be_protected: bool = True
):
    """Check the `protectionAlg` field in the PKI message for consistency with rfc 9483 Section 3.2.

    Check includes:
    --------------
        - `known ObjectIdentifier`
        - both the `protection` value and the `protectionAlg` field are present.
        - The CMPCertificates `subjectPublicKeyInfo` is consistent with `protectionAlg`, if signature protected.

    Arguments:
    ---------
        - `pki_message`: The PKI message containing the `protectionAlg` field to be checked.
        - `expected_type`: The expected type of the protection algorithm, either `"sig"` or
                            `"mac"`. If provided, the function checks that the algorithm matches this type.
        - `must_be_protected`: indicating if the value has to be present.



    Raises:
    ------
        - `ValueError`: If the `protectionAlg` and `protection` values are incorrectly set or missing.
        - `ValueError`: If the `protectionAlg` field does not match the expected protection type
        (either `"sig"` or `"mac"`).
        - `ValueError`: If signature-based protection is expected, but the `extraCerts` field is absent.
        - `ValueError`: If the `protectionAlg` field for signature-based protection is not consistent with the
          `subjectPublicKeyInfo` field in the associated CMP protection certificate.

    Examples:
    --------
    | Check Protection Algorithm Field | ${pki_message} | expected_type="sig" | must_be_protected=True |
    | Check Protection Algorithm Field | ${pki_message} | expected_type="sig" |
    | Check Protection Algorithm Field | ${pki_message} |

    Notes:
    -----
    - If it is a signature algorithm, its type *MUST* be MSG_SIG_ALG as specified in Section 3 of RFC9481.
    - For signature-based protection (`sig`), the `protectionAlg` *MUST* be consistent with the
    `subjectPublicKeyInfo` field of the CMP protection certificate.
    - For MAC-based protection (`mac`), the algorithm must conform to `MSG_MAC_ALG` as specified in
    RFC 9481 Section 6.1.

    """
    if not must_be_protected:
        if not pki_message["header"]["protectionAlg"].isValue:
            return

    # raises value error if values are expected to be present,
    # or if only the protection value is present or the alg id.
    _ = check_is_protection_present(pki_message=pki_message, must_be_protected=must_be_protected)

    # raise ValueError if unknown oid.
    protection_type = protectionutils.get_protection_type_from_pkimessage(pki_message)
    if expected_type is not None:
        if protection_type != expected_type:
            raise ValueError(
                f"Excepted to be {expected_type} protected, but the `PKIMessage` is {protection_type} protected"
            )

    if protection_type == "sig":
        if not pki_message["extraCerts"].isValue:
            raise ValueError("MUST be present for signature-based protection!")

        alg_id = pki_message["header"]["protectionAlg"]
        cert = pki_message["extraCerts"][0]
        if not check_protection_alg_conform_to_spki(alg_id, cert):
            raise ValueError(
                "For signature based protection, the `protectionAlg` parameters "
                "MUST be consistent with the subjectPublicKeyInfo field of the CMP protection certificate."
            )


@keyword(name="Check implicitconfirm In generalInfo")
def check_implicitconfirm_in_generalinfo(pki_message: PKIMessageTMP) -> None:  # noqa: D417 undocumented-param
    """Check whether `implicitConfirm` is correctly set in the `generalInfo` field of the `pki_message`.

    `implicitConfirm` is only allowed for the message types: `ip`, `cp`, `kup`, `ir`, `cr`, `kur`, and `p10cr`.
     Validate that `implicitConfirm` is set to `NULL` and verify its presence based on the message type.


    Arguments:
    ---------
         - `pki_message`: The PKI message object containing the GeneralInfo field.



    Raises:
    ------
    - `ValueError`: If `implicitConfirm` is present but not allowed for the message type
    - `ValueError`: If `implicitConfirm` is present but its value is not `NULL`.

    Examples:
    --------
    | Check ImplicitConfirm in GeneralInfo | ${pki_message} |

    """
    msg_type = cmputils.get_cmp_message_type(pki_message)

    if not pki_message["header"]["generalInfo"].isValue:
        return

    implicit_confirm = cmputils.get_value_from_seq_of_info_value_field(
        pki_message["header"]["generalInfo"], rfc9480.id_it_implicitConfirm
    )

    if implicit_confirm is None:
        return

    if msg_type in {"ip", "cp", "kup"} or msg_type in {"ir", "cr", "kur", "p10cr"}:
        pass
    else:
        raise BadRequest(f"'implicitConfirm' is not allowed to be set for PKIBody type: {msg_type}")

    # Both are NULL values, one sent over the wire; the other is set by the user.
    # Either remove and say the user must always en- and decode the `PKIMessage` or `generalInfo`,
    # or allow this behavior.
    if implicit_confirm not in [univ.Null(""), b"\x05\x00"]:
        logging.warning("implicit_confirm value is: %s", implicit_confirm.prettyPrint())
        raise BadRequest("The 'implicitConfirm' value must be NULL!")


@keyword(name="Check confirmWaitTime In generalInfo")
def check_confirmwaittime_in_generalinfo(pki_message: PKIMessageTMP) -> None:  # noqa D417 undocumented-param
    """Check if `confirmWaitTime` is correctly set, if set, in the GeneralInfo field of the `pki_message`.

    Verify that `confirmWaitTime` is properly set and validates its presence in relation
    to the `implicitConfirm` field. If `implicitConfirm` is present, `confirmWaitTime` must be absent.

    Arguments:
    ---------
        - `pki_message`: The PKI message object containing the GeneralInfo field.

    Raises:
    ------
        - `BadRequest`: If `confirmWaitTime` is present when `implicitConfirm` is also present,
        - `ValueError`: If the `confirmWaitTime` value is invalid or absent when required.


    Examples:
    --------
    | Check ConfirmWaitTime in GeneralInfo | ${pki_message} |

    """
    msg_type = cmputils.get_cmp_message_type(pki_message)

    if not pki_message["header"]["generalInfo"].isValue:
        return

    confirm_wait_time = cmputils.get_value_from_seq_of_info_value_field(
        pki_message["header"]["generalInfo"], rfc9480.id_it_confirmWaitTime
    )

    implicit_confirm = cmputils.get_value_from_seq_of_info_value_field(
        pki_message["header"]["generalInfo"], rfc9480.id_it_implicitConfirm
    )

    if confirm_wait_time is not None:
        try:
            confirm_wait_time, rest = decoder.decode(confirm_wait_time, useful.GeneralizedTime())
        except pyasn1.error.PyAsn1Error:
            raise BadDataFormat("Can not correctly decode the confirmWaitTime.")  # pylint: disable=raise-missing-from

        if rest != b"":
            raise BadAsn1Data("confirmWaitTime")

        time_obj = confirm_wait_time.asDateTime
        time_now = datetime.datetime.now(datetime.timezone.utc)

        # needs to be total_seconds otherwise .seconds returns the absolute value!
        time_diff = (time_obj - time_now).total_seconds()
        if time_diff <= 0:
            raise ValueError(f"The ConfirmWaitTime minus the current time was negative: {time_diff}")

        if implicit_confirm is None:
            if msg_type in {"ip", "cp", "kup"}:
                logging.info("The `confirmWaitTime` InfoTypeAndValue structure is recommended.")

        else:
            raise BadRequest(
                "The `confirmWaitTime` structure must not be present when `implicitConfirm` is present."
                "See [RFC4210], Section 5.1.1.2."
            )


def _get_cert_profile_msg_size(request: PKIMessageTMP) -> int:
    """Get the number of Request to match then later the CertProfile number.

    :param request: The PKIMessage object containing the `certProfile` field.
    :return: The number of requests in the PKIMessage.
    """
    msg_type = cmputils.get_cmp_message_type(request)

    if msg_type == "p10cr":
        return 1

    if msg_type in ["ir", "cr", "kur"]:
        return len(request["body"][msg_type])

    if msg_type == "genm":
        return len(request["body"]["genm"])

    raise BadRequest(f"Unknown message type: {msg_type} for certProfile size check!")


@keyword(name="Validate certProfile For CA")
def validate_cert_profile_for_ca(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    cert_profiles: Optional[List[str]] = None,
) -> None:
    """Validate the `certProfile` field in the PKIMessage for a CA.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage object containing the `certProfile` field, inside the `generalInfo` field.
        - `cert_profiles`: The list of `certProfile` to validate against. If `None`, the function will
        not perform any validation. If provided will add `""` to the list of profiles. Defaults to `None`.

    Raises:
    ------
        - `BadRequest`: If the `certProfile` is not allowed for CMP messages.
        - `BadRequest`: If the `certProfile` is present in messages where it should not be.

    Examples:
    --------
    | Validate CertProfiles for CA | ${pki_message} |
    | Validate CertProfiles for CA | ${pki_message} | ${cert_profiles} |

    """
    if not pki_message["header"]["generalInfo"].isValue:
        return

    msg_type = cmputils.get_cmp_message_type(pki_message)

    value = cmputils.get_value_from_seq_of_info_value_field(
        pki_message["header"]["generalInfo"], rfc9480.id_it_certProfile
    )

    if value is None:
        return

    if msg_type not in {"ir", "cr", "kur", "p10cr", "genm"}:
        raise BadRequest(f"`certProfile` should not be present in {msg_type} messages!")

    profiles, rest = asn1utils.try_decode_pyasn1(  # type: ignore
        value.asOctets(), CertProfileValueAsn1()
    )
    profiles: CertProfileValueAsn1

    if rest != b"":
        raise BadAsn1Data("CertProfileValue")

    if len(profiles) == 0:
        raise BadRequest("The `certProfile` structure must contain at least one profile.")

    if len(profiles) == _get_cert_profile_msg_size(pki_message):
        raise BadRequest("The `certProfile` structure must not contain the same profile multiple times.")

    if cert_profiles is not None:
        cert_profiles.append("")
        for profile in profiles:
            if profile.prettyPrint() not in cert_profiles:
                raise BadRequest(f"The `certProfile` {profile} is not known to the CA!")


@keyword(name="Check certProfile In generalInfo")
def check_certprofile_in_generalinfo(pki_message: PKIMessageTMP) -> None:  # noqa D417 undocumented-param
    """Check if `certProfile` is correctly set in the generalInfo field of the `pki_message`.

    The `certProfile` field is optional and can only be present in messages of type `ir`, `cr`, `kur`, `p10cr`,
    and `genm` of type `id-it-certProfile`. Ensures it is properly set or omitted as required.

    Arguments:
    ---------
    - `pki_message`: The PKI message object containing the GeneralInfo field.

    Raises:
    ------
    - `ValueError`: If `certProfile` is present in message types where it should be omitted.

    Examples:
    --------
    | Check CertProfile in GeneralInfo | ${pki_message} |

    """
    if not pki_message["header"]["generalInfo"].isValue:
        return

    msg_type = cmputils.get_cmp_message_type(pki_message)
    cert_profiles = cmputils.find_oid_in_general_info(pki_message, rfc9480.id_it_certProfile)

    if cert_profiles:
        if msg_type not in {"ir", "cr", "kur", "p10cr", "genm"}:
            raise BadRequest("`certProfile` should not be present!")

    # other checks are not relevant, for the Client.


@keyword(name="Check generalInfo Field")
def check_generalinfo_field(pki_message: PKIMessageTMP) -> None:  # noqa D417 # undocumented-param
    """Check the `implicitConfirm`, `confirmWaitTime` and `certProfile` in the GeneralInfo field of the `PKIMessage`.

    To ensure compliance with RFC 9483 3.1. General Description of the CMP Message Header.

    Arguments:
    ---------
        - `pki_message`: The PKI message object containing the GeneralInfo field.

    Raises:
    ------
    - `BadRequest`: If `certProfile`, `confirmWaitTime`, `implicitConfirm` are incorrectly present.
    - `ValueError`: If the values are incorrectly set.

    Examples:
    --------
    | Check GeneralInfo Field | ${pki_message} |

    """
    check_implicitconfirm_in_generalinfo(pki_message=pki_message)
    check_confirmwaittime_in_generalinfo(pki_message=pki_message)
    check_certprofile_in_generalinfo(pki_message=pki_message)


def _check_message_time_for_request(
    request_time: datetime.datetime,
    allowed_interval: int,
) -> None:
    """Check if the `messageTime` field is set in the PKIMessage header from a client request.

    :param request_time: The time when the request was made.
    """
    now_obj = datetime.datetime.now(datetime.timezone.utc)
    time_diff = (now_obj - request_time).total_seconds()
    if time_diff < 0:
        raise BadTime(f"The `messageTime` field is in the future! The time difference is: {time_diff} seconds")

    if time_diff == 0:
        logging.warning("The `messageTime` field is set to the current time!")

    if time_diff > allowed_interval:
        raise BadTime(
            f"The `messageTime` field is too old: {time_diff} seconds."
            f"The allowed interval is: {allowed_interval} seconds."
        )
    logging.info("The time difference was: %.2f seconds, which is within the allowed interval.", time_diff)


@not_keyword
def check_message_time_field(
    pki_message: PKIMessageTMP,
    allowed_interval: Optional[int] = None,
    request_time: Optional[datetime.datetime] = None,
):
    """Validate the `messageTime` field in the PKIMessage header and ensure compliance with the specified time.

    Validates the `messageTime` field is appropriately set in the PKIMessage header, particularly when
    the `confirmWaitTime` field is present. It also optionally verifies that the `messageTime` is within an acceptable
    time interval, either relative to a provided `request_time` or the current UTC time.

    :param pki_message: The PKIMessage object to be validated.
    :param allowed_interval: The maximum allowed time difference in seconds between the `messageTime` in the message
                            and the `request_time` or current time. If `None`, the time difference check is skipped.
    :param request_time: The original request time to compare against the `messageTime`. If not provided, the current
                        UTC time is used. Defaults to `None`.
    :raises BadTime: If the `messageTime` field is required but missing, or if the time difference exceeds
                       the allowed interval.
    """
    # PKI management entity: A non-EE PKI entity, i.e., an RA or a CA.
    if pki_message["header"]["generalInfo"].isValue:
        confirm_wait_time = cmputils.get_value_from_seq_of_info_value_field(
            pki_message["header"]["generalInfo"], rfc9480.id_it_confirmWaitTime
        )

        if confirm_wait_time is not None:
            if not pki_message["header"]["messageTime"].isValue:
                raise BadTime("The `messageTime` field must be present if `confirmWaitTime` is set!")

    if allowed_interval is not None:
        msg_time = asn1utils.get_asn1_value(pki_message, query="header.messageTime")  # type: ignore
        msg_time: useful.GeneralizedTime
        time_obj = msg_time.asDateTime

        if request_time is not None:
            time_diff = (time_obj - request_time).total_seconds()
            logging.info("Time difference between request and response was: %d seconds.", int(time_diff))
        else:
            _check_message_time_for_request(time_obj, allowed_interval)
            return

        if time_diff > allowed_interval:
            raise BadTime(f"Time difference exceeds allowed {allowed_interval} seconds: {time_diff} seconds")

        logging.info("The time difference was: %.2f seconds, which is within the allowed interval.", time_diff)


def validate_sender_and_recipient_nonce(  # noqa D417 undocumented-param
    response: PKIMessageTMP, request: PKIMessageTMP, nonce_sec: Strint = 128
) -> None:
    """Check the sender and recipient nonce in the response and request messages.

    Verifies that the `senderNonce` in the request message matches the `recipNonce` in the response
     message. Additionally, it checks if the `senderNonce` in the response message meets the minimum required
     security level, which is 128 bits by default.

    Arguments:
    ---------
         - `response`: The PKI response message containing the recipient nonce.
         - `request`: The PKI request message containing the sender nonce.
         - `nonce_sec`: The minimum required security level for the nonce in bits.
         Defaults to `128`. The Value cannot be set lower.

    Raises:
    ------
         - `BadRecipientNonce`: If the `recipNonce` is not set inside the response message.
         - `BadSenderNonce`: If the `senderNonce` is not set inside the request message.
         - `BadRecipientNonce`: If the `senderNonce` in the request does not match the `recipNonce` in the response.
         - `BadSenderNonce`: if the `senderNonce` in the response does not meet the minimum security length.
         - `BadRecipientNonce`: If the `recipNonce` in the response is shorter than the required security level.

    Examples:
    --------
     | Validate Sender and Recipient Nonce | ${pki_message_response} | ${pki_message_request} | nonce_sec=128 |
     | Validate Sender and Recipient Nonce | ${pki_message_response} | nonce_sec=128 |

    """
    if not response["header"]["recipNonce"].isValue:
        raise BadRecipientNonce("The `recipNonce` was not set inside the response message.")

    if not response["header"]["senderNonce"].isValue:
        raise BadSenderNonce("The `senderNonce` was not set inside the request message.")

    recip_nonce = response["header"]["recipNonce"].asOctets()
    nonce_sec = max(128, convertutils.str_to_int(nonce_sec))
    if len(bytearray(recip_nonce)) < (nonce_sec // 8):
        raise BadRecipientNonce(f"The `recipNonce` in the response is shorter than the required {nonce_sec} bits.")

    sender_nonce = request["header"]["senderNonce"].asOctets()
    if sender_nonce != response["header"]["recipNonce"].asOctets():
        raise BadRecipientNonce("The `senderNonce` in the request does not match the `recipNonce` in the response.")

    recip_nonce = response["header"]["senderNonce"].asOctets()

    nonce_sec = max(128, convertutils.str_to_int(nonce_sec))
    if len(bytearray(recip_nonce)) < (nonce_sec // 8):
        raise BadSenderNonce(f"The `senderNonce` in the response is shorter than the required {nonce_sec} bits.")


@keyword(name="Validate transactionID")
def validate_transaction_id(  # noqa D417 undocumented-param
    response: PKIMessageTMP, request: Optional[PKIMessageTMP] = None
):
    """Validate the `transactionID` in a PKIMessage according to Rfc 9483 Section 3.1.

    The `transactionID` must be exactly 128 bits (16 bytes), and The `transactionID` must match the
    one from the previous message.

    Arguments:
    ---------
        - `response`: The current PKIMessage containing the `transactionID` to validate.
        - `request`: The PKIMessage from the previous transaction, used to compare `transactionID` values for \
        consistency. Defaults to `None`.

    Raises:
    ------
        - `BadRequest`: If the `transactionID` in the first message is not 128 bits long.
        - `BadRequest`: If the `transactionID` does not match the one from the previous message.

    Examples:
    --------
    | Validate TransactionID | ${transaction_id} |
    | Validate TransactionID | ${transaction_id} | ${previous_transaction_id} |

    """
    if not response["header"]["transactionID"].isValue:
        raise BadDataFormat("The `transactionID` was not set!")

    transaction_id = response["header"]["transactionID"].asOctets()

    if len(transaction_id) != 16:
        raise BadRequest("The `transactionID` must be 128 bits long.")

    if request is not None:
        our_id = request["header"]["transactionID"].asOctets()
        if our_id != transaction_id:
            raise BadRequest(
                f"The response `transactionID` was: {transaction_id.hex()} != previous ID was: {our_id.hex()}"
            )


def validate_sender_and_recipient(  # noqa D417 undocumented-param
    response: PKIMessageTMP,
    request: PKIMessageTMP,
    must_be_eq: bool = False,
):
    """Check if the sender and recipient related fields in the request and response messages match.

    Include the following checks:
    - The transaction ID and nonces between the PKI request and response messages.
    - The senderNonce and the recipNonce matches.
    - The recipient of the response message matches the sender of the request message.

    Arguments:
    ---------
        - `pki_message_response`: The PKI response message containing the recipient.
        - `pki_message_request`: Our request message containing the `sender`, `transactionID` and `senderNonce`.
        - `must_be_eq`: Specifies whether the sender and recipient must be exactly equal. If set to `True`,
        a mismatch raises a `ValueError`. Defaults to `False`.

    Raises:
    ------
        - `ValueError`: If the recipient in the response message does not match the sender in the request message \
                        and `must_be_eq` is `True`.

    Examples:
    --------
    | validate Sender and Recipient | ${pki_message_response} | ${pki_message_request} | must_be_eq=${True} |
    | validate Sender and Recipient | ${pki_message_response} | ${pki_message_request} |


    """
    validate_transaction_id(
        response=response,
        request=request,
    )
    validate_sender_and_recipient_nonce(response=response, request=request)
    request_sender = request["header"]["sender"]
    response_recipient = response["header"]["recipient"]
    if response_recipient != request_sender:
        if not must_be_eq:
            logging.info("Recipient mismatch, we sent from %s, we got %s", request_sender, response_recipient)
        else:
            raise ValueError(f"Recipient mismatch, we sent from {request_sender}, we got {response_recipient}")


@keyword(name="Validate PKIMessage Header")
def validate_pkimessage_header(  # noqa D417 undocumented-param
    pki_message_response: PKIMessageTMP,
    pki_message_request: Optional[PKIMessageTMP] = None,
    protection: bool = True,
    time_interval: Union[None, Strint] = 200,
    allow_failure_sender: bool = True,
):
    """Validate the PKIMessage header fields to ensure conformance with CMP standards.

    Performs a comprehensive validation of the `PKIMessage` header to check for compliance with
    CMP protocol specifications. It verifies various elements such as the protocol version, protection presence,
    sender identity, message timestamps, and general information fields.

    Note:
    ----
        - only allows failure of the `sender` and `senderKID` for MAC-based-protection.

    Arguments:
    ---------
        - `pki_message_response`: The PKIMessage response object to validate.
        - `pki_message_request`: The original PKIMessage request. If provided,
          it is used to compare transaction IDs, sender and recipient fields, and timestamps. Defaults to `None`.
        - `protection`: Specifies whether protection (e.g., signature or MAC) is required on the response message.
          If `True`, ensures that protection is present. Defaults to `True`.
        - `time_interval`: The maximum allowable time difference (in seconds) between the `messageTime`
          field of the request and response. Defaults to `200`. If set to `None` is disabled.
        - `allow_failure_sender`: If `True`, logs a warning for sender mismatches instead of raising an error.
          Defaults to `True`.

    Raises:
    ------
        - `ValueError`: The protocol version is not set to 2 or 3.
        - `ValueError`: The required protection is not present.
        - `ValueError`: `senderKID` or `sender` validation fails when required.
        - `ValueError`: The `GeneralInfo` field values (e.g., `implicitConfirm`, `confirmWaitTime`, `certProfile`) \
        do not conform
        to the standard. Wrong values, types or un-decode-able.
        - `ValueError`: The `messageTime` field is missing or exceeds the allowed interval.
        - `ValueError`:`transactionID` and `senderNonce` in the response do not match those in the request.
        - `ValueError`: the recipientNonce is too small.
        - `ValueError`: The recipient in the response does not match the sender in the request, if `must_be_eq` \
        is `True`.

    Examples:
    --------
    | Validate PKIMessage Header | ${pki_message_response} | ${pki_message_request} | \
    protection=True | time_interval=200 |
    | Validate PKIMessage Header | ${pki_message_response} | ${pki_message_request} | allow_failure_sender=True |
    | Validate PKIMessage Header | ${pki_message_response} | protection=False |

    """
    if int(pki_message_response["header"]["pvno"]) not in [2, 3]:
        raise ValueError(f"Header version is {pki_message_response['header']['pvno']}")

    check_is_protection_present(pki_message_response, must_be_protected=protection)
    check_sender_cmp_protection(pki_message_response, must_be_protected=protection, allow_failure=allow_failure_sender)
    validate_senderkid_for_cmp_protection(
        pki_message_response, must_be_protected=protection, allow_mac_failure=allow_failure_sender
    )

    check_generalinfo_field(pki_message_response)

    request_time = None
    if pki_message_request is not None:
        if not pki_message_request["header"]["messageTime"].isValue:
            logging.info("`pki_message_request` messageTime is not set.")
        else:
            request_time = pki_message_request["header"]["messageTime"].asDateTime

    # Validate message time with allowed interval
    if time_interval is not None:
        time_interval = convertutils.str_to_int(time_interval)

    check_message_time_field(
        pki_message=pki_message_response,
        allowed_interval=time_interval,
        request_time=request_time,
    )

    if pki_message_request is not None:
        validate_sender_and_recipient(response=pki_message_response, request=pki_message_request, must_be_eq=False)


@keyword(name="Check RP CMP Message Body")
def check_rp_cmp_message_body(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, index: Strint = 0
) -> None:
    """Validate the content of an `rp` (Revocation Response) CMP message body according to Section 4.2 in RFC 9483.

    Arguments:
    ---------
        - `pki_message`: The CMP `PKIMessage` object containing the `rp` body type.
        - `index`: Optional index for selecting a specific `PKIStatusInfo` from a sequence of responses.
          Defaults to `0`, meaning the first `PKIStatusInfo` will be checked.



    Raises:
    ------
        - `ValueError`: If the body type of the `PKIMessage` is not 'rp'.
        - `ValueError`: If the status of the `PKIMessage` is neither 'accepted' nor 'rejected'.
        - `ValueError`: If the status is 'accepted' but the `failInfo` field is present.

    Examples:
    --------
    | Check RP CMP Message Body | ${pki_message} |
    | Check RP CMP Message Body | ${pki_message} | index=1 |

    """
    resp_body_name = pki_message["body"].getName()

    if resp_body_name != "rp":
        raise ValueError(f"Expected body type 'rp' in PKIMessage, but got '{resp_body_name}'.")

    pki_status_info: rfc9480.PKIStatusInfo = cmputils.get_pkistatusinfo(pki_message, int(index))

    is_correct = asn1utils.asn1_compare_named_values(pki_status_info["status"], "accepted")
    if is_correct:
        if pki_status_info["failInfo"].isValue:
            raise ValueError("The `failInfo` MUST be absent if the `status` is accepted")

        return
    is_correct = asn1utils.asn1_compare_named_values(pki_status_info["status"], "rejected")
    if is_correct:
        return

    raise ValueError("For the `PKIBody` `rp` are only the status: `accepted and rejected` allowed!")


@keyword(name="Validate certReqId")
def validate_certReqId(  # noqa D417 undocumented-param pylint: disable=invalid-name
    pki_message: PKIMessageTMP, response_index: Strint = 0, used_p10cr: bool = False
):
    """Validate the `certReqId` field in a PKIMessage according to Rfc 9383 Section 4.

    Notes:
    -----
    - For regular certificate requests (not using p10cr), the `certReqId` must be `0`.
    - For PKCS #10 Certificate Requests (p10cr), the `certReqId` must be `-1`.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the `certReqId` to be checked.
        - `response_index`: Index of the response in the `CertResponse` sequence to check. Defaults to `0`.
        - `used_p10cr`: Indicates if the message uses a PKCS #10 Certificate Request (p10cr). If `True`,
          the `certReqId` must be `-1`. If `False`, the `certReqId` must be `0`. Defaults to `False`.

    Raises:
    ------
       - `ValueError`: If the `certReqId` does not match the expected value based on the `used_p10cr` flag.

    Examples:
    --------
    | Validate CertReqId | ${pki_message} | response_index=1 | used_p10cr=True |
    | Validate CertReqId | ${pki_message} | used_p10cr=False |

    """
    cert_req_id = cmputils.get_certreqid_from_pkimessage(pki_message=pki_message, response_index=response_index)
    body_name = cmputils.get_cmp_message_type(pki_message)
    if not used_p10cr:
        if cert_req_id != 0:
            raise ValueError(f"The 'certReqId' MUST be 0. for body type: {body_name}")
    else:
        if cert_req_id != -1:
            raise ValueError(f"The 'certReqId' must be -1 for p10cr, but 'certReqId' was: {cert_req_id}.")


# TODO maybe support Polling or maybe auto generate Polling Request
def validate_ca_message_body(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    local_key_gen: bool = True,
    trustanchors: str = "./data/trustanchors",
    used_p10cr: bool = False,
    verbose: bool = False,
    allow_os_store: bool = True,
    expected_size: Strint = 1,
    response_index: Strint = 0,
    used_ir_as_cr: bool = False,
):
    """Validate the `ip`, `kup`, or `cp` PKIBody in a CMP message according to RFC 9483, Section 4.

    Verifies the structure and content of a CMP message's PKIBody, specifically for \
    `ip`, `kup`, or `cp` types. It ensures the message adheres to protocol rules, validates the certified key pair,
    and checks CA publications against specified trustanchors, if `caPubs` is present and allowed.

    Arguments:
    ---------
        - `pki_message`: The CMP message containing the PKIBody to validate.
        - `local_key_gen`: Indicates if the key pair was generated locally. If `True`, the `privateKey` \
        field must be absent. Defaults to `True`.
        - `trustanchors`: Path to a file or directory containing trusted CA certificates for validation.
          Defaults to `"data/trustanchors"`.
        - `used_p10cr`: Flag indicating if PKCS #10 Certificate Request was used. Defaults to `False`.
        - `verbose`: Enables verbose logging, including details about certificates in the `caPubs` field that
          are not trust anchors. Defaults to `False`.
        - `allow_os_store`: If `True`, allows the use of the OS certificate store as additional trust anchors.
          Defaults to `True`.
        - `expected_size`: The expected number of `CertResponse` entries in the `response`. Defaults to `1`.
        - `response_index`: Index of the response to check in the sequence of `response` entries. Defaults to `0`.
        - `used_ir_as_cr`: If `True`, the `caPubs` field must be absent.

    Raises:
    ------
        - `ValueError`: If the message structure or content violates protocol rules, such as:
        - `ValueError`: If the PKIMessage body is not of type `ip`, `kup`, or `cp`.
        - `ValueError`: If the response does not contain the expected number of `CertResponse` entries.
        - `ValueError`: If required fields like `certOrEncCert.certificate` or `privateKey` are improperly
        present or absent.
        - `ValueError`: If the `certifiedKeyPair` field is improperly present in a rejected message.
        - `NotImplementedError`: If polling logic is encountered (status "waiting"), which is currently unsupported.

    Examples:
    --------
    | Validate CA CMP Message Body | ${pki_message} | local_key_gen=False | trustanchors="/path/to/ca" |
    | Validate CA CMP Message Body | ${pki_message} | local_key_gen=True | trustanchors="/path/to/ca" |
    | Validate CA CMP Message Body | ${pki_message} | expected_size=2 |

    """
    body_name = pki_message["body"].getName()

    if body_name not in ["ip", "kup", "cp", "ccp"]:
        raise ValueError("Only supposed to be used on the `ip`, `kup` `ccp` or `cp` PKIBody")

    response_size = len(pki_message["body"][body_name]["response"])
    if response_size != int(expected_size):
        raise ValueError(
            "The 'response' field did not contain the expected size: "
            f"expected was: {expected_size} but got: {response_size}"
        )

    validate_certReqId(pki_message, response_index, used_p10cr)
    cert_response = cmputils.get_cert_response_from_pkimessage(pki_message, response_index)
    pki_status_info = cmputils.get_pkistatusinfo(pki_message)
    status = str(pki_status_info["status"])
    if status in ["accepted", "grantedWithMods"]:
        if pki_status_info["failInfo"].isValue:
            names = asn1utils.get_set_bitstring_names(pki_status_info["failInfo"])
            raise ValueError(f"The status was: {status}, but failinfo was set to: {names}")

        certified_key_pair: rfc9480.CertifiedKeyPair = cert_response["certifiedKeyPair"]
        if not certified_key_pair["certOrEncCert"]["certificate"].isValue:
            raise ValueError("certificate field has no Value!")

        logging.info(certified_key_pair.prettyPrint())

        validate_ca_msg_ca_pubs_field(
            pki_message=pki_message,
            trustanchors=trustanchors,
            verbose=verbose,
            allow_os_store=allow_os_store,
            used_ir_as_cr=used_ir_as_cr,
        )
        validate_certified_key_pair_structure(
            pki_message=pki_message, local_key_gen=local_key_gen, response_index=response_index
        )

    elif status == "rejection":
        if cert_response["certifiedKeyPair"].isValue:
            raise ValueError("In Case of rejection the `certifiedKeyPair` field must be absent.")

        # MAY be present if certifiedKeyPair is present.
        if pki_message["body"][body_name]["caPubs"].isValue:
            raise ValueError("'caPubs' field should not be present.")

    elif status == "waiting":
        raise NotImplementedError("Polling Logic is Unsupported! and not expected to validate a CA message!")
    else:
        raise ValueError(f"CA message got not allowed status: {status}!")


@keyword(name="Validate PKI Confirmation Message")
def validate_pki_confirmation_message(  # noqa D417 undocumented-param
    pki_conf_msg: PKIMessageTMP,
    ca_message: PKIMessageTMP,
    request: Optional[PKIMessageTMP] = None,
    allow_caching_certs: bool = True,
) -> None:
    """Validate the `pkiConf` body of a CMP PKIMessage.

    Ensures that the provided `pkiConf` PKIMessage meets expected format and content requirements by:
    - Verifying the `pkiConf` body is correctly set.
    - Checking protection consistency across related PKIMessages, including the request and response.
    - Validating the consistency of the CMP protection certificates for signature-based protection
    and checks the signature.

    For MAC-based protection, the `request` PKIMessage is required to confirm that the protection algorithm and
    parameters match. For signature-based protection, it checks that the `extraCerts` field contains the same
    certificate as the original CA response.

    Arguments:
    ---------
       - `pki_conf_msg`: The PKIMessage containing the `pkiConf` body to validate.
       - `ca_message`: The original CA PKIMessage to compare against, required to confirm protection algorithm
         and certificate consistency.
       - `request`: Optional the initial PKI request message, needed for MAC-based protection validation.
       - `allow_caching_certs`: Allows the `pkiConf` message to be valid even if `extraCerts` is missing
       Defaults to `True`.



    Raises:
    ------
       - `ValueError`: The `PKIBody` is not set to `pkiconf`.
       - `ValueError`: `extraCerts` is missing while `allow_caching_certs` is `False`.
       - `ValueError`: The Protection algorithms differ between `pkiConf` and the initial CA response message.
       - `ValueError`: `extraCerts` certificates differ between `pkiConf` and the original CA response, if required.

    Examples:
    --------
    | Check PKIMessage pkiconf | ${pki_conf_msg} | ca_message=${ca_message} | request=${request} |
    | Check PKIMessage pkiconf | ${pki_conf_msg} | ca_message=${ca_message} |
    | Check PKIMessage pkiconf | ${pki_conf_msg} | allow_caching_certs=False |

    """
    if pki_conf_msg["body"].getName() != "pkiconf":
        raise ValueError(
            f"PKIMessage does not have the `pkiConf` body set! Body Type was: {pki_conf_msg['body'].getName()}"
        )

    if not pki_conf_msg["extraCerts"].isValue:
        if allow_caching_certs:
            logging.info("The PKIMessage did not contain extraCerts.")
        else:
            raise ValueError("The `extraCerts` field is required but missing.")

    logging.warning("Header Checks are excluded for now.")

    ca_msg_type = {"ip", "cp", "rp", "kup"}
    if ca_message["body"].getName() not in ca_msg_type:
        raise ValueError(f"Expected a CA message of type: {ca_msg_type}")

    protection_type = protectionutils.get_protection_type_from_pkimessage(
        request if request is not None else ca_message
    )

    if "mac" == protection_type:
        if request is None:
            raise ValueError(
                "MAC-based protection check requires the `request` PKIMessage to verify matching algorithms."
            )
        protectionutils.mac_protection_algorithms_must_match(
            request=request,
            response=ca_message,
            pkiconf=pki_conf_msg,
        )
    else:
        protectionutils.signature_protection_must_match(ca_message, pki_conf_msg)


@keyword(name="Check For grantedWithMods")
def check_for_granted_with_mods(  # noqa D417 undocumented-param
    pki_message_response: PKIMessageTMP,
    pki_message_request: PKIMessageTMP,
    response_index: int = 0,
    include_fields: Optional[str] = None,
    exclude_fields: Optional[str] = None,
    strict_subject_validation: bool = False,
):
    """Check if the issued certificate matches the `CertTemplate` in the request and verify the `PKIStatus`.

    If any discrepancies are found between the template and issued certificate, the function checks
    if the `PKIStatus` is correctly set to `grantedWithMods`, indicating that the server issued the certificate with
    modifications as expected.

    Arguments:
    ---------
        - `pki_message_response`: The PKIMessage received from the CA, containing the issued certificate.
        - `pki_message_request`: The original PKIMessage request sent to the CA, containing the certificate template.
        - `response_index`: Optional index of the certificate response in case of multiple requests; Defaults to `0`.
        - `include_fields`: Optional comma-separated string of fields to include in the comparison.
        - `exclude_fields`: Optional comma-separated string of fields to exclude from the comparison.
        - `strict_subject_validation`: Indicates, if the subject has to be the same or needs to be contained
        inside the `subject` filed of the issued certificate.

    Raises:
    ------
        - `ValueError`: If `pki_message_response` is not a CA-issued message type (e.g., `ip`, `cp`, `kup`).
        -  `ValueError`: If `pki_message_request` is not of type `cr`, `ir`, or `kur`.
        -  `ValueError`: If the issued certificate differs from the template and the `PKIStatus` \
        is not `grantedWithMods`.
        -  `pyasn1.error.PyAsn1Error`: If the certificate and the cert template cannot be compared.

    Examples:
    --------
    | Check For grantedWithMods | ${pki_message_response} | ${pki_message_request} |

    """
    req_body_name = pki_message_request["body"].getName()
    resp_body_name = pki_message_response["body"].getName()

    if resp_body_name not in {"ip", "cp", "kup"}:
        raise ValueError(f"Not called on a CA message got body type: {pki_message_response['body'].getName()}")

    if req_body_name in {"cr", "ir", "kur"}:
        cert_template = pki_message_request["body"][req_body_name][response_index]["certReq"]["certTemplate"]
    else:
        raise ValueError(
            f"Supposed to be used if a request was `cr, ir, kur` "
            f"got body type: {pki_message_response['body'].getName()}"
        )

    issued_cert = cmputils.get_cert_from_pkimessage(pki_message_response)
    is_equal = compareutils.compare_cert_template_and_cert(
        cert_template,
        issued_cert=issued_cert,
        include_fields=include_fields,
        exclude_fields=exclude_fields,
        strict_subject_validation=strict_subject_validation,
    )

    if not is_equal:
        pki_status_info: rfc9480.PKIStatusInfo = cmputils.get_pkistatusinfo(pki_message_response)
        if "grantedWithMods" != str(pki_status_info["status"]):
            logging.info("CA responded with `PKIStatusInfo`: %s", pki_status_info.prettyPrint())
            raise ValueError(
                "The Certificate Template was different from the issued Certificate, "
                "but PKIStatus was not `grantedWithMods`!"
            )

        logging.info("`grantedWithMods` was correctly set.")


def validate_ids_and_nonces_for_nested_response(  # noqa D417 undocumented-param
    request: PKIMessageTMP, response: PKIMessageTMP
) -> None:
    """Validate transactionIDs and nonces for a nested PKIMessage response.

    Ensures that the correct size was returned and the bodies and transactionIDs, senderNonces were correctly
    parsed by the CA and the Bodies are correct options. As an example, the answer for a p10cr could be either
    "error", "cp", "pollReq".

    Arguments:
    ---------
        - `request`: The original PKIMessage request.
        - `response`: The response PKIMessage containing the nested message.

    Raises:
    ------
        - `ValueError`: If the response message `PKIBody` is not of type `nested`.
        - `ValueError`: If the size of the responses differs.
        - `ValueError`: If the transactionID or senderNonce cannot be found inside the responses or the \
         body type is incorrect.


    Examples:
    --------
    | Validate IDs and Nonces for Nested Response | request=${request_msg} | response=${response_msg} |

    """
    validate_sender_and_recipient(response, request, must_be_eq=False)

    if response["body"].getName() != "nested":
        raise ValueError("Expected the response to have a `nested` PKIBody.")

    if len(response["body"]["nested"]) != len(request["body"]["nested"]):
        raise ValueError(
            f"Different message size, the request contained: "
            f"{len(request['body'])}. The response size was: {len(response['body'])}"
        )

    req_pair: Dict[str, Tuple[bytes, bytes]] = {}
    resp_pair: Dict[Tuple[bytes, bytes], str] = {}
    for msg in response["body"]["nested"]:
        body_name = msg["body"].getName()
        resp_pair[(msg["header"]["recipNonce"].asOctets(), msg["header"]["transactionID"].asOctets())] = body_name

    for msg in request["body"]["nested"]:
        body_name = msg["body"].getName()
        req_pair[body_name] = (msg["header"]["senderNonce"].asOctets(), msg["header"]["transactionID"].asOctets())

    allowed_answer_bodies = {"p10cr": "cp", "cr": "cp", "genm": "genp", "kur": "kup", "ir": "ip"}
    always_allowed = ["error", "pollReq"]
    for body_name, tuple_data in req_pair.items():
        if tuple_data not in resp_pair:
            raise ValueError("The response nested message did not contain the response for a message.")

        if resp_pair[tuple_data] in always_allowed:
            continue

        if allowed_answer_bodies[body_name] != resp_pair[tuple_data]:
            raise ValueError(
                f"Expected to get the PKIBody type: {allowed_answer_bodies[body_name]} but got: {resp_pair[tuple_data]}"
            )


def _is_unique(lst: List[bytes]) -> bool:
    """Return True if all elements in lst are unique."""
    return len(lst) == len(set(lst))


def validate_nested_message_unique_nonces_and_ids(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    check_transaction_id: bool = True,
    check_sender_nonce: bool = True,
    check_recip_nonce: bool = True,
    check_length: bool = False,
) -> None:
    """
    Validate that the nested message has unique nonces and IDs based on specified checks.

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` to validate.
        - `check_transaction_id`: Whether to validate uniqueness of transactionID. Defaults to `True`.
        - `check_sender_nonce`: Whether to validate uniqueness of senderNonce. Defaults to `True`.
        - `check_recip_nonce`: Whether to validate uniqueness of recipNonce. Defaults to `True`.

    Raises:
    ------
        - `ValueError`: If the parsed `PKIMessage` was not a nested message.
        - `ValueError`: If any of the checks fail.

    """
    if pki_message["body"].getName() != "nested":
        raise ValueError("The parsed `PKIMessage` was not a nested message.")

    asn1utils.asn1_must_have_values_set(pki_message, "header.senderNonce, header.transactionID")
    sender_nonce = pki_message["header"]["senderNonce"].asOctets()
    id_ = pki_message["header"]["transactionID"].asOctets()
    nested_recip_nonces = []
    if not check_recip_nonce:
        if not pki_message["header"]["recipNonce"].isValue:
            logging.info("The `recipNonce` was not set for the nested `PKIMessage`.")
        else:
            recip_nonce = pki_message["header"]["recipNonce"].asOctets()
            nested_recip_nonces.append(recip_nonce)
    else:
        asn1utils.asn1_must_have_values_set(pki_message, "header.recipNonce")
        recip_nonce = pki_message["header"]["recipNonce"].asOctets()
        nested_recip_nonces.append(recip_nonce)

    ids = [id_]
    nested_sender_nonces = [sender_nonce]

    for i, msg in enumerate(pki_message["body"]["nested"]):
        if not msg["header"]["transactionID"].isValue:
            raise BadRequest(f"Nested message at index: {i} does not have a transactionID set.")

        if not msg["header"]["senderNonce"].isValue:
            raise BadSenderNonce(f"Nested message at index: {i} does not have a senderNonce set.")

        if not msg["header"]["recipNonce"].isValue and check_recip_nonce:
            raise BadRecipientNonce(f"Nested message at index: {i} does not have a recipNonce set.")

        ids.append(msg["header"]["transactionID"].asOctets())
        nested_sender_nonces.append(msg["header"]["senderNonce"].asOctets())
        if check_recip_nonce:
            nested_recip_nonces.append(msg["header"]["recipNonce"].asOctets())

    if check_transaction_id and not _is_unique(ids):
        raise BadRequest("The transactionIDs among nested messages are not unique.")
    if check_sender_nonce and not _is_unique(nested_sender_nonces):
        raise BadSenderNonce("The senderNonces among nested messages are not unique.")
    if check_recip_nonce and not _is_unique(nested_recip_nonces):
        raise BadRecipientNonce("The recipNonces among nested messages are not unique.")

    def _ensure_length(value_list: List[bytes], field_name: str, exc: Type[CMPTestSuiteError]):
        """Check if the length of the values in the list is 128 bits."""
        for val in value_list:
            if len(val) != 16:
                raise exc(f"One of the {field_name} values is not 128 bits long.")

    if check_length:
        _ensure_length(ids, "transactionID", BadRequest)
        _ensure_length(nested_sender_nonces, "senderNonce", BadSenderNonce)
        _ensure_length(nested_recip_nonces, "recipNonce", BadRecipientNonce)


def validate_add_protection_tx_id_and_nonces(  # noqa D417 undocumented-param
    request: PKIMessageTMP, check_length: bool = True
) -> None:
    """Validate if the transactionID and nonces are correctly set for the added protection request.

    The inner `PKIMessage` must contain the same `transactionID` and `senderNonce` as the outer request.

    Arguments:
    ---------
        - `request`: The `PKIMessage` to validate.
        - `check_length`: Whether to check the length of the nonces and transactionID. Defaults to `True`.

    Returns:
    -------
        - `PKIMessage`: The validated `PKIMessage`.

    Raises:
    ------
        - `ValueError`: If the `nested` body is not set, or does not contain exactly one element.
        - `BadSenderNonce`: If the `senderNonce` is not set or not 16 bytes long.
        - `BadDataFormat`: If the `transactionID` is not set.
        - `BadRequest`: If the `transactionID` is not 16 bytes long.
        - `BadRequest`: If the inner `transactionID` does not match the outer request.
        - `BadSenderNonce`: If the inner `senderNonce` does not match the outer request.
        - `BadRecipientNonce`: If the `recipNonce` is set for the added protection request.
        - `BadRecipientNonce`: If the `recipNonce` is not set for the `certConf` body.

    Examples:
    --------
    | Validate Add Protection Tx ID and Nonces | ${request} |
    | Validate Add Protection Tx ID and Nonces | ${request} | True |

    """
    nested = request["body"]["nested"]
    if not nested.isValue:
        raise ValueError("The `nested` body is not set.")
    if len(nested) != 1:
        raise ValueError("The `nested` body should contain exactly one element.")
    inner_body = nested[0]

    header = request["header"]
    if not header["senderNonce"].isValue:
        raise BadSenderNonce("The `senderNonce` is not set for the outer request.")

    if not header["transactionID"].isValue:
        raise BadDataFormat("The `transactionID` is not set for the outer request.")

    outer_tx_id = header["transactionID"].asOctets()
    inner_tx_id = inner_body["header"]["transactionID"].asOctets()
    if inner_tx_id != outer_tx_id:
        raise BadRequest("The `transactionID` does not match the inner request")

    outer_sender_nonce = header["senderNonce"].asOctets()
    inner_sender_nonce = inner_body["header"]["senderNonce"].asOctets()
    if inner_sender_nonce != outer_sender_nonce:
        raise BadSenderNonce("The `senderNonce` does not match the inner request")

    inner_body_name = inner_body["body"].getName()
    outer_recip_set = header["recipNonce"].isValue
    inner_recip_set = inner_body["header"]["recipNonce"].isValue

    if inner_body_name == "certConf":
        if not outer_recip_set:
            raise BadRecipientNonce("The `recipNonce` is not set for the outer `certConf` request.")
        if not inner_recip_set:
            raise BadRecipientNonce("The `recipNonce` is not set for the inner `certConf` body.")

        outer_recip = header["recipNonce"].asOctets()
        inner_recip = inner_body["header"]["recipNonce"].asOctets()
        if inner_recip != outer_recip:
            raise BadRecipientNonce("The `recipNonce` does not match the inner request")
        recip_nonce = outer_recip
    else:
        recip_nonce = None
        if inner_recip_set:
            raise BadRecipientNonce(f"The `recipNonce` is set for the inner {inner_body_name} body")
        if outer_recip_set:
            raise BadRecipientNonce("The `recipNonce` is set for the outer body")

    def _ensure_length(value: bytes, field_name: str, exc: Type[CMPTestSuiteError]):
        """Check if the value is 128 bits long."""
        if value is not None and len(value) != 16:
            raise exc(f"The inner `{field_name}` value is not 128 bits long.")

    if check_length:
        _ensure_length(inner_tx_id, "transactionID", BadRequest)
        _ensure_length(outer_sender_nonce, "senderNonce", BadSenderNonce)
        if recip_nonce is not None:
            _ensure_length(recip_nonce, "recipNonce", BadRecipientNonce)


def validate_cross_certification_response(  # noqa D417 undocumented-param
    ccp: PKIMessageTMP,
    verbose: bool = False,
    trustanchors: str = "./data/trustanchors",
    allow_os_store: bool = True,
):
    """Validate a Cross certification response.

    Arguments:
    ---------
        - `ccp`: The Cross Certification Response to validate.
        - `verbose`: Enables verbose logging, including details about certificates in the `caPubs` field that
            are not trust anchors. Defaults to `False`.
        - `trustanchors`: Path to a file or directory containing trusted CA certificates for validation of
        the caPubs field. Defaults to `"data/trustanchors"`.
        - `allow_os_store`: If `True`, allows the use of the OS certificate store as additional trust anchors.

    Raises:
    ------
        - `ValueError`: If the Cross Certification Response does not contain exactly one certificate.
        - `ValueError`: If the Cross Certification Response is MAC protected.
        - `BadMessageCheck`: If the Cross Certification Response does not contain `extraCerts`.
        - `ValueError`: If the Cross Certification Response does not conform to the standard.

    Examples:
    --------
    | Validate Cross Certification Response | ${ccp} | verbose=True |
    | Validate Cross Certification Response | ${ccp} | verbose=True | trustanchors="/path/to/ca" | allow_os_store=True |

    """
    entries = len(ccp["body"]["ccp"]["response"])
    if entries != 1:
        raise ValueError(f"The `ccr` body should contain exactly One certificate.Got: {entries}")

    _is_kem_based = ccp["header"]["protectionAlg"]["algorithm"] == id_KemBasedMac
    if protectionutils.get_protection_type_from_pkimessage(ccp) == "mac" or _is_kem_based:
        raise ValueError("The Cross Certification Response should be signed.Not MAC protected.")

    if not ccp["extraCerts"].isValue:
        raise BadMessageCheck("The Cross Certification Response should contain `extraCerts`.")
    validate_ca_message_body(
        ccp,
        used_p10cr=False,
        verbose=verbose,
        allow_os_store=allow_os_store,
        trustanchors=trustanchors,
        expected_size=1,
        response_index=0,
    )


def _validate_cert_conf_nonces_and_tx_id(
    request: PKIMessageTMP, response: PKIMessageTMP, check_length: bool = True
) -> None:
    """Validate the `certConf` body of a CMP PKIMessage.

    :param request: The PKIMessage containing the `certConf` body to validate.
    :param response: The PKIMessage containing the `certConf` body to validate against.
    :param check_length: Whether to check the length of the nonces and transactionID. Defaults to `True`.
    :raises ValueError: If the `certConf` body is not set or does not contain the required fields.
    :raises BadSenderNonce: If the `senderNonce` is not set or not 16 bytes long or not equal to the response.
    :raises BadRecipientNonce: If the `recipNonce` is not set or not 16 bytes long or not equal to the response.
    :raises BadDataFormat: If the `transactionID` is not equal or not 16 bytes long.
    :raises BadRequest: If the `transactionID` is not 16 bytes long.
    """
    if request["body"].getName() != "certConf":
        raise ValueError("The `PKIBody` was not a `certConf` message.")

    if not request["header"]["senderNonce"].isValue:
        raise BadSenderNonce("The `senderNonce` was not set inside the `certConf` body.")

    if not request["header"]["transactionID"].isValue:
        raise BadDataFormat("The `transactionID` was not set inside the `certConf` body.")

    if not request["header"]["recipNonce"].isValue:
        raise BadRecipientNonce("The `recipNonce` was not set inside the `certConf` body.")

    sender_nonce = request["header"]["senderNonce"].asOctets()
    tx_id = request["header"]["transactionID"].asOctets()
    recip_nonce = request["header"]["recipNonce"].asOctets()

    if check_length:
        if len(tx_id) != 16:
            raise BadRequest("The transaction ID was not 16 bytes long.")
        if len(sender_nonce) != 16:
            raise BadSenderNonce("The sender nonce was not 16 bytes long.")
        if len(recip_nonce) != 16:
            raise BadRecipientNonce("The recipient nonce was not 16 bytes long.")

    if request["header"]["recipNonce"].asOctets() != response["header"]["senderNonce"].asOctets():
        raise BadRecipientNonce("The `recipNonce` does not match the servers `senderNonce`")

    if request["header"]["transactionID"].asOctets() != response["header"]["transactionID"].asOctets():
        raise BadRequest("The `transactionID` does not match the servers `transactionID`")

    if request["header"]["senderNonce"].asOctets() != response["header"]["recipNonce"].asOctets():
        raise BadSenderNonce("The `senderNonce` does not match the servers `recipNonce`")


def validate_request_message_nonces_and_tx_id(  # noqa D417 undocumented-param
    request: PKIMessageTMP, response: Optional[PKIMessageTMP] = None
) -> None:
    """Validate the nonces and the `transactionID` of a `PKIMessage` send by a Client.

    The `transactionID` and `senderNonce` must be set, and the `recipNonce` must not be set.
    The `transactionID` and `senderNonce` must be 16 bytes long.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to validate.
        - `response`: Optional PKIMessage response to validate against.

    Raises:
    ------
        - `BadSenderNonce`: If the `senderNonce` is not set or not 16 bytes long.
        - `BadRecipientNonce`: If the `recipNonce` is set.
        - `BadDataFormat`: If the `transactionID` is not set.
        - `BadRequest`: If the `transactionID` is not 16 bytes long.

    Examples:
    --------
    | Validate Request Message Nonces and Tx ID | ${pki_message} |

    """
    if request["body"].getName() == "nested":
        raise NotImplementedError("The request message was not a nested message.")

    if request["body"].getName() == "certConf":
        if response is None:
            raise ValueError("The `response` PKIMessage must be provided for certConf validation.")
        _validate_cert_conf_nonces_and_tx_id(request=request, response=response)
        return

    if not request["header"]["senderNonce"].isValue:
        raise BadSenderNonce("The sender nonce was not set.")
    sender_nonce = request["header"]["senderNonce"].asOctets()
    if not request["header"]["transactionID"].isValue:
        raise BadDataFormat("The transaction ID was not set.")
    tx_id = request["header"]["transactionID"].asOctets()
    if request["header"]["recipNonce"].isValue:
        raise BadRecipientNonce("The recipient nonce was set.")

    if len(tx_id) != 16:
        raise BadRequest("The transaction ID was not 16 bytes long.")
    if len(sender_nonce) != 16:
        raise BadSenderNonce("The sender nonce was not 16 bytes long.")
