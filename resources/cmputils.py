# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=too-few-public-methods
"""Utilities for generating and parsing CMP-related data structures."""

import glob
import logging
import os
import random
import string
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple, Union
from urllib import parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, x448, x25519
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import base, char, constraint, namedtype, tag, univ, useful
from pyasn1.type.base import Asn1Type
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed, tagFormatSimple
from pyasn1_alt_modules import (
    rfc4210,
    rfc4211,
    rfc5280,
    rfc6402,
    rfc9480,
)
from robot.api.deco import keyword, not_keyword

from pq_logic.keys.abstract_wrapper_keys import HybridKEMPublicKey, KEMPublicKey
from pq_logic.pq_utils import get_kem_oid_from_key, is_kem_private_key
from resources import (
    asn1utils,
    certbuildutils,
    certextractutils,
    certutils,
    convertutils,
    cryptoutils,
    envdatautils,
    keyutils,
    oid_mapping,
    prepare_alg_ids,
    prepareutils,
    protectionutils,
    utils,
)
from resources.asn1_structures import CertProfileValueAsn1, KemCiphertextInfoAsn1, PKIMessagesTMP, PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.convertutils import copy_asn1_certificate, str_to_bytes
from resources.exceptions import BadAsn1Data, BadCertTemplate, BadDataFormat, BadRequest
from resources.typingutils import (
    CertObjOrPath,
    ControlsType,
    ExtensionsParseType,
    PrivateKey,
    PublicKey,
    SignKey,
    Strint,
)

# When dealing with post-quantum crypto algorithms, we encounter big numbers, which wouldn't be pretty-printed
# otherwise. This is just for cosmetic convenience.
sys.set_int_max_str_digits(0)

# from pyasn1 import debug
# debug.setLogger(debug.Debug('all'))


def _prepare_pki_header(
    sender: Union[str, rfc5280.GeneralName],
    recipient: Union[str, rfc5280.GeneralName],
    pvno: Optional[int],
    exclude_fields: set,
) -> rfc9480.PKIHeader:
    """Prepare a minimal PKIHeader for a PKIMessage, setting the sender, recipient, and protocol version.

    :param sender: The sender's name either as string or a GeneralName object.
    :param recipient: The recipient's name either as string or a GeneralName object.
    :param pvno: The protocol version number. Defaults to 2 if not provided and not omitted.
    :param exclude_fields: A set of field names to omit from the PKIHeader (e.g., {"pvno", "sender"}).
    :return: The populated `PKIHeader`.
    """
    pki_header = rfc9480.PKIHeader()
    if "pvno" not in exclude_fields:
        if pvno is None:
            pvno = 2
        pki_header["pvno"] = univ.Integer(pvno)  # type: ignore

    if "sender" not in exclude_fields:
        pki_header["sender"] = prepareutils.parse_to_general_name(sender)

    if "recipient" not in exclude_fields:
        pki_header["recipient"] = prepareutils.parse_to_general_name(recipient)

    return pki_header


def _prepare_octet_string_field(value: bytes, tag_number: int) -> univ.OctetString:
    """Prepare an OctetString field with a specific tag number.

    :param value: The value to be encoded in the OctetString.
    :param tag_number: The tag number to use for the OctetString.
    :return: A tagged OctetString.
    """
    return univ.OctetString(value).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_number))


def _prepare_sender_kid(
    sender_kid: Optional[Union[str, bytes]],
    sender: Union[str, rfc9480.GeneralName],
    default: bytes = b"CN=CloudCA-Integration-Test-User",
) -> univ.OctetString:
    """Prepare the sender KID based on the sender's name.

    :param sender_kid: The sender KID to be used.
    :param sender: The sender's name.
    :param default: The default KID to use if no common name is found.
    :return: The prepared sender KID.
    """
    if not sender_kid and isinstance(sender, str):
        sender_kid = get_common_name_from_str(sender)

    if sender_kid is None:
        sender_kid = default

    sender_kid = convertutils.str_to_bytes(sender_kid)
    return _prepare_octet_string_field(sender_kid, 2)


def _prepare_pvno(pvno: Optional[Strint], for_kga: bool, update_hash: bool, default: int = 2) -> int:
    """Prepare the protocol version number.

    :param pvno: The protocol version number.
    :param for_kga: Whether the message is for KGA.
    :param update_hash: Whether the hash was automatically updated for a
    `certConf` message.
    :param default: The default protocol version number. Defaults to `2`.
    :return: The prepared protocol version number.
    """
    for_kga = _ensure_is_bool(for_kga)
    update_hash = _ensure_is_bool(update_hash)

    if pvno is not None:
        return int(pvno)

    if update_hash or for_kga:
        return 3
    # If the message is not for KGA and no hash update is needed, use the default version.
    return default


def _ensure_is_bool(data: Union[bool, str]) -> bool:
    """Ensure that the input is a boolean value.

    :param data: The input data to check.
    :return: The boolean value of the input.
    :raises TypeError: If the input is not a boolean or a string that cannot be converted to a boolean.
    """
    # To fix invalid parsing from the Robot Framework.
    if isinstance(data, bool):
        return data
    if isinstance(data, str):
        data = data.strip()
        if data.lower() == "true":
            return True
        elif data.lower() == "false":
            return False
    raise TypeError(f"Expected a boolean or a string convertible to boolean, got {data!r}.")


@not_keyword
def prepare_pki_message(
    sender: Union[str, rfc5280.GeneralName] = "tests@example.com",
    recipient: Union[str, rfc5280.GeneralName] = "testr@example.com",
    exclude_fields: Optional[str] = None,
    transaction_id: Optional[Union[str, bytes]] = None,
    sender_nonce: Optional[bytes] = None,
    recip_nonce: Optional[bytes] = None,
    implicit_confirm: bool = False,
    recip_kid: Optional[bytes] = None,
    sender_kid: Optional[bytes] = None,
    message_time: Optional[useful.GeneralizedTime] = None,
    pki_free_text: Optional[Union[List[str], str]] = None,
    pvno: Optional[Strint] = 2,
    **kwargs,
) -> PKIMessageTMP:
    """Prepare the skeleton structure of a PKIMessage, with the body to be set later.

    :param sender: The sender's name as a string. Defaults to "tests@example.com".
    :param recipient: The recipient's name as a string. Defaults to "testr@example.com".
    :param exclude_fields: Optional str, comma-separated list of field names not to include in the resulting `PKIHeader`
                        (e.g., "transactionID,senderKID"). Defaults to None.
    :param transaction_id: A unique identifier for the transaction. Defaults to a random 16-byte value if not provided.
    :param sender_nonce: A unique value for identifying the sender. Defaults to a random 16-byte value if not provided.
    :param recip_nonce: A unique value used by the recipient to prevent replay attacks. Defaults to None.
    :param implicit_confirm: If True, adds implicit confirmation to the generalInfo field. Defaults to False.
    :param recip_kid: Key identifier for the recipient. Defaults to "CN=CloudPKI-Integration-Test".
    :param sender_kid: Key identifier for the sender. Automatically inferred based on the sender name
                       if a common name exists inside or defaults to "CN=CloudCA-Integration-Test-User".
                       Should be omitted if signature-based protection is used.
    :param message_time: The time the message was created. Defaults to the current UTC time if not provided.
    :param pvno: The protocol version number. Defaults to `2`.
    :param pki_free_text: A list of or a single text message to provide more context about the `PKIMessage`.
    :return: The `PKIMessage` with a populated header and empty body.
    """
    # Since pyasn1 does not give us a way to remove an attribute from a structure after it was added to it,
    # we proactively check whether a field should be omitted (e.g., when crafting bad inputs) and skip adding
    # it in the first place

    # exclude_fields
    to_exclude = set() if exclude_fields is None else set(exclude_fields.strip(" ").split(","))

    implicit_confirm = _ensure_is_bool(implicit_confirm)
    for_mac = _ensure_is_bool(kwargs.get("for_mac", False))

    pvno = _prepare_pvno(pvno, kwargs.get("for_kga", False), kwargs.get("update_hash", False))
    pki_header = _prepare_pki_header(sender, recipient, pvno, to_exclude)
    if "transactionID" not in to_exclude:
        transaction_value = convertutils.str_to_bytes(transaction_id or os.urandom(16))
        pki_header["transactionID"] = _prepare_octet_string_field(transaction_value, 4)

    if "senderNonce" not in to_exclude:
        pki_header["senderNonce"] = _prepare_octet_string_field(sender_nonce or os.urandom(16), 5)

    if "recipNonce" not in to_exclude and recip_nonce:
        pki_header["recipNonce"] = _prepare_octet_string_field(recip_nonce, 6)

    # SHOULD NOT be required
    if "messageTime" not in to_exclude:
        if message_time is None:
            # the date is not correctly converted, so that it could happen for test cases,
            # that the messageTime is in the future. So a slightly older time is used
            date_time = datetime.now(timezone.utc) - timedelta(seconds=3)
            message_time = useful.GeneralizedTime().fromDateTime(date_time)

        msg_time_obj = prepareutils.convert_to_generalized_time(
            message_time,
        )

        message_time_subtyped = msg_time_obj.subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 0))
        pki_header["messageTime"] = message_time_subtyped

    if "senderKID" not in to_exclude:
        # Changes the value for MAC-based protection automatically, if the sender is a string.
        pki_header["senderKID"] = _prepare_sender_kid(sender_kid, sender, default=b"CN=CloudCA-Integration-Test-User")

    if "recipKID" not in to_exclude:
        pki_header["recipKID"] = _prepare_octet_string_field(recip_kid or b"CN=CloudPKI-Integration-Test", 3)

    if "generalInfo" not in to_exclude and implicit_confirm:
        pki_header["generalInfo"] = _prepare_generalinfo(implicit_confirm=implicit_confirm)

    if "freeText" not in to_exclude:
        # This freeText attribute bears no functionality, but we include it here for the sake of
        # having a complete example of a PKIHeader structure
        free_text = rfc9480.PKIFreeText().subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 7))
        pki_header["freeText"] = _prepare_pki_free_text(texts=pki_free_text, target=free_text)

    # PKIMessage
    pki_message = PKIMessageTMP()
    pki_message["header"] = pki_header

    if for_mac:
        try:
            if not isinstance(sender, str):
                raise TypeError("Sender must be a string for MAC-based protection.")

            if "sender" not in to_exclude:
                pki_message = patch_sender(pki_message, sender_name=sender)

            if "sender_kid" not in to_exclude:
                pki_message = patch_senderkid(pki_message, for_mac=True)
        except Exception as e:
            raise ValueError("Could not prepare the sender and senderKID for MAC protected message.") from e

    return pki_message


@keyword(name="Build CMP Error Message")
def build_cmp_error_message(  # noqa D417 undocumented-param
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    status: str = "rejection",
    failinfo: Optional[str] = None,
    texts: Optional[Union[List[str], str]] = None,
    error_texts: Optional[Union[List[str], str]] = None,
    error_code: Strint = 1,
    **params,
) -> PKIMessageTMP:
    """Build a `PKIMessage` with an error-type body, setting relevant status and failure info.

    Arguments:
    ---------
        - `sender`: The sender of the request. Defaults to "test-cmp-cli@example.com".
        - `recipient`: The recipient of the request. Defaults to "test-cmp-srv@example.com".
        - `exclude_fields`: A comma-separated list of field names to exclude from the PKIMessage
        header. Defaults to `None`.
        - `status`: The status of the error, typically "rejection". Defaults to "rejection".
        - `failinfo`: Additional failure information to include in the error status. Used when `status` is not
        "accepted".
        - `texts`: A list of or a single text message to provide more context about the error.
        - `error_code`: The error code to include inside the `errorCode` field.
        - `error_texts`: A list of or a single text message to provided additional information.
        - **params to set `PKIHeader` fields.


    Returns:
    -------
        - The `PKIMessage` with the `error` body type populated, including status and failure info.

    Examples:
    --------
    | ${error_message}= | Build CMP Error Message | sender="test_sender@example.com" | recipient="error_recipient" |
    | ${error_message}= | Build CMP Error Message | failinfo=badAlg | recipient="error_recipient" |

    """
    err_body = rfc9480.ErrorMsgContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 23))

    err_body["pKIStatusInfo"] = prepare_pkistatusinfo(status=status, failinfo=failinfo, texts=texts)

    err_body["errorCode"] = univ.Integer(int(error_code))
    if error_texts is not None:
        err_body["errorDetails"] = _prepare_pki_free_text(texts=error_texts)
    pki_body = rfc9480.PKIBody()
    pki_body["error"] = err_body

    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        transaction_id=params.get("transaction_id"),
        sender_nonce=params.get("sender_nonce"),
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=int(params.get("pvno", 2)),
    )

    pki_message["body"] = pki_body

    return pki_message


@keyword(name="Prepare PKIStatusInfo")
def prepare_pkistatusinfo(  # noqa D417 undocumented-param
    status: str,
    failinfo: Optional[str] = None,
    texts: Optional[Union[List[str], str]] = "This text is free, so let us have it",
) -> rfc9480.PKIStatusInfo:
    """Create a `PKIStatusInfo` object with optional failure information and status text.

    Used to structure error messages in PKI exchanges, enabling specific status and failinfo fields.

    Arguments:
    ---------
        - `status`: Human-readable representation of the PKI status.
        - `failinfo`: Optional comma-separated names representing failure info, such as `badRequest`.
        Defaults to `None`.
        - `texts`: A list of or a single text used for the `PKIStatusText` structure. Defaults to
        `"This text is free, so let us have it"`.

    Returns:
    -------
        - The populated `PKIStatusInfo` structure.

    Examples:
    --------
    | ${pki_status_info}= | Prepare PKIStatusInfo | status=rejection | failinfo=badRequest |
    | ${pki_status_info}= | Prepare PKIStatusInfo | status=accepted |

    """
    pki_status_info = rfc9480.PKIStatusInfo()
    pki_status_info["status"] = rfc9480.PKIStatus(status)

    if failinfo is not None:
        pki_status_info["failInfo"] = rfc9480.PKIFailureInfo(failinfo)

    if texts is not None:
        pki_status_info["statusString"] = _prepare_pki_free_text(texts=texts)

    return pki_status_info


def _prepare_pki_free_text(
    texts: Optional[Union[List[str], str]] = None,
    target: Optional[rfc9480.PKIFreeText] = None,
) -> rfc9480.PKIFreeText:
    """Prepare a `PKIFreeText` structure for use in PKI messages.

    :param texts: A list or a single text to include.
    :param target: An existing `PKIFreeText` object to append text to, if specified.
    :return: A `PKIFreeText` structure with the specified text(s) for PKI messages.
    """
    if target is None:
        target = rfc9480.PKIFreeText()

    if texts:
        texts = utils.ensure_list(texts)
        for x in texts:
            target.append(char.UTF8String(x))

    return target


@keyword(name="Build P10cr From Key")
def build_p10cr_from_key(  # noqa D417 undocumented-param
    key: SignKey,
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    **params,
) -> PKIMessageTMP:
    """Create a `p10cr` (PKCS#10 Certificate Request) `PKIMessage` from a private key.

    Builds a PKIMessage of type `p10cr` by embedding the provided private key and setting up
    the necessary PKIHeader fields. The message can be customized with additional parameters
    for transaction and nonce handling.

    Arguments:
    ---------
        - `csr`: The `pyasn1` PKCS#10 CSR used to populate the `p10cr` body.
        - `sender`: The sender of the request. Defaults to "test-cmp-cli@example.com".
        - `recipient`: The recipient of the request. Defaults to "test-cmp-srv@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `None`.
        `**params`: Additional parameters setting the `PKIHeader`

    **params:
    --------
       - `spki` (SubjectPublicKeyInfo): The SPKI structure to use instead of generating it from the key. \
       Defaults to `None`.
       - `common_name` (str): The common name to use for the CSR subject. Defaults to `CN=Hans Mustermann`.
       - `hash_alg` (str): The hash algorithm to use for the SPKI and CSR signing. Defaults to "sha256".
       - `use_rsa_pss` (bool): If `True`, uses RSA-PSS for the signature and SPKI. Defaults to `False`.
       - `use_pre_hash` (bool): If `True`, uses pre-hashed version for composite-sig keys. Defaults to `False`.
       - `bad_pop` (bool): If True, prepares a bad proof-of-possession for the CSR. Defaults to `False`.
       - `extensions` (Sequence[Extension]): A list of Extension's or `Extensions` object to include. \
       Defaults to `None`.

    Returns:
    -------
        - The constructed PKIMessage with the `p10cr` body type.

    Examples:
    --------
    | ${pki_message}= | Build P10cr From Key | ${key} |
    | ${pki_message}= | Build P10cr From Key | ${key} | ${sender}="CN=Hans Mustermann" |
    | ${pki_message}= | Build P10cr From Key | ${key} | exclude_fields=messageTime,senderNonce |

    """
    spki = params.get("spki", None)
    if spki is None:
        spki = keyutils.prepare_subject_public_key_info(
            key=key,
            hash_alg=params.get("hash_alg", "sha256"),
            use_rsa_pss=params.get("use_rsa_pss", False),
            use_pre_hash=params.get("use_pre_hash", False),
        )

    csr = certbuildutils.build_csr(
        signing_key=key,
        common_name=params.get("common_name", "CN=Hans Mustermann"),
        bad_pop=params.get("bad_pop", False),
        spki=spki,
        hash_alg=params.get("hash_alg", "sha256"),
        use_rsa_pss=params.get("use_rsa_pss", False),
        use_pre_hash=params.get("use_pre_hash", False),
        extensions=params.get("extensions", None),
    )
    return build_p10cr_from_csr(
        csr=csr,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


@keyword(name="Build P10cr From CSR")
def build_p10cr_from_csr(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest,
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    **params,
):
    """Create a `p10cr` (PKCS#10 Certificate Request) `PKIMessage` from a `pyasn1` PKCS#10 CSR.

    Builds a PKIMessage of type `p10cr` by embedding the provided PKCS#10
    Certification Request (CSR) and setting up the necessary PKIHeader fields. The message
    can be customized with additional parameters for transaction and nonce handling.

    Arguments:
    ---------
        - `csr`: The `pyasn1` PKCS#10 CSR used to populate the `p10cr` body.
        - `sender`: The sender of the request. Defaults to "test-cmp-cli@example.com".
        - `recipient`: The recipient of the request. Defaults to "test-cmp-srv@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `None`.
        `**params`: Additional parameters setting the `PKIHeader`

    Returns:
    -------
        - The constructed PKIMessage with the `p10cr` body type.

    Examples:
    --------
    | ${pki_message}= | Build P10cr From CSR | ${csr} | sender=custom_sender@example.com |
    | ${pki_message}= | Build P10cr From CSR | ${csr} | exclude_fields=messageTime,senderNonce |
    | ${pki_message}= | Build P10cr From CSR | ${csr} | transaction_id=${transaction_id} | sender_nonce=${nonce} |
    | ${pki_message}= | Build P10cr From CSR | ${csr} | implicit_confirm=True |

    """
    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        transaction_id=params.get("transaction_id"),
        sender_nonce=params.get("sender_nonce"),
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=int(params.get("pvno", 2)),
        for_mac=params.get("for_mac", False),
        message_time=params.get("message_time"),
    )

    # Prepare PKIBody of type p10cr
    pki_body = rfc9480.PKIBody()
    # pki_body["p10cr"]["certificationRequestInfo"]["version"] = univ.Integer(0)
    pki_body["p10cr"]["certificationRequestInfo"] = csr["certificationRequestInfo"]
    pki_body["p10cr"]["signatureAlgorithm"] = csr["signatureAlgorithm"]
    pki_body["p10cr"]["signature"] = csr["signature"]

    pki_message["body"] = pki_body
    return pki_message


@keyword(name="Prepare OldCertId Control")
def prepare_old_cert_id_control(
    cert: Optional[rfc9480.CMPCertificate] = None,
    serial_number: Optional[int] = None,
    issuer: Optional[str] = None,
    inc_serial_number: bool = False,
    bad_issuer: bool = False,
) -> rfc4211.AttributeTypeAndValue:
    """Prepare an `OldCertId` structure for use in CMP controls.

    :param cert: An optional certificate from which the issuer and serial number are extracted.
    :param issuer: The issuer's distinguished name in OpenSSL notation.
    :param serial_number: The serial number of the certificate.
    :param inc_serial_number: Whether to increment the serial number by 1.
    :param bad_issuer: If True, the issuer will be modified to be invalid.
    :return: The `OldCertId` structure with the specified issuer and serial number.
    """
    if cert is None and not (serial_number and issuer):
        raise ValueError("Either a valid certificate or both `serial_number` and `issuer` must be specified.")

    ser_num = serial_number or int(cert["tbsCertificate"]["serialNumber"])  # type: ignore
    if inc_serial_number:
        ser_num += 1

    if cert is not None:
        cert_issuer = utils.get_openssl_name_notation(cert["tbsCertificate"]["issuer"])  # type: ignore
        cert_issuer: Optional[str]
    else:
        cert_issuer = None

    if bad_issuer and cert is None:
        raise ValueError("A valid certificate must be provided when `bad_issuer` is True.")

    if bad_issuer:
        issuer = certbuildutils.modify_common_name_cert(
            cert=cert,  # type: ignore
            issuer=True,
        )

    if issuer is None and cert_issuer is None:
        raise ValueError("Either a valid certificate or an issuer must be provided.")

    _issuer_name = issuer or cert_issuer  # type: ignore
    _issuer_name: str
    issuer_name = prepareutils.prepare_general_name(
        name_type="directoryName",
        name_str=_issuer_name,
    )

    old_cert_id = rfc4211.OldCertId()
    old_cert_id["issuer"] = issuer_name
    old_cert_id["serialNumber"] = ser_num

    attr_instance = rfc4211.AttributeTypeAndValue()
    attr_instance["type"] = rfc4211.id_regCtrl_oldCertID
    attr_instance["value"] = old_cert_id

    return attr_instance


@keyword(name="Add regInfo To PKIMessage")
def add_reg_info_to_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    request_infos: Union[rfc4211.AttributeTypeAndValue, List[rfc4211.AttributeTypeAndValue]],
    cert_req_index: Optional[Strint] = 0,
) -> PKIMessageTMP:
    """Add request information to a PKIMessage for a specific certificate request message.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to which the controls will be added.
        - `controls`: The controls to add. Can be a `Controls` structure or an `AttributeTypeAndValue`.
        - `cert_req_index`: The index of the certificate request. Defaults to `0`.
        if set to `None`, will be set for all requests.

    Returns:
    -------
        - The updated PKIMessage with the controls added.

    Raises:
    ------
        - `ValueError`: If the body type of the PKIMessage is not valid for adding controls.

    Examples:
    --------
    | ${pki_message}= | Add Controls To PKIMessage | ${pki_message} | controls=${controls} |

    """
    if isinstance(request_infos, rfc4211.AttributeTypeAndValue):
        request_infos = [request_infos]

    body_name = pki_message["body"].getName()
    if body_name not in ["ir", "cr", "kur", "ccr"]:
        raise ValueError(
            f"Invalid body type for adding controls: {pki_message['body'].getName()}."
            f"Expected 'ir', 'cr', 'kur', or 'ccr'."
        )

    if cert_req_index is not None:
        cert_req_msg = pki_message["body"][body_name][int(cert_req_index)]
        cert_req_msg: rfc4211.CertReqMsg
        cert_req_msg["regInfo"].extend(request_infos)
    else:
        for entry in pki_message["body"][body_name]:
            entry: rfc4211.CertReqMsg
            entry["regInfo"].extend(request_infos)

    return pki_message


@keyword(name="Add Controls To PKIMessage")
def add_controls_to_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    controls: Union[rfc4211.Controls, rfc4211.AttributeTypeAndValue, List[rfc4211.AttributeTypeAndValue]],
    cert_req_index: Optional[Strint] = 0,
) -> PKIMessageTMP:
    """Add controls to a PKIMessage for a specific certificate request.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to which the controls will be added.
        - `controls`: The controls to add. Can be a `Controls` structure or an `AttributeTypeAndValue`.
        - `cert_req_index`: The index of the certificate request. Defaults to `0`.
        if set to `None`, will be set for all requests.

    Returns:
    -------
        - The updated PKIMessage with the controls added.

    Raises:
    ------
        - `ValueError`: If the body type of the PKIMessage is not valid for adding controls.

    Examples:
    --------
    | ${pki_message}= | Add Controls To PKIMessage | ${pki_message} | controls=${controls} |

    """
    if isinstance(controls, rfc4211.AttributeTypeAndValue):
        controls = [controls]

    body_name = pki_message["body"].getName()
    if body_name not in ["ir", "cr", "kur", "ccr"]:
        raise ValueError(
            f"Invalid body type for adding controls: {pki_message['body'].getName()}."
            f"Expected 'ir', 'cr', 'kur', or 'ccr'."
        )

    if cert_req_index is not None:
        cert_req_msg = pki_message["body"][body_name][int(cert_req_index)]["certReq"]
        cert_req_msg: rfc4211.CertRequest
        cert_req_msg["controls"].extend(controls)
    else:
        for entry in pki_message["body"][body_name]:
            entry: rfc4211.CertReqMsg
            entry["certReq"]["controls"].extend(controls)

    return pki_message


@keyword(name="Add Extension To PKIMessage")
def add_extensions_to_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    extension: ExtensionsParseType,
    cert_req_index: Optional[Strint] = 0,
) -> PKIMessageTMP:
    """Add `Extension` objects to a PKIMessage for a specific certificate request.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to which the extension will be added.
        - `extension`: The extension to be added to a certificate template. \
        Can be a single `Extension` object or a list of `Extension` objects.
        - `cert_req_index`: The index of the certificate request, if set to `None`,
        will be set for all requests. Defaults to `0`.

    Returns:
    -------
        - The updated PKIMessage with the extension(s) added.

    Raises:
    ------
        - `ValueError`: If the body type of the PKIMessage is not valid for adding extensions.

    Examples:
    --------
    | ${pki_message}= | Add Extension To PKIMessage | ${pki_message} | extension=${extension} |

    """
    if isinstance(extension, rfc5280.Extension):
        extension = [extension]

    body_name = pki_message["body"].getName()
    if body_name not in ["ir", "cr", "kur", "ccr"]:
        raise ValueError(
            f"Invalid body type for adding controls: {pki_message['body'].getName()}."
            f"Expected 'ir', 'cr', 'kur', or 'ccr'."
        )

    if cert_req_index is not None:
        cert_request = pki_message["body"][body_name][int(cert_req_index)]["certReq"]
        cert_request: rfc4211.CertRequest
        cert_request["certTemplate"]["extensions"].extend(extension)
    else:
        for entry in pki_message["body"][body_name]:
            entry: rfc4211.CertReqMsg
            entry["certReq"]["certTemplate"]["extensions"].extend(extension)

    return pki_message


@keyword(name="Update POPO")
def update_popo(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    cert_req_index: Strint = 0,
    signing_key: Optional[SignKey] = None,
    popo: Optional[rfc4211.ProofOfPossession] = None,
    **kwargs,
) -> PKIMessageTMP:
    """Update the signature proof-of-possession (POPO) in a PKIMessage.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to update.
        - `cert_req_index`: The index of the certificate request. Defaults to `0`.
        - `signing_key`: The private key used for signing. If not provided, a new POPO will be generated.
        - `popo`: An optional existing POPO to use. If not provided, a new one will be generated.
        - `**kwargs`: Additional arguments for the signature preparation.

    Returns:
    -------
        - The updated PKIMessage with the new signature POPO.

    """
    if popo is None and signing_key is None:
        raise ValueError("Either `signing_key` or `popo` must be provided.")

    body_name = pki_message["body"].getName()

    if body_name not in ["ir", "cr", "kur", "ccr"]:
        raise ValueError(
            f"Invalid body type for adding controls: {pki_message['body'].getName()}."
            f"Expected 'ir', 'cr', 'kur', or 'ccr'."
        )

    if popo is None:
        cert_request = pki_message["body"][body_name][int(cert_req_index)]["certReq"]
        popo = prepare_signature_popo(
            cert_request=cert_request,
            signing_key=signing_key,  # type: ignore
            **kwargs,
        )

    pki_message["body"][body_name][int(cert_req_index)]["popo"] = popo
    return pki_message


@keyword(name="Prepare Controls Structure")
def prepare_controls_structure(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    serial_number: Optional[int] = None,
    issuer: Optional[str] = None,
    controls: Optional[Sequence[rfc9480.AttributeTypeAndValue]] = None,
) -> rfc9480.Controls:
    """Prepare a `pyasn1` Controls structure for a key update request.

    Constructs the `Controls` structure, which is recommended when sending a
    key update request (e.g., for certificate renewal or rekeying). It allows specifying
    either an existing certificate from which the issuer and serial number will be extracted,
    or the issuer and serial number can be provided directly as arguments.

    Arguments:
    ---------
        - `cert`: An optional certificate from which the issuer and serial number are extracted.
                  Used to set the values if `issuer` and `serial_number` are not provided. Defaults to `None`.
        - `serial_number`: The serial number of the certificate. Defaults to `None`.
        - `issuer`: The issuer's distinguished name in OpenSSL notation (e.g., "C=DE, ST=Bavaria,
          L=Munich, CN=CA Name"). Defaults to `None`.

    Returns:
    -------
        - A `Controls` structure populated with the specified issuer and serial number.

    Raises:
    ------
        - `ValueError`: If neither a valid certificate nor both `issuer` and `serial_number` are provided.

    Examples:
    --------
    | ${controls}= | Prepare Controls Structure | cert=${certificate} |
    | ${controls}= | Prepare Controls Structure | issuer=${issuer} | serial_number=12345 |

    """
    if not cert and not (serial_number is not None and issuer) and controls is None:
        raise ValueError(
            "Either a valid certificate must be provided, or both `serial_number` and `issuer` must be specified."
        )

    if isinstance(controls, rfc9480.AttributeTypeAndValue):
        controls = [controls]
    if controls is None:
        controls = []
    if cert is not None or (serial_number is not None and issuer):
        old_cert_id = prepare_old_cert_id_control(cert=cert, serial_number=serial_number, issuer=issuer)
        controls.append(old_cert_id)  # type: ignore

    control_instance = rfc9480.Controls()
    control_instance.extend(controls)
    return control_instance


# RFC4210bis-16 Section 5.2.6 Archive Options


@keyword(name="Prepare PKIArchiveOptions Controls")
def prepare_pkiarchiveoptions_controls(
    enc_key: Optional[Union[rfc9480.EnvelopedData, rfc4211.EncryptedValue]] = None,
    key_gen_params: Optional[bytes] = None,
    private_key: Optional[PrivateKey] = None,
    password: Optional[Union[str, bytes]] = None,
    use_archive_flag: bool = False,
) -> rfc4211.AttributeTypeAndValue:
    """Prepare the PKIArchiveOptions structure, to be used inside the Controls structure.

    Requesters may indicate that they wish the PKI to archive a private key value using the
    PKIArchiveOptions structure.

    :return: A populated `AttributeTypeAndValue` structure.
    """
    if (
        enc_key is None
        and key_gen_params is None
        and private_key is None
        and password is None
        and use_archive_flag is None
    ):
        raise ValueError(
            "At least one of `enc_key`, `key_gen_params`, `private_key`, "
            "`password` or `use_archive_flag` must be provided."
        )

    attr = rfc4211.AttributeTypeAndValue()
    attr["type"] = rfc4211.id_regCtrl_pkiArchiveOptions

    archive_options = rfc4211.PKIArchiveOptions()

    if enc_key is not None:
        if isinstance(enc_key, rfc9480.EnvelopedData):
            option = "envelopedData"
        else:
            option = "encryptedValue"
        archive_options["encryptedPrivKey"][option] = enc_key
    elif key_gen_params is not None or private_key is not None:
        if key_gen_params is None:
            key_gen_params = keyutils.private_key_to_private_numbers(
                private_key=private_key  # type: ignore
            )
        archive_options["keyGenParameters"] = key_gen_params

    elif password is not None and private_key is not None:
        private_key_data = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        archive_options["encryptedPrivKey"]["envelopedData"] = envdatautils.prepare_enveloped_data_with_pwri(
            data=private_key_data,
            password=password,
        )

    elif password is not None and private_key is None:
        raise ValueError("`private_key` must be provided when `password` is used.")

    else:
        archive_options["archiveRemGenPrivKey"] = use_archive_flag

    attr["value"] = archive_options

    return attr


def _validate_key_gen_params(  # noqa D417 undocumented-param,
    key_gen_params: rfc4211.KeyGenParameters,
    cert_template: Optional[rfc4211.CertTemplate],
) -> PrivateKey:
    """Validate the key generation parameters.

    :param key_gen_params: The key generation parameters to validate.
    :param cert_template: The certificate template to use for validation.
    :return: The private key generated from the key generation parameters.
    :raises BadAlg: If the key generation parameters are not valid.
    """
    if cert_template is None:
        raise ValueError("Certificate template needs to be provided, if the keyGenParameters are used.")

    public_key = keyutils.load_public_key_from_cert_template(cert_template, must_be_present=True)
    key_name = keyutils.get_key_name(public_key)  # type: ignore

    key_gen_data = key_gen_params.asOctets()

    curve = None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_gen_data = int.from_bytes(key_gen_data, "big")
        key_name = "ecc"
        curve = public_key.curve.name
    try:
        private_key = keyutils.generate_key(key_name, seed=key_gen_data, curve=curve)
    except ValueError as e:
        raise BadAsn1Data("KeyGenParameters") from e

    if private_key.public_key() != public_key:
        raise BadCertTemplate("The public key does not match the private from the key generation parameters.")

    return private_key


def validate_archive_options(  # noqa D417 undocumented-param
    controls: rfc9480.Controls,
    must_be_present: bool = False,
    cert_template: Optional[rfc4211.CertTemplate] = None,
) -> Optional[Union[rfc9480.EncryptedKey, PrivateKey]]:
    """Validate the PKIArchiveOptions structure, to be used inside the Controls structure.

    Arguments:
    ---------
        - `controls`: The controls to validate.
        - `must_be_present`: Whether the archive options must be present.
        - `cert_template`: The certificate template to use for validation. Defaults to `None`.

    Returns:
    -------
        - The `EncryptedKey` structure if present, otherwise `None`.

    Raises:
    ------
        - `ValueError`: If the archive options are not present and `must_be_present` is True.
        - `NotImplementedError`: If the keyGenParameters option is present.
        - `BadAsn1Data`: If the PKIArchiveOptions contains trailing data.

    Examples:
    --------
    | ${archive_options}= | Validate Archive Options | ${controls} |
    | ${archive_options}= | Validate Archive Options | ${controls} | must_be_present=True |

    """
    found = False
    archive_options = None
    for entry in controls:
        if entry["type"] == rfc4211.id_regCtrl_pkiArchiveOptions:
            archive_options = entry["value"].asOctets()
            found = True
            break

    if not found and must_be_present:
        raise ValueError("Missing PKIArchiveOptions in controls.")

    if not found:
        return None

    archive_options, rest = decoder.decode(archive_options, rfc4211.PKIArchiveOptions())
    if rest:
        raise BadAsn1Data("PKIArchiveOptions contains trailing data.", overwrite=True)

    option = archive_options.getName()
    if option == "encryptedPrivKey":
        return archive_options["encryptedPrivKey"]
    if option == "keyGenParameters":
        private_key = _validate_key_gen_params(
            key_gen_params=archive_options["keyGenParameters"],
            cert_template=cert_template,
        )
        return private_key
    if option == "archiveRemGenPrivKey":
        logging.info("PKIArchiveOptions: archiveRemGenPrivKey was: %s", str(archive_options["archiveRemGenPrivKey"]))

    return None


@keyword(name="Prepare regToken Controls")
def prepare_reg_token_controls(  # noqa D417 undocumented-param
    token: str,
) -> rfc4211.AttributeTypeAndValue:
    """Prepare the regToken control, to be used inside the Controls structure.

    Only used for initialization of an end entity into the PKI, to verify the identity of the subject.

    Arguments:
    ---------
        - `token`: The registration token to include in the control.

    Returns:
    -------
        - The populated `AttributeTypeAndValue` structure.

    Examples:
    --------
    | ${attr_value}= | Prepare regToken Controls | token="0x123456" |

    """
    # A regToken control contains one-time information (either based on a
    #    secret value or other shared information) intended to be used by the
    #    CA to verify the identity of the subject prior to issuing a
    #    certificate.

    # The regToken control is used only for initialization of an end entity
    #    into the PKI, whereas the authenticator control (see section 7.2 RFC4211) can
    #    be used for the initial as well as subsequent certification requests.

    attr = rfc4211.AttributeTypeAndValue()
    attr["type"] = rfc4211.id_regCtrl_regToken
    attr["value"] = rfc4211.RegToken(token)

    return attr


@keyword(name="Validate regToken Control")
def validate_reg_token_control(  # noqa D417 undocumented-param
    controls: rfc9480.Controls,
    must_be_present: bool = False,
    expected_token: Optional[str] = None,
) -> Optional[rfc4211.RegToken]:
    """Validate the regToken control, to be used inside the Controls structure.

    Arguments:
    ---------
        - `controls`: The controls to validate.
        - `must_be_present`: Whether the regToken control must be present.
        - `expected_token`: The expected token to compare with the actual token.

    Returns:
    -------
        - The `RegToken` structure if present, otherwise `None`.

    Raises:
    ------
        - `ValueError`: If the regToken control is not present and `must_be_present` is True.
        - `BadRequest`: If the expected token does not match the actual token.

    Examples:
    --------
    | ${reg_token}= | Validate req_token Control | ${controls} |
    | ${reg_token}= | Validate req_token Control | ${controls} | must_be_present=True |

    """
    der_data = None
    for entry in controls:
        if entry["type"] == rfc4211.id_regCtrl_regToken:
            der_data = entry["value"].asOctets()
            break

    if der_data is None and must_be_present:
        raise ValueError("Missing `regToken` in controls.")

    if der_data is None:
        return None

    _check_unique_controls(controls)

    reg_token, rest = try_decode_pyasn1(der_data, rfc4211.RegToken())  # type: ignore
    reg_token: rfc4211.RegToken

    if rest:
        raise BadAsn1Data("RegToken")

    reg_token_str = reg_token.prettyPrint()

    if expected_token is not None:
        if reg_token_str != expected_token:
            raise BadRequest(f"Expected regToken: {expected_token}, but got: {reg_token_str}.")

    return reg_token_str


def prepare_authenticator_control(  # noqa D417 undocumented-param
    auth_info: Union[str, bytes],
) -> rfc4211.AttributeTypeAndValue:
    """Prepare the authorization control, to be used inside the Controls structure.

    Used for the initial certificate request or on-going request to the CA.

    The authenticator control contains information used on an ongoing basis to establish a
    non-cryptographic check of identity in communication with the CA.
    Examples: the hash of the mother's maiden name.
    For more information see RFC4211 Section 6.2.

    Arguments:
    ---------
        - `auth_info`: The authorization information.

    Returns:
    -------
        - The populated `AttributeTypeAndValue` structure.

    Examples:
    --------
    | ${auth_controls}= | Prepare Authorization Control | auth_info="0x123456" |

    """
    if isinstance(auth_info, bytes):
        auth_info = "0x" + auth_info.hex()

    attr = rfc4211.AttributeTypeAndValue()
    attr["type"] = rfc4211.id_regCtrl_authenticator
    attr["value"] = rfc4211.Authenticator(auth_info)
    return attr


def validate_authenticator_control(  # noqa D417 undocumented-param
    controls: Sequence[rfc9480.AttributeTypeAndValue],
    must_be_present: bool = False,
    expected_auth_info: Optional[str] = None,
) -> Optional[rfc4211.Authenticator]:
    """Validate the authorization control, to be used inside the Controls structure.

    Arguments:
    ---------
        - `controls`: The controls to validate.
        - `must_be_present`: Whether the authorization control must be present.
        - `expected_auth_info`: The expected authorization information to compare with the actual information.

    Returns:
    -------
        - The `Authenticator` structure if present, otherwise `None`.

    Raises:
    ------
        - `ValueError`: If the authorization control is not present and `must_be_present` is True.
        - `BadRequest`: If the expected authorization information does not match the actual information.

    Examples:
    --------
    | ${auth_info}= | Validate Authorization Control | ${controls} |
    | ${auth_info}= | Validate Authorization Control | ${controls} | must_be_present=True |

    """
    der_data = None
    for entry in controls:
        if entry["type"] == rfc4211.id_regCtrl_authenticator:
            der_data = entry["value"].asOctets()
            break

    if der_data is None and must_be_present:
        raise ValueError("Missing authenticator in controls.")

    if der_data is None:
        return None

    _check_unique_controls(controls)

    auth_info, rest = try_decode_pyasn1(der_data, rfc4211.Authenticator())  # type: ignore
    auth_info: rfc4211.Authenticator

    if rest:
        raise BadAsn1Data("Authenticator")

    auth_info_str = auth_info.prettyPrint()

    if expected_auth_info is not None:
        if auth_info_str != expected_auth_info:
            raise BadRequest(f"Expected authenticator: {expected_auth_info}, but got: {auth_info_str}.")

    return auth_info_str


def prepare_single_publication_info(  # noqa D417 undocumented-param
    pub_method: str,
    pub_location: Optional[str] = None,
) -> rfc4211.SinglePubInfo:
    """Prepare the SinglePubInfo structure, to be used inside the PKIPublicationInfo structure.

    `badMethode` can be used for negative testing.

    Arguments:
    ---------
        - `pub_method`: The publication method to use (e.g., "dontCare", "x500", "web", \
        "ldap", "badMethod"). Defaults to `None`.
        - `pub_location`: The publication location. Defaults to `None`.

    Returns:
    -------
        - The populated `SinglePubInfo` structure.

    Raises:
    ------
        - `ValueError`: If `pub_method` is not one of "dontCare", "x500", "web", "ldap", "badMethod".

    Examples:
    --------
    | ${single_pub_info}= | Prepare Single Publication Info | pub_method=x500 | pub_location="https://example.com" |

    """
    single_pub_info = rfc4211.SinglePubInfo()
    options = {"dontCare": 0, "x500": 1, "web": 2, "ldap": 3, "badMethod": 4}
    if pub_method not in options:
        raise ValueError(f"Invalid pub_method: {pub_method}. Must be one of {options.keys()}")
    single_pub_info["pubMethod"] = options[pub_method]

    if pub_location is not None:
        single_pub_info["pubLocation"] = prepareutils.prepare_general_name("uri", pub_location)

    return single_pub_info


# RFC4210bis-16 Section 5.2.7. Publication Information or RFC4211 Section 6.3


@keyword(name="Prepare PKIPublicationInformation Control")
def prepare_pki_publication_information_control(  # noqa D417 undocumented-param
    action: str = "pleasePublish",
    pub_method: Optional[str] = None,
    pub_location: Optional[str] = None,
    entries: Optional[Union[Sequence[rfc4211.SinglePubInfo], rfc4211.SinglePubInfo]] = None,
) -> rfc4211.AttributeTypeAndValue:
    """Prepare the PKIPublicationInfo structure, to be used inside the Controls structure.

    Requesters may indicate that they wish the PKI to publish a certificate using the
    PKIPublicationInfo structure.

    Arguments:
    ---------
        - `action`: The action to take, either "dontPublish" or "pleasePublish" or "badAction"
        for negative testing. Defaults to `pleasePublish`.
        - `pub_method`: The publication method to use (e.g., "x500", "web", "ldap"). Defaults to `None`.
        - `pub_location`: The publication location (will be prepared as a `GeneralName` uri). Defaults to `None`.

    Returns:
    -------
        - The populated `AttributeTypeAndValue` structure.

    Raises:
    ------
        - `ValueError`: If `pub_method` is not one of "dontCare", "x500", "web", "ldap".

    Examples:
    --------
    | ${publication_info}= | Prepare PKIPublicationInformation Control | please_publish=True |
    | ${publication_info}= | Prepare PKIPublicationInformation Control | please_publish=True | \
    pub_method=web | pub_location="https://example.com" |
    | ${publication_info}= | Prepare PKIPublicationInformation Control | True | entries=${entries} |

    """
    actions = {"dontPublish": 0, "pleasePublish": 1, "badAction": 2}

    if action not in actions:
        raise ValueError(f"Invalid action: {action}. Must be one of {list(actions.keys())}")

    pki_pub_info = rfc4211.PKIPublicationInfo()
    pki_pub_info["action"] = univ.Integer(actions[action])

    if entries is None and pub_method is not None:
        entries = prepare_single_publication_info(
            pub_method="x500",
            pub_location=pub_location,
        )

    if isinstance(entries, rfc4211.SinglePubInfo):
        entries = [entries]

    if entries is not None:
        pki_pub_info["pubInfos"].extend(entries)

    attr = rfc4211.AttributeTypeAndValue()
    attr["type"] = rfc4211.id_regCtrl_pkiPublicationInfo
    attr["value"] = pki_pub_info
    return attr


@keyword(name="Validate PKIPublicationInformation")
def validate_pki_publication_information(  # noqa D417 undocumented-param
    controls: Union[rfc9480.Controls, Sequence[rfc9480.AttributeTypeAndValue]], must_be_present: bool = False
) -> None:
    """Validate the PKIPublicationInfo structure, to be used inside the Controls structure.

    Arguments:
    ---------
        - `controls`: The controls to validate.
        - `must_be_present`: Whether the publication information must be present. Defaults to `False`.

    Raises:
    ------
        - `ValueError`: If the publication information is invalid or missing.
        - `BadAsn1Data`: If the PKIPublicationInfo contains trailing data.
        - `ValueError`: If the publication method is "dontCare" and the pubInfos field is not omitted.
        - `ValueError`: If the publication location is not present and the publication method is not "dontCare".
        - `ValueError`: If the publication method is not one of "dontCare", "x500", "web", "ldap".

    Examples:
    --------
    | Validate Publication Information | ${controls} |
    | Validate Publication Information | ${controls} | must_be_present=True |

    """
    # TODO update to return the information to be used in some way.
    # maybe the Mock-Ca will be updated to use this.

    found = False
    publication_info_der = None
    for entry in controls:
        if entry["type"] == rfc4211.id_regCtrl_pkiPublicationInfo:
            publication_info_der = entry["value"].asOctets()
            found = True
            break

    if not found and must_be_present:
        raise ValueError("Missing PKIPublicationInfo in controls.")

    if not found:
        return

    publication_info, rest = decoder.decode(publication_info_der, asn1Spec=rfc4211.PKIPublicationInfo())

    if rest != b"":
        raise BadAsn1Data("PKIPublicationInfo contains trailing data.", overwrite=True)

    if int(publication_info["action"]) not in [0, 1]:
        raise BadDataFormat(
            f"Invalid action: {publication_info['action']}. Must be 0 (dontPublish) or 1 (pleasePublish)."
        )
    dont_publish = publication_info["action"] == 0

    # If dontPublish is used, the pubInfos field MUST be omitted.
    if dont_publish and publication_info["pubInfos"].isValue:
        raise BadDataFormat("If dontPublish is used, the pubInfos field MUST be omitted.")

    for entry in publication_info["pubInfos"]:
        if entry["pubMethod"] not in [0, 1, 2, 3]:
            raise BadDataFormat(f"Invalid pub_method: {entry['pubMethod']}. Must be 0, 1, 2, or 3.")

        if entry["pubMethod"] == 0:
            raise BadDataFormat("If dontCare is used, the pubInfos field MUST be omitted.")

        if not entry["pubLocation"].isValue:
            raise BadDataFormat("The publication location must be present.")

    # As of RFC4211 Section 6.3.
    if not dont_publish and not publication_info["pubInfos"].isValue:
        logging.info("The certificate can be published in any location.")


@keyword(name="Prepare Protocol Encryption Key Control")
def prepare_protocol_encryption_key_control(  # noqa D417 undocumented-param
    public_key: Optional[Union[PublicKey, rfc9480.CMPCertificate, rfc5280.SubjectPublicKeyInfo]] = None,
) -> rfc4211.AttributeTypeAndValue:
    """Prepare the protocolEncrKey structure, to be used inside the Controls structure.

    Used if the CA has information to send to the subscriber that needs to be encrypted.
    For more information have a look at RFC4211.

    Arguments:
    ---------
        - `ca_public_key`: The public key of the CA. Defaults to `None`.

    Returns:
    -------
        - The populated `AttributeTypeAndValue` structure.

    Raises:
    ------
        - `ValueError`: If neither `ca_public_key` nor `ca_cert` is provided.

    Examples:
    --------
    | ${protocol_encr_key}= | Prepare Controls Protocol Encr Key | ca_public_key=${public_key} |

    """
    if public_key is None:
        spki = rfc5280.SubjectPublicKeyInfo()
    elif isinstance(public_key, rfc9480.CMPCertificate):
        spki = public_key["tbsCertificate"]["subjectPublicKeyInfo"]
    elif isinstance(public_key, rfc5280.SubjectPublicKeyInfo):
        spki = public_key
    elif isinstance(public_key, PublicKey):
        spki = convertutils.subject_public_key_info_from_pubkey(public_key)
    else:
        raise TypeError(
            "Expected a PublicKey, CMPCertificate, SubjectPublicKeyInfo object,"
            "to prepare the protocol encryption key control."
        )

    attr = rfc4211.AttributeTypeAndValue()
    attr["type"] = rfc4211.id_regCtrl_protocolEncrKey
    attr["value"] = spki

    return attr


@keyword(name="Prepare CertReq reqInfo")
def prepare_cert_req_req_info(  # noqa D417 undocumented-param
    cert_req: Optional[rfc4211.CertRequest] = None,
) -> rfc9480.AttributeTypeAndValue:
    """Prepare the CertReq structure, to be used inside the reqInfo structure.

    The CertReq structure is used to specify the certificate request information.
    If the `CertTemplate` should not be used as it is, but cannot be modified due
    to the Proof-of-Possession, then can the RA set the `CertRequest` inside the
    `regInfo` structure, which will then be used to build the certificate.

    Arguments:
    ---------
        - `cert_req`: The certificate request to be prepared. Defaults to `None`.

    Returns:
    -------
        - The populated `AttributeTypeAndValue` structure.

    Examples:
    --------
    | ${cert_req}= | Prepare CertReq reqInfo | cert_req=${cert_request} |

    """
    if cert_req is None:
        logging.debug("No CertRequest provided, using empty CertRequest.")

    attr = rfc4211.AttributeTypeAndValue()
    attr["type"] = rfc4211.id_regInfo_certReq
    if cert_req is None:
        cert_req = rfc4211.CertRequest()

    attr["value"] = cert_req
    return attr


# TODO maybe allow some more strict settings,
# only extension are allowed to be modified and so on.
def _validate_cert_request_reg_info(
    given_cert_req: rfc4211.CertRequest,
    alt_cert_req: rfc4211.CertRequest,
) -> None:
    """Validate the CertReq structure inside the reqInfo structure.

    :param given_cert_req: The original `CertRequest` structure.
    :param alt_cert_req: The `CertRequest` structure inside the `regInfo` field.
    :raises BadCertTemplate: If the public key in the CertRequest does not match the one in the regInfo field.
    :raises BadRequest: If the certReqId in the CertRequest does not match the one in the regInfo field.
    """
    if given_cert_req["certReqId"] != alt_cert_req["certReqId"]:
        raise BadRequest("The certReqId in the CertRequest does not match the one in the regInfo field.")

    cert_template = given_cert_req["certTemplate"]
    alt_cert_template = alt_cert_req["certTemplate"]

    # all other fields can be ignored, as they are allowed
    # to be different, as long as the public key is the same,
    # unless the public key is absent, then can the RA modify the
    # public key as well.
    if cert_template["publicKey"].isValue:
        der_data = encoder.encode(cert_template["publicKey"])
        alt_der_data = encoder.encode(alt_cert_template["publicKey"])

        if der_data != alt_der_data:
            raise BadCertTemplate("The public key in the CertRequest does not match the one in the regInfo field.")

    if not cert_template["publicKey"].isValue and alt_cert_template["publicKey"].isValue:
        logging.info("The RA set the public key in the CertRequest, but the original CertRequest did not contain one.")


def _check_unique_controls(
    controls: Union[rfc9480.Controls, Sequence[rfc4211.AttributeTypeAndValue]],
) -> None:
    """Check if the controls are unique.

    :param controls: The controls to check.
    :raises ValueError: If the controls are not unique.
    """
    seen = set()
    for control in controls:
        if control["type"] in seen:
            raise BadRequest(f"Duplicate control type found: {control['type']}")
        seen.add(control["type"])


@keyword(name="Validate CertReq Inside regInfo")
def validate_cert_req_inside_reg_info(  # noqa D417 undocumented-param
    reg_infos: Sequence[rfc9480.AttributeTypeAndValue],
    given_cert_req: Optional[rfc4211.CertRequest] = None,
    must_be_present: bool = False,
) -> Optional[rfc4211.CertRequest]:
    """Validate the CertReq structure, to be used inside the regInfo structure.

    Arguments:
    ---------
        - `reg_infos`: The registration information to validate.
        - `must_be_present`: Whether the CertReq must be present. Defaults to `False`.

    Returns:
    -------
        - The `CertRequest` structure if present, otherwise `None`.

    Raises:
    ------
        - `ValueError`: If the CertReq is not present and `must_be_present` is True.
        - `badRequest`: If the CertReq is not only once present.
        - `BadAsn1Data`: If the CertReq contains trailing data.
        - `BadCertTemplate`: If the public key in the CertRequest does not match the one in the regInfo field.

    Examples:
    --------
    | ${cert_req}= | Validate reqInfo CertReq | ${reg_infos} |

    """
    der_data = None
    for entry in reg_infos:
        if entry["type"] == rfc4211.id_regInfo_certReq:
            der_data = entry["value"].asOctets()
            break

    if der_data is None and must_be_present:
        raise ValueError("Missing CertReq inside the `reqInfo` field.")

    if der_data is None:
        return None

    _check_unique_controls(reg_infos)

    cert_req, rest = decoder.decode(der_data, asn1Spec=rfc4211.CertRequest())
    if rest != b"":
        raise BadAsn1Data("The CertReq inside the `regInfo` field contains trailing data.", overwrite=True)

    if given_cert_req is None:
        return cert_req

    _validate_cert_request_reg_info(given_cert_req, cert_req)
    return cert_req


@keyword(name="Prepare UTF8Pairs reqInfo")
def prepare_utf8_pairs_req_info(  # noqa D417 undocumented-param
    data: str,
    encode: bool = True,
) -> rfc4211.AttributeTypeAndValue:
    """Prepare the UTF8Pairs structure, to be used inside the reqInfo structure.

    The UTF8Pairs structure is used to specify key-value pairs in UTF-8 encoding.
    The syntax is defined in RFC 4211: Name?Value%[Name?Value%]*

    Note:
    ----
       - Names MUST NOT start with a numeric character.
       - %xx is used to encode '?' and '%' characters if they are used as part of the value.
       (RFC1738)


    Name Value:
    ----------
      version            -- version of this variation of regInfo use
      corp_company       -- company affiliation of subscriber
      org_unit           -- organizational unit
      mail_firstName     -- personal name component
      mail_middleName    -- personal name component
      mail_lastName      -- personal name component
      mail_email         -- subscriber's email address
      jobTitle           -- job title of subscriber
      employeeID         -- employee identification number or string
      mailStop           -- mail stop
      issuerName         -- name of CA
      subjectName        -- name of Subject
      validity           -- validity interval

    Arguments:
    ---------
        - `data`: The complete string to be used as key-value pairs.
        - `encode`: Whether to URL-encode the data. Defaults to `True`.

    Returns:
    -------
        - The populated `AttributeTypeAndValue` structure.

    Examples:
    --------
    | ${utf8_pairs}= | Prepare reqInfo UTF8 Pairs |

    """
    if encode:
        data = parse.quote(data)

    attr = rfc4211.AttributeTypeAndValue()
    attr["type"] = rfc4211.id_regInfo_utf8Pairs
    attr["value"] = rfc4211.UTF8Pairs(data)

    return attr


def _parse_utf8_pairs(s: str) -> List[Tuple[str, str]]:
    """Parse a string in the format: Name?Value%[Name?Value%]*.

    Where any literal '?' in a name must be encoded as '%3f'
    and any literal '%' in a name or value must be encoded as '%25'.
    Names must not start with a numeric character.

    :param s: The string to parse.
    :raises ValueError: if the string does not conform to the expected format.
    :return: A list of (name, value) tuples.

    """
    pairs = []
    i = 0
    n = len(s)
    while i < n:
        # Parse the Name part until an unescaped '?' is encountered.
        name_chars = []
        while i < n:
            if s[i] == "?":
                # End of name reached
                i += 1  # Skip the terminator
                break
            if s[i] == "%":
                # We expect an escape sequence for '?' (%3f) or '%' (%25)
                if i + 2 < n:
                    seq = s[i + 1 : i + 3].lower()
                    if seq == "3f":
                        name_chars.append("?")
                    elif seq == "25":
                        name_chars.append("%")
                    else:
                        raise ValueError(f"Invalid percent encoding in name at position {i}: %{seq}")
                    i += 3  # Skip the escape sequence
                else:
                    raise ValueError("Incomplete percent encoding in name")
            else:
                name_chars.append(s[i])
                i += 1
        else:
            # No '?' terminator found for name
            raise ValueError("Missing '?' terminator for name")

        name = "".join(name_chars)
        # Validate that the name does not start with a numeric character.
        if name and name[0].isdigit():
            raise ValueError("Name must not start with a numeric character")

        # Parse the Value part until an unescaped '%' is encountered.
        value_chars = []
        while i < n:
            if s[i] == "%":
                # Check if this is the beginning of a valid escape sequence.
                if i + 2 < n:
                    seq = s[i + 1 : i + 3].lower()
                    if seq in ("3f", "25"):
                        # It's an escape for '?' or '%'
                        value_chars.append("?" if seq == "3f" else "%")
                        i += 3
                        continue  # Continue parsing the value
                # If not a valid escape, treat the '%' as the termination marker.
                i += 1  # Skip the terminator
                break
            else:
                value_chars.append(s[i])
                i += 1
        else:
            # No '%' terminator found for value
            raise ValueError("Missing '%' terminator for value")

        value = "".join(value_chars)
        pairs.append((name, str(value)))

    return pairs


@keyword(name="Validate regInfo UTF8Pairs")
def validate_reg_info_utf8_pairs(  # noqa D417 undocumented-param
    reg_infos: Sequence[rfc4211.AttributeTypeAndValue], must_be_present: bool = False
) -> Optional[List[Tuple[str, str]]]:
    """Validate the UTF8Pairs structure, to be used inside the regInfo structure.

    Arguments:
    ---------
        - `reg_infos`: The request information to validate.
        - `must_be_present`: Whether the UTF8Pairs must be present. Defaults to `False`.

    Returns:
    -------
        - The UTF8Pairs string if present, otherwise `None`.

    Raises:
    ------
        - `ValueError`: If the UTF8Pairs is not present and `must_be_present` is True.
        - `badRequest`: If the UTF8Pairs is not only once present.
        - `BadAsn1Data`: If the UTF8Pairs contains trailing data.

    Examples:
    --------
    | ${utf8_pairs}= | Validate regInfo UTF8 Pairs | ${reg_infos} |

    """
    der_data = None
    for entry in reg_infos:
        if entry["type"] == rfc4211.id_regInfo_utf8Pairs:
            der_data = entry["value"].asOctets()
            break

    if der_data is None and must_be_present:
        raise ValueError("Missing UTF8Pairs inside the `regInfo` field.")

    if der_data is None:
        return None

    _check_unique_controls(reg_infos)

    utf8_pairs, rest = decoder.decode(der_data, rfc4211.UTF8Pairs())
    if rest != b"":
        raise BadAsn1Data("The UTF8Pairs inside the `reqInfo` field contains trailing data.", overwrite=True)

    try:
        utf8_pairs_out = parse.unquote(str(utf8_pairs), encoding="utf-8", errors="strict")
        return _parse_utf8_pairs(utf8_pairs_out)
    except Exception as e:
        raise BadAsn1Data(f"Failed to decode/unquote UTF8Pairs: {e}") from e


@not_keyword
def validate_reg_info_field(
    cert_reg_msg: rfc4211.CertReqMsg,
    alt_reg_must_be_present: bool = False,
    utf8_pairs_must_be_present: bool = False,
) -> Tuple[Optional[rfc4211.CertRequest], Optional[List[Tuple[str, str]]]]:
    """Validate the reqInfo structure inside the CertRequest.

    :param cert_reg_msg: The original `CertRequest` structure.
    :param alt_reg_must_be_present: Whether the alternative request must be present. Defaults to `False`.
    :param utf8_pairs_must_be_present: Whether the UTF8Pairs must be present. Defaults to `False`.
    :return: A tuple containing the alternative request and UTF8Pairs string if present.
    """
    if not cert_reg_msg["regInfo"].isValue:
        if alt_reg_must_be_present or utf8_pairs_must_be_present:
            raise ValueError(
                "Missing regInfo inside the CertReqMsg. But Expecting at least one of the fields to be present."
            )
        return None, None

    alt_req = validate_cert_req_inside_reg_info(
        cert_reg_msg["regInfo"], cert_reg_msg["certReq"], must_be_present=alt_reg_must_be_present
    )
    utf8_pairs = validate_reg_info_utf8_pairs(cert_reg_msg["regInfo"], must_be_present=utf8_pairs_must_be_present)

    return alt_req, utf8_pairs


def _prepare_poposigningkeyinput(sender: str, public_key: PublicKey) -> rfc4211.POPOSigningKeyInput:
    """Prepare the POPOSigningKeyInput structure.

    :param sender: The sender of the PKI message.
    :param public_key: The public key of the newly to be issued certificate.
    :return: A populated `POPOSigningKeyInput` structure.
    """
    popo_signing_key_input = rfc4211.POPOSigningKeyInput()
    name_obj = prepareutils.prepare_name(sender, 4)
    general_name = rfc9480.GeneralName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    general_name = general_name.setComponentByName("directoryName", name_obj)
    popo_signing_key_input["authInfo"]["sender"] = general_name
    popo_signing_key_input["publicKey"] = convertutils.subject_public_key_info_from_pubkey(public_key)

    return popo_signing_key_input


def _prepare_poposigningkey(
    signing_key: Optional[SignKey],
    signature: Optional[bytes] = None,
    sender: Optional[Union[Dict[str, str], str]] = None,
    alg_oid: Optional[univ.ObjectIdentifier] = None,
    alg_id: Optional[rfc9480.AlgorithmIdentifier] = None,
    hash_alg: Optional[str] = None,
):
    """Prepare the `POPOSigningKey` structure.

    :param signing_key: The signing key, which must be provided for `POPOSigningKeyInput`.
    :param signature: The signature of the `CertRequest` to include.
    :param sender: The sender information for `POPOSigningKeyInput`.
    :param alg_oid: The algorithm OID (if not provided, derived from signing_key and hash_alg).
    :param alg_id: The algorithm identifier to use.
    :param hash_alg: The hash algorithm used for signing.
    :return: A populated `POPOSigningKey` object.
    """
    popo_key = rfc4211.POPOSigningKey().subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 1))
    if signature is not None:
        # Automatically removes raVerified, if set.
        popo_key["signature"] = univ.BitString().fromOctetString(signature)

    if sender is not None:
        if signing_key is None:
            raise ValueError(
                "Signing key must be provided when sender is specified, "
                "so that the `poposkInput` field can be populated."
            )
        if isinstance(sender, dict):
            sender_out = [f"{x}={y}" for x, y in sender.items()]
            sender = ",".join(sender_out)

        popo_key["poposkInput"] = _prepare_poposigningkeyinput(sender=sender, public_key=signing_key.public_key())

    if not (signing_key or alg_oid):
        raise ValueError(
            "Either `private_key` or `alg_oid` must be provided to "
            "determine the algorithm identifier for the signature."
        )

    if alg_oid is None and alg_id is None:
        alg_oid = oid_mapping.get_alg_oid_from_key_hash(signing_key, hash_alg=hash_alg)  # type: ignore

    if alg_oid is not None:
        popo_key["algorithmIdentifier"]["algorithm"] = alg_oid

    if alg_id is not None:
        popo_key["algorithmIdentifier"] = alg_id

    return popo_key


@keyword(name="Prepare POPO")
def prepare_popo(  # noqa D417 undocumented-param
    signature: Optional[bytes] = None,
    alg_oid: Optional[univ.ObjectIdentifier] = None,
    signing_key: Optional[SignKey] = None,
    hash_alg: str = "sha256",
    ra_verified: bool = False,
    sender: Optional[str] = None,
    use_encr_cert: bool = True,
    use_key_enc: Optional[bool] = True,
) -> rfc4211.ProofOfPossession:
    """Prepare the `ProofOfPossession` (POPO) structure for a certificate request.

    Constructs a `ProofOfPossession` object, which is used inside the `CertReqMsg`
    to indicate the PKI management entity has the key making the request. In cases where there
    is a change made by an intermediate PKI management entity, the `ProofOfPossession`
    may not be valid. The `ra_verified` parameter indicates whether the proof has been
    verified by a Registration Authority (RA). Also supports keyAgreement for x25519,x448 and
    `keyEncipherment` for KEM keys.

    Arguments:
    ---------
        - `signature`: The optional signature to be included in the POPO, provided as a byte sequence.
        - `alg_oid`: The `pyasn1` ObjectIdentifier of the algorithm used for the signature.
          If not provided, it will be determined based on the `private_key` and `hash_alg`.
        - `private_key`: The private key used to sign the certificate request. This is required
          if the `alg_oid` is not specified to derive the appropriate algorithm identifier.
        - `hash_alg`: The hash algorithm used for signing. Defaults to `sha256`.
        - `ra_verified`: Indicates if the RA (Registration Authority) has verified the Proof of Possession.
          If set to `True`, a POPO without a signature will be generated. Defaults to `False`.
        - `sender`: The sender of the `PKIMessage` used inside the `POPOSigningKeyInput` structure.
        (which *MUST* be absent.)
        - `use_encr_cert`: Indicates if the certificate request is for a keyAgreement or keyEncipherment key.
        _ `use_key_enc`: Indicates if the certificate request is for a keyEncipherment key.

    Returns:
    -------
        - The populated `ProofOfPossession` structure.

    Raises:
    ------
        - `ValueError`: If neither `private_key` nor `alg_oid` is provided, as at least one is necessary to determine
          the algorithm identifier for the signature.

    Examples:
    --------
    | ${popo}= | Prepare POPO | signature=${signature} | private_key=${private_key} |
    | ${popo}= | Prepare POPO | ra_verified=True |

    """
    if is_kem_private_key(signing_key):
        use_key_enc = True if use_key_enc is None else use_key_enc
        return prepare_popo_challenge_for_non_signing_key(use_encr_cert=use_encr_cert, use_key_enc=use_key_enc)

    if isinstance(signing_key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
        use_key_enc = False if use_key_enc is None else use_key_enc
        return prepare_popo_challenge_for_non_signing_key(use_encr_cert=use_encr_cert, use_key_enc=use_key_enc)

    popo = rfc4211.ProofOfPossession()
    if ra_verified:
        # raVerified automatically removes the signature, if set.
        value = univ.Null("").subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        popo["raVerified"] = value
        return popo

    popo_key = _prepare_poposigningkey(
        alg_oid=alg_oid, signing_key=signing_key, sender=sender, signature=signature, hash_alg=hash_alg
    )
    popo["signature"] = popo_key
    return popo


@keyword(name="Prepare CertRequest")
def prepare_cert_request(  # noqa D417 undocumented-param
    key: Union[PrivateKey, PublicKey],
    common_name: Optional[str] = None,
    cert_req_id: int = 0,
    cert_template: Optional[rfc4211.CertTemplate] = None,
    extensions: Optional[rfc5280.Extensions] = None,
    controls: Optional[ControlsType] = None,
    for_kga: bool = False,
    use_pre_hash: bool = False,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
) -> rfc4211.CertRequest:
    """Prepare a `CertRequest` structure for a certificate request.

    Generate an `rfc4211.CertRequest` object, which encapsulates
    the necessary information for a PKI management entity to request a certificate.
    If a `cert_template` is not provided, it is constructed using the specified key,
    common name, and optional extensions.

    Arguments:
    ---------
        - `key`: The key (private or public) used to create the certificate request. If a private key is provided,
          the corresponding public key will be extracted and used.
        - `common_name`: The common name (CN) for the subject of the certificate.
          Required if `cert_template` is not provided.
        - `cert_req_id`: An identifier for the certificate request. Defaults to `0`.
        - `cert_template`: An optional pre-constructed certificate
          template. If not provided, a new template will be created using the provided key
          and common name.
        - `extensions`: Optional extensions to be included in
          the certificate template. Only used if a new `cert_template` is constructed.
        - `controls`: Optional controls for the certificate request.
          May be used by the `Key Update Request`.
        - `for_kga`: Indicates if the certificate request is for a Key Generation Authority
          (KGA). Defaults to `False`.
        - `use_pre_hash`:Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `spki`: The SubjectPublicKeyInfo structure to use for the certificate request. Defaults to `None`.

    Returns:
    -------
        - The constructed `CertRequest` object.

    Raises:
    ------
        - `ValueError`: If `cert_template` is not provided and `common_name` is missing,
          as the common name is required to construct a certificate template.

    Examples:
    --------
    | ${cert_request}= | Prepare CertRequest | key=${private_key} | common_name=${cm} |
    | ${cert_request}= | Prepare CertRequest | key=${public_key} | cert_req_id=123 |

    """
    cert_request = rfc4211.CertRequest()
    cert_request["certReqId"] = univ.Integer(cert_req_id)
    if cert_template is None:
        if isinstance(key, PrivateKey):
            key = key.public_key()

        if common_name is None:
            raise ValueError("A `common_name` must be provided if `cert_template` is not specified.")
        cert_template = certbuildutils.prepare_cert_template(
            key=key,
            subject=common_name,
            extensions=extensions,
            for_kga=for_kga,
            use_pre_hash=use_pre_hash,
            spki=spki,
        )

    cert_request["certTemplate"] = cert_template

    if controls is not None:
        if isinstance(controls, rfc9480.AttributeTypeAndValue):
            controls = [controls]

        cert_request["controls"].extend(controls)

    return cert_request


@not_keyword
def prepare_sig_popo_structure(
    alg_id: Union[rfc9480.AlgorithmIdentifier, univ.ObjectIdentifier],
    signing_key: SignKey,
    signature: bytes,
    bad_pop: bool = False,
    poposk_input: Optional[rfc4211.POPOSigningKeyInput] = None,
) -> rfc4211.ProofOfPossession:
    """Prepare the `ProofOfPossession` (POPO) structure for a certificate request.

    :param alg_id: The algorithm identifier to use.
    :param signing_key: The signing key used to sign the certificate request.
    :param signature: The signature of the `CertRequest` to include.
    :param bad_pop: If `True`, the first byte of the signature will be modified to create an invalid POP signature.
    :param poposk_input: The `POPOSigningKeyInput` structure to include in the POPO. Defaults to `None`.
    :return: A populated `ProofOfPossession` object.
    """
    popo = rfc4211.ProofOfPossession()
    popo_key = rfc4211.POPOSigningKey().subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 1))

    if isinstance(alg_id, univ.ObjectIdentifier):
        alg_id = rfc9480.AlgorithmIdentifier()
        alg_id["algorithm"] = alg_id

    popo_key["algorithmIdentifier"] = alg_id

    if bad_pop:
        signature = utils.manipulate_bytes_based_on_key(signature, signing_key)

    if poposk_input is not None:
        popo_key["poposkInput"] = poposk_input

    popo_key["signature"] = univ.BitString().fromOctetString(signature)
    popo["signature"] = popo_key
    return popo


@keyword(name="Prepare Signature POPO")
def prepare_signature_popo(  # noqa: D417 undocumented-param
    signing_key: SignKey,
    cert_request: rfc4211.CertRequest,
    hash_alg: Optional[str] = "sha256",
    bad_pop: bool = False,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
    add_params_rand_val: bool = False,
    sender: Optional[str] = None,
) -> rfc4211.ProofOfPossession:
    """Prepare Proof-of-Possession for a certificate request.

    Arguments:
    ---------
        - `signing_key`: The private key used for signing the certificate request.
        - `cert_request`: The certificate request to sign.
        - `hash_alg`: The hash algorithm used for signing. Defaults to `sha256`.
        - `bad_pop`: If `True`, the first byte of the signature will be modified to create an invalid.
        POP signature.
        - `use_rsa_pss`: If `True`, the RSA-PSS signature scheme will be used.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `add_params_rand_val`: If `True`, the random value will be added to the parameters field of the signature
        alg id. Defaults to `False`.
        - `sender`: The sender information for `POPOSigningKeyInput`, which **MUST** be absent. Defaults to `None`.

    Returns:
    -------
        - The populated `ProofOfPossession` structure.

    Examples:
    --------
    | ${popo}= | Prepare Signature POPO | ${signing_key} | ${cert_request} | hash_alg=sha256 |

    """
    der_cert_request = encoder.encode(cert_request)
    signature = cryptoutils.sign_data(
        data=der_cert_request,
        key=signing_key,
        hash_alg=hash_alg,
        use_pre_hash=use_pre_hash,
        use_rsa_pss=use_rsa_pss,
    )
    logging.info("Calculated POPO without manipulation: %s", signature.hex())

    alg_id = prepare_alg_ids.prepare_sig_alg_id(
        signing_key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        add_params_rand_val=add_params_rand_val,
    )

    poposk_input = None
    if sender is not None:
        poposk_input = _prepare_poposigningkeyinput(sender=sender, public_key=signing_key.public_key())

    popo = prepare_sig_popo_structure(
        alg_id=alg_id,
        signing_key=signing_key,
        signature=signature,
        bad_pop=bad_pop,
        poposk_input=poposk_input,
    )
    return popo


@keyword(name="Prepare CertReqMsg")
def prepare_cert_req_msg(  # noqa D417 undocumented-param
    private_key: PrivateKey,
    common_name: Optional[str] = None,
    cert_req_id: Strint = 0,
    hash_alg: str = "sha256",
    extensions: Optional[rfc9480.Extensions] = None,
    cert_template: Optional[rfc4211.CertTemplate] = None,
    cert_request: Optional[rfc4211.CertRequest] = None,
    popo_structure: Optional[rfc4211.ProofOfPossession] = None,
    ra_verified: bool = False,
    for_kga: bool = False,
    controls: Optional[rfc4211.Controls] = None,
    exclude_popo: bool = False,
    bad_pop: bool = False,
    use_encr_cert: bool = True,
    use_pre_hash: bool = False,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
) -> rfc4211.CertReqMsg:
    """Prepare a `CertReqMsg` structure for a certificate request message ("ir", "cr", "kur").

    Generates a `CertReqMsg` object, which is used as part of a certificate request message.
    It provides options to customize the certificate request, handle Proof of Possession (POPO), use existing
    certificate templates, add extensions, and specify additional controls. The POPO structure can be provided
    or generated automatically unless the request is for Key Generation Authority (KGA).

    Arguments:
    ---------
        - `private_key`: The private key used for signing the certificate request or generating the POPO.
        - `common_name`: The common name (CN) to be used as the subject of the certificate request.
          Required if `cert_template` is not provided. The format follows OpenSSL notation, e.g.,
          `C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann`. Defaults to `None`.
        - `cert_req_id`: The identifier for the certificate request. Defaults to `0`.
        - `hash_alg`: The hash algorithm used for signing the POPO. Defaults to `sha256`.
        - `extensions`: Optional extensions to include in the certificate request.
        - `cert_template`: An optional pyasn1 `CertTemplate` object that defines the
          template for the certificate request. If not provided, a template will be generated using the provided key
          and common name.
        - `popo_structure`: A pre-constructed Proof of Possession object. If
          not provided, one is generated automatically unless the `for_kga` flag is `True`.
        - `ra_verified`: Indicates whether the Registration Authority (RA) has verified the certificate request.
          If `True`, a simplified POPO will be generated. Defaults to `False`.
        - `for_kga`: Indicates if the request is for a Key Generation Authority (KGA).
          If `True`, the POPO will be omitted. Defaults to `False`.
        - `controls`: Optional controls to include in the certificate request.
        - `exclude_popo`: If `True`, the POPO will be excluded from the request. Defaults to `False`.
        - `bad_pop`: If `True`, the first byte of the signature will be modified to create an invalid
        Proof-of-Possession.
        - `use_encr_cert`: If `True`, the certificate will be encrypted by the CA using the public key of the client.
        - `spki`: The SubjectPublicKeyInfo structure to use for the certificate request. Defaults to `None`.

    Returns:
    -------
        - The populated `CertReqMsg` object, ready for use in a certificate request.

    Raises:
    ------
        - `ValueError`: Raised if neither `common_name` nor `cert_template` is provided, as at least one is needed
          to create the certificate template.

    Examples:
    --------
    | ${cert_req_msg}= | Prepare CertReqMsg | ${private_key} | common_name=${cm} | cert_req_id=1 | hash_alg=sha512 |
    | ${cert_req_msg}= | Prepare CertReqMsg | ${private_key} | cert_template=${cert_template} | for_kga=True |
    | ${cert_req_msg}= | Prepare CertReqMsg | ${private_key} | common_name=${cm} | extensions=${extensions} | \
    controls=${controls} |

    """
    cert_request_msg = rfc4211.CertReqMsg()
    cert_request = cert_request or prepare_cert_request(
        key=private_key,
        common_name=common_name,
        cert_req_id=int(cert_req_id),
        extensions=extensions,
        cert_template=cert_template,
        controls=controls,
        for_kga=for_kga,
        spki=spki,
        use_pre_hash=use_pre_hash,
    )

    cert_request_msg["certReq"] = cert_request

    if for_kga:
        return cert_request_msg

    if popo_structure is not None:
        cert_request_msg["popo"] = popo_structure
        return cert_request_msg

    if exclude_popo:
        return cert_request_msg

    if is_kem_private_key(private_key):
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=use_encr_cert, use_key_enc=True)
        cert_request_msg["popo"] = popo

    elif not isinstance(private_key, (x448.X448PrivateKey, x25519.X25519PrivateKey, dh.DHPrivateKey)):
        popo = prepare_signature_popo(
            signing_key=private_key,  # type: ignore
            cert_request=cert_request,
            hash_alg=hash_alg,
            bad_pop=bad_pop,
        )

        if ra_verified:
            popo = prepare_popo(
                signature=None,
                signing_key=private_key,  # type: ignore
                ra_verified=ra_verified,
                hash_alg=hash_alg,
            )
        cert_request_msg["popo"] = popo
    elif isinstance(private_key, (x448.X448PrivateKey, x25519.X25519PrivateKey)):
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=use_encr_cert, use_key_enc=False)
        cert_request_msg["popo"] = popo

    return cert_request_msg


def _prepare_cert_req_msg_body(body_type: str) -> rfc9480.PKIBody:
    """Create and return a `rfc9480.PKIBody` structure based on the specified body type for certificate requests.

    :param body_type: The type of PKIBody to create. Must be one of "cr", "ir", or "kur".
    :raises ValueError: If the provided `body_type` is not one of the supported values ("cr", "ir", "kur").
    :return: A `PKIBody` object with the requested body type and appropriate tagging.
    """
    type_2_id = {"ir": 0, "cr": 2, "kur": 7, "ccr": 13, "krr": 9}
    if body_type not in type_2_id:
        raise ValueError(
            "The provided `body_type` is not one of the supported values "
            f"('cr', 'ir', 'kur', 'ccr'). But got: {body_type}"
        )

    pki_body = rfc9480.PKIBody()
    pki_body[body_type] = rfc9480.CertReqMessages().subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, type_2_id[body_type])
    )

    return pki_body


@keyword(name="Build Key Update Request")
def build_key_update_request(  # noqa D417 undocumented-param
    signing_key: SignKey,
    cert: Optional[rfc9480.CMPCertificate] = None,
    common_name: str = "CN=Hans Mustermann",
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = "sender,senderKID",
    use_controls: bool = False,
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    **params,
):
    """Create a Key Update Request (KUR) `PKIMessage` for updating a certificate with a new key.

    Builds a `kur` using the provided new key, existing certificate, and additional parameters.
    It constructs a certificate request message with the updated key information and prepares the
    PKIHeader. Optionally, controls can be included.

    Arguments:
    ---------
        - `signing_key`: The new private key to be used for updating the certificate.
        - `cert`: The existing certificate for which the key update is requested.
        - `common_name`: The common name to be used in the certificate request. Defaults to `CN=Hans Mustermann`.
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `sender,senderKID`.
        (needed for signature-based-protection)
        - `use_controls`: Whether to include control structures in the request. Defaults to `False`.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.

    `**params`: Additional parameters for customization:
        - `cert_req_id` (int, str): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to `sha256`.
        - `extensions` (rfc5280.Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (rfc4211.Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `cert_template` (rfc4211.CertTemplate): Custom certificate template.
        - `popo_structure` (rfc4211.ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)

    Returns:
    -------
        - The constructed Key Update Request `PKIMessage`.

    Raises:
    ------
        - `ValueError`: If controls are requested but no certificate is provided,
        or if an unsupported key algorithm is specified.

    Examples:
    --------
    | ${pki_message}= | Build Key Update Request | ${new_key} | ${cert} | common_name=${cm} |
    | ${pki_message}= | Build Key Update Request | ${new_key} | ${cert} | use_controls=True | \
    exclude_fields=messageTime,senderNonce |
    | ${pki_message}= | Build Key Update Request | ${new_key} | ${cert} | hash_alg=sha512 | implicit_confirm=True |

    """
    cert_template = params.get("cert_template")
    if cert_template is None:
        cert_template = certbuildutils.prepare_cert_template(
            key=signing_key,
            cert=cert,
            subject=common_name,
            exclude_fields="serialNumber,validity",
            for_kga=params.get("for_kga", False),
            extensions=params.get("extensions"),
            spki=params.get("spki"),
            # To remove the SKI extension from the cert.
            include_cert_extensions=params.get("include_cert_extensions", False),
        )

    controls = None
    if use_controls:
        if cert is None:
            raise ValueError("To prepare the `Controls` structure, a certificate must be provided.")

        controls = prepare_controls_structure(cert=cert)
        logging.info("%s", controls.prettyPrint())

    controls = controls or params.get("controls")
    cert_req_msg = cert_req_msg or prepare_cert_req_msg(
        private_key=signing_key,
        common_name=common_name,
        cert_req_id=params.get("cert_req_id", 0),
        hash_alg=params.get("hash_alg", "sha256"),
        extensions=params.get("extensions"),
        controls=controls,
        ra_verified=params.get("ra_verified", False),
        for_kga=params.get("for_kga", False),
        cert_template=cert_template,
        popo_structure=params.get("popo"),
        bad_pop=params.get("bad_pop", False),
    )

    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="kur",
        cert_req_msg=cert_req_msg,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


def _parse_pvno(pvno: Optional[Strint], for_kga: bool, default: int = 2) -> int:
    """Parse the provided Protocol Version Number (PVNO) and return the integer value.

    :param pvno: The Protocol Version Number to parse.
    :return: The parsed PVNO as an integer.
    """
    if pvno is None:
        pvno = default
        if for_kga:
            pvno = 3
    else:
        pvno = int(pvno)

    return pvno


def _prepare_build_cert_req_msgs_pkimessage(
    body_name: str,
    cert_req_msg: Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg],
    sender: Union[str, rfc9480.GeneralName],
    recipient: Union[str, rfc9480.GeneralName],
    **params,
) -> PKIMessageTMP:
    """Prepare a `PKIMessage` with the specified body name and `CertReqMsg`.

    :param body_name: The name of the PKI body (e.g., "cr", "ir", "krr").
    :param cert_req_msg: The `CertReqMsg` or list of `CertReqMsg` objects to include in the body.
    :param params: Additional parameters for customization.
    :return: The constructed `PKIMessage`.
    """
    pki_body = _prepare_cert_req_msg_body(body_name)
    pki_body[body_name].extend(utils.ensure_list(cert_req_msg))

    pvno = _parse_pvno(params.get("pvno"), params.get("for_kga", False))

    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=params.get("exclude_fields"),
        transaction_id=params.get("transaction_id"),
        sender_nonce=params.get("sender_nonce"),
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=pvno,
        for_mac=params.get("for_mac", False),
        message_time=params.get("message_time"),
    )
    pki_message["body"] = pki_body
    return pki_message


@keyword(name="Build Ir From Key")
def build_ir_from_key(  # noqa D417 undocumented-param
    signing_key: PrivateKey,
    common_name: str = "CN=Hans Mustermann",
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    bad_pop: bool = False,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
    for_mac: bool = False,
    **params,
):
    """Create an `ir` (Initialization Request) PKIMessage using a signing key and specified parameters.

    Constructs a `PKIMessage` with an `ir` body type, which is used for requesting
    the issuance of a new certificate. The message includes a `CertReqMsg` generated from the
    provided signing key and other optional parameters.

    Arguments:
    ---------
        - `signing_key`: A private key object used to sign the `CertReqMsg`.
        - `common_name`: The common name for the certificate subject in OpenSSL notation,
          e.g., `C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann`. Defaults to `CN=Hans Mustermann`.
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `None`.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.
        - `bad_pop`: If `True`, the Proof of Possession (POPO) will be manipulated to create an invalid signature.
        - `spki`: The `SubjectPublicKeyInfo` structure to use for the certificate request. Defaults to `None`.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)

    `**params`: Additional optional parameters for customization:
        - `cert_req_id` (int): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to `sha256`.
        - `extensions` (Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `cert_template` (CertTemplate): Custom certificate template.
        - `popo` (ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.


    Returns:
    -------
        - The constructed `PKIMessage` with the `ir` body.

    Raises:
    ------
        - `ValueError`: If required parameters are missing or invalid.

    Examples:
    --------
    | ${ir}= | Build Ir From Key | ${signing_key} |
    | ${ir}= | Build Ir From Key | ${signing_key} | sender=custom_sender@example.com |
    | ${ir}= | Build Ir From Key | ${signing_key} | exclude_fields=transactionID,senderNonce |

    """
    if cert_req_msg is None:
        cert_req_msg = prepare_cert_req_msg(
            private_key=signing_key,
            common_name=common_name,
            cert_req_id=params.get("cert_req_id", 0),
            hash_alg=params.get("hash_alg", "sha256"),
            extensions=params.get("extensions", None),
            controls=params.get("controls"),
            ra_verified=params.get("ra_verified", False),
            for_kga=params.get("for_kga", False),
            cert_template=params.get("cert_template"),
            cert_request=params.get("cert_request"),
            popo_structure=params.get("popo"),
            bad_pop=bad_pop,
            spki=spki,
        )

    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="ir",
        cert_req_msg=cert_req_msg,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        for_mac=for_mac,
        **params,
    )


@keyword(name="Build Cr From Key")
def build_cr_from_key(  # noqa D417 undocumented-param
    signing_key: PrivateKey,
    common_name: str = "CN=Hans Mustermann",
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    **params,
):
    """Create a `cr` (Certificate Request) type PKIMessage using a signing key and specified parameters.

    Constructs a `PKIMessage` with a `cr` body type, which is used for requesting
    the issuance of a new certificate. The message includes a `CertReqMsg` generated from the
    provided signing key and other optional parameters.

    Arguments:
    ---------
        - `signing_key`: The private key used to sign the `CertReqMsg`.
        - `common_name`: The common name for the subject of the certificate. Defaults to "CN=Hans Mustermann".
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Optional comma-separated string specifying which PKIHeader fields to
        exclude. Defaults to `None`.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.

    `**params`: Additional optional parameters for customization:
        - `cert_req_id` (int, str): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to "sha256".
        - `extensions` (rfc5280.Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (rfc4211.Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `cert_template` (rfc4211.CertTemplate): Custom certificate template.
        - `popo_structure` (rfc4211.ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)

    Returns:
    -------
        - The constructed `PKIMessage` with the `cr` body.

    Raises:
    ------
        - `ValueError`: If required parameters are missing or invalid.

    Examples:
    --------
    | ${cr}= | Build Cr From Key | ${signing_key} | cert_template=${cert_template} |
    | ${cr}= | Build Cr From Key | ${signing_key} | common_name=${cm} |
    | ${cr}= | Build Cr From Key | ${signing_key} | sender=sender@example.com | recipient=recip@example.com |
    | ${cr}= | Build Cr From Key | ${signing_key} | common_name=${common_name} | hash_alg=sha512 |

    """
    if cert_req_msg is None:
        cert_req_msg = prepare_cert_req_msg(
            private_key=signing_key,
            common_name=common_name,
            cert_req_id=params.get("cert_req_id", 0),
            hash_alg=params.get("hash_alg", "sha256"),
            extensions=params.get("extensions", None),
            controls=params.get("controls"),
            ra_verified=params.get("ra_verified", False),
            for_kga=params.get("for_kga", False),
            cert_template=params.get("cert_template"),
            popo_structure=params.get("popo"),
            bad_pop=params.get("bad_pop", False),
        )

    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="cr",
        cert_req_msg=cert_req_msg,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


@keyword(name="Build Krr From Key")
def build_krr_from_key(  # noqa D417 undocumented-param
    signing_key: PrivateKey,
    common_name: str = "CN=Hans Mustermann",
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    **params,
) -> PKIMessageTMP:
    """Create a Key-Recovery Request (KRR) PKIMessage using a signing key and specified parameters.

    Arguments:
    ---------
        - `signing_key`: A private key object used to sign the `CertReqMsg`.
        - `common_name`: The common name for the certificate subject. Defaults to "CN=Hans Mustermann".
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Optional comma-separated list of PKIHeader fields to exclude.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.

    `**params`:
    ----------
        - `cert_req_id` (int): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to `sha256`.
        - `extensions` (rfc5280.Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (rfc4211.Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `cert_template` (rfc4211.CertTemplate): Custom certificate template.
        - `popo_structure` (rfc4211.ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)

    Returns:
    -------
        - The constructed `PKIMessage` with the `krr` body.

    Raises:
    ------
        - `ValueError`: If required parameters are missing or invalid.

    Examples:
    --------
    | ${krr}= | Build Krr From Key | ${signing_key} |
    | ${krr}= | Build Krr From Key | ${signing_key} | sender=custom_sender@example.com |
    | ${krr}= | Build Krr From Key | ${signing_key} | exclude_fields=transactionID,senderNonce |

    """
    if cert_req_msg is None:
        cert_req_msg = prepare_cert_req_msg(
            private_key=signing_key,
            common_name=common_name,
            cert_req_id=params.get("cert_req_id", 0),
            hash_alg=params.get("hash_alg", "sha256"),
            extensions=params.get("extensions", None),
            controls=params.get("controls"),
            ra_verified=params.get("ra_verified", False),
            for_kga=params.get("for_kga", False),
            cert_template=params.get("cert_template"),
            popo_structure=params.get("popo"),
            bad_pop=params.get("bad_pop", False),
        )

    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="krr",
        cert_req_msg=cert_req_msg,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


@keyword(name="Build Ccr From Key")
def build_ccr_from_key(  # noqa D417 undocumented-param
    signing_key: SignKey,
    common_name: str = "CN=Hans Mustermann",
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = "sender,senderKID",
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    **params,
):
    """Create an `Crr` (Cross-Certification Request) PKIMessage using a signing key and specified parameters.

    Constructs a `PKIMessage` with an `crr` body type, which is used for requesting
    the issuance of a new certificate. The message includes a `CertReqMsg` generated from the
    provided signing key and other optional parameters.

    Arguments:
    ---------
        - `signing_key`: A private key object used to sign the `CertReqMsg`.
        - `common_name`: The common name for the certificate subject in OpenSSL notation,
          e.g., `C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann`. Defaults to `CN=Hans Mustermann`.
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `None`.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.

    `**params`: Additional optional parameters for customization:
        - `cert_req_id` (int): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to `sha256`.
        - `extensions` (rfc5280.Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (rfc4211.Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `cert_template` (rfc4211.CertTemplate): Custom certificate template.
        - `popo_structure` (rfc4211.ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)
       - `bad_pop`: If `True`, the Proof of Possession (POPO) will be manipulated to create an invalid signature.

    Returns:
    -------
        - The constructed `PKIMessage` with the `crr` body.

    Raises:
    ------
        - `ValueError`: If required parameters are missing or invalid.

    Examples:
    --------
    | ${crr}= | Build Ir From Key | ${signing_key} |
    | ${crr}= | Build Ir From Key | ${signing_key} | sender=custom_sender@example.com |
    | ${crr}= | Build Ir From Key | ${signing_key} | exclude_fields=transactionID,senderNonce |

    """
    if cert_req_msg is None:
        cert_req_msg = prepare_cert_req_msg(
            private_key=signing_key,
            common_name=common_name,
            cert_req_id=params.get("cert_req_id", 0),
            hash_alg=params.get("hash_alg", "sha256"),
            extensions=params.get("extensions", None),
            controls=params.get("controls"),
            ra_verified=params.get("ra_verified", False),
            for_kga=params.get("for_kga", False),
            cert_template=params.get("cert_template"),
            popo_structure=params.get("popo"),
            bad_pop=params.get("bad_pop", False),
        )

    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="ccr",
        cert_req_msg=cert_req_msg,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


@keyword(name="Build Ir From CSR")
def build_ir_from_csr(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest,
    signing_key: SignKey,
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    **params,
):
    """Create a PKIMessage of type `ir` (Initialization Request) from a PKCS#10 CSR and a signing key.

    The provided Certification Request (CSR) is used to create the `CertTemplate` structure.
    The `CertRequest` is then signed with the given `signing_key`, and optional parameters can be
    used to customize the message.

    Arguments:
    ---------
        - `csr`: The PKCS#10 `CertificationRequest` object used to generate the `CertTemplate`.
        - `signing_key`: A private key object for signing the `CertReqMsg`.
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `None`.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.

    `**params`: Additional optional parameters for customization:
        - `cert_req_id` (int, str): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to "sha256".
        - `extensions` (rfc5280.Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (rfc4211.Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `popo_structure` (rfc4211.ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)

    Returns:
    -------
        - The constructed `PKIMessage` with the `ir` body.

    Raises:
    ------
        - `ValueError`: If required parameters are missing or invalid.

    Examples:
    --------
    | ${ir}= | Build Ir From CSR | ${csr} | ${signing_key} |
    | ${ir}= | Build Ir From CSR | ${csr} | ${signing_key} | common_name=${cm} |
    | ${ir}= | Build Ir From CSR | ${csr} | ${signing_key} | sender=${sender} |
    | ${ir}= | Build Ir From CSR | ${csr} | ${signing_key} | exclude_fields=transactionID,senderNonce |

    """
    cert_template = certbuildutils.prepare_cert_template_from_csr(csr)
    message = prepare_cert_req_msg(
        private_key=signing_key,
        common_name=None,
        cert_req_id=params.get("cert_req_id", 0),
        hash_alg=params.get("hash_alg", "sha256"),
        extensions=params.get("extensions", None),
        controls=params.get("controls"),
        ra_verified=params.get("ra_verified", False),
        for_kga=params.get("for_kga", False),
        cert_template=cert_template,
        popo_structure=params.get("popo"),
        bad_pop=params.get("bad_pop", False),
    )
    messages = utils.ensure_list(cert_req_msg)
    messages.append(message)

    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="ir",
        cert_req_msg=messages,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


@keyword(name="Build Cr From CSR")
def build_cr_from_csr(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest,
    signing_key: SignKey,
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    **params,
):
    """Create a PKIMessage of type `cr` (Certification Request) from a PKCS#10 CSR and a signing key.

    The provided Certification Request (CSR) is used to create the `CertTemplate` structure.
    The `CertRequest` is then signed with the given `signing_key`, and optional parameters can be
    used to customize the message.

    Arguments:
    ---------
        - `csr`: The PKCS#10 `CertificationRequest` object used to generate the `CertTemplate`.
        - `signing_key`: A private key object for signing the `CertReqMsg`.
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `None`.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.

    `**params`: Additional optional parameters for customization:
        - `cert_req_id` (int, str): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to "sha256".
        - `extensions` (rfc5280.Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (rfc4211.Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `popo_structure` (rfc4211.ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)

    Returns:
    -------
        - The constructed `PKIMessage` with the `cr` body.

    Raises:
    ------
        - `ValueError`: If required parameters are missing or invalid.

    Examples:
    --------
    | ${cr}= | Build Cr From CSR | ${csr} | ${signing_key} |
    | ${cr}= | Build Cr From CSR | ${csr} | ${signing_key} | sender=${sender} |
    | ${cr}= | Build Cr From CSR | ${csr} | ${signing_key} | exclude_fields=transactionID,senderNonce |
    | ${cr}= | Build Cr From CSR | ${csr} | ${signing_key} | cert_req_id=1 | hash_alg=sha512 |

    """
    cert_template = certbuildutils.prepare_cert_template_from_csr(csr)

    message = prepare_cert_req_msg(
        private_key=signing_key,
        common_name=None,
        cert_req_id=params.get("cert_req_id", 0),
        hash_alg=params.get("hash_alg", "sha256"),
        extensions=params.get("extensions", None),
        controls=params.get("controls"),
        ra_verified=params.get("ra_verified", False),
        for_kga=params.get("for_kga", False),
        cert_template=cert_template,
        popo_structure=params.get("popo"),
    )

    messages = utils.ensure_list(cert_req_msg)
    messages.append(message)

    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="cr",
        cert_req_msg=messages,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


@keyword(name="Build Ccr From CSR")
def build_ccr_from_csr(  # noqa D417 undocumented-param
    csr: rfc6402.CertificationRequest,
    signing_key: SignKey,
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    exclude_fields: Optional[str] = None,
    cert_req_msg: Optional[Union[List[rfc4211.CertReqMsg], rfc4211.CertReqMsg]] = None,
    **params,
):
    """Create a PKIMessage of type `crr` (Cross-Certification Request) from a PKCS#10 CSR and a signing key.

    The provided Certification Request (CSR) is used to create the `CertTemplate` structure.
    The `CertRequest` is then signed with the given `signing_key`, and optional parameters can be
    used to customize the message.

    Arguments:
    ---------
        - `csr`: The PKCS#10 `CertificationRequest` object used to generate the `CertTemplate`.
        - `signing_key`: A private key object for signing the `CertReqMsg`.
        - `sender`: The sender of the request. Defaults to "tests@example.com".
        - `recipient`: The recipient of the request. Defaults to "testr@example.com".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIHeader. Defaults to `None`.
        - `cert_req_msg`: A list of or single `CertReqMsg` object to be appended.

    `**params`: Additional optional parameters for customization:
        - `cert_req_id` (int, str): ID for the certificate request. Defaults to `0`.
        - `hash_alg` (str): The hash algorithm for Proof of Possession (POP). Defaults to "sha256".
        - `extensions` (rfc5280.Extensions): Extensions to include in the `CertReqMsg`.
        - `controls` (rfc4211.Controls): Controls for the `CertReqMsg`.
        - `ra_verified` (bool): Flag indicating if the RA has verified the Proof of Possession.
        - `for_kga` (bool): Indicates if the request is for key generation authentication.
        - `popo_structure` (rfc4211.ProofOfPossession): Custom Proof of Possession structure.
        - The `PKIHeader` fields can also be set.
        - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)

    Returns:
    -------
        - The constructed `PKIMessage` with the `crr` body.

    Raises:
    ------
        - `ValueError`: If required parameters are missing or invalid.

    Examples:
    --------
    | ${crr}= | Build Ir From CSR | ${csr} | ${signing_key} |
    | ${crr}= | Build Ir From CSR | ${csr} | ${signing_key} | common_name=${cm} |
    | ${crr}= | Build Ir From CSR | ${csr} | ${signing_key} | sender=${sender} |
    | ${crr}= | Build Ir From CSR | ${csr} | ${signing_key} | exclude_fields=transactionID,senderNonce |

    """
    cert_template = certbuildutils.prepare_cert_template_from_csr(csr)
    message = prepare_cert_req_msg(
        private_key=signing_key,
        common_name=None,
        cert_req_id=params.get("cert_req_id", 0),
        hash_alg=params.get("hash_alg", "sha256"),
        extensions=params.get("extensions", None),
        controls=params.get("controls"),
        ra_verified=params.get("ra_verified", False),
        for_kga=params.get("for_kga", False),
        cert_template=cert_template,
        popo_structure=params.get("popo"),
        bad_pop=params.get("bad_pop", False),
    )
    messages = utils.ensure_list(cert_req_msg)
    messages.append(message)
    return _prepare_build_cert_req_msgs_pkimessage(
        body_name="ccr",
        cert_req_msg=messages,
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )


def calculate_cert_hash(  # noqa D417 undocumented-param
    cert: rfc9480.CMPCertificate, hash_alg: Optional[str] = None, different_hash: bool = False
) -> bytes:
    """Calculate a cryptographic hash for a `certConf` PKIMessage.

    Arguments:
    ---------
        - `cert`: The certificate object for which the hash is calculated.
        - `hash_alg`: An optional string specifying the hash algorithm to use (e.g., "sha256"). \
        If not provided, the algorithm is inferred from the certificate's signature.
        - `different_hash`: Whether to use a hash algorithm different from the one specified in the certificate's \
        signature. Defaults to `False`.

    Returns:
    -------
        - The calculated certificate hash as `bytes`.

    Raises:
    ------
        - `ValueError`: If no hash algorithm can be determined from the certificate and none is provided. \
        (The certificate was signed as an example by "ed25519" private key.)

    Examples:
    --------
    | ${cert_hash}= | Calculate Cert Hash | cert=${certificate} |
    | ${cert_hash}= | Calculate Cert Hash | cert=${certificate} | hash_alg=sha256 |
    | ${cert_hash}= | Calculate Cert Hash | cert=${certificate} | different_hash=True |

    """
    sig_algorithm = cert["signatureAlgorithm"]["algorithm"]
    if different_hash:
        hash_alg = oid_mapping.get_hash_from_oid(sig_algorithm, only_hash=True)
        if hash_alg == "sha256":
            hash_alg = "sha512"
        else:
            hash_alg = "sha256"

    if hash_alg is None:
        hash_alg = oid_mapping.get_hash_from_oid(sig_algorithm, only_hash=True)

    if hash_alg is None:
        raise ValueError(
            "The certificate was signed with a key, which does not use "
            "a hash algorithm for signing, and none was provided."
        )

    der_cert = asn1utils.encode_to_der(cert)
    hash_value = oid_mapping.compute_hash(hash_alg, der_cert)
    return hash_value


@keyword(name="Prepare CertStatus")
def prepare_certstatus(  # noqa D417 undocumented-param
    cert_hash: Optional[bytes] = None,
    hash_alg: Optional[str] = None,
    cert_req_id: Strint = 0,
    status: str = "accepted",
    status_info: Optional[rfc9480.PKIStatusInfo] = None,
    failinfo: Optional[str] = None,
    text: Optional[str] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    bad_cert_id: bool = False,
    different_hash: bool = False,
) -> rfc9480.CertStatus:
    """Prepare a `CertStatus` structure for a certificate confirmation `certConf` PKIMessage.

    Generates a CertStatus pyasn1 structure used in certificate confirmation messages to prove that the
    correct certificate was received and that the certificate was either accepted or rejected.

    Arguments:
    ---------
        - `cert_hash`: The hash of the certificate to be included in the `CertStatus` structure.
        - `hash_alg`: The name of the hash algorithm used for the certificate hash.
          If provided, the algorithm is included in the `CertStatus`.
        - `cert_req_id`: The certificate request ID, which identifies the certificate request being confirmed.
          Defaults to `0`.
        - `status`: The status of the certificate request, typically `"accepted"` or `"rejection"`.
          Defaults to `"accepted"`.
        - `status_info`: Optional pre-built status information to include in the `CertStatus`.
        - `failinfo`: Additional failure information to include in the status, if applicable.
          Used when the status is not `"accepted"`.
        - `text`: An optional text message to include in the status information.
        - `cert`: An optional certificate to use for the hash algorithm, if none is provided.
        - `bad_pop`: If `True`, the Proof of Possession (POPO) will be manipulated to create an invalid signature.
        - `different_hash`: If `True`, a different hash algorithm is used for the certificate hash.

    Returns:
    -------
        - The populated `CertStatus` structure.

    Examples:
    --------
    | ${cert_status}= | Prepare CertStatus | ${cert_hash} | hash_alg=sha256 | cert_req_id=1 |
    | ${cert_status}= | Prepare CertStatus | ${cert_hash} | status=rejection | failinfo=badCertId |
    | ${cert_status}= | Prepare CertStatus | ${cert_hash} | hash_alg=sha512 \
    | status=rejection | text=Certificate issued with modifications |

    """
    cert_status = rfc9480.CertStatus()

    cert_status["certReqId"] = int(cert_req_id)

    if status_info is not None:
        cert_status["statusInfo"] = status_info

    elif status != "accepted" or failinfo:
        cert_status["statusInfo"] = prepare_pkistatusinfo(status, failinfo=failinfo, texts=text)

    if hash_alg is not None:
        cert_status["hashAlg"]["algorithm"] = oid_mapping.sha_alg_name_to_oid(hash_alg)

    if hash_alg is None and cert is not None:
        sig_algorithm = cert["signatureAlgorithm"]["algorithm"]
        hash_alg = oid_mapping.get_hash_from_oid(sig_algorithm, only_hash=True)
        if different_hash:
            if hash_alg == "sha256":
                hash_alg = "sha512"
            else:
                hash_alg = "sha256"
            cert_status["hashAlg"]["algorithm"] = oid_mapping.sha_alg_name_to_oid(hash_alg)

    if cert is not None and not cert_hash and hash_alg:
        cert_hash = oid_mapping.compute_hash(alg_name=hash_alg, data=encoder.encode(cert))

    if cert_hash is not None:
        if bad_cert_id:
            cert_hash = utils.manipulate_first_byte(cert_hash)

        cert_status["certHash"] = univ.OctetString(cert_hash)

    if cert_hash is None:
        raise ValueError("No certificate hash provided, but be prepared or calculated.")

    return cert_status


def _prepare_cert_conf(cert_status: Union[List[rfc9480.CertStatus], rfc9480.CertStatus]) -> rfc9480.CertConfirmContent:
    """Create a `CertConfirmContent` structure for certificate confirmation.

    :param cert_status: A single or a list of `CertStatus` objects to include in the `CertConfirmContent` object.
    :return: A `CertConfirmContent` structure containing the certificate confirmation status(es).
    """
    if isinstance(cert_status, rfc9480.CertStatus):
        cert_status = [cert_status]

    cert_conf = rfc9480.CertConfirmContent().subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 24))
    cert_conf.extend(cert_status)
    return cert_conf


def _gen_unique_byte_seq(  # pylint: disable=inconsistent-return-statements
    in_use: List[bytes], size_num: int = 16
) -> bytes:  # type: ignore
    """Generate a unique byte sequence.

    :param in_use: The list with already used byte sequences.
    :param size_num: The size of the byte sequence to generate.
    :return: A unique byte sequence.
    :raises ValueError: If a unique byte sequence cannot be generated, after 10000 attempts.
    """
    val = None
    for _ in range(10000):
        val = os.urandom(size_num)
        if val not in in_use:
            return val
        val = None

    if val is None:
        raise ValueError("Could not generate a unique byte sequence")


def _patch_nested_pkimessage(target: PKIMessageTMP, exclude_fields: List[str]) -> PKIMessageTMP:
    """Patch a nested PKIMessage with

    :param target: The PKIMessage to patch.
    :param exclude_fields: A list of fields to exclude from patching.
    Which can either be senderNonce or transactionID.
    :return: The patched PKIMessage.
    """
    if target["body"].getName() != "nested":
        raise ValueError("Target `PKIMessage` is not a nested message")

    if len(target["body"]["nested"]) == 0:
        raise ValueError("Target `PKIMessage` has no nested messages")

    # must have different transactionID and senderNonce
    ids = []
    if "transactionID" not in exclude_fields:
        for entry in target["body"]["nested"]:
            if entry["header"]["transactionID"].isValue:
                ids.append(entry["header"]["transactionID"].asOctets())

        val = _gen_unique_byte_seq(ids)
        target = patch_transaction_id(target, new_id=val)

    nonces = []
    if "senderNonce" not in exclude_fields:
        for entry in target["body"]["nested"]:
            if entry["header"]["senderNonce"].isValue:
                nonces.append(entry["header"]["senderNonce"].asOctets())

        val = _gen_unique_byte_seq(nonces)
        target = patch_sendernonce(target, sender_nonce=val)

    return target


@keyword(name="Patch PKIMessage Header with Other PKIMessage")
def patch_pkimessage_header_with_other_message(  # noqa D417 undocumented-param
    target: PKIMessageTMP,
    other_message: Optional[PKIMessageTMP] = None,
    include_fields: Optional[str] = None,
    exclude_fields: Optional[str] = None,
    for_nested: bool = False,
    for_exchange: bool = False,
    for_added_protection: bool = False,
) -> PKIMessageTMP:
    """Patch a `PKIMessage` with another `PKIMessage`.

    Can either be used to directly patch a message for added protection or patch a nested message.
    Because the nested messages need to have different `transactionID` and `senderNonce`.
    Or just patch a message for exchange, the sender and recipient should be excluded, because
    of intermediate hops.

    Arguments:
    ---------
        - `target`: The PKIMessage to patch.
        - `other_message`: The PKIMessage to patch with. Defaults to `None`.
        - `include_fields`: PKIHeader fields to include. Defaults to `None`.
        - `exclude_fields`: PKIHeader fields to exclude. Defaults to `None`.
        - `for_nested`: Whether to patch a nested message. Defaults to `False`.
        - `for_exchange`: Whether to patch a message for exchange. Defaults to `False`.
        The exclude field names must be set in the reversed order.
        - `for_added_protection`: Whether to patch a message for added protection. Defaults to `False`.

    Returns:
    -------
        - The patched `PKIMessage`.

    Raises:
    ------
        - ValueError: If `for_nested` is `True` and target is not a nested message.
        - ValueError: If `other_message` is not provided and `include_fields` or `for_exchange` is `True`.

    Examples:
    --------
    | ${patched_message}= | Patch PKIMessage with Other PKIMessage | ${pki_message} | other_message=${other_message} |
    | ${patched_message}= | Patch PKIMessage with Other PKIMessage | ${pki_message} | other_message=${other_message} \
    | include_fields=sender |
    | ${patched_message}= | Patch PKIMessage with Other PKIMessage | ${pki_message} | other_message=${other_message} \
    | for_nested=True |
    | ${patched_message}= | Patch PKIMessage with Other PKIMessage | ${pki_message} | other_message=${other_message} \
    | for_exchange=True |
    | ${patched_message}= | Patch PKIMessage with Other PKIMessage | ${pki_message} | for_added_protection=True |

    """
    if (include_fields or for_exchange) and other_message is None:
        raise ValueError("include_fields or for_exchange requires `other_message`")

    if include_fields:
        fields = include_fields.split(",")
        for field in fields:
            target["header"][field] = other_message["header"][field]  # type: ignore

    if for_exchange:
        if other_message is None:
            raise ValueError("for_exchange requires `other_message` to be provided!")

        fields = extract_fields_for_exchange(other_message, exclude_fields, for_py_functions=False)
        for field, value in fields.items():
            target["header"][field] = value

        return target

    if for_added_protection:
        to_exclude = exclude_fields.split(",") if exclude_fields else []
        if target["body"].getName() != "nested":
            raise ValueError("Target `PKIMessage` is not a nested message")

        if len(target["body"]["nested"]) == 0:
            raise ValueError("Target `PKIMessage` has no nested messages")

        entry = target["body"]["nested"][0]

        # MUST have the same transactionID and senderNonce.
        if "transactionID" not in to_exclude:
            target["header"]["transactionID"] = entry["header"]["transactionID"]

        if "senderNonce" not in to_exclude:
            target["header"]["senderNonce"] = entry["header"]["senderNonce"]

        return target

    if for_nested:
        exclude = exclude_fields.split(",") if exclude_fields else []
        return _patch_nested_pkimessage(target, exclude)

    return target


@not_keyword
def extract_fields_for_exchange(
    other_msg: PKIMessageTMP,
    exclude_fields: Optional[str] = None,
    for_py_functions: bool = True,
    use_fresh_nonce: bool = False,
) -> dict:
    """Extract fields from a `PKIMessage`, to patch another one.

    :param other_msg: The `PKIMessage` to extract fields from.
    :param exclude_fields: The fields to exclude.
    :param for_py_functions: Whether to use the extracted fields for python functions.Defaults to `True`.
    :param use_fresh_nonce: Whether to use a fresh nonce. Defaults to `False`.
    :return: The extracted fields in a dictionary with the field name as key and the value as value.
    """
    to_exclude = exclude_fields or []  # type: ignore
    extracted_fields = {}

    if "transactionID" not in to_exclude:
        transaction_id = other_msg["header"]["transactionID"].asOctets()
        field_name = "transaction_id" if for_py_functions else "transactionID"
        extracted_fields[field_name] = transaction_id

    if "recipNonce" not in to_exclude:
        recipient_nonce = other_msg["header"]["senderNonce"].asOctets()
        field_name = "recip_nonce" if for_py_functions else "recipNonce"
        extracted_fields[field_name] = recipient_nonce

    if "senderNonce" not in to_exclude:
        if not use_fresh_nonce:
            sender_nonce = other_msg["header"]["recipNonce"].asOctets()

        else:
            sender_nonce = os.urandom(16)
        field_name = "sender_nonce" if for_py_functions else "senderNonce"
        extracted_fields[field_name] = sender_nonce

    if "recipKID" not in to_exclude:
        if other_msg["header"]["senderKID"].isValue:
            recip_kid = other_msg["header"]["senderKID"].asOctets()
            field_name = "recip_kid" if for_py_functions else "recipKID"
            extracted_fields[field_name] = recip_kid

    if "senderKID" not in to_exclude:
        if other_msg["header"]["recipKID"].isValue:
            sender_kid = other_msg["header"]["recipKID"].asOctets()
            field_name = "sender_kid" if for_py_functions else "senderKID"
            extracted_fields[field_name] = sender_kid

    return extracted_fields


def _may_set_hash_alg(
    set_for_ed: bool,
    allow_set_hash_for_ed: bool,
    cert: rfc9480.CMPCertificate,
    hash_alg: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Set the hash algorithm for EdDSA signatures.

    :param set_for_ed: Whether the hash algorithm is already set for EdDSA signatures.
    :param allow_set_hash_for_ed: Whether to allow setting the hash algorithm for EdDSA signatures.
    :param cert: The certificate to check.
    :param hash_alg: The hash algorithm to set.
    :return: A tuple with a boolean indicating whether the hash algorithm was set and the hash algorithm.
    """
    if allow_set_hash_for_ed and hash_alg is None:
        sig_algorithm = cert["tbsCertificate"]["signature"]["algorithm"]
        hash_alg = oid_mapping.get_hash_from_oid(sig_algorithm, only_hash=True)
        pubic_key = certutils.load_public_key_from_cert(cert)  # type: ignore
        if hash_alg is None:
            set_for_ed = True
            hash_alg = envdatautils.get_digest_from_key_hash(pubic_key)  # type: ignore
            return set_for_ed, hash_alg
        return set_for_ed, None

    return set_for_ed, hash_alg


def _process_single_cert_conf_cert(
    tmp_cert: rfc9480.CMPCertificate,
    hash_alg: Optional[str] = None,
    cert_req_id: Optional[Strint] = None,
    status_info: Optional[rfc9480.PKIStatusInfo] = None,
    cert_hash: Optional[bytes] = None,
    allow_set_hash: bool = True,
    set_for_ed: bool = False,
) -> Tuple[rfc9480.CertStatus, bool]:
    """Process a single certificate for `certConf` PKIMessage.

    :param tmp_cert: The certificate to process.
    :param hash_alg: The hash algorithm to use for the certificate. Defaults to `None`.
    :param cert_req_id: The certificate request ID. Defaults to `0`.
    :param status_info: The status information to include in the `CertStatus`.
    :param cert_hash: The hash of the certificate. Defaults to `None`.
    :param allow_set_hash: Whether to allow setting the hash algorithm for EdDSA signatures or
    other algorithms. Defaults to `True`.
    """
    # To remove the tagging.
    cert = copy_asn1_certificate(cert=tmp_cert)
    set_for_ed, digest_alg = _may_set_hash_alg(set_for_ed, allow_set_hash, cert, hash_alg)

    cert_status = prepare_certstatus(
        hash_alg=digest_alg,
        cert=cert,
        cert_req_id=0 if cert_req_id is None else int(cert_req_id),
        status="accepted",
        status_info=status_info,
        cert_hash=cert_hash,
    )
    return cert_status, set_for_ed


def _get_cert_req_id(
    cert_resp: rfc9480.CertResponse,
    length: int = 0,
    cert_req_id: Optional[Strint] = None,
) -> Strint:
    """Get the certificate request ID from the response message.

    :param cert_resp: The `CertResponse` object from which to extract the ID.
    :param length: The length of the certificate request ID. Defaults to `0`.
    :param cert_req_id: The certificate request ID to use. If not provided, it will be extracted from the response.
    """
    if length == 1 and cert_req_id is None:
        # To fix for `p10cr` response were the certReqId is `-1`.
        return max(int(cert_resp["certReqId"]), 0)
    return int(cert_req_id) if cert_req_id is not None else int(cert_resp["certReqId"])


@keyword(name="Build Cert Conf From Resp")
def build_cert_conf_from_resp(  # noqa D417 undocumented-param
    ca_message: PKIMessageTMP,
    recipient: str = "testr@example.com",
    sender: str = "tests@example.com",
    cert_status: Union[rfc9480.CertStatus, List[rfc9480.CertStatus], None] = None,
    exclude_fields: Optional[str] = None,
    hash_alg: Optional[str] = None,
    cert_req_id: Optional[Strint] = None,
    **params,
) -> PKIMessageTMP:
    """Create a certConf PKIMessage from a response PKIMessage.

    Builds a `certConf` PKIMessage based on a previously received response PKIMessage.
    It extracts fields like `transactionID`, `senderNonce`, `recipNonce`, and others from the response
    and uses them to construct a new PKIMessage for certificate confirmation (`certConf`). The extracted
    values can be overridden by passing them as keyword arguments in `params`.

    Arguments:
    ---------
        - `ca_message`: The response PKIMessage from which to extract fields for the new certConf message.
        - `sender`: The sender of the request. Defaults to "test-cmp-cli@example.com".
        - `recipient`: The recipient of the request. Defaults to "test-cmp-srv@example.com".
            - Other fields as per `certConf` requirements.
        - `cert_status`: A `CertStatus` object or a list of `CertStatus` objects. If not provided, it will be generated
         for all issued certificates.
        - `exclude_fields`: A comma-separated list of fields to omit from the PKIHeader.
        - `hash_alg`: The hash algorithm to use for calculating the certificate hash. Defaults to `None`.


    **params:
    ----------
       - Additional parameters for customizing the `PKIHeader`:
       - `status_info` (PKISatusInfo): PKISatusInfo object to include in the `CertStatus`.
       - `cert_req_id` (int, str): The certificate request ID. Defaults to `0`.
       - `cert_hash` (bytes): The hash of the certificate to confirm.
       - `for_mac` (bool): Flag indicating if the message is for MAC. Defaults to `False`.
       ( set the sender inside the directoryName choice of the GeneralName structure)
       - `allow_set_hash` (bool): Flag indicating if the hash can be automatically set for EdDSA signatures or
       other algorithms which do not use a direct hash algorithm. Defaults to `True`.
       - `use_fresh_nonce` (bool): Flag indicating if a fresh nonce should be used for the `senderNonce` or the
         `recipNonce` from the request. Defaults to `True`.


    Returns:
    -------
        - A PKIMessage of type `certConf`, constructed using the extracted values from the response PKIMessage
          and any provided parameters.

    Raises:
    ------
        - `ValueError`: If required fields are missing from the `response_pki_message`.

    Examples:
    --------
    | ${cert_conf}= | Build Cert Conf From Resp | ${response} | sender=tests@example.com | recipient=testr@example.com |
    | ${cert_conf}= | Build Cert Conf From Resp | ${response} | sender=tests@example.com | transaction_id=${new_id} |

    """
    extracted_fields = extract_fields_for_exchange(ca_message, use_fresh_nonce=params.get("use_fresh_nonce", True))
    for key, value in extracted_fields.items():
        if key not in params:
            params[key] = value

    message_type = ca_message["body"].getName()
    if message_type not in {"cp", "kup", "ip", "ccp"}:
        raise ValueError(f"The provided `PKIBody` does not contain a certificate. Got: `{message_type}`")

    cert_status_list = []
    set_for_ed = False

    if params.get("cert") is not None:
        tmp_cert = params.get("cert")
        if not isinstance(tmp_cert, rfc9480.CMPCertificate):
            raise ValueError("The provided `cert` is not a valid `CMPCertificate` object.")
        cert_status, set_for_ed = _process_single_cert_conf_cert(
            tmp_cert=tmp_cert,
            hash_alg=hash_alg,
            cert_req_id=cert_req_id,
            status_info=params.get("status_info"),
            cert_hash=params.get("cert_hash"),
            allow_set_hash=params.get("allow_set_hash", True),
        )
        cert_status_list.append(cert_status)

    elif cert_status is None:
        cert_resp_msg: rfc9480.CertRepMessage = ca_message["body"][message_type]["response"]
        entry: rfc9480.CertResponse
        for i, entry in enumerate(cert_resp_msg):
            # remove the tagging.
            cert_req_id = _get_cert_req_id(
                cert_resp=entry,
                length=len(cert_resp_msg),
                cert_req_id=cert_req_id,
            )

            tmp_cert = get_cert_from_pkimessage(ca_message, cert_number=i)

            cert_status, set_for_ed = _process_single_cert_conf_cert(
                tmp_cert=tmp_cert,
                hash_alg=hash_alg,
                cert_req_id=cert_req_id,
                status_info=params.get("status_info"),
                cert_hash=params.get("cert_hash"),
                allow_set_hash=params.get("allow_set_hash", True),
            )
            cert_status_list.append(cert_status)
    else:
        if isinstance(cert_status, rfc9480.CertStatus):
            cert_status = [cert_status]

        cert_status_list.extend(cert_status)

    pki_body = rfc9480.PKIBody()
    pki_body["certConf"] = _prepare_cert_conf(cert_status_list)

    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        transaction_id=params.get("transaction_id"),
        sender_nonce=params.get("sender_nonce"),
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=params.get("pvno"),
        for_mac=params.get("for_mac", False),
        update_hash=set_for_ed,
    )
    pki_message["body"] = pki_body
    return pki_message


@keyword(name="Build Cert Conf")
def build_cert_conf(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    status: str = "accepted",
    exclude_fields: Optional[str] = None,
    hash_alg: Optional[str] = None,
    cert_hash: Optional[bytes] = None,
    cert_status: Optional[rfc9480.CertStatus] = None,
    status_info: Optional[rfc9480.PKIStatusInfo] = None,
    **params,
) -> PKIMessageTMP:
    """Create a `certConf` PKIMessage for certificate confirmation.

    This allows the issuing PKI Management entity to verify that the correct certificate was received
    and that the certificate was either accepted or rejected.

    Arguments:
    ---------
        - `cert`: An optional certificate object representing the certificate to confirm.
        If provided, it is used to calculate the certificate hash.
        - `sender`: The sender of the request. Defaults to "test-cmp-cli@example.com".
        - `recipient`: The recipient of the request. Defaults to "test-cmp-srv@example.com".
        - `status`: The status of the certificate (e.g., "accepted" or "rejected"). Defaults to "accepted".
        - `exclude_fields`: A comma-separated list of field names to omit from the PKIMessage header.
        - `hash_alg`: The hash algorithm to use for calculating the certificate hash. Defaults to `None`.
        - `cert_hash`: The hash of the certificate, if already computed. Defaults to `None`.
        - `cert_status`: An optional `CertStatus` object representing the status of the certificate.
        If not provided, one will be generated.
        - `status_info`: Additional status information as a `PKIStatusInfo` object.

    `**params`: Additional parameters for customizing the `PKIHeader`:
        - `transaction_id` (bytes): The transaction ID for the message.
        - `sender_nonce` (bytes): A nonce generated by the sender.
        - `recip_nonce` (bytes): A nonce generated by the recipient.
        - `recip_kid` (bytes): The recipient's key identifier.
        - `implicit_confirm` (bool): Flag indicating if implicit confirmation is not needed. Defaults to `False`
        (confirmation is required).
        - `sender_kid` (bytes): The sender's key identifier.
        - `pvno` (int, str): The protocol version number. Defaults to `2`.
        - `cert_req_id` (int, str): The certificate request ID. Defaults to `0`.
        - `for_mac` (bool): Flag indicating if the message is MAC protected. Defaults to `False`.
        ( set the sender inside the directoryName choice of the GeneralName structure)
        .

    Returns:
    -------
        - The populated `PKIMessage` with the `certConf` `PKIBody`.

    Raises:
    ------
        - `ValueError`: If neither `cert`, `cert_hash`, nor `cert_status` is provided.

    Examples:
    --------
    | ${cert_conf_msg}= | Build Cert Conf | cert=${certificate} |
    | ${cert_conf_msg}= | Build Cert Conf | cert_hash=${hash_bytes} |
    | ${cert_conf_msg}= | Build Cert Conf | cert=${certificate} | status="rejected" | hash_alg=sha512 |
    | ${cert_conf_msg}= | Build Cert Conf | cert=${certificate} | transaction_id=${trans_id} | implicit_confirm=True |

    """
    if not cert and not cert_hash and not cert_status:
        raise ValueError(
            "At least one of `cert`, `cert_hash`, or `cert_status` must be provided to build a certConf message."
        )

    if cert is not None:
        cert = convertutils.copy_asn1_certificate(cert)

    if cert_hash is None and cert_status is None and cert is not None:
        cert_hash = calculate_cert_hash(cert, hash_alg)

    if cert_status is None:
        cert_status = prepare_certstatus(
            cert_hash=cert_hash, cert_req_id=params.get("cert_req_id", 0), status=status, status_info=status_info
        )

    pki_body = rfc9480.PKIBody()
    pki_body["certConf"] = _prepare_cert_conf(cert_status)

    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        transaction_id=params.get("transaction_id"),
        sender_nonce=params.get("sender_nonce"),
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=int(params.get("pvno", 2)),
        for_mac=params.get("for_mac", False),
    )
    pki_message["body"] = pki_body

    return pki_message


@keyword(name="Parse PKIMessage")
def parse_pkimessage(data: bytes) -> PKIMessageTMP:  # noqa D417 undocumented-param
    """Parse input data to PKIMessage structure and return the resulting object.

    Arguments:
    ---------
        - `data`: The raw input data to be parsed.

    Returns:
    -------
        - The `PKIMessage` structure.

    Raises:
    ------
        - `ValueError` if the input cannot be correctly parsed into a PKIMessage.

    Examples:
    --------
    | ${pki_message}= | Parse PKIMessage | ${response.content} |

    """
    try:
        pki_message, _remainder = decoder.decode(data, asn1Spec=PKIMessageTMP())

        if pki_message["body"].getName() == "nested":
            data = pki_message["body"]["nested"]
            msgs = PKIMessagesTMP().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 20))
            der_data = encoder.encode(data)
            msgs, _ = decoder.decode(der_data, msgs)
            # to clear the entries.
            pki_message["body"]["nested"] = PKIMessagesTMP().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 20)
            )
            for x in msgs:
                pki_message["body"]["nested"].append(x)

    except PyAsn1Error as err:
        # Suppress detailed pyasn1 error messages; they are typically too verbose and
        # not helpful for non-pyasn1 experts. If debugging is needed, retrieve the server's
        # response from Robot Framework's log and manually pass it into this function.
        raise ValueError(f"Failed to parse PKIMessage: {str(err)[:100]} ...") from err

    return pki_message


@keyword(name="Get Status From PKIMessage")
def get_status_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, response_index: Strint = 0
) -> str:
    """Return the status of a pyasn1 `PKIMessageTMP` object as a string.

    Arguments:
    ---------
         - `pki_message`: The PKIMessage object from which to extract the `certReqId`.
         - `response_index`: The index of the response from which to extract the `certReqId`. Defaults to `0`.

    Returns:
    -------
        - `status` in a human-readable string.

    Raises:
    ------
        - `ValueError`: If the `PKIBody` of the PKIMessage is not of type: `cp`, `kup`,
        `ip, `rr` or `error.`

    Examples:
    --------
     | ${status}= | Get Status From PKIMessage | ${pki_message} | response_index=1 |
     | ${status}= | Get Status From PKIMessage | ${pki_message} |

    """
    return str(get_pkistatusinfo(pki_message, response_index)["status"])


@keyword(name="Get CertReqId From PKIMessage")
def get_certreqid_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, response_index: Strint = 0
) -> int:
    """Extract the `certReqId` from a `PKIMessage`.

    Retrieves the `certReqId` from the specified response within a PKIMessage. The `certReqId` is
    typically used to identify the certificate request in CMP messages.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage object from which to extract the `certReqId`.
        - `response_index`: The index of the response from which to extract the `certReqId`. Defaults to `0`.

    Returns:
    -------
        - The `certReqId` as an integer.

    Raises:
    ------
        - `ValueError`: If the `PKIBody` of the PKIMessage is not of type: `cp`, `kup`, or `ip.

    Examples:
    --------
     | ${cert_req_id}= | Get CertReqId From PKIMessage | ${pki_message} | response_index=1 |
     | ${cert_req_id}= | Get CertReqId From PKIMessage | ${pki_message} |

    """
    response = get_cert_response_from_pkimessage(pki_message, int(response_index))
    cert_req_id = response["certReqId"]
    return int(cert_req_id)


@keyword(name="Get CMP Message Type")
def get_cmp_message_type(pki_message: PKIMessageTMP) -> str:  # noqa D417 undocumented-param
    """Return the body type of an pyasn1 object representing a PKIMessage as a string, e.g., rp, ip.

    Arguments:
    ---------
        - `pki_message`: The object to get the body name from.

    Returns:
    -------
        - The name of the body.

    Examples:
    --------
    | ${body_name}= | Get CMP Message Type | ${pki_message} |


    """
    return pki_message["body"].getName()


@keyword(name="Get CertResponse From PKIMessage")
def get_cert_response_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, response_index: Strint = 0
) -> rfc9480.CertResponse:
    """Extract a `CertResponse` from a CA `PKIMessage`.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage object from which to extract the `CertResponse`.
        - `response_index`: The index of the response to extract. Defaults to `0`.

    Returns:
    -------
        - The extracted `CertResponse` object from the PKIMessage.

    Raises:
    ------
        - `ValueError`: If the `PKIBody` of the PKIMessage is not of type: `cp`, `kup`, `ccp` or `ip.

    Examples:
    --------
    | ${cert_response}= | Get Cert Response From PKIMessage | ${pki_message} | response_index=1 |
    | ${cert_response}= | Get Cert Response From PKIMessage | ${pki_message} |

    """
    message_type = get_cmp_message_type(pki_message)

    if message_type == "error":
        logging.debug(utils.display_pki_status_info(pki_message, index=response_index))
        raise ValueError("The provided `PKIMessage` is an error message, which does not contain a certificate.")

    if message_type not in {"cp", "kup", "ip", "ccp"}:
        raise ValueError(f"The provided `PKIBody` does not contain a certificate. Got: `{message_type}`")

    return pki_message["body"][message_type]["response"][int(response_index)]


def _get_cert_from_krp_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
) -> rfc9480.CMPCertificate:
    """Extract a certificate from a KRP `PKIMessage`.

    :param pki_message: The PKIMessage object from which to extract the certificate.
    :return: The extracted certificate object from the KRP PKIMessage.
    """
    if get_cmp_message_type(pki_message) != "krp":
        raise ValueError("The provided PKIMessage is not a KRP message.")

    new_sig_cert = pki_message["body"]["krp"]["newSigCert"]

    if not new_sig_cert.isValue:
        raise ValueError("The provided `krp` PKIMessage did not have the `newSigCert` field set.")

    cert = convertutils.copy_asn1_certificate(new_sig_cert)
    return cert


@keyword(name="Get Cert From PKIMessage")
def get_cert_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    cert_number: Strint = 0,
) -> rfc9480.CMPCertificate:
    """Extract a certificate from a `PKIMessage`.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage from which the certificate is to be extracted.
        - `cert_number`: Optional index of the certificate to extract from the response. Defaults to `0`.

    Returns:
    -------
       - A certificate object representing the newly issued certificate.

    Raises:
    ------
        - `ValueError`: If the provided PKIMessage does not contain a valid certificate body type
          (e.g., `cp`, `kup`, `ip`, `krp`).

    Examples:
    --------
    | ${cert}= | Get Cert From PKIMessage | ${pki_message} |
    | ${cert}= | Get Cert From PKIMessage | ${pki_message} | cert_number=1 |

    """
    if get_cmp_message_type(pki_message) == "krp":
        return _get_cert_from_krp_pkimessage(pki_message)

    response = get_cert_response_from_pkimessage(pki_message, response_index=cert_number)

    if not response["certifiedKeyPair"].isValue:
        raise ValueError("The provided PKIMessage did not had the `certifiedKeyPair` field set.")

    if not response["certifiedKeyPair"]["certOrEncCert"].isValue:
        raise ValueError("The provided PKIMessage did not had the `certOrEncCert` field set.")

    cert = response["certifiedKeyPair"]["certOrEncCert"]["certificate"]
    if not cert.isValue:
        raise ValueError("The provided PKIMessage does not contain a certificate.")
    # To remove the tagging.
    cert = convertutils.copy_asn1_certificate(cert)
    return cert


@keyword(name="Parse CSR")
def parse_csr(raw_csr: bytes) -> rfc6402.CertificationRequest:  # noqa D417 undocumented-param
    """Parse a pyasn1-structured CSR out of raw bytes.

    Arguments:
    ---------
        - `raw_csr`: DER encoded CSR.

    Returns:
    -------
        - The decoded `pyasn1` `CertificationRequest`

    Examples:
    --------
    | ${csr}= | Parse CSR | ${der_data} |

    """
    csr, _ = decoder.decode(raw_csr, asn1Spec=rfc6402.CertificationRequest())
    return csr


@keyword(name="Find OID In generalInfo")
def find_oid_in_general_info(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, oid: str
) -> bool:
    """Check if a given OID is present in the generalInfo part of a PKIMessage header.

    Iterates through the `generalInfo` sequence within the PKIMessage header to determine
    whether the specified Object Identifier (OID) is present in any of the `infoType` fields of the
    `InfoTypeAndValue` entries. But does not check if the `infoValue` is set.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage object representing the message whose header
          will be inspected.
        - `oid`: The OID string to search for within the `generalInfo` field. It should be in
          dotted string format (e.g., "1.2.840.113549.1.9.16.1.4").

    Returns:
    -------
        - `True` if the OID is found in the `generalInfo` field; otherwise, `False`.

    Examples:
    --------
    | ${is_oid_present}= | Find OID In General Info | ${pki_message} | oid=1.3.6.1.5.5.7.4.1 |

    """
    # generalInfo [8] SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue OPTIONAL
    # generalInfo is a sequence, we iterate through it and look for the OID we need
    general_info = pki_message["header"]["generalInfo"]
    oid_obj = univ.ObjectIdentifier(oid)
    for entry in general_info:
        if entry["infoType"] == oid_obj:
            return True

    return False


@not_keyword
def get_value_from_seq_of_info_value_field(data: univ.SequenceOf, oid: univ.ObjectIdentifier) -> Union[None, univ.Any]:
    """Return the value of the oid.

    :param data: Sequence of `InfoTypeAndValue`
    :param oid: ObjectIdentifier.
    :return: None or the value of the oid.
    """
    x: rfc9480.InfoTypeAndValue
    for x in data:
        if x["infoType"] == oid:
            return x["infoValue"]

    return None


# this is a Python implementation of the RobotFramework keyword `Try to Log PKIMessage as ASN1`. Viewing
# the output of this one requires fewer clicks in the reports.
@keyword(name="Try To Log PKIMessage")
def try_to_log_pkimessage(data: Union[str, bytes, base.Asn1Type]):  # noqa: D417 for RF docs
    """Try to decode a DER-encoded PKIMessage and log the ASN1 structure in a human-readable way.

    Will also accept inputs that are pyasn1 objects or strings, for the convenience of invocation from RF tests.

    Arguments:
    ---------
        - `data`: something that is assumed to be a PKIMessage structure, either DER-encoded or a pyasn1 object.

    Examples:
    --------
    | Try To Log PKIMessage | ${der_data} |
    | Try To Log PKIMessage | ${message} |

    """
    if isinstance(data, base.Asn1Type):
        logging.info(data.prettyPrint())
        return

    if isinstance(data, str):
        data = bytes(data, "utf-8")

    try:
        parsed = parse_pkimessage(data)
    except ValueError:
        logging.info("Cannot prettyPrint this, it does not seem to be a valid PKIMessage")
    else:
        logging.info(parsed.prettyPrint())


@not_keyword
def prepare_extra_certs(certs: Sequence[rfc9480.CMPCertificate]):
    """Build the pyasn1 `PKIMessageTMP.extraCerts` field with a list of `rfc9480.CMPCertificate`.

    :param certs: A list with `rfc9480.CMPCertificate`
    :return: An `univ.SequenceOf` object filled with `rfc9480.CMPCertificate` instances.
    """
    extra_certs_wrapper: univ.SequenceOf = (
        univ.SequenceOf(componentType=rfc9480.CMPCertificate())  # type: ignore
        .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX))
        .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 1))
    )

    extra_certs_wrapper.extend(certs)

    return extra_certs_wrapper


@not_keyword
def prepare_extra_certs_from_path(path: str, recursive: bool = False) -> univ.SequenceOf:
    """Load certificates from a file or directory and return a `univ.SequenceOf` structure tagged for use in PKIMessage.

    :param path: Path to a file or a directory where the certificates are stored.
    :param recursive: If `True`, search recursively through the directory.
    :return: An `univ.SequenceOf` object filled with `rfc9480.CMPCertificate` instances.
    """
    extra_certs_wrapper = (
        univ.SequenceOf(componentType=rfc9480.CMPCertificate())  # type: ignore
        .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX))
        .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 1))
    )

    paths = glob.glob(path, recursive=recursive) if os.path.isdir(path) else [path]

    for file in paths:
        raw = utils.load_and_decode_pem_file(file)
        cert = certutils.parse_certificate(raw)
        extra_certs_wrapper.append(cert)

    return extra_certs_wrapper


@keyword(name="Prepare InfoTypeAndValue")
def prepare_info_type_and_value(  # noqa: D417 undocumented-param
    oid: Union[univ.ObjectIdentifier, str], value: Union[None, bytes, str, Asn1Type] = None, fill_random: bool = False
) -> rfc9480.InfoTypeAndValue:
    """Prepare an `InfoTypeAndValue` structure with the given ObjectIdentifier and optional value.

    Arguments:
    ---------
        - `oid`: The OID to set for the `infoType` field. Either as a `pyasn1` `ObjectIdentifier` or a string.
        - `value`: Optional bytes to populate the `infoValue` field. If `None`, the field is left absent.
            Can either be a str which is encoded to bytes or if startswith "0x" interpreted as hex, bytes directly or a
            `pyasn1` object.
        - `fill_random`: Whether to fill the `infoValue` filed with random 16-bytes.

    Returns:
    -------
        - A populated `InfoTypeAndValue` structure.

    Examples:
    --------
    | ${info_val}= | Prepare Info Value | ${oid} | ${value} |

    """
    info_value = rfc9480.InfoTypeAndValue()

    if isinstance(oid, str):
        oid = univ.ObjectIdentifier(oid)

    info_value["infoType"] = oid

    if fill_random:
        value = os.urandom(16)
        value = univ.OctetString(value)

    if isinstance(value, str):
        value = str_to_bytes(value=value)
        value = univ.OctetString(value)

    if value is not None:
        info_value["infoValue"] = value
    return info_value


def _prepare_generalinfo(
    implicit_confirm: bool = True,
    negative_value: bool = False,
    confirm_wait_time: Optional[Strint] = None,
    cert_profile: Optional[str] = None,
) -> univ.SequenceOf:
    """Prepare the `generalInfo` field inside the `PKIHeader` structure.

    Constructs the `generalInfo` field, supporting options for implicit confirmation,
    negative confirmation, confirmation wait time, and a certificate profile.

    :param implicit_confirm: If `True`, includes implicit confirmation information. Defaults to `True`.
    :param negative_value: If set to `True` changes, the datatypes which are expected for confirmWaitTime
    to `UTCTime`, adds random value to the MUST be absent value field for `implicitConfirm`, or
    adds a modified certReqTemplate, and the correct one, if a value is provided.
    :param confirm_wait_time: The wait time in seconds to be included, if specified. Defaults to `None`.
    :param cert_profile: An optional certificate profile value to include. Defaults to `None`.
    :return: The `generalInfo` structure.
    :raises ValueError: If decoding the DER-encoded structure results in leftover bytes.
    """
    general_info_wrapper = (
        univ.SequenceOf(componentType=rfc9480.InfoTypeAndValue())  # type: ignore
        .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX))
        .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 8))
    )

    if implicit_confirm:
        implicit_confirm_obj = prepare_info_type_and_value(
            oid=rfc9480.id_it_implicitConfirm, value=univ.Null(""), fill_random=negative_value
        )
        general_info_wrapper.append(implicit_confirm_obj)

    if confirm_wait_time is not None:
        confirm_wait_time_obj = rfc9480.InfoTypeAndValue()
        confirm_wait_time_obj["infoType"] = rfc9480.id_it_confirmWaitTime

        new_time = datetime.now(timezone.utc)
        new_time = new_time + timedelta(seconds=int(confirm_wait_time))
        if negative_value:
            new_time = useful.UTCTime().fromDateTime(new_time)
        else:
            new_time = useful.GeneralizedTime().fromDateTime(new_time)

        confirm_wait_time_obj["infoValue"] = new_time
        general_info_wrapper.append(confirm_wait_time_obj)

    if cert_profile is not None:
        cert_profile_obj = rfc9480.InfoTypeAndValue()
        value = CertProfileValueAsn1()
        value.append(char.UTF8String(cert_profile))

        if negative_value:
            # MUST be present in the same size as either `GenMsgContent` or `CertReqMsg`.
            value.append(char.UTF8String(modify_random_str(cert_profile)))

        value.append(cert_profile)
        cert_profile_obj["infoType"] = rfc9480.id_it_certProfile
        cert_profile_obj["infoValue"] = value
        general_info_wrapper.append(cert_profile_obj)

    return general_info_wrapper


# 5.3.19.12. Original PKIMessage: 5.1.1.3. OrigPKIMessage
# GenMsg: {id-it 15}, SEQUENCE SIZE (1..MAX) OF PKIMessage or generalInfo
# Validate omitted.


@keyword(name="Prepare Orig PKIMessage")
def prepare_orig_pki_message(  # noqa D417 undocumented-param
    pki_messages: Union[PKIMessageTMP, List[PKIMessageTMP]],
) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` to include the original PKIMessages in the generalInfo field.

    This is used by an RA to include the original PKIMessage received from the EE
    and forward it to the CA for further processing, along with any modifications
    made by the RA.

    Arguments:
    ---------
        - `pki_messages`: The original PKIMessage or PKIMessages from the EE.

    Returns:
    -------
        - The populated `InfoTypeAndValue` structure.

    Examples:
    --------
    | ${info_val}= | Prepare Orig PKIMessage | ${pki_message} |

    """
    # OrigPKIMessageValue
    obj = PKIMessagesTMP()

    if isinstance(pki_messages, PKIMessageTMP):
        pki_messages = [pki_messages]

    obj.extend(pki_messages)
    der_data = encoder.encode(obj)
    return prepare_info_type_and_value(rfc9480.id_it_origPKIMessage, value=der_data)


@not_keyword
def get_common_name_from_str(name: str) -> Union[None, str]:
    """Extract the common name (CN) from a given distinguished name string.

    Parses a distinguished name in OpenSSL notation (e.g., "C=DE, ST=Bavaria,
    L=Munich, CN=CA Name").

    :param name: The distinguished name string to extract the common name from.
    :return: The common name (CN) as a string if found, otherwise `None`.
    """
    if "=" not in name:
        return None

    common_name = ""
    for entry in name.split(","):
        attribute, value = entry.split("=")
        if attribute == "CN":
            common_name += f"CN={value}"

    if not common_name:
        return None

    return common_name


@not_keyword
def contains_extension(
    asn1object: Union[rfc9480.CMPCertificate, rfc4211.CertTemplate], oid: univ.ObjectIdentifier
) -> bool:
    """Check whether a `pyasn1` CertTemplate or CMPCertificate object contains an extension.

    :param asn1object: The object to check.
    :param oid: The `pyasn1` oid to check for.
    :return: `True` if inside the object else `False`
    """
    if isinstance(asn1object, rfc4211.CertTemplate):
        extensions = asn1object["extensions"]
    else:
        extensions = asn1object["tbsCertificate"]["extensions"]

    ext: rfc5280.Extension
    for ext in extensions:
        if ext["extnID"] == oid:
            return True
    return False


@keyword(name="Patch extraCerts")
def patch_extra_certs(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    certs: Sequence[rfc9480.CMPCertificate],
    swap_certs: bool = False,
) -> PKIMessageTMP:
    """Patch the `extraCerts` field in a `PKIMessage` with a provided list of certificates.

    Set the `extraCerts` field of the PKIMessage to the provided list of certificates.
    If `swap_certs` is set to `True`, it swaps the first two certificates in the list before adding them
    to the PKIMessage, useful for testing purposes.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage object to patch.
        - `certs`: A list of `pyasn1` `CMPCertificate` objects to \
        populate the `extraCerts` field with.
        - `swap_certs`: Flag to indicate whether to swap the first two certificates. Defaults to `False`.

    Returns:
    -------
        - The `PKIMessage` with the updated `extraCerts` field.

    Examples:
    --------
    | ${patched_message}= | Patch extraCerts | ${pki_message} | certs=${cert_list} |
    | ${patched_message}= | Patch extraCerts | ${pki_message} | certs=${cert_list} | negative=True |

    """
    if swap_certs:
        certs[0], certs[1] = certs[1], certs[0]  # type: ignore

    pki_message["extraCerts"] = prepare_extra_certs(certs)

    return pki_message


#######################################
# Patching PKIMessage PKIHeader fields
#######################################


@keyword(name="Patch transactionID")
def patch_transaction_id(  # noqa D417 undocumented-param
    pki_message: Union[bytes, PKIMessageTMP],
    new_id: Optional[Union[bytes, str]] = None,
    prefix: Optional[Union[bytes, str]] = None,
):
    """Patch the `transactionID` of a PKIMessage structure with a new ID.

    This is useful when you load a request from a file and send it multiple times to the CA. It would normally reject
    it because the transactionId is repeated - hence the patching.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure or raw DER-encoded data to be patched.
        If a bytes object is provided, it is parsed into a PKIMessage structure before updating.
        - `new_id`: Optional new `transactionID` to, if not provided a random one will be generated. \
        We also allow it to be a string it is converted to bytes using UTF-8 encoding, unless it begins with "0x", \
        in which case it will be interpreted as a hex string.
        - `prefix`:  Optional bytes or str, prefix to use for the transactionId, you will need this if \
        you want the transactionId to be random, but still easily identifiable in the logs; we allow it to be a \
        string it is converted to bytes using UTF-8 encoding, unless it begins with "0x", in which case it will be \
        interpreted as a hex string.

    Returns:
    -------
        - The `PKIMessage` object with the updated `transactionID` field.

    Raises:
    ------
        - `ValueError`: If the `transactionID` cannot be patched due to invalid inputs or if `pki_message`
          is not in the correct format.

    Examples:
    --------
    | ${patched_message}= | Patch transactionID | ${pki_message} | new_id=${new_id} |
    | ${patched_message}= | Patch transactionID | ${pki_message} | prefix=testPrefix |

    """
    if isinstance(pki_message, bytes):
        pki_message = parse_pkimessage(pki_message)

    new_id = new_id or os.urandom(16)
    new_id = convertutils.str_to_bytes(new_id)

    if prefix:
        new_id = convertutils.str_to_bytes(prefix) + new_id

    wrapper_transaction_id = univ.OctetString(new_id).subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 4))
    pki_message["header"]["transactionID"] = wrapper_transaction_id
    return pki_message


@keyword(name="Patch messageTime")
def patch_messageTime(  # noqa D417 undocumented-param pylint: disable=invalid-name
    pki_message: PKIMessageTMP, new_time: Optional[Union[datetime, str]] = None
) -> PKIMessageTMP:
    """Patch the messageTime field of a PKIMessage structure with a new time, or the current time if none is provided.

    Is useful for updating the `messageTime` field in PKIMessages, especially when re-sending requests
    that require a unique timestamp. It can handle both `PKIMessage` objects and raw DER-encoded data by converting
    bytes input into a PKIMessage structure before patching.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage structure or raw DER-encoded data to be patched. \
        If a bytes object is provided, it is parsed into a PKIMessage structure before updating.
        - `new_time`: Specifies the new time to set for the `messageTime` field. If not provided, the current time
        will be used as the default. This parameter can be a string representing the time in the default format used
        by the operating system.

    Returns:
    -------
        - The `PKIMessage` object with the updated `messageTime` field.

    Raises:
    ------
    - `ValueError`: If the `messageTime` field cannot be patched due to invalid inputs or if `pki_message` is not in
      the correct format.

    Examples:
    --------
    | ${patched_message}= | Patch messageTime | ${pki_message} | new_time=${today} |
    | ${patched_message}= | Patch messageTime | ${pki_message} |

    """
    if isinstance(pki_message, bytes):
        pki_message = parse_pkimessage(pki_message)

    message_time = prepareutils.prepare_generalized_time(new_time)
    message_time_subtyped = message_time.subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 0))
    pki_message["header"]["messageTime"] = message_time_subtyped
    return pki_message


def _patch_senderkid_for_mac(sender: rfc9480.GeneralName, negative: bool) -> bytes:
    """Generate a `senderKID` for MAC-based protection using the sender's common name (CN).

    For the MAC-based protection MUST the sender be the common name inside the
    `directoryName` choice, according to rfc9483 Section 3.1. If negative changes a
    random char of the correct `senderKID`, used to ensure that the CA checks the senderKID correctly.

    :param sender: An `rfc9480.GeneralName` object representing the sender's identity.
    Must contain a `directoryName` with a common name.
    :param negative: If True, applies a random modification to the common name (CN).
    :return: The byte-encoded common name of the sender.
    :raises ValueError: The `sender` field is not set, The `sender` is not
    of type `directoryName` or The common name is missing from the `directoryName`.
    """
    if not sender.isValue:
        raise ValueError("The 'sender' field must be present and set for MAC-based protection.")

    if sender.getName() != "directoryName":
        raise ValueError("The 'sender' must be of type 'directoryName' for MAC-based protection.")

    name_obj = sender["directoryName"]
    common_name = utils.get_openssl_name_notation(name_obj, oids=[rfc5280.id_at_commonName])
    if common_name is None:
        raise ValueError("The 'directoryName' must contain a common name (CN) for MAC-based protection.")

    if negative:
        common_name = modify_random_str(common_name)  # type: ignore

    return common_name.encode("utf-8")  # type: ignore


@keyword(name="Patch senderKID")
def patch_senderkid(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    sender_kid: Optional[Union[bytes, rfc9480.CMPCertificate]] = None,  # type: ignore
    for_mac: bool = False,
    negative: bool = False,
) -> PKIMessageTMP:
    """Update or set the `senderKID` field in a PKIMessage header.

    Set or update the `senderKID` field in the header of the provided `PKIMessage`. The value of \
    `senderKID` can be supplied as raw bytes, derived from a certificate’s `SubjectKeyIdentifier` extension, or, \
    if using MAC-based-protection, generated from the sender's common name. The `negative` parameter allows for \
    modification of the `senderKID` for testing purposes to ensure validation. If `negative` is set changes a \
    random byte.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage whose `senderKID` field will be updated.
        - `sender_kid`: A optional new `senderKID` value. It can either be raw bytes or A certificate.
        - `for_mac`: If `True`, and `sender_kid` is not provided, `senderKID` is generated based on the sender's
        common name for MAC-based protection, as specified in RFC 9483 Section 3.1. Defaults to `False`.
        - `negative`: If `True` and `for_mac` is also `True`, a random modification is applied to the `senderKID`
        to test the CA's validation of `senderKID`. Defaults to `False`.

    Returns:
    -------
        - The `PKIMessage` object with the updated `senderKID` field.

    Raises:
    ------
        - `ValueError`: If the `certificate` does not contain the `SubjectKeyIdentifier` extension, or if \
        MAC-based-protection is used without a valid common name in the sender's `directoryName`.

    Examples:
    --------
    | ${patched_pki_message}= | Patch senderKID | ${pki_message} | ${new_sender_kid} |
    | ${patched_pki_message}= | Patch senderKID | ${pki_message} | sender_kid=${cert_obj} | for_mac=True |
    | ${patched_pki_message}= | Patch senderKID | ${pki_message} | sender_kid=${None} | for_mac=True | negative=True |

    """
    if isinstance(sender_kid, rfc9480.CMPCertificate):
        sender_kid = certextractutils.get_field_from_certificate(sender_kid, extension="ski")  # type: ignore
        if sender_kid is None:
            raise ValueError("The certificate did not contain the SubjectKeyIdentifier extension!")

    if sender_kid is not None:
        sender_kid = convertutils.str_to_bytes(sender_kid)  # type: ignore
        sender_kid: bytes
        if negative:
            sender_kid = utils.manipulate_first_byte(sender_kid)

    elif for_mac:
        sender_kid = _patch_senderkid_for_mac(pki_message["header"]["sender"], negative=negative)

    pki_message["header"]["senderKID"] = rfc9480.KeyIdentifier(sender_kid).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
    )
    return pki_message


@keyword(name="Patch senderNonce")
def patch_sendernonce(  # noqa D417 undocumented-param
    msg_to_patch: PKIMessageTMP,
    other_msg: Optional[PKIMessageTMP] = None,
    sender_nonce: Optional[Union[str, bytes]] = None,  # type: ignore
    use_sender_nonce: bool = False,
) -> PKIMessageTMP:
    """Update the `senderNonce` field of a PKIMessage.

    Set the `senderNonce` field of the specified PKIMessage, this can be helpful for negative testing
    for setting the `senderNonce` to a different value, or helpful for parsing a sender Nonce from the first PKIMessage
    to `certConf` message. Also, the nested protection requires having the same values for the nonces, where this \
    function can be used.

    Arguments:
    ---------
        - `msg_to_patch`: The PKIMessage object to be updated with the new `senderNonce`.
        - `other_msg`: An optional PKIMessage from which the `senderNonce` or `recipNonce`
        field will be copied if `sender_nonce` is not explicitly provided.
        - `sender_nonce`: Optional explicit `senderNonce` to set. If provided as a string,
        it is interpreted as UTF-8 unless prefixed with "0x", in which case it is treated as hex.
        - `use_sender_nonce`: A Flag indicating if the `recipNonce` or `senderNonce` filed shall be copied to
        the `msg_to_patch` structure.


    Returns:
    -------
        - The `PKIMessage` object with the updated `senderNonce` field.

    Raises:
    ------
        - `ValueError`: If neither `sender_nonce` nor a valid `senderNonce` or `recipNonce` is available in `other_msg`.

    Examples:
    --------
    | ${updated_msg}= | Patch senderNonce | ${msg_to_patch} | other_msg=${other_msg} |
    | ${updated_msg}= | Patch senderNonce | ${msg_to_patch} | sender_nonce="0x12345678" |
    | ${updated_msg}= | Patch senderNonce | ${msg_to_patch} | other_msg=${other_msg} | use_sender_nonce=True |

    """
    if sender_nonce is None and other_msg is None:
        raise ValueError("Either a `sender_nonce` or another PKIMessage needs to be provided.")

    if sender_nonce is None:
        field = "senderNonce" if use_sender_nonce else "recipNonce"
        if not other_msg["header"][field].isValue:  # type: ignore
            raise ValueError(f"The provided `other_msg` does not contain a value for the `{field}` field!")

        sender_nonce = other_msg["header"][field].asOctets()  # type: ignore

    sender_nonce: bytes = convertutils.str_to_bytes(sender_nonce)
    wrapper_sender_nonce = univ.OctetString(sender_nonce).subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 5))
    msg_to_patch["header"]["senderNonce"] = wrapper_sender_nonce
    return msg_to_patch


@keyword(name="Patch recipNonce")
def patch_recipnonce(  # noqa D417 undocumented-param
    msg_to_patch: PKIMessageTMP, recip_nonce: Optional[Union[str, bytes]] = None
) -> PKIMessageTMP:
    """Patch the `recipNonce` field in a `PKIMessage` header.

    If `recip_nonce` is not provided, generates fresh automatically a random 16-byte long nonce.
    It Can be used to set the recipient for the first message transaction which is not allowed,
    according to rfc9483 Section 3.5 and 3.1.

    Arguments:
    ---------
        - `msg_to_patch`: The PKIMessage object to be updated.
        - `recip_nonce`: The nonce value to set in the `recipNonce` field. If provided as a string,
        it is interpreted as UTF-8 unless prefixed with "0x", in which case it is treated as hex.


    Returns:
    -------
        - The `PKIMessage` object with the updated `recipNonce` field.

    Raises:
    ------
        - `ValueError`: If `recip_nonce` is neither a string nor bytes.

    Examples:
    --------
    | ${patched_msg}= | Patch recipNonce | ${pki_message} | recip_nonce=0x1234abcd |
    | ${patched_msg}= | Patch recipNonce | ${pki_message} |

    """
    if recip_nonce is None:
        recip_nonce = os.urandom(16)

    recip_nonce = convertutils.str_to_bytes(recip_nonce)
    msg_to_patch["header"]["recipNonce"] = univ.OctetString(recip_nonce).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 6)
    )
    return msg_to_patch


@keyword(name="Patch sender")
def patch_sender(  # noqa D417 undocumented-param
    msg_to_patch: PKIMessageTMP,
    cert: Optional[CertObjOrPath] = None,
    subject: bool = True,
    general_name: Optional[rfc9480.GeneralName] = None,
    sender_name: Optional[str] = None,
) -> PKIMessageTMP:
    """Patch the `sender` field of a `PKIMessage` header.

    Updates the `sender` field in the header of a PKIMessage by setting it to the subject or issuer
    information extracted from the provided certificate, or by using a specified `GeneralName` or sender_name in
    the `directoryName` choice, as required for MAC-based protection.

    Arguments:
    ---------
        - `msg_to_patch`: The `PKIMessage` object to be patched.
        - `cert`: The certificate from which to extract the sender's identity field.
          This can be either a certificate object or a file path to a PEM-formatted certificate.
        - `subject`: Flag indicating whether to use the `subject` (default) or `issuer` field from the
          certificate. Set to `False` to use the `issuer` field instead of `subject`.
        - `general_name`: An optional `GeneralName` object to use as the sender.
        - `sender_name`: An optional string representing the sender's name in OpenSSL notation \
        (e.g., "C=DE,ST=Bavaria,L=Munich,CN=John Doe").

    Returns:
    -------
        - The `PKIMessage` object with the updated `sender` field.

    Raises:
    ------
        - `ValueError`: If no `certificate`, `general_name`, or `sender_name` is provided.

    Examples:
    --------
    | ${updated_msg}= | Patch sender | ${pki_message} | certificate=${certificate} |
    | ${updated_msg}= | Patch sender | ${pki_message} | certificate=${certificate} | subject=False |
    | ${updated_msg}= | Patch sender | ${pki_message} | general_name=${general_name} |
    | ${updated_msg}= | Patch sender | ${pki_message} | sender_name="C=DE,ST=Bavaria,L=Munich,CN=John Doe" |

    """
    if cert is None and general_name is None and sender_name is None:
        raise ValueError(
            "At least one argument among `certificate`, `general_name`, or "
            "`sender_name` must be provided to set the `sender` field."
        )

    if isinstance(cert, str):
        cert = utils.load_and_decode_pem_file(cert)  # type: ignore
        cert = certutils.parse_certificate(cert)  # type: ignore

    if general_name is not None:
        msg_to_patch["header"]["sender"] = general_name
        return msg_to_patch

    if sender_name is not None:
        msg_to_patch["header"]["sender"] = prepareutils.prepare_general_name(
            name_type="directoryName", name_str=sender_name
        )
        return msg_to_patch

    msg_to_patch["header"]["sender"] = prepareutils.prepare_general_name_from_name(
        cert,  # type: ignore
        extract_subject=subject,
    )
    return msg_to_patch


@keyword(name="Patch generalInfo")
def patch_generalinfo(  # noqa D417 undocumented-param
    msg_to_patch: PKIMessageTMP,
    implicit_confirm: bool = False,
    neg_info_value: bool = False,
    confirm_wait_time: Optional[Strint] = None,
    cert_profile: Optional[str] = None,
) -> PKIMessageTMP:
    """Update the `generalInfo` field in a PKIMessage header with optional confirmation, timing, and profile data.

    Patches the `generalInfo` field in the header of a `PKIMessage` to set fields related to implicit
    confirmation, confirmation wait time, and an optional certificate profile. These fields are relevant for
    controlling message response timing, protocol behavior, and certificate profile-specific requirements in CMP
    operations. With the negative flags can the `infoValue` set to random bytes for `Implicit_confirm`, for
    `cert_profile` is a second but modified value additionally added and for `confirm_wait_time` is the
    `UTCTime` structure used, which MUST be of type `GeneralizedTime`.

    Arguments:
    ---------
        - `msg_to_patch`: The PKIMessage object whose `generalInfo` field will be updated.
       - `implicit_confirm`: A flag indicating if implicit confirmation is not needed. Defaults to `False`
        (confirmation is required).
        - `neg_datatypes`: When `True`, adding randomized data to simulate edge cases
        for testing protocol robustness. Defaults to `False`.
        - `confirm_wait_time`: An optional stringified integer or integer representing the \
        confirmation wait time in seconds. Must be set with `negative` for adding the negative structure.
        - `cert_profile`: An optional certificate profile name to add to `generalInfo`, which can specify
        configuration constraints for the message.

    Returns:
    -------
        - The `PKIMessage` object with the updated `generalInfo` field.

    Examples:
    --------
    | ${updated_message}= | Patch generalInfo | ${pki_message} | implicit_confirm=True |
    | ${updated_message}= | Patch generalInfo | ${pki_message} | confirm_wait_time=300 |
    | ${updated_message}= | Patch generalInfo | ${pki_message} | implicit_confirm=True \
    | negative=True | confirm_wait_time=300 | cert_profile="exampleProfile" |

    Notes:
    -----
        - If neither `confirm_wait_time` nor `implicit_confirm` is set, the function returns the message unaltered.

    """
    if confirm_wait_time is None and not implicit_confirm:
        return msg_to_patch

    msg_to_patch["header"]["generalInfo"] = _prepare_generalinfo(
        implicit_confirm=implicit_confirm,
        negative_value=neg_info_value,
        confirm_wait_time=confirm_wait_time,
        cert_profile=cert_profile,
    )

    return msg_to_patch


@keyword(name="Add generalInfo Values")
def add_general_info_values(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    info_vals: Optional[Union[List[rfc9480.InfoTypeAndValue], rfc9480.InfoTypeAndValue]] = None,
    implicit_confirm: bool = False,
    cert_profile: Optional[str] = None,
    confirm_wait_time: Optional[Strint] = None,
    orig_pki_message: Optional[PKIMessageTMP] = None,
) -> PKIMessageTMP:
    """Add generalInfo to the PKIMessage header.

    Arguments:
    ---------
       - `pki_message`: The PKIMessage object to be updated.
       - `info_vals`: A list of InfoTypeAndValue objects to add to the generalInfo field. Defaults to `None`.
       - `implicit_confirm`: A flag indicating whether implicit confirmation is needed. Defaults to `False`.
       - `cert_profile`: An optional certificate profile name to add to generalInfo. Defaults to `None`.
       - `confirm_wait_time`: The confirmation wait time in seconds. Defaults to `None`.

    Returns:
    -------
         - The PKIMessage object with the updated generalInfo field.

    Examples:
    --------
    | ${updated_message}= | Add generalInfo Values | ${pki_message} | implicit_confirm=True |
    | ${updated_message}= | Add generalInfo Values | ${pki_message} | confirm_wait_time=300 |
    | ${updated_message}= | Add generalInfo Values | ${pki_message} | ${info_vals} |

    """
    if info_vals is None:
        info_vals = []

    if isinstance(info_vals, rfc9480.InfoTypeAndValue):
        info_vals = [info_vals]

    if orig_pki_message is not None:
        info_vals.append(prepare_orig_pki_message(orig_pki_message))

    gen_infos = _prepare_generalinfo(
        implicit_confirm=implicit_confirm,
        confirm_wait_time=confirm_wait_time,
        cert_profile=cert_profile,
    )

    if not pki_message["header"]["generalInfo"].isValue:
        pki_message["header"]["generalInfo"] = gen_infos
        for entry in info_vals:
            pki_message["header"]["generalInfo"].append(entry)
        return pki_message

    for x in gen_infos:
        info_vals.append(x)

    pki_message["header"]["generalInfo"].extend(info_vals)
    return pki_message


########################
# Revocation and Revive
########################


@keyword(name="Build CMP Revoke Request")
def build_cmp_revoke_request(  # noqa D417 undocumented-param
    cert: Optional[CertObjOrPath] = None,
    serial_number: Optional[Strint] = None,
    sender: str = "test-cmp-cli@example.com",
    recipient: str = "test-cmp-srv@example.com",
    reason: str = "unspecified",
    exclude_fields: Union[None, str] = "sender,senderKID",
    crl_entry_details: Optional[rfc9480.Extensions] = None,
    cert_template: Optional[rfc9480.CertTemplate] = None,
    exclude_cert_temp_vals: str = "extensions,validity,publicKey,subject",
    exclude_crl_entry: bool = False,
    **params,
) -> PKIMessageTMP:
    """Build a CMP revocation request (`rr`) as defined in RFC 9483 Section 4.2.

    Arguments:
    ---------
        - `cert`: The certificate object or file path from which the revocation request is built.
        - `serial_number`: The serial number of the certificate to revoke. If not provided, it is extracted from the \
        certificate.
        - `sender`: The sender of the request. Defaults to "test-cmp-cli@example.com".
        - `recipient`: The recipient of the request. Defaults to "test-cmp-srv@example.com".
        - `reason`: The reason for revocation. Defaults to "unspecified".
        - `exclude_fields`: Comma-separated list of fields to omit from the PKIMessage header.
        Defaults to "sender,senderKID".
        - `crl_entry_details`: Optional CRL (Certificate Revocation List) entry details. If not provided, it is \
        generated based on the `reason`.
        - `cert_template`: Optional certificate template. If not provided, it is generated from the certificate and \
        excludes certain fields.
        - `exclude_cert_temp_vals`: A comma-separated string of certificate template fields to exclude, such as \
        "extensions,validity,publicKey,subject".
        - `exclude_crl_entry`: Whether to exclude the CRL entry from the `RevDetails`. Defaults to `False`.
        - The `PKIHeader` fields can also be set.

    Returns:
    -------
        - A CMP PKIMessage object representing the revocation request.

    Raises:
    ------
        - `ValueError`: If the `certificate` or `serial_number` is invalid, or required fields are missing.


    Examples:
    --------
    | ${rr}= | Build CMP Revoke Request | serial_number=12345 | sender=test@example.com | reason="keyCompromise" |
    | ${rr}= | Build CMP Revoke Request | serial_number=67890 | exclude_cert_temp_vals=issuer,subject |
    | ${rr}= | Build CMP Revoke Request | serial_number=54321 | cert=${certificate_path} \
    | reason="unspecified" |

    """
    if cert is not None:
        if isinstance(cert, str):
            der_data = utils.load_and_decode_pem_file(cert)
            cert = certutils.parse_certificate(der_data)

    rev_req_content = prepare_rev_req_content(
        cert=cert,  # type: ignore
        reason=reason,
        serial_number=serial_number,
        crl_entry_details=crl_entry_details,
        cert_template=cert_template,
        exclude_crl_entry=exclude_crl_entry,
        exclude_cert_temp_vals=exclude_cert_temp_vals,
    )

    pki_body = rfc4210.PKIBody()
    pki_body["rr"] = rev_req_content
    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        **params,
    )
    pki_message["body"] = pki_body
    return pki_message


@keyword(name="Build CMP Revive Request")
def build_cmp_revive_request(  # noqa: D103 undocumented-public-function
    serial_number: Optional[Strint] = None,
    sender: str = "test-cli@test.com",
    recipient: str = "test-srv@test.com",
    **params,
):
    # No docstring, this is just a wrapper
    return build_cmp_revoke_request(
        serial_number=serial_number, sender=sender, recipient=recipient, reason="removeFromCRL", **params
    )


def _prepare_crl_reason_extension(
    data: bytes,
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare a CRLReason extension for a certificate revocation request.

    :param data: The DER-encoded data for the extension.
    :param critical: A flag indicating whether the extension is critical. Defaults to `False`.
    :return: The populated `Extension` structure.
    """
    crl_reason = rfc5280.Extension()
    crl_reason["extnID"] = rfc5280.id_ce_cRLReasons
    crl_reason["critical"] = critical
    crl_reason["extnValue"] = univ.OctetString(data)
    return crl_reason


@keyword(name="Prepare CRLReason Extensions")
def prepare_crl_reason_extensions(  # noqa D417 undocumented-param
    reasons: Optional[str] = None,
    invalid_reason: bool = False,
    invalid_der: bool = False,
    add_bytes: bool = False,
    critical: bool = False,
) -> rfc5280.Extensions:
    """Prepare a `pyasn1` Extensions structure with CRL (Certificate Revocation List) reasons.

    Arguments:
    ---------
        - `reasons`: A comma-separated string of reasons for certificate
          revocation (e.g., "keyCompromise,affiliationChanged").
        - `invalid_reason`: A flag for generating an invalid CRLReason extension for testing
          purposes. When `True`, the function will create a CRLReason with an out-of-range value
          (i.e., a reason that does not exist in the defined CRL reasons).
        - `invalid_der`: Whether to generate an invalid DER encoding for the `CRLReason`.
        - `add_bytes`: Whether to add additional bytes to the end of the DER encoding.
        Defaults to `False`.
        - `critical`: Whether the extension should be marked as critical. Defaults to `False`.

    Returns:
    -------
        - A `pyasn1` Extensions structure containing the CRLReason extensions.

    Raises:
    ------
        - `ValueError`: If `reasons` is not provided and the `negative` flag is set to `False`.

    Examples:
    --------
    | ${crl_extensions}= | Prepare CRLReason Extensions | reasons=removeFromCRL,keyCompromise |
    | ${crl_extensions}= | Prepare CRLReason Extensions | invalid_extension=True |
    | ${crl_extensions}= | Prepare CRLReason Extensions | reasons=keyCompromise,cessationOfOperation \
    | negative=True |
    | ${crl_extensions}= | Prepare CRLReason Extensions | invalid_der=True |

    """
    if reasons is None and not invalid_reason and not invalid_der:
        raise ValueError("Either `reasons` or `invalid_reason` or `invalid_der` must be provided.")
    if reasons is not None:
        reasons = set(reasons.strip(" ").split(","))  # type: ignore

    crl_entry_details = rfc5280.Extensions()
    if reasons is not None:
        for reason in reasons:
            data = encoder.encode(rfc5280.CRLReason(reason))
            if add_bytes:
                data += b"\x00\x00\x00\x00"
            crl_reason = _prepare_crl_reason_extension(data, critical)
            crl_entry_details.append(crl_reason)

    if invalid_reason:
        # generate a number out of range. the last number is 10 "aACompromise".
        data = encoder.encode(univ.Enumerated(20))
        crl_reason = _prepare_crl_reason_extension(data, critical)
        crl_entry_details.append(crl_reason)

    if invalid_der:
        # generate a CRLReason extension which can not be decoded.
        data = b"This is not a valid DER encoding."
        crl_reason = _prepare_crl_reason_extension(data, critical)
        crl_entry_details.append(crl_reason)

    return crl_entry_details


@keyword(name="Prepare RevDetails")
def prepare_rev_details(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    reason: str = "unspecified",
    serial_number: Optional[Strint] = None,
    issuer: Optional[str] = None,
    cert_template: Optional[rfc9480.CertTemplate] = None,
    crl_entry_details: Optional[rfc9480.Extensions] = None,
    exclude_cert_temp_vals: str = "extensions,validity,publicKey,subject",
    exclude_crl_entry: bool = False,
) -> rfc4210.RevDetails:
    """Prepare the `RevDetails` structure for a certificate revocation request.

    Creates a `RevDetails` structure by optionally including a `CertTemplate`
    and `CRL` entry details. The `RevDetails` structure contains the information about
    the certificate that is being revoked.

    Arguments:
    ---------
        - `cert`: The certificate from which to extract revocation details (optional).
        - `reason`: The reason for revocation. Defaults to "unspecified".
        - `serial_number`: The serial number of the certificate to revoke. If not provided, \
        it is extracted from the certificate.
        - `issuer`: The issuer's distinguished name in OpenSSL notation (e.g., "C=DE, ST=Bavaria, \
        L=Munich, CN=CA Name").
        - `cert_template`: Optional custom certificate template.
        - `crl_entry_details`: Optional CRL (Certificate Revocation List) \
        entry details. Defaults to `None`.
        - `exclude_cert_temp_vals`: A comma-separated string of `CertTemplate` fields to exclude \
        from the template. Default is to exclude "extensions", "validity", "publicKey", and "subject".
        - `exclude_crl_entry`: Whether to exclude the CRL entry details from the `RevDetails`. Defaults to `False`.

    Returns:
    -------
        - A `RevDetails` structure filled with the provided revocation details.

    Examples:
    --------
    | ${rev_details}= | Prepare RevDetails | cert=${cert} | reason=keyCompromise |
    | ${rev_details}= | Prepare RevDetails | serial_number=12345 | reason=unspecified \
    | exclude_cert_temp_vals=issuer,subject |
    | ${rev_details}= | Prepare RevDetails | cert_template=${cert_template} | crl_entry_details=${crl_extensions} |

    """
    rev_details = rfc4210.RevDetails()

    if cert_template is None:
        cert_template = certbuildutils.prepare_cert_template(
            serial_number=serial_number,
            issuer=issuer,
            cert=cert,
            exclude_fields=exclude_cert_temp_vals,
        )

    if crl_entry_details is None and not exclude_crl_entry:
        crl_entry_details = prepare_crl_reason_extensions(reason)

    if not exclude_crl_entry:
        rev_details["crlEntryDetails"] = crl_entry_details

    rev_details["certDetails"] = cert_template

    return rev_details


@keyword(name="Prepare RevReqContent")
def prepare_rev_req_content(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    reason: str = "unspecified",
    issuer: Optional[str] = None,
    serial_number: Optional[Strint] = None,
    crl_entry_details: Optional[rfc9480.Extensions] = None,
    cert_template: Optional[rfc9480.CertTemplate] = None,
    exclude_cert_temp_vals: str = "extensions,validity,publicKey,subject",
    exclude_crl_entry: bool = False,
) -> rfc9480.RevReqContent:
    r"""Create a `RevReqContent` structure for a CMP revocation request.

    Constructs the revocation request content for a CMP (Certificate Management Protocol)
    message by appending a `RevDetails` structure to a `RevReqContent` object.

    Arguments:
    ---------
        - `cert`: An optional `CMPCertificate` object from which revocation details are extracted.
        - `reason`: A string specifying the reason for revocation (e.g., "keyCompromise").
                    Defaults to "unspecified".
        - `issuer`: An optional string representing the issuer's distinguished name in OpenSSL
                    notation (e.g., "C=DE, ST=Bavaria, L=Munich, CN=CA Name").
        - `serial_number`: An optional string specifying the serial number of the certificate
                           to be revoked. Extracted from `cert` if not provided.
        - `crl_entry_details`: Optional CRL entry details, represented as an `rfc9480.Extensions` object.
        - `cert_template`: An optional `CertTemplate` object containing custom certificate details for the revocation.
        - `exclude_cert_temp_vals`: A comma-separated string specifying fields to exclude
                                    from the `CertTemplate`. Defaults to excluding
                                    "extensions", "validity", "publicKey", and "subject".
        - `exclude_crl_entry`: Whether to exclude the CRL entry details from the `RevDetails`. Defaults to `False`.

    Returns:
    -------
        - The populated `RevReqContent` structure containing revocation details for a \
        certificate revocation\revive request.

    Examples:
    --------
    | ${rev_req_content}= | Prepare RevReqContent | cert=${cert} | reason=keyCompromise |
    | ${rev_req_content}= | Prepare RevReqContent | serial_number=67890 | reason=unspecified |
    | ${rev_req_content}= | Prepare RevReqContent | cert_template=${cert_template} | crl_entry_details=${crl_exts} |

    """
    rev_req_content = rfc9480.RevReqContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))

    rev_details = prepare_rev_details(
        cert=cert,
        reason=reason,
        issuer=issuer,
        serial_number=serial_number,
        crl_entry_details=crl_entry_details,
        cert_template=cert_template,
        exclude_cert_temp_vals=exclude_cert_temp_vals,
        exclude_crl_entry=exclude_crl_entry,
    )

    rev_req_content.append(rev_details)
    return rev_req_content


@keyword(name="Get PKIStatusInfo")
def get_pkistatusinfo(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, index: Strint = 0
) -> rfc9480.PKIStatusInfo:
    """Extract PKIStatusInfo from the PKIMessage based on the body type.

    The following body types are supported: "error", "rp", "ip", "cp", "kup".

    Arguments:
    ---------
       - `pki_message`: The PKIMessage from which the `PKIStatusInfo` will be extracted.
       - `index`: The index of the status to retrieve in case of multiple responses. Defaults to `0`.

    Returns:
    -------
        - The extracted `PKIStatusInfo` object.

    Examples:
    --------
    | ${pki_status_info}= | Get PKIStatusInfo | ${pki_message} |
    | ${pki_status_info}= | Get PKIStatusInfo | ${pki_message} | index=0 |

    """
    index = int(index)
    body_name = pki_message["body"].getName()
    if body_name == "error":
        pki_status_info: rfc9480.PKIStatusInfo = pki_message["body"]["error"]["pKIStatusInfo"]

    elif body_name == "rp":
        pki_status_info: rfc9480.PKIStatusInfo = pki_message["body"]["rp"]["status"][index]

    elif body_name in {"ip", "cp", "kup", "ccp"}:
        pki_status_info: rfc9480.PKIStatusInfo = pki_message["body"][body_name]["response"][index]["status"]

    elif body_name == "certConf":
        pki_status_info: rfc9480.PKIStatusInfo = pki_message["body"]["certConf"][index]["statusInfo"]

    else:
        raise ValueError(f"Body type {body_name} was not expected!")

    return pki_status_info


# TODO decide to completely remove.


@keyword(name="Verify PKIStatusInfo")
def verify_pkistatusinfo(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    body_type: Optional[str] = None,
    status: Optional[str] = None,
    failinfos: Optional[str] = None,
    exclusive: bool = True,
    must_be_present: bool = False,
    allow_failure_info: bool = True,
) -> None:
    """Verify the PKIStatusInfo status and optional PKIFailureInfo bits in a PKIMessage.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the PKIStatusInfo and optional failInfo to verify.
        - `body_type`: The expected body type in the PKIMessage. If None, no body type validation is performed.
        - `status`: The expected status to match against the PKIStatusInfo.status.
          If None and `failinfos` is provided, it defaults to "rejection".
        - `failinfos`: Comma-separated human-readable names from the PKIFailureInfo field to check.
          If None, no failInfo check is done.
        - `exclusive`: Ensures the specified failInfo bits are the only ones set. Default is `True`.
        - `must_be_present`: Ensures the failInfo bit is present. Default is `False`.
        - `allow_failure_info`: A flag indicating to throw an exception, if the failInfo bits are
        not correctly set. Defaults to `True`.

    Raises:
    ------
        - `ValueError`: If no `status` or `failinfos` is provided.
        - `ValueError`: If the PKIStatusInfo status does not match the expected value.
        - `ValueError`: If the expected failInfo bits are not present when `must_be_present` is `True`.
        - `ValueError`: If the failInfo bits do not exclusively match the expected values when `exclusive` is `True`.

    Examples:
    --------
    | Verify PKIStatusInfo | ${pki_message} | status=accepted |
    | Verify PKIStatusInfo | ${pki_message} | failinfos=badPop,badSig | exclusive=True |

    """
    if status is None and failinfos is not None:
        status = "rejection"

    if status is None and failinfos is None:
        raise ValueError("Both `status` and `failinfos` cannot be None. Provide at least one.")

    body_name = pki_message["body"].getName()
    pki_status_info = get_pkistatusinfo(pki_message=pki_message)
    is_correct = asn1utils.asn1_compare_named_values(pki_status_info["status"], status)  # type: ignore

    if not is_correct:
        logging.info("PKIBody type: %s \n %s", body_name, pki_status_info.prettyPrint())
        raise ValueError(f"We expected `PKIStatus`: {status}, but got {pki_status_info['status']}.")

    if not pki_status_info["failInfo"].isValue and must_be_present:
        raise ValueError("The `failInfo` structure was not present.")

    if failinfos is not None:
        is_correct = asn1utils.is_bit_set(pki_status_info["failInfo"], failinfos.strip(), exclusive=exclusive)

        if pki_status_info["statusString"].isValue:
            logging.info("PKIFreeText: %s", pki_status_info["statusString"])

        if not is_correct:
            logging.info("PKIBody type: %s \n %s", body_name, pki_status_info.prettyPrint())
            names = asn1utils.get_set_bitstring_names(pki_status_info["failInfo"])
            msg = f"We expected `PKIFailureInfo`: {failinfos}, but got: {names}."
            if allow_failure_info:
                logging.debug(msg)
            else:
                raise ValueError(msg)

    if body_type is not None:
        if body_type.strip() != body_name:
            raise ValueError(f"Response body type mismatch: expected {body_type}, but received {body_name}.")


@keyword(name="Verify statusString")
def verify_statusstring(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    any_text: Optional[str] = None,
    all_text: Optional[str] = None,
    index: Strint = 0,
    must_be_present: bool = False,
):
    """Verify the `statusString` field of the `PKIStatusInfo` in a given `PKIMessage`.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the `statusString` field within the `PKIStatusInfo` to be verified.
        - `any_text`: A comma-separated string of text phrases. The `statusString`
          must contain at least one of these phrases for the check to pass. Defaults to `None`.
        - `all_text`: A comma-separated string of text phrases. The `statusString`
          must contain all of these phrases for the check to pass. Defaults to `None`.
        - `index`: The index of the `statusString` to be verified. Can be either a string or integer. Defaults to `0`.
        - `must_be_present`: If `True`, the `PKIFreeText` must be present inside the `PKIStatusInfo`. \
        Defaults to `False`.

    Raises:
    ------
        - `ValueError`: If the `statusString` is not present and `must_be_present` is `True`.
        - `ValueError`: If `any_text` is provided and none of the specified phrases are found in the `statusString`.
        - `ValueError`: If `all_text` is provided and not all specified phrases are found in the `statusString`.

    Examples:
    --------
    | Verify statusString | ${pki_message} | any_text=error,failed | index=0 | must_be_present=True |
    | Verify statusString | ${pki_message} | all_text=success,completed |

    """
    pki_free_text: rfc9480.PKIFreeText = get_pkistatusinfo(pki_message=pki_message)["statusString"]

    if not pki_free_text.isValue:
        if must_be_present:
            raise ValueError("The `statusString` field is not present in the `PKIStatusInfo`.")

    status_text = pki_free_text[int(index)]

    if any_text:
        any_items = any_text.split(",")
        if not any(any_item in status_text for any_item in any_items):
            raise ValueError(
                f"The `statusString` does not contain any of the required phrases from 'any_text': {any_text}."
            )

    if all_text:
        all_items = all_text.split(",")
        if not all(all_item in status_text for all_item in all_items):
            raise ValueError(
                f"The `statusString` does not contain all the required phrases from 'all_text': {all_text}."
            )


def generate_unique_byte_values(  # noqa D417 undocumented-param
    length: Strint, size: Strint = 16
) -> List[bytes]:
    """Generate a list of unique random byte values with a specified size.

    Arguments:
    ---------
        - `length`: The number of unique byte values to generate.
        - `size`: The size of each byte sequence in bytes. Defaults to `16`.

    Returns:
    -------
        - A list of unique byte sequences.

    Examples:
    --------
    | ${unique_bytes}= | Generate Unique Byte Values | length=10 | size=32 |
    | ${unique_bytes}= | Generate Unique Byte Values | length=5 |

    """
    size_num = int(size)
    values = []

    for _ in range(int(length)):
        val = os.urandom(size_num)
        if val not in values:
            values.append(val)

    return values


@keyword(name="Append PKIMessage To Nested Message")
def append_pki_message_to_nested_message(  # noqa D417 undocumented-param
    nested: PKIMessageTMP, message: Union[PKIMessageTMP, Sequence[PKIMessageTMP]]
) -> PKIMessageTMP:
    """Append a `PKIMessage` or messages to a nested `PKIMessage`.

    Arguments:
    ---------
        - `nested`: The nested `PKIMessage` to which the message will be appended.
        - `message`: The `PKIMessage` or list of `PKIMessages` to append to the nested message.

    Returns:
    -------
        - The updated `PKIMessage` with the appended message.

    Examples:
    --------
    | ${nested_msg}= | Append PKIMessage To Nested Message | ${nested_msg} | ${message} |

    """
    if isinstance(message, PKIMessageTMP):
        message = [message]

    nested["body"]["nested"].extend(message)
    return nested


@keyword(name="Build Nested PKIMessage")
def build_nested_pkimessage(  # noqa D417 undocumented-param
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    other_messages: Optional[Union[PKIMessageTMP, List[PKIMessageTMP]]] = None,
    exclude_fields: Optional[str] = "sender,senderKID",
    transaction_id: Optional[bytes] = None,
    sender_nonce: Optional[bytes] = None,
    for_added_protection: bool = False,
    **params,
):
    """Build a nested PKIMessage structure, used for wrapped protection or batch requests.

    Can be used for protecting a PKIMessage as described in Section 5.2.2.1 Adding Protection to a Request Message
    or for a batching.

    Arguments:
    ---------
        - `sender`: The sender of the PKIMessage. Defaults to "tests@example.com".
        - `recipient`: The recipient of the PKIMessage. Defaults to "testr@example.com".
        - `other_messages`: Additional `PKIMessage` or `PKIMessages` to include in the nested structure.
        - `exclude_fields`: Comma-separated fields to omit from the PKIMessage header.
        Default is "sender,senderKID". Must be set to ${None} if the fields should not be omitted.
        - `transaction_id`: The transaction ID for the message. Default is `None`.
        - `sender_nonce`: The sender's nonce for the message. Default is `None`.
        - **params: allows you to set other `PKIHeader` fields.

    Returns:
    -------
        - The built `PKIMessage` with a nested body structure that can be used to append additional messages.

    Note Section 5 in Rfc9483:
    -------------------------
        - For a nested adding protection message *MUST* the `transactionID` and `senderNonce` have
        the same values as the wrapped message.
        - For Batching *MUST* a Unique `transactionID` and `senderNonce` be used.

    Examples:
    --------
    | ${nested_msg}= | Build Nested PKIMessage | sender=client@example.com | recipient=server@example.com |
    | ${nested_msg}= | Build Nested PKIMessage | other_messages=${list_of_messages} |

    """
    pki_body = rfc9480.PKIBody()
    nested_content = rfc9480.NestedMessageContent().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 20)
    )

    if isinstance(other_messages, PKIMessageTMP):
        other_messages = [other_messages]

    if for_added_protection:
        if other_messages is None:
            raise ValueError("For added protection, `other_messages` must be provided.")

        transaction_id_tmp = None
        if other_messages[0]["header"]["transactionID"].isValue:
            transaction_id_tmp = other_messages[0]["header"]["transactionID"].asOctets()

        sender_nonce_tmp = None
        if other_messages[0]["header"]["senderNonce"].isValue:
            sender_nonce_tmp = other_messages[0]["header"]["senderNonce"].asOctets()

        sender_nonce = sender_nonce_tmp if sender_nonce is None else sender_nonce
        transaction_id = transaction_id_tmp if transaction_id is None else transaction_id
        if other_messages[0]["body"].getName() == "certConf":
            recip_nonce_tmp = None
            if other_messages[0]["header"]["recipNonce"].isValue:
                recip_nonce_tmp = other_messages[0]["header"]["recipNonce"].asOctets()
            params["recip_nonce"] = recip_nonce_tmp if params.get("recip_nonce") is None else params["recip_nonce"]

    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=exclude_fields,
        transaction_id=transaction_id,
        sender_nonce=sender_nonce,
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=params.get("pvno"),
        message_time=params.get("message_time"),
    )

    pki_body["nested"] = nested_content
    if other_messages is not None:
        pki_body["nested"].extend(other_messages)

    pki_message["body"] = pki_body
    return pki_message


# This workaround addresses a potential bug in pyasn1-alt-module.
class CertReq(univ.Sequence):
    """CertReq structure needs to be built because of possible bug in `pyasn1_alt_modules.rfc4210`."""

    componentType = namedtype.NamedTypes(namedtype.NamedType("certReqId", univ.Integer()))


def build_polling_request(  # noqa D417 undocumented-param
    sender: str, recipient: str, resp_pki_message: Optional[PKIMessageTMP] = None, cert_req_id: int = 0, **params
):
    """Build a CMP Polling Request message (pollReq).

    Constructs a PollReqContent structure that allows an entity to query the status of an outstanding
    certificate request (e.g., following an `ip` or `cp` response). The request can optionally include the original
    response message to extract transaction details or allow a custom certReqId to be specified.

    Arguments:
    ---------
        - `resp_pki_message`: The original PKIMessage response that initiated the polling.
          If provided, transaction details (transactionId, sender, recipient) will be used.
        - `cert_req_id`: The certReqId to be used in the polling request. Defaults to `0` unless the
          response message was a certificate request message, in which case the certReqId will be -1.
        - `**params`: Additional parameters to be passed when constructing the `PKIHeader`, including optional
        message attributes like sender, recipient, and transactionID.

    Returns:
    -------
        - The constructed `pyasn1` PKIMessage containing the polling request.

    Examples:
    --------
    | ${poll_req} | Build Polling Request | resp_pki_message=${pki_message} | cert_req_id=1 \
    | transaction_id=${transaction_id} |
    | ${poll_req} | Build Polling Request | resp_pki_message=${pki_message} | cert_req_id=1 |
    | ${poll_req} | Build Polling Request | cert_req_id=1 |
    | ${poll_req} | Build Polling Request |

    """
    body_content = rfc9480.PollReqContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 25))

    # certReqId: MUST be 0 if referring to a CertResponse element, else -1.
    cert_req = univ.Integer(cert_req_id)
    cert_req_obj = CertReq()
    cert_req_obj["certReqId"] = cert_req
    body_content.append(cert_req_obj)

    if resp_pki_message is not None:
        fields = extract_fields_for_exchange(resp_pki_message)

        for key, value in fields.items():
            if key not in params:
                params[key] = value

    # for newer messageTime is positioned here.
    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=params.get("exclude_fields"),
        transaction_id=params.get("transaction_id"),
        sender_nonce=params.get("sender_nonce"),
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=params.get("pvno"),
    )
    pki_body = rfc9480.PKIBody()
    pki_body.setComponentByName("pollReq", body_content)
    pki_message["body"] = pki_body
    return pki_message


@not_keyword
def prepare_poll_content_structure(
    cert_req_id: int, check_after: int, status_text: Optional[Union[List[str], str]] = None
) -> univ.Sequence:
    """Prepare a poll content structure for a PKI polling request.

    This function constructs a `pollContent` structure, which includes the certificate request ID,
    a check-after interval, and an optional reason/status text, in compliance with the PKI protocol.

    :param cert_req_id: The certificate request ID to include in the poll content structure.
    Should be 0 for a `CertResponse` or -1 otherwise.
    :param check_after: The number of seconds after which the next poll is suggested.
    :param status_text: Optional status messages or reason for the polling request.
    :return: An `pyasn1` `univ.Sequence` representing the poll content structure.
    """
    # because not available as a single structure.
    poll_content_structure = univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType("certReqId", univ.Integer()),
            namedtype.NamedType("checkAfter", univ.Integer()),
            namedtype.OptionalNamedType("reason", rfc9480.PKIFreeText()),
        )
    )

    poll_content_structure["certReqId"] = univ.Integer(cert_req_id)
    # certReqId: MUST be 0 if referring to a CertResponse element, else -1.
    poll_content_structure["checkAfter"] = univ.Integer(check_after)

    if status_text is not None:
        status = rfc9480.PKIFreeText()
        status.append(char.UTF8String(status_text))
        poll_content_structure["reason"] = status

    return poll_content_structure


def build_polling_response(  # noqa D417 undocumented-param
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    req_pki_message: Optional[PKIMessageTMP] = None,
    check_after: Strint = 150,
    cert_req_id: Strint = 0,
    status_text: Optional[str] = None,
    **params,
):
    """Build a CMP Polling Response (pollRep) message.

    This function constructs a PollRepContent structure in response to a PollReqContent. It specifies when the next
    status check should occur via the `checkAfter` field and optionally includes a free-text status message.

    Arguments:
    ---------
        - `sender`: The sender of the PKIMessage. Defaults to "tests@example.com".
        - `recipient`: The recipient of the PKIMessage. Defaults to "testr@example.com".
        - `req_pki_message`: The original polling request PKIMessage. The transactionId,
        sender, and recipient fields from this message will be used to build the response if not excluded.
        - `check_after`: Specifies the delay (in seconds) after which the requester should check again
          for the status. Defaults to `150` seconds.
        - `cert_req_id`: The certificate request ID. Defaults to `0`.
        - `status_text`: Optional free-text message describing the status. Defaults to `None`.
        - `**params`: Additional parameters to be passed when constructing the `PKIHeader`, including optional
          attributes like sender, recipient, and transactionId.

    Returns:
    -------
        - The constructed `pyasn1` PKIMessage containing the polling response.

    Example:
    -------
    | ${poll_rep}= | Build Polling Response | req_pki_message=${poll_req} | check_after=300 \
    | certReqId=1 | status_text="Processing" |
    | ${poll_rep}= | Build Polling Response | req_pki_message=${poll_req} | check_after=300 | certReqId=1 |
    | ${poll_rep}= | Build Polling Response | req_pki_message=${poll_req} | certReqId=1 |
    | ${poll_rep}= | Build Polling Response | req_pki_message=${poll_req} | check_after=300 |
    | ${poll_rep}= | Build Polling Response | req_pki_message=${poll_req} |

    """
    body_content = rfc9480.PollRepContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 26))

    poll_content_structure = prepare_poll_content_structure(
        int(cert_req_id), check_after=int(check_after), status_text=status_text
    )

    body_content.append(poll_content_structure)

    if not params.get("exclude_pki_message") and req_pki_message is not None:
        fields = extract_fields_for_exchange(req_pki_message)
        for key, value in fields.items():
            if key not in params:
                params[key] = value

    pki_message = prepare_pki_message(
        sender=sender,
        recipient=recipient,
        exclude_fields=params.get("exclude_fields"),
        transaction_id=params.get("transaction_id"),
        sender_nonce=params.get("sender_nonce"),
        recip_nonce=params.get("recip_nonce"),
        recip_kid=params.get("recip_kid"),
        implicit_confirm=params.get("implicit_confirm", False),
        sender_kid=params.get("sender_kid"),
        pvno=int(params.get("pvno", 2)),
    )
    pki_body = rfc9480.PKIBody()
    pki_body.setComponentByName("pollRep", body_content)
    pki_message["body"] = pki_body
    return pki_message


@keyword(name="Prepare POPO Challenge For Non Signing Key")
def prepare_popo_challenge_for_non_signing_key(  # noqa D417 undocumented-param
    use_encr_cert: bool = True,
    use_key_enc: bool = True,
) -> rfc4211.ProofOfPossession:
    """Prepare a Proof-of-Possession (PoP) structure for Key encipherment or key agreement.

    Using either the encrypted certificate or the challenge method.

    Arguments:
    ---------
        - `use_encr_cert`: A flag indicating whether to use an encrypted certificate (`True`) or
            a challenge-based message (`False`). Defaults to `True`.
        - `use_key_enc`: A flag indicating whether to use the key encipherment (`True`) or
            the key agreement (`False`) option for the PoP structure. Defaults to `True`.

    Returns:
    -------
        - A populated `rfc4211.ProofOfPossession` structure.

    Examples:
    --------
    | ${popo_structure}= | Prepare PoPo Challenge For Non Signing Key | use_encr_cert=True | use_key_enc=True |

    """
    option = "keyEncipherment" if use_key_enc else "keyAgreement"
    challenge = "encrCert" if use_encr_cert else "challengeResp"

    popo_structure = rfc4211.ProofOfPossession()
    popo_structure[option]["subsequentMessage"] = challenge
    return popo_structure


@keyword(name="Build KEMBasedMAC Protected Message")
def build_kem_based_mac_protected_message(  # noqa: D417 Missing argument description in the docstring
    request: PKIMessageTMP,
    shared_secret: Optional[bytes] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    kem_ct_info: Optional[rfc9480.InfoTypeAndValue] = None,
    client_key: Optional[KEMPublicKey] = None,
) -> Tuple[bytes, PKIMessageTMP]:
    """Build a KEM based MAC protected message.

    Either sends the kem ciphertextinfo inside the general message or uses
    the shared secret to protect the message.

    Arguments:
    ---------
        - `shared_secret`: The shared secret to use for the MAC. Defaults to `None`.
        - `ca_cert`: The CA certificate to use for encapsulation. Defaults to `None`.
        - `request`: The PKIMessage with the request. Defaults to `None`.
        - `client_key`: The client key used for the pkiMessage, if request is not provided. Defaults to `None`.
        (The default message is "ir".)

    Returns:
    -------
        - The protected PKIMessage.

    Raises:
        - `ValueError`: If the shared secret is not provided or generated.
        - `ValueError`: If the KEM algorithm does not match the client key.
        - `ValueError`: If the CA certificate is not provided and no client key is given.

    Examples:
    --------
    | ${shared_secret} ${protected_message}= | Build KEMBasedMAC Protected Message | request=${request} |

    """
    if kem_ct_info is not None and client_key is None:
        raise ValueError("Client key must be provided if kem_ct_info is used.")

    if shared_secret is not None:
        pass

    elif client_key is not None and kem_ct_info is not None:
        obj, rest = decoder.decode(kem_ct_info["infoValue"].asOctets(), asn1Spec=KemCiphertextInfoAsn1())

        if rest:
            raise BadAsn1Data("KemCiphertextInfo")

        if get_kem_oid_from_key(client_key) != obj["kem"]["algorithm"]:
            raise ValueError("KEM algorithm mismatch.")

        shared_secret = client_key.decaps(obj["ct"].asOctets())  # type: ignore

    elif ca_cert is not None:
        ca_key = keyutils.load_public_key_from_spki(ca_cert["tbsCertificate"]["subjectPublicKeyInfo"])

        ca_key = convertutils.ensure_is_kem_pub_key(ca_key)

        if isinstance(ca_key, HybridKEMPublicKey):
            shared_secret, ct = ca_key.encaps(client_key)  # type: ignore
        else:
            shared_secret, ct = ca_key.encaps()  # type: ignore

        kem_ct_info = protectionutils.prepare_kem_ciphertextinfo(
            key=ca_key,
            ct=ct,
        )
        request["header"]["generalInfo"].append(kem_ct_info)

    if shared_secret is None:
        raise ValueError("Shared secret must be provided or generated.")

    return shared_secret, protectionutils.protect_pkimessage_kem_based_mac(
        pki_message=request,
        shared_secret=shared_secret,
    )


@not_keyword
def modify_random_str(data: str, index: Optional[int] = None) -> str:  # type: ignore[reportReturnType]
    """Modify a random character with a digit or ascii letter (upper and lower).

    :param data: String to change a random character.
    :param index: Optional index to change the character.
    :return: The changed string.
    :raises ValueError: If the character could not be changed, after 100 attempts.
    """
    chars = list(data)
    options = list(string.ascii_letters) + list(string.digits)
    random_index: int = index or random.randint(0, len(data) - 1)
    for _ in range(100):
        option = random.choice(options)
        if option != chars[random_index]:
            chars[random_index] = option
            return "".join(chars)

    raise ValueError("Could not change the character.")


@keyword(name="Add Certs To PKIMessage")
def add_certs_to_pkimessage(  # noqa D417 Missing argument description in the docstring
    pki_message: PKIMessageTMP,
    certs: Union[rfc9480.CMPCertificate, List[rfc9480.CMPCertificate]],
    for_ca_pubs: bool = False,
) -> PKIMessageTMP:
    """Add certificates to a `PKIMessage` either in the `extraCerts` or `caPubs` field.

    Arguments:
    ---------
       - `pki_message`: The PKIMessage to which the certificate(s) will be added.
       - `certs`: A certificate or a list of certificates to add to the `PKIMessage`.
       - `for_ca_pubs`: A flag indicating whether the certificate(s) are CA certificates and
       added to the `caPubs` field. Defaults to `False`.

    Returns:
    -------
        - The PKIMessage with the added certificate(s).

    Examples:
    --------
    ${pki_message}= | Add Certs To PKIMessage | ${pki_message} | certs=${certs} |
    ${pki_message}= | Add Certs To PKIMessage | ${pki_message} | certs=${certs} | for_ca_pubs=True |

    """
    if isinstance(certs, rfc9480.CMPCertificate):
        certs = [certs]

    if not for_ca_pubs:
        pki_message["extraCerts"].extend(certs)
    else:
        body_name = pki_message["body"].getName()
        if body_name in ["ip", "cp", "kup", "ccp"]:
            pki_message["body"][body_name]["caPubs"].extend(certs)
        else:
            raise ValueError(f"The `PKIMessage` body type does not support adding CA certificates.Got: {body_name}.")

    return pki_message


@keyword(name="Get Inner PKIMessage")
def get_inner_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP, index: Strint = 0
) -> PKIMessageTMP:
    """Extract the inner `PKIMessage` from a nested `PKIMessage`.

    Arguments:
    ---------
        - `pki_message`: The outer `PKIMessage` containing the nested message.
        - `index`: The index of the inner message to retrieve. Defaults to `0`.

    Returns:
    -------
        - The inner `PKIMessage` at the specified index.

    Raises:
    ------
        - `ValueError`: If the body type of the `pki_message` is not "nested".
        - `ValueError`: If the nested `PKIMessage` does not contain any inner messages.
        - `IndexError`: If the specified index is out of bounds for the inner messages.

    Examples:
    --------
    | ${inner_msg}= | Get Inner PKIMessage | ${pki_message} |
    | ${inner_msg}= | Get Inner PKIMessage | ${pki_message} | index=1 |

    """
    body_name = get_cmp_message_type(pki_message)
    if body_name != "nested":
        raise ValueError(f"Expected a nested PKIMessage, but got {body_name}.")

    length = len(pki_message["body"]["nested"])
    if length == 0:
        raise ValueError("The nested PKIMessage does not contain any inner messages.")
    index = int(index)
    if index < 0 or index >= length:
        raise IndexError(f"Index {index} is out of bounds for the nested PKIMessage with length {length}.")

    return pki_message["body"]["nested"][index]
