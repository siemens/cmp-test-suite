# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Extra nested PKIMessage processing utilities for the Mock CA."""

import logging
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480, rfc9481
from robot.api.deco import keyword

from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from resources.asn1_structures import PKIMessagesTMP, PKIMessageTMP
from resources.ca_ra_utils import build_ip_cmp_message, build_kup_from_kur, build_pki_conf_from_cert_conf
from resources.checkutils import (
    check_is_protection_present,
    validate_add_protection_tx_id_and_nonces,
)
from resources.cmputils import build_nested_pkimessage, find_oid_in_general_info, get_value_from_seq_of_info_value_field
from resources.exceptions import BadMessageCheck, BadRequest, InvalidAltSignature
from resources.protectionutils import (
    get_protection_type_from_pkimessage,
    protect_hybrid_pkimessage,
    protect_pkimessage,
    verify_pkimessage_protection,
)
from resources.typingutils import SignKey


def get_same_mac_protection(alg_id: rfc9480.AlgorithmIdentifier) -> str:
    """Return the same MAC protection algorithm based on the algorithm identifier."""
    # only uses LwCMP protection algorithms.
    if alg_id["algorithm"] == rfc9481.id_PBMAC1:
        return "pbmac1"
    if alg_id["algorithm"] == rfc9481.id_PasswordBasedMac:
        return "password_based_mac"
    return "password_based_mac"


def _protect_nested_added_prot_response(
    response: PKIMessageTMP,
    request: PKIMessageTMP,
    mac_protection: Optional[bytes] = None,
    private_key: Optional[SignKey] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
) -> PKIMessageTMP:
    """Protect the nested response with the given protection type.

    :param response: The nested PKIMessage response to protect.
    :param mac_protection: The shared secret for MAC protection.
    :param private_key: The private key for signature protection.
    :param cert: The certificate for signature protection.
    :return: The protected PKIMessage response.
    """
    if response["body"].getName() != "nested":
        _inner_body = request["body"]["nested"][0]
        if _inner_body["header"]["protectionAlg"].isValue:
            prot_type = get_protection_type_from_pkimessage(_inner_body)
            if prot_type == "mac":
                prot_type = get_same_mac_protection(_inner_body["header"]["protectionAlg"])
                return protect_pkimessage(
                    pki_message=response,
                    password=mac_protection,
                    protection=prot_type,
                )

    if private_key is None:
        raise ValueError("The private key is not set for the nested response.")

    return protect_hybrid_pkimessage(
        pki_message=response,
        private_key=private_key,
        protection="signature",
        cert=cert,
    )


def _protect_batch_entry(
    entry: PKIMessageTMP,
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    mac_protection: Optional[bytes] = None,
):
    if request["header"]["protectionAlg"].isValue:
        prot_type = get_protection_type_from_pkimessage(request)
        if prot_type == "mac":
            prot_type = get_same_mac_protection(request["header"]["protectionAlg"])
            return protect_pkimessage(
                pki_message=entry,
                password=mac_protection,
                protection=prot_type,
            )
    return protect_hybrid_pkimessage(
        pki_message=entry,
        private_key=ca_key,
        protection="signature",
        cert=ca_cert,
    )


@keyword(name="Validate Original PKIMessage")
def validate_orig_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    must_be_present: bool = False,
    pre_shared_secret: Optional[bytes] = None,
) -> None:
    """Validate the original PKIMessage.

    If an intermediate RA or PKI entity receives a PKIMessage and modifies it, it can include
    the original PKIMessage in the `generalInfo` field.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to validate.
        - `must_be_present`: If the original PKIMessage must be present. Defaults to `False`.

    Raises:
    ------
        - `BadRequest`: If the generalInfo is not set or the original PKIMessage is not found.
        - `BadMessageCheck`: If the original PKIMessage has an invalid signature.
        - `pre_shared_secret`: The shared secret for MAC protection. Defaults to `None`.

    Examples:
    --------
    | Validate Original PKIMessage | ${pki_message} |
    | Validate Original PKIMessage | ${pki_message} | must_be_present=True |

    """
    if not pki_message["header"]["generalInfo"].isValue:
        if must_be_present:
            raise BadRequest("The generalInfo was not set. Could not verify the original `PKIMessage`.")
        return

    result = find_oid_in_general_info(pki_message, rfc9480.id_it_origPKIMessage)
    if not must_be_present and not result:
        logging.info("Added protection request, did not contain the original `PKIMessage`.")
        return

    if not result:
        raise BadRequest("The original PKIMessage was not found in the `generalInfo` field.")

    val = get_value_from_seq_of_info_value_field(
        pki_message["header"]["generalInfo"],
        rfc9480.id_it_origPKIMessage,
    )

    if val is None:
        raise BadRequest("The original PKIMessage was not found in the `generalInfo` field.")

    info_val = val.asOctets()
    orig_message, rest = decoder.decode(info_val, asn1Spec=PKIMessagesTMP())
    if rest:
        raise BadMessageCheck("Original PKIMessage")

    for msg in orig_message:
        try:
            _verify_protection(msg, pre_shared_secret=pre_shared_secret)
        except BadMessageCheck:
            raise BadMessageCheck("The original `PKIMessage` protection is invalid.")


def validate_added_protection_request(
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    extensions: Optional[rfc9480.Extensions] = None,
    mac_protection: Optional[bytes] = None,
    shared_secrets: Optional[bytes] = None,
    hybrid_kem_key: Optional[HybridKEMPrivateKey] = None,
    ca_sign_key: Optional[SignKey] = None,
    ca_sign_cert: Optional[rfc9480.CMPCertificate] = None,
    to_be_confirmed_cert: Optional[List[rfc9480.CMPCertificate]] = None,
) -> PKIMessageTMP:
    """
    Process an added protection request by inlining the logic for 'ir' and 'kur' message types.

    This function performs the following:

    - Validates the transaction ID and nonces.
    - (Optionally) verifies the added protection (the verification logic would be inlined here).
    - Extracts the inner message from the nested request.
    - For an "ir" message:
        - If protection is missing, skips the check since added protection requests assume protection is not required.
        - Finds the implicit confirmation OID.
        - Builds the inner PKI response using the IR processing logic.
    - For a "kur" message:
        - Tries hybrid protection verification; on failure falls back to password-based MAC verification.
        - Builds the inner response using the KUR processing logic.
    - Finally, signs the nested response (inlined from the original _sign_nested_response logic).

    :param request: The outer PKIMessage containing a nested added protection request.
    :param ca_cert: The CA certificate.
    :param ca_key: The CA private key.
    :param extensions: A list of extensions (e.g. OCSP and CRL) to include in the response.
    :param mac_protection: The shared secret for MAC protection.
    :param shared_secrets: The shared secret for EC or KEM protection.
    :param hybrid_kem_key: The fallback key for verifying password-based protection.
    :param ca_sign_key: The CA signing key for the nested response.
    :param ca_sign_cert: The CA signing certificate for the nested response.
    :param to_be_confirmed_cert: The list of certificates to be confirmed.
    :return: The signed nested PKIMessage response.
    :raises NotImplementedError: For unsupported inner message types.
    :raises BadMessageCheck: If signature verification for a KUR message fails.
    """
    # Validate transaction ID and nonces for added protection.
    validate_add_protection_tx_id_and_nonces(request)
    # (Inline any added-protection verification logic here if needed.)
    validate_orig_pkimessage(request, must_be_present=False, pre_shared_secret=mac_protection)
    _inner_body = request["body"]["nested"][0]
    body_name = _inner_body["body"].getName()

    if body_name == "certConf":
        if to_be_confirmed_cert is None:
            raise BadRequest("The `to_be_confirmed_cert` is not set for the `certConf` request.")

        response = build_pki_conf_from_cert_conf(
            request=_inner_body,
            issued_certs=to_be_confirmed_cert,
        )

    elif body_name == "ir":
        # Inlined IR processing logic:
        # (Since added protection requests use IR with protection not required,
        #  we do not check for a missing protection algorithm.)
        confirm_ = find_oid_in_general_info(_inner_body, rfc9480.id_it_implicitConfirm)
        response, certs = build_ip_cmp_message(
            request=_inner_body,
            ca_cert=ca_cert,
            ca_key=ca_key,
            implicit_confirm=confirm_,
            extensions=extensions,
            verify_ra_verified=False,
        )
    elif body_name == "kur":
        try:
            try:
                verify_hybrid_pkimessage_protection(pki_message=_inner_body)
            except ValueError:
                verify_pkimessage_protection(
                    pki_message=_inner_body,
                    shared_secret=shared_secrets,
                    private_key=hybrid_kem_key,
                    password=mac_protection,
                )
            response, certs = build_kup_from_kur(
                request=_inner_body,
                ca_cert=ca_cert,
                ca_key=ca_key,
                extensions=extensions,
            )
        except (InvalidSignature, InvalidAltSignature) as e:
            raise BadMessageCheck(f"The kur request did not have a valid signature: {e}")
    else:
        raise NotImplementedError(f"Not implemented to handle the body: {body_name} for added protection")

    return _protect_nested_added_prot_response(
        response=response,
        request=request,
        mac_protection=mac_protection,
        private_key=ca_sign_key or ca_key,
        cert=ca_sign_cert or ca_cert,
    )


def _verify_protection(
    entry: PKIMessageTMP,
    must_be_protected: bool = True,
    pre_shared_secret: Optional[bytes] = None,
    shared_secrets: Optional[bytes] = None,
) -> None:
    """Verify the protection of a PKIMessage entry.

    :param entry: The PKIMessage entry to verify.
    :param must_be_protected: If the entry must be protected. Defaults to `True`.
    :param pre_shared_secret: The shared secret for MAC protection. Defaults to `None`.
    :param shared_secrets: The shared secret for EC or KEM protection. Defaults to `None`.
    """
    failed = False

    if not check_is_protection_present(pki_message=entry, must_be_protected=must_be_protected):
        return

    if get_protection_type_from_pkimessage(entry) == "mac":
        try:
            verify_pkimessage_protection(
                pki_message=entry,
                shared_secret=shared_secrets,
                password=pre_shared_secret,
            )
        except (InvalidSignature, ValueError):
            raise BadMessageCheck("The protection of the a nested entry was not valid.")
    else:
        try:
            verify_hybrid_pkimessage_protection(pki_message=entry)
        except (InvalidSignature, InvalidAltSignature):
            raise BadMessageCheck("The protection of the a nested entry was not valid.")

    if failed:
        raise BadMessageCheck("The protection of the a nested entry was not valid.")


def process_batch_message(
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    extensions: Optional[rfc9480.Extensions] = None,
    mac_protection: Optional[bytes] = None,
    shared_secret: Optional[bytes] = None,
    hybrid_kem_key: Optional[HybridKEMPrivateKey] = None,
    ca_sign_key: Optional[SignKey] = None,
    ca_sign_cert: Optional[rfc9480.CMPCertificate] = None,
    to_be_confirmed_cert: Optional[List[rfc9480.CMPCertificate]] = None,
    must_be_protected: bool = False,
) -> PKIMessageTMP:
    """Process a batch PKIMessage request.

    :param request:
    :param ca_cert:
    :param ca_key:
    :param extensions:
    :param mac_protection:
    :param shared_secret:
    :param hybrid_kem_key:
    :param ca_sign_key:
    :param ca_sign_cert:
    :param to_be_confirmed_cert:
    :return:
    """
    out = []

    for entry in request["body"]["nested"]:
        if not entry["body"].isValue:
            raise BadRequest("The body is not set")

        if entry["body"].getName() == "nested":
            if len(entry["body"]["nested"]) != 1:
                raise BadRequest(
                    "The Mock CA only supports one level of nested requests"
                    ", but allows a added protection request. "
                    f"Got length: {len(entry['body']['nested'])}."
                )
            response = validate_added_protection_request(
                entry,
                ca_cert,
                ca_key,
                extensions,
                mac_protection,
                shared_secret,
                hybrid_kem_key,
                ca_sign_key,
                ca_sign_cert,
                to_be_confirmed_cert,
            )
            out.append(response)
        else:
            _verify_protection(
                entry,
                pre_shared_secret=mac_protection,
                must_be_protected=must_be_protected,
                shared_secrets=shared_secret,
            )
            if entry["body"].getName() == "ir":
                confirm_ = find_oid_in_general_info(entry, rfc9480.id_it_implicitConfirm)
                response, certs = build_ip_cmp_message(
                    request=entry,
                    ca_cert=ca_cert,
                    ca_key=ca_key,
                    implicit_confirm=confirm_,
                    extensions=extensions,
                    verify_ra_verified=False,
                )
                response = _protect_batch_entry(response, entry, ca_cert, ca_key, mac_protection)
                out.append(response)
            else:
                raise NotImplementedError(
                    f"Not implemented to handle the body: {entry['body'].getName()} for batched requests,"
                    f"only support `ir`."
                )

    return build_nested_pkimessage(
        other_messages=out,
        transaction_id=request["header"]["transactionID"].asOctets(),
        recip_nonce=request["header"]["senderNonce"].asOctets(),
        sender=request["header"]["recipient"],
        recipient=request["header"]["sender"],
    )
