# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Nested handler for the Mock CA."""

import copy
import logging
from typing import Optional

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480

from mock_ca.cert_req_handler import CertReqHandler
from mock_ca.mock_fun import CAOperationState
from mock_ca.nestedutils import process_batch_message, validate_added_protection_request
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import get_popo_from_pkimessage
from resources.certutils import load_certificates_from_dir
from resources.checkutils import validate_add_protection_tx_id_and_nonces, validate_nested_message_unique_nonces_and_ids
from resources.cmputils import build_nested_pkimessage, parse_pkimessage
from resources.exceptions import BadMessageCheck, BadRecipientNonce, BadRequest, InvalidAltSignature, WrongIntegrity
from resources.protectionutils import get_protection_type_from_pkimessage, protect_hybrid_pkimessage


class NestedHandler:
    """Handler for nested requests."""

    def __init__(
        self,
        ca_handler: "CAHandler" = None,  # noqa F821 # type: ignore
        ca_operation_state: Optional[CAOperationState] = None,
        extensions: Optional[rfc9480.Extensions] = None,
        allowed_ras: Optional[str] = None,
        allow_inner_unprotected: bool = True,
    ):
        """Initialize the handler with the parent."""
        self.ca_handler = ca_handler
        self.cert_req_handler: Optional[CertReqHandler] = ca_handler.cert_req_handler if ca_handler else None
        self.ras = []
        if allowed_ras:
            self.ras = load_certificates_from_dir(allowed_ras)
        self.check_sender = False if not allowed_ras else True
        self.allow_inner_unprotected = allow_inner_unprotected
        self.extensions = extensions

        self.ca_op_state = ca_operation_state or CAOperationState(
            ca_key=self.ca_handler.ca_key,
            ca_cert=self.ca_handler.ca_cert,
            pre_shared_secret=self.ca_handler.pre_shared_secret,
            extensions=extensions,
        )

    def _check_sender(self, request: PKIMessageTMP) -> None:
        """Check the sender of the request is allowed to forward the request or add protection.

        :param request: The request to check.
        :raises NotAuthorized: If the sender is not allowed to forward the request.

        """
        raise NotImplementedError("Method not implemented")

    @staticmethod
    def _has_set_ra_verified(inner_req: PKIMessageTMP) -> bool:
        """Check if the RA is verified.

        :param inner_req: The inner request to check.
        :raises ValueError: If the body name is not valid, only supports "ir" and "cr".
        :return: True if the RA is verified, False otherwise.
        """
        body_name = inner_req["body"].getName()

        if body_name not in ["ir", "cr"]:
            raise ValueError(f"The body name is not valid. Got: {body_name}")

        popo = get_popo_from_pkimessage(
            inner_req,
        )
        if not popo.isValue:
            logging.error("The POPO is not set")
            return False

        if popo["raVerified"].isValue:
            return True
        return False

    def _verify_added_protection(self, request: PKIMessageTMP) -> None:
        """Verify the added protection request.

        :param request: The request to verify.
        :raises BadMessageCheck: If the request is not valid.
        """
        _inner_body = request["body"]["nested"][0]
        body_name = _inner_body["body"].getName()

        if self.ca_handler is None:
            return

        try:
            self.ca_handler.verify_protection(_inner_body, must_be_protected=not self.allow_inner_unprotected)
            return
        except (BadMessageCheck, InvalidAltSignature, InvalidSignature):
            pass

        if body_name == "kur":
            raise BadMessageCheck(
                "The added protection request was a key update request, which is not allowed, to modify the message."
            )

        if body_name in ["ir", "cr"]:
            if self._has_set_ra_verified(_inner_body):
                return

        raise BadMessageCheck("The added protection request was not valid protected.")

    def _process_added_protection_request(self, request: PKIMessageTMP) -> PKIMessageTMP:
        """Process the added protection request."""
        validate_add_protection_tx_id_and_nonces(request)
        self._verify_added_protection(request)
        inner_response = validate_added_protection_request(
            request=request,
            ca_cert=self.ca_op_state.ca_cert,
            ca_key=self.ca_op_state.ca_key,
            extensions=self.ca_op_state.extensions,
            mac_protection=self.ca_op_state.pre_shared_secret,
        )
        return inner_response

    def _check_protection(self, request: PKIMessageTMP) -> None:
        """Check the protection of the request is valid and signature-based.

        :param request: The request to check.
        :raises BadRequest: If the protection is not set.
        """
        if not request["protection"].isValue:
            raise BadMessageCheck("The protection is not set")
        if not request["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("The protection algorithm is not set")

        prot_type = get_protection_type_from_pkimessage(request)
        if prot_type == "mac":
            raise WrongIntegrity("The protection type is MAC-based")

    def process_nested_request(self, request: PKIMessageTMP) -> PKIMessageTMP:
        """Process the nested request."""
        len_request = len(request["body"]["nested"])

        if len_request == 0:
            raise BadRequest("No nested requests found")

        if self.check_sender:
            self._check_sender(request)

        self._check_protection(request)

        if len_request == 1:
            return self._process_added_protection_request(request)

        return self.process_batched_request(request)

    @staticmethod
    def check_recip_nonce_is_absent(request: PKIMessageTMP) -> None:
        """Check that the recipient nonce is absent in both the outer and nested message headers.

        :param request: The PKIMessage to check.
        :raises BadRecipientNonce: If any recipNonce is set.
        """
        if not request["header"].isValue:
            raise BadRequest("The header is not set")

        if request["header"]["recipNonce"].isValue:
            raise BadRecipientNonce("Outer PKIHeader 'recipNonce' must not be set in batched requests")

        for msg in request["body"]["nested"]:
            if msg["header"]["recipNonce"].isValue:
                raise BadRecipientNonce("Nested PKIHeader 'recipNonce' must not be set in batched requests")

    def _check_nonces_depth(self, request: PKIMessageTMP) -> None:
        """Check the nonces of the request in depth."""
        der_data = encoder.encode(request)
        der_data2 = copy.deepcopy(der_data)
        request2 = parse_pkimessage(der_data2)

        cert_conf_nonces = False
        print("called", "_check_nonces_depth")
        print(len(request["body"]["nested"]))
        print((request["body"]["nested"][0]["body"].getName()))
        # print(request["body"]["nested"][0]["body"].prettyPrint())

        for entry in request2["body"]["nested"]:
            if entry["body"].getName() == "nested":
                if len(entry["body"]["nested"]) != 1:
                    raise BadRequest(
                        "The Mock CA only supports one level of nested requests, but allows a added protection request"
                    )
                validate_add_protection_tx_id_and_nonces(entry["body"]["nested"][0])

            elif entry["body"].getName() == "certConf":
                cert_conf_nonces = True

            elif entry["body"].getName() in ["cr", "ir", "kur", "p10cr", "rr"]:
                self.check_recip_nonce_is_absent(entry)
            else:
                raise BadRequest(
                    "The request type is not supported. "
                    "Only 'certConf', 'cr', 'ir', 'kur', 'p10cr', 'rr' are supported"
                    f" for batched requests. Got: {entry['body'].getName()}"
                )

        if cert_conf_nonces:
            validate_nested_message_unique_nonces_and_ids(
                request, check_transaction_id=False, check_sender_nonce=False, check_recip_nonce=True, check_length=True
            )

    @staticmethod
    def log_body_and_types(request: PKIMessageTMP) -> None:
        """Check the body and types of the request."""
        request_body = request["body"].getName()
        name = request_body + ":\n" + "\n".join([msg["body"].getName() for msg in request["body"]["nested"]])
        logging.debug("Processing batched request, request: \n\t%s", name)

    def _check_nonces(self, request: PKIMessageTMP) -> None:
        """Check the nonces of the request."""
        self.log_body_and_types(request)
        validate_nested_message_unique_nonces_and_ids(
            request, check_transaction_id=True, check_sender_nonce=True, check_recip_nonce=False, check_length=True
        )
        # self._check_nonces_depth(request)

    def validate_batch_request(self, request: PKIMessageTMP) -> None:
        """Validate the batched request."""
        self._check_nonces(request)
        pki_message, certs = process_batch_message(
            request=request,
            ca_cert=self.ca_op_state.ca_cert,
            ca_key=self.ca_op_state.ca_key,
            extensions=self.ca_op_state.extensions,
            mac_protection=self.ca_op_state.pre_shared_secret,
            must_be_protected=not self.allow_inner_unprotected,
        )

        return pki_message

    def process_batched_request(self, request: PKIMessageTMP) -> PKIMessageTMP:
        """Process the batched request."""
        out = []
        self._check_nonces(request)

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
                response = self._process_added_protection_request(entry)
                out.append(response)
            else:
                if self.ca_handler is not None:
                    self.ca_handler.verify_protection(entry, must_be_protected=False)
                if entry["body"].getName() == "ir":
                    response = self.cert_req_handler.process_ir(  # type: ignore
                        entry, must_be_protected=False, verify_ra_verified=False
                    )
                    out.append(response)
                else:
                    raise NotImplementedError(
                        f"Not implemented to handle the body: {entry['body'].getName()} for batched requests,"
                        f"only support `ir`."
                    )

        pki_message = build_nested_pkimessage(
            other_messages=out,
            transaction_id=request["header"]["transactionID"].asOctets(),
            recip_nonce=request["header"]["senderNonce"].asOctets(),
            sender=request["header"]["recipient"],
            recipient=request["header"]["sender"],
        )
        return protect_hybrid_pkimessage(
            pki_message=pki_message,
            private_key=self.ca_op_state.ca_key,
            cert=self.ca_op_state.ca_cert,
        )
