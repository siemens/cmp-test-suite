# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Nested handler for the Mock CA."""

import copy
import logging

from pyasn1.codec.der import encoder

from mock_ca.cert_conf_handler import CertConfHandler
from mock_ca.cert_req_handler import CertReqHandler
from mock_ca.prot_handler import ProtectionHandler
from resources.asn1_structures import PKIMessageTMP
from resources.checkutils import validate_add_protection_tx_id_and_nonces, validate_nested_message_unique_nonces_and_ids
from resources.cmputils import build_nested_pkimessage, get_cmp_message_type, parse_pkimessage
from resources.exceptions import BadRecipientNonce, BadRequest


class NestedHandler:
    """Handler for nested requests."""

    def __init__(
        self,
        cert_req_handler: CertReqHandler,
        cert_conf_handler: CertConfHandler,
        allow_inner_unprotected: bool = True,
    ):
        """Initialize the handler with the parent.

        :param cert_req_handler: The certificate request handler, to process the requests.
        :param cert_conf_handler: The certificate confirmation handler, to process confirmation messages.
        :param allow_inner_unprotected: If inner unprotected messages are allowed. Defaults to `True`.
        """
        self.cert_req_handler = cert_req_handler
        self.cert_conf_handler = cert_conf_handler
        self.check_sender = False
        self.allow_inner_unprotected = allow_inner_unprotected

    def _check_sender(self, request: PKIMessageTMP) -> None:
        """Check the sender of the request is allowed to forward the request or add protection.

        :param request: The request to check.
        :raises NotAuthorized: If the sender is not allowed to forward the request.

        """
        raise NotImplementedError("Method not implemented")

    @staticmethod
    def get_nested_body_name(request: PKIMessageTMP, index: int) -> str:
        """Get the nested body name.

        :param request: The request to check.
        :param index: The index of the nested request.
        :raises BadRequest: If the request is not valid.
        """
        if not request["body"].isValue:
            raise BadRequest("The body is not set")

        if len(request["body"]["nested"]) <= index:
            raise BadRequest(f"The index {index} is out of range")

        return get_cmp_message_type(request["body"]["nested"][index])

    def _process_added_protection_request(
        self, request: PKIMessageTMP, prot_handler: ProtectionHandler
    ) -> PKIMessageTMP:
        """Process the added protection request.

        :param request: The request to process.
        :param prot_handler: The protection handler to use, to validate the protection, of the request.
        Defaults to `None`.
        """
        validate_add_protection_tx_id_and_nonces(request)
        body_name = NestedHandler.get_nested_body_name(request, 0)

        prot_handler.verify_added_protection(request, must_be_protected=not self.allow_inner_unprotected)
        inner_msg = request["body"]["nested"][0]
        if body_name in ["ir", "cr", "p10cr", "kur", "ccr"]:
            response = self.cert_req_handler.process_cert_request(
                pki_message=inner_msg,
                verify_ra_verified=True,
                must_be_protected=not self.allow_inner_unprotected,
            )

        elif body_name == "certConf":
            response = self.cert_conf_handler.process_cert_conf(
                pki_message=inner_msg,
            )

        else:
            raise BadRequest(
                "The request type is not supported. Only 'ir', 'cr', 'p10cr', 'kur', 'ccr' are supported for added protection requests."
            )

        return prot_handler.protect_pkimessage(
            response=response,
            request=inner_msg,
        )

    def process_nested_request(self, request: PKIMessageTMP, prot_handler: ProtectionHandler) -> PKIMessageTMP:
        """Process the nested request.

        :param request: The request to process.
        :param prot_handler: The protection handler to use, to validate the protection, of the request.
        :raises BadRequest: If the request is not valid.
        """
        prot_handler.verify_nested_protection(pki_message=request)
        len_request = len(request["body"]["nested"])
        self.cert_req_handler.validate_header(pki_message=request, must_be_protected=True, for_nested=True)

        if len_request == 0:
            raise BadRequest("No nested requests found")

        if self.check_sender:
            self._check_sender(request)

        if len_request == 1:
            return self._process_added_protection_request(request, prot_handler=prot_handler)

        return self.process_batched_request(request, prot_handler=prot_handler)

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
        names = [get_cmp_message_type(entry) for entry in request["body"]["nested"]]
        if "certConf" in names:
            if set(names) == {"certConf"}:
                pass
            raise BadRequest(
                "THe `nested` body must only contain `certConf` messages, "
                "or only requests of type `ir`, `cr`, `kur`, `p10cr`, `rr`."
                f" Got: {names}."
            )
        elif request["header"]["recipNonce"].isValue:
            raise BadRecipientNonce(
                "The recipient nonce must not be set in the outer message of a batched request."
                "Which contains requests of type `ir`, `cr`, `kur`, `p10cr`, `rr`."
            )

    def process_batched_request(self, request: PKIMessageTMP, prot_handler: ProtectionHandler) -> PKIMessageTMP:
        """Process the batched request."""
        out = []
        self._check_nonces(request)

        for i, entry in enumerate(request["body"]["nested"]):
            if not entry["body"].isValue:
                raise BadRequest("The body is not set")

            if entry["body"].getName() == "nested":
                if len(entry["body"]["nested"]) != 1:
                    raise BadRequest(
                        "The Mock CA only supports one level of nested requests"
                        ", but allows a added protection request. "
                        f"Got length: {len(entry['body']['nested'])}."
                    )
                response = self._process_added_protection_request(entry, prot_handler=prot_handler)
                out.append(response)

            elif entry["body"].getName() == "certConf":
                response = self.cert_conf_handler.process_cert_conf(
                    pki_message=entry,
                )
                response = prot_handler.protect_pkimessage(
                    response=response,
                    request=entry,
                )
                out.append(response)

            else:
                prot_handler.verify_inner_batch_pkimessage(
                    pki_message=entry,
                    must_be_protected=not self.allow_inner_unprotected,
                    index=i,
                )
                if entry["body"].getName() in ["cr", "ir", "p10cr"]:
                    response = self.cert_req_handler.process_cert_request(
                        entry,
                        must_be_protected=not self.allow_inner_unprotected,
                        verify_ra_verified=True,
                    )
                    response = prot_handler.protect_pkimessage(
                        response=response,
                        request=entry,
                    )
                    out.append(response)
                elif entry["body"].getName() in ["kur", "ccr"]:
                    response = self.cert_req_handler.process_cert_request(
                        pki_message=entry,
                        must_be_protected=not self.allow_inner_unprotected,
                        verify_ra_verified=True,
                    )
                    response = prot_handler.protect_pkimessage(
                        response=response,
                        request=entry,
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
            sender=prot_handler.sender,
            recipient=request["header"]["sender"],
        )
        return prot_handler.protect_pkimessage(response=pki_message, request=request)
