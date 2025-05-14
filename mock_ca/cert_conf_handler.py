# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Certificate Confirmation handler for the Mock CA."""

import logging
from dataclasses import dataclass, field
from typing import Dict, List

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_pki_conf_from_cert_conf
from resources.checkutils import validate_pkimessage_header
from resources.exceptions import (
    BadDataFormat,
    BadMessageCheck,
    BadRecipientNonce,
    BadRequest,
    BadSenderNonce,
    CertConfirmed,
    WrongAuthority,
    WrongIntegrity,
)
from resources.protectionutils import get_protection_type_from_pkimessage


@dataclass
class CertConfState:
    """The state of the certificate confirmation handler."""

    to_be_confirmed_certs: Dict[bytes, List[rfc9480.CMPCertificate]] = field(default_factory=dict)
    ca_responses: Dict[bytes, PKIMessageTMP] = field(default_factory=dict)
    requests: Dict[bytes, PKIMessageTMP] = field(default_factory=dict)
    already_confirmed_certs: List[bytes] = field(default_factory=list)

    def add_confirmed_cert(self, request: PKIMessageTMP, cert: rfc9480.CMPCertificate) -> None:
        """Add the confirmed certificate to the state."""
        if not request["header"]["transactionID"].isValue:
            raise BadRequest("The transaction ID is not set.")

        tx_id = request["header"]["transactionID"].asOctets()
        self.already_confirmed_certs.append(tx_id)

    def contains_tx_id(self, tx_id: bytes) -> bool:
        """Check if the transaction ID is already in the state."""
        return tx_id in self.requests

    def remove_request(self, pki_message: PKIMessageTMP):
        """Remove the request from the state."""
        if not pki_message["header"]["transactionID"].isValue:
            raise BadRequest("The transaction ID is not set.")

        tx_id = pki_message["header"]["transactionID"].asOctets()
        self.already_confirmed_certs.append(tx_id)
        if tx_id in self.requests:
            del self.requests[tx_id]
        if tx_id in self.ca_responses:
            del self.ca_responses[tx_id]
        _ = self.to_be_confirmed_certs.pop(tx_id)

    def add_response(self, pki_message: PKIMessageTMP, issued_certs: List[rfc9480.CMPCertificate]):
        """Add the CA response to the state."""
        if not pki_message["header"]["transactionID"].isValue:
            raise BadRequest("The transaction ID is not set.")

        tx_id = pki_message["header"]["transactionID"].asOctets()
        self.ca_responses[tx_id] = pki_message
        self.to_be_confirmed_certs[tx_id] = issued_certs

    def is_confirmed(self, pki_message: PKIMessageTMP) -> None:
        """Check if the certificates are already confirmed."""
        if not pki_message["header"]["transactionID"].isValue:
            raise BadRequest("The transaction ID is not set.")

        tx_id = pki_message["header"]["transactionID"].asOctets()

        if tx_id in self.already_confirmed_certs:
            raise CertConfirmed("The certificates are already confirmed.")

    def is_not_confirmed(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if the certificate is to be confirmed."""
        der_data = encoder.encode(cert)
        for certs in self.to_be_confirmed_certs.values():
            for cert_to_confirm in certs:
                if der_data == encoder.encode(cert_to_confirm):
                    return True

        return False

    def was_already_confirmed(self, pki_message: PKIMessageTMP) -> bool:
        """Check if the certificates were already confirmed."""
        if not pki_message["header"]["transactionID"].isValue:
            raise BadDataFormat("The transaction ID is not set.")

        tx_id = pki_message["header"]["transactionID"].asOctets()
        return tx_id in self.already_confirmed_certs

    def get_confirmable_certs(self, pki_message: PKIMessageTMP) -> List[rfc9480.CMPCertificate]:
        """Get the certificates that can be confirmed."""
        if not pki_message["header"]["transactionID"].isValue:
            raise BadDataFormat("The transaction ID is not set.")

        if self.was_already_confirmed(pki_message):
            raise CertConfirmed("The certificates are already confirmed.")

        tx_id = pki_message["header"]["transactionID"].asOctets()
        if self.to_be_confirmed_certs.get(tx_id) is None:
            raise BadRequest("The transaction ID is not known.")
        return self.to_be_confirmed_certs[tx_id]

    def get_ca_response(self, request: PKIMessageTMP) -> PKIMessageTMP:
        """Get the CA response for the request."""
        if not request["header"]["transactionID"].isValue:
            raise BadRequest("The transaction ID is not set.")

        tx_id = request["header"]["transactionID"].asOctets()
        if self.ca_responses.get(tx_id) is None:
            raise BadRequest("The transaction ID is not known.")
        return self.ca_responses[tx_id]

    def add_request(self, pki_message: PKIMessageTMP):
        """Add the certificate confirmation request to the state."""
        if not pki_message["header"]["transactionID"].isValue:
            raise BadRequest("The transaction ID is not set.")

        tx_id = pki_message["header"]["transactionID"].asOctets()
        self.requests[tx_id] = pki_message

    def get_request(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Get the request for the transaction ID."""
        if not pki_message["header"]["transactionID"].isValue:
            raise BadDataFormat("The transaction ID is not set.")

        tx_id = pki_message["header"]["transactionID"].asOctets()
        return self.requests[tx_id]

    def validate_tx_id(self, cert_conf: PKIMessageTMP) -> None:
        """Validate the transaction ID."""
        if not cert_conf["header"]["transactionID"].isValue:
            raise BadDataFormat("The transaction ID is not set.")

        tx_id = cert_conf["header"]["transactionID"].asOctets()
        if tx_id not in self.requests:
            raise BadRequest("The transaction ID is not known.")

    def validate_nonces(self, cert_conf: PKIMessageTMP) -> None:
        """Validate the nonces."""
        if not cert_conf["header"]["senderNonce"].isValue:
            raise BadSenderNonce("The sender nonce is missing inside the certificate confirmation message.")

        if not cert_conf["header"]["recipNonce"].isValue:
            raise BadRecipientNonce("The recipient nonce is missing inside the certificate confirmation message.")

        ca_response = self.get_ca_response(cert_conf)
        request = self.get_request(cert_conf)

        sender_nonce = cert_conf["header"]["senderNonce"].asOctets()
        req_sender_nonce = request["header"]["senderNonce"].asOctets()

        if ca_response["header"]["senderNonce"].asOctets() != cert_conf["header"]["recipNonce"].asOctets():
            raise BadRecipientNonce("The recipient nonce does not match the sender nonce in the CA response.")

        if req_sender_nonce != ca_response["header"]["recipNonce"].asOctets():
            raise BadSenderNonce("The sender nonce does not match the recipient nonce in the CA response.")

        if sender_nonce != req_sender_nonce:
            raise BadSenderNonce("The sender nonce does not match the sender nonce in the request.")

    def validate_tx_fields(self, cert_conf: PKIMessageTMP) -> None:
        """Validate the transaction fields."""
        self.validate_tx_id(cert_conf)
        self.validate_nonces(cert_conf)


class CertConfHandler:
    """Certificate Confirmation handler for the Mock CA."""

    def __init__(self, state_db, config_vars: Optional[CertConfConfigVars] = None):
        """Initialize the handler with the state database."""
        self.conf_state = CertConfState()
        self.state_db = state_db
        self.sender = "CN=Mock CA"
        self.config_vars = config_vars or CertConfConfigVars(
            enforce_same_alg=True,
            must_be_protected=True,
            allow_auto_ed=True,
            must_be_fresh_nonce=True,
        )

    def set_config_vars(self, config_vars: Union[CertConfConfigVars, dict]) -> None:
        """Set the configuration variables."""
        if isinstance(config_vars, dict):
            config_vars = CertConfConfigVars(**config_vars)
        elif not isinstance(config_vars, CertConfConfigVars):
            raise TypeError("config_vars must be a CertConfConfigVars instance or a dictionary.")

        self.config_vars = config_vars

    @classmethod
    def from_config_vars(cls, **kwargs):
        """Create a new instance of the handler with the given configuration variables."""
        if "cert_conf_handler" in kwargs:
            return cls.from_config_vars(**kwargs["cert_conf_handler"])

        if "config_vars" in kwargs:
            config_vars = kwargs.pop("config_vars")
            if not isinstance(config_vars, CertConfConfigVars):
                config_vars = CertConfConfigVars(**config_vars)
        else:
            if all(k in kwargs for k in fields(CertConfConfigVars)):
                config_vars = CertConfConfigVars(**kwargs)
            elif any(k in kwargs for k in fields(CertConfConfigVars)):
                config_vars = CertConfConfigVars(
                    enforce_same_alg=kwargs.get("enforce_same_alg", True),
                    must_be_protected=kwargs.get("must_be_protected", True),
                    allow_auto_ed=kwargs.get("allow_auto_ed", True),
                    must_be_fresh_nonce=kwargs.get("must_be_fresh_nonce", True),
                )
            else:
                config_vars = None

        return cls(state_db=kwargs["conf_state"], config_vars=config_vars)

    def details(self) -> Dict[str, Union[CertConfConfigVars, CertConfState]]:
        """Return the details of the certificate confirmation handler."""
        return {"config_vars": self.config_vars, "conf_state": self.conf_state}

    def add_confirmed_certs(self, request: PKIMessageTMP, certs: List[rfc9480.CMPCertificate]) -> None:
        """Add the confirmed certificate to the state."""
        for cert in certs:
            self.conf_state.add_confirmed_cert(request, cert)

    def add_request(self, pki_message: PKIMessageTMP):
        """Add the certificate confirmation request to the state."""
        self.conf_state.add_request(pki_message)

    def is_not_confirmed(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if the certificate is to be confirmed."""
        return self.conf_state.is_not_confirmed(cert)

    def add_response(self, pki_message: PKIMessageTMP, certs: List[rfc9480.CMPCertificate]):
        """Add the CA response to the state."""
        self.conf_state.add_response(pki_message, certs)

    def _confirm_cert(self, first_cert: rfc9480.CMPCertificate, second_cert: rfc9480.CMPCertificate):
        """Confirm the certificate."""
        if first_cert.isValue and not second_cert.isValue:
            raise WrongIntegrity("The first message was signature protected, but the second was not.")

        if not first_cert.isValue and second_cert.isValue:
            raise WrongIntegrity("The second message was signature protected, but the first was not.")

        if first_cert.isValue and second_cert.isValue:
            if encoder.encode(first_cert) != encoder.encode(second_cert):
                raise WrongAuthority("The authority is not the same as the one for the request.")

    def _verify_protection(self, pki_message: PKIMessageTMP) -> None:
        """Verify the consistency of the protection.

        :param pki_message: The message to verify.
        """
        logging.info("Verifying the protection of the message.")
        print("Verifying the protection of the message.")
        request = self.conf_state.get_request(pki_message)

        prot_type = get_protection_type_from_pkimessage(pki_message=request)

        if not pki_message["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("The protection algorithm is not set.")

        now_prot_type = get_protection_type_from_pkimessage(pki_message=pki_message)

        if prot_type == "sig":
            self._confirm_cert(request["extraCerts"][0], pki_message["extraCerts"][0])

        if prot_type == "mac" and now_prot_type != "mac":
            raise WrongIntegrity("The protection type is not as expected.")

        if prot_type == "mac":
            if pki_message["header"]["protectionAlg"]["algorithm"] != request["header"]["protectionAlg"]["algorithm"]:
                raise BadMessageCheck("The protection algorithm is not as expected.")

        if prot_type == "sig" and now_prot_type != "sig":
            raise WrongIntegrity("The protection type is not as expected.")

    def process_cert_conf(self, pki_message: PKIMessageTMP):
        """Process the certificate confirmation message.

        :param pki_message: The CertConf message.
        :return: The PKIMessage containing the response.
        :raises BadRequest: If the request cannot be processed,
        due miss match of the transaction ID.
        """
        self.conf_state.is_confirmed(pki_message)
        self.conf_state.validate_tx_fields(pki_message)
        self._verify_protection(pki_message)

        response = self.conf_state.get_ca_response(pki_message)

        validate_pkimessage_header(
            pki_message,
            response,
            allow_failure_sender=False,
            time_interval=None,
        )

        issued_certs = self.conf_state.get_confirmable_certs(pki_message)

        if not issued_certs:
            raise CertConfirmed("No certificates to confirm.")

        response = build_pki_conf_from_cert_conf(
            request=pki_message,
            issued_certs=issued_certs,
            allow_auto_ed=self.config_vars.allow_auto_ed,
        )

        self.conf_state.remove_request(pki_message)
        self.state_db.add_certs(issued_certs)

        return response
