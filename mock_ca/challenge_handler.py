# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The challenge handler for the Mock-CA."""

import os
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyasn1_alt_modules import rfc9480

from mock_ca.operation_dbs import MockCAOPCertsAndKeys
from pq_logic.keys.abstract_wrapper_keys import KEMPublicKey
from pq_logic.keys.trad_kem_keys import RSAEncapKey
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import (
    build_ip_cmp_message,
    build_popdecc_from_request,
    get_cert_template_from_pkimessage,
    get_popo_from_pkimessage,
    prepare_cert_response,
)
from resources.certbuildutils import build_cert_from_cert_template
from resources.exceptions import BadCertTemplate, BadRequest
from resources.keyutils import load_public_key_from_cert_template
from resources.protectionutils import get_protection_type_from_pkimessage
from resources.typingutils import ECDHPrivateKey, ECDHPublicKey, SignKey


class ChallengeHandler:
    """The challenge handler for the CMP server.

    Only the challenge for `popdecc` messages are supported.
    The `encrCert` challenge is directly supported inside the `CertRequestHandler`.
    """

    challenge: Dict[Tuple[int, bytes], Tuple[rfc9480.CertTemplate, str]]

    def __init__(
        self,
        ca_key: SignKey,
        ca_cert: rfc9480.CMPCertificate,
        extensions: Optional[rfc9480.Extensions] = None,
        challenge: Optional[Dict] = None,
        ecc_key: Optional[EllipticCurvePrivateKey] = None,
        x25519_key: Optional[X25519PrivateKey] = None,
        x448_key: Optional[X448PrivateKey] = None,
        operation_state: Optional[MockCAOPCertsAndKeys] = None,
        cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    ):
        """Initialize the challenge handler.

        :param ca_key: The CA key.
        :param ca_cert: The CA certificate.
        :param extensions: The extensions to use.
        :param challenge: The challenges already loaded.
        :param ecc_key: The CA ECC key.
        :param x25519_key: The CA X25519 key.
        :param x448_key: The CA X448 key.
        :param operation_state: The operation parameters to use.
        :param cmp_protection_cert: The CMP protection certificate.
        """
        self.ca_key = ca_key
        self.extensions = extensions
        self.ca_cert = ca_cert
        self.challenge = challenge or {}
        self.ca_ecc_key = ecc_key
        self.ca_x25519_key = x25519_key
        self.ca_x448_key = x448_key
        self.sender = "CN=CMP-Test-Suite"
        self.operation_state = operation_state or MockCAOPCertsAndKeys(
            ca_cert=ca_cert,
            ca_key=ca_key,
            ecc_key=ecc_key,
            x25519_key=x25519_key,
            x448_key=x448_key,
        )
        self.cmp_protection_cert = cmp_protection_cert or ca_cert

    def _get_ca_key(self, request: PKIMessageTMP) -> Optional[ECDHPrivateKey]:
        """Get the CA key based on the request."""
        popo = get_popo_from_pkimessage(request=request)
        cert_template = get_cert_template_from_pkimessage(request=request)
        public_key = load_public_key_from_cert_template(cert_template)
        if popo.getName() == "keyEncipherment":
            if not isinstance(public_key, (KEMPublicKey, RSAEncapKey, RSAPublicKey)):
                raise BadCertTemplate("The keyEncipherment is only allowed for RSA or KEM keys.")
        elif popo.getName() == "keyAgreement":
            if not isinstance(public_key, ECDHPublicKey):
                raise BadCertTemplate("The keyAgreement is only allowed for ECDH keys.")
            if isinstance(public_key, X448PublicKey):
                return self.ca_x448_key or self.operation_state.x448_key
            elif isinstance(public_key, X25519PublicKey):
                return self.ca_x25519_key or self.operation_state.x25519_key
            else:
                return self.ca_ecc_key or self.operation_state.ecc_key
        return None

    def _process_challenge(self, request: PKIMessageTMP) -> Tuple[PKIMessageTMP, Optional[ECDHPrivateKey]]:
        """Process the challenge response."""
        prot_type = get_protection_type_from_pkimessage(request)
        if request["header"]["pvno"] == 3 and prot_type == "mac":
            raise BadRequest("The challenge request was version 3, and MAC protected, this is not allowed!")

        body_name = request["body"].getName()
        num = int.from_bytes(os.urandom(4), "big")
        ca_key = self._get_ca_key(request)
        response, num = build_popdecc_from_request(
            request=request,
            challenge=self.challenge,
            rand_int=num,
            ca_key=ca_key,
            expected_size=1,
            sender=self.sender,
            cmp_protection_cert=self.cmp_protection_cert,
        )
        tx_id = request["header"]["transactionID"].asOctets()
        self.challenge[(num, tx_id)] = (request["body"][body_name][0]["certReq"]["certTemplate"], body_name)

        return response, ca_key

    def _process_popdecr(self, request: PKIMessageTMP) -> Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]:
        """Process the popdecr response."""
        certs = []
        body_name = None
        tx_id = request["header"]["transactionID"].asOctets()
        for entry in request["body"]["popdecr"]:
            tmp_entry = (int(entry), tx_id)
            if tmp_entry not in self.challenge:
                raise BadRequest(f"The challenge number is not found. Got: {entry}")
            out = self.challenge[tmp_entry]
            cert = build_cert_from_cert_template(
                cert_template=out[0],
                ca_key=self.ca_key,
                ca_cert=self.ca_cert,
                extensions=self.extensions,
            )
            del self.challenge[tmp_entry]
            if body_name is None:
                body_name = out[1]
            certs.append(cert)

        if body_name == "ir":
            responses = []
            for cert in certs:
                cert_resp = prepare_cert_response(
                    cert=cert,
                )
                responses.append(cert_resp)
        else:
            raise NotImplementedError(
                f"The challenge response for '{body_name}' is not implemented yet. Got: {body_name}"
            )

        return build_ip_cmp_message(
            request=request,
            responses=responses,
        )

    def handle_challenge(
        self, request: PKIMessageTMP
    ) -> Tuple[PKIMessageTMP, Union[List[rfc9480.CMPCertificate], Optional[ECDHPrivateKey]]]:
        """Handle the challenge response."""
        body_name = request["body"].getName()
        if body_name in ["ir", "cr"]:
            return self._process_challenge(request)
        elif body_name == "popdecr":
            return self._process_popdecr(request)
        else:
            raise BadRequest(
                f"The challenge issuing process can only be used with: 'ir' or 'cr' messages, not '{body_name}'."
            )
