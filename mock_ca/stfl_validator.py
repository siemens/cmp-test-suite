# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Mock CA Stateful Signature PKIMessage Validator."""

import logging
from typing import List, Optional

from pyasn1_alt_modules import rfc6402, rfc9480

from mock_ca.mock_fun import PQStatefulSigKeyConfig
from mock_ca.operation_dbs import StatefulSigKeyState, StatefulSigState
from pq_logic.hybrid_sig.chameleon_logic import get_delta_request_signature
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPublicKey
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import get_cert_template_from_pkimessage, get_popo_from_pkimessage
from resources.certutils import load_public_key_from_cert
from resources.cmputils import get_cmp_message_type
from resources.exceptions import BadMessageCheck, BadRequest, InvalidKeyData
from resources.keyutils import load_public_key_from_spki
from resources.oidutils import PQ_STATEFUL_HASH_SIG_OID_2_NAME
from resources.suiteenums import ProtectedType


class STFLPKIMessageValidator:
    """Additional validator for Stateful signature PKIMessages."""

    def __init__(
        self,
        stfl_state: StatefulSigState,
        stfl_config: Optional[PQStatefulSigKeyConfig] = None,
    ) -> None:
        """Create the validator with required handlers."""
        self._stfl_state = stfl_state
        self.pq_stateful_cfg = stfl_config if stfl_config else PQStatefulSigKeyConfig()

    def add_pq_stateful_pki_message(self, pki_message: PKIMessageTMP) -> None:
        """Add a PKI message to the CA handler."""
        if not pki_message["header"]["protectionAlg"].isValue:
            return

        prot_type = ProtectedType.get_protection_type(pki_message)
        if prot_type != ProtectedType.PQ_HASH_STATEFUL_SIG:
            return

        ee_cert = pki_message["extraCerts"][0]
        state = self._stfl_state.get_state(cert=ee_cert)
        if state is None:
            raise BadMessageCheck(
                "The PKIMessage does not contain a valid Stateful signature state. "
                "Please check if the certificate is registered for Stateful signatures."
            )

        public_key = load_public_key_from_cert(ee_cert)  # type: ignore[assignment]
        public_key: PQHashStatefulSigPublicKey
        signature = pki_message["protection"].asOctets()
        index = public_key.get_leaf_index(signature)
        state.add_used_index(index)

    def validate_pq_stateful_pki_message(self, pki_message: PKIMessageTMP) -> None:
        """Validate the PKI message."""
        if not pki_message["header"]["protectionAlg"].isValue:
            return

        prot_type = ProtectedType.get_protection_type(pki_message)
        if prot_type != ProtectedType.PQ_HASH_STATEFUL_SIG:
            return

        if not pki_message["extraCerts"].isValue:
            raise BadMessageCheck("No extra certificates in PKI message. Cannot validate signature.")

        if get_cmp_message_type(pki_message) == "ccr":
            # Validate if the signer is allowed to send a CCR.
            if not self.pq_stateful_cfg.allow_stfl_ccr:
                raise BadRequest("The Stateful signature algorithm is not allowed for CCRs")

        ee_cert = pki_message["extraCerts"][0]
        try:
            public_key = load_public_key_from_cert(ee_cert)
        except InvalidKeyData as e:
            raise BadMessageCheck(
                "The extra certificate in the PKI message does not contain a valid public key.",
                error_details=[e.message] + e.error_details,
            ) from e

        if not isinstance(public_key, PQHashStatefulSigPublicKey):
            raise BadMessageCheck(
                "The extra certificate in the PKI message does not contain a valid Stateful signature public key."
            )

        state = self._stfl_state.get_state(cert=ee_cert)

        if state is None:
            raise BadMessageCheck(
                "The PKIMessage does not contain a valid Stateful signature state. "
                "Please check if the certificate is registered for Stateful signatures."
            )

        signature = pki_message["protection"].asOctets()
        index = public_key.get_leaf_index(signature)

        if state.contains_used_index(index):
            raise BadMessageCheck(
                "The signature in the PKIMessage has already been used. Stateful signatures must not be reused."
            )

        if self.pq_stateful_cfg.saved_bad_message_check_stfl_key:
            state.add_used_index(index)

    def _get_popo_sig(self, request: PKIMessageTMP, index: int) -> Optional[StatefulSigKeyState]:
        """Get the POPO signature state for a given request index."""
        body_name = request["body"].getName()

        if body_name == "p10cr":
            signature = request["body"]["p10cr"]["signature"].asOctets()
            spki = request["body"]["p10cr"]["certificationRequestInfo"]["subjectPublicKeyInfo"]

        elif body_name in ["ir", "cr", "kur", "ccr", "krr"]:
            popo = get_popo_from_pkimessage(request, index)
            if not popo.isValue:
                return None

            option = popo.getName()

            if option == "raVerified":
                raise BadRequest("The RA verification is not allowed to be set for Stateful signatures keys.")

            if option != "signature":
                raise BadRequest("The POPO signature is missing in the request.")

            signature = popo["signature"]["signature"].asOctets()

            cert_template = get_cert_template_from_pkimessage(request, index)
            spki = cert_template["publicKey"]
        else:
            raise ValueError("Stateful signatures only support P10CR, IR, CR, KUR, CCR, and KRR requests.")

        public_key = load_public_key_from_spki(spki)
        if not isinstance(public_key, PQHashStatefulSigPublicKey):
            raise ValueError("The public key in the request is not a valid Stateful signature public key.")
        index = public_key.get_leaf_index(signature)
        state = StatefulSigKeyState(used_indices=[index])
        return state

    def _may_add_delta_cert(self, delta_cert: rfc9480.CMPCertificate, csr: rfc6402.CertificationRequest) -> None:
        """Add a delta certificate to the CA handler.

        :param delta_cert: The CMPCertificate to add.
        :param csr: The CertificationRequest associated with the delta certificate.
        """
        spki = delta_cert["tbsCertificate"]["subjectPublicKeyInfo"]
        oid = spki["algorithm"]["algorithm"]
        if oid not in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
            return

        signature = get_delta_request_signature(csr=csr)
        public_key = load_public_key_from_spki(spki)
        if not isinstance(public_key, PQHashStatefulSigPublicKey):
            raise InvalidKeyData(
                "The public key in the delta certificate is not a valid Stateful signature public key."
            )

        index = public_key.get_leaf_index(signature)
        tmp_state = StatefulSigKeyState(used_indices=[index])
        self._stfl_state.add_state(delta_cert, tmp_state)

    def _may_add_paired_cert(self, paired_cert: rfc9480.CMPCertificate, csr: rfc6402.CertificationRequest) -> None:
        """May add the STFL state for a chameleon paired certificate."""
        spki = paired_cert["tbsCertificate"]["subjectPublicKeyInfo"]
        oid = spki["algorithm"]["algorithm"]
        if oid not in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
            return
        public_key = load_public_key_from_spki(spki)
        if not isinstance(public_key, PQHashStatefulSigPublicKey):
            raise InvalidKeyData(
                "The public key in the paired certificate is not a valid Stateful signature public key."
            )

        signature = csr["signature"].asOctets()
        index = public_key.get_leaf_index(signature)
        tmp_state = StatefulSigKeyState(used_indices=[index])
        self._stfl_state.add_state(paired_cert, tmp_state)

    def _process_chameleon_pki_message(self, pki_message: PKIMessageTMP, certs: List[rfc9480.CMPCertificate]) -> None:
        """Process a PQ Stateful PKI message.

        :param pki_message: The PKIMessage to process.
        :param certs: The list of certificates associated with the PKIMessage.
        """
        if len(certs) != 2:
            msg = (
                "Chameleon requests must contain exactly two certificates."
                " The paired certificate and the delta certificate."
            )
            raise TypeError(msg)

        paired_cert, delta_cert = certs[0], certs[1]
        self._may_add_delta_cert(delta_cert=delta_cert, csr=pki_message["body"]["p10cr"])
        self._may_add_paired_cert(paired_cert=paired_cert, csr=pki_message["body"]["p10cr"])

    def process_stfl_after_request(
        self,
        request: PKIMessageTMP,
        certs: List[rfc9480.CMPCertificate],
        confirmed: bool = False,
        chameleon: bool = False,
    ) -> None:
        """Process the Stateful signature state after a request.

        :param request: The PKIMessage containing the request.
        :param certs: The certificates associated with the request.
        :param confirmed: Whether the certificates were confirmed or not.
        :param chameleon: Whether the request is a chameleon request.
        """
        if chameleon:
            logging.debug("Chameleon request detected, skipping processing.")
            self._process_chameleon_pki_message(request, certs)
            return

        body_name = request["body"].getName()
        if body_name not in ["ir", "cr", "kur", "p10cr", "ccr", "krr"]:
            return

        if confirmed:
            for i, cert in enumerate(certs):
                spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
                oid = spki["algorithm"]["algorithm"]
                if oid not in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
                    continue
                alg_name = PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]
                logging.debug("Processing confirmed request for algorithm: %s", alg_name)
                tmp_state = self._get_popo_sig(request=request, index=i)
                if tmp_state is None:
                    continue
                self._stfl_state.add_state(cert, tmp_state)
