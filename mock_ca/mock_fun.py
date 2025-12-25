# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Necessary dataclasses and functions for the mock CA to operate."""

import enum
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple, Union

from cryptography import x509
from cryptography.x509 import CertificateRevocationList, ExtensionNotFound, ocsp
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc5280, rfc9480

from mock_ca.operation_dbs import SunHybridState
from pq_logic.keys.abstract_wrapper_keys import HybridPublicKey, KEMPublicKey
from resources import ca_ra_utils, certutils, keyutils
from resources.asn1_structures import PKIMessageTMP
from resources.certutils import load_public_key_from_cert
from resources.cmputils import get_cmp_message_type
from resources.compareutils import compare_pyasn1_names
from resources.convertutils import copy_asn1_certificate, ensure_is_trad_sign_key
from resources.copyasn1utils import copy_subject_public_key_info
from resources.deprecatedutils import _sign_crl_builder
from resources.exceptions import (
    BadCertId,
    BadMessageCheck,
    BadRequest,
    CertConfirmed,
    CertRevoked,
    TransactionIdInUse,
)
from resources.oid_mapping import compute_hash
from resources.oidutils import id_KemBasedMac
from resources.protectionutils import verify_kem_based_mac_protection
from resources.typingutils import ECDHPrivateKey, PrivateKey, PublicKey, SignKey
from unit_tests.utils_for_test import compare_pyasn1_objects, convert_to_crypto_lib_cert


@dataclass
class RevokedEntry:
    """A revoked entry containing the reason and the certificate."""

    reason: str
    cert: rfc9480.CMPCertificate
    hashed_cert: Optional[bytes] = None
    revoked_date: Optional[datetime] = None


@dataclass
class RevokedEntryList:
    """A list of revoked entries."""

    entries: List[RevokedEntry] = field(default_factory=list)
    hash_alg: str = "sha1"

    @classmethod
    def build(cls, hash_alg: str, entries: List[Union[dict, rfc9480.CMPCertificate]]) -> "RevokedEntryList":
        """Build a RevokedEntryList from the given entries."""
        data = []
        for entry in entries:
            if isinstance(entry, dict):
                data.append(RevokedEntry(**entry))
            elif isinstance(entry, rfc9480.CMPCertificate):
                hashed_cert = compute_hash(hash_alg, encoder.encode(entry))
                new_entry = RevokedEntry(
                    reason="unspecified",
                    cert=entry,
                    hashed_cert=hashed_cert,
                )
                data.append(new_entry)
            else:
                raise TypeError(f"Unsupported entry type: {type(entry).__name__}")

        return cls(entries=data, hash_alg=hash_alg)

    def __len__(self) -> int:
        """Return the number of entries."""
        return len(self.entries)

    def contains_hash(self, hashed_cert: bytes) -> bool:
        """Check if the list contains a certificate with the given hash."""
        for entry in self.entries:
            if entry.hashed_cert is None:
                tmp = compute_hash(self.hash_alg, encoder.encode(entry.cert))
            else:
                tmp = entry.hashed_cert

            if tmp == hashed_cert:
                return True
        return False

    def get_by_hash(self, hashed_cert: bytes) -> Optional[rfc9480.CMPCertificate]:
        """Get a revoked entry by its hash."""
        for entry in self.entries:
            if entry.hashed_cert is None:
                entry.hashed_cert = compute_hash(self.hash_alg, encoder.encode(entry.cert))
            if entry.hashed_cert == hashed_cert:
                return entry.cert
        return None

    def remove_by_hash(self, hashed_cert: bytes) -> Optional[RevokedEntry]:
        """Remove a revoked certificate by its hash."""
        found = None
        for entry in self.entries:
            if entry.hashed_cert is None:
                entry.hashed_cert = compute_hash(self.hash_alg, encoder.encode(entry.cert))

            if entry.hashed_cert == hashed_cert:
                found = entry
                break

        if found is not None:
            self.entries.remove(found)
            logging.info("Removed revoked certificate")

    def __post_init__(self):
        """Convert the entries to RevokedEntry instances."""
        data = []
        for entry in self.entries:
            if isinstance(entry, dict):
                data.append(RevokedEntry(**entry))
            else:
                data.append(entry)

        self.entries = data

    def get_cert_by_serial_number(self, serial_number: int) -> Optional[rfc9480.CMPCertificate]:
        """Return the certificate with the given serial number."""
        for entry in self.entries:
            if int(entry.cert["tbsCertificate"]["serialNumber"]) == serial_number:
                return entry.cert
        return None

    @property
    def serial_numbers(self) -> List[int]:
        """Return the serial numbers of the revoked certificates."""
        return [int(entry.cert["tbsCertificate"]["serialNumber"]) for entry in self.entries]

    @property
    def certs(self) -> List[rfc9480.CMPCertificate]:
        """Return the certificates."""
        return [entry.cert for entry in self.entries]

    def remove(self, entry: RevokedEntry) -> None:
        """Remove an entry from the list."""
        found = None
        for x in self.entries:
            if compare_pyasn1_objects(
                entry.cert,
                x.cert,
            ):
                found = x
                break

        if found is not None:
            self.entries.remove(found)

    def add_entry(self, entry: Union[RevokedEntry, dict, List[dict]]) -> None:
        """Add a revoked entry to the list."""
        if isinstance(entry, dict):
            data = [RevokedEntry(**entry)]  # type: ignore
        elif isinstance(entry, list):
            data = [RevokedEntry(**entry) for entry in entry]  # type: ignore
        else:
            data = [entry]

        if not isinstance(data, list):
            raise ValueError("Entry must be a list or a single entry.")

        for item in data:
            if item.reason == "removeFromCRL":
                self.remove(item)
            else:
                self.entries.append(item)

    @property
    def compromised_keys(self) -> List[PublicKey]:
        """Return the compromised keys."""
        data = []
        for entry in self.entries:
            public_key = keyutils.load_public_key_from_spki(entry.cert["tbsCertificate"]["subjectPublicKeyInfo"])

            if isinstance(public_key, HybridPublicKey):
                data.append(public_key.pq_key)
                data.append(public_key.trad_key)
                data.append(public_key)
            else:
                data.append(public_key)
        return data

    def _contains(self, key: Union[PublicKey, HybridPublicKey]) -> bool:
        """Check if the key is in the list of compromised keys."""
        if isinstance(key, HybridPublicKey):
            return (
                key.pq_key in self.compromised_keys
                or key.trad_key in self.compromised_keys
                or key in self.compromised_keys
            )
        return key in self.compromised_keys

    def contains_key(
        self, structure_or_key: Union[PublicKey, HybridPublicKey, rfc9480.CMPCertificate, rfc9480.CertTemplate]
    ) -> bool:
        """Check if the key is in the list of compromised keys.

        :param structure_or_key: The key to check or a certificate or certificate template.
        """
        if isinstance(structure_or_key, HybridPublicKey):
            return self._contains(structure_or_key)
        if isinstance(structure_or_key, PublicKey):
            return self._contains(structure_or_key)

        if isinstance(structure_or_key, rfc9480.CMPCertificate):
            public_key = keyutils.load_public_key_from_spki(structure_or_key["tbsCertificate"]["subjectPublicKeyInfo"])
            return self._contains(public_key)
        if isinstance(structure_or_key, rfc9480.CertTemplate):
            spki = copy_subject_public_key_info(
                filled_sub_pubkey_info=structure_or_key["publicKey"],
                target=rfc5280.SubjectPublicKeyInfo(),
            )
            public_key = keyutils.load_public_key_from_spki(spki)
            return self._contains(public_key)

        raise ValueError(f"Unsupported key type: {type(structure_or_key).__name__}")

    def is_revoked(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if the certificate is revoked.

        :param cert: The certificate to check.
        :return: Whether the certificate is revoked.
        """
        for x in self.certs:
            if compare_pyasn1_objects(cert, x):
                return True
        return False


@dataclass
class CertRevStateDB:
    """The certificate revocation state database."""

    rev_entry_list: RevokedEntryList = field(default_factory=RevokedEntryList)
    update_entry_list: RevokedEntryList = field(default_factory=RevokedEntryList)
    _update_eq_rev: bool = True  # Whether the update entry list is also counted as revoked.
    _crl_number: int = 1  # The CRL number.
    hash_alg: str = "sha1"

    @classmethod
    def build(
        cls,
        hash_alg: Optional[str] = None,
        revoked_certs: Optional[List[rfc9480.CMPCertificate]] = None,
        updated_certs: Optional[List[rfc9480.CMPCertificate]] = None,
        crl_number: int = 1,
    ) -> "CertRevStateDB":
        """Build the certificate revocation state database."""
        hash_alg = hash_alg or "sha1"
        rev_list = RevokedEntryList.build(hash_alg=hash_alg, entries=revoked_certs or [])  # type: ignore
        update_list = RevokedEntryList.build(hash_alg=hash_alg, entries=updated_certs or [])  # type: ignore
        return cls(
            rev_entry_list=rev_list,
            update_entry_list=update_list,
            _update_eq_rev=True,
            _crl_number=crl_number,
            hash_alg=hash_alg,
        )

    @staticmethod
    def _get_nonce(ocsp_request: ocsp.OCSPRequest) -> Optional[bytes]:
        """Get the OCSP nonce from the request."""
        try:
            ocsp_nonce = ocsp_request.extensions.get_extension_for_class(x509.OCSPNonce)
            nonce = ocsp_nonce.value.nonce
            logging.info("OCSP Nonce: %s", nonce.hex())
            return nonce
        except ExtensionNotFound:
            logging.info("OCSP Nonce not found in the request.")
            return None

    def _check_ocps_request_cert_status(
        self,
        request: ocsp.OCSPRequest,
        issued_certs: List[rfc9480.CMPCertificate],
    ) -> Tuple[Optional[rfc9480.CMPCertificate], str]:
        """Check the OCSP request for the certificate status.

        If the certificate is not found in the list of issued certificates,
        is the status set to "unauthorized".

        :param request: The OCSP request.
        :param issued_certs: The list of issued certificates.
        :return: The certificate, if found and the status.
        """
        num = request.serial_number

        nums = self.rev_entry_list.serial_numbers

        if self._update_eq_rev:
            nums += self.update_entry_list.serial_numbers

        status = "unauthorized"
        found_cert = None
        if num in nums:
            status = "revoked"
            found_cert = self.rev_entry_list.get_cert_by_serial_number(num)
        else:
            for cert in issued_certs:
                if num == int(cert["tbsCertificate"]["serialNumber"]):
                    found_cert = cert
                    status = "good"
                    break

        return found_cert, status

    def get_ocsp_response(
        self,
        request: ocsp.OCSPRequest,
        sign_key: SignKey,
        ca_cert: rfc9480.CMPCertificate,
        issued_certs: List[rfc9480.CMPCertificate],
        responder_cert: Optional[rfc9480.CMPCertificate] = None,
    ) -> ocsp.OCSPResponse:
        """Get the OCSP response for the request."""
        found_cert, status = self._check_ocps_request_cert_status(request, issued_certs)

        if found_cert is None and status == "unauthorized":
            # If the extension is not present:
            # As of RFC 6960, section 2.3
            # The response "unauthorized" is returned in cases where the client is
            # not authorized to make this query to this server or the server is not
            # capable of responding authoritatively (cf. [RFC5019], Section 2.2.3).
            return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        if found_cert is None:
            raise NotImplementedError("Certificate not found in the list of issued certificates.")

        nonce = self._get_nonce(request)

        # TODO maybe also save revocation time.
        revocation_time = None
        if status == "revoked":
            revocation_time = datetime.now(timezone.utc) - timedelta(seconds=60)

        return certutils.build_ocsp_response(
            cert=found_cert,
            ca_cert=ca_cert,
            hash_alg=request.hash_algorithm.name,
            status=status,
            revocation_time=revocation_time,
            responder_hash_alg=request.hash_algorithm.name,
            responder_key=sign_key,
            responder_cert=responder_cert,
            nonce=nonce,
        )

    def get_crl_response(
        self,
        sign_key: SignKey,
        ca_cert: rfc9480.CMPCertificate,
        hash_alg: Optional[str] = None,
    ) -> CertificateRevocationList:
        """Get the CRL response for the request.

        :param sign_key: The private key to sign the CRL.
        :param ca_cert: The CA certificate.
        :param hash_alg: The hash algorithm to use for signing.
        """
        nums = self.rev_entry_list.serial_numbers
        if self._update_eq_rev:
            nums += self.update_entry_list.serial_numbers

        crypto_ca_cert = convert_to_crypto_lib_cert(ca_cert)
        _now = datetime.now(timezone.utc) - timedelta(seconds=60)  # to avoid time issues.
        _next_update = _now + timedelta(days=1)

        aia_value = x509.AuthorityKeyIdentifier.from_issuer_public_key(crypto_ca_cert.public_key())  # type: ignore
        aia_extn = x509.Extension(
            x509.AuthorityKeyIdentifier.oid,
            False,
            aia_value,
        )

        builder = x509.CertificateRevocationListBuilder(
            issuer_name=crypto_ca_cert.subject,
            last_update=_now,
            next_update=_next_update,
            extensions=[aia_extn],
        )
        builder = builder.add_extension(x509.CRLNumber(self._crl_number), critical=False)
        self._crl_number += 1

        for serial_number in nums:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder(serial_number=serial_number, revocation_date=datetime.now()).build(),
            )

        trad_sign_key = ensure_is_trad_sign_key(sign_key)
        return _sign_crl_builder(crl_builder=builder, sign_key=trad_sign_key, hash_alg=hash_alg or "sha256")

    def add_compromised_key(self, entry: Union[dict, RevokedEntry]) -> None:
        """Add a compromised key to the list."""
        self.rev_entry_list.add_entry(entry)

    def add_rev_entry(self, entry: Union[RevokedEntry, dict, List[dict]]) -> None:
        """Add a revoked entry to the list."""
        self.rev_entry_list.add_entry(entry)

    def check_request_for_compromised_key(self, request: PKIMessageTMP) -> bool:
        """Check if the request contains a compromised key.

        :param request: The certificate request.
        :return: Whether the request contains a compromised key.
        """
        if request["body"].getName() == "p10cr":
            public_key = keyutils.load_public_key_from_spki(
                request["body"]["p10cr"]["certificationRequestInfo"]["subjectPublicKeyInfo"]
            )
            return self.rev_entry_list.contains_key(public_key)

        body_name = request["body"].getName()

        if body_name in ["ir", "cr", "crr", "kur"]:
            for entry in request["body"][body_name]:
                public_key = ca_ra_utils.get_public_key_from_cert_req_msg(entry, must_be_present=False)
                if public_key is None:
                    return False

                if self.rev_entry_list.contains_key(public_key):
                    return True

        return False

    def get_by_hash(self, data: Union[bytes, rfc9480.CMPCertificate]) -> Optional[rfc9480.CMPCertificate]:
        """Get a revoked entry by its hash.

        :param data: The certificate to hash or the already computed hash value.
        :return: The revoked certificate if found, `None` otherwise.
        """
        if isinstance(data, bytes):
            hashed_cert = data
        else:
            hashed_cert = compute_hash(self.hash_alg, encoder.encode(data))
        return self.rev_entry_list.get_by_hash(hashed_cert=hashed_cert)

    def is_revoked_by_hash(self, hashed_cert: bytes) -> bool:
        """Check if the certificate with the given hash is revoked."""
        return self.rev_entry_list.contains_hash(hashed_cert=hashed_cert)

    def is_updated_by_hash(self, hashed_cert: bytes) -> bool:
        """Check if the certificate with the given hash is updated."""
        return self.update_entry_list.contains_hash(hashed_cert=hashed_cert)

    def add_updated_cert(self, cert: rfc9480.CMPCertificate) -> None:
        """Add an updated certificate to the list."""
        hashed_cert = compute_hash("sha1", encoder.encode(cert))
        self.update_entry_list.add_entry(RevokedEntry(reason="updated", cert=cert, hashed_cert=hashed_cert))


@dataclass
class CAOperationState:
    """The state of the CA operation.

    Attributes
    ----------
        - `ca_key`: The private key of the CA.
        - `ca_cert`: The certificate of the CA.
        - `pre_shared_secret`: The pre-shared secret.
        - `extensions`: The extensions of the CA.

    """

    ca_key: SignKey
    ca_cert: rfc9480.CMPCertificate
    pre_shared_secret: bytes
    extensions: Optional[rfc9480.Extensions]


@dataclass
class KEMSharedSharedState:
    """The state of the KEM shared key.

    Attributes
    ----------
        - `shared_secret`: The KEM shared secret.
        - `transaction_id`: The transaction ID of the sender.
        - `sender`: The sender of the message.
        - `kem_public_key`: The KEM public key.
        - `kem_cert`: The KEM certificate.
        - `was_used_for_issuing`: Whether the shared secret was used for issuing a certificate.

    """

    shared_secret: bytes
    transaction_id: bytes
    sender: Optional[rfc9480.Name] = None
    kem_public_key: Optional[KEMPublicKey] = None
    kem_cert: Optional[rfc9480.CMPCertificate] = None
    was_used_for_issuing: bool = False  # used so that it can correctly be used
    # to confirm the certificate request.

    def is_for_request(self, request: PKIMessageTMP) -> bool:
        """Check if the shared secret is for the given transaction ID."""
        if request["header"]["transactionID"].asOctets() == self.transaction_id:
            return True
        return False


@dataclass
class KEMSharedSecretList:
    """A list of KEM shared secrets.

    Attributes
    ----------
        - `shared_secrets`: The list of KEM shared secrets.

    """

    shared_secrets: List[KEMSharedSharedState] = field(default_factory=list)

    def get_all_shared_secrets(self) -> List[bytes]:
        """Get all KEM shared secrets."""
        return [ss_obj.shared_secret for ss_obj in self.shared_secrets]

    def __len__(self) -> int:
        """Return the number of KEM shared secrets entries."""
        return len(self.shared_secrets)

    def __getitem__(self, index: int) -> KEMSharedSharedState:
        """Get the KEM shared secret at the given index."""
        return self.shared_secrets[index]

    def update_shared_secret_state(self, ss: Optional[bytes], request: PKIMessageTMP) -> None:
        """Update the state of the shared secrets, because a new request was received.

        Only used, if the request was valid and the shared secret was used for issuing a certificate,
        so that it cannot be used again.
        """
        tx_id = request["header"]["transactionID"].asOctets()
        for shared_secret in self.shared_secrets:
            if shared_secret.is_for_request(request):
                if ss is not None:
                    shared_secret.was_used_for_issuing = True
                elif shared_secret.transaction_id == tx_id:
                    shared_secret.was_used_for_issuing = True

    def add_shared_secret(self, request: PKIMessageTMP, ss: bytes) -> None:
        """Add a KEM shared secret to the list."""
        states = KEMSharedSharedState(
            shared_secret=ss,
            transaction_id=request["header"]["transactionID"].asOctets(),
            sender=request["header"]["sender"],
        )
        self.shared_secrets.append(states)

    def remove_shared_secret(self, request: PKIMessageTMP) -> Optional[KEMSharedSharedState]:
        """Remove a KEM shared secret from the list."""
        for shared_secret in self.shared_secrets:
            if shared_secret.is_for_request(request):
                self.shared_secrets.remove(shared_secret)
                return shared_secret
        return None

    def contains_shared_secret(self, request: PKIMessageTMP) -> bool:
        """Check if the list contains a KEM shared secret with the given transaction ID."""
        for shared_secret in self.shared_secrets:
            if shared_secret.is_for_request(request):
                return True
        return False

    def get_shared_secret(self, request: PKIMessageTMP) -> Optional[bytes]:
        """Get the KEM shared secret for the given transaction ID."""
        for shared_secret in self.shared_secrets:
            if shared_secret.is_for_request(request):
                return shared_secret.shared_secret
        return None

    def get_shared_secret_object(self, request: PKIMessageTMP) -> Optional[KEMSharedSharedState]:
        """Get the KEM shared secret object for the given transaction ID."""
        for shared_secret in self.shared_secrets:
            if shared_secret.is_for_request(request):
                return shared_secret
        return None

    def verify_pkimessage_protection(self, request: PKIMessageTMP) -> None:
        """Check if the request is protected by a KEM shared secret.

        :param request: The request to be verified.
        :raises BadMessageCheck: If the request is not valid, protected by a KEM shared secret.
        :raises BadMessageCheck: If the request's shared secret was already used for another request.
        """
        result = self.contains_shared_secret(request)
        if not result:
            raise BadMessageCheck("Shared secret MUST be provided for KEM-based protection.")

        body_name = get_cmp_message_type(request)
        if body_name == "certConf":
            shared_secret = self.get_shared_secret(request)
            verify_kem_based_mac_protection(pki_message=request, shared_secret=shared_secret)
            logging.debug("KEM-based MAC protection verified.")
        else:
            kem_object = self.get_shared_secret_object(request)  # type: ignore
            kem_object: KEMSharedSharedState

            if kem_object.was_used_for_issuing:
                raise BadMessageCheck("Shared secret was already used for issuing a certificateor another request.")
            verify_kem_based_mac_protection(pki_message=request, shared_secret=kem_object.shared_secret)

    def may_update_state(self, request: PKIMessageTMP) -> None:
        """Check if the request was protected with a KEM shared secret.

        So that if a request is invalid, that the shared secret can still be used for the next request.

        :param request: The request to check.
        """
        alg_id = request["header"]["protectionAlg"]
        if not alg_id.isValue:
            return

        if alg_id["algorithm"] == id_KemBasedMac:
            ss = self.get_shared_secret(request)
            self.update_shared_secret_state(
                request=request,
                ss=ss,
            )


@dataclass
class KeySecurityChecker:
    """Check if a public key is already in use (issued, updated or revoked)."""

    issued_certs: List[rfc9480.CMPCertificate] = field(default_factory=list)
    revoked_certs: List[rfc9480.CMPCertificate] = field(default_factory=list)
    updated_certs: List[rfc9480.CMPCertificate] = field(default_factory=list)

    @staticmethod
    def _compare_pub_keys(pub_key: PublicKey, cert: rfc9480.CMPCertificate) -> bool:
        """Compare the public key with the certificate.

        :param pub_key: The public key to compare.
        :param cert: The certificate to compare with.
        :return: `True` if the public key matches the certificate, otherwise `False`.
        """
        loaded_pub_key = load_public_key_from_cert(cert)
        if isinstance(pub_key, HybridPublicKey):
            if not isinstance(loaded_pub_key, HybridPublicKey):
                return loaded_pub_key in [pub_key.trad_key, pub_key.pq_key]

            if pub_key == loaded_pub_key:
                return True
            if pub_key.trad_key == loaded_pub_key.trad_key:
                return True
            if pub_key.pq_key == loaded_pub_key.pq_key:
                return True
            if pub_key.pq_key == loaded_pub_key.trad_key:
                return True
            return False

        if isinstance(loaded_pub_key, HybridPublicKey):
            if pub_key == loaded_pub_key.trad_key:
                return True
            if pub_key == loaded_pub_key.pq_key:
                return True
            return False

        return pub_key == loaded_pub_key

    def contains_pub_key(self, pub_key: PublicKey, sender: rfc9480.Name) -> bool:
        """Check if the public key is already in use (issued or revoked).

        :param pub_key: The public key to check.
        :param sender: The sender of the request.
        :return: `True` if the public key is already in use, otherwise `False`.
        """
        all_certs = self.issued_certs + self.revoked_certs + self.updated_certs
        return self._check_contains_pub_key(certs=all_certs, pub_key=pub_key, sender=sender)

    def _check_contains_pub_key(
        self,
        certs: List[rfc9480.CMPCertificate],
        pub_key: PublicKey,
        sender: rfc9480.Name,
    ) -> bool:
        """Check if the public key is already in use."""
        for cert in certs:
            if not compare_pyasn1_names(sender, cert["tbsCertificate"]["subject"], "without_tag"):
                continue
            if self._compare_pub_keys(pub_key, cert):
                return True
        return False

    def check_cert_status(
        self,
        pub_key: PublicKey,
        sender: rfc9480.Name,
    ) -> str:
        """Check the status of the certificate.

        :return: The status of the certificate ("good", "revoked", "updated", "in_use").
        """
        if self._check_contains_pub_key(certs=self.revoked_certs, pub_key=pub_key, sender=sender):
            return "revoked"

        if self._check_contains_pub_key(certs=self.updated_certs, pub_key=pub_key, sender=sender):
            return "updated"

        if self._check_contains_pub_key(certs=self.issued_certs, pub_key=pub_key, sender=sender):
            return "in_use"

        return "good"


@enum.unique
class CertStateEnum(enum.Enum):
    """The state of the update certificate.

    Attributes
    ----------
        - `NOT_CONFIRMED`: The certificate was issued, but is still waiting for the confirmation.
        - `CONFIRMED`: The certificate issued and confirmed.
        - `REVOKED`: The certificate was revoked.
        - `UPDATED`: The certificate was updated, which is confirmed.
        - `UPDATED_BUT_NOT_CONFIRMED`: The certificate was updated, but not confirmed.
        - `REVOKED_AND_REVIVED`: The certificate was revoked and was now revived.

    """

    NOT_CONFIRMED = 0  # The certificate was issued, but is still waiting for the confirmation.
    CONFIRMED = 1  # The certificate was issued and confirmed.
    REVOKED = 2  # The certificate was revoked.
    UPDATED = 3  # The certificate was updated, which is confirmed.
    UPDATED_BUT_NOT_CONFIRMED = 4  # The certificate was updated, but not confirmed.
    REVIVED = 5  # The certificate was revoked and then revived.
    UNKNOWN = 6  # The certificate is in an unknown state, which measn it was either not issued by us
    # or in an earlier state (boot-up).


@dataclass
class CertDBEntry:
    """A certificate database entry.

    Attributes
    ----------
        - `cert`: The certificate.
        - `cert_state`: The state of the certificate.
        - `update_cert`: The updated certificate.
        - `revoked_entry`: The revoked entry.

    """

    cert_state: CertStateEnum
    cert: rfc9480.CMPCertificate
    cert_digest: bytes
    issue_date: Optional[datetime] = None
    update_cert_digest: Optional[bytes] = None
    updated_date: Optional[datetime] = None
    revoked_entry: Optional[RevokedEntry] = None


@dataclass
class UpdateCertDB:
    """A database for update certificates.

    Attributes
    ----------
        - `certs`: The list of certificates.
        - `hash_alg`: The hash algorithm to use for hashing the certificates. Defaults to "sha1".

    """

    certs: List[CertDBEntry] = field(default_factory=list)
    hash_alg: str = "sha1"
    timeout: int = 10  # seconds

    def get_cert_by_digest(self, digest: bytes) -> Optional[CertDBEntry]:
        """Get a certificate by its digest."""
        for entry in self.certs:
            if entry.cert_digest == digest:
                return entry
        return None

    def get_entry(self, cert: rfc9480.CMPCertificate) -> Optional[CertDBEntry]:
        """Get a certificate entry by its certificate."""
        digest = compute_hash(self.hash_alg, encoder.encode(cert))
        return self.get_cert_by_digest(digest)

    def is_updated(self, cert: rfc9480.CMPCertificate, allow_timeout: bool) -> bool:
        """Check if the certificate is an update.

        :param cert: The certificate to check.
        :param allow_timeout: Whether to check the strictness of the update.
        :return: `True` if the certificate was updated, otherwise `False`.
        """
        time_now = datetime.now(timezone.utc).replace(microsecond=0)
        cert_entry = self.get_entry(cert)
        if cert_entry is None:
            return False

        if cert_entry.updated_date is None or cert_entry.cert_state == CertStateEnum.UPDATED:
            return True

        time_diff = (time_now - cert_entry.updated_date).total_seconds()
        if time_diff > self.timeout and not allow_timeout:
            return False
        return True

    def _for_cert_conf(self, entry: CertDBEntry, strict: bool = True) -> None:
        """Check if the entry is for a certificate confirmation.

        :param entry: The certificate entry to check.
        :param strict: Whether to check the strictness of the update timeout. Defaults to `True`.
        :raises CertConfirmed: If the certificate is already confirmed.
        :raises BadRequest: If the certificate timeout is exceeded and strict is `True`.
        """
        time_now = datetime.now(timezone.utc).replace(microsecond=0)
        time_diff = (time_now - entry.updated_date).total_seconds() if entry.updated_date else None

        if entry.cert_state == CertStateEnum.UPDATED:
            raise CertConfirmed("Certificate already updated and confirmed.")

        if time_diff is not None and time_diff > self.timeout and strict:
            raise BadRequest(
                "The certificate timeout is exceeded, cannot confirm the certificate."
                "Please start a new request to update the certificate."
            )

        if time_diff is not None and time_diff > self.timeout and not strict:
            logging.debug("The certificate timeout is exceeded, but the certificate can still be confirmed.")

    def _for_kur(self, entry: CertDBEntry) -> None:
        """Check if the entry is for a KUR (Key Update Request).

        :param entry: The certificate entry to check.
        :raises BadRequest: If the certificate is not confirmed or updated.
        """
        if entry.cert_state == CertStateEnum.UPDATED:
            raise CertRevoked("Certificate already updated and confirmed, cannot send a KUR.")

        time_now = datetime.now(timezone.utc).replace(microsecond=0)

        if entry.updated_date is None:
            raise TypeError("The certificate entry does not have an updated date, cannot verify the timeout.")

        time_diff = (time_now - entry.updated_date).total_seconds()
        if entry.cert_state == CertStateEnum.UPDATED_BUT_NOT_CONFIRMED:
            if time_diff < self.timeout:
                msg = (
                    "Either confirm the certificate or wait for the timeout to expire."
                    f"Timeout: {self.timeout} seconds. Time diff.: {int(time_diff)}"
                )
                raise BadRequest(
                    "The certificate is updated but not confirmed, cannot send a KUR. "
                    f"Please confirm the other request first. {msg}"
                )
        else:
            raise TypeError(
                f"Unexpected certificate state for KUR: {entry.cert_state}. "
                "Expected UPDATED_BUT_NOT_CONFIRMED or UPDATED."
            )

    def _for_rr(self, entry: CertDBEntry, allow_timeout: bool) -> None:
        """Check if the entry is for a RR (Revocation Request).

        :param entry: The certificate entry to check.
        :param allow_timeout: Whether to allow the certificate to be used after the timeout.
        :raises BadRequest: If the certificate is not confirmed or updated.
        """
        if entry.cert_state == CertStateEnum.UPDATED:
            raise CertRevoked("Certificate already updated and confirmed, cannot send a RR.")

        time_now = datetime.now(timezone.utc).replace(microsecond=0)

        if entry.updated_date is None:
            raise TypeError("The certificate entry does not have an updated date, cannot verify the timeout.")

        time_diff = (time_now - entry.updated_date).total_seconds()

        if entry.cert_state == CertStateEnum.UPDATED:
            raise CertRevoked("Certificate already updated and confirmed, cannot be revoked.")

        if time_diff < self.timeout and allow_timeout:
            logging.debug("The certificate is updated, but the timeout is not exceeded, so it can still be revoked.")
            return

        raise BadRequest(
            "The certificate is updated but not confirmed, cannot send a RR. Please confirm the other request first."
        )

    def validate_is_updated(
        self,
        body_name: str,
        cert: rfc9480.CMPCertificate,
        allow_timeout: bool = False,
    ) -> None:
        """Validate if a certificate is updated.

        :param body_name: The name of the body to check against.
        :param cert: The certificate to check.
        :param allow_timeout: Whether to allow the certificate to be used after the timeout,
        `True` no and `False` means yes. Defaults to `False`.
        :raises CertRevoked: If the certificate is updated.
        """
        cert_entry = self.get_entry(cert)
        if cert_entry is None:
            return

        cert_state = cert_entry.cert_state
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        if cert_state == CertStateEnum.UPDATED and body_name != "kur":
            raise CertRevoked(f"Certificate already updated. Serial number: {serial_number}")

        if body_name == "certConf":
            self._for_cert_conf(entry=cert_entry)
            return

        if body_name == "kur":
            self._for_kur(entry=cert_entry)
            return

        if body_name == "rr":
            self._for_rr(entry=cert_entry, allow_timeout=allow_timeout)
            return

        if body_name in ["ir", "cr", "p10cr"] and cert_state == CertStateEnum.UPDATED_BUT_NOT_CONFIRMED:
            raise BadRequest(
                "The certificate is updated but not confirmed, cannot request IR/CR/P10CR."
                "Please confirm the other request first.",
                failinfo="badRequest,certRevoked",
            )

        if self.is_updated(cert, allow_timeout=allow_timeout):
            raise CertRevoked(f"Certificate already updated. Serial number: {serial_number}")

    @classmethod
    def build_from_entries(
        cls,
        entries: List[CertDBEntry],
        hash_alg: Optional[str] = None,
        timeout: int = 10,
    ) -> "UpdateCertDB":
        """Build the update certificate database from entries.

        :param entries: The list of certificate database entries.
        :param hash_alg: The hash algorithm to use for hashing the certificates. Defaults to "sha1".
        :param timeout: The timeout for the update certificates in seconds. Defaults to 10 seconds.
        """
        hash_alg = hash_alg or "sha1"

        only_valid_entries = []
        for entry in entries:
            if entry.cert_state in [CertStateEnum.UPDATED, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED]:
                only_valid_entries.append(entry)

        return cls(certs=only_valid_entries, hash_alg=hash_alg, timeout=timeout)


@dataclass
class CertificateDB:
    """A certificate database.

    Attributes
    ----------
        - `certs`: The list of certificates.
        - `hash_alg`: The hash algorithm to use for hashing the certificates. Defaults to "sha1".
        - `save_date_time`: Whether to save the datetime, when the certificate was issued. Defaults to `False`.
        - `save_revoked_date_time`: Whether to save the datetime, when the certificate was revoked. Defaults to `False`.
        - `treat_update_as_revoked`: Whether to treat the update certificates as revoked. Defaults to `True`.
        - `updated_cert_timeout`: The timeout for the updated certificates in seconds. Defaults to 10 seconds.

    """

    _certs: List[CertDBEntry] = field(default_factory=list)
    save_date_time: bool = False
    save_revoked_date_time: bool = False
    treat_update_as_revoked: bool = True
    hash_alg: str = "sha1"
    updated_cert_timeout: int = 10  # seconds
    _crl_number: int = 1

    def get_details(self) -> dict:
        """Get the details of the certificate database."""
        return {
            "issued_certs": self.issued_certs,
            "revoked_certs": self.revoked_certs,
            "updated_certs": self.updated_certs,
            "crl_number": self._crl_number,
            "cert_db_hash_alg": self.hash_alg,
        }

    @property
    def update_state(self) -> UpdateCertDB:
        """Return the update state of the certificate database."""
        return UpdateCertDB.build_from_entries(
            entries=self._certs, hash_alg=self.hash_alg, timeout=self.updated_cert_timeout
        )

    @property
    def issued_certs(self) -> List[rfc9480.CMPCertificate]:
        """Return all issued certificates (revoked, update and so on)."""
        issued_certs = []
        for entry in self._certs:
            if entry.cert_state not in [
                CertStateEnum.NOT_CONFIRMED,
                CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
            ]:
                issued_certs.append(entry.cert)

        return issued_certs

    @property
    def not_confirmed_certs(self) -> List[rfc9480.CMPCertificate]:
        """Return all not confirmed certificates."""
        return self._get_certs_by_state(cert_state=CertStateEnum.NOT_CONFIRMED)

    def check_is_updated(self, cert: rfc9480.CMPCertificate, allow_timeout: bool = False) -> bool:
        """Check if the certificate is an update.

        :param cert: The certificate to check.
        :param allow_timeout: Whether to check the strictness of the update.
        :return: `True` if the certificate is an update, otherwise `False`.
        """
        update_obj = UpdateCertDB.build_from_entries(
            entries=self._certs, hash_alg=self.hash_alg, timeout=self.updated_cert_timeout
        )
        return update_obj.is_updated(cert=cert, allow_timeout=allow_timeout)

    def _get_certs_by_state(
        self,
        cert_state: CertStateEnum,
    ) -> List[rfc9480.CMPCertificate]:
        """Get the certificates by their state."""
        return [entry.cert for entry in self._certs if entry.cert_state == cert_state]

    @property
    def revoked_certs(self) -> List[rfc9480.CMPCertificate]:
        """Return the revoked certificates."""
        return self._get_certs_by_state(cert_state=CertStateEnum.REVOKED)

    @property
    def updated_certs(self) -> List[rfc9480.CMPCertificate]:
        """Return the updated certificates."""
        return self._get_certs_by_state(cert_state=CertStateEnum.UPDATED) + self._get_certs_by_state(
            cert_state=CertStateEnum.UPDATED_BUT_NOT_CONFIRMED
        )

    def add_cert(self, cert: rfc9480.CMPCertificate, cert_state: CertStateEnum) -> None:
        """Add a certificate to the database.

        :param cert: The certificate to add.
        :param cert_state: The state of the certificate (either NOT_CONFIRMED or CONFIRMED).
        :raises ValueError: If the certificate state is not valid.

        """
        if cert_state not in [CertStateEnum.NOT_CONFIRMED, CertStateEnum.CONFIRMED]:
            raise ValueError(
                "The certificate state must be either NOT_CONFIRMED or CONFIRMED."
                "To be added otherwise use the `change_cert_state` method."
            )

        tmp_cert = copy_asn1_certificate(cert)
        cert_digest = compute_hash(self.hash_alg, encoder.encode(tmp_cert))

        self._certs.append(
            CertDBEntry(
                cert=tmp_cert,
                cert_state=cert_state,
                cert_digest=cert_digest,
                issue_date=datetime.now(timezone.utc) if self.save_date_time else None,
            )
        )

    def _process_rev_cert(
        self,
        entry: CertDBEntry,
        cert_digest: bytes,
        revoke_entry: Optional[Union[RevokedEntry, dict]] = None,
    ) -> None:
        """Process the revoked certificate.

        :param cert_digest: The digest of the certificate.
        :param revoke_entry: The revoked entry to add to the certificate.
        """
        if revoke_entry is None:
            RevokedEntry(
                reason="unspecified",
                cert=entry.cert,
                hashed_cert=cert_digest,
                revoked_date=datetime.now(timezone.utc) if self.save_revoked_date_time else None,
            )
        elif isinstance(revoke_entry, dict):
            revoke_entry = RevokedEntry(**revoke_entry)
        entry.revoked_entry = revoke_entry

    def _process_update_cert(
        self,
        entry: CertDBEntry,
        cert_state: CertStateEnum,
        updated_cert: Optional[rfc9480.CMPCertificate] = None,
    ) -> None:
        """Process the updated certificate.

        :param entry: The certificate entry.
        :param cert_state: The new state of the certificate.
        :param updated_cert: The updated certificate (the new certificate).
        """
        logging.debug("State before:", entry.cert_state)
        if cert_state == CertStateEnum.UPDATED and entry.cert_state == CertStateEnum.UPDATED_BUT_NOT_CONFIRMED:
            if entry.update_cert_digest is None:
                if updated_cert is None:
                    raise ValueError("The updated certificate must be provided, if the state is UPDATED.")
                entry.update_cert_digest = compute_hash(self.hash_alg, encoder.encode(updated_cert))

        elif cert_state in [CertStateEnum.UPDATED, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED]:
            if not isinstance(updated_cert, rfc9480.CMPCertificate):
                raise TypeError(
                    f"The updated certificate must be of type `CMPCertificate`.Got: {type(updated_cert).__name__}"
                )
            entry.update_cert_digest = compute_hash(self.hash_alg, encoder.encode(updated_cert))
            entry.updated_date = datetime.now(timezone.utc).replace(microsecond=0)
        else:
            raise ValueError(
                f"The certificate state must be either UPDATED or UPDATED_BUT_NOT_CONFIRMED.Got: {cert_state}."
            )

        entry.cert_state = cert_state

    def change_cert_state(
        self,
        cert: rfc9480.CMPCertificate,
        new_state: CertStateEnum,
        revoke_entry: Optional[Union[RevokedEntry, dict]] = None,
        updated_cert: Optional[rfc9480.CMPCertificate] = None,
        error_suffix: Optional[str] = None,
    ) -> None:
        """Update the state of the certificate in the database.

        :param cert: The certificate to update.
        :param new_state: The new state of the certificate.
        :param revoke_entry: The revoked entry to add to the certificate. Defaults to `None`.
        :param updated_cert: The updated certificate (the new certificate). Defaults to `None`.
        :param error_suffix: The error suffix to add to the exception message. Defaults to `None`.
        :raises ValueError: If the certificate is not in the database or the state is not valid.
        :raises TypeError: If the updated certificate is not of type `CMPCertificate` or not provided.
        """
        if new_state not in [
            CertStateEnum.CONFIRMED,
            CertStateEnum.UPDATED,
            CertStateEnum.REVOKED,
            CertStateEnum.REVIVED,
            CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
        ]:
            raise ValueError(
                f"The certificate state must be either CONFIRMED, UPDATED, REVOKED or REVIVED. But got: {new_state}."
            )

        if not isinstance(cert, rfc9480.CMPCertificate):
            raise TypeError(f"The certificate must be of type `rfc9480.CMPCertificate`.Got: {type(cert).__name__}")

        cert_digest = compute_hash(self.hash_alg, encoder.encode(cert))
        logging.debug("Cert digest:", cert_digest.hex())
        logging.debug("Called with new state:", new_state)
        for entry in self._certs:
            if cert_digest == entry.cert_digest:
                if new_state == CertStateEnum.REVOKED:
                    if entry.cert_state not in [CertStateEnum.REVIVED, CertStateEnum.CONFIRMED]:
                        raise ValueError(
                            f"The certificate state must be either REVIVED or CONFIRMED, to change it to REVOKED."
                            f" Got: {entry.cert_state}. {error_suffix}"
                        )

                    self._process_rev_cert(entry, cert_digest, revoke_entry)
                    entry.cert_state = new_state

                elif new_state == CertStateEnum.REVIVED:
                    if entry.cert_state != CertStateEnum.REVOKED:
                        raise ValueError(
                            f"The certificate state must be REVOKED, to change it to REVIVED."
                            f" Got: {entry.cert_state}. {error_suffix}"
                        )
                    entry.cert_state = new_state
                    entry.revoked_entry = None
                elif new_state in [CertStateEnum.UPDATED, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED]:
                    self._process_update_cert(entry=entry, cert_state=new_state, updated_cert=updated_cert)
                elif new_state == CertStateEnum.CONFIRMED:
                    if entry.cert_state == CertStateEnum.NOT_CONFIRMED:
                        entry.cert_state = new_state
                    else:
                        raise ValueError(
                            f"The certificate state must be NOT_CONFIRMED, to change it to CONFIRMED."
                            f" Got: {new_state}. {error_suffix}"
                        )
                else:
                    raise ValueError(
                        f"The certificate state must be either REVIVED, REVOKED, UPDATED or UPDATED_BUT_NOT_CONFIRMED."
                        f"Got: {new_state}. {error_suffix}"
                    )

                return

        to_add = "" if error_suffix is None else f" {error_suffix}"
        raise ValueError(f"The certificate is not in the database.{to_add}")

    def get_cert_state(self, cert: rfc9480.CMPCertificate) -> CertStateEnum:
        """Get the state of the certificate in the database.

        :param cert: The certificate to get the state for.
        :return: The state of the certificate or `UNKNOWN` if not found.
        """
        cert_digest = compute_hash(self.hash_alg, encoder.encode(cert))
        for entry in self._certs:
            if cert_digest == entry.cert_digest:
                return entry.cert_state
        return CertStateEnum.UNKNOWN

    def get_cert(self, cert: rfc9480.CMPCertificate) -> Optional[CertDBEntry]:
        """Get the certificate from the database.

        :param cert: The certificate to get.
        :return: The certificate entry or `None` if not found.
        """
        cert_digest = compute_hash(self.hash_alg, encoder.encode(cert))
        return self._get_cert_by_digest(cert_digest)

    def _get_cert_by_digest(self, cert_digest: bytes) -> Optional[CertDBEntry]:
        """Get the certificate by its digest.

        :param cert_digest: The digest of the certificate.
        :return: The certificate entry or `None` if not found.
        """
        for entry in self._certs:
            if cert_digest == entry.cert_digest:
                return entry
        return None

    def get_updated_history(
        self,
        cert: rfc9480.CMPCertificate,
    ) -> Optional[List[rfc9480.CMPCertificate]]:
        """Get the update history of the certificate.

        :param cert: The certificate to get the update history for.
        :return: A list of updated certificates, or `None` if the certificate is not found.
        """
        entry = self.get_cert(cert)
        if entry is None:
            return None

        if entry.update_cert_digest is None:
            return None

        history = [entry.cert]
        for _ in range(10):  # Avoid infinite loops
            if entry.update_cert_digest is None:
                break
            next_entry = self._get_cert_by_digest(entry.update_cert_digest)
            if next_entry is None:
                break
            history.append(next_entry.cert)
            entry = next_entry
        return history

    def get_current_crl(
        self,
        ca_key: SignKey,
        ca_cert: rfc9480.CMPCertificate,
        hash_alg: Optional[str] = "sha256",
    ) -> CertificateRevocationList:
        """Get the current CRL for the database.

        :param ca_key: The private key to sign the CRL.
        :param ca_cert: The CRL signer certificate.
        :param hash_alg: The hash algorithm to use for signing. Defaults to `sha256`.
        :return: The current CRL DER-encoded.
        """
        rev_db = CertRevStateDB.build(
            hash_alg=self.hash_alg,
            revoked_certs=self.revoked_certs,
            updated_certs=self.updated_certs,
            crl_number=self._crl_number,
        )
        return rev_db.get_crl_response(
            sign_key=ca_key,
            ca_cert=ca_cert,
            hash_alg=hash_alg,
        )

    def get_ocsp_response(
        self,
        request: ocsp.OCSPRequest,
        sign_key: SignKey,
        ca_cert: rfc9480.CMPCertificate,
        responder_cert: Optional[rfc9480.CMPCertificate] = None,
        add_certs: Optional[List[rfc9480.CMPCertificate]] = None,
    ) -> ocsp.OCSPResponse:
        """Get the OCSP response for the database.

        :param request: The OCSP request.
        :param sign_key: The private key to sign the OCSP response.
        :param ca_cert: The CA certificate.
        :param responder_cert: The responder certificate. Defaults to `ca_cert`.
        :param add_certs: Additional certificates to include in the response. Defaults to `None`.
        :return: The OCSP response.
        """
        add_certs = add_certs or []

        rev_db = CertRevStateDB.build(
            hash_alg=self.hash_alg,
            revoked_certs=self.revoked_certs,
            updated_certs=self.updated_certs,
            crl_number=self._crl_number,
        )
        return rev_db.get_ocsp_response(
            request=request,
            sign_key=sign_key,
            ca_cert=ca_cert,
            issued_certs=self.issued_certs + add_certs,
            responder_cert=responder_cert,
        )


@dataclass
class MockCAState:
    """A simple class to store the state of the MockCAHandler.

    Attributes:
        currently_used_ids: The currently used IDs.
        kem_mac_based: The KEM-MAC-based shared secrets.
        to_be_confirmed_certs: The certificates to be confirmed.
        challenge_rand_int: The challenge random integers.
        sun_hybrid_state: The state of the Sun Hybrid handler.

    """

    cert_state_db: CertRevStateDB = field(default_factory=CertRevStateDB)
    currently_used_ids: Set[bytes] = field(default_factory=set)
    # stores the transaction id mapped to the shared secret.
    kem_mac_based: KEMSharedSecretList = field(default_factory=KEMSharedSecretList)
    # stores the (txid, sender_raw) mapped to the certificate.
    to_be_confirmed_certs: Dict[Tuple[bytes, bytes], List[rfc9480.CMPCertificate]] = field(default_factory=dict)
    challenge_rand_int: Dict[bytes, int] = field(default_factory=dict)
    sun_hybrid_state: SunHybridState = field(default_factory=SunHybridState)
    certificate_db: CertificateDB = field(default_factory=CertificateDB)

    @property
    def issued_certs(self) -> List[rfc9480.CMPCertificate]:
        """Get the issued certificates."""
        return self.certificate_db.issued_certs

    def contains_pub_key(self, pub_key: PublicKey, sender: rfc9480.Name) -> bool:
        """Check if the public key is already in use.

        :param pub_key: The public key to check.
        :param sender: The sender of the request.
        :return: `True` if the public key is already in use, otherwise `False`.
        """
        key_sec_check = KeySecurityChecker(
            issued_certs=self.certificate_db.issued_certs,
            # revoked_certs=self.certificate_db.revoked_certs,
            updated_certs=self.certificate_db.not_confirmed_certs,
        )

        return key_sec_check.contains_pub_key(
            pub_key=pub_key,
            sender=sender,
        )

    def add_tx_id(self, tx_id: bytes) -> None:
        """Store the transaction ID.

        :param tx_id: The transaction ID to store.
        """
        if tx_id in self.currently_used_ids:
            raise TransactionIdInUse(f"Transaction ID {tx_id.hex()} already exists.")
        self.currently_used_ids.add(tx_id)

    def remove_tx_id(self, tx_id: bytes) -> None:
        """Remove the transaction ID.

        :param tx_id: The transaction ID to remove.
        """
        self.currently_used_ids.remove(tx_id)

    @property
    def len_issued_certs(self) -> int:
        """Get the number of issued certificates."""
        return len(self.certificate_db.issued_certs)

    @property
    def len_to_be_confirmed_certs(self) -> int:
        """Get the number of certificates to be confirmed."""
        return len(self.to_be_confirmed_certs)

    def store_transaction_certificate(self, pki_message, certs: List[rfc9480.CMPCertificate]) -> None:
        """Store a transaction certificate.

        :param pki_message: The PKIMessage request.
        :param certs: A list of certificates to store.
        :raises TransactionIdInUse: If the transaction ID is already in use.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        sender = pki_message["header"]["sender"]

        if transaction_id in self.currently_used_ids:
            raise TransactionIdInUse(f"Transaction ID {transaction_id.hex()} already exists for sender {sender}")

        der_sender = encoder.encode(sender)
        self.to_be_confirmed_certs[(transaction_id, der_sender)] = certs
        self.currently_used_ids.add(transaction_id)

    def add_kem_mac_shared_secret(self, pki_message: PKIMessageTMP, shared_secret: bytes) -> None:
        """Add the shared secret for the KEM-MAC-based protection.

        :param pki_message: The PKIMessage request.
        :param shared_secret: The shared secret.
        """
        self.kem_mac_based.add_shared_secret(request=pki_message, ss=shared_secret)

    def get_kem_mac_shared_secret(self, pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Retrieve the shared secret for the KEM-MAC-based protection.

        :param pki_message: The PKI message containing the request.
        :return: The shared secret.
        """
        return self.kem_mac_based.get_shared_secret(request=pki_message)

    def get_issued_certs(self, pki_message: PKIMessageTMP) -> List[rfc9480.CMPCertificate]:
        """Retrieve the issued certificates.

        :param pki_message: The PKI message containing the request.
        :return: The issued certificates.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        der_sender = encoder.encode(pki_message["header"]["sender"])
        return self.to_be_confirmed_certs[(transaction_id, der_sender)]

    def get_cert_by_serial_number(self, serial_number: int) -> rfc9480.CMPCertificate:
        """Get the Sun-Hybrid certificate for the specified serial number.

        :param serial_number: The serial number of the certificate.
        :return: The certificate.
        :raises BadRequest: If the certificate could not be found.
        """
        for cert in self.certificate_db.issued_certs:
            if serial_number == int(cert["tbsCertificate"]["serialNumber"]):
                return cert

        raise BadCertId(f"Could not find certificate with serial number {serial_number}")

    def add_certs(self, certs: List[rfc9480.CMPCertificate], was_confirmed: bool = True) -> None:
        """Add the issued certificates to the state.

        :param certs: The certificates to add.
        :param was_confirmed: Whether the certificates were confirmed. Defaults to `True`.
        """
        cert_status = CertStateEnum.CONFIRMED if was_confirmed else CertStateEnum.NOT_CONFIRMED

        for x in certs:
            self.certificate_db.add_cert(
                cert=x,
                cert_state=cert_status,
            )

    def check_request_for_compromised_key(self, request_msg: PKIMessageTMP) -> bool:
        """Check the request for a compromised key."""
        return self.cert_state_db.check_request_for_compromised_key(request_msg)

    def add_may_update_cert(
        self, old_cert: rfc9480.CMPCertificate, update_cert: rfc9480.CMPCertificate, was_confirmed: bool
    ) -> None:
        """Add a certificate that may be updated in the future.

        :param old_cert: The certificate to add be updated in the future.
        :param update_cert: The certificate that may be updated.
        :param was_confirmed: Whether the certificate was confirmed.
        """
        if not isinstance(old_cert, rfc9480.CMPCertificate):
            raise TypeError("The old certificate must be of type `rfc9480.CMPCertificate`.")

        if not isinstance(update_cert, rfc9480.CMPCertificate):
            raise TypeError("The update certificate must be of type `rfc9480.CMPCertificate`.")

        cert_state = CertStateEnum.UPDATED_BUT_NOT_CONFIRMED
        if was_confirmed:
            cert_state = CertStateEnum.UPDATED

        self.certificate_db.change_cert_state(
            cert=old_cert,
            new_state=cert_state,
            updated_cert=update_cert,
            revoke_entry=None,
        )

    def contains_cert(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if the certificate is already in use."""
        tmp_cert = copy_asn1_certificate(cert)
        return self.certificate_db.get_cert(tmp_cert) is not None


# TODO Include this class to support Key Recovery requests in the future.


@dataclass
class IssuingReturnValue:
    """A class to store the return value of the issuing process.

    Which contains the issued certificates and other interesting information.

    Attributes
    ----------
        - `certs`: The list of issued certificates.
        - `dh_cert`: The EC-Diffie-Hellman certificate, if used.
        - `dh_key`: The EC-Diffie-Hellman key, if used.
        - `private_key`: The private key of the Client, if provided or generated.

    """

    certs: List[rfc9480.CMPCertificate]
    dh_cert: Optional[rfc9480.CMPCertificate] = None
    dh_key: Optional[ECDHPrivateKey] = None
    private_key: Optional[PrivateKey] = None


@dataclass
class PQStatefulSigKeyConfig:
    """A class to store the PQ Stateful Signature Key Configuration.

    Attributes
    ----------
        - `allow_stfl_ccr` (bool): Whether a pq stateful signature key is allowed to be used in a CCR.
        - `saved_bad_message_check_stfl_key` (bool): Whether the badPOP or badMessageCheck stateful key is also saved
    as a burned key.

    """

    allow_stfl_ccr: bool = True
    saved_bad_message_check_stfl_key: bool = True


@dataclass
class BaseURLData:
    """Data class to hold base URL information.

    Arguments:
    ---------
    - `bare_url`: The bare URL without port.
    - `port_num`: The port number.

    """

    bare_url: str
    port_num: int

    @property
    def base_url(self) -> str:
        """Return the base URL with port."""
        return f"{self.bare_url}:{self.port_num}"

    @property
    def ocsp_url(self) -> str:
        """Return the OCSP URL path."""
        return f"{self.base_url}/ocsp"

    @property
    def crl_url(self) -> str:
        """Return the CRL URL path."""
        return f"{self.base_url}/crl"

    def get_cert_url(self, serial_number: int):
        """Return the certificate URL path."""
        return f"{self.base_url}/cert/{serial_number}"

    def get_sig_url(self, serial_number: int):
        """Return the signature URL path."""
        return f"{self.base_url}/sig/{serial_number}"

    def get_pubkey_url(self, serial_number: int):
        """Return the public key URL path."""
        return f"{self.base_url}/pubkey/{serial_number}"
