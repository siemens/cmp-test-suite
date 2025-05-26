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

from pq_logic.keys.abstract_wrapper_keys import HybridPublicKey, KEMPublicKey
from resources import ca_ra_utils, certutils, keyutils
from resources.asn1_structures import PKIMessageTMP
from resources.certutils import load_public_key_from_cert
from resources.cmputils import get_cmp_message_type
from resources.compareutils import compare_pyasn1_names
from resources.convertutils import ensure_is_trad_sign_key
from resources.copyasn1utils import copy_subject_public_key_info
from resources.deprecatedutils import _sign_crl_builder
from resources.exceptions import BadMessageCheck
from resources.oid_mapping import compute_hash
from resources.oidutils import id_KemBasedMac
from resources.protectionutils import verify_kem_based_mac_protection
from resources.typingutils import PublicKey, SignKey
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
    ) -> "CertRevStateDB":
        """Build the certificate revocation state database."""
        hash_alg = hash_alg or "sha1"
        rev_list = RevokedEntryList.build(hash_alg=hash_alg, entries=revoked_certs or [])  # type: ignore
        update_list = RevokedEntryList.build(hash_alg=hash_alg, entries=updated_certs or [])  # type: ignore
        return cls(
            rev_entry_list=rev_list,
            update_entry_list=update_list,
            _update_eq_rev=True,
            _crl_number=1,
            hash_alg=hash_alg,
        )

    @property
    def revoked_certs(self) -> List[rfc9480.CMPCertificate]:
        """Return the revoked certificates."""
        return self.rev_entry_list.certs or []

    @property
    def updated_certs(self) -> List[rfc9480.CMPCertificate]:
        """Return the updated certificates."""
        return self.update_entry_list.certs or []

    @property
    def len_revoked_certs(self) -> int:
        """Return the number of revoked certificates."""
        return len(self.rev_entry_list)

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

    def add_update_entry(self, entry: Union[RevokedEntry, dict, List[dict]]) -> None:
        """Add an updated entry to the list."""
        self.update_entry_list.add_entry(entry)

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

    def is_revoked(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if the certificate is revoked.

        :param cert: The certificate to check.
        :return: Whether the certificate is revoked.
        """
        hashed_cert = compute_hash(self.hash_alg, encoder.encode(cert))
        return self.is_revoked_by_hash(hashed_cert) or self.is_updated_by_hash(hashed_cert)

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
        for cert in all_certs:
            if self._compare_pub_keys(pub_key, cert):
                return compare_pyasn1_names(sender, cert["tbsCertificate"]["subject"], "without_tag")
        return False

    def _check_contains_pub_key(
        self,
        certs: List[rfc9480.CMPCertificate],
        pub_key: PublicKey,
        sender: rfc9480.Name,
    ) -> bool:
        """Check if the public key is already in use."""
        for cert in certs:
            if self._compare_pub_keys(pub_key, cert):
                return compare_pyasn1_names(sender, cert["tbsCertificate"]["subject"], "without_tag")
        return False

    def check_cert_status(
        self,
        pub_key: PublicKey,
        sender: rfc9480.Name,
    ) -> str:
        """Check the status of the certificate.

        :return: The status of the certificate ("good", "revoked", "updated", "in_use").
        """
        if self._check_contains_pub_key(certs=self.issued_certs, pub_key=pub_key, sender=sender):
            return "in_use"

        if self._check_contains_pub_key(certs=self.revoked_certs, pub_key=pub_key, sender=sender):
            return "revoked"

        if self._check_contains_pub_key(certs=self.updated_certs, pub_key=pub_key, sender=sender):
            return "updated"

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


