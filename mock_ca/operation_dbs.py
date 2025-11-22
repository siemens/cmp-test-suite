# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Defines Dataclass for the Mock-CA."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyasn1_alt_modules import rfc9480

from pq_logic.keys.abstract_pq import PQSignaturePrivateKey
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey
from resources.asn1utils import encode_to_der
from resources.certutils import build_cert_chain_from_dir, parse_certificate
from resources.convertutils import ensure_is_sign_key, str_to_bytes
from resources.exceptions import BadConfig, BadRequest
from resources.keyutils import load_private_key_from_file
from resources.oid_mapping import compute_hash
from resources.typingutils import ECDHPrivateKey, PrivateKey, PublicKey, SignKey
from resources.utils import (
    is_certificate_and_key_set,
    load_and_decode_pem_file,
    load_certificate_chain,
    may_load_cert_and_key,
)


def _load_cert_and_key(
    data: dict, cert_field: str, key_field: str, key_pwd_field: Optional[str] = None
) -> Tuple[Optional[rfc9480.CMPCertificate], Optional[PrivateKey]]:
    """Load a certificate and key pair from the provided data.

    Args:
        data: The input dictionary.
        cert_field: The key in data for the certificate.
        key_field: The key in data for the private key.
        key_pwd_field: Optional key in data for the key password.

    Returns:
        A tuple of (certificate, key) if both are provided; otherwise, (None, None).

    Raises:
        ValueError: If only one of the two fields is provided.

    """
    if (cert_field in data) ^ (key_field in data):
        raise ValueError(f"Both {cert_field} and {key_field} must be provided together, or omitted.")
    if cert_field in data and key_field in data:
        cert = parse_certificate(load_and_decode_pem_file(data[cert_field]))

        if key_pwd_field in data:
            key = load_private_key_from_file(data[key_field], password=data[key_pwd_field])
        else:
            # If no password is provided, load the key with the default password.
            key = load_private_key_from_file(data[key_field])

        return cert, key
    return None, None


@dataclass
class IssuingCertAndKeys:
    """A simple class to store the certificates and keys for the Mock CA.

    Attributes:
        ca_cert: The CA certificate.
        ca_key: The CA key.
        cmp_prot_cert: The CMP protocol certificate.
        cmp_prot_key: The CMP protocol key.
        cmp_prot_key_alt: The CMP protocol alternative key.
        pre_shared_secret: The pre-shared secret.
        kga_cert_chain: The KGA certificate chain.
        kga_key: The KGA key.
        hybrid_kem_cert: The hybrid KEM certificate.
        hybrid_kem_key: The hybrid KEM key.

    """

    ca_cert: rfc9480.CMPCertificate
    ca_key: SignKey
    cmp_prot_cert: Optional[rfc9480.CMPCertificate] = None
    cmp_prot_key: Optional[SignKey] = None
    cmp_prot_key_alt: Optional[PQSignaturePrivateKey] = None
    pre_shared_secret: Optional[bytes] = None
    kga_cert_chain: Optional[List[rfc9480.CMPCertificate]] = None
    kga_key: Optional[SignKey] = None
    hybrid_kem_cert: Optional[rfc9480.CMPCertificate] = None
    hybrid_kem_key: Optional[HybridKEMPrivateKey] = None

    def __post_init__(self):
        """Post-initialization processing for the IssuingCertAndKeys class."""
        # If a KGA certificate chain is provided but its type is not a list,
        # assume it needs to be built from a directory.
        if self.kga_cert_chain is not None:
            if not isinstance(self.kga_cert_chain, list):
                self.kga_cert_chain = build_cert_chain_from_dir(
                    self.kga_cert_chain,  # type: ignore
                    cert_chain_dir="data/unittest",
                    root_dir="data/trustanchors",
                    must_be_complete=True,
                )
        if self.pre_shared_secret is not None:
            self.pre_shared_secret = str_to_bytes(self.pre_shared_secret)
        # If CMP protocol certificate/key are not provided, default them to CA values.
        if self.cmp_prot_cert is None and self.cmp_prot_key is None:
            self.cmp_prot_cert = self.ca_cert
            self.cmp_prot_key = self.ca_key

    def validate(self) -> None:
        """Validate the IssuingCertAndKeys object.

        :raises ValueError: If the validation fails.
        """
        result = is_certificate_and_key_set(self.ca_cert, self.ca_key)
        if not result:
            raise ValueError("The CA certificate and key are not a pair. Please check the configuration.")
        result = is_certificate_and_key_set(self.cmp_prot_cert, self.cmp_prot_key)
        if not result:
            raise ValueError("The CMP protocol certificate and key are not a pair. Please check the configuration.")
        kga_cert = self.kga_cert_chain[0] if self.kga_cert_chain else None
        result = is_certificate_and_key_set(kga_cert, self.kga_key)
        if not result:
            raise ValueError("The KGA certificate and key are not a pair. Please check the configuration.")

    @staticmethod
    def _load_cert_key_pair(
        data: dict, pair_name: str, cert_field: str, key_field: str, key_pwd_field: Optional[str] = None
    ):
        """Private helper to load a certificate-key pair.

        Args:
            data: The input dictionary.
            pair_name: A human-friendly name for the pair (e.g. "CMP protocol" or "hybrid KEM").
            cert_field: The key in data for the certificate.
            key_field: The key in data for the private key.
            key_pwd_field: Optional key in data for the key password.

        Returns:
            A tuple of (certificate, key) if both are provided; otherwise, (None, None).

        Raises:
            ValueError: If only one of the two fields is provided.

        """
        if (cert_field in data) ^ (key_field in data):
            raise ValueError(f"Both {pair_name} certificate and key must be provided together, or omitted.")
        if cert_field in data and key_field in data:
            return may_load_cert_and_key(
                cert_path=data[cert_field], key_path=data[key_field], key_password=data.get(key_pwd_field)
            )
        return None, None

    @staticmethod
    def _load_key(key_path: str, key_pwd: Optional[Union[str, bool]] = None) -> SignKey:
        """Load the private key from a file."""
        # MUST be false if the key password is not set,
        # so that the default value is used.
        if key_pwd == False:  # noqa: E712
            key = load_private_key_from_file(key_path)
        else:
            key = load_private_key_from_file(key_path, password=key_pwd)  # type: ignore
        key = ensure_is_sign_key(key)
        return key

    @staticmethod
    def _load_kga(
        kga_cert_chain: Optional[str],
        kga_cert: Optional[str],
        kga_key: Optional[str],
        kga_key_pwd: Optional[Union[str, bool]] = None,
    ) -> Tuple[List[rfc9480.CMPCertificate], Optional[SignKey]]:
        """Load the KGA certificate and key pair."""
        if kga_cert_chain is not None:
            kga_cert_chain = load_certificate_chain(kga_cert_chain)  # type: ignore
        if kga_key is not None:
            kga_key = IssuingCertAndKeys._load_key(kga_key, key_pwd=kga_key_pwd)  # type: ignore

        if kga_cert is None and kga_cert_chain is None:
            raise BadConfig("Either kga_cert or kga_cert_chain must be provided. Please check the configuration.")

        if kga_cert_chain is None:
            kga_cert_chain = [parse_certificate(load_and_decode_pem_file(kga_cert))]  # type: ignore

        return kga_cert_chain, kga_key  # type: ignore

    @staticmethod
    def load(data: dict) -> "IssuingCertAndKeys":
        """Load the IssuingCertAndKeys object from a dictionary.

        :param data: The dictionary containing the data to load.
        """
        if "ca_cert" not in data:
            raise ValueError("The CA certificate is missing.")
        if "ca_key" not in data:
            raise ValueError("The CA key is missing.")

        if "ca_key_pwd" not in data:
            ca_cert, ca_key = may_load_cert_and_key(
                cert_path=data["ca_cert"],
                key_path=data["ca_key"],
            )
        else:
            ca_cert, ca_key = may_load_cert_and_key(
                cert_path=data["ca_cert"],
                key_path=data["ca_key"],
                key_password=data["ca_key_pwd"],
            )
        # Load CMP protocol certificate and key pair.
        cmp_prot_cert, cmp_prot_key = IssuingCertAndKeys._load_cert_key_pair(
            data, "CMP protocol", "cmp_prot_cert", "cmp_prot_key", "cmp_prot_key_pwd"
        )
        # Load Hybrid KEM certificate and key pair.
        hybrid_kem_cert, hybrid_kem_key = IssuingCertAndKeys._load_cert_key_pair(
            data, "hybrid KEM", "hybrid_kem_cert", "hybrid_kem_key", "hybrid_kem_key_pwd"
        )

        # Load KGA certificate and key pair.
        kga_cert_chain, kga_key = IssuingCertAndKeys._load_kga(
            kga_cert_chain=data.get("kga_cert_chain"),
            kga_cert=data.get("kga_cert"),
            kga_key=data.get("kga_key"),
            kga_key_pwd=data.get("kga_key_pwd") if "kga_key_pwd" in data else False,
        )
        cmp_prot_key_alt = None
        if data.get("cmp_prot_key_alt"):
            cmp_prot_key_alt = IssuingCertAndKeys._load_key(
                data["cmp_prot_key_alt"],
                key_pwd=data.get("cmp_prot_key_alt_pwd") if "cmp_prot_key_alt_pwd" in data else False,
            )

        if hybrid_kem_key is not None:
            if not isinstance(hybrid_kem_key, HybridKEMPrivateKey):
                raise BadConfig("The hybrid KEM key is not a valid HybridKEM key. Please check the configuration.")

        if cmp_prot_key_alt is not None:
            if not isinstance(cmp_prot_key_alt, PQSignaturePrivateKey):
                raise BadConfig(
                    "The CMP protection alternative key is not a valid PQSignature key. Please check the configuration."
                )

        if cmp_prot_key is not None:
            if not isinstance(cmp_prot_key, SignKey):
                raise BadConfig("The CMP protection key is not a valid SignKey. Please check the configuration.")

        if not isinstance(ca_key, SignKey):
            raise BadConfig("The CA key is not a valid SignKey. Please check the configuration.")

        if not isinstance(ca_cert, rfc9480.CMPCertificate):
            raise BadConfig("The CA certificate is not a valid CMPCertificate. Please check the configuration.")

        return IssuingCertAndKeys(
            ca_cert=ca_cert,
            ca_key=ca_key,
            cmp_prot_cert=cmp_prot_cert,
            cmp_prot_key=cmp_prot_key,
            cmp_prot_key_alt=cmp_prot_key_alt,
            pre_shared_secret=data.get("pre_shared_secret", "SiemensIT"),  # type: ignore
            kga_cert_chain=kga_cert_chain,
            kga_key=kga_key,
            hybrid_kem_cert=hybrid_kem_cert,
            hybrid_kem_key=hybrid_kem_key,
        )


@dataclass
class NonSigningKeyCertsAndKeys:
    """A simple class to store the certificates and keys for the Mock CA.

    Attributes:
        x25519_cert: The CA X25519 certificate.
        x25519_key: The X25519 key.
        x448_cert: The X448 certificate.
        x448_key: The X448 key.
        ecc_cert: The ECC certificate.
        ecc_key: The ECC key.

    """

    x25519_cert: Optional[rfc9480.CMPCertificate] = None
    x25519_key: Optional[X25519PrivateKey] = None
    x448_cert: Optional[rfc9480.CMPCertificate] = None
    x448_key: Optional[X448PrivateKey] = None
    ecc_cert: Optional[rfc9480.CMPCertificate] = None
    ecc_key: Optional[EllipticCurvePrivateKey] = None

    @classmethod
    def load(cls, data: dict) -> "NonSigningKeyCertsAndKeys":
        """Load the non-signing key certificates and keys from a given configuration dictionary."""
        _x25519_cert, x25519_key = _load_cert_and_key(data, "x25519_cert", "x25519_key", key_pwd_field="x25519_key_pwd")
        _x448_cert, x448_key = _load_cert_and_key(data, "x448_cert", "x448_key", key_pwd_field="x448_key_pwd")
        _ecc_cert, ecc_key = _load_cert_and_key(data, "ecc_cert", "ecc_key", key_pwd_field="ecc_key_pwd")

        obj = cls(
            x25519_cert=_x25519_cert,  # type: ignore
            x25519_key=x25519_key,  # type: ignore
            x448_cert=_x448_cert,  # type: ignore
            x448_key=x448_key,  # type: ignore
            ecc_cert=_ecc_cert,  # type: ignore
            ecc_key=ecc_key,  # type: ignore
        )
        obj.validate()
        return obj

    def to_dict(self) -> dict:
        """Convert the NonSigningKeyCertsAndKeys object to a dictionary.

        :return: A dictionary representation of the object.
        """
        return {
            "x25519_cert": self.x25519_cert,
            "x25519_key": self.x25519_key,
            "x448_cert": self.x448_cert,
            "x448_key": self.x448_key,
            "ecc_cert": self.ecc_cert,
            "ecc_key": self.ecc_key,
        }

    def validate(self) -> None:
        """Validate the NonSigningKeyCertsAndKeys object.

        :raises ValueError: If the validation fails.
        """
        is_certificate_and_key_set(self.x25519_cert, self.x25519_key)
        if self.x25519_key is not None:
            if not isinstance(self.x25519_key, X25519PrivateKey):
                raise ValueError("The x25519 key is not a valid X25519 key. Please check the configuration.")

        is_certificate_and_key_set(self.x448_cert, self.x448_key)
        if self.x448_key is not None:
            if not isinstance(self.x448_key, X448PrivateKey):
                raise ValueError("The x448 key is not a valid X448 key. Please check the configuration.")
        is_certificate_and_key_set(self.ecc_cert, self.ecc_key)
        if self.ecc_key is not None:
            if not isinstance(self.ecc_key, EllipticCurvePrivateKey):
                raise ValueError("The ecc key is not a valid ECC key. Please check the configuration.")


@dataclass(frozen=True)
class MockCAOPCertsAndKeys:
    """A simple class to store the certificates and keys for the Mock CA.

    Attributes:
        ca_cert: The CA certificate.
        ca_key: The CA key.
        ca_alt_key: The CA alternative key.
        hybrid_kem_cert: The hybrid KEM certificate.
        hybrid_kem_key: The hybrid KEM key.
        kem_cert: The KEM certificate.
        kem_key: The KEM key.
        x25519_cert: The X25519 certificate.
        x25519_key: The X25519 key.
        x448_cert: The X448 certificate.
        x448_key: The X448 key.
        ecc_cert: The ECC certificate.
        ecc_key: The ECC key.
        encr_rsa_cert: The encryption RSA certificate.
        encr_rsa_key: The encryption RSA key.

    """

    ca_cert: rfc9480.CMPCertificate
    ca_key: SignKey
    ca_alt_key: Optional[PQSignaturePrivateKey] = None
    hybrid_kem_cert: Optional[rfc9480.CMPCertificate] = None
    hybrid_kem_key: Optional[HybridKEMPrivateKey] = None
    kem_cert: Optional[rfc9480.CMPCertificate] = None
    kem_key: Optional[HybridKEMPrivateKey] = None
    x25519_cert: Optional[rfc9480.CMPCertificate] = None
    x25519_key: Optional[X25519PrivateKey] = None
    x448_cert: Optional[rfc9480.CMPCertificate] = None
    x448_key: Optional[X448PrivateKey] = None
    ecc_cert: Optional[rfc9480.CMPCertificate] = None
    ecc_key: Optional[EllipticCurvePrivateKey] = None
    encr_rsa_cert: Optional[rfc9480.CMPCertificate] = None
    encr_rsa_key: Optional[RSAPrivateKey] = None

    @staticmethod
    def load(**config) -> "MockCAOPCertsAndKeys":
        """Load the supported certificates and keys from a given configuration dictionary."""
        ca_cert = config.get("ca_cert")
        ca_key = config.get("ca_key")
        if ca_cert is None or ca_key is None:
            raise ValueError("The CA certificate and key are missing. Please check the configuration.")

        ca_key = ensure_is_sign_key(ca_key)

        if not isinstance(ca_cert, rfc9480.CMPCertificate):
            raise ValueError("The CA certificate is not a valid CMPCertificate. Please check the configuration.")

        return MockCAOPCertsAndKeys(
            ca_cert=ca_cert,
            ca_key=ca_key,
            ca_alt_key=config.get("ca_alt_key"),
            hybrid_kem_cert=config.get("hybrid_cert"),
            hybrid_kem_key=config.get("hybrid_kem"),
            x25519_cert=config.get("ca_x25519_cert"),
            x25519_key=config.get("ca_x25519_key"),
            x448_cert=config.get("ca_x448_cert"),
            x448_key=config.get("ca_x448_key"),
            ecc_cert=config.get("ca_ecc_cert"),
            ecc_key=config.get("ca_ecc_key"),
        )

    def get_ecc_cert(self, key: Optional[ECDHPrivateKey]) -> Optional[rfc9480.CMPCertificate]:
        """Retrieve the ECC certificate for the specified key."""
        # Can be used for the challenge method to issue an ECC key.
        # Or for the experimental ECC keyAgreement revocation.
        if key is None:
            return None

        if isinstance(key, X448PrivateKey):
            cert = self.x448_cert
        elif isinstance(key, X25519PrivateKey):
            cert = self.x25519_cert
        else:
            cert = self.ecc_cert

        if cert is None:
            raise ValueError(
                f"Could not find certificate for the specified key.: {type(key)}Please update the `config.json` file."
            )

        return cert


@dataclass
class SunHybridState:
    """A simple class to store the state of the SunHybridHandler."""

    sun_hybrid_certs: Dict[int, rfc9480.CMPCertificate] = field(default_factory=dict)
    sun_hybrid_pub_keys: Dict[int, PublicKey] = field(default_factory=dict)
    sun_hybrid_signatures: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class StatefulSigKeyState:
    """A simple class to store the state of the StatefulSigHandler."""

    used_indices: List[int] = field(default_factory=list)

    def add_used_index(self, index: int) -> None:
        """Add a used index to the state."""
        self.used_indices.append(index)

    def contains_used_index(self, index: int) -> bool:
        """Check if a used index exists in the state."""
        # logging.debug(f"Checking if index {index} is in used indices: {self.used_indices}")
        return index in self.used_indices


@dataclass
class StatefulSigState:
    """A simple class to store the state of the StatefulSigHandler."""

    used_indices: Dict[bytes, StatefulSigKeyState] = field(default_factory=dict)
    hash_alg: str = "sha256"

    def add_state(self, cert: rfc9480.CMPCertificate, state: Optional[StatefulSigKeyState] = None) -> None:
        """Add a state for a given certificate."""
        der_data = encode_to_der(cert)
        hashed_cert = compute_hash(self.hash_alg, der_data)
        if hashed_cert in self.used_indices:
            raise BadRequest("State for this certificate already exists.")
        self.used_indices[hashed_cert] = state or StatefulSigKeyState(used_indices=[0])

    def get_state(self, cert: rfc9480.CMPCertificate) -> Optional[StatefulSigKeyState]:
        """Get the state for a given certificate."""
        der_data = encode_to_der(cert)
        hashed_cert = compute_hash(self.hash_alg, der_data)
        if hashed_cert not in self.used_indices:
            return None
        return self.used_indices[hashed_cert]

    def add_used_index(self, cert: rfc9480.CMPCertificate, index: int) -> None:
        """Add a used index for a given certificate."""
        state = self.get_state(cert)
        if state is None:
            raise BadRequest(
                "StatefulSigKeyState not found for the given certificate."
                "Is only supported for MockCA issued certificates."
            )
        state.used_indices.append(index)

    def contains_used_index(self, cert: rfc9480.CMPCertificate, index: int) -> bool:
        """Check if a used index exists for a given certificate.

        :param cert: The certificate to check.
        :param index: The index to check.
        :return: True if the index is used, False otherwise.
        :raises BadRequest: If the state for the certificate is not found.
        """
        state = self.get_state(cert)
        if state is None:
            raise BadRequest(
                "StatefulSigKeyState not found for the given certificate."
                "Is only supported for MockCA issued certificates."
            )
        return index in state.used_indices


# TODO include this class to support PQ Stateful Signature keys in the future.
# also include it for the CEK, which might
# uses the EncryptedKey, to proof the possession of the Private Key.


@dataclass
class BadRandomState:
    """A class to store the states related to the randomness used by the Client.

    Attributes
    ----------
        - `bad_hss_random`: The bad random number generator.
        - `bad_random_count`: The number of times the bad random number generator was used.

    """

    bad_hss_random: Optional[bytes] = None
    bad_random_count: int = 0
