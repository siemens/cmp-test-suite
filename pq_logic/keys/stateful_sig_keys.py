# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""All stateful hash signature keys.

Currently supported:
- XMSS (eXtended Merkle Signature Scheme)
- XMSSMT (eXtended Merkle Signature Scheme with Multiple Trees)
- HSS (Hierarchical Signature Scheme)

"""

import importlib.util
import logging
import math
import struct
from multiprocessing import Pool
from typing import List, Optional, Tuple

import hsslms
from cryptography.exceptions import InvalidSignature
from hsslms import HSS_Priv, HSS_Pub, LMS_Priv
from hsslms.utils import LMOTS_ALGORITHM_TYPE, u32str
from pyasn1.codec.der import encoder
from pyasn1.type import namedtype, tag, univ
from test_lms_hss_seed_der import extract_hss_leaf_index, generate_hss_priv_key_by_name

from resources.exceptions import InvalidKeyData

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name

from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey

XMSS_ALG_DETAILS = {
    "xmss-sha2_10_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 10},
    "xmss-sha2_16_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 16},
    "xmss-sha2_20_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 20},
    "xmss-sha2_10_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 10},
    "xmss-sha2_16_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 16},
    "xmss-sha2_20_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 20},
    "xmss-shake_10_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 10},
    "xmss-shake_16_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 16},
    "xmss-shake_20_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 20},
    "xmss-shake_10_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 10},
    "xmss-shake_16_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 16},
    "xmss-shake_20_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 20},
}

XMSSMT_ALG_DETAILS = {
    # XMSS^MT parameter sets (lower-case keys)
    "xmssmt-sha2_20/2_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 20, "d": 2},
    "xmssmt-sha2_20/4_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 20, "d": 4},
    "xmssmt-sha2_40/2_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 40, "d": 2},
    "xmssmt-sha2_40/4_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 40, "d": 4},
    "xmssmt-sha2_40/8_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 40, "d": 8},
    "xmssmt-sha2_60/3_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 60, "d": 3},
    "xmssmt-sha2_60/6_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 60, "d": 6},
    "xmssmt-sha2_60/12_256": {"hash_alg": "sha-256", "n": 32, "w": 16, "len": 67, "h": 60, "d": 12},
    "xmssmt-sha2_20/2_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 20, "d": 2},
    "xmssmt-sha2_20/4_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 20, "d": 4},
    "xmssmt-sha2_40/2_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 40, "d": 2},
    "xmssmt-sha2_40/4_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 40, "d": 4},
    "xmssmt-sha2_40/8_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 40, "d": 8},
    "xmssmt-sha2_60/3_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 60, "d": 3},
    "xmssmt-sha2_60/6_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 60, "d": 6},
    "xmssmt-sha2_60/12_512": {"hash_alg": "sha-512", "n": 64, "w": 16, "len": 131, "h": 60, "d": 12},
    "xmssmt-shake_20/2_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 20, "d": 2},
    "xmssmt-shake_20/4_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 20, "d": 4},
    "xmssmt-shake_40/2_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 40, "d": 2},
    "xmssmt-shake_40/4_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 40, "d": 4},
    "xmssmt-shake_40/8_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 40, "d": 8},
    "xmssmt-shake_60/3_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 60, "d": 3},
    "xmssmt-shake_60/6_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 60, "d": 6},
    "xmssmt-shake_60/12_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 60, "d": 12},
    "xmssmt-shake_20/2_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 20, "d": 2},
    "xmssmt-shake_20/4_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 20, "d": 4},
    "xmssmt-shake_40/2_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 40, "d": 2},
    "xmssmt-shake_40/4_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 40, "d": 4},
    "xmssmt-shake_40/8_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 40, "d": 8},
    "xmssmt-shake_60/3_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 60, "d": 3},
    "xmssmt-shake_60/6_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 60, "d": 6},
    "xmssmt-shake_60/12_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 60, "d": 12},
}

lmots_algorithm_type_dict = {
    "LMOTS_SHA256_N32_W1": 1,
    "LMOTS_SHA256_N32_W2": 2,
    "LMOTS_SHA256_N32_W4": 3,
    "LMOTS_SHA256_N32_W8": 4,
    "LMOTS_SHA256_N24_W1": 5,
    "LMOTS_SHA256_N24_W2": 6,
    "LMOTS_SHA256_N24_W4": 7,
    "LMOTS_SHA256_N24_W8": 8,
}

lms_algorithm_type_dict = {
    "LMS_SHA256_M32_H5": 5,
    "LMS_SHA256_M32_H10": 6,
    "LMS_SHA256_M32_H15": 7,
    "LMS_SHA256_M32_H20": 8,
    "LMS_SHA256_M32_H25": 9,
    "LMS_SHA256_M24_H5": 10,
    "LMS_SHA256_M24_H10": 11,
    "LMS_SHA256_M24_H15": 12,
    "LMS_SHA256_M24_H20": 13,
    "LMS_SHA256_M24_H25": 14,
}
lms_id_2_algorithm_type_dict = {y: x for x, y in lms_algorithm_type_dict.items()}
lmots_id_2_algorithm_type_dict = {y: x for x, y in lmots_algorithm_type_dict.items()}


def _xmss_liboqs_sk_to_pk(sk: bytes, name: str = "XMSS-SHA2_10_256") -> bytes:
    """Extract root||PUB_SEED from a liboqs-exported XMSS or XMSS-MT secret key.

    XMSS Format is: ID(4) || index(4) || SK_SEED(n) || SK_PRF(n) || PUB_SEED(n) || root(n)

    :param sk: secret key bytes from liboqs
    :param name: name of the XMSS or XMSS-MT algorithm, e.g. "XMSS-SHA2_20/2_256" or "XMSSMT-SHA2_20/2_256"
    :return: public key bytes in the format OID(4) || PUB_SEED(n) || root(n)
    """
    hdr = 8  # 4-byte OID + 4-byte index
    oid = sk[0:4]  # OID, unused here

    if not name.upper().startswith("XMSS-") and not name.upper().startswith("XMSSMT-"):
        raise ValueError(f"Variant must start with 'XMSS-' or 'XMSSMT-'. Got: {name}")

    num = name.split("_")[-1]  # e.g. "XMSSMT-SHA2_20/2_256" -> 32
    n = int(num) // 8

    if name.upper().startswith("XMSSMT"):
        root_off, pub_seed_off = hdr + 2 * n, hdr + 3 * n
    else:
        start = 8 + 2 * n
        return oid + sk[start : start + n] + sk[start + n : start + 2 * n]

    h = XMSSMT_ALG_DETAILS[name.lower()]["h"]
    offset2 = math.ceil(h / 8) - 4
    root_off += offset2
    pub_seed_off += offset2
    # for XMSSMT, the public key is constructed as:
    # OID(4) || root(n) || PUB_SEED(n)
    # For "60/6" "60/3" "60/12" plus 4.
    # For "20/2" "20/4" minus 1.
    # For "40/2" "40/4" "40/8" plus 1.
    return oid + sk[root_off : root_off + n] + sk[pub_seed_off : pub_seed_off + n]


class XMSSPublicKey(PQHashStatefulSigPublicKey):
    """Class representing an XMSS public key."""

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSS private key."""
        return b"XMSS"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmss":
            name = "xmss-sha2_20_256"
        if name.upper() not in XMSS_ALG_IDS.values():
            raise ValueError(f"Unsupported XMSS algorithm: {name}")
        return name, name.upper()

    def _initialize_key(self):
        """Initialize the XMSS public key with the provided name and public key bytes."""
        if len(self._public_key_bytes) != self.key_size:
            msg = (
                f"Invalid public key size for {self.name}: expected {self.key_size + 4}, "
                f"got {len(self._public_key_bytes)}"
            )
            raise InvalidKeyData(msg)
        self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore

    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the XMSS signature."""
        # First 4 bytes of XMSS signature is the leaf index
        if len(signature) != self.sig_size:
            raise ValueError(f"Invalid XMSS signature size: expected {self.sig_size}, got {len(signature)}")

        if len(signature) < 4:
            raise ValueError("Invalid XMSS signature: too short")
        return struct.unpack(">I", signature[:4])[0]

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    @classmethod
    def from_public_bytes(cls, data: bytes):
        """Set the public key bytes from the provided bytes."""
        name = data[:4]
        alg_id = int.from_bytes(name, "big")
        if alg_id not in XMSS_ALG_IDS:
            raise InvalidKeyData(f"Unsupported XMSS algorithm ID: {alg_id}")
        return cls(XMSS_ALG_IDS[alg_id].upper(), data)

    def verify(self, data: bytes, signature: bytes) -> None:
        """Verify the signature against the data using the public key.

        :param data: The data to verify the signature against.
        :param signature: The signature to verify.
        """
        if len(signature) != self.sig_size:
            raise InvalidSignature(f"Signature size mismatch: expected {self.sig_size}, got {len(signature)}")

        if not self._sig.verify(message=data, signature=signature, public_key=self._public_key_bytes):
            raise InvalidSignature("XMSS Signature verification failed")

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSS public key."""
        h = int(self.name.split("_")[1])
        return 2**h - 1

    @property
    def key_size(self) -> int:
        """Return the size of the public key for this XMSS public key."""
        # public_key_size = n (seed) + n (root) = 2 ⋅ n
        # details = XMSS_ALG_DETAILS[self.name.lower()]
        # n = details["n"]
        hash_num = self.name.split("_")[-1]  # Extract the hash algorithm and parameters
        n = int(hash_num) // 8
        return 2 * n + 4  # 4 bytes for the algorithm identifier

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this XMSSMT public key."""
        # 4+n+(l+h)n
        # Where:
        # 4: Algorithm identifier size
        # n: Hash output size
        # h: Height of the tree
        # l: Winternitz parameter
        details = XMSS_ALG_DETAILS[self.name.lower()]
        n = details["n"]  # Hash output size
        height = details["h"]  # Height of the tree
        length = details["len"]  # Winternitz parameter
        return 4 + n + (length + height) * n


class XMSSPrivateKey(PQHashStatefulSigPrivateKey):
    """Class representing an XMSS private key."""

    _sig: Optional["oqs.StatefulSignature"]

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSS private key."""
        return b"XMSS"

    def public_key(self) -> XMSSPublicKey:
        """Return the corresponding public key for this XMSS private key."""
        if self._public_key_bytes is None:
            self._public_key_bytes = _xmss_liboqs_sk_to_pk(self._sig.export_secret_key(), self._other_name)
        return XMSSPublicKey(self._name, public_key=self._public_key_bytes)

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmss":
            name = "xmss-sha2_10_256"
        if name.upper() not in XMSS_ALG_IDS.values():
            msg = f"Unsupported XMSS algorithm: {name}"
            raise ValueError(msg)

        return name, name.upper()

    def _initialize_key(self):
        """Initialize the XMSS private key with the provided name and private key bytes."""
        if self._private_key_bytes is not None:
            self._sig = oqs.StatefulSignature(self._other_name, secret_key=self._private_key_bytes)  # type: ignore
            if len(self._private_key_bytes) != self.key_size:
                msg = (
                    f"Invalid private key size for {self.name}: expected {self.key_size}, "
                    f"got {len(self._private_key_bytes)}"
                )
                raise InvalidKeyData(msg)
        else:
            self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore
            self._public_key_bytes = self._sig.generate_keypair()
            self._private_key_bytes = self._sig.export_secret_key()

    def private_numbers(self) -> bytes:
        """Return the private key as bytes.

        Returns the seed used to derive the private key:
        - 4 bytes for the algorithm identifier
        - 4 bytes for the current leaf counter.
        - 3 * n bytes for the seed, where n is the hash output size.
        - n for the root hash.

        :return: The private key seed bytes.
        """
        n = XMSS_ALG_DETAILS[self.name.lower()]["n"]
        return self._sig.export_secret_key()[: 4 + 4 * n]

    @classmethod
    def from_private_bytes(cls, data: bytes):
        """Set the private key bytes from the provided bytes."""
        alg_id = int.from_bytes(data[:4], "big")
        # Only support XMSS used by OQS, the seed derivation is not implemented.
        # Starts with:
        # 4 bytes for the algorithm identifier
        # 4 bytes for the current leaf counter.
        # n-bytes (hash output size) for the seed.
        # SK_SEED(n) || SK_PRF(n) || PUB_SEED(n) || root(n)
        # The total length is 4 + 4 + 3 * n, where n is the hash output size.
        # Afterwards follows the BDS traversal cache,
        # otherwise would the size be a lot bigger.
        name = XMSS_ALG_IDS.get(alg_id)
        n = int(name.split("_")[-1]) // 8 if name else None
        if name is None:
            raise InvalidKeyData(f"Unsupported XMSS algorithm ID: {alg_id}")
        if len(data) < 4 + 3 * n:
            raise InvalidKeyData(f"Invalid private key size for {name}: expected at least {4 + 3 * n}, got {len(data)}")
        if len(data) == 4 + 3 * n:
            raise NotImplementedError("Derivation of the private from a seed is not implemented yet.")
        return cls(XMSS_ALG_IDS[alg_id], data)

    def sign(self, data: bytes) -> bytes:
        """Sign the data using the private key.

        :param data: The data to sign.
        :return: The signature of the data.
        """
        return self._sig.sign(data)

    @property
    def used_keys(self) -> list[bytes]:
        """Return the list of used keys during signing."""
        return self._sig.export_used_keys()

    def _export_private_key(self) -> bytes:
        """Return the private key as bytes."""
        return self._sig.export_secret_key()

    def private_bytes_raw(self) -> bytes:
        """Return the raw private key bytes."""
        return self._export_private_key()

    @property
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining for this XMSS private key."""
        return self._sig.sigs_remaining()

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSS private key."""
        return self._sig.sigs_total()

    @property
    def key_size(self) -> int:
        """Return the size of the private key for this XMSS private key."""
        return self._sig.details["length_secret_key"]


class XMSSMTPublicKey(PQHashStatefulSigPublicKey):
    """Class representing an XMSSMT public key."""

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSSMT public key."""
        return b"XMSSMT"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmssmt":
            name = "xmssmt-sha2_20/2_256"
        if name.upper() not in XMSSMT_ALG_IDS.values():
            raise ValueError(f"Unsupported XMSS^MT algorithm: {name}")
        return name, name.upper()

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    def _initialize_key(self):
        """Initialize the XMSS public key with the provided name and public key bytes."""
        self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore
        if len(self._public_key_bytes) != self.key_size:
            msg = (
                f"Invalid public key size for {self.name}: expected {self.key_size + 4}, "
                f"got {len(self._public_key_bytes)}"
            )
            raise ValueError(msg)

    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the XMSSMT signature.

        :param signature: The XMSSMT signature to extract the leaf index from.
        :return: The leaf index extracted from the signature.
        """
        if len(signature) < 4:
            raise ValueError("Invalid XMSSMT signature: too short")

        # According to RFC 8391 Section 4.2.3.  XMSS^MT Signature.
        h = XMSSMT_ALG_DETAILS[self._name.lower()]["h"]
        length = math.ceil(h / 8)
        # The leaf index is stored as a big-endian integer
        return int.from_bytes(signature[:length], "big")  # Ensure it's a valid integer

    @classmethod
    def from_public_bytes(cls, data: bytes):
        """Set the public key bytes from the provided bytes."""
        alg_id = int.from_bytes(data[:4], "big")
        _name = XMSSMT_ALG_IDS[alg_id]
        key_size = XMSSMT_ALG_DETAILS[_name.lower()]["n"] * 2
        if len(data) != key_size + 4:
            raise InvalidKeyData(f"Invalid public key size for {_name}: expected {key_size + 4}, got {len(data)}")
        if alg_id not in XMSSMT_ALG_IDS:
            raise InvalidKeyData(f"Unsupported XMSSMT algorithm ID: {alg_id}")
        return cls(XMSSMT_ALG_IDS[alg_id], data)

    def verify(self, data: bytes, signature: bytes) -> None:
        """Verify the signature against the data using the public key.

        :param data: The data to verify the signature against.
        :param signature: The signature to verify.
        """
        if len(signature) != self.sig_size:
            raise InvalidSignature(f"Signature size mismatch: expected {self.sig_size}, got {len(signature)}")

        if not self._sig.verify(message=data, signature=signature, public_key=self._public_key_bytes):
            raise InvalidSignature("XMSS^MT Signature verification failed")

    def get_used_keys(self) -> list[bytes]:
        """Return the list of used keys during signing."""
        return self._sig.export_used_keys()

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSSMT public key."""
        h = XMSSMT_ALG_DETAILS[self.name.lower()]["h"]
        return 2**h - 1

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this XMSSMT public key."""
        # Where:
        # 4: Algorithm identifier size
        # n: Hash output size
        # h: Height of the tree
        # l: Winternitz parameter
        # d: Number of trees in the forest.
        details = XMSSMT_ALG_DETAILS[self.name.lower()]
        n = details["n"]
        height = details["h"]
        length = details["len"]
        d = details["d"]
        return math.ceil(height / 8) + n + (height + d * length) * n

    @property
    def key_size(self) -> int:
        """Return the size of the public key for this XMSSMT public key."""
        return self._sig.details["length_public_key"]


class XMSSMTPrivateKey(PQHashStatefulSigPrivateKey):
    """Class representing an XMSSMT private key."""

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSSMT private key."""
        return b"XMSSMT"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmssmt":
            name = "xmssmt-sha2_20/2_256"
        if name not in XMSSMT_ALG_DETAILS:
            raise ValueError(f"Unsupported XMSS^MT algorithm: {name}")
        return name.lower(), name.upper()

    def _initialize_key(self):
        """Initialize the XMSSMT private key with the provided name and private key bytes."""
        if self._private_key_bytes is not None:
            self._sig = oqs.StatefulSignature(self._other_name, secret_key=self._private_key_bytes)  # type: ignore
            if len(self._private_key_bytes) != self.key_size:
                msg = (
                    f"Invalid private key size for {self.name}: expected {self.key_size}, "
                    f"got {len(self._private_key_bytes)}"
                )
                raise InvalidKeyData(msg)
        else:
            self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore
            self._public_key_bytes = self._sig.generate_keypair()
            self._private_key_bytes = self._sig.export_secret_key()

    def public_key(self) -> XMSSMTPublicKey:
        """Return the corresponding public key for this XMSSMT private key."""
        if self._public_key_bytes is None:
            self._public_key_bytes = _xmss_liboqs_sk_to_pk(self._sig.export_secret_key(), self._other_name)
        return XMSSMTPublicKey(self._name, public_key=self._public_key_bytes)

    def sign(self, data: bytes) -> bytes:
        """Sign the data using the private key.

        :param data: The data to sign.
        :return: The signature of the data.
        """
        return self._sig.sign(data)

    def _export_private_key(self) -> bytes:
        """Return the private key as bytes."""
        return self._sig.export_secret_key()

    def private_bytes_raw(self) -> bytes:
        """Return the raw private key bytes."""
        return self._export_private_key()

    @classmethod
    def from_private_bytes(cls, data: bytes):
        """Set the private key bytes from the provided bytes."""
        alg_id = int.from_bytes(data[:4], "big")
        return cls(XMSSMT_ALG_IDS[alg_id], data)

    @property
    def key_size(self) -> int:
        """Return the size of the private key for this XMSSMT private key."""
        return self._sig.details["length_secret_key"]

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSSMT private key."""
        return self._sig.sigs_total()

    @property
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining for this XMSSMT private key."""
        return self._sig.sigs_remaining()

    @property
    def used_keys(self) -> list[bytes]:
        """Return the list of used keys during signing."""
        return self._sig.export_used_keys()


class HSSPublicKey(PQHashStatefulSigPublicKey):
    """Class representing an HSS public key."""

    pub: Optional[hsslms.HSS_Pub]

    def _get_header_name(self) -> bytes:
        """Return the header name for the HSS public key."""
        return b"HSS"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the HSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        # support formats:
        # hss_lms_sha256_m32_h10_n32_w1
        # hss_lms_sha256_m32_h10_lmots_sha256_n32_w1
        # LMS_SHA256_H10_W1
        if "lmots" in name:
            # If the name contains "lmots", we assume it's a valid HSS name
            name = name.lower()
            if name.startswith("hss_"):
                name = name.replace("hss_", "", 1)
            # name = f"hss_{lms_algorithm.lower()}_{_n}_{_w}"
            lmots_algorithm = name.split("_lmots_")[1]
            _w = lmots_algorithm.split("_")[-1].lower()
            _n = lmots_algorithm.split("_")[-2].lower()
            name = "hss_" + name.split("_lmots_")[0] + f"_{_n}_{_w}"
            # Needs to look up the HSS algorithm name
            return name, self._correct_hss_name(name)

        elif name.startswith("hss_"):
            # check if the name is in the following format:
            # hss_lms_sha256_m32_h10_n32_w1
            hss_parts = name.split("_")
            if len(hss_parts) < 5 or hss_parts[0] != "hss" or hss_parts[1] != "lms":
                raise ValueError(f"Invalid HSS name format: {name}")

        elif name.startswith("lms_"):
            # If the name starts with "lms_", we assume it's a valid HSS name
            # Convert to the expected format: hss_lms_sha256_m32_h10_n32_w1
            # Got: LMS_SHA256_H10_W1
            other_name = name
            hash_alg = name.split("_")[1].upper()
            hss_parts = name.split("_")
            h = hss_parts[2].lower()  # Height
            n = hss_parts[3].lower()  # Number of leaves
            name = f"hss_lms_{hash_alg.lower()}_{h}_{n}"
            return name, other_name

        return name, self._correct_hss_name(name)

    def _initialize_key(self):
        """Initialize the HSS public key with the provided name and public key bytes."""
        self._sig = None
        if oqs is None or hasattr("oqs", "StatefulSignature") is False:
            try:
                self.pub = hsslms.HSS_Pub(self._public_key_bytes)
                self._public_key_bytes = self.pub.get_pubkey()
            except hsslms.INVALID as e:
                raise InvalidKeyData("Invalid HSS public key data.") from e
        else:
            self.pub = None
            # For OQS, we use the public key bytes directly
            self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore
            self._public_key_bytes = self._public_key_bytes

            if len(self._public_key_bytes) != self.key_size:
                msg = f"Invalid public key size for {self.name}: expected {self.key_size + 4}, "
                msg += f"got {len(self._public_key_bytes)}"
                raise InvalidKeyData(msg)

    @property
    def name(self) -> str:
        """Return the name of the HSS public key."""
        return self._name

    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the HSS signature.

        :param signature: The HSS signature to extract the leaf index from.
        :return: The leaf index extracted from the signature.
        """
        return extract_hss_leaf_index(signature)

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    @staticmethod
    def _load_hss_public_key(public_bytes: bytes):
        """Load a public key from DER-encoded data."""
        idx = public_bytes[:4]
        idx = int.from_bytes(idx, "big")
        logging.info("HSS public key index:", idx)
        name = lmots_id_2_algorithm_type_dict[idx]
        logging.info("LMOTS algorithm name:", name)
        length = public_bytes[0:4]
        lms_public_key = public_bytes[4:]
        logging.info("LMS Public Key:", lms_public_key.hex())
        return HSS_Pub(public_bytes), name, length

    @staticmethod
    def _correct_hss_name(name: str) -> str:
        """Correct the HSS name to match the expected format."""
        # Old name: hss_lms_sha256_m32_h10_n32_w1
        # New OQS name: LMS_SHA256_H20_W1
        if name.startswith("hss_"):
            name = name.replace("hss_", "", 1)
            split_name = name.split("_")
            split_names = split_name[0:2] + [split_name[3], split_name[5]]
            lms_algorithm = "_".join(split_names).upper()
            return lms_algorithm
        raise NotImplementedError(f"Unsupported HSS algorithm name: {name}")

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "HSSPublicKey":
        """Create a new public key object from the provided bytes."""
        try:
            hss_pub, lmots_name, _ = cls._load_hss_public_key(data)
        except hsslms.INVALID as e:
            raise InvalidKeyData("Invalid HSS public key data.") from e
        # Check if the algorithm is supported
        _w = lmots_name.split("_")[-1].lower()
        _n = lmots_name.split("_")[-2].lower()
        # output format: hss_lms_sha256_m32_h10_n32_w1
        lms_algorithm = lms_id_2_algorithm_type_dict[hss_pub.pub.pubtype.value]
        name = f"hss_{lms_algorithm.lower()}_{lmots_name.lower()}"
        return cls(name, data)

    def verify(self, data: bytes, signature: bytes) -> None:
        """Verify the signature against the data using the public key.

        :param data: The data to verify the signature against.
        :param signature: The signature to verify.
        """
        if self._sig is None:
            try:
                self.pub.verify(message=data, signature=signature)
            except hsslms.INVALID as e:
                raise InvalidSignature("Invalid HSS signature for the provided data.") from e
            return
        if len(signature) != self.sig_size:
            raise InvalidSignature(f"Signature size mismatch: expected {self.sig_size}, got {len(signature)}")

        with oqs.StatefulSignature(self._name) as sig:  # type: ignore
            if not sig.verify(data, signature, self._public_key_bytes):
                raise InvalidSignature("Signature verification failed.")

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this HSS public key."""
        return self._sig.sigs_total()

    @property
    def key_size(self) -> int:
        """Return the size of the public key for this HSS public key."""
        if self._sig is not None:
            return self._sig.details()["public_key_length"]
        return len(self.public_bytes_raw())

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this HSS public key."""
        if self._sig is not None:
            return self._sig.details()["signature_length"]
        raise NotImplementedError("Signature size calculation for HSS is not implemented without OQS.")


class HSSPrivateKey(PQHashStatefulSigPrivateKey):
    """A class used to hold the private key of Hierarchical Signatures (HSS).

    For a reference see RFC 8554, section 6.
    """

    _length: int

    def _get_header_name(self) -> bytes:
        """Return the header name for the HSS private key."""
        return b"HSS"

    def _export_private_key(self) -> bytes:
        """Export the private key in a format suitable for serialization."""
        return self.private_bytes_raw()

    def get_leaf_index(self, signature: bytes) -> int:
        """Get the leaf index from the HSS signature."""
        return extract_hss_leaf_index(signature)

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature."""
        nums = 2 ** self.priv.priv[0].h
        for x in self.priv.priv:
            nums *= 2**x.h
        return nums

    @property
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining for this private key."""
        return self.priv.avail_signatures

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check the name of the HSS algorithm and return the LMS and LMOTS names."""
        return name, name

    @property
    def key_size(self) -> int:
        """Return the size of the private key in bytes."""
        return len(self.private_bytes_raw())

    @staticmethod
    def _gen_combination(name: str) -> Tuple[str, str]:
        """Generate the combination of LMS and LMOTS algorithms based on the name."""
        if name.startswith("hss_"):
            tmp = name[4:]
            parts = tmp.split("_n")
            lms_algorithm = parts[0]
            hash_alg = lms_algorithm.replace("lms_", "").split("_m")[0]
            lmots_algorithm = f"lmots_{hash_alg}_n{parts[1]}"
            lms_algorithm = lms_algorithm.upper()
            lmots_algorithm = lmots_algorithm.upper()
            return lms_algorithm, lmots_algorithm
        else:
            raise ValueError("Invalid HSS algorithm name. Got: {}".format(name))

    def __init__(self, alg_name: str, length: Optional[int] = 1):
        """Initialize the HSS private key."""
        self._length = length
        super().__init__(alg_name)

    def _initialize_key(self):
        """Initialize the private key with a single LMS private key."""
        if self.name == "hss":
            self._name = "hss_lms_sha256_m32_h10_n32_w1"

        lms_name, lmots_name = self._gen_combination(self._name)
        if lms_name not in lms_algorithm_type_dict:
            raise ValueError(f"Invalid LMS algorithm name: {lms_name}")
        if lmots_name not in lmots_algorithm_type_dict:
            raise ValueError(f"Invalid LMOTS algorithm name: {lmots_name}")

        if self._length is None or self._length < 1:
            self._length = 1

        if self._length < 1:
            raise ValueError("Length must be a positive integer.")

        lmots_id = lmots_algorithm_type_dict[lmots_name]
        lms_id = lms_algorithm_type_dict[lms_name]
        lms_type = hsslms.LMS_ALGORITHM_TYPE(lms_id)
        self.priv = hsslms.HSS_Priv(
            lmstypecodes=[lms_type] * self._length, otstypecode=hsslms.LMOTS_ALGORITHM_TYPE(lmots_id), num_cores=1
        )

    def public_key(self) -> HSSPublicKey:
        """Return the public key associated with this private key."""
        return HSSPublicKey(alg_name=self.name, public_key=self.priv.gen_pub().get_pubkey())

    def _single_key_raw(self, key: LMS_Priv) -> bytes:
        """Return the private key as raw bytes for a single key."""
        return (
            key.typecode.value.to_bytes(4, "big")
            + key.otstypecode.value.to_bytes(4, "big")
            + key.q.to_bytes(4, "big")
            + key.SEED
            + key.I
        )

    @staticmethod
    def _generate_single_key(
        lms_type: hsslms.LMS_ALGORITHM_TYPE,
        otstypecode: hsslms.LMOTS_ALGORITHM_TYPE,
        seed: bytes,
        I: bytes,  # noqa: E741
        q: int,
    ) -> LMS_Priv:
        """Generate a single LMS private key.

        :param lms_type: The LMS algorithm type.
        :param otstypecode: The LMOTS algorithm type.
        :param seed: The seed for the LMS private key.
        :param I: The identifier or extra 16 bytes for the LMS private key.
        :param q: The number of available signatures for the LMS private key.
        :return: An instance of LMS_Priv representing the LMS private key.

        """
        H, m, h = lms_type.H, lms_type.m, lms_type.h

        with Pool(1) as p:
            T = [None] * (2 ** (h + 1))
            T[2**h : 2 ** (h + 1)] = p.starmap(
                LMS_Priv._calc_leafs, ((H, I, r, h, otstypecode, seed) for r in range(2**h, 2 ** (h + 1)))
            )
            for i in range(h - 1, -1, -1):
                T[2**i : 2 ** (i + 1)] = p.starmap(
                    LMS_Priv._calc_knots, ((H, I, r, T[2 * r], T[2 * r + 1], m) for r in range(2**i, 2 ** (i + 1)))
                )

        tmp = LMS_Priv(
            typecode=lms_type,
            otstypecode=otstypecode,
            num_cores=1,
        )
        tmp.SEED = seed
        tmp.I = I
        tmp.q = q
        tmp.T = T
        return tmp

    def _laod_single_key(self, key: bytes) -> Tuple[LMS_Priv, bytes]:
        """Load a single key from raw bytes.

        :param key: The raw bytes representing the LMS private key.
        :return: A tuple containing the LMS private key and the remaining bytes.
        """
        lms_id = int.from_bytes(key[:4], "big")
        lmots_id = int.from_bytes(key[4:8], "big")
        q = int.from_bytes(key[8:12], "big")
        lms_type = hsslms.LMS_ALGORITHM_TYPE(lms_id)
        seed = key[12 : 12 + lms_type.m]
        I = key[12 + lms_type.m : 12 + lms_type.m + 16]  # noqa: E741
        rest = key[12 + lms_type.m + 16 :]
        return self._generate_single_key(
            lms_type=lms_type, otstypecode=hsslms.LMOTS_ALGORITHM_TYPE(lmots_id), seed=seed, I=I, q=q
        ), rest

    def _load_private_key(self, private_bytes: bytes) -> None:
        """Load the private key from raw bytes."""
        length = int.from_bytes(private_bytes[:4], "big")
        if length < 1:
            raise ValueError("Invalid private key length. Must be at least 1.")

        single_key_bytes = private_bytes[4:]
        self.priv.priv = []
        for _ in range(length):
            key, single_key_bytes = self._laod_single_key(single_key_bytes)
            self.priv.priv.append(key)
        self.priv.L = length
        self.priv.otstypecode = self.priv.priv[0].otstypecode
        self.priv.lmstypecodes = [key.typecode for key in self.priv.priv]
        self.priv.pub = [key.gen_pub() for key in self.priv.priv]
        self.priv.sig = [self.priv.priv[i].sign(self.priv.pub[i + 1].get_pubkey()) for i in range(length - 1)]
        self.priv.avail_signatures = 1
        for key in self.priv.priv:
            self.priv.avail_signatures *= key.get_avail_signatures()

    def private_bytes_raw(self) -> bytes:
        """Return the private key as raw bytes."""
        keys = [self._single_key_raw(x) for x in self.priv.priv]
        return self.priv.L.to_bytes(4, "big") + b"".join(keys)

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "HSSPrivateKey":
        """Create a new private key object from the provided bytes."""
        tmp = HSSPrivateKey(alg_name="hss")
        tmp._load_private_key(private_bytes=data)
        return tmp

    @property
    def private_keys(self) -> List[LMS_Priv]:
        """Return the list of LMS private keys."""
        return self.priv.priv

    def _sign_same_index(self, data: bytes, index: int) -> bytes:
        """Sign the provided data with the private key at a specific index."""
        raise NotImplementedError("Signing with a specific index is not implemented in this example.")

    @property
    def length(self) -> int:
        """Return the length of the HSS private key."""
        return self.priv.L

    @property
    def left_sigs(self) -> int:
        """Return the number of available signatures."""
        return self.priv.avail_signatures

    def _internal_sign(self, data: bytes, index: Optional[int] = None) -> bytes:
        d = self.priv.L
        length = self.length
        if index is not None:
            while self.private_keys[d - 1].get_avail_signatures() == 0:
                d -= 1
                if d == 0:
                    logging.error("Private keys exhausted.")
            index = d

        for i in range(index, length):
            self.private_keys[i] = LMS_Priv(self.priv.lmstypecodes[i], self.priv.otstypecode)
            self.priv.pub[i] = self.private_keys[i].gen_pub()
            self.priv.sig[i - 1] = self.private_keys[i - 1].sign(self.priv.pub[i].get_pubkey())
        signature = u32str(self.length - 1)
        for i in range(self.length - 1):
            signature += self.priv.sig[i] + self.priv.pub[i + 1].get_pubkey()  # signed_pub_key
        self.priv.avail_signatures -= 1
        return signature + self.private_keys[-1].sign(data)

    def sign(self, data: bytes, index: Optional[int] = None) -> bytes:
        """Sign the provided data with the private key.

        :param data: The data to be signed.
        :param index: Optional index to specify which private key to use for signing.
                      If not provided, the last private key is used.
        :raises ValueError: If the index is out of bounds.
        :return: The signature for the provided data.
        """
        if index is not None:
            return self._internal_sign(data, index)

        sig = self.priv.sign(data)
        return sig

    def _get_lmots_sig_size(self) -> int:
        """Return the size of the LMOTS signature."""
        p = self.private_keys[0].otstypecode.p
        n = self.private_keys[0].otstypecode.n
        return 4 + n + p * n

    @property
    def max_sig(self) -> int:
        """Return the size of the signature."""
        m = self.private_keys[0].typecode.m
        h = self.private_keys[0].typecode.h
        lmots_signature_size = self._get_lmots_sig_size()
        lms_signature_size = 4 + lmots_signature_size + 4 + h * m
        lms_public_key_size = 4 + 4 + 16 + m  # typecode + otstypecode + identifier + root node
        return 4 + (self.length - 1) * (lms_signature_size + lms_public_key_size) + lms_signature_size

    @staticmethod
    def _cast_to_key_object(
        lms_type: hsslms.LMS_ALGORITHM_TYPE, otstypecode: LMOTS_ALGORITHM_TYPE, length: int, keys: List
    ) -> HSS_Priv:
        """Cast the private key to an HSS_Priv object."""
        priv = [keys[0]]
        avail_signatures = priv[0].get_avail_signatures()
        pub = [priv[0].gen_pub()]
        sig = []
        type_codes = [priv[0].typecode]
        for i in range(1, length):
            priv.append(keys[i])
            avail_signatures *= priv[i].get_avail_signatures()
            pub.append(priv[-1].gen_pub())
            sig.append(priv[-2].sign(pub[-1].get_pubkey()))
            type_codes.append(priv[i].typecode)

        hss_priv = HSS_Priv(type_codes, otstypecode)
        hss_priv.priv = priv
        hss_priv.pub = pub
        hss_priv.sig = sig
        hss_priv.L = length
        hss_priv.avail_signatures = avail_signatures
        return hss_priv

    @classmethod
    def from_seed(cls, seed: bytes, name: str, length: int) -> "HSSPrivateKey":
        """Create a new private key object from a seed."""
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes long.")
        lms_name, lmots_name = cls._gen_combination(name)
        print("LMS Name:", lms_name)
        print("LMOTS Name:", lmots_name)
        level_names = [(lms_name.lower(), lmots_name.lower())] * length
        keys = generate_hss_priv_key_by_name(
            master_seed=seed,
            level_names=level_names,
        )
        lms_id = lms_algorithm_type_dict[lms_name]
        lms_type = hsslms.LMS_ALGORITHM_TYPE(lms_id)
        keys_out = []
        for key in keys["lms_keys"]:
            single_key = cls._generate_single_key(
                lms_type=lms_type,
                otstypecode=LMOTS_ALGORITHM_TYPE(key["lmots_typecode"]),
                seed=key["SEED"],
                I=key["I"],
                q=key["q"],
            )
            keys_out.append(single_key)

        lmots_algorithm_type = LMOTS_ALGORITHM_TYPE(lmots_algorithm_type_dict[lmots_name])

        priv = cls._cast_to_key_object(lms_type, lmots_algorithm_type, length, keys_out)

        private_key = HSSPrivateKey(alg_name=name, length=length)
        private_key.priv = priv
        return private_key


def serialize_key(self, include_public: bool = False, include_signatures: bool = False) -> bytes:
    """
    Serialize the entire HSS private key as described in RFC 8554 §6.1.

    Layout (big-endian):
        u32str(L) ||
        ⨁  [ for each level i = 0 … L-1 ]
            u32str(lms_typecode[i])     # RFC 8554 Table 2 numeric ID
            u32str(lmots_typecode[i])   # RFC 8554 Table 1 numeric ID
            I[i]                        # 16-byte identifier
            u32str(q[i])                # next unused OTS index
            SEED[i]                     # m bytes (depends on LMS set)
            [ pub[i] ]                  # optional, if include_public
            [ sig[i] ]                  # optional, if include_signatures & i<L-1
    """
    out = u32str(self.priv.L)  # number of levels

    for i in range(self.priv.L):
        prv = self.priv.priv[i]  # type: LMS_Priv

        out += u32str(prv.typecode.value)  # LMS typecode
        out += u32str(prv.otstypecode.value)  # LM-OTS typecode
        out += prv.I  # 16-byte identifier
        out += u32str(prv.q)  # current leaf
        out += prv.SEED  # m-byte SEED

        if include_public:
            out += self.priv.pub[i].get_pubkey()  # 24 + m bytes
        if include_signatures and i < self.priv.L - 1:
            out += self.priv.sig[i]  # chained LMS sig

    return out


# ---------- ASN.1 helpers ----------
class _LMS_LevelKey(univ.Sequence):
    """ASN.1 structure for LMS level key.

    LMS_LevelKey: Sequence {
        rawPrivate OCTET STRING,  # LMS private key
        publicKey OCTET STRING OPTIONAL,  # LMS public key
        signatureToNext OCTET STRING OPTIONAL  # LMS signature to next level
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("rawPrivate", univ.OctetString()),
        namedtype.OptionalNamedType(
            "publicKey", univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.OptionalNamedType(
            "signatureToNext",
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
        ),
    )


class HSSPrivateKeyASN1(univ.Sequence):
    """ASN.1 structure for HSS private key.

    HSSPrivateKey: Sequence {
        keys SEQUENCE OF LMS_LevelKey
    }
    """

    componentType = namedtype.NamedTypes(namedtype.NamedType("keys", univ.SequenceOf(componentType=_LMS_LevelKey())))


def _serialize_to_asn1(self: "HSSPrivateKey", include_public: bool = False, include_signatures: bool = False) -> bytes:
    """DER-encode this HSS private key according to the ASN.1 structure above.

    :param self: The HSSPrivateKey instance to serialize.
    :param include_public: If True, include public keys in the serialization.
    :param include_signatures: If True, include signatures in the serialization.
    :return: DER-encoded ASN.1 SEQUENCE of LMS_LevelKey.

    """
    top = HSSPrivateKeyASN1()
    keys_seq = univ.SequenceOf(componentType=_LMS_LevelKey())

    for i in range(self.priv.L):
        lvl = _LMS_LevelKey()
        lvl["rawPrivate"] = self._single_key_raw(self.priv.priv[i])
        if include_public:
            lvl["publicKey"] = self.priv.pub[i].get_pubkey()
        if include_signatures and i < self.priv.L - 1:
            lvl["signatureToNext"] = self.priv.sig[i]

        keys_seq.append(lvl)

    top["keys"] = keys_seq
    return encoder.encode(top)


# attach it to the class
HSSPrivateKey.serialize_to_asn1 = _serialize_to_asn1

XMSS_ALG_IDS = {
    0x00000001: "XMSS-SHA2_10_256",
    0x00000002: "XMSS-SHA2_16_256",
    0x00000003: "XMSS-SHA2_20_256",
    0x00000004: "XMSS-SHA2_10_512",
    0x00000005: "XMSS-SHA2_16_512",
    0x00000006: "XMSS-SHA2_20_512",
    0x00000007: "XMSS-SHAKE_10_256",
    0x00000008: "XMSS-SHAKE_16_256",
    0x00000009: "XMSS-SHAKE_20_256",
    0x0000000A: "XMSS-SHAKE_10_512",
    0x0000000B: "XMSS-SHAKE_16_512",
    0x0000000C: "XMSS-SHAKE_20_512",
    0x0000000D: "XMSS-SHA2_10_192",
    0x0000000E: "XMSS-SHA2_16_192",
    0x0000000F: "XMSS-SHA2_20_192",
    0x00000010: "XMSS-SHAKE256_10_256",
    0x00000011: "XMSS-SHAKE256_16_256",
    0x00000012: "XMSS-SHAKE256_20_256",
    0x00000013: "XMSS-SHAKE256_10_192",
    0x00000014: "XMSS-SHAKE256_16_192",
    0x00000015: "XMSS-SHAKE256_20_192",
}

XMSSMT_ALG_IDS = {
    0x00000001: "XMSSMT-SHA2_20/2_256",
    0x00000002: "XMSSMT-SHA2_20/4_256",
    0x00000003: "XMSSMT-SHA2_40/2_256",
    0x00000004: "XMSSMT-SHA2_40/4_256",
    0x00000005: "XMSSMT-SHA2_40/8_256",
    0x00000006: "XMSSMT-SHA2_60/3_256",
    0x00000007: "XMSSMT-SHA2_60/6_256",
    0x00000008: "XMSSMT-SHA2_60/12_256",
    0x00000009: "XMSSMT-SHA2_20/2_512",
    0x0000000A: "XMSSMT-SHA2_20/4_512",
    0x0000000B: "XMSSMT-SHA2_40/2_512",
    0x0000000C: "XMSSMT-SHA2_40/4_512",
    0x0000000D: "XMSSMT-SHA2_40/8_512",
    0x0000000E: "XMSSMT-SHA2_60/3_512",
    0x0000000F: "XMSSMT-SHA2_60/6_512",
    0x00000010: "XMSSMT-SHA2_60/12_512",
    0x00000011: "XMSSMT-SHAKE_20/2_256",
    0x00000012: "XMSSMT-SHAKE_20/4_256",
    0x00000013: "XMSSMT-SHAKE_40/2_256",
    0x00000014: "XMSSMT-SHAKE_40/4_256",
    0x00000015: "XMSSMT-SHAKE_40/8_256",
    0x00000016: "XMSSMT-SHAKE_60/3_256",
    0x00000017: "XMSSMT-SHAKE_60/6_256",
    0x00000018: "XMSSMT-SHAKE_60/12_256",
    0x00000019: "XMSSMT-SHAKE_20/2_512",
    0x0000001A: "XMSSMT-SHAKE_20/4_512",
    0x0000001B: "XMSSMT-SHAKE_40/2_512",
    0x0000001C: "XMSSMT-SHAKE_40/4_512",
    0x0000001D: "XMSSMT-SHAKE_40/8_512",
    0x0000001E: "XMSSMT-SHAKE_60/3_512",
    0x0000001F: "XMSSMT-SHAKE_60/6_512",
    0x00000020: "XMSSMT-SHAKE_60/12_512",
    0x00000021: "XMSSMT-SHA2_20/2_192",
    0x00000022: "XMSSMT-SHA2_20/4_192",
    0x00000023: "XMSSMT-SHA2_40/2_192",
    0x00000024: "XMSSMT-SHA2_40/4_192",
    0x00000025: "XMSSMT-SHA2_40/8_192",
    0x00000026: "XMSSMT-SHA2_60/3_192",
    0x00000027: "XMSSMT-SHA2_60/6_192",
    0x00000028: "XMSSMT-SHA2_60/12_192",
    0x00000029: "XMSSMT-SHAKE256_20/2_256",
    0x0000002A: "XMSSMT-SHAKE256_20/4_256",
    0x0000002B: "XMSSMT-SHAKE256_40/2_256",
    0x0000002C: "XMSSMT-SHAKE256_40/4_256",
    0x0000002D: "XMSSMT-SHAKE256_40/8_256",
    0x0000002E: "XMSSMT-SHAKE256_60/3_256",
    0x0000002F: "XMSSMT-SHAKE256_60/6_256",
    0x00000030: "XMSSMT-SHAKE256_60/12_256",
    0x00000031: "XMSSMT-SHAKE256_20/2_192",
    0x00000032: "XMSSMT-SHAKE256_20/4_192",
    0x00000033: "XMSSMT-SHAKE256_40/2_192",
    0x00000034: "XMSSMT-SHAKE256_40/4_192",
    0x00000035: "XMSSMT-SHAKE256_40/8_192",
    0x00000036: "XMSSMT-SHAKE256_60/3_192",
    0x00000037: "XMSSMT-SHAKE256_60/6_192",
    0x00000038: "XMSSMT-SHAKE256_60/12_192",
}
