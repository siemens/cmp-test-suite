# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=invalid-name

"""XWing key classes."""

import copy
import logging
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from pyasn1.type import univ

from pq_logic.keys.abstract_wrapper_keys import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey, MLKEMPublicKey
from resources.exceptions import InvalidKeyData
from resources.typingutils import ECDHPrivateKey

##################################
# XWing Keys
##################################

_XWING_LABEL = rb"""
                \./
                /^\
              """.replace(b"\n", b"").replace(b" ", b"")
_XWING_OID_STR = "1.3.6.1.4.1.62253.25722"


class XWingPublicKey(AbstractHybridRawPublicKey):
    """Class representing a XWing public key."""

    _pq_key: MLKEMPublicKey  # type: ignore
    _trad_key: x25519.X25519PublicKey  # type: ignore

    def __init__(self, pq_key: MLKEMPublicKey, trad_key: x25519.X25519PublicKey):
        """Initialize the XWing public key.

        :param pq_key: The ML-KEM public key.
        :param trad_key: The X25519 public key.
        """
        super().__init__(pq_key, trad_key)  # type: ignore

        if not isinstance(pq_key, MLKEMPublicKey):
            raise ValueError("pq_key must be an instance of MLKEMPublicKey.")

        if not isinstance(trad_key, x25519.X25519PublicKey):
            raise ValueError("trad_key must be an instance of X25519PublicKey.")

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the key."""
        return univ.ObjectIdentifier(_XWING_OID_STR)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "XWingPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :return: The public key.
        """
        if len(data) != 1216:
            raise InvalidKeyData(f"Public key must be 1216 bytes in total, but got: {len(data)}.")

        pk_M = data[:1184]
        pk_X = data[1184:]
        trad_key = x25519.X25519PublicKey.from_public_bytes(pk_X)
        pq_key = MLKEMPublicKey.from_public_bytes(name="ml-kem-768", data=pk_M)
        return cls(pq_key=pq_key, trad_key=trad_key)

    def public_bytes_raw(self) -> bytes:
        """Serialize the public keys into a concatenated byte string."""
        return self._pq_key.public_bytes_raw() + self._trad_key.public_bytes_raw()

    def encaps(self, private_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and ciphertext for the given private key.

        :param private_key: The private key to encapsulate the shared secret for.
        :return: The shared secret and ciphertext.
        """
        if not isinstance(private_key, x25519.X25519PrivateKey):
            private_key = x25519.X25519PrivateKey.generate()

        pk_X = self._trad_key.public_bytes_raw()
        ss_X = private_key.exchange(self._trad_key)
        ss_M, ct_M = self._pq_key.encaps()
        ct_X = private_key.public_key().public_bytes_raw()
        ss = XWingPrivateKey.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        ct = ct_M + ct_X
        return ss, ct

    @property
    def key_size(self) -> int:
        """Return the size of the key in bits."""
        return self._pq_key.key_size + 32

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return self._pq_key.ct_length + 32

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return "xwing"

    @property
    def trad_key(self) -> x25519.X25519PublicKey:
        """Return the X25519 public key."""
        return self._trad_key

    @property
    def pq_key(self) -> MLKEMPublicKey:
        """Return the ML-KEM public key."""
        return self._pq_key


class XWingPrivateKey(AbstractHybridRawPrivateKey):
    """Class representing a XWing private key."""

    _pq_key: MLKEMPrivateKey
    _trad_key: x25519.X25519PrivateKey
    _seed: Optional[bytes]

    def __init__(
        self,
        pq_key: Optional[MLKEMPrivateKey] = None,
        trad_key: Optional[x25519.X25519PrivateKey] = None,
        seed: Optional[bytes] = None,
    ):
        """Initialize the XWing private key.

        :param pq_key: The ML-KEM private key.
        :param trad_key: The X25519 private key.
        :param seed: The seed to derive the keys from.
        """
        super().__init__(pq_key, trad_key)  # type: ignore
        if pq_key is None and trad_key is None:
            _key = XWingPrivateKey.expand(seed)
            pq_key = _key.pq_key
            trad_key = _key.trad_key
            seed = _key._seed
        elif pq_key is None or trad_key is None:
            raise ValueError("Both keys must be provided or none.")

        self._pq_key = pq_key  # type: ignore
        self._trad_key = trad_key  # type: ignore
        self._seed = seed  # type: ignore

    def private_numbers(self) -> bytes:
        """Return the private key seed.

        :return: The private key seed as 32 bytes, unless the provided seed is 96 bytes,
        in which case it returns as 96 bytes.
        :raises ValueError: If the private key does not have a seed.
        """
        if self._seed is None:
            raise ValueError("The private key does not have a seed set.")
        return self._seed

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the key."""
        return univ.ObjectIdentifier(_XWING_OID_STR)

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"XWING"

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "XWingPrivateKey":
        """Create a private key from the given byte string.

        :param data: The byte string to create the private key from.
        :return: The private key.
        """
        if len(data) == 96:
            pq_key = MLKEMPrivateKey.from_private_bytes(name="ml-kem-768", data=data[:64])
            trad_key = x25519.X25519PrivateKey.from_private_bytes(data[64:])
            return cls(pq_key, trad_key)

        if len(data) == 32:
            return cls.expand(data)

        if len(data) != 2432 and len(data) != 2432 + 32:
            raise InvalidKeyData(
                f"The private key must be 2400 bytes for ML-KEM and 32 bytes for X25519."
                f"Or the private key must be the 32 bytes seed and then raw key."
                f"Got: {len(data)} bytes."
            )
        seed_key = None
        if len(data) == 2432 + 32:
            seed_key = cls(seed=data[:32])
            trad_data = data[2432:]
            pq_data = data[32:2432]
        else:
            trad_data = data[2400:]
            pq_data = data[:2400]

        trad_key = x25519.X25519PrivateKey.from_private_bytes(trad_data)
        pq_key = MLKEMPrivateKey.from_private_bytes(pq_data, "ml-kem-768")
        key = cls(pq_key, trad_key)
        if seed_key is not None:
            if seed_key.private_bytes_raw() != key.private_bytes_raw():
                raise InvalidKeyData("The X-Wing private key does not match the seed.")
            return seed_key
        return key

    @staticmethod
    def kem_combiner(mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine shared secrets and other parameters into a final shared secret.

        :param mlkem_ss: Shared secret from ML-KEM.
        :param trad_ss: Shared secret from X25519.
        :param trad_ct: Ciphertext from X25519.
        :param trad_pk: Serialized X25519 public key.
        :return: The combined shared secret.
        """
        hash_function = hashes.Hash(hashes.SHA3_256())
        hash_function.update(mlkem_ss + trad_ss + trad_ct + trad_pk + _XWING_LABEL)
        ss = hash_function.finalize()
        logging.info("XWing ss: %s", ss)
        return ss

    def encaps(self, public_key: XWingPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and ciphertext for the given public key.

        :param public_key: The public key to encapsulate the shared secret for.
        :return: The shared secret and ciphertext.
        """
        pk_X = public_key.trad_key.public_bytes_raw()
        ss_X = self._trad_key.exchange(public_key.trad_key)
        ss_M, ct_M = public_key.pq_key.encaps()
        ct_X = self._trad_key.public_key().public_bytes_raw()
        ss = self.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        ct = ct_M + ct_X
        return ss, ct

    def decaps(self, ct: bytes):
        """Decapsulate a shared secret from the given ciphertext.

        :param ct: The ciphertext to decapsulate the shared secret from.
        :return: The shared secret.
        """
        ct_M = ct[:1088]
        ct_X = ct[1088:1120]
        ss_M = self.pq_key.decaps(ct_M)
        ss_X = self._trad_key.exchange(x25519.X25519PublicKey.from_public_bytes(ct_X))
        pk_X = self._trad_key.public_key().public_bytes_raw()
        ss = self.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        return ss

    @staticmethod
    def generate(**params):
        """Generate a new private key."""
        return XWingPrivateKey.expand(params.get("seed"))

    def public_key(self) -> XWingPublicKey:
        """Return the corresponding public key class."""
        return XWingPublicKey(self.pq_key.public_key(), self._trad_key.public_key())

    def _export_private_key(self) -> bytes:
        """Export the private key to be stored inside a `OneAsymmetricKey` structure."""
        return self._seed or self.private_bytes_raw()

    @staticmethod
    def _from_seed(seed: bytes) -> Tuple[MLKEMPrivateKey, x25519.X25519PrivateKey, bytes]:
        """Create a new key from the given seed."""
        seed_before = copy.copy(seed)
        if len(seed) == 32:
            shake = hashes.SHAKE256(digest_size=96)
            hasher = hashes.Hash(shake)
            hasher.update(seed)
            seed = hasher.finalize()

        if len(seed) != 96:
            raise ValueError("The seed must be 32 or 96 bytes long.")

        ml_kem_key = MLKEMPrivateKey.from_private_bytes(name="ml-kem-768", data=seed[:64])
        x25519_key = x25519.X25519PrivateKey.from_private_bytes(seed[64:96])
        return ml_kem_key, x25519_key, seed_before

    @classmethod
    def from_seed(cls, seed: bytes) -> "XWingPrivateKey":
        """Create a private key from the given seed.

        :param seed: The seed to derive the keys from.
        :return: The private key.
        """
        if len(seed) in [32, 96]:
            return cls(*cls._from_seed(seed))
        raise ValueError("The seed must be 32 bytes for X25519 and 96 bytes for ML-KEM.")

    @classmethod
    def expand(cls, sk: Optional[bytes] = None) -> "XWingPrivateKey":
        """Expand the 32-byte secret seed into its components.

        :param sk: A 32-byte secret seed to derive the keys from.
        :return: The created private key.
        """
        sk = sk or os.urandom(32)
        return cls(*cls._from_seed(sk))

    @property
    def key_size(self) -> int:
        """Return the size of the key in bits."""
        return self.pq_key.key_size + 32

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return "xwing"

    @property
    def trad_key(self) -> x25519.X25519PrivateKey:
        """Return the X25519 private key."""
        return self._trad_key

    @property
    def pq_key(self) -> MLKEMPrivateKey:
        """Return the ML-KEM private key."""
        return self._pq_key
