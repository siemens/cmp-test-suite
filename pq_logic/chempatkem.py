# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519
from pyasn1.type import univ

from pq_logic.kem_mechanism import DHKEMRFC9180
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPublicKey, AbstractHybridRawPrivateKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.keys.kem_keys import McEliecePrivateKey, McEliecePublicKey, MLKEMPrivateKey, Sntrup761PrivateKey
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.tmp_mapping import get_oid_for_chemnpat
from resources.exceptions import InvalidKeyCombination

CURVE_NAME_2_CONTEXT_NAME = {
    "secp256r1": "P256",
    "brainpoolP256r1": "brainpoolP256",
    "secp384r1": "P384",
    "brainpoolP384r1": "brainpoolP384",
}


TRAD_ALG_2_NENC = {"brainpoolP384": 48, "P256": 32, "brainpoolP256": 32, "X448": 56, "X25519": 32, "P384": 48}


def _get_trad_name(trad_key: Union[ECDHPrivateKey, ECDHPrivateKey]) -> str:
    """Return the traditional name to generate the context string"""
    if isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        name = CURVE_NAME_2_CONTEXT_NAME[trad_key.curve.name]
    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        name = "X448"
    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        name = "X25519"
    else:
        raise ValueError("Unsupported key type.")
    return name


class ChempatKEM:
    """
    Class implementing a hybrid key encapsulation mechanism (Chempat), combining a traditional KEM (TKEM)
    with a post-quantum KEM (PQKEM).
    """

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: Optional[ECDHPrivateKey] = None):
        """Initialize the ChempatKEM instance with keys.

        :param trad_key: Traditional private.
        :param pq_key: Post-quantum private.
        """
        self.pq_key = pq_key
        self.trad_key = trad_key
        self.context = self.get_context()

    def get_context(self) -> bytes:
        """Generate the context string based on the traditional and post-quantum keys.

        The context string uniquely identifies the hybrid KEM configuration, including
        the types of keys in use.

        :return: The context string as bytes.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        if self.pq_key.name == "sntrup761":
            pq_name = "sntrup761"

        elif isinstance(self.pq_key, (McEliecePrivateKey, McEliecePublicKey)):
            pq_name = self.pq_key.name.replace("-", "").lower()
        elif isinstance(self.pq_key, MLKEMPrivateKey):
            pq_name = self.pq_key.name.upper()
        else:
            raise InvalidKeyCombination(f"Unsupported post-quantum key type for Chempat.: {self.pq_key.name}")

        name = bytes(_get_trad_name(self.trad_key), "utf-8")

        return b"Chempat-" + name + b"-" + bytes(pq_name, "utf-8")

    @staticmethod
    def _hash_sha3_256(data: bytes) -> bytes:
        """Compute the SHA3-256 hash of the given data.

        :param data: Input data as bytes.
        :return: Hash digest as bytes.
        """
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(data)
        return digest.finalize()

    def encap(self, peer_pq_key: PQKEMPublicKey, trad_pk: ECDHPublicKey) -> Tuple[bytes, bytes]:
        """Perform hybrid key encapsulation with a peer's public key.

        :param peer_pq_key: The peer's post-quantum public key.
        :param trad_pk: The peer's traditional public key.
        :return: A tuple containing the kem combined shared secret and combined ciphertext
        """
        dhkem = DHKEMRFC9180(private_key=self.trad_key)
        ss_T, ct_T = dhkem.encaps(trad_pk)
        ss_PQ, ct_PQ = peer_pq_key.encaps()

        pk_trad = DHKEMRFC9180.encode_public_key(trad_pk)
        pk_pq = peer_pq_key.public_bytes_raw()

        ss = self.kem_combiner(ss_T, ss_PQ, ct_T, ct_PQ, pk_trad, pk_pq)
        return ss, b"".join([ct_T, ct_PQ])

    def decap(self, ct: bytes) -> bytes:
        """Perform hybrid key decapsulation using the provided ciphertext.

        :param ct: Concatenated ciphertext of the traditional and post-quantum keys.
        :return: The combined shared secret as bytes.
        :raises ValueError: If the input ciphertext length does not match the expected value.
        """
        nenc = TRAD_ALG_2_NENC[_get_trad_name(self.trad_key)]

        if len(ct) != nenc + self.pq_key.ct_length:
            raise ValueError(
                "Invalid ciphertext length. Expected: %d, got: %d" % (nenc + self.pq_key.ct_length, len(ct))
            )

        ct_T = ct[0:nenc]
        ct_PQ = ct[nenc:]
        dhkem = DHKEMRFC9180(private_key=self.trad_key)

        ss_T = dhkem.decaps(ct_T)
        ss_PQ = self.pq_key.decaps(ct_PQ)

        pk_trad = DHKEMRFC9180.encode_public_key(self.trad_key.public_key())
        pk_pq = self.pq_key.public_key().public_bytes_raw()

        ss = self.kem_combiner(ss_T, ss_PQ, ct_T, ct_PQ, pk_trad, pk_pq)
        logging.info("Chempat ss: %s", ss)
        return ss

    def kem_combiner(
        self,
        receiver_pk_TKEM: bytes,
        receiver_pk_PQKEM: bytes,
        sender_ct_TKEM: bytes,
        sender_ct_PQKEM: bytes,
        ss_TKEM: bytes,
        ss_PQKEM: bytes,
    ) -> bytes:
        """Generate a hybrid shared secret using traditional-KEM and PQ-KEM.

        :param receiver_pk_TKEM: Public key for the traditional KEM (TKEM) as bytes.
        :param receiver_pk_PQKEM: Public key for the post-quantum KEM (PQKEM) as bytes.
        :param sender_ct_TKEM: Ciphertext from the sender for TKEM as bytes.
        :param sender_ct_PQKEM: Ciphertext from the sender for PQKEM as bytes.
        :param ss_TKEM: Shared secret derived from TKEM as bytes.
        :param ss_PQKEM: Shared secret derived from PQKEM as bytes.
        :return: The hybrid shared secret as bytes.
        """
        hybrid_pk = receiver_pk_TKEM + receiver_pk_PQKEM
        hybrid_ct = sender_ct_TKEM + sender_ct_PQKEM

        h_hybrid_ct = self._hash_sha3_256(hybrid_ct)
        h_hybrid_pk = self._hash_sha3_256(hybrid_pk)

        concatenated_data = ss_TKEM + ss_PQKEM + h_hybrid_ct + h_hybrid_pk + self.context

        hybrid_ss = self._hash_sha3_256(concatenated_data)

        return hybrid_ss


class ChempatPublicKey(AbstractHybridRawPublicKey):

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: Optional[ECDHPublicKey] = None):
        """Constructor for the ChempatPublicKey class.

        :param pq_key: The post-quantum public key.
        :param trad_key: The traditional public key.
        :raises ValueError: If the trad_key is not None and not an ECDHPublicKey.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        super().__init__(pq_key, trad_key)
        if trad_key and not isinstance(trad_key, ECDHPublicKey):
            raise ValueError("Unsupported key type for Chempat the trad_key must be `None` or `ECDHPublicKey`")

        self.chempat_kem = get_oid_for_chemnpat(pq_key, trad_key)

    def public_bytes_raw(self) -> bytes:
        """Return the raw bytes of the public key as concatenation of the post-quantum and traditional keys."""
        return self.pq_key.public_bytes_raw() + self.trad_key.public_bytes_raw()

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for the Chempat key."""
        return get_oid_for_chemnpat(self.pq_key, self.trad_key)


class ChempatPrivateKey(AbstractHybridRawPrivateKey):

    @classmethod
    def generate(cls):
        raise NotImplementedError("The ChempatPrivateKey class does not support key generation.")

    def private_bytes_raw(self) -> bytes:
        return self.pq_key.private_bytes_raw() + self.trad_key.private_bytes_raw()

    @classmethod
    def from_private_bytes(cls, data: bytes, name: Optional[str] = None) -> "ChempatPrivateKey":

        if name is None:
            raise ValueError("The key name must be provided to create a ChempatPrivateKey instance.")

        if "sntrup761" in name:
            return ChempatSntrup761PrivateKey.from_private_bytes(data)

        if "mceliece" in name:
            return ChempatMcEliecePrivateKey.from_private_bytes(data)

        elif "ml-kem-768" in name:
            return ChempatMLKEM768PrivateKey.from_private_bytes(data)
        else:
            raise ValueError("Unsupported key type for Chempat.")


    def _get_key_name(self) -> bytes:
        """Return the key name for the key, for saving the key to a file."""
        return b"CHEMPAT"

    def __init__(self, pq_key, trad_key: Optional[ECDHPrivateKey] = None):
        """Constructor for the ChempatPrivateKey class.

        :param pq_key: The post-quantum private key.
        :param trad_key: The traditional private key, if None, will be created in the `encaps` function.
        :raises ValueError: If the trad_key is not None and not an ECDHPrivateKey.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        super().__init__(pq_key, trad_key)
        if trad_key and not isinstance(trad_key, ECDHPrivateKey):
            raise ValueError("Unsupported key type for Chempat the trad_key must be `None` or `ECDHPrivateKey`")

        self.chempat_kem = ChempatKEM(self.pq_key, self.trad_key)

    @staticmethod
    def parse_keys(pq_key, trad_key) -> "ChempatPrivateKey":
        """Parse and create a ChempatPrivateKey instance based on the provided keys.

        :param pq_key: The post-quantum private key.
        :param trad_key: The traditional private key.
        :return: The corresponding `ChempatPrivateKey` instance.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        if isinstance(pq_key, MLKEMPrivateKey):
            return ChempatMLKEM768PrivateKey(pq_key, trad_key)

        if isinstance(pq_key, McEliecePrivateKey):
            return ChempatMcEliecePrivateKey(pq_key, trad_key)

        if isinstance(pq_key, Sntrup761PrivateKey):
            return ChempatSntrup761PrivateKey(pq_key, trad_key)

        else:
            return ChempatPrivateKey(pq_key, trad_key)

    def encaps(self, peer_key: ChempatPublicKey) -> Tuple[bytes, bytes]:
        """Perform key encapsulation with a peer's public key.

        :param peer_key: The peer's hybrid public key.
        :return: The encapsulated shared secret and ciphertext.
        """
        return self.chempat_kem.encap(peer_key.pq_key, peer_key.trad_key)

    def decaps(self, ct: bytes) -> bytes:
        """Perform key decapsulation using the provided ciphertext.

        :param ct: The ciphertext to be decrypted.
        :return: The decapsulated shared secret.
        """
        return self.chempat_kem.decap(ct)


class ChempatSntrup761PublicKey(ChempatPublicKey):
    pass


class ChempatSntrup761PrivateKey(ChempatPrivateKey):
    def public_key(self) -> ChempatSntrup761PublicKey:
        """Return the corresponding public key class."""
        return ChempatSntrup761PublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    @classmethod
    def from_private_bytes(cls, data: bytes, name: Optional[str] = None) -> "ChempatSntrup761PrivateKey":
        """Create a ChempatSntrup761PrivateKey instance from the provided private bytes.

        :param data: The private key bytes, which are the pq-part and the trad-part concatenated.
        :param name: The pq-algorithm name.
        :return: The created `ChempatSntrup761PrivateKey` instance.
        """
        key = PQKeyFactory.generate_pq_key("sntrup761")
        key_size = key.key_size
        pq_key = Sntrup761PrivateKey.from_private_bytes(data=data[:key_size], name="sntrup761")
        trad_key = x25519.X25519PrivateKey.from_private_bytes(data=data[key_size:])
        return ChempatSntrup761PrivateKey(pq_key, trad_key)

class ChempatMcEliecePublicKey(ChempatPublicKey):
    """Public key class for the Chempat hybrid key encapsulation mechanism."""

    pass


class ChempatMcEliecePrivateKey(ChempatPrivateKey):
    def public_key(self) -> ChempatMcEliecePublicKey:
        return ChempatMcEliecePublicKey(self.pq_key.public_key(), self.trad_key.public_key())


class ChempatMLKEM768PublicKey(ChempatPublicKey):
    """Public key class for the Chempat hybrid key encapsulation mechanism."""

    pass


class ChempatMLKEM768PrivateKey(ChempatPrivateKey):
    """Chempat ML-KEM 768 private key class."""

    @classmethod
    def generate(cls, trad_name: str = None, curve: str = None):
        """Generate a ChempatMLKEM768PrivateKey instance.

        :param trad_name: The traditional key name.
        :param curve: The curve name.
        :return: The generated `ChempatMLKEM768PrivateKey` instance.
        """
        if trad_name is None or trad_name == "x25519":
            return cls(PQKeyFactory.generate_pq_key("ml-kem-768"), x25519.X25519PrivateKey.generate())
        raise NotImplementedError("Currently only x25519 is supported.")

    def public_key(self) -> ChempatMLKEM768PublicKey:
        return ChempatMLKEM768PublicKey(self.pq_key.public_key(), self.trad_key.public_key())
