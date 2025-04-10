# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite KEM 06 implementation.

Based on: https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-kem-06.html.
"""

import logging
from re import split
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pyasn1.codec.der import encoder
from pyasn1.type import univ

from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.keys.abstract_wrapper_keys import TradKEMPrivateKey, TradKEMPublicKey
from pq_logic.keys.composite_kem05 import CompositeKEMPrivateKey, CompositeKEMPublicKey
from pq_logic.keys.trad_kem_keys import DHKEMPrivateKey, DHKEMPublicKey
from pq_logic.tmp_oids import COMPOSITE_KEM06_NAME_2_OID
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey
from resources.exceptions import InvalidKeyCombination


def _get_composite_kem_hash_alg(pq_name: str, trad_key, alternative: bool = False) -> str:
    """Return the hash algorithm for a composite KEM.

    :param pq_name: The name of the post-quantum algorithm.
    :param trad_key: The traditional key algorithm.
    :param alternative: Whether to use an alternative hash algorithm.
    (addresses the issue:  No composite is currently compatible with CNSA 2.0 #102 )
    (to use HKDF-SHA2-512)
    :return: The hash algorithm.
    """
    # TODO maybe do directly by claimed NIST level ?

    if pq_name == "ml-kem-1024" and isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve = trad_key.curve.name
        if curve == "secp384r1":
            return "hkdf-sha384" if not alternative else "hkdf-sha512"

    if pq_name in ["ml-kem-1024", "frodokem-1344-aes", "frodokem-1344-shake"]:
        return "sha3-256"

    if pq_name in ["frodokem-976-aes", "frodokem-976-shake", "ml-kem-768"] and isinstance(
        trad_key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)
    ):
        return "sha3-256"

    if pq_name in ["frodokem-976-aes", "frodokem-976-shake", "ml-kem-768"]:
        return "hkdf-sha256" if not alternative else "hkdf-sha512"

    raise InvalidKeyCombination(f"Unsupported composite KEM: {pq_name} with {trad_key}")


class CompositeKEM06PublicKey(CompositeKEMPublicKey):
    """A Composite KEM public key for the Composite KEM 06."""

    _trad_key: TradKEMPublicKey
    _pq_key: PQKEMPublicKey
    _alternative_hash: bool = False
    _name = "composite-kem"

    def _export_public_key(self) -> bytes:
        """Export the public key."""
        _pq_export = self.pq_key.public_bytes_raw()
        _length = len(_pq_export).to_bytes(4, byteorder="little", signed=False)
        return _length + _pq_export + self.encode_trad_part()

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        if COMPOSITE_KEM06_NAME_2_OID.get(self.name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {self.name}")
        return COMPOSITE_KEM06_NAME_2_OID[self.name]

    def kem_combiner(self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine the shared secrets from the post-quantum and traditional parts.

        :param mlkem_ss: The shared secret from the post-quantum part.
        :param trad_ss: The shared secret from the traditional part.
        :param trad_ct: The traditional ciphertext.
        :param trad_pk: The traditional public key.
        :return: The combined shared secret.
        """
        concatenated_inputs = mlkem_ss + trad_ss + trad_ct + trad_pk + encoder.encode(self.get_oid())
        logging.info("CompositeKEM concatenated inputs: %s", concatenated_inputs)
        kdf_name = _get_composite_kem_hash_alg(self.pq_key.name, self.trad_key)

        # Decided to use the in CMS defined HKDF usage (Expand and Extract).
        # Otherwise, only the expand function is used.
        if "hkdf" in kdf_name:
            hash_alg = split("-", kdf_name)[1]
            hash_instance = getattr(hashes, hash_alg.upper())()
            hkdf = HKDF(algorithm=hash_instance, length=32, salt=None, info=None)
            return hkdf.derive(concatenated_inputs)

        h = hashes.Hash(hashes.SHA3_256())
        h.update(concatenated_inputs)
        return h.finalize()

    def _prepare_ct_vals(self, mlkem_ct: bytes, trad_ct: bytes) -> bytes:
        """Prepare the ciphertext values for the composite KEM.

        :param mlkem_ct: The post-quantum ciphertext.
        :param trad_ct: The traditional ciphertext.
        :return: The combined ciphertext.
        """
        _length = len(mlkem_ct).to_bytes(4, byteorder="little", signed=False)
        return _length + mlkem_ct + trad_ct


class CompositeKEM06PrivateKey(CompositeKEMPrivateKey):
    """A Composite KEM private key for the Composite KEM 06."""

    _trad_key: TradKEMPrivateKey
    _pq_key: PQKEMPrivateKey
    _name = "composite-kem"

    def public_key(self) -> CompositeKEM06PublicKey:
        """Return the public key for the private key."""
        return CompositeKEM06PublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        if COMPOSITE_KEM06_NAME_2_OID.get(self.name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {self.name}")
        return COMPOSITE_KEM06_NAME_2_OID[self.name]

    def decaps(self, ct: bytes) -> bytes:
        """Perform key decapsulation to compute the combined shared secret.

        :param ct: The DER-encoded encapsulated composite ciphertext, both ML-KEM and traditional KEM.
        :return: The computed combined shared secret as bytes.
        :raises BadAsn1Data: If the ciphertext structure is invalid or cannot be decoded.
        """
        _length = int.from_bytes(ct[:4], byteorder="little", signed=False)

        data = ct[4:]
        pq_ct = data[:_length]
        trad_ct = data[_length:]
        mlkem_ss = self.pq_key.decaps(pq_ct)
        trad_ss = self._perform_trad_decaps(trad_ct)
        trad_pk = self.encode_trad_part()
        combined_ss = self.kem_combiner(
            mlkem_ss,
            trad_ss,
            trad_ct,
            trad_pk,
        )
        return combined_ss

    def _export_private_key(self) -> bytes:
        """Export the private key to be stored inside the `OneAsymmetricKey` structure."""
        _pq_data = self.pq_key._export_private_key()  # pylint: disable=protected-access
        pq_data = univ.OctetString(_pq_data)
        pq_data = encoder.encode(pq_data)
        _length = len(pq_data).to_bytes(4, byteorder="little", signed=False)
        trad_data = univ.OctetString(self.trad_key.encode())
        return _length + pq_data + encoder.encode(trad_data)


class CompositeDHKEMRFC9180PublicKey(CompositeKEM06PublicKey):
    """Composite DHKEMRFC9180 public key."""

    _name = "composite-dhkem"
    _trad_key: DHKEMPublicKey

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: Union[DHKEMPublicKey, ECDHPublicKey]):
        """Initialize the composite KEM private key."""
        super().__init__(pq_key, trad_key)
        self._trad_key = DHKEMPublicKey(trad_key, use_rfc9180=True)

    @property
    def name(self) -> str:
        """Return the name of the DHKEM composite KEM."""
        return f"{self._name}-{self.pq_key.name}-{self.trad_key.get_trad_name}"


class CompositeDHKEMRFC9180PrivateKey(CompositeKEM06PrivateKey):
    """Composite DHKEMRFC9180 private key."""

    _name = "composite-dhkem"
    _trad_key: DHKEMPrivateKey

    @property
    def trad_key(self) -> DHKEMPrivateKey:
        """Return the traditional key."""
        return self._trad_key

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: Union[DHKEMPrivateKey, ECDHPrivateKey]):
        """Initialize the composite KEM private key."""
        super().__init__(pq_key, trad_key)
        self._trad_key = DHKEMPrivateKey(trad_key, use_rfc9180=True)

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"COMPOSITE-DHKEM"

    def public_key(self) -> CompositeDHKEMRFC9180PublicKey:
        """Return the public key of the composite KEM."""
        return CompositeDHKEMRFC9180PublicKey(self.pq_key.public_key(), self.trad_key.public_key())
