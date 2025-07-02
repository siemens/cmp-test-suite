"""Contains the logic for handling HSS keys."""

# pylint: disable=invalid-name

from __future__ import annotations

import os
import struct
from typing import Optional

from cryptography.exceptions import InvalidSignature

from pq_logic.keys.hss_utils import (
    D_MESG,
    D_PBLC,
    LMOTS_ALGORITHM_NAME_2_ID,
    LMOTS_ID_2_PARAMS,
    LMOTSAlgorithmParams,
    cksm,
    coef,
    u8str,
    u16str,
    u32str,
)


#################################
# LMOTS key classes
#################################
class LMOTSPublicKey:
    """Public key counterpart for :class:`LMOTSPrivateKey`."""

    def __init__(self, pubkey: bytes) -> None:
        if len(pubkey) < 24:
            raise ValueError("Malformed LMOTS public key")
        typecode = struct.unpack(">I", pubkey[:4])[0]
        self.params = LMOTS_ID_2_PARAMS[typecode]
        self.I = pubkey[4:20]
        self.q = struct.unpack(">I", pubkey[20:24])[0]
        self.K = pubkey[24:]
        self.pubkey = pubkey

    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify a signature against the data using this LMOTS public key.

        :param signature: The signature to verify.
        :param data: The data that was signed.
        """
        if len(signature) < 4:
            raise InvalidSignature("Signature too short")
        sigtype = struct.unpack(">I", signature[:4])[0]
        if sigtype != self.params.identifier:
            raise InvalidSignature("LMOTS type mismatch")
        n = self.params.n
        if len(signature) != self.sig_size:
            raise InvalidSignature("Malformed LMOTS signature")
        C = signature[4 : 4 + n]
        Q = self.params.compute_hash(self.I + u32str(self.q) + D_MESG + C + data)
        Qa = Q + cksm(Q, self.params.w, self.params.n, self.params.ls)
        Kc = self.params.compute_hash(self.I + u32str(self.q) + D_PBLC)
        for i in range(self.params.p):
            a = coef(Qa, i, self.params.w)
            tmp = signature[4 + n + i * n : 4 + n + (i + 1) * n]
            for j in range(a, 2**self.params.w - 1):
                tmp = self.params.compute_hash(self.I + u32str(self.q) + u16str(i) + u8str(j) + tmp)
            Kc += tmp
        Kc = self.params.compute_hash(Kc)
        if Kc != self.K:
            raise InvalidSignature("Invalid LMOTS signature")

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "LMOTSPublicKey":
        """Instantiate a public key from its byte representation."""
        return cls(data)

    @property
    def sig_size(self) -> int:
        """Return the length of a signature for this LMOTS key."""
        return 4 + self.params.n * (self.params.p + 1)

    def public_bytes_raw(self) -> bytes:
        """Return the serialized public key bytes."""
        return u32str(self.params.identifier) + self.I + u32str(self.q) + self.K


class LMOTSPrivateKey:
    """A minimal LMOTS private key."""

    def __init__(self, params: LMOTSAlgorithmParams, idx: bytes, q: int, seed: bytes) -> None:
        self.params = params
        self.I = idx
        self.q = q
        self.seed = seed
        self._keys = self.params.derive_leafs(seed, q)
        self.used = False

    def sign(self, data: bytes, c: Optional[bytes] = None) -> bytes:
        """Sign data with the LMOTS private key."""
        if self.used:
            raise ValueError("LMOTS key already used")
        self.used = True
        return self.params.sign(data, self._keys, self.I, self.q, c)

    def gen_pub_K(self) -> bytes:
        """Generate the public key K from the private key."""
        u32q = u32str(self.q)
        K = self.params.compute_hash(self.I + u32q + D_PBLC)
        for i, x in enumerate(self._keys):
            tmp = x
            for j in range(2**self.params.w - 1):
                tmp = self.params.compute_hash(self.I + u32q + u16str(i) + u8str(j) + tmp)
            K += tmp
        return self.params.compute_hash(K)

    def public_key(self) -> LMOTSPublicKey:
        """Return the public key corresponding to this private key."""
        return LMOTSPublicKey(u32str(self.params.identifier) + self.I + u32str(self.q) + self.gen_pub_K())

    @classmethod
    def from_private_bytes(cls, privkey: bytes) -> "LMOTSPrivateKey":
        """Create an LMOTS private key from bytes."""
        if len(privkey) < 24:
            raise ValueError("Malformed LMOTS private key")
        typecode = struct.unpack(">I", privkey[:4])[0]
        params = LMOTS_ID_2_PARAMS[typecode]
        idx = privkey[4:20]
        q = struct.unpack(">I", privkey[20:24])[0]
        seed = privkey[24:]
        return cls(params, idx, q, seed)

    @classmethod
    def from_name(
        cls,
        lms_name: str,
        seed: Optional[bytes] = None,
        identifier: Optional[bytes] = None,
        q: int = 0,
    ) -> "LMOTSPrivateKey":
        """Create an LMOTS private key from a name."""
        lms_id = LMOTS_ALGORITHM_NAME_2_ID[lms_name]
        params = LMOTS_ID_2_PARAMS[lms_id]
        seed = seed or os.urandom(params.n)
        identifier = identifier or os.urandom(16)
        return cls(params, identifier, q, seed)

    @property
    def sig_size(self) -> int:
        """Return the length of a signature for this LMOTS key."""
        return self.public_key().sig_size
