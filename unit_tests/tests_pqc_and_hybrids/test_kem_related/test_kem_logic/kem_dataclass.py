# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Optional

from pyasn1.type import univ
from pyasn1_alt_modules import rfc9629

from unit_tests.asn1_wrapper_class.base import Asn1Wrapper


@dataclass(repr=False)
class KEMRecipientInfo(Asn1Wrapper):
    """Defines the KEM recipient info structure."""

    def from_der(self, data: bytes) -> bytes:
        raise NotImplementedError()

    def from_pyasn1(self, data: bytes) -> "Asn1Wrapper":
        raise NotImplementedError()

    def encode(self) -> bytes:
        raise NotImplementedError()

    version: univ.Integer = univ.Integer(0)
    rid: Optional[rfc9629.RecipientIdentifier] = None
    kem: Optional[rfc9629.AlgorithmIdentifier] = None
    kemct: Optional[univ.OctetString] = None
    kdf: Optional[rfc9629.KeyDerivationAlgorithmIdentifier] = None
    kekLength: Optional[univ.Integer] = None
    ukm: Optional[univ.OctetString] = None
    wrap: Optional[rfc9629.KeyEncryptionAlgorithmIdentifier] = None
    encryptedKey: Optional[univ.OctetString] = None


    def __post_init__(self):
        if isinstance(self.kem, univ.ObjectIdentifier):
            kem = rfc9629.AlgorithmIdentifier()
            kem["algorithm"] = self.kem
            self.kem = kem

        if isinstance(self.kdf, univ.ObjectIdentifier):
            kdf = rfc9629.KeyDerivationAlgorithmIdentifier()
            kdf["algorithm"] = self.kdf
            self.kdf = kdf

        if isinstance(self.wrap, univ.ObjectIdentifier):
            wrap = rfc9629.AlgorithmIdentifier()
            wrap["algorithm"] = self.wrap
            self.wrap = wrap # type: ignore
