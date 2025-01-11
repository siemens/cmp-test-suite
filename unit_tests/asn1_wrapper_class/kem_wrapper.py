# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field
from typing import List, Optional

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, tag, univ
from pyasn1_alt_modules import rfc9480

from unit_tests.asn1_wrapper_class import wrapper_alg_id
from unit_tests.asn1_wrapper_class.base import Asn1Wrapper

MAX_VALUE = float("inf")
TBA_NUM = (9999,)
id_it_KemCiphertextInfo = rfc9480.id_it + TBA_NUM

@dataclass(repr=False)
class PKIFreeText(Asn1Wrapper):
    """
    A Python dataclass equivalent to the PKIFreeText ASN.1 structure.

    PKIFreeText ::= SEQUENCE OF UTF8String (SIZE(1..MAX))
    """

    texts: List[str] = field(default_factory=list)

    def encode(self) -> bytes:
        """Encodes the PKIFreeText object to a byte string."""
        asn1_object = rfc9480.PKIFreeText()
        for text in self.texts:
            asn1_object.append(char.UTF8String(text))
        return encoder.encode(asn1_object)

    @classmethod
    def from_der(cls, data: bytes) -> "PKIFreeText":
        """Parses DER-encoded data into a PKIFreeText object."""
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc9480.PKIFreeText())
        texts = [str(text) for text in asn1_object]
        return cls(texts=texts)


@dataclass(repr=False)
class KemOtherInfo(Asn1Wrapper):
    """
    KemOtherInfo ::= SEQUENCE {
    staticString      PKIFreeText,
    transactionID     OCTET STRING, Out of the Message
    kemContext    [0] OCTET STRING     OPTIONAL # Context information as input to the KDF
    for domain separation and for ensuring uniqueness of MAC-keys.

    }
    """

    staticString: PKIFreeText
    transactionID: bytes
    kemContext: Optional[bytes] = None  # Optional OCTET STRING for the KEM context.

    def encode(self) -> bytes:
        """Encodes the KemOtherInfo object to a DER-encoded byte string."""
        data = b""
        data += self.staticString.encode()
        data += encoder.encode(univ.OctetString(self.transactionID))

        if self.kemContext is not None:
            tmp = univ.OctetString(self.kemContext).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
            data += encoder.encode(tmp)

        return self.get_size(data)


@dataclass(repr=False)
class KemCiphertextInfo(Asn1Wrapper):
    """
    KemCiphertextInfo ::= SEQUENCE {
      kem               AlgorithmIdentifier{KEM-ALGORITHM {...}},
      ct                OCTET STRING
    }
    """

    kem: wrapper_alg_id.AlgorithmIdentifier
    ct: bytes

    def encode(self) -> bytes:
        """Encodes the KemCiphertextInfo object to a DER-encoded byte string."""
        return self.get_size(self.kem.encode() + encoder.encode(univ.OctetString(self.ct)))
