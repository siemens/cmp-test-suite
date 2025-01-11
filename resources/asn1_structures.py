# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Defines ASN.1 structures which are updated or newly defined."""

from pyasn1.type import constraint, namedtype, tag, univ
from pyasn1_alt_modules import rfc5280, rfc9480


class KemBMParameterAsn1(univ.Sequence):
    """Defines the ASN.1 structure for the `KemBMParameter`.

    KemBMParameter ::= SEQUENCE {
        kdf               AlgorithmIdentifier{KEY-DERIVATION {...}},
        kemContext    [0] OCTET STRING     OPTIONAL, #  if needed with the used KEM algorithm like ukm in cms-kemri.
        len               INTEGER (1..MAX),
        mac               AlgorithmIdentifier{MAC-ALGORITHM {...}}
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("kdf", rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType(
            "kemContext", univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType(
            "len", univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(1, float("inf")))
        ),
        namedtype.NamedType("mac", rfc5280.AlgorithmIdentifier()),
    )


class KemCiphertextInfoAsn1(univ.Sequence):
    """Defines the ASN.1 structure for the `KemCiphertextInfo`.

    KemCiphertextInfo ::= SEQUENCE {
      kem               AlgorithmIdentifier{KEM-ALGORITHM {...}},
      ct                OCTET STRING
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("kem", rfc5280.AlgorithmIdentifier()), namedtype.NamedType("ct", univ.OctetString())
    )


class KemOtherInfoAsn1(univ.Sequence):
    """Defines the ASN.1 structure for the `KemOtherInfo`.

    KemOtherInfo ::= SEQUENCE {
    staticString      PKIFreeText,
    transactionID     OCTET STRING, Out of the Message
    kemContext    [0] OCTET STRING     OPTIONAL # Context information as input to the KDF
    for domain separation and for ensuring uniqueness of MAC-keys.

    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("staticString", rfc9480.PKIFreeText()),
        namedtype.NamedType("transactionID", univ.OctetString()),
        namedtype.OptionalNamedType(
            "kemContext", univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
    )


KemCiphertextInfoValue = KemCiphertextInfoAsn1


# Ref: 5.2.8.3.3. Direct Method - Challenge-Response Protocol
class ChallengeASN1(univ.Sequence):
    """Defines the ASN.1 structure for the challenge."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("owf", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("witness", univ.OctetString()),
        namedtype.NamedType("challenge", univ.OctetString()),
        namedtype.OptionalNamedType(
            "encryptedRand",
            rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
    )


class POPODecKeyChallContentAsn1(univ.SequenceOf):
    """Defines the ASN.1 structure for the POPODecKeyChallContent."""

    componentType = ChallengeASN1()


class CAKeyUpdContent(univ.Choice):
    """`CAKeyUpdContent` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("cAKeyUpdAnnV2", rfc9480.CAKeyUpdAnnContent()),
        namedtype.NamedType(
            "cAKeyUpdAnnV3",
            rfc9480.RootCaKeyUpdateContent().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
    )
