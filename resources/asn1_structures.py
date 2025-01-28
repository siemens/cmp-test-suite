# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Defines ASN.1 structures which are updated or newly defined.

Will be removed as soon as the draft becomes an RFC.
"""

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


# Needs to be here, because of the `InfoTypeAndValue` class,
# cms opentype map.
class InfoTypeAndValueAsn1(univ.Sequence):
    """`InfoTypeAndValue` structure.

    InfoTypeAndValue ::= SEQUENCE {
        infoType OBJECT IDENTIFIER,
        infoValue OPTIONAL ANY DEFINED BY infoType
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("infoType", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("infoValue", univ.Any()),
    )


class GenRepContentAsn1(univ.SequenceOf):
    """`GenRepContent` structure.

    GenRepContent ::= SEQUENCE OF InfoTypeAndValue
    """

    componentType = InfoTypeAndValueAsn1()


# The challenge change, so that the PKIBody needs to be overwritten.
# So the only difference is the `popdecc: POPODecKeyChallContentAsn1`
# body. The rest is the same as the `PKIBody` class.
class PKIBodyTMP(univ.Choice):
    """Defines the ASN.1 structure for the `PKIBody`."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "ir", rfc9480.CertReqMessages().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType(
            "ip",
            rfc9480.CertRepMessage().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
        namedtype.NamedType(
            "cr", rfc9480.CertReqMessages().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        ),
        namedtype.NamedType(
            "cp",
            rfc9480.CertRepMessage().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)),
        ),
        namedtype.NamedType(
            "p10cr",
            rfc9480.CertificationRequest().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
        ),
        namedtype.NamedType(
            "popdecc",
            POPODecKeyChallContentAsn1().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
        ),
        namedtype.NamedType(
            "popdecr",
            rfc9480.POPODecKeyRespContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
        ),
        namedtype.NamedType(
            "kur", rfc9480.CertReqMessages().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
        ),
        namedtype.NamedType(
            "kup",
            rfc9480.CertRepMessage().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8)),
        ),
        namedtype.NamedType(
            "krr", rfc9480.CertReqMessages().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))
        ),
        namedtype.NamedType(
            "krp",
            rfc9480.KeyRecRepContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 10)),
        ),
        namedtype.NamedType(
            "rr", rfc9480.RevReqContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))
        ),
        namedtype.NamedType(
            "rp",
            rfc9480.RevRepContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 12)),
        ),
        namedtype.NamedType(
            "ccr", rfc9480.CertReqMessages().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))
        ),
        namedtype.NamedType(
            "ccp",
            rfc9480.CertRepMessage().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 14)),
        ),
        namedtype.NamedType(
            "ckuann",
            rfc9480.CAKeyUpdAnnContent().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 15)
            ),
        ),
        namedtype.NamedType(
            "cann",
            rfc9480.CertAnnContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 16)),
        ),
        namedtype.NamedType(
            "rann",
            rfc9480.RevAnnContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 17)),
        ),
        namedtype.NamedType(
            "crlann", rfc9480.CRLAnnContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 18))
        ),
        namedtype.NamedType(
            "pkiconf",
            rfc9480.PKIConfirmContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 19)),
        ),
        namedtype.NamedType("nested", rfc9480.nestedMessageContent),
        namedtype.NamedType(
            "genm", rfc9480.GenMsgContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 21))
        ),
        namedtype.NamedType(
            "genp", GenRepContentAsn1().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 22))
        ),
        namedtype.NamedType(
            "error",
            rfc9480.ErrorMsgContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 23)),
        ),
        namedtype.NamedType(
            "certConf",
            rfc9480.CertConfirmContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 24)),
        ),
        namedtype.NamedType(
            "pollReq",
            rfc9480.PollReqContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 25)),
        ),
        namedtype.NamedType(
            "pollRep",
            rfc9480.PollRepContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 26)),
        ),
    )


# Set the body to the temporary PKIBodyTMP.
class PKIMessageTMP(univ.Sequence):
    """Defines the ASN.1 structure for the `PKIMessage`."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("header", rfc9480.PKIHeader()),
        namedtype.NamedType("body", PKIBodyTMP()),
        namedtype.OptionalNamedType(
            "protection",
            rfc9480.PKIProtection().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.OptionalNamedType(
            "extraCerts",
            univ.SequenceOf(componentType=rfc9480.CMPCertificate())
            .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, float("inf")))
            .subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
        ),
    )
