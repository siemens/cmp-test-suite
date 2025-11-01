# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# type: ignore
"""Defines ASN.1 structures which are updated or newly defined.

Will be removed as soon as the draft becomes an RFC.
"""

from pkilint.itu.x520_name import ub_business_category, ub_postal_code, ub_street_address
from pyasn1.type import char, constraint, namedtype, tag, univ
from pyasn1_alt_modules import rfc5280, rfc9480


class OIDs(univ.SequenceOf):
    """Defines the ASN.1 structure for the `KeyPairParamRep`.

    OIDs ::= SEQUENCE OF OBJECT IDENTIFIER
    """

    componentType = univ.ObjectIdentifier()


class AlgorithmIdentifiers(univ.SequenceOf):
    """Defines the ASN.1 structure for the `KeyPairParamRep`.

    AlgorithmIdentifiers ::= SEQUENCE OF AlgorithmIdentifier
    """

    componentType = rfc9480.AlgorithmIdentifier()


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
            "kemContext", univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType(
            "len", univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(1, float("inf")))
        ),
        namedtype.NamedType("mac", rfc5280.AlgorithmIdentifier()),
    )


class KemCiphertextInfoAsn1(univ.Sequence):
    """Defines the ASN.1 structure for the `KemCiphertextInfo`.

    KemCiphertextInfo ::= SEQUENCE {
      kem AlgorithmIdentifier{KEM-ALGORITHM {...}},
      ct OCTET STRING
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
    """Defines the ASN.1 structure for the challenge.

    Challenge ::= SEQUENCE {
        owf AlgorithmIdentifier OPTIONAL,
        witness OCTET STRING,
        challenge OCTET STRING,
        encryptedRand [0] EnvelopedData OPTIONAL
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("owf", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("witness", univ.OctetString()),
        namedtype.NamedType("challenge", univ.OctetString()),
        namedtype.OptionalNamedType(
            "encryptedRand",
            rfc9480.EnvelopedData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
    )


class POPODecKeyChallContentAsn1(univ.SequenceOf):
    """Defines the ASN.1 structure for the POPODecKeyChallContent."""

    componentType = ChallengeASN1()


class CAKeyUpdContent(univ.Choice):
    """`CAKeyUpdContent` structure.

    CAKeyUpdContent ::= CHOICE {
        cAKeyUpdAnnV2       CAKeyUpdAnnContent,
        cAKeyUpdAnnV3   [1] RootCaKeyUpdateContent
    }
    """

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
class InfoTypeAndValue(univ.Sequence):
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

    componentType = InfoTypeAndValue()


# TODO inform about the bug of using the wrong `CertifiedKeyPair` structure.


class CertResponseTMP(univ.Sequence):
    """Define the ASN.1 structure for the `CertResponse`.

    CertResponse ::= SEQUENCE {
        certReqId INTEGER,
        status PKIStatusInfo,
        certifiedKeyPair CertifiedKeyPair OPTIONAL,
        rspInfo OCTET STRING OPTIONAL
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certReqId", univ.Integer()),
        namedtype.NamedType("status", rfc9480.PKIStatusInfo()),
        namedtype.OptionalNamedType("certifiedKeyPair", rfc9480.CertifiedKeyPair()),
        namedtype.OptionalNamedType("rspInfo", univ.OctetString()),
    )


class CertRepMessageTMP(univ.Sequence):
    """Define the ASN.1 structure for the `CertRepMessage`.

    CertRepMessage ::= SEQUENCE {
         caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL,
         response         SEQUENCE OF CertResponse
     }
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "caPubs",
            univ.SequenceOf(componentType=rfc9480.CMPCertificate()).subtype(
                sizeSpec=constraint.ValueSizeConstraint(1, float("inf")),
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1),
            ),
        ),
        namedtype.NamedType("response", univ.SequenceOf(componentType=CertResponseTMP())),
    )


class NestedMessageContentTMP(univ.SequenceOf):
    """Defines the ASN.1 structure for the `NestedMessageContent`.

    NestedMessageContent ::= SEQUENCE OF PKIMessage
    """

    componentType = univ.Any()


nestedMessageContent = NestedMessageContentTMP().subtype(
    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 20)
)


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
            CertRepMessageTMP().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
        namedtype.NamedType(
            "cr", rfc9480.CertReqMessages().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        ),
        namedtype.NamedType(
            "cp",
            CertRepMessageTMP().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)),
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
            CertRepMessageTMP().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8)),
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
            CertRepMessageTMP().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 14)),
        ),
        namedtype.NamedType(
            "ckuann",
            CAKeyUpdContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 15)),
        ),
        namedtype.NamedType(
            "cann",  # codespell:ignore
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
        namedtype.NamedType("nested", nestedMessageContent),
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


MAX = float("inf")


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
            .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))
            .subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
        ),
    )


class PKIMessagesTMP(univ.SequenceOf):
    """Defines the ASN.1 structure for the `PKIMessages`.

    PKIMessages ::= SEQUENCE OF PKIMessage
    """

    componentType = PKIMessageTMP()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class ProtectedPartTMP(univ.Sequence):
    """Defines the ASN.1 structure for the `ProtectedPart`.

    ProtectedPart ::= SEQUENCE {
        header PKIHeader,
        body PKIBody
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("header", rfc9480.PKIHeader()), namedtype.NamedType("body", PKIBodyTMP())
    )


# Since pyasn1 does not naturally handle recursive definitions, this hack:
#
NestedMessageContentTMP._componentType = PKIMessagesTMP()  # pylint: disable=protected-access
nestedMessageContent._componentType = PKIMessagesTMP()  # pylint: disable=protected-access


class CatalystPreTBSCertificate(univ.Sequence):
    """Defines the ASN.1 structure for the `CatalystPreTBSCertificate`."""


CatalystPreTBSCertificate.componentType = namedtype.NamedTypes(
    namedtype.DefaultedNamedType(
        "version",
        rfc5280.Version().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).subtype(value="v1"),
    ),
    namedtype.NamedType("serialNumber", rfc5280.CertificateSerialNumber()),
    namedtype.NamedType("issuer", rfc5280.Name()),
    namedtype.NamedType("validity", rfc5280.Validity()),
    namedtype.NamedType("subject", rfc5280.Name()),
    namedtype.NamedType("subjectPublicKeyInfo", rfc5280.SubjectPublicKeyInfo()),
    namedtype.OptionalNamedType(
        "issuerUniqueID",
        rfc5280.UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
    ),
    namedtype.OptionalNamedType(
        "subjectUniqueID",
        rfc5280.UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)),
    ),
    namedtype.OptionalNamedType(
        "extensions", rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
    ),
)


class CRLSourceAsn1(univ.Choice):
    """Defines the ASN.1 structure for the `CRLSource`.

    CRLSource ::= CHOICE {
     dpn          [0] DistributionPointName,
     issuer       [1] GeneralNames }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "dpn",
            rfc5280.DistributionPointName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType(
            "issuer", rfc5280.GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        ),
    )


class CRLStatusAsn1(univ.Sequence):
    """Defines the ASN.1 structure for the `CRLStatus`.

    CRLStatus ::= SEQUENCE {
        source CRLSource,
        thisUpdate Time OPTIONAL
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("source", CRLSourceAsn1()), namedtype.OptionalNamedType("thisUpdate", rfc9480.Time())
    )


class CRLStatusListValueAsn1(univ.SequenceOf):
    """Defines the ASN.1 structure for the `CRLStatusListValue`.

    CRLStatusListValue ::= SEQUENCE OF CRLStatus SIZE (1..MAX)
    """

    componentType = CRLStatusAsn1()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class CertProfileValueAsn1(univ.SequenceOf):
    """Defines the ASN.1 structure for the `CertProfileValue`."""

    componentType = char.UTF8String()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


# MUST be 2 characters.
class X520countryNameASN1(char.PrintableString):
    """Defines the ASN.1 structure for the `X520countryName`."""

    size_max = 2
    size_min = 2


# To remove the value size constraint, of 1.
class EmailAddressASN1(char.IA5String):
    """Defines the ASN.1 structure for the `EmailAddress`."""

    size_min = 1
    size_max = rfc5280.ub_emailaddress_length


# To remove the value size constraint, of 1.
class X520SerialNumberASN1(char.PrintableString):
    """Defines the ASN.1 structure for the `X520SerialNumber`."""

    size_min = 1
    size_max = rfc5280.ub_serial_number


class X520nameASN1(univ.Choice):
    """Defines the ASN.1 structure for the `X520name`."""

    size_min = 1
    size_max = rfc5280.ub_name


X520nameASN1.componentType = namedtype.NamedTypes(
    namedtype.NamedType("teletexString", char.TeletexString()),
    namedtype.NamedType("printableString", char.PrintableString()),
    namedtype.NamedType("universalString", char.UniversalString()),
    namedtype.NamedType("utf8String", char.UTF8String()),
    namedtype.NamedType("bmpString", char.BMPString()),
)


class X520PseudonymASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520Pseudonym`."""

    size_max = rfc5280.ub_pseudonym


class X520TitleASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520Title`."""

    size_max = rfc5280.ub_title


class X520BusinessCategoryASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520BusinessCategory`."""

    size_max = ub_business_category


class X520PostalCodeASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520PostalCode`."""

    size_max = ub_postal_code


class X520StreetAddressASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520StreetAddress`."""

    size_max = ub_street_address


class X520OrganizationalUnitNameASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520OrganizationalUnitName`."""

    size_max = rfc5280.ub_organizational_unit_name


class X520CommonNameASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520CommonName`."""

    size_max = rfc5280.ub_common_name


class X520LocalityNameASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520LocalityName`."""

    size_max = rfc5280.ub_locality_name


class X520StateOrProvinceNameASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520StateOrProvinceName`."""

    size_max = rfc5280.ub_state_name


class X520OrganizationNameASN1(X520nameASN1):
    """Defines the ASN.1 structure for the `X520OrganizationName`."""

    size_max = rfc5280.ub_organization_name
