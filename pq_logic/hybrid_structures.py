# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=too-few-public-methods
"""ASN.1 structures for hybrid cryptographic schemes/mechanisms."""

from pyasn1.type import char, constraint, namedtype, tag, univ
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules.rfc2315 import IssuerAndSerialNumber
from pyasn1_alt_modules.rfc7906 import BinaryTime


# Used for the Sun-Hybrid-Signature method.
class UniformResourceIdentifier(char.IA5String):
    """ASN.1 Definition of the `UniformResourceIdentifier` structure.

    UniformResourceIdentifier ::= IA5String
    """


class AltSubPubKeyExt(univ.Sequence):
    """ASN.1 Definition of the `AltSubPubKeyExt` structure.

    AltSubPubKeyExt ::= SEQUENCE {
        byVal BOOLEAN DEFAULT FALSE,
        plainOrHash BIT STRING,
        altAlgorithm AlgorithmIdentifier,
        hashAlg AlgorithmIdentifier OPTIONAL,
        location IA5String OPTIONAL
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType("byVal", univ.Boolean(False)),
        namedtype.NamedType("plainOrHash", univ.BitString()),
        namedtype.NamedType("altAlgorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType("hashAlg", rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType("location", UniformResourceIdentifier()),
    )


class AltSignatureExt(univ.Sequence):
    """ASN.1 Definition of the `AltSignatureExt` structure.

    AltSignatureExt ::= SEQUENCE {
        byVal BOOLEAN DEFAULT FALSE,
        plainOrHash BIT STRING,
        altSigAlgorithm AlgorithmIdentifier,
        hashAlg AlgorithmIdentifier OPTIONAL,
        location IA5String OPTIONAL
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType("byVal", univ.Boolean(False)),
        namedtype.NamedType("plainOrHash", univ.BitString()),
        namedtype.NamedType("altSigAlgorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType("hashAlg", rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType("location", UniformResourceIdentifier()),
    )


# Used for the cert-discovery method.
class RelatedCertificateDescriptor(univ.Sequence):
    """ASN.1 Definition of the `RelatedCertificateDescriptor` structure.

    RelatedCertificateDescriptor ::= SEQUENCE {
           uniformResourceIdentifier IA5String,
           signatureAlgorithm   [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
           publicKeyAlgorithm   [1] IMPLICIT AlgorithmIdentifier OPTIONAL
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("uniformResourceIdentifier", char.IA5String()),
        namedtype.OptionalNamedType(
            "signatureAlgorithm",
            rfc5280.AlgorithmIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.OptionalNamedType(
            "publicKeyAlgorithm",
            rfc5280.AlgorithmIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
        ),
    )


class OnRelatedCertificateDescriptor(rfc5280.AnotherName):
    """ASN.1 Definition of the `OnRelatedCertificateDescriptor` structure.

    OnRelatedCertificateDescriptor ::= SEQUENCE {
           type-id OBJECT IDENTIFIER,
           value RelatedCertificateDescriptor
    """


# Used for the cert-binding-for-multiple-authentication method.


class RequesterCertificate(univ.Sequence):
    """ASN.1 Definition of the `RequesterCertificate` structure.

    RequesterCertificate ::= SEQUENCE {
        certID IssuerAndSerialNumber,
        requestTime BinaryTime,
        locationInfo IA5String,
        signature BIT STRING
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certID", IssuerAndSerialNumber()),
        namedtype.NamedType("requestTime", BinaryTime()),
        namedtype.NamedType("locationInfo", UniformResourceIdentifier()),
        namedtype.NamedType("signature", univ.BitString()),
    )


class RelatedCertificate(univ.OctetString):
    """ASN.1 Definition of the `RelatedCertificate` structure.

    RelatedCertificate ::= OCTET STRING
    (hash of entire related certificate)
    """


# Used for the Chameleon Signature method.


class DeltaCertificateDescriptor(univ.Sequence):
    """ASN.1 Definition of the `DeltaCertificateDescriptor` structure.

    DeltaCertificateDescriptor ::= SEQUENCE {
        serialNumber CertificateSerialNumber,
        signature [0] EXPLICIT AlgorithmIdentifier OPTIONAL,
        issuer [1] EXPLICIT Name OPTIONAL,
        validity [2] EXPLICIT Validity OPTIONAL,
        subject [3] EXPLICIT Name OPTIONAL,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        extensions [4] EXPLICIT Extensions OPTIONAL,
        signatureValue BIT STRING
    }

    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("serialNumber", rfc5280.CertificateSerialNumber()),
        namedtype.OptionalNamedType(
            "signature",
            rfc5280.AlgorithmIdentifier().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
        namedtype.OptionalNamedType(
            "issuer", rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        ),
        namedtype.OptionalNamedType(
            "validity",
            rfc5280.Validity().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)),
        ),
        namedtype.OptionalNamedType(
            "subject", rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        ),
        namedtype.NamedType("subjectPublicKeyInfo", rfc5280.SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType(
            "extensions",
            rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)),
        ),
        namedtype.NamedType("signatureValue", univ.BitString()),
    )


class DeltaCertificateRequestValue(univ.Sequence):
    """ASN.1 Definition of the `DeltaCertificateRequestValue` structure.

    DeltaCertificateRequestValue ::= SEQUENCE {
        subject [0] EXPLICIT Name OPTIONAL,
        subjectPKInfo SubjectPublicKeyInfo,
        extensions [1] EXPLICIT Extensions OPTIONAL,
        signatureAlgorithm [2] EXPLICIT AlgorithmIdentifier OPTIONAL
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "subject", rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        ),
        namedtype.NamedType("subjectPKInfo", rfc5280.SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType(
            "extensions",
            rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
        namedtype.OptionalNamedType(
            "signatureAlgorithm",
            rfc5280.AlgorithmIdentifier().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
            ),
        ),
    )


class DeltaCertificateRequestSignatureValue(univ.BitString):
    """ASN.1 Definition of the `DeltaCertificateRequestSignatureValue` structure.

    DeltaCertificateRequestSignatureValue ::= BIT STRING
    """


# Catalyst X.509 Certificate Extension Classes.


class SubjectAltPublicKeyInfoExt(rfc5280.SubjectPublicKeyInfo):
    """Extension for alternative public key information."""


class AltSignatureAlgorithmExt(rfc5280.AlgorithmIdentifier):
    """Extension for alternative signature algorithm."""


class AltSignatureValueExt(univ.BitString):
    """Extension for alternative signature value."""


def _OctetStringFixed(size: int):
    """Create a fixed-size OctetString with a specific size."""
    return univ.OctetString().subtype(subtypeSpec=constraint.ValueSizeConstraint(size, size))


class BothMLDSA44(univ.Sequence):
    """ASN.1 Definition of the `BothMLDSA44` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(32)), namedtype.NamedType("expandedKey", _OctetStringFixed(2560))
    )


class BothMLDSA65(univ.Sequence):
    """ASN.1 Definition of the `BothMLDSA65` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(32)), namedtype.NamedType("expandedKey", _OctetStringFixed(4032))
    )


class BothMLDSA87(univ.Sequence):
    """ASN.1 Definition of the `BothMLDSA87` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(32)), namedtype.NamedType("expandedKey", _OctetStringFixed(4896))
    )


class MLDSA44PrivateKeyASN1(univ.Choice):
    """ASN.1 Definition of the `MLDSA44PrivateKey` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed", _OctetStringFixed(32).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(2560)),
        namedtype.NamedType("both", BothMLDSA44()),
    )


class MLDSA65PrivateKeyASN1(univ.Choice):
    """ASN.1 Definition of the `MLDSA65PrivateKey` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed", _OctetStringFixed(32).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(4032)),
        namedtype.NamedType("both", BothMLDSA65()),
    )


class MLDSA87PrivateKeyASN1(univ.Choice):
    """ASN.1 Definition of the `MLDSA87PrivateKey` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed", _OctetStringFixed(32).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(4896)),
        namedtype.NamedType("both", BothMLDSA87()),
    )


class BothMLKEM512(univ.Sequence):
    """ASN.1 Definition of the `BothMLKEM512` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(64)), namedtype.NamedType("expandedKey", _OctetStringFixed(1632))
    )


class BothMLKEM768(univ.Sequence):
    """ASN.1 Definition of the `BothMLKEM768` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(64)), namedtype.NamedType("expandedKey", _OctetStringFixed(2400))
    )


class BothMLKEM1024(univ.Sequence):
    """ASN.1 Definition of the `BothMLKEM1024` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(64)), namedtype.NamedType("expandedKey", _OctetStringFixed(3168))
    )


class MLKEM512PrivateKeyASN1(univ.Choice):
    """ASN.1 Definition of the `MLKEM512PrivateKey` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed", _OctetStringFixed(64).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(1632)),
        namedtype.NamedType("both", BothMLKEM512()),
    )


class MLKEM768PrivateKeyASN1(univ.Choice):
    """ASN.1 Definition of the `MLKEM768PrivateKey` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed", _OctetStringFixed(64).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(2400)),
        namedtype.NamedType("both", BothMLKEM768()),
    )


class MLKEM1024PrivateKeyASN1(univ.Choice):
    """ASN.1 Definition of the `MLKEM1024PrivateKey` structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed", _OctetStringFixed(64).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(3168)),
        namedtype.NamedType("both", BothMLKEM1024()),
    )
