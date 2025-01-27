# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 structures for hybrid cryptographic schemes/mechanisms."""

from pyasn1.type import char, constraint, namedtype, tag, univ
from pyasn1_alt_modules import rfc5280, rfc5958
from pyasn1_alt_modules.rfc2315 import IssuerAndSerialNumber
from pyasn1_alt_modules.rfc7906 import BinaryTime


# Define the CompositeKEMPrivateKey as a SequenceOf OCTET STRING
class CompositeKEMPrivateKeyAsn1(univ.SequenceOf):
    """Define the CompositeKEMPrivateKey as a SequenceOf OCTET STRING of size 2."""

    componentType = univ.OctetString()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(2, 2)


# Define CompositeKEMPublicKey as a SequenceOf BIT STRING of size 2
class CompositeKEMPublicKey(univ.SequenceOf):
    """Define CompositeKEMPublicKey as a SequenceOf BIT STRING of size 2."""

    componentType = univ.BitString()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(2, 2)


class XWingPublicKeyASN1(univ.OctetString):
    """XWingPublicKeyASN1 is an OctetString."""

    pass


class CompositeCiphertextValue(univ.SequenceOf):
    """Define CompositeCiphertextValue as a SequenceOf BIT STRING of size 2."""

    componentType = univ.OctetString()
    subtypeSpec = constraint.ValueSizeConstraint(2, float("inf"))


class CompositeKemParams(univ.SequenceOf):
    """Define CompositeKemParams as a SequenceOf AlgorithmIdentifier of size 2."""

    componentType = rfc5280.AlgorithmIdentifier()
    subtypeSpec = constraint.ValueSizeConstraint(2, float("inf"))


# https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html#name-certificate-conventions
#  Section 5.1. CompositeSignaturePublicKey


class CompositeSignaturePrivateKeyAsn1(univ.SequenceOf):
    """Define CompositeSignaturePrivateKeyAsn1 as a SequenceOf OneAsymmetricKey of size 2."""

    componentType = rfc5958.OneAsymmetricKey()
    subtypeSpec = constraint.ValueSizeConstraint(2, 2)


class CompositeSignaturePublicKeyAsn1(univ.SequenceOf):
    """Define CompositeSignaturePublicKeyAsn1 as a SequenceOf BIT STRING of size 2."""

    componentType = univ.BitString()
    subtypeSpec = constraint.ValueSizeConstraint(2, 2)


class CompositeSignatureValue(univ.SequenceOf):
    """Define CompositeSignatureValue as a SequenceOf BIT STRING of size 2."""

    componentType = univ.BitString()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(2, 2)


# Used for the Sun-Hybrid-Signature methode.
class UniformResourceIdentifier(char.IA5String):
    """ASN.1 Definition of the `UniformResourceIdentifier` structure.

    UniformResourceIdentifier ::= IA5String
    """

    pass


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


# Used for the cert-discovery methode.
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

    pass


# Used for the cert-binding-for-multiple-authentication methode.


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

    pass


# Used for the Chameleon Signature methode.


class DeltaCertificateDescriptor(univ.Sequence):
    """ASN.1 Definition of the `DeltaCertificateDescriptor` structure.

    DeltaCertificateDescriptor ::= SEQUENCE {
        serialNumber CertificateSerialNumber,
        signature [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
        issuer [1] IMPLICIT Name OPTIONAL,
        validity [2] IMPLICIT Validity OPTIONAL,
        subject [3] IMPLICIT Name OPTIONAL,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        extensions [4] IMPLICIT Extensions OPTIONAL,
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
        subject [0] IMPLICIT Name OPTIONAL,
        subjectPKInfo SubjectPublicKeyInfo,
        extensions [1] IMPLICIT Extensions OPTIONAL,
        signatureAlgorithm [2] IMPLICIT AlgorithmIdentifier OPTIONAL
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

    pass
