# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field
from typing import List, Optional

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402

from unit_tests.asn1_wrapper_class.base import Asn1Wrapper


@dataclass(repr=False)
class SubjectPublicKeyInfo(Asn1Wrapper):
    """
    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm           AlgorithmIdentifier,
        subjectPublicKey    BIT STRING
    }
    """

    algorithm: rfc5280.AlgorithmIdentifier
    subjectPublicKey: univ.BitString

    def encode(self):
        seq = univ.Sequence()
        seq.setComponentByPosition(0, self.algorithm)
        seq.setComponentByPosition(1, self.subjectPublicKey)

        return encoder.encode(seq)


    @staticmethod
    def from_pyasn1(decoded: rfc5280.SubjectPublicKeyInfo) -> 'SubjectPublicKeyInfo':
        """

        :param decoded: The raw ASN.1 DER encoded certificate or request.
        :return: The CertificationRequestInfo object.
        """
        algorithm = decoded[0]  # This should be the AlgorithmIdentifier
        subject_public_key = decoded[1]  # This should be the BIT STRING

        # Create and return the SubjectPublicKeyInfo object
        return SubjectPublicKeyInfo(
            algorithm=algorithm,
            subject_public_key=subject_public_key
        )


    @staticmethod
    def from_der_bytes(data: bytes) -> 'SubjectPublicKeyInfo':
        """
        Deserialize the SubjectPublicKeyInfo from an ASN.1 DER encoded data.

        :param data: The raw ASN.1 DER encoded SubjectPublicKeyInfo structure.
        :return: The SubjectPublicKeyInfo object.
        """
        decoded, _ = decoder.decode(data)
        return SubjectPublicKeyInfo.from_pyasn1(decoded)




@dataclass(repr=False)
class CertificationRequestInfo(Asn1Wrapper):
    """
    CertificationRequestInfo ::= SEQUENCE {
        version             INTEGER,
        subject             Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        attributes          [0] IMPLICIT SET OF Attribute
    }
    """

    version: int
    subject: rfc5280.Name
    spki: SubjectPublicKeyInfo
    attributes: List[rfc5652.Attribute] = field(default_factory=list)


    def to_pyasn1(self) -> univ.Sequence:
        seq = univ.Sequence()
        seq.setComponentByPosition(0, univ.Integer(self.version))
        seq.setComponentByPosition(1, self.subject)
        seq.setComponentByPosition(2, self.subject_public_key_info)
        seq.setComponentByPosition(3, self.attributes)
        return seq


    @staticmethod
    def from_der_bytes(data: bytes) -> 'CertificationRequestInfo':
        decoded, _ = decoder.decode(data)
        return CertificationRequestInfo.from_pyasn1(decoded)

    @staticmethod
    def from_pyasn1(data: univ.Sequence) -> 'CertificationRequestInfo':
        """

        :param data: The raw ASN.1 DER encoded certificate or request.
        :return: The CertificationRequestInfo object.
        """
        version = int(data[0])
        subject = data[1]
        attributes = data.getComponentByPosition(3, default=[]) or []

        return CertificationRequestInfo(
            version=version,
            subject=subject,
            subject_public_key_info=SubjectPublicKeyInfo.from_pyasn1(data[2]),
            attributes=[attr for attr in attributes]
        )

    def encode(self) -> bytes:
        sequence = univ.Sequence()

        sequence.setComponentByPosition(0, univ.Integer(self.version))
        sequence.setComponentByPosition(1, self.subject)

        if self.subject_public_key_info:
            sequence.setComponentByPosition(2, self.subject_public_key_info.encode())

        if self.attributes:
            sequence.setComponentByPosition(3, univ.Set(self.attributes))
        else:
            sequence.setComponentByPosition(3, univ.Set())

        return encoder.encode(sequence)

@dataclass(repr=False)
class CertificationRequest(Asn1Wrapper):
    """
    CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm       AlgorithmIdentifier,
        signature                BIT STRING
    }
    """

    certificationRequestInfo: Optional[CertificationRequestInfo] = None
    signatureAlgorithm: Optional[rfc5280.AlgorithmIdentifier] = None
    signature: Optional[univ.BitString] = None

    def encode(self) -> bytes:

        data = b""
        if self.certificationRequestInfo is not None:
            data += self.certificationRequestInfo.encode()

        if self.signatureAlgorithm is not None:
            data += encoder.encode(self.signatureAlgorithm)

        if self.signature is not None:
            data += encoder.encode(self.signature)


        return data

    def from_der(self, data: bytes) -> None:
        obj, _ = decoder.decode(data, rfc6402.CertificationRequest())
        if obj["certificationRequestInfo"].isValue:
            self.certificationRequestInfo = CertificationRequestInfo.from_pyasn1(encoder.encode())



if __name__ == "__main__":

    version = 2
    subject = rfc5280.Name()
    algorithm = rfc5280.AlgorithmIdentifier()
    subjectPublicKey = univ.BitString('01010101')
    spki = SubjectPublicKeyInfo(algorithm=algorithm, subjectPublicKey=subjectPublicKey)


    breakpoint()
    cert_req_info = CertificationRequestInfo(version=version, subject=subject, subject_public_key_info=spki)

    signature_algorithm = rfc5280.AlgorithmIdentifier()
    signature = univ.BitString('0101010101010101')

    cert_request = CertificationRequest(
        certificationRequestInfo=cert_req_info,
        signatureAlgorithm=signature_algorithm,
        signature=signature
    )

    der_encoded_cert_request = cert_request.encode()
    print(f"DER Encoded CertificationRequest: {der_encoded_cert_request.hex()}")

    new_cert_request = CertificationRequest()
    new_cert_request.from_der(der_encoded_cert_request)
    print(f"Decoded CertificationRequest: {new_cert_request}")
