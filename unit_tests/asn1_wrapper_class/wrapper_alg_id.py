# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Union

from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pq_logic.keys.abstract_pq import PQKEMPrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import constraint, namedtype, tag, univ
from pyasn1_alt_modules import rfc3370, rfc5280, rfc5480, rfc5990, rfc8018, rfc9480, rfc9481
from resources import cryptoutils
from resources.oid_mapping import hash_name_to_instance
from resources.oidutils import HKDF_NAME_2_OID, HMAC_OID_2_NAME, id_KemBasedMac

from unit_tests.asn1_wrapper_class.base import Asn1Wrapper

hash_algs = univ.ObjectIdentifier("2.16.840.1.101.3.4.2")
MAX_VALUE = float("inf")

SHA3_NAME_2_OID = {
    # As specified in rfc9688 section 2.
    "sha3-224": hash_algs + (7,),
    "sha3-256": hash_algs + (8,),
    "sha3-384": hash_algs + (9,),
    "sha3-512": hash_algs + (10,),
}

ALG_ID_NAME_2_OIDS = {
    "sha1": rfc5480.id_sha1,
    "sha224": rfc5480.id_sha224,
    "sha256": rfc5480.id_sha256,
    "sha384": rfc5480.id_sha384,
    "sha512": rfc5480.id_sha512,

    "hmac-sha1": rfc3370.hMAC_SHA1,
    "hmac-sha224": rfc9481.id_hmacWithSHA224,
    "hmac-sha256": rfc9481.id_hmacWithSHA256,
    "hmac-sha384": rfc9481.id_hmacWithSHA384,
    "hmac-sha512": rfc9481.id_hmacWithSHA512,

    "aes128_gmac": rfc9481.id_aes128_GMAC,
    "aes192_gmac": rfc9481.id_aes192_GMAC,
    "aes256_gmac": rfc9481.id_aes256_GMAC,
    "aes-gmac": rfc9481.id_aes256_GMAC,
    "aes_gmac": rfc9481.id_aes256_GMAC,

    "password_based_mac": rfc9480.id_PasswordBasedMac,
    "pbmac1": rfc8018.id_PBMAC1,

    "dh_based_mac": rfc9480.id_DHBasedMac,

    "kmac-shake128": rfc9481.id_KMACWithSHAKE128,
    "kmac-shake256": rfc9481.id_KMACWithSHAKE256,

    # # As specified in rfc9688 section 4.
    "hmac-sha3-224": hash_algs + (13,),
    "hmac-sha3-256": hash_algs + (14,),
    "hmac-sha3-384": hash_algs + (15,),
    "hmac-sha3-512": hash_algs + (16,),

    "pbkdf2": rfc9481.id_PBKDF2,
    "kdf2": rfc5990.id_kdf_kdf2,
    "kdf3": rfc5990.id_kdf_kdf3,

    "kem_based_mac": id_KemBasedMac
}

ALG_ID_NAME_2_OIDS.update(HKDF_NAME_2_OID)

ALG_ID_OID_2_NAME = {y:x for x,y in ALG_ID_NAME_2_OIDS.items()}


@dataclass(repr=False)
class Parameters(Asn1Wrapper):
    """
    A base class for cryptographic parameter structures.
    Includes a default 'unsafe' boolean value, set to False.
    """

    unsafe: bool = field(init=False, default=False)

    def encode(self) -> bytes:
        """
        Encode the Parameters structure to DER format.
        To be overridden by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @classmethod
    def from_der(cls, data: bytes) -> "Parameters":
        """
        Decode the Parameters structure from DER-encoded data.
        To be overridden by subclasses.

        :param data: DER-encoded data.
        :return: Parameters instance.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @abstractmethod
    def equal(self, other: "Parameters", exclude_salt: bool = True) -> bool:
        """
        Compare two Parameters objects for equality.
        To be implemented by subclasses.

        :param other: Another Parameters object.
        :param exclude_salt: Option to exclude salt during comparison.
        :return: True if equal, False otherwise.
        """
        pass

@dataclass(repr=False)
class AlgorithmIdentifier(Asn1Wrapper):
    """
    AlgorithmIdentifier ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters ANY DEFINED BY algorithm OPTIONAL
    }
    """

    algorithm: str
    parameters: Optional[Parameters] = None
    use_null: bool = field(init=False, default=False)

    def encode(self) -> bytes:
        """
        Encode the AlgorithmIdentifier structure to DER format.

        :return: DER-encoded AlgorithmIdentifier.
        """
        data = b""

        algorithm_oid = ALG_ID_NAME_2_OIDS[self.algorithm]
        data += encoder.encode(algorithm_oid)

        if self.parameters is None and not self.use_null:
            pass  # No parameters and no NULL placeholder
        elif self.parameters is None and self.use_null:
            data += encoder.encode(univ.Null(""))
        elif isinstance(self.parameters, Parameters):
            data += self.parameters.encode()
        elif isinstance(self.parameters, AlgorithmIdentifier):
            data += self.parameters.encode()
        elif isinstance(self.parameters, bytes):
            data += encoder.encode(univ.Any(self.parameters))
        else:
            raise TypeError(f"Invalid type for parameters: {type(self.parameters)}")

        return self.get_size(data)

    @classmethod
    def from_alg_id(cls, asn1_object: rfc9480.AlgorithmIdentifier) -> "AlgorithmIdentifier":
        algorithm = asn1_object['algorithm']
        name = ALG_ID_OID_2_NAME[algorithm]
        parameters = None
        if  asn1_object["parameters"].isValue:
            if isinstance(parameters, univ.Any):
                parameters = asn1_object["parameters"].asOctets()
            else:
                parameters = encoder.encode(asn1_object["parameters"])

        return cls(algorithm=name, parameters=parameters)


    @classmethod
    def from_der(cls, data: bytes) -> "AlgorithmIdentifier":
        """
        Decode the AlgorithmIdentifier structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: AlgorithmIdentifier instance.
        """
        asn1_object, _ = decoder.decode(data, rfc5280.AlgorithmIdentifier())

        algorithm = asn1_object['algorithm']
        name = ALG_ID_OID_2_NAME[algorithm]

        parameters_data = asn1_object["parameters"].isValue
        parameters = None
        if parameters_data:
            parameters = encoder.encode(parameters_data)

        return cls(algorithm=name, parameters=parameters)

    def equal(self, other: "AlgorithmIdentifier", exclude_salt: bool = False, allow_null: bool = False, exclude_nonce: bool = False) -> bool:
        """
        Compare two AlgorithmIdentifier objects for equality.

        :param other: Another AlgorithmIdentifier to compare.
        :param exclude_salt: Compare without the salt parameter.
        :param allow_null: A boolean indicating if null is the same as absent.
        :param exclude_nonce: Compare without the nonce parameter.
        :return: True if equal, False otherwise.
        """
        if self.algorithm != other.algorithm:
            return False

        if allow_null:
            if (self.parameters is None or self.parameters == univ.Null("")) and \
                    (other.parameters is None or other.parameters == univ.Null("")):
                return True

        if self.parameters is None and other.parameters is None:
            return True

        if (self.parameters is None) != (other.parameters is None):
            return False

        if isinstance(self.parameters, Parameters) and isinstance(other.parameters, Parameters):
            self_params = vars(self.parameters)
            other_params = vars(other.parameters)

            if exclude_salt:
                self_params = {k: v for k, v in self_params.items() if k != "salt"}
                other_params = {k: v for k, v in other_params.items() if k != "salt"}

            if exclude_nonce:
                self_params = {k: v for k, v in self_params.items() if k != "nonce"}
                other_params = {k: v for k, v in other_params.items() if k != "nonce"}

            return self_params == other_params

        return self.parameters == other.parameters

@dataclass(repr=False)
class MACAlgorithmIdentifier(AlgorithmIdentifier):
    def compute(self, data: bytes, key: bytes) -> bytes:
        """
        Compute the result based on the algorithm type.
        :param data: The input data to process.
        :param key: The key to use for the operation.
        :return: The computed result as bytes.
        """
        raise NotImplementedError(f"Compute not implemented for algorithm {self.algorithm}")


@dataclass(repr=False)
class KDFAlgorithmIdentifier(AlgorithmIdentifier):
    def compute(self, key: bytes, length: int, **params) -> bytes:
        raise NotImplementedError(f"Compute not implemented for algorithm {self.algorithm}")

@dataclass(repr=False)
class SHAAlgID(MACAlgorithmIdentifier):
    def compute(self, data: bytes) -> bytes:
        if self.algorithm not in ["sha256", "sha1", "sha512"]:
            raise ValueError(f"Unsupported SHA algorithm: {self.algorithm}")
        return cryptoutils.compute_hash(alg_name=self.algorithm, data=data)

class HMACAlgID(MACAlgorithmIdentifier):
    def compute(self, data: bytes, key: bytes) -> bytes:
        hash_alg = HMAC_OID_2_NAME[self.algorithm].split("-")[1]
        return cryptoutils.compute_hmac(data=data, key=key, hash_alg=hash_alg)

@dataclass(repr=False)
class KMACAlgorithmIdentifier(MACAlgorithmIdentifier):
    def compute(self, data: bytes, key: bytes) -> bytes:
        return cryptoutils.compute_kmac_from_alg_id(alg_id=self, data=data, key=key)

@dataclass(repr=False)
class PBKDF2Params(Parameters):
    """
    PBKDF2_params ::= SEQUENCE {
        salt                CHOICE {
            specified       OCTET STRING,
            otherSource     AlgorithmIdentifier
        },
        iterationCount      INTEGER (1..MAX),
        keyLength           INTEGER (1..MAX) OPTIONAL,
        prf                 AlgorithmIdentifier DEFAULT algid_hmacWithSHA1
    }
    """

    salt: Union[bytes, AlgorithmIdentifier]
    iterationCount: int
    keyLength: Optional[int] = None
    prf: AlgorithmIdentifier = field(default_factory=lambda: AlgorithmIdentifier(
        algorithm="hmac-sha1"
    ))

    def encode(self) -> bytes:
        """
        Encode the PBKDF2Params structure to DER format.

        :return: DER-encoded PBKDF2Params.
        """
        pbkdf2_params = rfc8018.PBKDF2_params()
        if isinstance(self.salt, bytes):
            pbkdf2_params["salt"]["specified"] = univ.OctetString(self.salt)
        else:
            pbkdf2_params["salt"]["otherSource"] = decoder.decode(self.salt.encode())[0]

        pbkdf2_params["iterationCount"] = self.iterationCount

        if self.keyLength is not None:
            pbkdf2_params["keyLength"] = self.keyLength

        pbkdf2_params["prf"] = decoder.decode(self.prf.encode())[0]

        return encoder.encode(pbkdf2_params)

    @classmethod
    def from_der(cls, data: bytes) -> "PBKDF2Params":
        """
        Decode the PBKDF2Params structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: PBKDF2Params instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc8018.PBKDF2_params())
        salt_component = asn1_object["salt"]
        if "specified" == salt_component.getName():
            salt = bytes(salt_component["specified"])
        else:
            salt = AlgorithmIdentifier.from_alg_id(salt_component["otherSource"])

        iteration_count = int(asn1_object["iterationCount"])
        key_length = int(asn1_object["keyLength"]) if asn1_object["keyLength"].isValue else None
        prf = AlgorithmIdentifier.from_alg_id(asn1_object["prf"])
        return cls(salt=salt, iterationCount=iteration_count, keyLength=key_length, prf=prf)

@dataclass(repr=False)
class PBKDF2AlgId(KDFAlgorithmIdentifier):
    """
    PBKDF2AlgId ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters PBKDF2Params
    }
    """

    algorithm: str = field(init=False, default="pbkdf2")
    parameters: PBKDF2Params

    def encode(self) -> bytes:
        """
        Encode the PBKDF2AlgId structure to DER format.

        :return: DER-encoded PBKDF2AlgId.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_PBKDF2
        alg_id["parameters"] = decoder.decode(self.parameters.encode())[0]
        return encoder.encode(alg_id)

    @classmethod
    def from_der(cls, data: bytes) -> "PBKDF2AlgId":
        """
        Decode the PBKDF2AlgId structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: PBKDF2AlgId instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc5280.AlgorithmIdentifier())

        # Extract algorithm OID
        algorithm_oid = asn1_object["algorithm"]
        if algorithm_oid != rfc9481.id_PBKDF2:
            raise ValueError("Algorithm OID does not match PBKDF2")

        # Decode parameters
        parameters_data = asn1_object["parameters"].asOctets()
        parameters = PBKDF2Params.from_der(parameters_data)

        return cls(parameters=parameters)



@dataclass(repr=False)
class PBMParameter(Parameters):
    """
    PBMParameter ::= SEQUENCE {
         salt                OCTET STRING,
         owf                 AlgorithmIdentifier,
         iterationCount      INTEGER,
         mac                 AlgorithmIdentifier
    }
    """

    salt: bytes  # with a constraint of 0-128 bytes, to be validated during instantiation
    owf: AlgorithmIdentifier
    iterationCount: int
    mac: AlgorithmIdentifier

    def __post_init__(self):
        if not self.unsafe:
            # Validate the salt size constraint (0 to 128 bytes)
            if not (0 <= len(self.salt) <= 128):
                raise ValueError("salt must be between 0 and 128 bytes")

    def encode(self) -> bytes:
        """Encode the PBMParameter structure to DER format.

        :return: DER-encoded PBMParameter.
        """
        pbm_param = rfc9480.PBMParameter()
        pbm_param["salt"] = univ.OctetString(self.salt).subtype(subtypeSpec=constraint.ValueSizeConstraint(0, 128))
        pbm_param["iterationCount"] = self.iterationCount
        pbm_param["owf"] = decoder.decode(self.owf.encode())[0]
        pbm_param["mac"] = decoder.decode(self.mac.encode())[0]
        return encoder.encode(pbm_param)

    @classmethod
    def from_der(cls, data: bytes) -> "PBMParameter":
        """
        Decode the PBMParameter structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: PBMParameter instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc9480.PBMParameter())
        salt = asn1_object["salt"].asOctets()
        iteration_count = int(asn1_object["iterationCount"])
        owf = AlgorithmIdentifier.from_alg_id(asn1_object["owf"])
        mac = AlgorithmIdentifier.from_alg_id(asn1_object["mac"])

        return cls(salt=salt, iterationCount=iteration_count, owf=owf, mac=mac)

@dataclass(repr=False)
class PasswordBasedMac(MACAlgorithmIdentifier):
    """
    PasswordBasedMac is a specialization of AlgorithmIdentifier used for password-based MAC algorithms.
    """

    algorithm: str = field(init=False, default="password_based_mac")
    parameters: PBMParameter

    @classmethod
    def from_der(cls, data: bytes) -> "PasswordBasedMac":
        """Decode the PasswordBasedMac structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: PasswordBasedMac instance.

        """
        alg_id, _ = decoder.decode(data, rfc9480.AlgorithmIdentifier())
        if ALG_ID_OID_2_NAME[alg_id["algorithm"]] != cls.algorithm:
            raise ValueError(f"The algorithm Identifier was not password_based_mac: but:{ALG_ID_OID_2_NAME.get(alg_id, alg_id)}")


        der_data = alg_id["parameters"].asOctets()

        parameters = PBMParameter.from_der(der_data)
        return cls(parameters=parameters)


@dataclass(repr=False)
class PBMAC1Params(Parameters):
    """
    PBMAC1Params ::= SEQUENCE {
        keyDerivationFunc   AlgorithmIdentifier,
        messageAuthScheme   AlgorithmIdentifier
    }
    """

    keyDerivationFunc: AlgorithmIdentifier
    messageAuthScheme: AlgorithmIdentifier

    def encode(self) -> bytes:
        """
        Encode the PBMAC1Params structure to DER format.

        :return: DER-encoded PBMAC1Params.
        """
        pbmac1_params = rfc8018.PBMAC1_params()
        pbmac1_params["keyDerivationFunc"] = decoder.decode(self.keyDerivationFunc.encode())[0]
        pbmac1_params["messageAuthScheme"] = decoder.decode(self.messageAuthScheme.encode())[0]
        return encoder.encode(pbmac1_params)

    @classmethod
    def from_der(cls, data: bytes) -> "PBMAC1Params":
        """
        Decode the PBMAC1Params structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: PBMAC1Params instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc8018.PBMAC1_params())
        key_derivation_func = AlgorithmIdentifier.from_alg_id(asn1_object["keyDerivationFunc"])
        message_auth_scheme = AlgorithmIdentifier.from_alg_id(asn1_object["messageAuthScheme"])
        return cls(keyDerivationFunc=key_derivation_func, messageAuthScheme=message_auth_scheme)

@dataclass(repr=False)
class PBMAC1AlgId(MACAlgorithmIdentifier):
    """
    PBMAC1AlgId ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters PBMParameter
    }
    PBMAC1AlgId is a specialization of AlgorithmIdentifier with the algorithm
    preset to PBMAC1 OID and specific parameters of type PBMParameter.
    """

    algorithm: str = field(init=False, default="pbmac1")
    parameters: PBMAC1Params

    @classmethod
    def from_der(cls, data: bytes) -> "PBMAC1AlgId":
        """
        Decode the PBMAC1AlgId structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: PBMAC1AlgId instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc5280.AlgorithmIdentifier())

        algorithm_oid = asn1_object["algorithm"]
        if algorithm_oid != rfc9481.id_PBMAC1:
            raise ValueError("Algorithm OID does not match PBMAC1")

        parameters_data = asn1_object["parameters"].asOctets()
        parameters = PBMAC1Params.from_der(parameters_data)
        return cls(parameters=parameters)

@dataclass(repr=False)
class DHBMParameter(Parameters):
    """
    DHBMParameter ::= SEQUENCE {
         owf                 AlgorithmIdentifier,
         mac                 AlgorithmIdentifier
    }
    """

    owf: AlgorithmIdentifier
    mac: AlgorithmIdentifier

    def encode(self) -> bytes:
        """
        Encode the DHBMParameter structure to DER format.

        :return: DER-encoded DHBMParameter.
        """
        dhbm_param = univ.Sequence()
        dhbm_param.setComponentByPosition(0, decoder.decode(self.owf.encode())[0])
        dhbm_param.setComponentByPosition(1, decoder.decode(self.mac.encode())[0])
        return encoder.encode(dhbm_param)

    @classmethod
    def from_der(cls, data: bytes) -> "DHBMParameter":
        """
        Decode the DHBMParameter structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: DHBMParameter instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=univ.Sequence())
        owf = AlgorithmIdentifier.from_der(encoder.encode(asn1_object[0]))
        mac = AlgorithmIdentifier.from_der(encoder.encode(asn1_object[1]))
        return cls(owf=owf, mac=mac)

@dataclass(repr=False)
class DHBasedMac(MACAlgorithmIdentifier):
    """
    DHBasedMac is a specialization of AlgorithmIdentifier with parameters of type DHBMParameter.
    """

    algorithm: str = field(init=False, default="dh_based_mac")
    parameters: DHBMParameter

    @classmethod
    def from_der(cls, data: bytes) -> "DHBasedMac":
        """
        Decode the DHBasedMac structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: DHBasedMac instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc5280.AlgorithmIdentifier())
        algorithm_oid = asn1_object["algorithm"]
        if algorithm_oid != univ.ObjectIdentifier("1.2.840.113533.7.66.30"):  # OID for DHBasedMac
            raise ValueError("Algorithm OID does not match DHBasedMac")

        parameters_data = asn1_object["parameters"].asOctets()
        parameters = DHBMParameter.from_der(parameters_data)

        return cls(parameters=parameters)


@dataclass(repr=False)
class GCMParameters(Parameters):
    """
    GCMParameters ::= SEQUENCE {
        nonce OCTET STRING,
        length INTEGER DEFAULT 12
    }
    """

    nonce: bytes
    length: int = 12

    def encode(self) -> bytes:
        """
        Encode the GCMParameters structure to DER format.

        :return: DER-encoded GCMParameters.
        """
        gcm_params = univ.Sequence()
        gcm_params.setComponentByPosition(0, univ.OctetString(self.nonce))
        gcm_params.setComponentByPosition(1, univ.Integer(self.length))
        return encoder.encode(gcm_params)

    @classmethod
    def from_der(cls, data: bytes) -> "GCMParameters":
        """
        Decode the GCMParameters structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: GCMParameters instance.
        """
        asn1_object, _ = decoder.decode(data, asn1Spec=univ.Sequence())
        nonce = bytes(asn1_object.getComponentByPosition(0))
        length = int(asn1_object.getComponentByPosition(1) or 12)
        return cls(nonce=nonce, length=length)

@dataclass(repr=False)
class GMACAlgId(MACAlgorithmIdentifier):
    """
    GMACAlgId ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters GCMParameters
    }
    GMACAlgId is a specialization of AlgorithmIdentifier with the algorithm
    preset to GMAC OIDs and specific parameters of type GCMParameters.
    """

    algorithm: str = field(init=False, default="gmac")
    parameters: Optional[GCMParameters] = None

    @classmethod
    def from_der(cls, data: bytes) -> "GMACAlgId":
        """
        Decode the GMACAlgId structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: GMACAlgId instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc5280.AlgorithmIdentifier())

        algorithm_oid = asn1_object["algorithm"]
        if algorithm_oid not in [rfc9481.id_aes128_GMAC, rfc9481.id_aes192_GMAC, rfc9481.id_aes256_GMAC]:
            raise ValueError("Algorithm OID does not match GMAC")

        params_data = asn1_object["parameters"].asOctets() if asn1_object["parameters"].isValue else None
        parameters = GCMParameters.from_der(data=params_data)
        return cls(parameters=parameters)

    def compute(self, data: bytes, key: bytes) -> bytes:
        if not isinstance(self.parameters, GCMParameters):
            self.parameters = GCMParameters.from_der(self.parameters.encode())
        nonce = self.parameters.nonce
        return cryptoutils.compute_gmac(data=data, key=key, iv=nonce)

@dataclass
class KDF2Params(MACAlgorithmIdentifier):
    pass

@dataclass(repr=False)
class KDF2AlgId(KDFAlgorithmIdentifier):
    """
    KDF2AlgId ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters KDF2Params
    }
    """

    algorithm: str = field(init=False, default="kdf2")
    parameters: KDF2Params

    def __post_init__(self):

        if isinstance(self.parameters, str):
            self.parameters = SHAAlgID(algorithm=self.parameters)

    @classmethod
    def from_der(cls, data: bytes) -> "KDF2AlgId":
        """
        Decode the KDF2AlgId structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: KDF2AlgId instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc5280.AlgorithmIdentifier())

        algorithm_oid = asn1_object["algorithm"]
        if algorithm_oid != rfc5990.id_kdf_kdf2:
            raise ValueError("Algorithm OID does not match KDF2")

        parameters_data = asn1_object["parameters"].asOctets()
        parameters = KDF2Params.from_der(parameters_data)

        return cls(parameters=parameters)

    def compute(self, key, length, other_info: Optional[bytes] = None, alg_name: Optional[str] = None):
        """Compute the KDF2

        :param key: The key material.
        :param length: The length of the to derive key.
        :param other_info: The other information.
        :param alg_name: The hash algorithm to use (e.g, "sha256").
        Defaults to `parameters` algorithm name.
        :return:
        """
        hash_name = self.parameters.algorithm or alg_name
        alg_id = SHAAlgID(hash_name)
        counter = 1
        keying_material = b""

        # KDF2 K(i) = Hash (Z || D || otherInfo)

        while len(keying_material) < length:
            counter_bytes = counter.to_bytes(4, byteorder="big")
            keying_material += alg_id.compute(data=key + counter_bytes + other_info)
            counter += 1

        return keying_material[:length]


        kdf = ConcatKDFHash(hash_name_to_instance(alg_name or self.parameters.algorithm),
                            length=length,
                            otherinfo=other_info
                            )

        return kdf.derive(key_material=key)

@dataclass(repr=False)
class HKDFAlgID(KDFAlgorithmIdentifier):

    def compute(self, key: bytes, salt: bytes, length: int,
                other_info: Optional[bytes]= None,
                hash_alg: Optional[str] = None):
        """Derive key material using HKDF with the specified parameters.

        :param key: Input key material (IKM) for key derivation.
        :param salt: Non-secret random value to randomize the HKDF, ideally the same length as the hash output.
        :param other_info: Application-specific context or additional information (info). Defaults to None.
        :param length: Desired length of the output key material (OKM) in bytes.
        :param hash_alg: Optional override for the hash algorithm (e.g., "sha256", "sha384", "sha512").
                          Used for testing unsupported or mismatched algorithms. Defaults to the class's algorithm.

        :return: Derived key material as bytes.
        :raises ValueError: If the hash algorithm is unsupported or input parameters are invalid.
        """
        hash_fun = hash_name_to_instance(hash_alg or self.algorithm.split("-")[1])
        hkdf = HKDF(
            algorithm=hash_fun,
            length=length,
            salt=salt,
            info=other_info,
        )
        return hkdf.derive(key)

@dataclass(repr=False)
class KDF3Params(MACAlgorithmIdentifier):
    pass

@dataclass(repr=False)
class KDF3AlgId(KDFAlgorithmIdentifier):
    """
    KDF3AlgId ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters KDF3Params
    }
    """

    algorithm: str = field(init=False, default="kdf3")
    parameters: KDF3Params

    def __post_init__(self):

        if isinstance(self.parameters, str):
            self.parameters = SHAAlgID(algorithm=self.parameters)

    @classmethod
    def from_der(cls, data: bytes) -> "KDF3AlgId":
        """
        Decode the KDF3AlgId structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: KDF3AlgId instance.
        """
        asn1_object, rest = decoder.decode(data, asn1Spec=rfc5280.AlgorithmIdentifier())

        algorithm_oid = asn1_object["algorithm"]
        if algorithm_oid != rfc5990.id_kdf_kdf3:
            raise ValueError("Algorithm OID does not match KDF3")

        parameters_data = asn1_object["parameters"].asOctets()
        parameters = KDF3Params.from_der(parameters_data)

        return cls(parameters=parameters)

    def compute(self,
                shared_secret: bytes,
                key_length: int,
                der_other_info: bytes,
                hash_alg: Optional[str] = None,
                ) -> bytes:
        """Generate keying material using the ANSI X9.63 KDF.

        :param shared_secret: Shared secret from ECDH, as bytes.
        :param key_length: Desired length of the KEK in bytes.
        :param der_other_info: DER-encoded `ECC-CMS-SharedInfo` or `MQVuserKeyingMaterial` structure
        or other info.
        :param hash_alg: Hash algorithm to use. Defaults to SHA256.
        :return: Derived ContentEncryptionKey as bytes.
        """
        hash_name = self.parameters.algorithm or hash_alg
        alg_id = SHAAlgID(hash_name)
        counter = 1
        keying_material = b""

        # KDF3: K(i) = Hash (D || Z || otherInfo)

        while len(keying_material) < key_length:
            counter_bytes = counter.to_bytes(4, byteorder="big")
            keying_material += alg_id.compute(data=counter_bytes + shared_secret + der_other_info)
            counter += 1

        return keying_material[:key_length]


@dataclass(repr=False)
class KemBasedMacParameter(Parameters):
    """
    KemBMParameter ::= SEQUENCE {
        kdf               AlgorithmIdentifier{KEY-DERIVATION {...}},
        kemContext    [0] OCTET STRING     OPTIONAL, #  if needed with the used KEM algorithm like ukm in cms-kemri.
        len               INTEGER (1..MAX),
        mac               AlgorithmIdentifier{MAC-ALGORITHM {...}}
    }
    """

    kdf: KDFAlgorithmIdentifier
    length: int
    mac: MACAlgorithmIdentifier
    kem_context: Optional[bytes] = None

    def encode(self) -> bytes:
        """Encode the KemBMParameter structure to DER format.

        :return: DER-encoded KemBMParameter.
        """
        asn1_obj = KemBMParameterAsn1()
        asn1_obj['kdf'] = decoder.decode(self.kdf.encode())[0]
        if self.kem_context is not None:
            data = univ.OctetString(self.kem_context).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
            asn1_obj['kemContext'] = data

        asn1_obj['len'] = self.length
        asn1_obj['mac'] = decoder.decode(self.mac.encode())[0]
        return encoder.encode(asn1_obj)

    @classmethod
    def from_der(cls, data: bytes) -> "KemBasedMacParameter":
        """
        Decode the KemBasedMacParameter structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: KemBasedMacParameter instance.
        """
        asn1_obj, _ = decoder.decode(data, asn1Spec=KemBMParameterAsn1())
        kdf = KDFAlgorithmIdentifier.from_der(encoder.encode(asn1_obj["kdf"]))
        kem_context = (
            bytes(asn1_obj["kemContext"])
            if asn1_obj["kemContext"].isValue
            else None
        )
        length = int(asn1_obj["len"])
        mac = MACAlgorithmIdentifier.from_der(encoder.encode(asn1_obj["mac"]))
        return cls(kdf=kdf, kem_context=kem_context, length=length, mac=mac)

    def compute_ss(self, private_key: PQKEMPrivateKey):
        ss = private_key.decaps(self.kem_context)


        if self.kdf.algorithm.startswith("hkdf"):
            derived_key = self.kdf.compute(
                key=ss,
                salt=self.kem_context,
                length=self.length,
                other_info=None,
            )
        elif self.kdf in ["kdf2", "kdf3"]:
            derived_key = self.kdf.compute(
                key=ss,
                other_info=self.kem_context,
                length=self.length,
            )
        else:
            raise NotImplementedError()


        mac_value = self.mac.compute(data=derived_key)

        return mac_value


@dataclass(repr=False)
class KemBasedMacAlgId(AlgorithmIdentifier):
    """
    Represents the KemBasedMac AlgorithmIdentifier structure.

    Attributes:
        algorithm: The OID for the KemBasedMac algorithm.
        parameters: Parameters of type KemBasedMacParameter.

    """

    algorithm: str = field(init=False, default="kem_based_mac")
    parameters: Optional[KemBasedMacParameter] = None

    def encode(self) -> bytes:
        """
        Encode the KemBasedMacAlgId structure to DER format.

        :return: DER-encoded KemBasedMacAlgId.
        """
        alg_id = rfc9480.AlgorithmIdentifier()
        alg_id["algorithm"] = id_KemBasedMac
        if self.parameters is not None:
            alg_id["parameters"] = decoder.decode(self.parameters.encode())[0]
        else:
            alg_id["parameters"] = univ.Null()
        return encoder.encode(alg_id)

    @classmethod
    def from_der(cls, data: bytes) -> "KemBasedMacAlgId":
        """
        Decode the KemBasedMacAlgId structure from DER-encoded data.

        :param data: DER-encoded data.
        :return: KemBasedMacAlgId instance.
        """
        asn1_obj, _ = decoder.decode(data, asn1Spec=rfc9480.AlgorithmIdentifier())

        if asn1_obj["algorithm"] != id_KemBasedMac:
            raise ValueError("Algorithm OID does not match KemBasedMac")
        parameters = (
            KemBasedMacParameter.from_der(asn1_obj["parameters"].asOctets())
            if asn1_obj["parameters"].isValue
            else None
        )
        return cls(parameters=parameters)

    def compute_ss(self, private_key: PQKEMPrivateKey):
        return self.parameters.compute_ss(private_key)


class AlgIdFactory:
    """
    A factory class for creating AlgorithmIdentifier objects or subclasses,
    with dynamic handling of supported parameter structures.
    """

    @staticmethod
    def create(
            name: str,
            salt: Optional[bytes] = None,
            iteration_count: Optional[int] = None,
            key_length: int = 32,
            prf: Optional[str] = None,
            mac: Optional[str] = None,
            hash_alg: Optional[str] = None,
            parameters: Optional[Union[AlgorithmIdentifier, Parameters]] = None,
    ) -> AlgorithmIdentifier:
        """
        Create an AlgorithmIdentifier or subclass based on the provided name
        and parameter values.

        :param name: The name of the algorithm.
        :param salt: Salt value for algorithms like PBKDF2 or PBMAC1.
        :param iteration_count: Number of iterations for PBKDF2 or PBMAC1.
        :param key_length: Key length for PBKDF2. Defaults to 32.
        :param prf: Pseudorandom function algorithm for PBKDF2.
        :param mac: Message authentication code algorithm for PBMAC1.
        :param hash_alg: Hash algorithm for KMAC or HMAC.
        :param parameters: Additional parameters for the AlgorithmIdentifier.
        :return: The constructed AlgorithmIdentifier object.
        :raises ValueError: If the algorithm name is unsupported.
        """
        if name == "sha256":
            return SHAAlgID(algorithm="sha256", parameters=parameters)

        elif name == "aes-gmac":
            return GMACAlgId(algorithm="aes-gmac", parameters=parameters)

        elif name == "pbkdf2":
            params = PBKDF2Params(
                salt=salt or os.urandom(16),
                iterationCount=iteration_count or 100000,
                keyLength=key_length,
                prf=AlgorithmIdentifier(prf or "hmac-sha1"),
            )
            return PBKDF2AlgId(parameters=params)

        elif name == "pbmac1":
            kdf = parameters or AlgIdFactory.create("pbkdf2", salt, iteration_count, key_length, prf, mac, hash_alg)
            params = parameters or PBMAC1Params(keyDerivationFunc=kdf,
                         messageAuthScheme=mac or AlgorithmIdentifier("hmac-sha256"))

            return PBMAC1AlgId(parameters=params)

        elif name == "kmac":
            kmac_algorithm = f"kmac-{hash_alg or 'shake128'}"
            return AlgorithmIdentifier(algorithm=kmac_algorithm, parameters=parameters)

        elif name == "hmac":
            hmac_algorithm = f"hmac-{hash_alg or 'sha256'}"
            return HMACAlgID(algorithm=hmac_algorithm, parameters=parameters)

        elif name == "dh_based_mac":
            params = DHBMParameter(
                owf=AlgorithmIdentifier(hash_alg or "sha1"),
                mac=AlgorithmIdentifier(mac or "hmac-sha1"),
            )
            return DHBasedMac(parameters=params)

        elif name in ["aes128_gmac", "aes192_gmac", "aes256_gmac"]:
            salt or os.urandom(12)
            length = len(salt)
            params = parameters or GCMParameters(nonce=salt, length=length)
            return GMACAlgId(parameters=params)

        elif name == "kdf2":
            params = parameters or KDF3Params(algorithm=hash_alg or "sha256")
            return KDF2AlgId(parameters=params)

        elif name == "kdf3":
            params = parameters or KDF3Params(algorithm=hash_alg or "sha256")
            return KDF3AlgId(parameters=params)

        else:
            raise ValueError(
                f"Unsupported algorithm '{name}'. Supported algorithms are: "
                f"sha256, aes-gmac, pbkdf2, pbmac1, kmac, hmac, dh_based_mac, kdf2, kdf3."
            )

    @staticmethod
    def from_der(data: bytes) -> AlgorithmIdentifier:
        """
        Decode a DER-encoded AlgorithmIdentifier structure and instantiate
        the appropriate AlgorithmIdentifier subclass.

        :param data: DER-encoded data.
        :return: An instance of the appropriate AlgorithmIdentifier subclass.
        :raises ValueError: If the OID does not match any known algorithm.
        """
        asn1_object, rest = decoder.decode(data, rfc5280.AlgorithmIdentifier())

        algorithm_oid = asn1_object["algorithm"]
        algorithm_name = ALG_ID_OID_2_NAME.get(algorithm_oid)

        if not algorithm_name:
            raise ValueError(f"Unknown algorithm OID: {algorithm_oid}")

        parameters_data = asn1_object["parameters"].asOctets() if asn1_object["parameters"].isValue else None

        if algorithm_name == "pbkdf2":
            params = PBKDF2Params.from_der(parameters_data) if parameters_data else None
            return PBKDF2AlgId(parameters=params)

        elif algorithm_name == "pbmac1":
            params = PBMAC1Params.from_der(parameters_data) if parameters_data else None
            return PBMAC1AlgId(parameters=params)

        elif algorithm_name == "dh_based_mac":
            params = DHBMParameter.from_der(parameters_data) if parameters_data else None
            return DHBasedMac(parameters=params)

        elif algorithm_name == "kdf2":
            params = KDF2Params.from_der(parameters_data) if parameters_data else None
            return KDF2AlgId(parameters=params)

        elif algorithm_name == "kdf3":
            params = KDF3Params.from_der(parameters_data) if parameters_data else None
            return KDF3AlgId(parameters=params)

        else:
            params = AlgorithmIdentifier.from_der(parameters_data) if parameters_data else None
            return AlgorithmIdentifier(algorithm=algorithm_name, parameters=params)


class KemBMParameterAsn1(univ.Sequence):
    """
    KemBMParameter ::= SEQUENCE {
        kdf               AlgorithmIdentifier{KEY-DERIVATION {...}},
        kemContext    [0] OCTET STRING     OPTIONAL, #  if needed with the used KEM algorithm like ukm in cms-kemri.
        len               INTEGER (1..MAX),
        mac               AlgorithmIdentifier{MAC-ALGORITHM {...}}
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('kdf', rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType(
            'kemContext', univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType('len', univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(1, MAX_VALUE))),
        namedtype.NamedType('mac', rfc5280.AlgorithmIdentifier())
    )
