# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Dataclass objects needed for the issuing processes."""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480, rfc9481

from resources.typingutils import ECDHPrivateKey, ECDHPublicKey
from resources.oidutils import (
    AES_GMAC_OID_2_NAME,
    ECDSA_SHA3_OID_2_NAME,
    ECDSA_SHA_OID_2_NAME,
    HMAC_OID_2_NAME,
    HYBRID_SIG_OID_2_NAME,
    KDF_OID_2_NAME,
    KM_KA_ALG,
    KM_KT_ALG,
    KM_KW_ALG,
    KMAC_OID_2_NAME,
    PQ_SIG_OID_2_NAME,
    PROT_SYM_ALG,
    RSA_SHA3_OID_2_NAME,
    RSA_SHA_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    SHA3_OID_2_NAME,
    SHA_OID_2_NAME,
    id_KemBasedMac,
)


@dataclass
class ExtraIssuingData:
    """Extra data for the issuing process.

    Attributes:
        regToken: Optional registration token.
        found_regToken: Optional found registration token.
        authenticator: Optional authenticator.

    """

    regToken: Optional[str] = None
    found_regToken: bool = False
    authenticator: Optional[str] = None


@dataclass
class KARICertsAndKeys:
    """Class to hold KARI certificates and keys.

    Attributes:
        x25519_cert: Optional[rfc9480.CMPCertificate]
        x25519_key: Optional[X25519PrivateKey]
        x448_cert: Optional[rfc9480.CMPCertificate]
        x448_key: Optional[X448PrivateKey]
        ecc_cert: Optional[rfc9480.CMPCertificate]
        ecc_key: Optional[EllipticCurvePrivateKey]

    """

    x25519_cert: Optional[rfc9480.CMPCertificate] = None
    x25519_key: Optional[X25519PrivateKey] = None
    x448_cert: Optional[rfc9480.CMPCertificate] = None
    x448_key: Optional[X448PrivateKey] = None
    ecc_cert: Optional[rfc9480.CMPCertificate] = None
    ecc_key: Optional[EllipticCurvePrivateKey] = None

    def get_cert_and_key(self, public_key: ECDHPublicKey) -> Tuple[rfc9480.CMPCertificate, ECDHPrivateKey]:
        """Get the certificate and key for the given public key.

        :param public_key: The public key for which to retrieve the certificate and key.
        :return: A tuple containing the certificate and key.
        :raises ValueError: If the public key type is not supported, or if the corresponding
        certificate or key is not set.
        """
        if isinstance(public_key, X25519PublicKey):
            if self.x25519_cert is None or self.x25519_key is None:
                raise ValueError("X25519 certificate and key are not set.")
            return self.x25519_cert, self.x25519_key
        if isinstance(public_key, X448PublicKey):
            if self.x448_cert is None or self.x448_key is None:
                raise ValueError("X448 certificate and key are not set.")
            return self.x448_cert, self.x448_key
        if isinstance(public_key, EllipticCurvePublicKey):
            if self.ecc_cert is None or self.ecc_key is None:
                raise ValueError("ECC certificate and key are not set.")
            return self.ecc_cert, self.ecc_key

        raise ValueError(f"Unsupported public key type: {type(public_key)}")

    @staticmethod
    def from_kwargs(**kwargs) -> "KARICertsAndKeys":
        """Create an instance of `KARICertsAndKeys` from keyword arguments.

        :param kwargs: Keyword arguments representing the attributes of the class.
        :return: An instance of `KARICertsAndKeys`.
        """
        return KARICertsAndKeys(
            x25519_cert=kwargs.get("x25519_cert"),
            x25519_key=kwargs.get("x25519_key"),
            x448_cert=kwargs.get("x448_cert"),
            x448_key=kwargs.get("x448_key"),
            ecc_cert=kwargs.get("ecc_cert"),
            ecc_key=kwargs.get("ecc_key"),
        )


class AlgorithmProfile:
    """A class to represent an algorithm profile used by the CMP protocol.

    For LwCMP is the algorithm profile defined in RFC 9481.
    """

    # The allowed PKIMessage signature algorithms. Section 3 RFC 9481.
    msg_sig_alg: Dict[univ.ObjectIdentifier, str]
    # The allowed PKIMessage digest algorithms.
    # Used for:
    # - Digest algorithm identifiers are located in the:
    # - hashAlg field of OOBCertHash and CertStatus,
    # - owf field of Challenge, PBMParameter, and DHBMParameter,
    # - digestAlgorithms field of SignedData,
    # - digestAlgorithm field of SignerInfo.
    #  Section 2 RFC 9481.
    msg_digest_alg: Dict[univ.ObjectIdentifier, str]
    #
    # Key agreement algorithms. Section 4.1 RFC 9481.
    km_ka_alg: Dict[univ.ObjectIdentifier, str]
    # Key transport algorithms. Section 4.2 RFC 9481.
    km_kt_alg: Dict[univ.ObjectIdentifier, str]
    # Symmetric protection algorithms. Section 4.3 RFC 9481.
    km_kw_alg: Dict[univ.ObjectIdentifier, str]
    # Key derivation algorithms. Section 4.4 RFC 9481.
    km_kd_alg: Dict[univ.ObjectIdentifier, str]
    # Content-Encryption algorithms. Section 5 RFC 9481.
    PROT_SYM_ALG: Dict[univ.ObjectIdentifier, str]
    # Message authentication Code algorithms. Section 6 RFC 9481.
    msg_mac_alg: Dict[univ.ObjectIdentifier, str]

    @classmethod
    def get_key_wrap_algs(cls) -> Dict[univ.ObjectIdentifier, str]:
        """Get the key wrap algorithms.

        :return: The key wrap algorithms.
        """
        return cls.km_kw_alg

    @classmethod
    def get_key_transport_algs(cls) -> Dict[univ.ObjectIdentifier, str]:
        """Get the key transport algorithms.

        :return: The key transport algorithms.
        """
        return cls.km_kt_alg

    @classmethod
    def get_key_agreement_algs(cls) -> Dict[univ.ObjectIdentifier, str]:
        """Get the key agreement algorithms.

        :return: The key agreement algorithms.
        """
        return cls.km_ka_alg

    @classmethod
    def get_key_derivation_algs(cls, usage: Optional[str] = None) -> Dict[univ.ObjectIdentifier, str]:
        """Get the key derivation algorithms.

        :param usage: The usage of the key derivation algorithm, to filter more specifically.
        :return: The key derivation algorithms.
        """
        return cls.km_kd_alg

    @classmethod
    def get_signature_prot_algs(cls) -> Dict[univ.ObjectIdentifier, str]:
        """Get the message signature algorithms.

        :return: The message signature algorithms.
        """
        return cls.msg_sig_alg

    @classmethod
    def get_mac_protection_algs(cls) -> Dict[univ.ObjectIdentifier, str]:
        """Get the MAC protection algorithms.

        :return: The MAC protection algorithms.
        """
        return cls.km_kw_alg

    @classmethod
    def get_content_encryption_algs(cls) -> Dict[univ.ObjectIdentifier, str]:
        """Get the content encryption algorithms.

        :return: The content encryption algorithms.
        """
        return cls.PROT_SYM_ALG

    @classmethod
    def get_digest_algorithms(cls) -> Dict[univ.ObjectIdentifier, str]:
        """Get the digest algorithms.

        :return: The digest algorithms.
        """
        return cls.msg_digest_alg


class AllAlgorithmProfile(AlgorithmProfile):
    """A class to represent all algorithms used by the CMP protocol."""

    # The allowed PKIMessage signature algorithms. Section 3 RFC 9481.
    msg_sig_alg = {
        **ECDSA_SHA3_OID_2_NAME,
        **ECDSA_SHA_OID_2_NAME,
        **RSA_SHA_OID_2_NAME,
        **RSASSA_PSS_OID_2_NAME,
        **RSA_SHA3_OID_2_NAME,
        **PQ_SIG_OID_2_NAME,
        **HYBRID_SIG_OID_2_NAME,
        **{rfc9480.id_DHBasedMac: "dh_based_mac", id_KemBasedMac: "kem_based_mac"},
    }
    # The allowed PKIMessage digest algorithms.
    msg_digest_alg = {
        **SHA_OID_2_NAME,
        **SHA3_OID_2_NAME,
    }
    # Key agreement algorithms. Section 4.1 RFC 9481.
    km_ka_alg = {
        **KM_KA_ALG,
    }
    # Key transport algorithms. Section 4.2 RFC 9481.
    km_kt_alg = {
        **KM_KT_ALG,
    }
    # Symmetric protection algorithms. Section 4.3 RFC 9481.
    km_kw_alg = {
        **KM_KW_ALG,
    }
    km_kd_alg = {**{rfc9481.id_PBKDF2: "pbkdf2"}, **KDF_OID_2_NAME}
    prot_sym_alg = {**PROT_SYM_ALG}
    # Message authentication Code algorithms. Section 6 RFC 9481.
    msg_mac_alg = {
        **{rfc9481.id_PBMAC1: "pbmac1", rfc9481.id_PasswordBasedMac: "password_based_mac"},
        **HMAC_OID_2_NAME,
        **AES_GMAC_OID_2_NAME,
        **KMAC_OID_2_NAME,
    }


# TODO ADD LwCMP ALGORITHM PROFILES


class LwCMPAlgProfile(AlgorithmProfile):
    """A class to represent the LwCMP algorithms used by the CMP protocol.

    The algorithms are defined in RFC 9481.
    """
