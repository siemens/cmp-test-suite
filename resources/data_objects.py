"""Dataclass objects needed for the issuing processes."""

from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyasn1_alt_modules import rfc9480

from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey


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
        elif isinstance(public_key, X448PublicKey):
            if self.x448_cert is None or self.x448_key is None:
                raise ValueError("X448 certificate and key are not set.")
            return self.x448_cert, self.x448_key
        elif isinstance(public_key, EllipticCurvePublicKey):
            if self.ecc_cert is None or self.ecc_key is None:
                raise ValueError("ECC certificate and key are not set.")
            return self.ecc_cert, self.ecc_key
        else:
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
