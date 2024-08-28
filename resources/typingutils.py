from typing import Union, Any, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey

from pyasn1_alt_modules import rfc2986, rfc9480

# Type alias for supported private key types
ASYM_PRIVATE_KEY = Union[RSAPrivateKey, EllipticCurvePrivateKey, DSAPrivateKey, DHPrivateKey]
ASYM_PUBLIC_KEY = Union[RSAPublicKey, EllipticCurvePublicKey, DSAPublicKey, DHPublicKey]


# those types are Alias for the option a function can have.
CSR_TYPE = Union[bytes, x509.CertificateSigningRequest, rfc2986.CertificationRequest]
CERT_TYPE = Union[bytes, x509.Certificate, rfc9480.Certificate]


# If a certificate is generated, a tuple is returned with the following type:
CERT_GEN_RET = Tuple[x509.Certificate, ASYM_PRIVATE_KEY]
