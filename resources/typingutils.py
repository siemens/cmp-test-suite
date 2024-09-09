"""
Provides type aliases to enhance code readability, maintainability, and type safety.
Type aliases are used to create descriptive names for commonly used types, making the codebase
easier to understand and work with.

"""

from typing import Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from pyasn1_alt_modules import rfc2986, rfc9480

# Type alias for supported private key types
PrivateKey = Union[
    RSAPrivateKey,
    EllipticCurvePrivateKey,
    DSAPrivateKey,
    DHPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
    X25519PrivateKey,
    X448PrivateKey
]
# Type alias for supported public key types
PublicKey = Union[
    RSAPublicKey,
    EllipticCurvePublicKey,
    DSAPublicKey,
    DHPublicKey,
    Ed25519PublicKey,
    Ed448PublicKey,
    X25519PublicKey,
    X448PublicKey
]


# Keys which can be used for Signing and Verification of a Signature.
# Used to make sure that only the right keys are allowed for Singing.
PrivateKeySig = Union[
    RSAPrivateKey,
    EllipticCurvePrivateKey,
    DSAPrivateKey,
    DHPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
]
PublicKeySig = Union[
    RSAPublicKey,
    EllipticCurvePublicKey,
    DSAPublicKey,
    DHPublicKey,
    Ed25519PublicKey,
]

# These `cryptography` keys can be used to sign a certificate.
# For signature protection, a certificate is required in the
# first position of the `pyasn1 rfc9480.PKIMessage` `extraCerts` field.
# To ensure the correct keys are used, this type is introduced.
PrivSignCertKey = Union[
    RSAPrivateKey,
    EllipticCurvePrivateKey,
    DSAPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
]


# those types are Alias for the option a function can have.
CsrType = Union[bytes, x509.CertificateSigningRequest, rfc2986.CertificationRequest]
CertType = Union[bytes, x509.Certificate, rfc9480.Certificate]

# If a certificate is generated, a tuple is returned with the following type.
# Introduced for Developer for Better Readability.
CertGenRet = Tuple[x509.Certificate, PrivateKey]


# A Value which can be parsed to a function.
# So that a PKIMessage does not need to be in pyasn1 format, but
# the raw bytes are also allowed to be parsed.
# Convince for the user
PKIMsgType = Union[rfc9480.PKIMessage, bytes]


# This is a "stringified int", to make it easier to pass numeric data
# to RobotFramework keywords. Normally, if you want
# to pass an integer, you have to write it as `${45}` - which hinders readability.
# With a stringified integer, we provide
# some syntactic sugar, enabling both notations: `${45}` and `45`.
Strint = Union[str, int]


# At different stages of RobotFramework tests we deal with
# certificates in various forms, e.g., DER-encoded bytes,
# PEM-encoded strings, pyasn1 structures, etc. This type
# is used in functions that can accept either of these formats
# and will transform them internally, as required.
AnyCert = Union[bytes, x509.Certificate, rfc9480.Certificate, str]
