"""
typing_utils.py

This module provides type aliases to enhance code readability, maintainability, and type safety.
Type aliases are used to create descriptive names for commonly used types, making the codebase
easier to understand and work with.

"""

from typing import Union, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey

from pyasn1_alt_modules import rfc2986, rfc9480

# Type alias for supported private key types
PrivateKey = Union[RSAPrivateKey, EllipticCurvePrivateKey, DSAPrivateKey, DHPrivateKey]
# Type alias for supported public key types
PublicKey = Union[RSAPublicKey, EllipticCurvePublicKey, DSAPublicKey, DHPublicKey]

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
PkiMsgType = Union[rfc9480.PKIMessage, bytes]


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

