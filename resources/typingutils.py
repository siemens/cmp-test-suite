# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Type aliases to enhance code readability, maintainability, and type safety.

Type aliases are used to create descriptive names for commonly used types, making the codebase
easier to understand and work with.
"""

from typing import Union

from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyasn1_alt_modules import rfc9480

from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey
from pq_logic.keys.abstract_pq import (
    PQKEMPublicKey,
    PQPrivateKey,
    PQPublicKey,
    PQSignaturePrivateKey,
    PQSignaturePublicKey,
)

TradSigPrivKey = Union[
    RSAPrivateKey,
    EllipticCurvePrivateKey,
    DSAPrivateKey,
    DHPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
]

# Type alias for supported private key types
PrivateKey = Union[
    TradSigPrivKey,
    DHPrivateKey,
    X25519PrivateKey,
    X448PrivateKey,
    PQPrivateKey,
    AbstractHybridRawPrivateKey,
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
    X448PublicKey,
    PQPublicKey,
    PQKEMPublicKey,
    PQSignaturePublicKey,
]


# Keys which can be used for signing and verification of a signature.
# They are used to ensure that only authorized keys are used for signing.
PrivateKeySig = Union[
    RSAPrivateKey,
    EllipticCurvePrivateKey,
    DSAPrivateKey,
    DHPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
    PQSignaturePrivateKey,
]
PublicKeySig = Union[
    RSAPublicKey,
    EllipticCurvePublicKey,
    DSAPublicKey,
    DHPublicKey,
    Ed25519PublicKey,
    Ed448PublicKey,
    PQSignaturePublicKey,
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

# This is a "stringified integer", to make it easier to pass numeric data
# to RobotFramework keywords. Normally, if you want
# to pass an integer, you have to write it as `${45}` - which hinders readability.
# With a stringified integer, we provide
# some syntactic sugar, enabling both notations: `${45}` and `45`.
Strint = Union[str, int]

# At different stages of RobotFramework tests we deal with
# certificates in forms, e.g., pyasn1 structures, or filepaths. This type
# is used in functions that can accept either of these formats
# and will transform them internally, as required.
CertObjOrPath = Union[rfc9480.Certificate, str]


# The `KGAKeyTypes` includes all private key types supported
# for operations in the Key Generation Authority (KGA) logic.
# This type ensures that only compatible private keys are used
# for key exchange and key encipherment.
EnvDataPrivateKey = Union[RSAPrivateKey, Ed25519PrivateKey, Ed448PrivateKey, EllipticCurvePrivateKey, PQKEMPublicKey]

# The `ECDHPrivKeyTypes` includes all private key types supported
# for ECDH operations. This type ensures that only compatible
# private keys are used in ECDH-related operations.
# Used in Key Generation Authority logic to make sure the key agreement
# used the correct type.
ECDHPrivKeyTypes = Union[EllipticCurvePrivateKey, X25519PrivateKey, X448PrivateKey]

# The `ECDHPubKeyTypes` includes all public key types supported
# for ECDH operations. This type ensures that only compatible
# public keys are used in ECDH-related operations.
# Used in Key Generation Authority logic to make sure the key agreement
# used the correct type.
ECDHPubKeyTypes = Union[EllipticCurvePublicKey, X25519PublicKey, X448PublicKey]
