# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from pyasn1.type import namedtype, tag, univ
from pyasn1_alt_modules import rfc5280

# ----------------------------
# ASN.1 Structure Definitions
# ----------------------------


class MLDSAPublicKeyASN1(univ.OctetString):
    """ASN.1 structure for ML-DSA Public Key."""

    pass


class MLDSAPrivateKeyASN1(univ.Sequence):
    """ASN.1 structure for ML-DSA Private Key."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("privateKeyAlgorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("privateKey", univ.OctetString()),
        namedtype.OptionalNamedType(
            "publicKey", MLDSAPublicKeyASN1().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        ),
    )


MLKEMPublicKeyANS1 = MLDSAPublicKeyASN1
MLKEMPrivateKeyANS1 = MLDSAPrivateKeyASN1
SLHDSAPublicKeyASN1 = MLDSAPublicKeyASN1
SLHDSAPrivateKeyANS1 = MLDSAPrivateKeyASN1
