"""Defines Object Identifiers (OIDs) and mappings for the Test-Suite."""

# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=invalid-name
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pkilint.itu.x520_name import (
    X520BusinessCategory,
    X520OrganizationIdentifier,
    X520PostalCode,
    X520StreetAddress,
    id_at_businessCategory,
    id_at_organizationIdentifier,
    id_at_postalCode,
    id_at_streetAddress,
)
from pyasn1.type import univ
from pyasn1_alt_modules import (
    rfc3370,
    rfc3565,
    rfc5084,
    rfc5280,
    rfc5480,
    rfc5639,
    rfc5753,
    rfc5990,
    rfc6664,
    rfc8017,
    rfc8018,
    rfc8619,
    rfc9480,
    rfc9481,
    rfc9654,
    rfc9688,
    rfc9690,
    rfc9708,
)

from pq_logic.tmp_oids import (
    CHEMPAT_OID_2_NAME,
    COMPOSITE_KEM_OID_2_NAME,
    COMPOSITE_SIG_OID_TO_NAME,
    FALCON_NAME_2_OID,
    FRODOKEM_NAME_2_OID,
    MCELIECE_NAME_2_OID,
    id_altSignatureExt,
    id_altSubPubKeyExt,
    id_ce_deltaCertificateDescriptor,
    id_relatedCert,
    id_sntrup761,
)
from resources.asn1_structures import (
    EmailAddressASN1,
    X520BusinessCategoryASN1,
    X520CommonNameASN1,
    X520countryNameASN1,
    X520LocalityNameASN1,
    X520nameASN1,
    X520OrganizationalUnitNameASN1,
    X520OrganizationNameASN1,
    X520PostalCodeASN1,
    X520PseudonymASN1,
    X520SerialNumberASN1,
    X520StateOrProvinceNameASN1,
    X520StreetAddressASN1,
    X520TitleASN1,
)

# In RFC 9480 Certificate Management Protocol (CMP) Updates
# Are new extended key usages (EKU) defined, which indicate the role the certificate can have.
# KGA: "The CMP KGA knows the private key it generated on behalf of the end entity. This is a very sensitive"
# As of RFC 9480, which is why we check those extended key usages inside the validation functions.
# These mappings make it easier to parse human-readable names to the function,
# which prepares and check these extended key usages.
CMP_EKU_OID_2_NAME = {rfc9480.id_kp_cmKGA: "cmKGA", rfc9480.id_kp_cmcRA: "cmcRA", rfc9480.id_kp_cmcCA: "cmcCA"}
AES_GMAC_NAME_2_OID = {
    "aes128_gmac": rfc9481.id_aes128_GMAC,
    "aes192_gmac": rfc9481.id_aes192_GMAC,
    "aes256_gmac": rfc9481.id_aes256_GMAC,
    "aes-gmac": rfc9481.id_aes256_GMAC,
    "aes_gmac": rfc9481.id_aes256_GMAC,
}
AES_GMAC_OID_2_NAME: Dict[univ.ObjectIdentifier, str] = {
    rfc9481.id_aes128_GMAC: "aes128_gmac",
    rfc9481.id_aes192_GMAC: "aes192_gmac",
    rfc9481.id_aes256_GMAC: "aes256_gmac",
}
RSA_SHA2_OID_2_NAME = {
    rfc9481.sha224WithRSAEncryption: "rsa-sha224",
    rfc9481.sha256WithRSAEncryption: "rsa-sha256",
    rfc9481.sha384WithRSAEncryption: "rsa-sha384",
    rfc9481.sha512WithRSAEncryption: "rsa-sha512",
}
ECDSA_SHA_OID_2_NAME = {
    rfc9481.ecdsa_with_SHA224: "ecdsa-sha224",
    rfc9481.ecdsa_with_SHA256: "ecdsa-sha256",
    rfc9481.ecdsa_with_SHA384: "ecdsa-sha384",
    rfc9481.ecdsa_with_SHA512: "ecdsa-sha512",
    rfc9481.id_ecdsa_with_shake128: "ecdsa-shake128",
    rfc9481.id_ecdsa_with_shake256: "ecdsa-shake256",
}


RSASSA_PSS_OID_2_NAME: Dict[univ.ObjectIdentifier, str] = {
    rfc9481.id_RSASSA_PSS: "rsassa_pss-sha256",
    rfc9481.id_RSASSA_PSS_SHAKE128: "rsassa_pss-shake128",
    rfc9481.id_RSASSA_PSS_SHAKE256: "rsassa_pss-shake256",
}


# These mappings facilitate the identification of the specific HMAC-SHA algorithm
# used for MAC (Message Authentication Code) protection algorithms for the PKIMessage.

HMAC_SHA_OID_2_NAME = {
    rfc9481.id_hmacWithSHA224: "hmac-sha224",
    rfc9481.id_hmacWithSHA256: "hmac-sha256",
    rfc9481.id_hmacWithSHA384: "hmac-sha384",
    rfc9481.id_hmacWithSHA512: "hmac-sha512",
}

HMAC_SHA3_OID_2_NAME = {
    rfc9688.id_hmacWithSHA3_224: "hmac-sha3_224",
    rfc9688.id_hmacWithSHA3_256: "hmac-sha3_256",
    rfc9688.id_hmacWithSHA3_384: "hmac-sha3_384",
    rfc9688.id_hmacWithSHA3_512: "hmac-sha3_512",
}

HMAC_SHA_NAME_2_OID = {v: k for k, v in HMAC_SHA_OID_2_NAME.items()}
HMAC_SHA3_NAME_2_OID = {v: k for k, v in HMAC_SHA3_OID_2_NAME.items()}

HMAC_OID_2_NAME = {rfc3370.hMAC_SHA1: "hmac-sha1"}
HMAC_OID_2_NAME.update(HMAC_SHA_OID_2_NAME)
HMAC_OID_2_NAME.update(HMAC_SHA3_OID_2_NAME)
HMAC_NAME_2_OID = {v: k for k, v in HMAC_OID_2_NAME.items()}

# These mappings facilitate the identification of the specific KMAC-SHA algorithm
# used for protecting PKIMessages with KMAC (Keccak Message Authentication Code.
KMAC_OID_2_NAME = {rfc9481.id_KMACWithSHAKE128: "kmac-shake128", rfc9481.id_KMACWithSHAKE256: "kmac-shake256"}


# Used for preparing Signature Protection of the PKIMessage.
SHA2_OID_2_NAME = {
    rfc8017.id_sha224: "sha224",
    rfc8017.id_sha256: "sha256",
    rfc8017.id_sha384: "sha384",
    rfc8017.id_sha512: "sha512",
}

SHA2_NAME_2_OID = {v: k for k, v in SHA2_OID_2_NAME.items()}

SHA_OID_2_NAME = {
    rfc5480.id_sha1: "sha1",
}
SHA_OID_2_NAME.update(SHA2_OID_2_NAME)


id_hash_algs = "2.16.840.1.101.3.4.2"  # pylint: disable=invalid-name


SHA3_OID_2_NAME = {
    univ.ObjectIdentifier(f"{id_hash_algs}.7"): "sha3_224",
    univ.ObjectIdentifier(f"{id_hash_algs}.8"): "sha3_256",
    univ.ObjectIdentifier(f"{id_hash_algs}.9"): "sha3_384",
    univ.ObjectIdentifier(f"{id_hash_algs}.10"): "sha3_512",
    univ.ObjectIdentifier(f"{id_hash_algs}.11"): "shake128",
    univ.ObjectIdentifier(f"{id_hash_algs}.12"): "shake256",
}

SHA3_NAME_2_OID = {v: k for k, v in SHA3_OID_2_NAME.items()}

ECDSA_SHA3_OID_2_NAME = {
    rfc9688.id_ecdsa_with_sha3_224: "ecdsa-sha3_224",
    rfc9688.id_ecdsa_with_sha3_256: "ecdsa-sha3_256",
    rfc9688.id_ecdsa_with_sha3_384: "ecdsa-sha3_384",
    rfc9688.id_ecdsa_with_sha3_512: "ecdsa-sha3_512",
}
RSA_SHA3_OID_2_NAME = {
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_224: "rsa-sha3_224",
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_256: "rsa-sha3_256",
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_384: "rsa-sha3_384",
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_512: "rsa-sha3_512",
}

RSA_OID_2_NAME = {
    rfc8017.sha1WithRSAEncryption: "rsa-sha1",
}
RSA_OID_2_NAME.update(RSA_SHA2_OID_2_NAME)
RSA_OID_2_NAME.update(RSA_SHA3_OID_2_NAME)

ECDSA_OID_2_NAME = {}
ECDSA_OID_2_NAME.update(ECDSA_SHA_OID_2_NAME)
ECDSA_OID_2_NAME.update(ECDSA_SHA3_OID_2_NAME)

AES_CBC_NAME_2_OID = {
    "aes128_cbc": rfc9481.id_aes128_CBC,
    "aes192_cbc": rfc9481.id_aes192_CBC,
    "aes256_cbc": rfc9481.id_aes256_CBC,
}

AES_CBC_OID_2_NAME = {v: k for k, v in AES_CBC_NAME_2_OID.items()}

AES_GCM_NAME_2_OID = {
    "aes128_gcm": rfc5084.id_aes128_GCM,
    "aes192_gcm": rfc5084.id_aes192_GCM,
    "aes256_gcm": rfc5084.id_aes256_GCM,
}

AES_GCM_OID_2_NAME = {v: k for k, v in AES_GCM_NAME_2_OID.items()}


# map OIDs of signature algorithms to the names of the hash functions
# used in the signature; this is needed to compute the certificate has for
# certConfirm messages, since it must contain the hash of the certificate,
# computed with the same algorithm as the one in the signature
OID_HASH_MAP: Dict[univ.ObjectIdentifier, str] = {}
OID_HASH_MAP.update(RSA_OID_2_NAME)
OID_HASH_MAP.update(RSASSA_PSS_OID_2_NAME)
OID_HASH_MAP.update(ECDSA_SHA_OID_2_NAME)
OID_HASH_MAP.update(ECDSA_SHA3_OID_2_NAME)
OID_HASH_MAP.update(HMAC_OID_2_NAME)
OID_HASH_MAP.update(SHA_OID_2_NAME)
OID_HASH_MAP.update(SHA3_OID_2_NAME)

OID_HASH_NAME_2_OID = {v: k for k, v in OID_HASH_MAP.items()}

# Updating the main dictionary with RSA and ECDSA OIDs
# to check quickly if a given OID is supported by the Test-Suite
MSG_SIG_ALG = {rfc9481.id_Ed25519: "ed25519", rfc9481.id_Ed448: "ed448"}
MSG_SIG_ALG.update(RSA_SHA2_OID_2_NAME)
MSG_SIG_ALG.update(RSASSA_PSS_OID_2_NAME)
MSG_SIG_ALG.update(ECDSA_SHA_OID_2_NAME)

# Add additional OIDs specified in RFC9688.
TRAD_SIG_OID_2_NAME = {}
TRAD_SIG_OID_2_NAME.update(MSG_SIG_ALG)
TRAD_SIG_OID_2_NAME.update(RSA_OID_2_NAME)
TRAD_SIG_OID_2_NAME.update(ECDSA_OID_2_NAME)

TRAD_SIG_NAME_2_OID = {v: k for k, v in TRAD_SIG_OID_2_NAME.items()}

MSG_SIG_ALG_NAME_2_OID = {v: k for k, v in MSG_SIG_ALG.items()}

LWCMP_MAC_OID_2_NAME = {rfc9480.id_PasswordBasedMac: "password_based_mac", rfc8018.id_PBMAC1: "pbmac1"}

id_KemBasedMac = univ.ObjectIdentifier("1.2.840.113533.7.66.16")

SYMMETRIC_PROT_ALGO = {}
SYMMETRIC_PROT_ALGO.update(
    {
        rfc9480.id_DHBasedMac: "dh_based_mac",
        id_KemBasedMac: "kem_based_mac",
    }
)

SYMMETRIC_PROT_ALGO.update(LWCMP_MAC_OID_2_NAME)
SYMMETRIC_PROT_ALGO.update(HMAC_OID_2_NAME)
SYMMETRIC_PROT_ALGO.update(AES_GMAC_OID_2_NAME)
SYMMETRIC_PROT_ALGO.update(KMAC_OID_2_NAME)

SUPPORTED_MAC_OID_2_NAME = {}
SUPPORTED_MAC_OID_2_NAME.update(MSG_SIG_ALG)
SUPPORTED_MAC_OID_2_NAME.update(SYMMETRIC_PROT_ALGO)

# reverse the dictionary to get OIDs with names
# to perform lookups for getting PKIMessage Protection AlgorithmIdentifier
SUPPORTED_MAC_NAME_2_OID = {v: k for k, v in SUPPORTED_MAC_OID_2_NAME.items()}

# used for non-local Key generation if the ktri structure is used.
KM_KT_ALG = {rfc9481.rsaEncryption: "rsa", rfc9481.id_RSAES_OAEP: "rsaes-oaep"}
PROT_SYM_ALG = {
    rfc9481.id_aes128_CBC: "aes128_cbc",
    rfc9481.id_aes192_CBC: "aes192_cbc",
    rfc9481.id_aes256_CBC: "aes256_cbc",
}  # as of Section 5
# KM_KA_ALG as specified in
#     --   [RFC9481], Section 4.1

# map strings used in OpenSSL-like common name notation to objects of NameOID types that
# cryptography.x509 uses internally

SYMMETRIC_ENCR_ALG_OID_2_NAME = {}
SYMMETRIC_ENCR_ALG_OID_2_NAME.update(AES_CBC_OID_2_NAME)

SYMMETRIC_ENCR_ALG_NAME_2_OID = {v: k for k, v in SYMMETRIC_ENCR_ALG_OID_2_NAME.items()}

# Used to get the hash instances with their respective names.
# This is used to make it easier for users to parse and select hash algorithms by name.
# These hash instances are typically used for signing purposes, computing message digests,
# or for MAC (Message Authentication Code) protection algorithms such as HMAC.
ALLOWED_HASH_TYPES = {
    "sha1": hashes.SHA1(),
    "sha224": hashes.SHA224(),
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
    "shake128": hashes.SHAKE128(32),
    "shake256": hashes.SHAKE256(64),
    "sha3_224": hashes.SHA3_224(),
    "sha3_256": hashes.SHA3_256(),
    "sha3_384": hashes.SHA3_384(),
    "sha3_512": hashes.SHA3_512(),
}


# Saves the supported curves to perform a lookup for key generation.
CURVE_NAMES_TO_INSTANCES: Dict[str, ec.EllipticCurve] = {
    "secp192r1": ec.SECP192R1(),  # NIST P-192
    "prime192v1": ec.SECP192R1(),  # NIST P-192 (alias)
    "secp224r1": ec.SECP224R1(),  # NIST P-224
    "prime224v1": ec.SECP224R1(),  # NIST P-224 (alias)
    "secp256r1": ec.SECP256R1(),  # NIST P-256
    "prime256v1": ec.SECP256R1(),  # NIST P-256 (alias)
    "secp384r1": ec.SECP384R1(),  # NIST P-384
    "secp521r1": ec.SECP521R1(),  # NIST P-521
    "secp256k1": ec.SECP256K1(),  # SECG curve over a 256 bit prime field (used in Bitcoin)
    "sect163k1": ec.SECT163K1(),  # SECG/WTLS curve over a 163 bit binary field
    "sect163r2": ec.SECT163R2(),  # SECG curve over a 163 bit binary field
    "sect233k1": ec.SECT233K1(),  # SECG curve over a 233 bit binary field
    "sect233r1": ec.SECT233R1(),  # SECG curve over a 233 bit binary field
    "sect283k1": ec.SECT283K1(),  # SECG curve over a 283 bit binary field
    "sect283r1": ec.SECT283R1(),  # SECG curve over a 283 bit binary field
    "sect409k1": ec.SECT409K1(),  # SECG curve over a 409 bit binary field
    "sect409r1": ec.SECT409R1(),  # SECG curve over a 409 bit binary field
    "sect571k1": ec.SECT571K1(),  # SECG curve over a 571 bit binary field
    "sect571r1": ec.SECT571R1(),  # SECG curve over a 571 bit binary field
    "brainpoolP256r1": ec.BrainpoolP256R1(),  # Brainpool curve over a 256 bit prime field
    "brainpoolP384r1": ec.BrainpoolP384R1(),  # Brainpool curve over a 384 bit prime field
    "brainpoolP512r1": ec.BrainpoolP512R1(),  # Brainpool curve over a 512 bit prime field
    "brainpoolp256r1": ec.BrainpoolP256R1(),  # Brainpool curve over a 256 bit prime field
    "brainpoolp384r1": ec.BrainpoolP384R1(),  # Brainpool curve over a 384 bit prime field
    "brainpoolp512r1": ec.BrainpoolP512R1(),  # Brainpool curve over a 512 bit prime field
}

CURVE_OID_2_NAME = {
    rfc5480.secp192r1: "secp192r1",
    rfc5480.secp224r1: "secp224r1",
    rfc5480.secp256r1: "secp256r1",
    rfc5480.secp384r1: "secp384r1",
    rfc5480.secp521r1: "secp521r1",
    rfc5480.sect163r2: "sect163r2",
    rfc5480.sect233r1: "sect233r1",
    rfc5480.sect283r1: "sect283r1",
    rfc5480.sect409r1: "sect409r1",
    rfc5480.sect571r1: "sect571r1",
    rfc5480.sect163k1: "sect163k1",
    rfc5480.sect233k1: "sect233k1",
    rfc5480.sect283k1: "sect283k1",
    rfc5480.sect409k1: "sect409k1",
    rfc5480.sect571k1: "sect571k1",
    rfc5639.brainpoolP160r1: "brainpoolP160r1",
    rfc5639.brainpoolP192r1: "brainpoolP192r1",
    rfc5639.brainpoolP224r1: "brainpoolP224r1",
    rfc5639.brainpoolP256r1: "brainpoolP256r1",
    rfc5639.brainpoolP320r1: "brainpoolP320r1",
    rfc5639.brainpoolP384r1: "brainpoolP384r1",
    rfc5639.brainpoolP512r1: "brainpoolP512r1",
}


CURVE_NAME_2_OID = {}

for curve in CURVE_NAMES_TO_INSTANCES.values():
    tmp_oid = getattr(ec.EllipticCurveOID(), curve.name.upper())
    oid = univ.ObjectIdentifier(tmp_oid.dotted_string)
    CURVE_OID_2_NAME[oid] = curve.name
    CURVE_NAME_2_OID[curve.name] = oid


KM_KA_ALG = {
    # Section 4.1.1: Diffie-Hellman
    rfc9481.id_alg_ESDH: "esdh",
    # Section 4.1.2: ECDH
    rfc9481.dhSinglePass_stdDH_sha224kdf_scheme: "stdDH-sha224",
    rfc9481.dhSinglePass_stdDH_sha256kdf_scheme: "stdDH-sha256",
    rfc9481.dhSinglePass_stdDH_sha384kdf_scheme: "stdDH-sha384",
    rfc9481.dhSinglePass_stdDH_sha512kdf_scheme: "stdDH-sha512",
    rfc9481.dhSinglePass_cofactorDH_sha224kdf_scheme: "cofactorDH-sha224",
    rfc9481.dhSinglePass_cofactorDH_sha256kdf_scheme: "cofactorDH-sha256",
    rfc5753.dhSinglePass_cofactorDH_sha384kdf_scheme: "cofactorDH-sha384",
    rfc5753.dhSinglePass_cofactorDH_sha512kdf_scheme: "cofactorDH-sha512",
    # Section 4.1.3: Curve-Based Key Agreement
    rfc9481.id_X25519: "x25519",
    rfc9481.id_X448: "x448",
}

ECMQV = {
    rfc9481.mqvSinglePass_sha224kdf_scheme: "mqv-sha224",
    rfc9481.mqvSinglePass_sha256kdf_scheme: "mqv-sha256",
    rfc9481.mqvSinglePass_sha384kdf_scheme: "mqv-sha384",
    rfc9481.mqvSinglePass_sha512kdf_scheme: "mqv-sha512",
}

CURVE_2_COFACTORS = {
    # Curves over prime fields (Fp)
    "secp112r1": 1,
    "secp112r2": 4,
    "secp128r1": 1,
    "secp128r2": 4,
    "secp160k1": 1,
    "secp160r1": 1,
    "secp160r2": 1,
    "secp192k1": 1,
    "secp192r1": 1,
    "secp224k1": 1,
    "secp224r1": 1,
    "secp256k1": 1,
    "secp256r1": 1,
    "secp384r1": 1,
    "secp521r1": 1,
    # Curves over binary fields (F2m)
    "sect113r1": 2,
    "sect113r2": 2,
    "sect131r1": 2,
    "sect131r2": 2,
    "sect163k1": 2,
    "sect163r1": 2,
    "sect163r2": 2,
    "sect193r1": 2,
    "sect193r2": 2,
    "sect233k1": 4,
    "sect233r1": 2,
    "sect239k1": 4,
    "sect283k1": 4,
    "sect283r1": 2,
    "sect409k1": 4,
    "sect409r1": 2,
    "sect571k1": 4,
    "sect571r1": 2,
    # Brainpool curves RFC 5639
    "brainpoolP160r1": 1,
    "brainpoolP192r1": 1,
    "brainpoolP224r1": 1,
    "brainpoolP256r1": 1,
    "brainpoolP320r1": 1,
    "brainpoolP384r1": 1,
    "brainpoolP512r1": 1,
    "brainpoolP160t1": 1,
    "brainpoolP192t1": 1,
    "brainpoolP224t1": 1,
    "brainpoolP256t1": 1,
    "brainpoolP320t1": 1,
    "brainpoolP384t1": 1,
    "brainpoolP512t1": 1,
    # Montgomery and Edwards curves
    "curve25519": 8,
    "curve448": 4,
    "edwards25519": 8,
    "edwards448": 4,
}


ECMQV_NAME_2_OID = {y: x for x, y in ECMQV.items()}
KM_KA_ALG.update(ECMQV)
KM_KA_ALG_NAME_2_OID = {y: x for x, y in KM_KA_ALG.items()}

KM_KD_ALG = {rfc9481.id_PBKDF2: "pbkdf2"}  # As per Section 4.4 in RFC 9481
KM_KW_ALG = {
    rfc9481.id_aes128_wrap: "aes128_wrap",
    rfc9481.id_aes192_wrap: "aes192_wrap",
    rfc9481.id_aes256_wrap: "aes256_wrap",
}  # As per Section 4.3 in RFC 9481

RFC9481_OID_2_NAME = {}
RFC9481_OID_2_NAME.update(KM_KA_ALG)
RFC9481_OID_2_NAME.update(KM_KD_ALG)
RFC9481_OID_2_NAME.update(KM_KW_ALG)
RFC9481_OID_2_NAME.update(AES_CBC_OID_2_NAME)
RFC9481_OID_2_NAME.update(SUPPORTED_MAC_OID_2_NAME)
RFC9481_OID_2_NAME.update(SYMMETRIC_PROT_ALGO)
RFC9481_OID_2_NAME.update(KMAC_OID_2_NAME)
RFC9481_OID_2_NAME.update(RSASSA_PSS_OID_2_NAME)


ALL_KNOWN_OIDS_2_NAME = {}
ALL_KNOWN_OIDS_2_NAME.update({rfc6664.id_ecPublicKey: "ecPublicKey"})
ALL_KNOWN_OIDS_2_NAME.update(RFC9481_OID_2_NAME)
ALL_KNOWN_OIDS_2_NAME.update(HMAC_NAME_2_OID)


###########################
# HKDF with update RFC9688
###########################

id_alg = univ.ObjectIdentifier("1.2.840.113549.1.9.16.3")
HKDF_NAME_2_OID = {
    "hkdf-sha256": rfc8619.id_alg_hkdf_with_sha256,
    "hkdf-sha384": rfc8619.id_alg_hkdf_with_sha384,
    "hkdf-sha512": rfc8619.id_alg_hkdf_with_sha512,
    # As specified in rfc9688 section 5.
    "hkdf-sha3-224": id_alg + (32,),
    "hkdf-sha3-256": id_alg + (33,),
    "hkdf-sha3-384": id_alg + (34,),
    "hkdf-sha3-512": id_alg + (35,),
}

HKDF_OID_2_NAME = {v: k for k, v in HKDF_NAME_2_OID.items()}


KDF_OID_2_NAME = {}
KDF_OID_2_NAME.update(KM_KD_ALG)
KDF_OID_2_NAME.update(HKDF_OID_2_NAME)
KDF_OID_2_NAME.update({rfc9690.id_kdf_kdf3: "kdf3", rfc9690.id_kdf_kdf2: "kdf2"})


KDF_NAME_2_OID = {y: x for x, y in KDF_OID_2_NAME.items()}

ALL_KNOWN_OIDS_2_NAME.update(KDF_OID_2_NAME)

#########################
# PQ OIDs
#########################

# as of https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration.
# Define the root OID for NIST Algorithms as per the draft
# Define the OID for ML-KEM and ML-DSA

nist_algorithms_oid = rfc5990.nistAlgorithm
sig_algorithms_oid = nist_algorithms_oid + (3,)
kems_oid = nist_algorithms_oid + (4,)

# ###################------
# KEM OIDs
# ###################------


id_ml_kem_512 = kems_oid + (1,)
id_ml_kem_768 = kems_oid + (2,)
id_ml_kem_1024 = kems_oid + (3,)
ML_KEM_OID_2_NAME = {
    id_ml_kem_512: "ml-kem-512",
    id_ml_kem_768: "ml-kem-768",
    id_ml_kem_1024: "ml-kem-1024",
}

ML_KEM_NAME_2_OID = {
    "ml-kem-512": id_ml_kem_512,
    "ml-kem-768": id_ml_kem_768,
    "ml-kem-1024": id_ml_kem_1024,
}


# saves all OIDs related to PQ-KEM algorithm.
PQ_KEM_NAME_2_OID = {}
PQ_KEM_NAME_2_OID.update(ML_KEM_NAME_2_OID)

ALL_KNOWN_OIDS_2_NAME.update(PQ_KEM_NAME_2_OID)

# ###################------
# PQ Sig OIDs
# ###################------

id_ml_dsa_44_oid = sig_algorithms_oid + (17,)
id_ml_dsa_65_oid = sig_algorithms_oid + (18,)
id_ml_dsa_87_oid = sig_algorithms_oid + (19,)
id_ml_dsa_44_with_sha512 = sig_algorithms_oid + (32,)
id_ml_dsa_65_with_sha512 = sig_algorithms_oid + (33,)
id_ml_dsa_87_with_sha512 = sig_algorithms_oid + (34,)

ML_DSA_OID_2_NAME = {
    id_ml_dsa_44_oid: "ml-dsa-44",
    id_ml_dsa_65_oid: "ml-dsa-65",
    id_ml_dsa_87_oid: "ml-dsa-87",
}

ML_DSA_PRE_HASH_OID_2_NAME = {
    id_ml_dsa_44_with_sha512: "ml-dsa-44-sha512",
    id_ml_dsa_65_with_sha512: "ml-dsa-65-sha512",
    id_ml_dsa_87_with_sha512: "ml-dsa-87-sha512",
}
ML_DSA_OID_2_NAME.update(ML_DSA_PRE_HASH_OID_2_NAME)

ML_DSA_NAME_2_OID = {y: x for x, y in ML_DSA_OID_2_NAME.items()}


SIG_ALGS = "2.16.840.1.101.3.4.3"
id_slh_dsa_sha2_128s = f"{SIG_ALGS}.20"
id_slh_dsa_sha2_128f = f"{SIG_ALGS}.21"
id_slh_dsa_sha2_192s = f"{SIG_ALGS}.22"
id_slh_dsa_sha2_192f = f"{SIG_ALGS}.23"
id_slh_dsa_sha2_256s = f"{SIG_ALGS}.24"
id_slh_dsa_sha2_256f = f"{SIG_ALGS}.25"
id_slh_dsa_shake_128s = f"{SIG_ALGS}.26"
id_slh_dsa_shake_128f = f"{SIG_ALGS}.27"
id_slh_dsa_shake_192s = f"{SIG_ALGS}.28"
id_slh_dsa_shake_192f = f"{SIG_ALGS}.29"
id_slh_dsa_shake_256s = f"{SIG_ALGS}.30"
id_slh_dsa_shake_256f = f"{SIG_ALGS}.31"

SLH_DSA_NAME_2_OID = {
    "slh-dsa-sha2-128s": univ.ObjectIdentifier(id_slh_dsa_sha2_128s),
    "slh-dsa-sha2-128f": univ.ObjectIdentifier(id_slh_dsa_sha2_128f),
    "slh-dsa-sha2-192s": univ.ObjectIdentifier(id_slh_dsa_sha2_192s),
    "slh-dsa-sha2-192f": univ.ObjectIdentifier(id_slh_dsa_sha2_192f),
    "slh-dsa-sha2-256s": univ.ObjectIdentifier(id_slh_dsa_sha2_256s),
    "slh-dsa-sha2-256f": univ.ObjectIdentifier(id_slh_dsa_sha2_256f),
    "slh-dsa-shake-128s": univ.ObjectIdentifier(id_slh_dsa_shake_128s),
    "slh-dsa-shake-128f": univ.ObjectIdentifier(id_slh_dsa_shake_128f),
    "slh-dsa-shake-192s": univ.ObjectIdentifier(id_slh_dsa_shake_192s),
    "slh-dsa-shake-192f": univ.ObjectIdentifier(id_slh_dsa_shake_192f),
    "slh-dsa-shake-256s": univ.ObjectIdentifier(id_slh_dsa_shake_256s),
    "slh-dsa-shake-256f": univ.ObjectIdentifier(id_slh_dsa_shake_256f),
}

SLH_DSA_PRE_HASH_NAME_2_OID = {
    "slh-dsa-sha2-128s-sha256": sig_algorithms_oid + (35,),
    "slh-dsa-sha2-128f-sha256": sig_algorithms_oid + (36,),
    "slh-dsa-sha2-192s-sha512": sig_algorithms_oid + (37,),
    "slh-dsa-sha2-192f-sha512": sig_algorithms_oid + (38,),
    "slh-dsa-sha2-256s-sha512": sig_algorithms_oid + (39,),
    "slh-dsa-sha2-256f-sha512": sig_algorithms_oid + (40,),
    "slh-dsa-shake-128s-shake128": sig_algorithms_oid + (41,),
    "slh-dsa-shake-128f-shake128": sig_algorithms_oid + (42,),
    "slh-dsa-shake-192s-shake256": sig_algorithms_oid + (43,),
    "slh-dsa-shake-192f-shake256": sig_algorithms_oid + (44,),
    "slh-dsa-shake-256s-shake256": sig_algorithms_oid + (45,),
    "slh-dsa-shake-256f-shake256": sig_algorithms_oid + (46,),
}

# As per RFC 9814 defined.
# Those hash algorithms are used to the SignedData structure inside the signature
# and for the certificate confirmation, when the signature algorithm is one of the
# SLH-DSA algorithms.
# Uses the same for the Pre-Hash variants.
SLH_DSA_HASH_MAPPING = {
    "slh-dsa-sha2-128s": "sha256",
    "slh-dsa-sha2-128f": "sha256",
    "slh-dsa-sha2-192s": "sha512",
    "slh-dsa-sha2-192f": "sha512",
    "slh-dsa-sha2-256s": "sha512",
    "slh-dsa-sha2-256f": "sha512",
    "slh-dsa-shake-128s": "shake128",
    "slh-dsa-shake-128f": "shake128",
    "slh-dsa-shake-192s": "shake256",
    "slh-dsa-shake-192f": "shake256",
    "slh-dsa-shake-256s": "shake256",
    "slh-dsa-shake-256f": "shake256",
}


SLH_DSA_PRE_HASH_OID_2_NAME = {y: x for x, y in SLH_DSA_PRE_HASH_NAME_2_OID.items()}

SLH_DSA_NAME_2_OID.update(SLH_DSA_PRE_HASH_NAME_2_OID)

SLH_DSA_OID_2_NAME = {y: x for x, y in SLH_DSA_NAME_2_OID.items()}


PQ_STATEFUL_HASH_SIG_NAME_2_OID = {
    "xmss": univ.ObjectIdentifier("1.3.6.1.5.5.7.6.34"),
    "xmssmt": univ.ObjectIdentifier("1.3.6.1.5.5.7.6.35"),
    "hss": rfc9708.id_alg_hss_lms_hashsig,
}

PQ_STATEFUL_HASH_SIG_OID_2_NAME = {y: x for x, y in PQ_STATEFUL_HASH_SIG_NAME_2_OID.items()}


PQ_SIG_NAME_2_OID = {}
PQ_SIG_NAME_2_OID.update(ML_DSA_NAME_2_OID)
PQ_SIG_NAME_2_OID.update(SLH_DSA_NAME_2_OID)
PQ_SIG_NAME_2_OID.update(FALCON_NAME_2_OID)

PQ_SIG_OID_2_NAME = {y: x for x, y in PQ_SIG_NAME_2_OID.items()}

PQ_NAME_2_OID = {}
PQ_NAME_2_OID.update(PQ_SIG_NAME_2_OID)
PQ_NAME_2_OID.update(PQ_KEM_NAME_2_OID)
PQ_NAME_2_OID.update(PQ_STATEFUL_HASH_SIG_NAME_2_OID)

KEY_WRAP_NAME_2_OID = {
    "aes128_wrap": rfc3565.id_aes128_wrap,
    "aes192_wrap": rfc3565.id_aes192_wrap,
    "aes256_wrap": rfc3565.id_aes256_wrap,
    # currently unsupported, maybe available in the future.
    # is available inside the `cryptography` library,
    # but was not inside RFC9383.
    #   "aes128-wrap-pad": rfc5649.id_aes128_wrap_pad,
    #   "aes192-wrap-pad": rfc5649.id_aes192_wrap_pad,
    #   "aes256-wrap-pad": rfc5649.id_aes256_wrap_pad
}
KEY_WRAP_OID_2_NAME = {v: k for k, v in KEY_WRAP_NAME_2_OID.items()}

# ###################
# Update Maps
# ###################

OID_HASH_MAP.update(ML_DSA_OID_2_NAME)
ALL_KNOWN_OIDS_2_NAME.update(ML_DSA_NAME_2_OID)


# ###################
# Composite OIDS
# ###################

# Base Composite Signature OID
# Base Composite KEM OID

# ###################
# Composite KEM OIDS
# ###################


# XWING
XWING_OID_STR = "1.3.6.1.4.1.62253.25722"


ALL_COMPOSITE_SIG_COMBINATIONS = [
    {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
    {"pq_name": "ml-dsa-44", "trad_name": "ed25519", "curve": None},
    {"pq_name": "ml-dsa-44", "trad_name": "ecdsa", "curve": "secp256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "secp256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "secp384r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "brainpoolP256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ed25519", "curve": None},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "secp384r1"},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "brainpoolP384r1"},
    {"pq_name": "ml-dsa-87", "trad_name": "ed448", "curve": None},
    {"pq_name": "ml-dsa-87", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-dsa-87", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "secp512r1"},
]


PQ_SIG_NAME_2_OID.update(FALCON_NAME_2_OID)

PQ_KEM_NAME_2_OID.update({"sntrup761": id_sntrup761})
PQ_KEM_NAME_2_OID.update(MCELIECE_NAME_2_OID)
PQ_KEM_NAME_2_OID.update(FRODOKEM_NAME_2_OID)

PQ_KEM_OID_2_NAME = {y: x for x, y in PQ_KEM_NAME_2_OID.items()}

PQ_SIG_PRE_HASH_OID_2_NAME = {}
PQ_SIG_PRE_HASH_OID_2_NAME.update(ML_DSA_PRE_HASH_OID_2_NAME)
PQ_SIG_PRE_HASH_OID_2_NAME.update(SLH_DSA_PRE_HASH_OID_2_NAME)

PQ_SIG_PRE_HASH_NAME_2_OID = {y: x for x, y in PQ_SIG_PRE_HASH_OID_2_NAME.items()}

PQ_NAME_2_OID.update(PQ_KEM_NAME_2_OID)
PQ_NAME_2_OID.update(PQ_SIG_NAME_2_OID)

PQ_OID_2_NAME = {y: x for x, y in PQ_NAME_2_OID.items()}


KEM_OID_2_NAME = {y: x for x, y in PQ_KEM_NAME_2_OID.items()}
KEM_OID_2_NAME.update(CHEMPAT_OID_2_NAME)
KEM_OID_2_NAME.update({univ.ObjectIdentifier(XWING_OID_STR): "xwing"})
KEM_OID_2_NAME.update(COMPOSITE_KEM_OID_2_NAME)
KEM_OID_2_NAME.update({rfc5990.id_kem_rsa: "rsa-kem"})

KEM_NAME_2_OID = {y: x for x, y in KEM_OID_2_NAME.items()}

TRAD_STR_OID_TO_KEY_NAME = {
    "1.3.101.110": "x25519",
    "1.3.101.111": "x448",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.113549.1.9.16.3.14": "rsa-kem",
}


HYBRID_KEM_OID_2_NAME = {}
HYBRID_KEM_OID_2_NAME.update(CHEMPAT_OID_2_NAME)
HYBRID_KEM_OID_2_NAME.update({univ.ObjectIdentifier(XWING_OID_STR): "xwing"})
HYBRID_KEM_OID_2_NAME.update(COMPOSITE_KEM_OID_2_NAME)

COMPOSITE_SIG_NAME_TO_OID = {y: x for x, y in COMPOSITE_SIG_OID_TO_NAME.items()}

HYBRID_SIG_OID_2_NAME = {}
HYBRID_SIG_OID_2_NAME.update(COMPOSITE_SIG_OID_TO_NAME)

HYBRID_SIG_NAME_2_OID = {y: x for x, y in HYBRID_SIG_OID_2_NAME.items()}

HYBRID_OID_2_NAME = {}
HYBRID_OID_2_NAME.update(HYBRID_SIG_OID_2_NAME)
HYBRID_OID_2_NAME.update(HYBRID_KEM_OID_2_NAME)

HYBRID_NAME_2_OID = {y: x for x, y in HYBRID_OID_2_NAME.items()}

ALL_KNOWN_OIDS_2_NAME.update(PQ_OID_2_NAME)
ALL_KNOWN_OIDS_2_NAME.update(KEM_OID_2_NAME)
ALL_KNOWN_OIDS_2_NAME.update({rfc9481.rsaEncryption: "rsa"})
ALL_KNOWN_OIDS_2_NAME.update(TRAD_STR_OID_TO_KEY_NAME)
ALL_KNOWN_OIDS_2_NAME.update(HYBRID_OID_2_NAME)
# Extension Object Identifiers (OIDs)
id_ce_subjectAltPublicKeyInfo = rfc5280.id_ce + (72,)
id_ce_altSignatureAlgorithm = rfc5280.id_ce + (73,)
id_ce_altSignatureValue = rfc5280.id_ce + (74,)

EXTENSION_NAME_2_OID = {
    "ski": rfc5280.id_ce_subjectKeyIdentifier,
    "aia": rfc5280.id_pe_authorityInfoAccess,
    "key_usage": rfc5280.id_ce_keyUsage,
    "eku": rfc5280.id_ce_extKeyUsage,
    "basic_constraints": rfc5280.id_ce_basicConstraints,
    "aki": rfc5280.id_ce_authorityKeyIdentifier,
    "san": rfc5280.id_ce_subjectAltName,
    "ian": rfc5280.id_ce_issuerAltName,
    "dcd": id_ce_deltaCertificateDescriptor,
    "alt_sig_alg": id_ce_altSignatureAlgorithm,
    "alt_sig_val": id_ce_altSignatureValue,
    "alt_spki": id_ce_subjectAltPublicKeyInfo,
    "crl": rfc5280.id_ce_cRLDistributionPoints,
    "sun_hybrid_alt_sig": id_altSignatureExt,
    "sun_hybrid_alt_pubkey": id_altSubPubKeyExt,
    "idp": rfc5280.id_ce_issuingDistributionPoint,
    "related_cert": id_relatedCert,
    "private_key_usage_period": rfc5280.id_ce_privateKeyUsagePeriod,
    "cert_policies": rfc5280.id_ce_certificatePolicies,
    "ocsp_nonce": rfc9654.id_pkix_ocsp_nonce,
}

EXTENSION_OID_2_SPECS = {
    rfc5280.id_ce_authorityKeyIdentifier: rfc5280.AuthorityKeyIdentifier,
    rfc5280.id_ce_basicConstraints: rfc5280.BasicConstraints,
    rfc5280.id_ce_keyUsage: rfc5280.KeyUsage,
    rfc5280.id_ce_extKeyUsage: rfc5280.ExtKeyUsageSyntax,
    rfc5280.id_ce_subjectAltName: rfc5280.SubjectAltName,
    rfc5280.id_ce_issuerAltName: rfc5280.IssuerAltName,
    rfc5280.id_ce_subjectKeyIdentifier: rfc5280.SubjectKeyIdentifier,
    rfc5280.id_ce_cRLDistributionPoints: rfc5280.CRLDistributionPoints,
    rfc5280.id_ce_issuingDistributionPoint: rfc5280.IssuingDistributionPoint,
    rfc5280.id_pe_authorityInfoAccess: rfc5280.AuthorityInfoAccessSyntax,
    rfc5280.id_ce_privateKeyUsagePeriod: rfc5280.PrivateKeyUsagePeriod,
    rfc5280.id_ce_certificatePolicies: rfc5280.CertificatePolicies,
    rfc9654.id_pkix_ocsp_nonce: rfc9654.Nonce,
}

ALL_SIG_ALG_OID_2_NAME = {}
ALL_SIG_ALG_OID_2_NAME.update(TRAD_SIG_OID_2_NAME)
ALL_SIG_ALG_OID_2_NAME.update(PQ_SIG_OID_2_NAME)
ALL_SIG_ALG_OID_2_NAME.update(PQ_STATEFUL_HASH_SIG_NAME_2_OID)
ALL_SIG_ALG_OID_2_NAME.update(HYBRID_SIG_OID_2_NAME)

ALL_SIG_ALG_NAME_2_OID = {y: x for x, y in ALL_SIG_ALG_OID_2_NAME.items()}

EXTENSION_OID_2_NAME = {y: x for x, y in EXTENSION_NAME_2_OID.items()}

ALL_KNOWN_OIDS_2_NAME["id_ecPublicKey"] = rfc6664.id_ecPublicKey
ALL_KNOWN_OIDS_2_NAME["id_ecDH"] = rfc6664.id_ecDH
ALL_KNOWN_OIDS_2_NAME["id_ecMQV"] = rfc6664.id_ecMQV
ALL_KNOWN_OIDS_2_NAME.update(ALL_SIG_ALG_OID_2_NAME)
ALL_KNOWN_OIDS_2_NAME.update(EXTENSION_OID_2_NAME)
ALL_KNOWN_OIDS_2_NAME.update(COMPOSITE_KEM_OID_2_NAME)
ALL_KNOWN_NAMES_2_OID = {y: x for x, y in ALL_KNOWN_OIDS_2_NAME.items()}


ENC_KEY_AGREEMENT_TYPES_OID_2_NAME = {
    rfc9481.rsaEncryption: "rsa",
    rfc9481.id_X25519: "x25519",
    rfc9481.id_X448: "x448",
}

ENC_KEY_AGREEMENT_TYPES_OID_2_NAME.update(CURVE_OID_2_NAME)

ENC_KEY_AGREEMENT_TYPES_NAME_2_OID = {y: x for x, y in ENC_KEY_AGREEMENT_TYPES_OID_2_NAME.items()}


OID_CM_NAME_MAP = {
    "CN": rfc5280.id_at_commonName,
    "L": rfc5280.id_at_localityName,
    "ST": rfc5280.id_at_stateOrProvinceName,
    "O": rfc5280.id_at_organizationName,
    "OU": rfc5280.id_at_organizationalUnitName,
    "C": rfc5280.id_at_countryName,
    "STREET": id_at_streetAddress,
    "DC": rfc5280.id_domainComponent,
    "SN": rfc5280.id_at_serialNumber,
    "T": rfc5280.id_at_title,
    "GN": rfc5280.id_at_givenName,
    "S": rfc5280.id_at_surname,
    "I": rfc5280.id_at_initials,
    "GQ": rfc5280.id_at_generationQualifier,
    "DNQ": rfc5280.id_at_dnQualifier,
    "PSEUDONYM": rfc5280.id_at_pseudonym,
    "NAME": rfc5280.id_at_name,
    "EMAIL": rfc5280.id_emailAddress,
    "businessCategory": id_at_businessCategory,
    "postalCode": id_at_postalCode,
    "organizationIdentifier": id_at_organizationIdentifier,
}

PYASN1_CM_OID_2_NAME = {v: k for k, v in OID_CM_NAME_MAP.items()}

CERT_ATTR_OID_2_STRUCTURE = {
    # X.520 attributes
    rfc5280.id_at_name: X520nameASN1(),
    rfc5280.id_at_surname: X520nameASN1(),
    rfc5280.id_at_givenName: X520nameASN1(),
    rfc5280.id_at_initials: X520nameASN1(),
    rfc5280.id_at_generationQualifier: X520nameASN1(),
    rfc5280.id_at_commonName: X520CommonNameASN1(),
    rfc5280.id_at_localityName: X520LocalityNameASN1(),
    rfc5280.id_at_stateOrProvinceName: X520StateOrProvinceNameASN1(),
    rfc5280.id_at_organizationName: X520OrganizationNameASN1(),
    rfc5280.id_at_organizationalUnitName: X520OrganizationalUnitNameASN1(),
    rfc5280.id_at_title: X520TitleASN1(),
    rfc5280.id_at_dnQualifier: rfc5280.X520dnQualifier(),
    rfc5280.id_at_countryName: X520countryNameASN1(),
    rfc5280.id_at_serialNumber: X520SerialNumberASN1(),
    rfc5280.id_at_pseudonym: X520PseudonymASN1(),
    # Other commonly used identifiers
    rfc5280.id_domainComponent: rfc5280.DomainComponent(),
    rfc5280.id_emailAddress: EmailAddressASN1(),
    id_at_businessCategory: X520BusinessCategoryASN1(),
    id_at_postalCode: X520PostalCodeASN1(),
    id_at_streetAddress: X520StreetAddressASN1(),
    id_at_organizationIdentifier: X520OrganizationIdentifier(),
}
CERT_ATTR_OID_2_CORRECT_STRUCTURE = {
    # X.520 attributes
    rfc5280.id_at_name: rfc5280.X520name(),
    rfc5280.id_at_surname: rfc5280.X520name(),
    rfc5280.id_at_givenName: rfc5280.X520name(),
    rfc5280.id_at_initials: rfc5280.X520name(),
    rfc5280.id_at_generationQualifier: rfc5280.X520name(),
    rfc5280.id_at_commonName: rfc5280.X520CommonName(),
    rfc5280.id_at_localityName: rfc5280.X520LocalityName(),
    rfc5280.id_at_stateOrProvinceName: rfc5280.X520StateOrProvinceName(),
    rfc5280.id_at_organizationName: rfc5280.X520OrganizationName(),
    rfc5280.id_at_organizationalUnitName: rfc5280.X520OrganizationalUnitName(),
    rfc5280.id_at_title: rfc5280.X520Title(),
    rfc5280.id_at_dnQualifier: rfc5280.X520dnQualifier(),
    rfc5280.id_at_countryName: rfc5280.X520countryName(),
    rfc5280.id_at_serialNumber: rfc5280.X520SerialNumber(),
    rfc5280.id_at_pseudonym: rfc5280.X520Pseudonym(),
    # Other commonly used identifiers
    rfc5280.id_domainComponent: rfc5280.DomainComponent(),
    rfc5280.id_emailAddress: rfc5280.EmailAddress(),
    id_at_businessCategory: X520BusinessCategory(),
    id_at_postalCode: X520PostalCode(),
    id_at_streetAddress: X520StreetAddress(),
    id_at_organizationIdentifier: X520OrganizationIdentifier(),
}
