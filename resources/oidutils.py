"""Defines Object Identifiers (OIDs) and mappings for the Test-Suite."""

# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pq_logic.tmp_oids import (
    CHEMPAT_OID_2_NAME,
    CMS_COMPOSITE_OID_2_HASH,
    COMPOSITE_KEM_OID_2_NAME,
    FALCON_NAME_2_OID,
    FRODOKEM_NAME_2_OID,
    FRODOKEM_OID_2_NAME,
    HASH_COMPOSITE_NAME_TO_OID,
    MCELIECE_NAME_2_OID,
    MCELIECE_OID_2_NAME,
    PREHASH_OID_2_HASH,
    PURE_COMPOSITE_NAME_TO_OID,
    PURE_OID_TO_HASH,
    id_sntrup761_str,
)
from pyasn1.type import univ
from pyasn1_alt_modules import (
    rfc3370,
    rfc3565,
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
RSA_SHA_OID_2_NAME = {
    rfc8017.sha1WithRSAEncryption: "rsa-sha1",
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
    rfc9481.id_RSASSA_PSS: "rsassa_pss",
    rfc9481.id_RSASSA_PSS_SHAKE128: "rsassa_pss-shake128",
    rfc9481.id_RSASSA_PSS_SHAKE256: "rsassa_pss-shake256",
}


# These mappings facilitate the identification of the specific HMAC-SHA algorithm
# used for MAC (Message Authentication Code) protection algorithms for the PKIMessage.

HMAC_OID_2_NAME = {
    rfc3370.hMAC_SHA1: "hmac-sha1",
    rfc9481.id_hmacWithSHA224: "hmac-sha224",
    rfc9481.id_hmacWithSHA256: "hmac-sha256",
    rfc9481.id_hmacWithSHA384: "hmac-sha384",
    rfc9481.id_hmacWithSHA512: "hmac-sha512",
}


# These mappings facilitate the identification of the specific KMAC-SHA algorithm
# used for protecting PKIMessages with KMAC (Keccak Message Authentication Code.
KMAC_OID_2_NAME = {rfc9481.id_KMACWithSHAKE128: "kmac-shake128", rfc9481.id_KMACWithSHAKE256: "kmac-shake256"}


# Used for preparing Signature Protection of the PKIMessage.
SHA_OID_2_NAME = {
    rfc5480.id_sha1: "sha1",
    rfc5480.id_sha224: "sha224",
    rfc5480.id_sha256: "sha256",
    rfc5480.id_sha384: "sha384",
    rfc5480.id_sha512: "sha512",
}

id_hash_algs = "2.16.840.1.101.3.4.2"

SHA3_OID_2_NAME = {
    univ.ObjectIdentifier(f"{id_hash_algs}.7"): "sha3-224",
    univ.ObjectIdentifier(f"{id_hash_algs}.8"): "sha3-256",
    univ.ObjectIdentifier(f"{id_hash_algs}.9"): "sha3-384",
    univ.ObjectIdentifier(f"{id_hash_algs}.10"): "sha3-512",
    univ.ObjectIdentifier(f"{id_hash_algs}.11"): "shake128",
    univ.ObjectIdentifier(f"{id_hash_algs}.12"): "shake256",
}


# map OIDs of signature algorithms to the names of the hash functions
# used in the signature; this is needed to compute the certificate has for
# certConfirm messages, since it must contain the hash of the certificate,
# computed with the same algorithm as the one in the signature
OID_HASH_MAP: Dict[univ.ObjectIdentifier, str] = {}
OID_HASH_MAP.update(RSA_SHA_OID_2_NAME)
OID_HASH_MAP.update(ECDSA_SHA_OID_2_NAME)
OID_HASH_MAP.update(HMAC_OID_2_NAME)
OID_HASH_MAP.update(SHA_OID_2_NAME)
OID_HASH_MAP.update(SHA3_OID_2_NAME)

OID_HASH_NAME_2_OID = {v: k for k, v in OID_HASH_MAP.items()}

# Updating the main dictionary with RSA and ECDSA OIDs
# to check quickly if a given OID is supported by the Test-Suite
MSG_SIG_ALG = {rfc9481.id_Ed25519: "ed25519", rfc9481.id_Ed448: "ed448"}
MSG_SIG_ALG.update(RSA_SHA_OID_2_NAME)
MSG_SIG_ALG.update(RSASSA_PSS_OID_2_NAME)
MSG_SIG_ALG.update(ECDSA_SHA_OID_2_NAME)

LWCMP_MAC_OID_2_NAME = {rfc9480.id_PasswordBasedMac: "password_based_mac", rfc8018.id_PBMAC1: "pbmac1"}


SYMMETRIC_PROT_ALGO = {}
SYMMETRIC_PROT_ALGO.update(
    {
        rfc9480.id_DHBasedMac: "dh_based_mac",
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
SUPPORTED_MAC_NAME_2_OID = {y: x for x, y in SUPPORTED_MAC_OID_2_NAME.items()}

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
NAME_MAP = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "CN": NameOID.COMMON_NAME,
}
OID_CM_NAME_MAP = {
    "C": rfc5280.id_at_countryName,
    "ST": rfc5280.id_at_stateOrProvinceName,
    "L": rfc5280.id_at_localityName,
    "O": rfc5280.id_at_organizationName,
    "CN": rfc5280.id_at_commonName,
    "OU": rfc5280.id_at_organizationalUnitName,
}
PYASN1_CM_NAME_2_OIDS = {v: k for k, v in OID_CM_NAME_MAP.items()}

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
}


# TODO update for more.
CURVE_NAMES_TO_OIDS = {
    "secp192r1": rfc5480.secp192r1,  # NIST P-192
    "prime192v1": rfc5480.secp192r1,  # NIST P-192 (alias)
    "secp224r1": rfc5480.secp224r1,  # NIST P-224
    "prime224v1": rfc5480.secp224r1,  # NIST P-224 (alias)
    "secp256r1": rfc5480.secp256r1,  # NIST P-256
    "prime256v1": rfc5480.secp256r1,  # NIST P-256 (alias)
    "secp384r1": rfc5480.secp384r1,  # NIST P-384
    "secp521r1": rfc5480.secp521r1,  # NIST P-521
}

# Saves the supported curves to perform a lookup for key generation.
CURVE_NAMES_TO_INSTANCES = {
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
    "brainpoolp256r1": ec.BrainpoolP256R1(),  # Brainpool curve over a 256 bit prime field (alias)
    "brainpoolp384r1": ec.BrainpoolP384R1(),  # Brainpool curve over a 384 bit prime field
    "brainpoolp512r1": ec.BrainpoolP512R1(),  # Brainpool curve over a 512 bit prime field
}

CURVE_OIDS_2_NAME = {
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

KM_KA_ALG = {
    # Section 4.1.1: Diffie-Hellman
    rfc9481.id_alg_ESDH: "esdh",
    # Section 4.1.2: ECDH
    rfc9481.dhSinglePass_stdDH_sha224kdf_scheme: "stdDH-SHA224",
    rfc9481.dhSinglePass_stdDH_sha256kdf_scheme: "stdDH-SHA256",
    rfc9481.dhSinglePass_stdDH_sha384kdf_scheme: "stdDH-SHA384",
    rfc9481.dhSinglePass_stdDH_sha512kdf_scheme: "stdDH-SHA512",
    rfc9481.dhSinglePass_cofactorDH_sha224kdf_scheme: "cofactorDH-SHA224",
    rfc9481.dhSinglePass_cofactorDH_sha256kdf_scheme: "cofactorDH-SHA256",
    rfc5753.dhSinglePass_cofactorDH_sha384kdf_scheme: "cofactorDH-SHA384",
    rfc5753.dhSinglePass_cofactorDH_sha512kdf_scheme: "cofactorDH-SHA512",
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

KM_KA_ALG.update(ECMQV)

KM_KD_ALG = {rfc9481.id_PBKDF2}  # As per Section 4.4 in RFC 9481
KM_KW_ALG = {
    rfc9481.id_aes128_wrap: "aes128_wrap",
    rfc9481.id_aes192_wrap: "aes192_wrap",
    rfc9481.id_aes256_wrap: "aes256_wrap",
}  # As per Section 4.3 in RFC 9481


ALL_KNOWN_PROTECTION_OIDS = {}
ALL_KNOWN_PROTECTION_OIDS.update({rfc6664.id_ecPublicKey: "ecPubKey"})
ALL_KNOWN_PROTECTION_OIDS.update(SUPPORTED_MAC_OID_2_NAME)
ALL_KNOWN_PROTECTION_OIDS.update(SYMMETRIC_PROT_ALGO)
ALL_KNOWN_PROTECTION_OIDS.update(KMAC_OID_2_NAME)
ALL_KNOWN_PROTECTION_OIDS.update(RSASSA_PSS_OID_2_NAME)


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

# ###################-----
# PQ OIDs
# ###################-----

# as of https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration.
# Define the root OID for NIST Algorithms as per the draft
# Define the OID for ML-KEM and ML-DSA

nist_algorithms_oid = rfc5990.nistAlgorithm
sig_algorithms_oid = nist_algorithms_oid + (3,)
kems_oid = nist_algorithms_oid + (4,)

# ###################------
# KEM OIDs
# ###################------
id_KemBasedMac = univ.ObjectIdentifier("1.2.840.113533.7.66.16")


id_alg_ml_kem_512_oid = kems_oid + (1,)
id_ml_kem_768_oid = kems_oid + (2,)
id_alg_ml_kem_1024_oid = kems_oid + (3,)
ML_KEM_OID_2_NAME = {
    id_alg_ml_kem_512_oid: "ml-kem-512",
    id_ml_kem_768_oid: "ml-kem-768",
    id_alg_ml_kem_1024_oid: "ml-kem-1024",
}

ML_KEM_NAME_2_OID = {
    "ml-kem-512": id_alg_ml_kem_512_oid,
    "ml-kem-768": id_ml_kem_768_oid,
    "ml-kem-1024": id_alg_ml_kem_1024_oid,
}


# saves all OIDs related to PQ-KEM algorithm.
PQ_KEM_NAME_2_OID = {}
PQ_KEM_NAME_2_OID.update(ML_KEM_NAME_2_OID)

PQ_KEM_OID_2_NAME = {y: x for x, y in PQ_KEM_NAME_2_OID.items()}

ALL_KNOWN_PROTECTION_OIDS.update(PQ_KEM_NAME_2_OID)

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

SLH_DSA_NAME_2_OID = {
    "slh-dsa-sha2-128s": sig_algorithms_oid + (20,),
    "slh-dsa-sha2-128f": sig_algorithms_oid + (21,),
    "slh-dsa-sha2-192s": sig_algorithms_oid + (22,),
    "slh-dsa-sha2-192f": sig_algorithms_oid + (23,),
    "slh-dsa-sha2-256s": sig_algorithms_oid + (24,),
    "slh-dsa-sha2-256f": sig_algorithms_oid + (25,),
    "slh-dsa-shake-128s": sig_algorithms_oid + (26,),
    "slh-dsa-shake-128f": sig_algorithms_oid + (27,),
    "slh-dsa-shake-192s": sig_algorithms_oid + (28,),
    "slh-dsa-shake-192f": sig_algorithms_oid + (29,),
    "slh-dsa-shake-256s": sig_algorithms_oid + (30,),
    "slh-dsa-shake-256f": sig_algorithms_oid + (31,),
}



SLH_DSA_NAME_2_OID_PRE_HASH = {
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

SLH_DSA_OID_2_PRE_HASH_NAME = {y: x for x, y in SLH_DSA_NAME_2_OID_PRE_HASH.items()}

SLH_DSA_NAME_2_OID.update(SLH_DSA_NAME_2_OID_PRE_HASH)

SLH_DSA_OID_2_NAME = {y: x for x, y in SLH_DSA_NAME_2_OID.items()}


PQ_SIG_NAME_2_OID = {}
PQ_SIG_NAME_2_OID.update(ML_DSA_NAME_2_OID)
PQ_SIG_NAME_2_OID.update(SLH_DSA_NAME_2_OID)


PQ_NAME_2_OID = {}
PQ_NAME_2_OID.update(PQ_SIG_NAME_2_OID)
PQ_NAME_2_OID.update(PQ_KEM_NAME_2_OID)

PQ_OID_2_NAME = {y: x for x, y in PQ_NAME_2_OID.items()}

PQ_NAME_2_OID.update(FALCON_NAME_2_OID)

KEY_WRAP_NAME_2_OID = {
    "aes128-wrap": rfc3565.id_aes128_wrap,
    "aes192-wrap": rfc3565.id_aes192_wrap,
    "aes256-wrap": rfc3565.id_aes256_wrap,
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
ALL_KNOWN_PROTECTION_OIDS.update(ML_DSA_NAME_2_OID)


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


ALL_POSS_COMBINATIONS = [
    {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
    {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
    {"pq_name": "ml-dsa-44", "trad_name": "ed25519", "curve": None},
    {"pq_name": "ml-dsa-44", "trad_name": "ecdsa", "curve": "secp256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "secp384r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "brainpoolP256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ed25519", "curve": None},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "secp384r1"},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "brainpoolP384r1"},
    {"pq_name": "ml-dsa-87", "trad_name": "ed448", "curve": None},
]


CMS_COMPOSITE_OID_2_HASH.update(PURE_OID_TO_HASH)
CMS_COMPOSITE_OID_2_HASH.update(PREHASH_OID_2_HASH)

# custom from oqs


CMS_COMPOSITE_NAME_2_OID = {}
CMS_COMPOSITE_NAME_2_OID.update(PURE_COMPOSITE_NAME_TO_OID)
CMS_COMPOSITE_NAME_2_OID.update(HASH_COMPOSITE_NAME_TO_OID)


CMS_COMPOSITE_OID_2_NAME: Dict[univ.ObjectIdentifier, str] = {y: x for x, y in CMS_COMPOSITE_NAME_2_OID.items()}




PQ_SIG_NAME_2_OID.update(FALCON_NAME_2_OID)

PQ_KEM_NAME_2_OID.update({"sntrup761": id_sntrup761_str})
PQ_KEM_NAME_2_OID.update(MCELIECE_NAME_2_OID)


PQ_SIG_PRE_HASH_OID_2_NAME = {}
PQ_SIG_PRE_HASH_OID_2_NAME.update(ML_DSA_PRE_HASH_OID_2_NAME)
PQ_SIG_PRE_HASH_OID_2_NAME.update(SLH_DSA_OID_2_PRE_HASH_NAME)

PQ_NAME_2_OID.update(PQ_KEM_NAME_2_OID)
PQ_NAME_2_OID.update(PQ_SIG_NAME_2_OID)
PQ_NAME_2_OID.update(FRODOKEM_NAME_2_OID)
PQ_OID_2_NAME = {y: x for x, y in PQ_NAME_2_OID.items()}


KEM_OID_2_NAME = {y: x for x, y in PQ_KEM_NAME_2_OID.items()}
KEM_OID_2_NAME.update(FRODOKEM_OID_2_NAME)
KEM_OID_2_NAME.update(MCELIECE_OID_2_NAME)
KEM_OID_2_NAME.update(CHEMPAT_OID_2_NAME)
KEM_OID_2_NAME.update({univ.ObjectIdentifier(XWING_OID_STR): "xwing"})
KEM_OID_2_NAME.update(COMPOSITE_KEM_OID_2_NAME)


ALL_KNOWN_PROTECTION_OIDS.update(PQ_OID_2_NAME)
ALL_KNOWN_PROTECTION_OIDS.update(KEM_OID_2_NAME)
ALL_KNOWN_PROTECTION_OIDS.update({rfc9481.rsaEncryption : "rsa_encryption"})
