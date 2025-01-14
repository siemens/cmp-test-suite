# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5990, rfc9480

##############################
# Test Suite OIDs
##############################

# Define the OID for the test suite oids.
id_test_suite_oid = f"{rfc9480.id_it}.9996.9999"

# Define the OID for the test suite KEM

id_kem_test_suite = f"{id_test_suite_oid}.2"

# Define the OID for the hybrid KEM test suite.
id_hybrid_kems_test_suite = f"{id_test_suite_oid}.3"

# Define the OID for the hybrid signature test suite.
id_hybrid_sig_test_suite = f"{id_test_suite_oid}.4"


# Hybrid KEM's.
id_composite_kem_test_suite = f"{id_hybrid_kems_test_suite}.1"
id_Chempat = f"{id_hybrid_kems_test_suite}.2"


# Hybrid Signature's.

id_composite_sig_test_suite = f"{id_hybrid_sig_test_suite}.1"

# used inside cert-binding-for-multiple-authentication.
id_hybrid_sig_multi_auth = univ.ObjectIdentifier(f"{id_hybrid_sig_test_suite}.2")

# used inside the cert discovery methode.
id_hybrid_sig_cert_binding = univ.ObjectIdentifier(f"{id_hybrid_sig_test_suite}.3")

# OIDs used for the sun-hybrid signature methode.
id_hybrid_sun = univ.ObjectIdentifier(f"{id_hybrid_sig_test_suite}.4")

nist_algorithms_oid = rfc5990.nistAlgorithm

# Ref: https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md

id_falcon_512 = univ.ObjectIdentifier("1.3.9999.3.6")
id_falcon_1024 = univ.ObjectIdentifier("1.3.9999.3.9")

id_falcon_padded_512 = univ.ObjectIdentifier("1.3.9999.3.16")
id_falcon_padded_1024 = univ.ObjectIdentifier("1.3.9999.3.19")


FALCON_NAME_2_OID = {
    "falcon-512": id_falcon_512,
    "falcon-padded-512": id_falcon_padded_512,
    "falcon-1024": id_falcon_1024,
    "falcon-padded-1024": id_falcon_padded_1024,
}


id_ntru = f"{id_kem_test_suite}.1"
id_sntrup761_str = f"{id_ntru}.1"


id_mceliece = f"{id_kem_test_suite}.2"

MCELIECE_NAME_2_OID = {
    "mceliece-348864": f"{id_mceliece}.1",
    "mceliece-460896": f"{id_mceliece}.2",
    "mceliece-6688128": f"{id_mceliece}.3",
    "mceliece-6960119": f"{id_mceliece}.4",
    "mceliece-8192128": f"{id_mceliece}.5",
}

id_frodokem = f"{id_kem_test_suite}.3"

FRODOKEM_NAME_2_OID = {
    "frodokem-640-aes": f"{id_frodokem}.1",
    "frodokem-640-shake": f"{id_frodokem}.2",
    "frodokem-976-aes": f"{id_frodokem}.3",
    "frodokem-976-shake": f"{id_frodokem}.4",
    "frodokem-1344-aes": f"{id_frodokem}.5",
    "frodokem-1344-shake": f"{id_frodokem}.6",
}

FRODOKEM_OID_2_NAME = {y: x for x, y in FRODOKEM_NAME_2_OID.items()}
MCELIECE_OID_2_NAME = {y: x for x, y in MCELIECE_NAME_2_OID.items()}

id_it_KemCiphertextInfo = rfc9480.id_it + (9999,)

id_CompSig = "2.16.840.1.114027.80.8.1"
id_CompKEM = "2.16.840.1.114027.80.5.2"

id_HashMLDSA44_RSA2048_PSS_SHA256 = univ.ObjectIdentifier(f"{id_CompSig}.40")
id_HashMLDSA44_RSA2048_PKCS15_SHA256 = univ.ObjectIdentifier(f"{id_CompSig}.41")
id_HashMLDSA44_Ed25519_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.42")
id_HashMLDSA44_ECDSA_P256_SHA256 = univ.ObjectIdentifier(f"{id_CompSig}.43")
id_HashMLDSA65_RSA3072_PSS_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.44")
id_HashMLDSA65_RSA3072_PKCS15_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.45")
id_HashMLDSA65_RSA4096_PSS_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.46")
id_HashMLDSA65_RSA4096_PKCS15_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.47")
id_HashMLDSA65_ECDSA_P384_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.48")
id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.49")
id_HashMLDSA65_Ed25519_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.50")
id_HashMLDSA87_ECDSA_P384_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.51")
id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.52")
id_HashMLDSA87_Ed448_SHA512 = univ.ObjectIdentifier(f"{id_CompSig}.53")

PREHASH_OID_2_HASH = {
    id_HashMLDSA44_RSA2048_PSS_SHA256: "sha256",
    id_HashMLDSA44_RSA2048_PKCS15_SHA256: "sha256",
    id_HashMLDSA44_Ed25519_SHA512: "sha512",
    id_HashMLDSA44_ECDSA_P256_SHA256: "sha256",
    id_HashMLDSA65_RSA3072_PSS_SHA512: "sha512",
    id_HashMLDSA65_RSA3072_PKCS15_SHA512: "sha512",
    id_HashMLDSA65_RSA4096_PSS_SHA512: "sha512",
    id_HashMLDSA65_RSA4096_PKCS15_SHA512: "sha512",
    id_HashMLDSA65_ECDSA_P384_SHA512: "sha512",
    id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512: "sha512",
    id_HashMLDSA65_Ed25519_SHA512: "sha512",
    id_HashMLDSA87_ECDSA_P384_SHA512: "sha512",
    id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512: "sha512",
    id_HashMLDSA87_Ed448_SHA512: "sha512",
}
CMS_COMPOSITE_OID_2_HASH = {}

id_MLDSA44_RSA2048_PSS = univ.ObjectIdentifier(f"{id_CompSig}.21")
id_MLDSA44_RSA2048_PKCS15 = univ.ObjectIdentifier(f"{id_CompSig}.22")
id_MLDSA44_Ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.23")
id_MLDSA44_ECDSA_P256 = univ.ObjectIdentifier(f"{id_CompSig}.24")
id_MLDSA65_RSA3072_PSS = univ.ObjectIdentifier(f"{id_CompSig}.26")
id_MLDSA65_RSA3072_PKCS15 = univ.ObjectIdentifier(f"{id_CompSig}.27")
id_MLDSA65_RSA4096_PSS = univ.ObjectIdentifier(f"{id_CompSig}.34")
id_MLDSA65_RSA4096_PKCS15 = univ.ObjectIdentifier(f"{id_CompSig}.35")
id_MLDSA65_ECDSA_P384 = univ.ObjectIdentifier(f"{id_CompSig}.28")
id_MLDSA65_ECDSA_brainpoolP256r1 = univ.ObjectIdentifier(f"{id_CompSig}.29")
id_MLDSA65_Ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.30")
id_MLDSA87_ECDSA_P384 = univ.ObjectIdentifier(f"{id_CompSig}.31")
id_MLDSA87_ECDSA_brainpoolP384r1 = univ.ObjectIdentifier(f"{id_CompSig}.32")
id_MLDSA87_Ed448 = univ.ObjectIdentifier(f"{id_CompSig}.33")


PURE_COMPOSITE_NAME_TO_OID = {
    "ml-dsa-44-rsa2048-pss": id_MLDSA44_RSA2048_PSS,
    "ml-dsa-44-rsa2048-pkcs15": id_MLDSA44_RSA2048_PKCS15,
    "ml-dsa-44-ed25519": id_MLDSA44_Ed25519,
    "ml-dsa-44-ecdsa-secp256r1": id_MLDSA44_ECDSA_P256,
    "ml-dsa-65-rsa3072-pss": id_MLDSA65_RSA3072_PSS,
    "ml-dsa-65-rsa3072-pkcs15": id_MLDSA65_RSA3072_PKCS15,
    "ml-dsa-65-rsa4096-pss": id_MLDSA65_RSA4096_PSS,
    "ml-dsa-65-rsa4096-pkcs15": id_MLDSA65_RSA4096_PKCS15,
    "ml-dsa-65-ecdsa-secp384r1": id_MLDSA65_ECDSA_P384,
    "ml-dsa-65-ecdsa-brainpoolp256r1": id_MLDSA65_ECDSA_brainpoolP256r1,
    "ml-dsa-65-ed25519": id_MLDSA65_Ed25519,
    "ml-dsa-87-ecdsa-secp384r1": id_MLDSA87_ECDSA_P384,
    "ml-dsa-87-ecdsa-brainpoolp384r1": id_MLDSA87_ECDSA_brainpoolP384r1,
    "ml-dsa-87-ed448": id_MLDSA87_Ed448,
}
HASH_COMPOSITE_NAME_TO_OID = {
    "hash-ml-dsa-44-rsa2048-pss": id_HashMLDSA44_RSA2048_PSS_SHA256,
    "hash-ml-dsa-44-rsa2048-pkcs15": id_HashMLDSA44_RSA2048_PKCS15_SHA256,
    "hash-ml-dsa-44-ed25519": id_HashMLDSA44_Ed25519_SHA512,
    "hash-ml-dsa-44-ecdsa-secp256r1": id_HashMLDSA44_ECDSA_P256_SHA256,
    "hash-ml-dsa-65-rsa3072-pss": id_HashMLDSA65_RSA3072_PSS_SHA512,
    "hash-ml-dsa-65-rsa3072-pkcs15": id_HashMLDSA65_RSA3072_PKCS15_SHA512,
    "hash-ml-dsa-65-rsa4096-pss": id_HashMLDSA65_RSA4096_PSS_SHA512,
    "hash-ml-dsa-65-rsa4096-pkcs15": id_HashMLDSA65_RSA4096_PKCS15_SHA512,
    "hash-ml-dsa-65-ecdsa-secp384r1": id_HashMLDSA65_ECDSA_P384_SHA512,
    "hash-ml-dsa-65-ecdsa-brainpoolp256r1": id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512,
    "hash-ml-dsa-65-ed25519": id_HashMLDSA65_Ed25519_SHA512,
    "hash-ml-dsa-87-ecdsa-secp384r1": id_HashMLDSA87_ECDSA_P384_SHA512,
    "hash-ml-dsa-87-ecdsa-brainpoolp384r1": id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512,
    "hash-ml-dsa-87-ed448": id_HashMLDSA87_Ed448_SHA512,
}
id_rsa_kem_spki = univ.ObjectIdentifier("1.2.840.113549.1.9.16.3")
PURE_OID_TO_HASH = {
    id_MLDSA44_RSA2048_PSS: "sha256",
    id_MLDSA44_RSA2048_PKCS15: "sha256",
    id_MLDSA44_Ed25519: None,
    id_MLDSA44_ECDSA_P256: "sha256",
    id_MLDSA65_RSA3072_PSS: "sha256",
    id_MLDSA65_RSA3072_PKCS15: "sha256",
    id_MLDSA65_RSA4096_PSS: "sha384",
    id_MLDSA65_RSA4096_PKCS15: "sha384",
    id_MLDSA65_ECDSA_P384: "sha384",
    id_MLDSA65_ECDSA_brainpoolP256r1: "sha256",
    id_MLDSA65_Ed25519: None,
    id_MLDSA87_ECDSA_P384: "sha384",
    id_MLDSA87_ECDSA_brainpoolP384r1: "sha384",
    id_MLDSA87_Ed448: None,
}


######################
# Composite KEM
######################


id_MLKEM768_RSA2048 = univ.ObjectIdentifier(f"{id_CompKEM}.21")
id_MLKEM768_RSA3072 = univ.ObjectIdentifier(f"{id_CompKEM}.22")
id_MLKEM768_RSA4096 = univ.ObjectIdentifier(f"{id_CompKEM}.23")
id_MLKEM768_X25519 = univ.ObjectIdentifier(f"{id_CompKEM}.24")
id_MLKEM768_ECDH_P384 = univ.ObjectIdentifier(f"{id_CompKEM}.25")
id_MLKEM768_ECDH_brainpoolP256r1 = univ.ObjectIdentifier(f"{id_CompKEM}.26")

id_MLKEM1024_ECDH_P384 = univ.ObjectIdentifier(f"{id_CompKEM}.27")
id_MLKEM1024_ECDH_brainpoolP384r1 = univ.ObjectIdentifier(f"{id_CompKEM}.28")
id_MLKEM1024_X448 = univ.ObjectIdentifier(f"{id_CompKEM}.29")


id_composite_frodokem = f"{id_composite_kem_test_suite}.1"
id_composite_mlkem_dhkemrfc9180 = f"{id_composite_kem_test_suite}.2"
id_composite_frodokem_dhkemrfc9180 = f"{id_composite_kem_test_suite}.3"




# FrodoKEM-976-AES, FrodoKEM-976-SHAKE are Claimed NIST Level 3
# So define eq to ML-KEM-768
id_frodokem_976_aes_rsa2048 = univ.ObjectIdentifier(f"{id_composite_frodokem}.1")
id_frodokem_976_aes_rsa3072 = univ.ObjectIdentifier(f"{id_composite_frodokem}.2")
id_frodokem_976_aes_rsa4096 = univ.ObjectIdentifier(f"{id_composite_frodokem}.3")
id_frodokem_976_aes_x25519 = univ.ObjectIdentifier(f"{id_composite_frodokem}.4")
id_frodokem_976_aes_ecdh_p384 = univ.ObjectIdentifier(f"{id_composite_frodokem}.5")
id_frodokem_976_aes_brainpoolP256r1 = univ.ObjectIdentifier(f"{id_composite_frodokem}.6")

id_frodokem_976_shake_rsa2048 = univ.ObjectIdentifier(f"{id_composite_frodokem}.7")
id_frodokem_976_shake_rsa3072 = univ.ObjectIdentifier(f"{id_composite_frodokem}.8")
id_frodokem_976_shake_rsa4096 = univ.ObjectIdentifier(f"{id_composite_frodokem}.9")
id_frodokem_976_shake_x25519 = univ.ObjectIdentifier(f"{id_composite_frodokem}.10")
id_frodokem_976_shake_ecdh_p384 = univ.ObjectIdentifier(f"{id_composite_frodokem}.11")
id_frodokem_976_shake_brainpoolP256r1 = univ.ObjectIdentifier(f"{id_composite_frodokem}.12")

# FrodoKEM-1344-AES and FrodoKEM-1344-SHAKE are Claimed NIST Level 5.
# So define eq to ML-KEM-1024
id_frodokem_1344_aes_ecdh_p384 = univ.ObjectIdentifier(f"{id_composite_frodokem}.13")
id_frodokem_1344_aes_ecdh_brainpoolP384r1 = univ.ObjectIdentifier(f"{id_composite_frodokem}.14")
id_frodokem_1344_aes_x448 = univ.ObjectIdentifier(f"{id_composite_frodokem}.15")
id_frodokem_1344_shake_ecdh_p384 = univ.ObjectIdentifier(f"{id_composite_frodokem}.16")
id_frodokem_1344_shake_ecdh_brainpoolP384r1 = univ.ObjectIdentifier(f"{id_composite_frodokem}.17")
id_frodokem_1344_shake_x448 = univ.ObjectIdentifier(f"{id_composite_frodokem}.18")


MLKEM_OID_2_KDF_MAPPING = {
    id_MLKEM768_RSA2048: "hkdf-sha256",
    id_MLKEM768_RSA3072: "hkdf-sha256",
    id_MLKEM768_RSA4096: "hkdf-sha256",
    id_MLKEM768_X25519: "sha3-256",
    id_MLKEM768_ECDH_P384: "hkdf-sha256",
    id_MLKEM768_ECDH_brainpoolP256r1: "hkdf-sha256",
    id_MLKEM1024_ECDH_P384: "sha3-256",
    id_MLKEM1024_ECDH_brainpoolP384r1: "sha3-256",
    id_MLKEM1024_X448: "sha3-256",
}


FRODOKEM_OID_2_KDF_MAPPING = {
id_frodokem_976_aes_rsa2048: "hkdf-sha256",
id_frodokem_976_aes_rsa3072: "hkdf-sha256",
id_frodokem_976_aes_rsa4096: "hkdf-sha256",
id_frodokem_976_aes_x25519: "sha3-256",
id_frodokem_976_aes_ecdh_p384: "hkdf-sha256",
id_frodokem_976_aes_brainpoolP256r1: "hkdf-sha256",
id_frodokem_976_shake_rsa2048: "hkdf-sha256",
id_frodokem_976_shake_rsa3072: "hkdf-sha256",
id_frodokem_976_shake_rsa4096: "hkdf-sha256",
id_frodokem_976_shake_x25519: "sha3-256",
id_frodokem_976_shake_ecdh_p384: "hkdf-sha256",
id_frodokem_976_shake_brainpoolP256r1: "hkdf-sha256",
# NIST claimed level 5
id_frodokem_1344_aes_ecdh_p384: "sha3-256",
id_frodokem_1344_aes_ecdh_brainpoolP384r1: "sha3-256",
id_frodokem_1344_aes_x448: "sha3-256",
id_frodokem_1344_shake_ecdh_p384: "sha3-256",
id_frodokem_1344_shake_ecdh_brainpoolP384r1: "sha3-256",
id_frodokem_1344_shake_x448: "sha3-256",
}
##################################
# Alternative DHKEM RFC9180 OIDs
##################################

id_composite_mlkem768_dhkemrfc9180_X25519 = f"{id_composite_mlkem_dhkemrfc9180}.1"
id_composite_mlkem768_dhkemrfc9180_P384 = f"{id_composite_mlkem_dhkemrfc9180}.2"
id_composite_mlkem768_dhkemrfc9180_brainpoolP256r1 = f"{id_composite_mlkem_dhkemrfc9180}.3"
id_composite_mlkem1024_dhkemrfc9180_P384 = f"{id_composite_mlkem_dhkemrfc9180}.4"
id_composite_mlkem1024_dhkemrfc9180_brainpoolP384r1 = f"{id_composite_mlkem_dhkemrfc9180}.5"
id_composite_mlkem1024_dhkemrfc9180_X448 = f"{id_composite_mlkem_dhkemrfc9180}.6"

id_composite_frodokem_976_aes_dhkemrfc9180_X25519 = f"{id_composite_frodokem_dhkemrfc9180}.1"
id_composite_frodokem_976_aes_dhkemrfc9180_P384 = f"{id_composite_frodokem_dhkemrfc9180}.2"
id_composite_frodokem_976_aes_dhkemrfc9180_brainpoolP256r1 = f"{id_composite_frodokem_dhkemrfc9180}.3"
id_composite_frodokem_976_shake_dhkemrfc9180_X25519 = f"{id_composite_frodokem_dhkemrfc9180}.4"
id_composite_frodokem_976_shake_dhkemrfc9180_P384 = f"{id_composite_frodokem_dhkemrfc9180}.5"
id_composite_frodokem_976_shake_dhkemrfc9180_brainpoolP256r1 = f"{id_composite_frodokem_dhkemrfc9180}.6"

id_composite_frodokem_1344_aes_dhkemrfc9180_P384 = f"{id_composite_frodokem_dhkemrfc9180}.7"
id_composite_frodokem_1344_aes_dhkemrfc9180_brainpoolP384r1 = f"{id_composite_frodokem_dhkemrfc9180}.8"
id_composite_frodokem_1344_aes_dhkemrfc9180_X448 = f"{id_composite_frodokem_dhkemrfc9180}.9"
id_composite_frodokem_1344_shake_dhkemrfc9180_P384 = f"{id_composite_frodokem_dhkemrfc9180}.10"
id_composite_frodokem_1344_shake_dhkemrfc9180_brainpoolP384r1 = f"{id_composite_frodokem_dhkemrfc9180}.11"
id_composite_frodokem_1344_shake_dhkemrfc9180_X448 = f"{id_composite_frodokem_dhkemrfc9180}.12"

COMPOSITE_KEM_DHKEMRFC9180_NAME_2_OID = {

    "dhkemrfc9180-ml-kem-768-x25519": id_composite_mlkem768_dhkemrfc9180_X25519,
    "dhkemrfc9180-ml-kem-768-ecdh-secp384r1": id_composite_mlkem768_dhkemrfc9180_P384,
    "dhkemrfc9180-ml-kem-768-ecdh-brainpoolP256r1": id_composite_mlkem768_dhkemrfc9180_brainpoolP256r1,

    "dhkemrfc9180-ml-kem-1024-ecdh-secp384r1": id_composite_mlkem1024_dhkemrfc9180_P384,
    "dhkemrfc9180-ml-kem-1024-ecdh-brainpoolP384r1": id_composite_mlkem1024_dhkemrfc9180_brainpoolP384r1,
    "dhkemrfc9180-ml-kem-1024-x448": id_composite_mlkem1024_dhkemrfc9180_X448,

    "dhkemrfc9180-frodokem-976-aes-x25519": id_composite_frodokem_976_aes_dhkemrfc9180_X25519,
    "dhkemrfc9180-frodokem-976-aes-ecdh-secp384r1": id_composite_frodokem_976_aes_dhkemrfc9180_P384,
    "dhkemrfc9180-frodokem-976-aes-brainpoolP256r1": id_composite_frodokem_976_aes_dhkemrfc9180_brainpoolP256r1,
    "dhkemrfc9180-frodokem-976-shake-x25519": id_composite_frodokem_976_shake_dhkemrfc9180_X25519,
    "dhkemrfc9180-frodokem-976-shake-ecdh-secp384r1": id_composite_frodokem_976_shake_dhkemrfc9180_P384,
    "dhkemrfc9180-frodokem-976-shake-brainpoolP256r1": id_composite_frodokem_976_shake_dhkemrfc9180_brainpoolP256r1,

    "dhkemrfc9180-frodokem-1344-aes-ecdh-secp384r1": id_composite_frodokem_1344_aes_dhkemrfc9180_P384,
    "dhkemrfc9180-frodokem-1344-aes-ecdh-brainpoolP384r1": id_composite_frodokem_1344_aes_dhkemrfc9180_brainpoolP384r1,
    "dhkemrfc9180-frodokem-1344-aes-x448": id_composite_frodokem_1344_aes_dhkemrfc9180_X448,
    "dhkemrfc9180-frodokem-1344-shake-ecdh-secp384r1": id_composite_frodokem_1344_shake_dhkemrfc9180_P384,
    "dhkemrfc9180-frodokem-1344-shake-ecdh-brainpoolP384r1": id_composite_frodokem_1344_shake_dhkemrfc9180_brainpoolP384r1,
    "dhkemrfc9180-frodokem-1344-shake-x448": id_composite_frodokem_1344_shake_dhkemrfc9180_X448,
}




COMPOSITE_MLKEM_MAPPING = {
    "ml-kem-768": {
        "RSA2048": id_MLKEM768_RSA2048,
        "RSA3072": id_MLKEM768_RSA3072,
        "RSA4096": id_MLKEM768_RSA4096,
        "X25519": id_MLKEM768_X25519,
        "ECDH-P384": id_MLKEM768_ECDH_P384,
        "ECDH-brainpoolP256r1": id_MLKEM768_ECDH_brainpoolP256r1,
    },
    "ml-kem-1024": {
        "ECDH-P384": id_MLKEM1024_ECDH_P384,
        "ECDH-brainpoolP384r1": id_MLKEM1024_ECDH_brainpoolP384r1,
        "X448": id_MLKEM1024_X448,
    },
}


id_ce_deltaCertificateDescriptor = univ.ObjectIdentifier("2.16.840.1.114027.80.6.1")
id_at_deltaCertificateRequestSignature = univ.ObjectIdentifier("2.16.840.1.114027.80.6.3")
id_at_deltaCertificateRequest = univ.ObjectIdentifier("2.16.840.1.114027.80.6.2")




id_Chempat_X25519_sntrup761 = univ.ObjectIdentifier(f"{id_Chempat}.1")
id_Chempat_X25519_mceliece348864 = univ.ObjectIdentifier(f"{id_Chempat}.2")
id_Chempat_X25519_mceliece460896 = univ.ObjectIdentifier(f"{id_Chempat}.3")
id_Chempat_X25519_mceliece6688128 = univ.ObjectIdentifier(f"{id_Chempat}.4")
id_Chempat_X25519_mceliece6960119 = univ.ObjectIdentifier(f"{id_Chempat}.5")
id_Chempat_X25519_mceliece8192128 = univ.ObjectIdentifier(f"{id_Chempat}.6")
id_Chempat_X448_mceliece348864 = univ.ObjectIdentifier(f"{id_Chempat}.7")
id_Chempat_X448_mceliece460896 = univ.ObjectIdentifier(f"{id_Chempat}.8")
id_Chempat_X448_mceliece6688128 = univ.ObjectIdentifier(f"{id_Chempat}.9")
id_Chempat_X448_mceliece6960119 = univ.ObjectIdentifier(f"{id_Chempat}.10")
id_Chempat_X448_mceliece8192128 = univ.ObjectIdentifier(f"{id_Chempat}.11")
id_Chempat_X25519_ML_KEM_768 = univ.ObjectIdentifier(f"{id_Chempat}.12")
id_Chempat_X448_ML_KEM_1024 = univ.ObjectIdentifier(f"{id_Chempat}.13")
id_Chempat_P256_ML_KEM_768 = univ.ObjectIdentifier(f"{id_Chempat}.14")
id_Chempat_P384_ML_KEM_1024 = univ.ObjectIdentifier(f"{id_Chempat}.15")
id_Chempat_brainpoolP256_ML_KEM_768 = univ.ObjectIdentifier(f"{id_Chempat}.16")
id_Chempat_brainpoolP384_ML_KEM_1024 = univ.ObjectIdentifier(f"{id_Chempat}.17")

# FrodoKEM
id_Chempat_X25519_frodokem_aes_976 = univ.ObjectIdentifier(f"{id_Chempat}.18")
id_Chempat_X25519_frodokem_shake_976 = univ.ObjectIdentifier(f"{id_Chempat}.19")
id_Chempat_X448_frodokem_aes_1344 = univ.ObjectIdentifier(f"{id_Chempat}.20")
id_Chempat_X448_frodokem_shake_1344 = univ.ObjectIdentifier(f"{id_Chempat}.21")
id_chempat_P256_frodokem_aes_976 = univ.ObjectIdentifier(f"{id_Chempat}.22")
id_chempat_P256_frodokem_shake_976 = univ.ObjectIdentifier(f"{id_Chempat}.23")
id_chempat_P384_frodokem_aes_1344 = univ.ObjectIdentifier(f"{id_Chempat}.24")
id_chempat_P384_frodokem_shake_1344 = univ.ObjectIdentifier(f"{id_Chempat}.25")
id_chempat_brainpoolP256_frodokem_aes_976 = univ.ObjectIdentifier(f"{id_Chempat}.26")
id_chempat_brainpoolP256_frodokem_shake_976 = univ.ObjectIdentifier(f"{id_Chempat}.27")
id_chempat_brainpoolP384_frodokem_aes_1344 = univ.ObjectIdentifier(f"{id_Chempat}.28")
id_chempat_brainpoolP384_frodokem_shake_1344 = univ.ObjectIdentifier(f"{id_Chempat}.29")


CHEMPAT_OID_2_NAME = {
    id_Chempat_X25519_sntrup761: "Chempat-X25519-sntrup761",
    id_Chempat_X25519_mceliece348864: "Chempat-X25519-mceliece348864",
    id_Chempat_X25519_mceliece460896: "Chempat-X25519-mceliece460896",
    id_Chempat_X25519_mceliece6688128: "Chempat-X25519-mceliece6688128",
    id_Chempat_X25519_mceliece6960119: "Chempat-X25519-mceliece6960119",
    id_Chempat_X25519_mceliece8192128: "Chempat-X25519-mceliece8192128",
    id_Chempat_X448_mceliece348864: "Chempat-X448-mceliece348864",
    id_Chempat_X448_mceliece460896: "Chempat-X448-mceliece460896",
    id_Chempat_X448_mceliece6688128: "Chempat-X448-mceliece6688128",
    id_Chempat_X448_mceliece6960119: "Chempat-X448-mceliece6960119",
    id_Chempat_X448_mceliece8192128: "Chempat-X448-mceliece8192128",
    id_Chempat_X25519_ML_KEM_768: "Chempat-X25519-ML-KEM-768",
    id_Chempat_X448_ML_KEM_1024: "Chempat-X448-ML-KEM-1024",
    id_Chempat_P256_ML_KEM_768: "Chempat-P256-ML-KEM-768",
    id_Chempat_P384_ML_KEM_1024: "Chempat-P384-ML-KEM-1024",
    id_Chempat_brainpoolP256_ML_KEM_768: "Chempat-brainpoolP256-ML-KEM-768",
    id_Chempat_brainpoolP384_ML_KEM_1024: "Chempat-brainpoolP384-ML-KEM-1024",
}

CHEMPAT_FRODOKEM_OID_2_NAME = {
    id_Chempat_X25519_frodokem_aes_976: "Chempat-X25519-frodokem-976-aes",
    id_Chempat_X25519_frodokem_shake_976: "Chempat-X25519-frodokem-976-shake",
    id_chempat_P256_frodokem_aes_976: "Chempat-P256-frodokem-976-aes",
    id_chempat_P256_frodokem_shake_976: "Chempat-P256-frodokem-976-shake",
    id_chempat_brainpoolP256_frodokem_aes_976: "Chempat-brainpoolP256-frodokem-976-aes",
    id_chempat_brainpoolP256_frodokem_shake_976: "Chempat-brainpoolP256-frodokem-976-shake",
    id_chempat_brainpoolP384_frodokem_aes_1344: "Chempat-brainpoolP384-frodokem-1344-aes",
    id_chempat_brainpoolP384_frodokem_shake_1344: "Chempat-brainpoolP384-frodokem-1344-shake",
    id_chempat_P384_frodokem_aes_1344: "Chempat-P384-frodokem-1344-aes",
    id_chempat_P384_frodokem_shake_1344: "Chempat-P384-frodokem-1344-shake",
    id_Chempat_X448_frodokem_aes_1344: "Chempat-X448-frodokem-1344-aes",
    id_Chempat_X448_frodokem_shake_1344: "Chempat-X448-frodokem-1344-shake",
}

CHEMPAT_OID_2_NAME.update(CHEMPAT_FRODOKEM_OID_2_NAME)
CHEMPAT_NAME_2_OID = {y: x for x, y in CHEMPAT_OID_2_NAME.items()}

########################
# Hybrid Signature OIDs
########################




id_relatedCert = univ.ObjectIdentifier(f"{id_hybrid_sig_multi_auth}.{1}")
id_aa_relatedCertRequest = univ.ObjectIdentifier(f"{id_hybrid_sig_multi_auth}.{2}")
id_mod_related_cert = univ.ObjectIdentifier(f"{id_hybrid_sig_multi_auth}.{3}")


id_ad_certDiscovery = univ.ObjectIdentifier(f"{id_hybrid_sig_cert_binding}.{1}")
id_ad_relatedCertificateDescriptor = univ.ObjectIdentifier(f"{id_hybrid_sig_cert_binding}.{2}")



# Hybrid SUN Signature OIDs
# CSR OIDs

id_altSubPubKeyHashAlgAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.2")
id_altSubPubKeyLocAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.3")
id_altSigValueHashAlgAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.4")
id_altSigValueLocAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.5")

# x509 OIDs

id_altSubPubKeyExt = univ.ObjectIdentifier(f"{id_hybrid_sun}.6")
id_altSignatureExt = univ.ObjectIdentifier(f"{id_hybrid_sun}.7")

COMPOSITE_MLKEM_NAME_2_OID = {
    "ml-kem-768-rsa2048": id_MLKEM768_RSA2048,
    "ml-kem-768-rsa3072": id_MLKEM768_RSA3072,
    "ml-kem-768-rsa4096": id_MLKEM768_RSA4096,
    "ml-kem-768-ecdh-secp384r1": id_MLKEM768_ECDH_P384,
    "ml-kem-768-ecdh-brainpoolP256r1": id_MLKEM768_ECDH_brainpoolP256r1,
    "ml-kem-768-x25519": id_MLKEM768_X25519,
    "ml-kem-1024-ecdh-secp384r1": id_MLKEM1024_ECDH_P384,
    "ml-kem-1024-ecdh-brainpoolP384r1": id_MLKEM1024_ECDH_brainpoolP384r1,
    "ml-kem-1024-x448": id_MLKEM1024_X448,
}
COMPOSITE_FRODOKEM_NAME_2_OID = {
    "frodokem-976-aes-rsa2048": id_frodokem_976_aes_rsa2048,
    "frodokem-976-aes-rsa3072": id_frodokem_976_aes_rsa3072,
    "frodokem-976-aes-rsa4096": id_frodokem_976_aes_rsa4096,
    "frodokem-976-aes-x25519": id_frodokem_976_aes_x25519,
    "frodokem-976-aes-ecdh-secp384r1": id_frodokem_976_aes_ecdh_p384,
    "frodokem-976-aes-brainpoolP256r1": id_frodokem_976_aes_brainpoolP256r1,
    "frodokem-976-shake-rsa2048": id_frodokem_976_shake_rsa2048,
    "frodokem-976-shake-rsa3072": id_frodokem_976_shake_rsa3072,
    "frodokem-976-shake-rsa4096": id_frodokem_976_shake_rsa4096,
    "frodokem-976-shake-x25519": id_frodokem_976_shake_x25519,
    "frodokem-976-shake-ecdh-secp384r1": id_frodokem_976_shake_ecdh_p384,
    "frodokem-976-shake-brainpoolP256r1": id_frodokem_976_shake_brainpoolP256r1,
    "frodokem-1344-aes-ecdh-secp384r1": id_frodokem_1344_aes_ecdh_p384,
    "frodokem-1344-aes-ecdh-brainpoolP384r1": id_frodokem_1344_aes_ecdh_brainpoolP384r1,
    "frodokem-1344-aes-x448": id_frodokem_1344_aes_x448,
    "frodokem-1344-shake-ecdh-secp384r1": id_frodokem_1344_shake_ecdh_p384,
    "frodokem-1344-shake-ecdh-brainpoolP384r1": id_frodokem_1344_shake_ecdh_brainpoolP384r1,
    "frodokem-1344-shake-x448": id_frodokem_1344_shake_x448,
}
COMPOSITE_KEM_NAME_2_OID = {}
COMPOSITE_KEM_NAME_2_OID.update(COMPOSITE_MLKEM_NAME_2_OID)
COMPOSITE_KEM_NAME_2_OID.update(COMPOSITE_FRODOKEM_NAME_2_OID)
COMPOSITE_KEM_NAME_2_OID.update(COMPOSITE_KEM_DHKEMRFC9180_NAME_2_OID)

COMPOSITE_KEM_OID_2_NAME = {str(oid): name for name, oid in COMPOSITE_KEM_NAME_2_OID.items()}
