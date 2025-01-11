# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5990, rfc9480

nist_algorithms_oid = rfc5990.nistAlgorithm
kems_oid = nist_algorithms_oid + (4,)

# Ref: https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md

id_falcon_512 = univ.ObjectIdentifier("1.3.9999.3.6")
id_falcon_1024 = univ.ObjectIdentifier("1.3.9999.3.9")

id_falcon_padded_512 = univ.ObjectIdentifier("1.3.9999.3.16")
id_falcon_padded_1024 = univ.ObjectIdentifier("1.3.9999.3.19")
id_falcon_512_P256 = univ.ObjectIdentifier("1.3.9999.3.12")
id_falcon_512_rsa3072 = univ.ObjectIdentifier("1.3.9999.3.13")
id_falcon_padded_512_P256 = univ.ObjectIdentifier("1.3.9999.3.17")
id_falcon_padded_512_rsa3072 = univ.ObjectIdentifier("1.3.9999.3.18")
id_falcon_1024_P512 = univ.ObjectIdentifier("1.3.9999.3.15")
id_falcon_padded_1024_P512 = univ.ObjectIdentifier("1.3.9999.3.20")

FALCON_NAME_2_OID = {
    "falcon-512": id_falcon_512,
    "falcon-padded-512": id_falcon_padded_512,
    "falcon-1024": id_falcon_1024,
    "falcon-padded-1024": id_falcon_padded_1024,
}
FALCON_HYBRID_NAME_2_OID = {
    "falcon-512-ecdsa-secp256r1": id_falcon_512_P256,
    "falcon-512-rsa3072-pkcs15": id_falcon_512_rsa3072,
    "falcon-padded-512-ecdsa-secp256r1": id_falcon_padded_512_P256,
    "falcon-padded-512-rsa3072-pkcs15": id_falcon_padded_512_rsa3072,
    "falcon-1024-ecdsa-secp512r1": id_falcon_1024_P512,
    "falcon-padded-1024-ecdsa-secp512r1": id_falcon_padded_1024_P512,
}
FALCON_HYBRID_NAME_2_HASH = {
    id_falcon_512_P256: "sha256",
    id_falcon_512_rsa3072: "sha256",
    id_falcon_padded_512_P256: "sha256",
    id_falcon_padded_512_rsa3072: "sha256",
    id_falcon_1024_P512: "sha512",
    id_falcon_padded_1024_P512: "sha512",
}
id_sntrup761_str = f"{kems_oid}.4"
MCELIECE_NAME_2_OID = {
    "mceliece-348864": f"{kems_oid}.5",
    "mceliece-460896": f"{kems_oid}.6",
    "mceliece-6688128": f"{kems_oid}.7",
    "mceliece-6960119": f"{kems_oid}.8",
    "mceliece-8192128": f"{kems_oid}.9",
}
FRODOKEM_NAME_2_OID = {
    "frodokem-640-aes": f"{kems_oid}.10",
    "frodokem-640-shake": f"{kems_oid}.11",
    "frodokem-976-aes": f"{kems_oid}.12",
    "frodokem-976-shake": f"{kems_oid}.13",
    "frodokem-1344-aes": f"{kems_oid}.14",
    "frodokem-1344-shake": f"{kems_oid}.15",
}
FRODOKEM_OID_2_NAME = {y: x for x, y in FRODOKEM_NAME_2_OID.items()}
MCELIECE_OID_2_NAME = {y: x for x, y in MCELIECE_NAME_2_OID.items()}

id_it_KemCiphertextInfo = rfc9480.id_it + (9999,)

id_CompSig = "2.16.840.1.114027.80.8.1"
id_CompKEM = "2.16.840.1.114027.80.5.2.1"

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

COMPOSITE_KEM_OID_2_NAME = {
    f"{id_CompKEM}.21": "id_MLKEM768_RSA2048",
    f"{id_CompKEM}.22": "id_MLKEM768_RSA3072",
    f"{id_CompKEM}.23": "id_MLKEM768_RSA4096",
    f"{id_CompKEM}.24": "id_MLKEM768_X25519",
    f"{id_CompKEM}.25": "id_MLKEM768_ECDH_P384",
    f"{id_CompKEM}.26": "id_MLKEM768_ECDH_brainpoolP256r1",
    f"{id_CompKEM}.27": "id_MLKEM1024_ECDH_P384",
    f"{id_CompKEM}.28": "id_MLKEM1024_ECDH_brainpoolP384r1",
    f"{id_CompKEM}.29": "id_MLKEM1024_X448",
}
