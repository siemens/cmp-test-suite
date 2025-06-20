# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=invalid-name
"""Defines temporary OIDs for the test suite.

Which may change in the future or are replaced be different OIDs or updated for the final
version.
"""

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

# used inside the cert discovery method.
id_hybrid_sig_cert_binding = univ.ObjectIdentifier(f"{id_hybrid_sig_test_suite}.3")

# OIDs used for the sun-hybrid signature method.
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

FALCON_OID_2_NAME = {y: x for x, y in FALCON_NAME_2_OID.items()}

id_ntru = f"{id_kem_test_suite}.1"
id_sntrup761 = univ.ObjectIdentifier(f"{id_ntru}.1")


id_mceliece = f"{id_kem_test_suite}.2"

MCELIECE_NAME_2_OID = {
    "mceliece-348864": univ.ObjectIdentifier(f"{id_mceliece}.1"),
    "mceliece-460896": univ.ObjectIdentifier(f"{id_mceliece}.2"),
    "mceliece-6688128": univ.ObjectIdentifier(f"{id_mceliece}.3"),
    "mceliece-6960119": univ.ObjectIdentifier(f"{id_mceliece}.4"),
    "mceliece-8192128": univ.ObjectIdentifier(f"{id_mceliece}.5"),
}

id_frodokem = f"{id_kem_test_suite}.3"

FRODOKEM_NAME_2_OID = {
    "frodokem-640-aes": univ.ObjectIdentifier(f"{id_frodokem}.1"),
    "frodokem-640-shake": univ.ObjectIdentifier(f"{id_frodokem}.2"),
    "frodokem-976-aes": univ.ObjectIdentifier(f"{id_frodokem}.3"),
    "frodokem-976-shake": univ.ObjectIdentifier(f"{id_frodokem}.4"),
    "frodokem-1344-aes": univ.ObjectIdentifier(f"{id_frodokem}.5"),
    "frodokem-1344-shake": univ.ObjectIdentifier(f"{id_frodokem}.6"),
}

FRODOKEM_OID_2_NAME = {y: x for x, y in FRODOKEM_NAME_2_OID.items()}
MCELIECE_OID_2_NAME = {y: x for x, y in MCELIECE_NAME_2_OID.items()}

id_it_KemCiphertextInfo = rfc9480.id_it + (9999,)

id_CompSig = "2.16.840.1.114027.80.8.1.1"
id_CompKEM = "2.16.840.1.114027.80.5.2.1"

id_hash_mldsa44_rsa2048_pss_sha256 = univ.ObjectIdentifier(f"{id_CompSig}.40")
id_hash_mldsa44_rsa2048_pkcs15_sha256 = univ.ObjectIdentifier(f"{id_CompSig}.41")
id_hash_mldsa44_ed25519_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.42")
id_hash_mldsa44_ecdsa_p256_sha256 = univ.ObjectIdentifier(f"{id_CompSig}.43")
id_hash_mldsa65_rsa3072_pss_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.44")
id_hash_mldsa65_rsa3072_pkcs15_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.45")
id_hash_mldsa65_rsa4096_pss_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.46")
id_hash_mldsa65_rsa4096_pkcs15_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.47")
id_hash_mldsa65_ecdsa_p384_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.48")
id_hash_mldsa65_ecdsa_brainpool_p256r1_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.49")
id_hash_mldsa65_ed25519_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.50")
id_hash_mldsa87_ecdsa_p384_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.51")
id_hash_mldsa87_ecdsa_brainpool_p384r1_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.52")
id_hash_mldsa87_ed448_sha512 = univ.ObjectIdentifier(f"{id_CompSig}.53")

COMP_SIG03_PREHASH_OID_2_HASH = {
    id_hash_mldsa44_rsa2048_pss_sha256: "sha256",
    id_hash_mldsa44_rsa2048_pkcs15_sha256: "sha256",
    id_hash_mldsa44_ed25519_sha512: "sha512",
    id_hash_mldsa44_ecdsa_p256_sha256: "sha256",
    id_hash_mldsa65_rsa3072_pss_sha512: "sha512",
    id_hash_mldsa65_rsa3072_pkcs15_sha512: "sha512",
    id_hash_mldsa65_rsa4096_pss_sha512: "sha512",
    id_hash_mldsa65_rsa4096_pkcs15_sha512: "sha512",
    id_hash_mldsa65_ecdsa_p384_sha512: "sha512",
    id_hash_mldsa65_ecdsa_brainpool_p256r1_sha512: "sha512",
    id_hash_mldsa65_ed25519_sha512: "sha512",
    id_hash_mldsa87_ecdsa_p384_sha512: "sha512",
    id_hash_mldsa87_ecdsa_brainpool_p384r1_sha512: "sha512",
    id_hash_mldsa87_ed448_sha512: "sha512",
}
CMS_COMPOSITE03_OID_2_HASH = {}

id_mldsa44_rsa2048_pss = univ.ObjectIdentifier(f"{id_CompSig}.21")
id_mldsa44_rsa2048_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.22")
id_mldsa44_ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.23")
id_mldsa44_ecdsa_p256 = univ.ObjectIdentifier(f"{id_CompSig}.24")
id_mldsa65_rsa3072_pss = univ.ObjectIdentifier(f"{id_CompSig}.26")
id_mldsa65_rsa3072_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.27")
id_mldsa65_rsa4096_pss = univ.ObjectIdentifier(f"{id_CompSig}.34")
id_mldsa65_rsa4096_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.35")
id_mldsa65_ecdsa_p384 = univ.ObjectIdentifier(f"{id_CompSig}.28")
id_mldsa65_ecdsa_brainpool_p256r1 = univ.ObjectIdentifier(f"{id_CompSig}.29")
id_mldsa65_ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.30")
id_mldsa87_ecdsa_p384 = univ.ObjectIdentifier(f"{id_CompSig}.31")
id_mldsa87_ecdsa_brainpool_p384r1 = univ.ObjectIdentifier(f"{id_CompSig}.32")
id_mldsa87_ed448 = univ.ObjectIdentifier(f"{id_CompSig}.33")

PURE_COMPOSITE_SIG03_NAME_TO_OID = {
    "composite-sig-03-ml-dsa-44-rsa2048-pss": id_mldsa44_rsa2048_pss,
    "composite-sig-03-ml-dsa-44-rsa2048": id_mldsa44_rsa2048_pkcs15,
    "composite-sig-03-ml-dsa-44-ed25519": id_mldsa44_ed25519,
    "composite-sig-03-ml-dsa-44-ecdsa-secp256r1": id_mldsa44_ecdsa_p256,
    "composite-sig-03-ml-dsa-65-rsa3072-pss": id_mldsa65_rsa3072_pss,
    "composite-sig-03-ml-dsa-65-rsa3072": id_mldsa65_rsa3072_pkcs15,
    "composite-sig-03-ml-dsa-65-rsa4096-pss": id_mldsa65_rsa4096_pss,
    "composite-sig-03-ml-dsa-65-rsa4096": id_mldsa65_rsa4096_pkcs15,
    "composite-sig-03-ml-dsa-65-ecdsa-secp384r1": id_mldsa65_ecdsa_p384,
    "composite-sig-03-ml-dsa-65-ecdsa-brainpoolP256r1": id_mldsa65_ecdsa_brainpool_p256r1,
    "composite-sig-03-ml-dsa-65-ed25519": id_mldsa65_ed25519,
    "composite-sig-03-ml-dsa-87-ecdsa-secp384r1": id_mldsa87_ecdsa_p384,
    "composite-sig-03-ml-dsa-87-ecdsa-brainpoolP384r1": id_mldsa87_ecdsa_brainpool_p384r1,
    "composite-sig-03-ml-dsa-87-ed448": id_mldsa87_ed448,
}

PURE_COMPOSITE_SIG03_OID_TO_NAME = {y: x for x, y in PURE_COMPOSITE_SIG03_NAME_TO_OID.items()}

COMPOSITE_SIG03_HASH_NAME_2_OID = {
    "composite-sig-03-hash-ml-dsa-44-rsa2048-pss": id_hash_mldsa44_rsa2048_pss_sha256,
    "composite-sig-03-hash-ml-dsa-44-rsa2048": id_hash_mldsa44_rsa2048_pkcs15_sha256,
    "composite-sig-03-hash-ml-dsa-44-ed25519": id_hash_mldsa44_ed25519_sha512,
    "composite-sig-03-hash-ml-dsa-44-ecdsa-secp256r1": id_hash_mldsa44_ecdsa_p256_sha256,
    "composite-sig-03-hash-ml-dsa-65-rsa3072-pss": id_hash_mldsa65_rsa3072_pss_sha512,
    "composite-sig-03-hash-ml-dsa-65-rsa3072": id_hash_mldsa65_rsa3072_pkcs15_sha512,
    "composite-sig-03-hash-ml-dsa-65-rsa4096-pss": id_hash_mldsa65_rsa4096_pss_sha512,
    "composite-sig-03-hash-ml-dsa-65-rsa4096": id_hash_mldsa65_rsa4096_pkcs15_sha512,
    "composite-sig-03-hash-ml-dsa-65-ecdsa-secp384r1": id_hash_mldsa65_ecdsa_p384_sha512,
    "composite-sig-03-hash-ml-dsa-65-ecdsa-brainpoolP256r1": id_hash_mldsa65_ecdsa_brainpool_p256r1_sha512,
    "composite-sig-03-hash-ml-dsa-65-ed25519": id_hash_mldsa65_ed25519_sha512,
    "composite-sig-03-hash-ml-dsa-87-ecdsa-secp384r1": id_hash_mldsa87_ecdsa_p384_sha512,
    "composite-sig-03-hash-ml-dsa-87-ecdsa-brainpoolP384r1": id_hash_mldsa87_ecdsa_brainpool_p384r1_sha512,
    "composite-sig-03-hash-ml-dsa-87-ed448": id_hash_mldsa87_ed448_sha512,
}
COMPOSITE_SIG03_HASH_OID_2_NAME = {y: x for x, y in COMPOSITE_SIG03_HASH_NAME_2_OID.items()}

id_rsa_kem_spki = univ.ObjectIdentifier("1.2.840.113549.1.9.16.3")

PURE_OID_TO_HASH = {
    id_mldsa44_rsa2048_pss: "sha256",
    id_mldsa44_rsa2048_pkcs15: "sha256",
    id_mldsa44_ed25519: None,
    id_mldsa44_ecdsa_p256: "sha256",
    id_mldsa65_rsa3072_pss: "sha256",
    id_mldsa65_rsa3072_pkcs15: "sha256",
    id_mldsa65_rsa4096_pss: "sha384",
    id_mldsa65_rsa4096_pkcs15: "sha384",
    id_mldsa65_ecdsa_p384: "sha384",
    id_mldsa65_ecdsa_brainpool_p256r1: "sha256",
    id_mldsa65_ed25519: None,
    id_mldsa87_ecdsa_p384: "sha384",
    id_mldsa87_ecdsa_brainpool_p384r1: "sha384",
    id_mldsa87_ed448: None,
}

COMPOSITE_SIG_SIGNED_DATA_OID_HASH = {
    id_mldsa44_rsa2048_pss: "sha256",
    id_mldsa44_rsa2048_pkcs15: "sha256",
    id_mldsa44_ed25519: "sha512",
    id_mldsa44_ecdsa_p256: "sha256",
    id_mldsa65_rsa3072_pss: "sha512",
    id_mldsa65_rsa3072_pkcs15: "sha512",
    id_mldsa65_rsa4096_pss: "sha512",
    id_mldsa65_rsa4096_pkcs15: "sha512",
    id_mldsa65_ecdsa_p384: "sha512",
    id_mldsa65_ecdsa_brainpool_p256r1: "sha512",
    id_mldsa65_ed25519: "sha512",
    id_mldsa87_ecdsa_p384: "sha512",
    id_mldsa87_ecdsa_brainpool_p384r1: "sha512",
    id_mldsa87_ed448: "sha512",
}


id_compSig04_mldsa44_rsa2048_pss = univ.ObjectIdentifier(f"{id_CompSig}.60")
id_compSig04_mldsa44_rsa2048_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.61")
id_compSig04_mldsa44_ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.62")
id_compSig04_mldsa44_ecdsa_p256 = univ.ObjectIdentifier(f"{id_CompSig}.63")
id_compSig04_mldsa65_rsa3072_pss = univ.ObjectIdentifier(f"{id_CompSig}.64")
id_compSig04_mldsa65_rsa3072_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.65")
id_compSig04_mldsa65_rsa4096_pss = univ.ObjectIdentifier(f"{id_CompSig}.66")
id_compSig04_mldsa65_rsa4096_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.67")
id_compSig04_mldsa65_ecdsa_p256 = univ.ObjectIdentifier(f"{id_CompSig}.68")
id_compSig04_mldsa65_ecdsa_p384 = univ.ObjectIdentifier(f"{id_CompSig}.69")
id_compSig04_mldsa65_ecdsa_brainpool_p256r1 = univ.ObjectIdentifier(f"{id_CompSig}.70")
id_compSig04_mldsa65_ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.71")
id_compSig04_mldsa87_ecdsa_p384 = univ.ObjectIdentifier(f"{id_CompSig}.72")
id_compSig04_mldsa87_ecdsa_brainpool_p384r1 = univ.ObjectIdentifier(f"{id_CompSig}.73")
id_compSig04_mldsa87_ed448 = univ.ObjectIdentifier(f"{id_CompSig}.74")
id_compSig04_mldsa87_rsa4096_pss = univ.ObjectIdentifier(f"{id_CompSig}.75")

COMPOSITE_SIG04_PURE_NAME_TO_OID = {
    # ML-DSA-44
    "composite-sig-04-ml-dsa-44-rsa2048-pss": id_compSig04_mldsa44_rsa2048_pss,
    "composite-sig-04-ml-dsa-44-rsa2048": id_compSig04_mldsa44_rsa2048_pkcs15,
    "composite-sig-04-ml-dsa-44-ed25519": id_compSig04_mldsa44_ed25519,
    "composite-sig-04-ml-dsa-44-ecdsa-secp256r1": id_compSig04_mldsa44_ecdsa_p256,
    # ML-DSA-65
    "composite-sig-04-ml-dsa-65-rsa3072-pss": id_compSig04_mldsa65_rsa3072_pss,
    "composite-sig-04-ml-dsa-65-rsa3072": id_compSig04_mldsa65_rsa3072_pkcs15,
    "composite-sig-04-ml-dsa-65-rsa4096-pss": id_compSig04_mldsa65_rsa4096_pss,
    "composite-sig-04-ml-dsa-65-rsa4096": id_compSig04_mldsa65_rsa4096_pkcs15,
    "composite-sig-04-ml-dsa-65-ecdsa-secp256r1": id_compSig04_mldsa65_ecdsa_p256,
    "composite-sig-04-ml-dsa-65-ecdsa-secp384r1": id_compSig04_mldsa65_ecdsa_p384,
    "composite-sig-04-ml-dsa-65-ecdsa-brainpoolP256r1": id_compSig04_mldsa65_ecdsa_brainpool_p256r1,
    "composite-sig-04-ml-dsa-65-ed25519": id_compSig04_mldsa65_ed25519,
    # ML-DSA-87
    "composite-sig-04-ml-dsa-87-ecdsa-secp384r1": id_compSig04_mldsa87_ecdsa_p384,
    "composite-sig-04-ml-dsa-87-ecdsa-brainpoolP384r1": id_compSig04_mldsa87_ecdsa_brainpool_p384r1,
    "composite-sig-04-ml-dsa-87-ed448": id_compSig04_mldsa87_ed448,
    "composite-sig-04-ml-dsa-87-rsa4096-pss": id_compSig04_mldsa87_rsa4096_pss,
}

# Hash-based ML-DSA 44 OIDs
composite_sig04_hash_ml_dsa_44_rsa2048_pss = univ.ObjectIdentifier(f"{id_CompSig}.80")
composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.81")
composite_sig04_hash_ml_dsa_44_ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.82")
composite_sig04_hash_ml_dsa_44_ecdsa_p256 = univ.ObjectIdentifier(f"{id_CompSig}.83")

# Hash-based ML-DSA 65 OIDs
composite_sig04_hash_ml_dsa_65_rsa3072_pss = univ.ObjectIdentifier(f"{id_CompSig}.84")
composite_sig04_hash_ml_dsa_65_rsa3072_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.85")
composite_sig04_hash_ml_dsa_65_rsa4096_pss = univ.ObjectIdentifier(f"{id_CompSig}.86")
composite_sig04_hash_ml_dsa_65_rsa4096_pkcs15 = univ.ObjectIdentifier(f"{id_CompSig}.87")
composite_sig04_hash_ml_dsa_65_ecdsa_p256 = univ.ObjectIdentifier(f"{id_CompSig}.88")
composite_sig04_hash_ml_dsa_65_ecdsa_p384 = univ.ObjectIdentifier(f"{id_CompSig}.89")
composite_sig04_hash_ml_dsa_65_ecdsa_brainpoolp256r1 = univ.ObjectIdentifier(f"{id_CompSig}.90")
composite_sig04_hash_ml_dsa_65_ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.91")

# Hash-based ML-DSA 87 OIDs
composite_sig04_hash_ml_dsa_87_ecdsa_p384 = univ.ObjectIdentifier(f"{id_CompSig}.92")
composite_sig04_hash_ml_dsa_87_ecdsa_brainpoolp384r1 = univ.ObjectIdentifier(f"{id_CompSig}.93")
composite_sig04_hash_ml_dsa_87_ed448 = univ.ObjectIdentifier(f"{id_CompSig}.94")
composite_sig04_hash_ml_dsa_87_rsa4096_pss = univ.ObjectIdentifier(f"{id_CompSig}.95")


COMPOSITE_SIG04_HASH_NAME_TO_OID = {
    "composite-sig-04-hash-ml-dsa-44-rsa2048-pss": composite_sig04_hash_ml_dsa_44_rsa2048_pss,
    "composite-sig-04-hash-ml-dsa-44-rsa2048": composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15,
    "composite-sig-04-hash-ml-dsa-44-ed25519": composite_sig04_hash_ml_dsa_44_ed25519,
    "composite-sig-04-hash-ml-dsa-44-ecdsa-secp256r1": composite_sig04_hash_ml_dsa_44_ecdsa_p256,
    "composite-sig-04-hash-ml-dsa-65-rsa3072-pss": composite_sig04_hash_ml_dsa_65_rsa3072_pss,
    "composite-sig-04-hash-ml-dsa-65-rsa3072": composite_sig04_hash_ml_dsa_65_rsa3072_pkcs15,
    "composite-sig-04-hash-ml-dsa-65-rsa4096-pss": composite_sig04_hash_ml_dsa_65_rsa4096_pss,
    "composite-sig-04-hash-ml-dsa-65-rsa4096": composite_sig04_hash_ml_dsa_65_rsa4096_pkcs15,
    "composite-sig-04-hash-ml-dsa-65-ecdsa-secp256r1": composite_sig04_hash_ml_dsa_65_ecdsa_p256,
    "composite-sig-04-hash-ml-dsa-65-ecdsa-secp384r1": composite_sig04_hash_ml_dsa_65_ecdsa_p384,
    "composite-sig-04-hash-ml-dsa-65-ecdsa-brainpoolP256r1": composite_sig04_hash_ml_dsa_65_ecdsa_brainpoolp256r1,
    "composite-sig-04-hash-ml-dsa-65-ed25519": composite_sig04_hash_ml_dsa_65_ed25519,
    "composite-sig-04-hash-ml-dsa-87-ecdsa-secp384r1": composite_sig04_hash_ml_dsa_87_ecdsa_p384,
    "composite-sig-04-hash-ml-dsa-87-ecdsa-brainpoolP384r1": composite_sig04_hash_ml_dsa_87_ecdsa_brainpoolp384r1,
    "composite-sig-04-hash-ml-dsa-87-ed448": composite_sig04_hash_ml_dsa_87_ed448,
    "composite-sig-04-hash-ml-dsa-87-rsa4096-pss": composite_sig04_hash_ml_dsa_87_rsa4096_pss,
}

COMPOSITE_SIG04_HASH_OID_2_NAME = {y: x for x, y in COMPOSITE_SIG04_HASH_NAME_TO_OID.items()}

COMP_SIG04_PREHASH_OID_2_HASH = {
    composite_sig04_hash_ml_dsa_44_rsa2048_pss: "sha256",
    composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15: "sha256",
    composite_sig04_hash_ml_dsa_44_ecdsa_p256: "sha256",
}


######################
# Composite KEM
######################

id_mlkem768_rsa2048 = univ.ObjectIdentifier(f"{id_CompKEM}.21")
id_mlkem768_rsa3072 = univ.ObjectIdentifier(f"{id_CompKEM}.22")
id_mlkem768_rsa4096 = univ.ObjectIdentifier(f"{id_CompKEM}.23")
id_mlkem768_x25519 = univ.ObjectIdentifier(f"{id_CompKEM}.24")
id_mlkem768_ecdh_p384 = univ.ObjectIdentifier(f"{id_CompKEM}.25")
id_mlkem768_ecdh_brainpool_p256r1 = univ.ObjectIdentifier(f"{id_CompKEM}.26")

id_mlkem1024_ecdh_p384 = univ.ObjectIdentifier(f"{id_CompKEM}.27")
id_mlkem1024_ecdh_brainpool_p384r1 = univ.ObjectIdentifier(f"{id_CompKEM}.28")
id_mlkem1024_x448 = univ.ObjectIdentifier(f"{id_CompKEM}.29")


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
    id_mlkem768_rsa2048: "hkdf-sha256",
    id_mlkem768_rsa3072: "hkdf-sha256",
    id_mlkem768_rsa4096: "hkdf-sha256",
    id_mlkem768_x25519: "sha3-256",
    id_mlkem768_ecdh_p384: "hkdf-sha256",
    id_mlkem768_ecdh_brainpool_p256r1: "hkdf-sha256",
    id_mlkem1024_ecdh_p384: "sha3-256",
    id_mlkem1024_ecdh_brainpool_p384r1: "sha3-256",
    id_mlkem1024_x448: "sha3-256",
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

# Composite KEM v06

# Composite KEM v06 OIDs
id_comp_kem06_mlkem768_rsa2048 = univ.ObjectIdentifier(f"{id_CompKEM}.30")
id_comp_kem06_mlkem768_rsa3072 = univ.ObjectIdentifier(f"{id_CompKEM}.31")
id_comp_kem06_mlkem768_rsa4096 = univ.ObjectIdentifier(f"{id_CompKEM}.32")
id_comp_kem06_mlkem768_x25519 = univ.ObjectIdentifier(f"{id_CompKEM}.33")
id_comp_kem06_mlkem768_ecdh_p256 = univ.ObjectIdentifier(f"{id_CompKEM}.34")
id_comp_kem06_mlkem768_ecdh_p384 = univ.ObjectIdentifier(f"{id_CompKEM}.35")
id_comp_kem06_mlkem768_ecdh_brainpool_p256r1 = univ.ObjectIdentifier(f"{id_CompKEM}.36")
id_comp_kem06_mlkem1024_ecdh_p384 = univ.ObjectIdentifier(f"{id_CompKEM}.37")
id_comp_kem06_mlkem1024_ecdh_brainpool_p384r1 = univ.ObjectIdentifier(f"{id_CompKEM}.38")
id_comp_kem06_mlkem1024_x448 = univ.ObjectIdentifier(f"{id_CompKEM}.39")

COMPOSITE_KEM06_MLKEM_NAME_2_OID = {
    "composite-kem-ml-kem-768-rsa2048": id_comp_kem06_mlkem768_rsa2048,
    "composite-kem-ml-kem-768-rsa3072": id_comp_kem06_mlkem768_rsa3072,
    "composite-kem-ml-kem-768-rsa4096": id_comp_kem06_mlkem768_rsa4096,
    "composite-kem-ml-kem-768-x25519": id_comp_kem06_mlkem768_x25519,
    "composite-kem-ml-kem-768-ecdh-secp256r1": id_comp_kem06_mlkem768_ecdh_p256,
    "composite-kem-ml-kem-768-ecdh-secp384r1": id_comp_kem06_mlkem768_ecdh_p384,
    "composite-kem-ml-kem-768-ecdh-brainpoolP256r1": id_comp_kem06_mlkem768_ecdh_brainpool_p256r1,
    "composite-kem-ml-kem-1024-ecdh-secp384r1": id_comp_kem06_mlkem1024_ecdh_p384,
    "composite-kem-ml-kem-1024-ecdh-brainpoolP384r1": id_comp_kem06_mlkem1024_ecdh_brainpool_p384r1,
    "composite-kem-ml-kem-1024-x448": id_comp_kem06_mlkem1024_x448,
}


##################################
# Alternative DHKEM RFC9180 OIDs
##################################

id_composite_mlkem768_dhkemrfc9180_X25519 = univ.ObjectIdentifier(f"{id_composite_mlkem_dhkemrfc9180}.1")
id_composite_mlkem768_dhkemrfc9180_P384 = univ.ObjectIdentifier(f"{id_composite_mlkem_dhkemrfc9180}.2")
id_composite_mlkem768_dhkemrfc9180_brainpoolP256r1 = univ.ObjectIdentifier(f"{id_composite_mlkem_dhkemrfc9180}.3")
id_composite_mlkem1024_dhkemrfc9180_P384 = univ.ObjectIdentifier(f"{id_composite_mlkem_dhkemrfc9180}.4")
id_composite_mlkem1024_dhkemrfc9180_brainpoolP384r1 = univ.ObjectIdentifier(f"{id_composite_mlkem_dhkemrfc9180}.5")
id_composite_mlkem1024_dhkemrfc9180_X448 = univ.ObjectIdentifier(f"{id_composite_mlkem_dhkemrfc9180}.6")

id_composite_frodokem_976_aes_dhkemrfc9180_X25519 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.1")
id_composite_frodokem_976_aes_dhkemrfc9180_P384 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.2")
id_composite_frodokem_976_aes_dhkemrfc9180_brainpoolP256r1 = univ.ObjectIdentifier(
    f"{id_composite_frodokem_dhkemrfc9180}.3"
)
id_composite_frodokem_976_shake_dhkemrfc9180_X25519 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.4")
id_composite_frodokem_976_shake_dhkemrfc9180_P384 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.5")
id_composite_frodokem_976_shake_dhkemrfc9180_brainpoolP256r1 = univ.ObjectIdentifier(
    f"{id_composite_frodokem_dhkemrfc9180}.6"
)

id_composite_frodokem_1344_aes_dhkemrfc9180_P384 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.7")
id_composite_frodokem_1344_aes_dhkemrfc9180_brainpoolP384r1 = univ.ObjectIdentifier(
    f"{id_composite_frodokem_dhkemrfc9180}.8"
)
id_composite_frodokem_1344_aes_dhkemrfc9180_X448 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.9")
id_composite_frodokem_1344_shake_dhkemrfc9180_P384 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.10")
id_composite_frodokem_1344_shake_dhkemrfc9180_brainpoolP384r1 = univ.ObjectIdentifier(
    f"{id_composite_frodokem_dhkemrfc9180}.11"
)
id_composite_frodokem_1344_shake_dhkemrfc9180_X448 = univ.ObjectIdentifier(f"{id_composite_frodokem_dhkemrfc9180}.12")

COMPOSITE_KEM_DHKEMRFC9180_NAME_2_OID = {
    "composite-dhkem-ml-kem-768-x25519": id_composite_mlkem768_dhkemrfc9180_X25519,
    "composite-dhkem-ml-kem-768-ecdh-secp384r1": id_composite_mlkem768_dhkemrfc9180_P384,
    "composite-dhkem-ml-kem-768-ecdh-brainpoolP256r1": id_composite_mlkem768_dhkemrfc9180_brainpoolP256r1,
    "composite-dhkem-ml-kem-1024-ecdh-secp384r1": id_composite_mlkem1024_dhkemrfc9180_P384,
    "composite-dhkem-ml-kem-1024-ecdh-brainpoolP384r1": id_composite_mlkem1024_dhkemrfc9180_brainpoolP384r1,
    "composite-dhkem-ml-kem-1024-x448": id_composite_mlkem1024_dhkemrfc9180_X448,
    "composite-dhkem-frodokem-976-aes-x25519": id_composite_frodokem_976_aes_dhkemrfc9180_X25519,
    "composite-dhkem-frodokem-976-aes-ecdh-secp384r1": id_composite_frodokem_976_aes_dhkemrfc9180_P384,
    "composite-dhkem-frodokem-976-aes-ecdh-brainpoolP256r1": id_composite_frodokem_976_aes_dhkemrfc9180_brainpoolP256r1,
    "composite-dhkem-frodokem-976-shake-x25519": id_composite_frodokem_976_shake_dhkemrfc9180_X25519,
    "composite-dhkem-frodokem-976-shake-ecdh-secp384r1": id_composite_frodokem_976_shake_dhkemrfc9180_P384,
    "composite-dhkem-frodokem-976-shake-ecdh-brainpoolP256r1":  # fmt: off
    id_composite_frodokem_976_shake_dhkemrfc9180_brainpoolP256r1,
    "composite-dhkem-frodokem-1344-aes-ecdh-secp384r1": id_composite_frodokem_1344_aes_dhkemrfc9180_P384,
    "composite-dhkem-frodokem-1344-aes-ecdh-brainpoolP384r1":  # fmt: off
    id_composite_frodokem_1344_aes_dhkemrfc9180_brainpoolP384r1,
    "composite-dhkem-frodokem-1344-aes-x448": id_composite_frodokem_1344_aes_dhkemrfc9180_X448,
    "composite-dhkem-frodokem-1344-shake-ecdh-secp384r1": id_composite_frodokem_1344_shake_dhkemrfc9180_P384,
    "composite-dhkem-frodokem-1344-shake-ecdh-brainpoolP384r1":  # fmt: off
    id_composite_frodokem_1344_shake_dhkemrfc9180_brainpoolP384r1,
    "composite-dhkem-frodokem-1344-shake-x448": id_composite_frodokem_1344_shake_dhkemrfc9180_X448,
}

id_ce_deltaCertificateDescriptor = univ.ObjectIdentifier("2.16.840.1.114027.80.6.1")
id_at_deltaCertificateRequestSignature = univ.ObjectIdentifier("2.16.840.1.114027.80.6.3")
id_at_deltaCertificateRequest = univ.ObjectIdentifier("2.16.840.1.114027.80.6.2")


id_chempat_x25519_sntrup761 = univ.ObjectIdentifier(f"{id_Chempat}.1")
id_chempat_x25519_mceliece348864 = univ.ObjectIdentifier(f"{id_Chempat}.2")
id_chempat_x25519_mceliece460896 = univ.ObjectIdentifier(f"{id_Chempat}.3")
id_chempat_x25519_mceliece6688128 = univ.ObjectIdentifier(f"{id_Chempat}.4")
id_chempat_x25519_mceliece6960119 = univ.ObjectIdentifier(f"{id_Chempat}.5")
id_chempat_x25519_mceliece8192128 = univ.ObjectIdentifier(f"{id_Chempat}.6")
id_chempat_x448_mceliece348864 = univ.ObjectIdentifier(f"{id_Chempat}.7")
id_chempat_x448_mceliece460896 = univ.ObjectIdentifier(f"{id_Chempat}.8")
id_chempat_x448_mceliece6688128 = univ.ObjectIdentifier(f"{id_Chempat}.9")
id_chempat_x448_mceliece6960119 = univ.ObjectIdentifier(f"{id_Chempat}.10")
id_chempat_x448_mceliece8192128 = univ.ObjectIdentifier(f"{id_Chempat}.11")
id_chempat_x25519_ml_kem_768 = univ.ObjectIdentifier(f"{id_Chempat}.12")
id_chempat_x448_ml_kem_1024 = univ.ObjectIdentifier(f"{id_Chempat}.13")
id_chempat_p256_ml_kem_768 = univ.ObjectIdentifier(f"{id_Chempat}.14")
id_Chempat_P384_ML_KEM_1024 = univ.ObjectIdentifier(f"{id_Chempat}.15")
id_chempat_brainpool_p256_ml_kem_768 = univ.ObjectIdentifier(f"{id_Chempat}.16")
id_chempat_brainpool_p384_ml_kem_1024 = univ.ObjectIdentifier(f"{id_Chempat}.17")

# newly added in version 03, just specifies FrodoKEM and not aes or shake.
id_chempat_x25519_frodokem_aes_976 = univ.ObjectIdentifier(f"{id_Chempat}.18")
id_chempat_x25519_frodokem_shake_976 = univ.ObjectIdentifier(f"{id_Chempat}.19")
id_chempat_brainpoolP256_frodokem_aes_640 = univ.ObjectIdentifier(f"{id_Chempat}.20")
id_chempat_brainpoolP256_frodokem_shake_640 = univ.ObjectIdentifier(f"{id_Chempat}.21")
id_chempat_brainpoolP384_frodokem_aes_976 = univ.ObjectIdentifier(f"{id_Chempat}.22")
id_chempat_brainpoolP384_frodokem_shake_976 = univ.ObjectIdentifier(f"{id_Chempat}.23")
id_chempat_brainpoolP512_frodokem_aes_1344 = univ.ObjectIdentifier(f"{id_Chempat}.24")
id_chempat_brainpoolP512_frodokem_shake_1344 = univ.ObjectIdentifier(f"{id_Chempat}.25")

# not inside the draft, but added for completeness.
id_chempat_x448_frodokem_aes_1344 = univ.ObjectIdentifier(f"{id_Chempat}.26")
id_chempat_x448_frodokem_shake_1344 = univ.ObjectIdentifier(f"{id_Chempat}.27")

# TODO add eFrodoKEM.
# id_chempat_x25519_efrodokem_aes_640

CHEMPAT_OID_2_NAME = {
    id_chempat_x25519_sntrup761: "chempat-sntrup761-x25519",
    id_chempat_x25519_mceliece348864: "chempat-mceliece-348864-x25519",
    id_chempat_x25519_mceliece460896: "chempat-mceliece-460896-x25519",
    id_chempat_x25519_mceliece6688128: "chempat-mceliece-6688128-x25519",
    id_chempat_x25519_mceliece6960119: "chempat-mceliece-6960119-x25519",
    id_chempat_x25519_mceliece8192128: "chempat-mceliece-8192128-x25519",
    id_chempat_x448_mceliece348864: "chempat-mceliece-348864-x448",
    id_chempat_x448_mceliece460896: "chempat-mceliece-460896-x448",
    id_chempat_x448_mceliece6688128: "chempat-mceliece-6688128-x448",
    id_chempat_x448_mceliece6960119: "chempat-mceliece-6960119-x448",
    id_chempat_x448_mceliece8192128: "chempat-mceliece-8192128-x448",
    id_chempat_x25519_ml_kem_768: "chempat-ml-kem-768-x25519",
    id_chempat_x448_ml_kem_1024: "chempat-ml-kem-1024-x448",
    id_chempat_p256_ml_kem_768: "chempat-ml-kem-768-ecdh-secp256r1",
    id_Chempat_P384_ML_KEM_1024: "chempat-ml-kem-1024-ecdh-secp384r1",
    id_chempat_brainpool_p256_ml_kem_768: "chempat-ml-kem-768-ecdh-brainpoolP256r1",
    id_chempat_brainpool_p384_ml_kem_1024: "chempat-ml-kem-1024-ecdh-brainpoolP384r1",
    id_chempat_x25519_frodokem_aes_976: "chempat-frodokem-976-aes-x25519",
    id_chempat_x25519_frodokem_shake_976: "chempat-frodokem-976-shake-x25519",
    id_chempat_brainpoolP256_frodokem_aes_640: "chempat-frodokem-640-aes-ecdh-brainpoolP256r1",
    id_chempat_brainpoolP256_frodokem_shake_640: "chempat-frodokem-640-shake-ecdh-brainpoolP256r1",
    id_chempat_brainpoolP384_frodokem_aes_976: "chempat-frodokem-976-aes-ecdh-brainpoolP384r1",
    id_chempat_brainpoolP384_frodokem_shake_976: "chempat-frodokem-976-shake-ecdh-brainpoolP384r1",
    id_chempat_brainpoolP512_frodokem_aes_1344: "chempat-frodokem-1344-aes-ecdh-brainpoolP512r1",
    id_chempat_brainpoolP512_frodokem_shake_1344: "chempat-frodokem-1344-shake-ecdh-brainpoolP512r1",
    id_chempat_x448_frodokem_aes_1344: "chempat-frodokem-1344-aes-x448",
    id_chempat_x448_frodokem_shake_1344: "chempat-frodokem-1344-shake-x448",
}


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

COMPOSITE_KEM05_MLKEM_NAME_2_OID = {
    "composite-kem-05-ml-kem-768-rsa2048": id_mlkem768_rsa2048,
    "composite-kem-05-ml-kem-768-rsa3072": id_mlkem768_rsa3072,
    "composite-kem-05-ml-kem-768-rsa4096": id_mlkem768_rsa4096,
    "composite-kem-05-ml-kem-768-ecdh-secp384r1": id_mlkem768_ecdh_p384,
    "composite-kem-05-ml-kem-768-ecdh-brainpoolP256r1": id_mlkem768_ecdh_brainpool_p256r1,
    "composite-kem-05-ml-kem-768-x25519": id_mlkem768_x25519,
    "composite-kem-05-ml-kem-1024-ecdh-secp384r1": id_mlkem1024_ecdh_p384,
    "composite-kem-05-ml-kem-1024-ecdh-brainpoolP384r1": id_mlkem1024_ecdh_brainpool_p384r1,
    "composite-kem-05-ml-kem-1024-x448": id_mlkem1024_x448,
}
# Always added to the last version of the draft.
COMPOSITE_FRODOKEM_NAME_2_OID = {
    "composite-kem-frodokem-976-aes-rsa2048": id_frodokem_976_aes_rsa2048,
    "composite-kem-frodokem-976-aes-rsa3072": id_frodokem_976_aes_rsa3072,
    "composite-kem-frodokem-976-aes-rsa4096": id_frodokem_976_aes_rsa4096,
    "composite-kem-frodokem-976-aes-x25519": id_frodokem_976_aes_x25519,
    "composite-kem-frodokem-976-aes-ecdh-secp384r1": id_frodokem_976_aes_ecdh_p384,
    "composite-kem-frodokem-976-aes-ecdh-brainpoolP256r1": id_frodokem_976_aes_brainpoolP256r1,
    "composite-kem-frodokem-976-shake-rsa2048": id_frodokem_976_shake_rsa2048,
    "composite-kem-frodokem-976-shake-rsa3072": id_frodokem_976_shake_rsa3072,
    "composite-kem-frodokem-976-shake-rsa4096": id_frodokem_976_shake_rsa4096,
    "composite-kem-frodokem-976-shake-x25519": id_frodokem_976_shake_x25519,
    "composite-kem-frodokem-976-shake-ecdh-secp384r1": id_frodokem_976_shake_ecdh_p384,
    "composite-kem-frodokem-976-shake-ecdh-brainpoolP256r1": id_frodokem_976_shake_brainpoolP256r1,
    "composite-kem-frodokem-1344-aes-ecdh-secp384r1": id_frodokem_1344_aes_ecdh_p384,
    "composite-kem-frodokem-1344-aes-ecdh-brainpoolP384r1": id_frodokem_1344_aes_ecdh_brainpoolP384r1,
    "composite-kem-frodokem-1344-aes-x448": id_frodokem_1344_aes_x448,
    "composite-kem-frodokem-1344-shake-ecdh-secp384r1": id_frodokem_1344_shake_ecdh_p384,
    "composite-kem-frodokem-1344-shake-ecdh-brainpoolP384r1": id_frodokem_1344_shake_ecdh_brainpoolP384r1,
    "composite-kem-frodokem-1344-shake-x448": id_frodokem_1344_shake_x448,
}

COMPOSITE_KEM05_NAME_2_OID = {}
COMPOSITE_KEM05_NAME_2_OID.update(COMPOSITE_KEM05_MLKEM_NAME_2_OID)


COMPOSITE_KEM05_OID_2_NAME = {oid: name for name, oid in COMPOSITE_KEM05_NAME_2_OID.items()}


COMPOSITE_KEM06_NAME_2_OID = {}
COMPOSITE_KEM06_NAME_2_OID.update(COMPOSITE_KEM06_MLKEM_NAME_2_OID)
COMPOSITE_KEM06_NAME_2_OID.update(COMPOSITE_FRODOKEM_NAME_2_OID)
COMPOSITE_KEM06_NAME_2_OID.update(COMPOSITE_KEM_DHKEMRFC9180_NAME_2_OID)

COMPOSITE_KEM06_OID_2_NAME = {oid: name for name, oid in COMPOSITE_KEM06_NAME_2_OID.items()}


COMPOSITE_SIG03_OID_2_NAME = {}
COMPOSITE_SIG03_OID_2_NAME.update(PURE_COMPOSITE_SIG03_OID_TO_NAME)
COMPOSITE_SIG03_OID_2_NAME.update(COMPOSITE_SIG03_HASH_OID_2_NAME)

COMPOSITE_SIG03_NAME_2_OID = {name: oid for oid, name in COMPOSITE_SIG03_OID_2_NAME.items()}


COMPOSITE_SIG04_NAME_2_OID = {}
COMPOSITE_SIG04_NAME_2_OID.update(COMPOSITE_SIG04_HASH_NAME_TO_OID)
COMPOSITE_SIG04_NAME_2_OID.update(COMPOSITE_SIG04_PURE_NAME_TO_OID)

COMPOSITE_SIG04_OID_2_NAME = {y: x for x, y in COMPOSITE_SIG04_NAME_2_OID.items()}
