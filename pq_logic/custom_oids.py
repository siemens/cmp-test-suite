# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains OIDs which are currently not even defined as temporary OIDs.

So that keys like Chempat can be used.

In this file are completely unknowmn OIDs which are introduecd for the TEst-Suite

"""

from pyasn1.type import univ
from pyasn1_alt_modules.rfc5751 import id_aa
from pyasn1_alt_modules.rfc9215 import id_ca

####################
# Chempat OIDs
####################

# TODO fix to Correct OIDs!!!

id_test_suite_alg = f"{id_ca}.9996"

id_Chempat = f"{id_test_suite_alg}.5"
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

CHEMPAT_OID_2_NAME = {
    id_Chempat_X25519_sntrup761: "x25519-sntrup761",
    id_Chempat_X25519_mceliece348864: "x25519_mceliece348864",
    id_Chempat_X25519_mceliece460896: "x25519_mceliece460896",
    id_Chempat_X25519_mceliece6688128: "x25519_mceliece6688128",
    id_Chempat_X25519_mceliece6960119: "x25519_mceliece6960119",
    id_Chempat_X25519_mceliece8192128: "x25519_mceliece8192128",
    id_Chempat_X448_mceliece348864: "x448-mceliece348864",
    id_Chempat_X448_mceliece460896: "x448-mceliece460896",
    id_Chempat_X448_mceliece6688128: "x448-mceliece6688128",
    id_Chempat_X448_mceliece6960119: "x448-mceliece6960119",
    id_Chempat_X448_mceliece8192128: "x448-mceliece8192128",
    id_Chempat_X25519_ML_KEM_768: "x25519-ml-kem-768",
    id_Chempat_X448_ML_KEM_1024: "x448-ml-kem-1024",
    id_Chempat_P256_ML_KEM_768: "P256-ml-kem-768",
    id_Chempat_P384_ML_KEM_1024: "P384-ml-kem-1024",
    id_Chempat_brainpoolP256_ML_KEM_768: "brainpoolP256-ml-kem-768",
    id_Chempat_brainpoolP384_ML_KEM_1024: "brainpoolP384-ml-kem-1024",
}


id_X25519Kyber768Draft00 = f"{id_test_suite_alg}.6"


# used inside cert-binding-for-multiple-authentication.

tba = 9997
id_relatedCert = univ.ObjectIdentifier(f"{id_ca}.{tba}")
id_aa_relatedCertRequest = univ.ObjectIdentifier(f"{id_aa}.{tba -1}")
id_mod_related_cert = univ.ObjectIdentifier(f"{id_aa}.{tba - 2}")

# used inside the cert discovery method.
id_ad_certDiscovery = univ.ObjectIdentifier(f"{id_ca}.{tba-3}")
id_ad_relatedCertificateDescriptor = univ.ObjectIdentifier(f"{id_ca}.{tba - 4}")
