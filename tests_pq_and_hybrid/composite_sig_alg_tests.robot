# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
# robocop: off=SPC11,LEN28,LEN27
# To deactivate the rule the next line is used otherwise needs to deactivate
# (line-too-long LEN08)
# LEN28:  File is too long.
# LEN27:  Too-many-test cases.

*** Settings ***
Documentation    Test cases for Composite Signature Algorithms in all flavors. Supports version 3 and 4.

Resource            ../config/${environment}.robot
Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_verify_logic.py

Test Tags           hybrid   hybrid-sig  composite-sig  verbose-alg
Suite Setup    Set Up Test Suite
Test Template     Request With Composite Sig


*** Test Cases ***     ALGORITHM       USE_RSA_PSS        USE_PRE_HASH        badPOP
Invalid COMPOSITE-SIG-03-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-03-ml-dsa-44-rsa2048-pss    True    False    True
     [Tags]    negative  rsa  rsa-pss

Valid COMPOSITE-SIG-03-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-03-ml-dsa-44-rsa2048-pss    True    False    False
     [Tags]    positive  rsa  rsa-pss

Invalid COMPOSITE-SIG-03-ML-DSA-44-RSA2048 Request
     ...    composite-sig-03-ml-dsa-44-rsa2048    False    False    True
     [Tags]    negative  rsa

Valid COMPOSITE-SIG-03-ML-DSA-44-RSA2048 Request
     ...    composite-sig-03-ml-dsa-44-rsa2048    False    False    False
     [Tags]    positive  rsa

Invalid COMPOSITE-SIG-03-ML-DSA-44-ED25519 Request
     ...    composite-sig-03-ml-dsa-44-ed25519    False    False    True
     [Tags]    negative  ed25519

Valid COMPOSITE-SIG-03-ML-DSA-44-ED25519 Request
     ...    composite-sig-03-ml-dsa-44-ed25519    False    False    False
     [Tags]    positive  ed25519

Invalid COMPOSITE-SIG-03-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-03-ml-dsa-44-ecdsa-secp256r1    False    False    True
     [Tags]    negative  ecdsa  secp256r1

Valid COMPOSITE-SIG-03-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-03-ml-dsa-44-ecdsa-secp256r1    False    False    False
     [Tags]    positive  ecdsa  secp256r1

Invalid COMPOSITE-SIG-03-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-03-ml-dsa-65-rsa3072-pss    True    False    True
     [Tags]    negative  rsa  rsa-pss

Valid COMPOSITE-SIG-03-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-03-ml-dsa-65-rsa3072-pss    True    False    False
     [Tags]    positive  rsa  rsa-pss

Invalid COMPOSITE-SIG-03-ML-DSA-65-RSA3072 Request
     ...    composite-sig-03-ml-dsa-65-rsa3072    False    False    True
     [Tags]    negative  rsa

Valid COMPOSITE-SIG-03-ML-DSA-65-RSA3072 Request
     ...    composite-sig-03-ml-dsa-65-rsa3072    False    False    False
     [Tags]    positive  rsa

Invalid COMPOSITE-SIG-03-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-03-ml-dsa-65-rsa4096-pss    True    False    True
     [Tags]    negative  rsa  rsa-pss

Valid COMPOSITE-SIG-03-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-03-ml-dsa-65-rsa4096-pss    True    False    False
     [Tags]    positive  rsa  rsa-pss

Invalid COMPOSITE-SIG-03-ML-DSA-65-RSA4096 Request
     ...    composite-sig-03-ml-dsa-65-rsa4096    False    False    True
     [Tags]    negative  rsa

Valid COMPOSITE-SIG-03-ML-DSA-65-RSA4096 Request
     ...    composite-sig-03-ml-dsa-65-rsa4096    False    False    False
     [Tags]    positive  rsa

Invalid COMPOSITE-SIG-03-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-03-ml-dsa-65-ecdsa-secp384r1    False    False    True
     [Tags]    negative  ecdsa  secp384r1

Valid COMPOSITE-SIG-03-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-03-ml-dsa-65-ecdsa-secp384r1    False    False    False
     [Tags]    positive  ecdsa  secp384r1

Invalid COMPOSITE-SIG-03-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-03-ml-dsa-65-ecdsa-brainpoolP256r1    False    False    True
     [Tags]    negative  ecdsa  brainpoolp256r1

Valid COMPOSITE-SIG-03-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-03-ml-dsa-65-ecdsa-brainpoolP256r1    False    False    False
     [Tags]    positive  ecdsa  brainpoolp256r1

Invalid COMPOSITE-SIG-03-ML-DSA-65-ED25519 Request
     ...    composite-sig-03-ml-dsa-65-ed25519    False    False    True
     [Tags]    negative  ed25519  completeness

Valid COMPOSITE-SIG-03-ML-DSA-65-ED25519 Request
     ...    composite-sig-03-ml-dsa-65-ed25519    False    False    False
     [Tags]    positive  ed25519  completeness

Invalid COMPOSITE-SIG-03-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-03-ml-dsa-87-ecdsa-secp384r1    False    False    True
     [Tags]    negative  ecdsa  secp384r1  completeness

Valid COMPOSITE-SIG-03-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-03-ml-dsa-87-ecdsa-secp384r1    False    False    False
     [Tags]    positive  ecdsa  secp384r1  completeness

Invalid COMPOSITE-SIG-03-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-03-ml-dsa-87-ecdsa-brainpoolP384r1    False    False    True
     [Tags]    negative  ecdsa  brainpoolp384r1

Valid COMPOSITE-SIG-03-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-03-ml-dsa-87-ecdsa-brainpoolP384r1    False    False    False
     [Tags]    positive  ecdsa  brainpoolp384r1

Invalid COMPOSITE-SIG-03-ML-DSA-87-ED448 Request
     ...    composite-sig-03-ml-dsa-87-ed448    False    False    True
     [Tags]    negative  ed448

Valid COMPOSITE-SIG-03-ML-DSA-87-ED448 Request
     ...    composite-sig-03-ml-dsa-87-ed448    False    False    False
     [Tags]    positive  ed448

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-03-hash-ml-dsa-44-rsa2048-pss    True    True    True
     [Tags]    negative  rsa  rsa-pss  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-03-hash-ml-dsa-44-rsa2048-pss    True    True    False
     [Tags]    positive  rsa  rsa-pss  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-44-RSA2048 Request
     ...    composite-sig-03-hash-ml-dsa-44-rsa2048    False    True    True
     [Tags]    negative  rsa  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-44-RSA2048 Request
     ...    composite-sig-03-hash-ml-dsa-44-rsa2048    False    True    False
     [Tags]    positive  rsa  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-44-ED25519 Request
     ...    composite-sig-03-hash-ml-dsa-44-ed25519    False    True    True
     [Tags]    negative  ed25519  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-44-ED25519 Request
     ...    composite-sig-03-hash-ml-dsa-44-ed25519    False    True    False
     [Tags]    positive  ed25519  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-03-hash-ml-dsa-44-ecdsa-secp256r1    False    True    True
     [Tags]    negative  ecdsa  secp256r1  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-03-hash-ml-dsa-44-ecdsa-secp256r1    False    True    False
     [Tags]    positive  ecdsa  secp256r1  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa3072-pss    True    True    True
     [Tags]    negative  rsa  rsa-pss  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa3072-pss    True    True    False
     [Tags]    positive  rsa  rsa-pss  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA3072 Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa3072    False    True    True
     [Tags]    negative  rsa  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA3072 Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa3072    False    True    False
     [Tags]    positive  rsa  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa4096-pss    True    True    True
     [Tags]    negative  rsa  rsa-pss  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa4096-pss    True    True    False
     [Tags]    positive  rsa  rsa-pss  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA4096 Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa4096    False    True    True
     [Tags]    negative  rsa  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-65-RSA4096 Request
     ...    composite-sig-03-hash-ml-dsa-65-rsa4096    False    True    False
     [Tags]    positive  rsa  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-03-hash-ml-dsa-65-ecdsa-secp384r1    False    True    True
     [Tags]    negative  ecdsa  secp384r1  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-03-hash-ml-dsa-65-ecdsa-secp384r1    False    True    False
     [Tags]    positive  ecdsa  secp384r1  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-03-hash-ml-dsa-65-ecdsa-brainpoolP256r1    False    True    True
     [Tags]    negative  ecdsa  brainpoolp256r1  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-03-hash-ml-dsa-65-ecdsa-brainpoolP256r1    False    True    False
     [Tags]    positive  ecdsa  brainpoolp256r1  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-65-ED25519 Request
     ...    composite-sig-03-hash-ml-dsa-65-ed25519    False    True    True
     [Tags]    negative  ed25519  completeness  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-65-ED25519 Request
     ...    composite-sig-03-hash-ml-dsa-65-ed25519    False    True    False
     [Tags]    positive  ed25519  completeness  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-03-hash-ml-dsa-87-ecdsa-secp384r1    False    True    True
     [Tags]    negative  ecdsa  secp384r1  completeness  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-03-hash-ml-dsa-87-ecdsa-secp384r1    False    True    False
     [Tags]    positive  ecdsa  secp384r1  completeness  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-03-hash-ml-dsa-87-ecdsa-brainpoolP384r1    False    True    True
     [Tags]    negative  ecdsa  brainpoolp384r1  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-03-hash-ml-dsa-87-ecdsa-brainpoolP384r1    False    True    False
     [Tags]    positive  ecdsa  brainpoolp384r1  pre_hash

Invalid COMPOSITE-SIG-03-HASH-ML-DSA-87-ED448 Request
     ...    composite-sig-03-hash-ml-dsa-87-ed448    False    True    True
     [Tags]    negative  ed448  pre_hash

Valid COMPOSITE-SIG-03-HASH-ML-DSA-87-ED448 Request
     ...    composite-sig-03-hash-ml-dsa-87-ed448    False    True    False
     [Tags]    positive  ed448  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-04-hash-ml-dsa-44-rsa2048-pss    True    True    True
     [Tags]    negative  rsa  rsa-pss  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-04-hash-ml-dsa-44-rsa2048-pss    True    True    False
     [Tags]    positive  rsa  rsa-pss  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-44-RSA2048 Request
     ...    composite-sig-04-hash-ml-dsa-44-rsa2048    False    True    True
     [Tags]    negative  rsa  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-44-RSA2048 Request
     ...    composite-sig-04-hash-ml-dsa-44-rsa2048    False    True    False
     [Tags]    positive  rsa  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-44-ED25519 Request
     ...    composite-sig-04-hash-ml-dsa-44-ed25519    False    True    True
     [Tags]    negative  ed25519  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-44-ED25519 Request
     ...    composite-sig-04-hash-ml-dsa-44-ed25519    False    True    False
     [Tags]    positive  ed25519  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-04-hash-ml-dsa-44-ecdsa-secp256r1    False    True    True
     [Tags]    negative  ecdsa  secp256r1  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-04-hash-ml-dsa-44-ecdsa-secp256r1    False    True    False
     [Tags]    positive  ecdsa  secp256r1  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa3072-pss    True    True    True
     [Tags]    negative  rsa  rsa-pss  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa3072-pss    True    True    False
     [Tags]    positive  rsa  rsa-pss  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA3072 Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa3072    False    True    True
     [Tags]    negative  rsa  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA3072 Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa3072    False    True    False
     [Tags]    positive  rsa  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa4096-pss    True    True    True
     [Tags]    negative  rsa  rsa-pss  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa4096-pss    True    True    False
     [Tags]    positive  rsa  rsa-pss  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA4096 Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa4096    False    True    True
     [Tags]    negative  rsa  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-RSA4096 Request
     ...    composite-sig-04-hash-ml-dsa-65-rsa4096    False    True    False
     [Tags]    positive  rsa  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-ECDSA-SECP256R1 Request
     ...    composite-sig-04-hash-ml-dsa-65-ecdsa-secp256r1    False    True    True
     [Tags]    negative  ecdsa  secp256r1  completeness  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-ECDSA-SECP256R1 Request
     ...    composite-sig-04-hash-ml-dsa-65-ecdsa-secp256r1    False    True    False
     [Tags]    positive  ecdsa  secp256r1  completeness  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-04-hash-ml-dsa-65-ecdsa-secp384r1    False    True    True
     [Tags]    negative  ecdsa  secp384r1  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-04-hash-ml-dsa-65-ecdsa-secp384r1    False    True    False
     [Tags]    positive  ecdsa  secp384r1  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-04-hash-ml-dsa-65-ecdsa-brainpoolP256r1    False    True    True
     [Tags]    negative  ecdsa  brainpoolp256r1  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-04-hash-ml-dsa-65-ecdsa-brainpoolP256r1    False    True    False
     [Tags]    positive  ecdsa  brainpoolp256r1  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-65-ED25519 Request
     ...    composite-sig-04-hash-ml-dsa-65-ed25519    False    True    True
     [Tags]    negative  ed25519  completeness  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-65-ED25519 Request
     ...    composite-sig-04-hash-ml-dsa-65-ed25519    False    True    False
     [Tags]    positive  ed25519  completeness  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-04-hash-ml-dsa-87-ecdsa-secp384r1    False    True    True
     [Tags]    negative  ecdsa  secp384r1  completeness  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-04-hash-ml-dsa-87-ecdsa-secp384r1    False    True    False
     [Tags]    positive  ecdsa  secp384r1  completeness  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-04-hash-ml-dsa-87-ecdsa-brainpoolP384r1    False    True    True
     [Tags]    negative  ecdsa  brainpoolp384r1  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-04-hash-ml-dsa-87-ecdsa-brainpoolP384r1    False    True    False
     [Tags]    positive  ecdsa  brainpoolp384r1  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-87-ED448 Request
     ...    composite-sig-04-hash-ml-dsa-87-ed448    False    True    True
     [Tags]    negative  ed448  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-87-ED448 Request
     ...    composite-sig-04-hash-ml-dsa-87-ed448    False    True    False
     [Tags]    positive  ed448  pre_hash

Invalid COMPOSITE-SIG-04-HASH-ML-DSA-87-RSA4096-PSS Request
     ...    composite-sig-04-hash-ml-dsa-87-rsa4096-pss    True    True    True
     [Tags]    negative  rsa  rsa-pss  pre_hash

Valid COMPOSITE-SIG-04-HASH-ML-DSA-87-RSA4096-PSS Request
     ...    composite-sig-04-hash-ml-dsa-87-rsa4096-pss    True    True    False
     [Tags]    positive  rsa  rsa-pss  pre_hash

Invalid COMPOSITE-SIG-04-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-04-ml-dsa-44-rsa2048-pss    True    False    True
     [Tags]    negative  rsa  rsa-pss

Valid COMPOSITE-SIG-04-ML-DSA-44-RSA2048-PSS Request
     ...    composite-sig-04-ml-dsa-44-rsa2048-pss    True    False    False
     [Tags]    positive  rsa  rsa-pss

Invalid COMPOSITE-SIG-04-ML-DSA-44-RSA2048 Request
     ...    composite-sig-04-ml-dsa-44-rsa2048    False    False    True
     [Tags]    negative  rsa

Valid COMPOSITE-SIG-04-ML-DSA-44-RSA2048 Request
     ...    composite-sig-04-ml-dsa-44-rsa2048    False    False    False
     [Tags]    positive  rsa

Invalid COMPOSITE-SIG-04-ML-DSA-44-ED25519 Request
     ...    composite-sig-04-ml-dsa-44-ed25519    False    False    True
     [Tags]    negative  ed25519

Valid COMPOSITE-SIG-04-ML-DSA-44-ED25519 Request
     ...    composite-sig-04-ml-dsa-44-ed25519    False    False    False
     [Tags]    positive  ed25519

Invalid COMPOSITE-SIG-04-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-04-ml-dsa-44-ecdsa-secp256r1    False    False    True
     [Tags]    negative  ecdsa  secp256r1

Valid COMPOSITE-SIG-04-ML-DSA-44-ECDSA-SECP256R1 Request
     ...    composite-sig-04-ml-dsa-44-ecdsa-secp256r1    False    False    False
     [Tags]    positive  ecdsa  secp256r1

Invalid COMPOSITE-SIG-04-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-04-ml-dsa-65-rsa3072-pss    True    False    True
     [Tags]    negative  rsa  rsa-pss

Valid COMPOSITE-SIG-04-ML-DSA-65-RSA3072-PSS Request
     ...    composite-sig-04-ml-dsa-65-rsa3072-pss    True    False    False
     [Tags]    positive  rsa  rsa-pss

Invalid COMPOSITE-SIG-04-ML-DSA-65-RSA3072 Request
     ...    composite-sig-04-ml-dsa-65-rsa3072    False    False    True
     [Tags]    negative  rsa

Valid COMPOSITE-SIG-04-ML-DSA-65-RSA3072 Request
     ...    composite-sig-04-ml-dsa-65-rsa3072    False    False    False
     [Tags]    positive  rsa

Invalid COMPOSITE-SIG-04-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-04-ml-dsa-65-rsa4096-pss    True    False    True
     [Tags]    negative  rsa  rsa-pss

Valid COMPOSITE-SIG-04-ML-DSA-65-RSA4096-PSS Request
     ...    composite-sig-04-ml-dsa-65-rsa4096-pss    True    False    False
     [Tags]    positive  rsa  rsa-pss

Invalid COMPOSITE-SIG-04-ML-DSA-65-RSA4096 Request
     ...    composite-sig-04-ml-dsa-65-rsa4096    False    False    True
     [Tags]    negative  rsa

Valid COMPOSITE-SIG-04-ML-DSA-65-RSA4096 Request
     ...    composite-sig-04-ml-dsa-65-rsa4096    False    False    False
     [Tags]    positive  rsa

Invalid COMPOSITE-SIG-04-ML-DSA-65-ECDSA-SECP256R1 Request
     ...    composite-sig-04-ml-dsa-65-ecdsa-secp256r1    False    False    True
     [Tags]    negative  ecdsa  secp256r1  completeness

Valid COMPOSITE-SIG-04-ML-DSA-65-ECDSA-SECP256R1 Request
     ...    composite-sig-04-ml-dsa-65-ecdsa-secp256r1    False    False    False
     [Tags]    positive  ecdsa  secp256r1  completeness

Invalid COMPOSITE-SIG-04-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-04-ml-dsa-65-ecdsa-secp384r1    False    False    True
     [Tags]    negative  ecdsa  secp384r1

Valid COMPOSITE-SIG-04-ML-DSA-65-ECDSA-SECP384R1 Request
     ...    composite-sig-04-ml-dsa-65-ecdsa-secp384r1    False    False    False
     [Tags]    positive  ecdsa  secp384r1

Invalid COMPOSITE-SIG-04-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-04-ml-dsa-65-ecdsa-brainpoolP256r1    False    False    True
     [Tags]    negative  ecdsa  brainpoolp256r1

Valid COMPOSITE-SIG-04-ML-DSA-65-ECDSA-BRAINPOOLP256R1 Request
     ...    composite-sig-04-ml-dsa-65-ecdsa-brainpoolP256r1    False    False    False
     [Tags]    positive  ecdsa  brainpoolp256r1

Invalid COMPOSITE-SIG-04-ML-DSA-65-ED25519 Request
     ...    composite-sig-04-ml-dsa-65-ed25519    False    False    True
     [Tags]    negative  ed25519  completeness

Valid COMPOSITE-SIG-04-ML-DSA-65-ED25519 Request
     ...    composite-sig-04-ml-dsa-65-ed25519    False    False    False
     [Tags]    positive  ed25519  completeness

Invalid COMPOSITE-SIG-04-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-04-ml-dsa-87-ecdsa-secp384r1    False    False    True
     [Tags]    negative  ecdsa  secp384r1  completeness

Valid COMPOSITE-SIG-04-ML-DSA-87-ECDSA-SECP384R1 Request
     ...    composite-sig-04-ml-dsa-87-ecdsa-secp384r1    False    False    False
     [Tags]    positive  ecdsa  secp384r1  completeness

Invalid COMPOSITE-SIG-04-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-04-ml-dsa-87-ecdsa-brainpoolP384r1    False    False    True
     [Tags]    negative  ecdsa  brainpoolp384r1

Valid COMPOSITE-SIG-04-ML-DSA-87-ECDSA-BRAINPOOLP384R1 Request
     ...    composite-sig-04-ml-dsa-87-ecdsa-brainpoolP384r1    False    False    False
     [Tags]    positive  ecdsa  brainpoolp384r1

Invalid COMPOSITE-SIG-04-ML-DSA-87-ED448 Request
     ...    composite-sig-04-ml-dsa-87-ed448    False    False    True
     [Tags]    negative  ed448

Valid COMPOSITE-SIG-04-ML-DSA-87-ED448 Request
     ...    composite-sig-04-ml-dsa-87-ed448    False    False    False
     [Tags]    positive  ed448

Invalid COMPOSITE-SIG-04-ML-DSA-87-RSA4096-PSS Request
     ...    composite-sig-04-ml-dsa-87-rsa4096-pss    True    False    True
     [Tags]    negative  rsa  rsa-pss

Valid COMPOSITE-SIG-04-ML-DSA-87-RSA4096-PSS Request
     ...    composite-sig-04-ml-dsa-87-rsa4096-pss    True    False    False
     [Tags]    positive  rsa  rsa-pss


*** Keywords ***
Exchange Composite Sig Request
    [Documentation]    Exchange a composite signature request with the CA.
    [Arguments]    ${request}
    ${response}=    Exchange Migration PKIMessage    ${request}  ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    RETURN    ${response}

Validate BadPOP Or Cert
    [Documentation]    Validate the response for a bad POP or certificate.
    [Arguments]    ${response}   ${bad_pop}   ${alg_name}
    IF   ${bad_pop}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP
    ELSE
        PKIStatus Must Be    ${response}    accepted
        Validate Certificate Was Issued For Expected Alg  ${response}  ${alg_name}
    END

Request With Composite Sig
    [Documentation]   Request a certificate with a composite signature algorithm.
    [Arguments]    ${alg_name}   ${use_rsa_pss}    ${use_pre_hash}  ${bad_pop}
    ${comp_key}=    Generate Key    ${alg_name}   by_name=True
    ${cm}=   Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${comp_key}
    ...        use_pre_hash=${use_pre_hash}
    ...        use_rsa_pss=${use_rsa_pss}
    ${cert_request}=   Prepare CertRequest  ${comp_key}  ${cm}  spki=${spki}
    ${popo}=   Prepare Signature POPO    ${comp_key}   ${cert_request}  bad_pop=${bad_pop}
    ...        use_rsa_pss=${use_rsa_pss}   use_pre_hash=${use_pre_hash}
    ${ir}=   Build Ir From Key    ${comp_key}   cert_request=${cert_request}  popo=${popo}
    ${protected_ir}=   Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Composite Sig Request  ${protected_ir}
    Validate BadPOP Or Cert  ${response}   ${bad_pop}   ${alg_name}
