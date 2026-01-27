# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
# robocop: off=LEN08,LEN27,LEN28
# LEN08:  Line length is longer than 120 characters.
# LEN28:  File is too long.
# LEN27:  Too-many-test cases.


*** Settings ***
Documentation    Tests for PQ KEM algorithms and Hybrid KEM algorithms to verify all known combinations.

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

Test Tags           pqc  verbose-alg   verbose-tests   verbose-kem-tests

Suite Setup         Set Up Test Suite

Test Template     Request With PQ KEM Key


*** Test Cases ***     ALGORITHM    INVALID_KEY_SIZE
Invalid XWING Key Size    xwing    True
     [Tags]    negative  xwing

Valid XWING Request    xwing    False
     [Tags]    positive  xwing

Invalid CHEMPAT-SNTRUP761-X25519 Key Size    chempat-sntrup761-x25519    True
     [Tags]    negative  chempat  sntrup761  x25519

Valid CHEMPAT-SNTRUP761-X25519 Request    chempat-sntrup761-x25519    False
     [Tags]    positive  chempat  sntrup761  x25519

Invalid CHEMPAT-MCELIECE-348864-X25519 Key Size    chempat-mceliece-348864-x25519    True
     [Tags]    negative  chempat  mceliece  x25519

Valid CHEMPAT-MCELIECE-348864-X25519 Request    chempat-mceliece-348864-x25519    False
     [Tags]    positive  chempat  mceliece  x25519

Invalid CHEMPAT-MCELIECE-460896-X25519 Key Size    chempat-mceliece-460896-x25519    True
     [Tags]    negative  chempat  mceliece  x25519

Valid CHEMPAT-MCELIECE-460896-X25519 Request    chempat-mceliece-460896-x25519    False
     [Tags]    positive  chempat  mceliece  x25519

Invalid CHEMPAT-MCELIECE-6688128-X25519 Key Size    chempat-mceliece-6688128-x25519    True
     [Tags]    negative  chempat  mceliece  x25519

Valid CHEMPAT-MCELIECE-6688128-X25519 Request    chempat-mceliece-6688128-x25519    False
     [Tags]    positive  chempat  mceliece  x25519

Invalid CHEMPAT-MCELIECE-6960119-X25519 Key Size    chempat-mceliece-6960119-x25519    True
     [Tags]    negative  chempat  mceliece  x25519

Valid CHEMPAT-MCELIECE-6960119-X25519 Request    chempat-mceliece-6960119-x25519    False
     [Tags]    positive  chempat  mceliece  x25519

Invalid CHEMPAT-MCELIECE-8192128-X25519 Key Size    chempat-mceliece-8192128-x25519    True
     [Tags]    negative  chempat  mceliece  x25519

Valid CHEMPAT-MCELIECE-8192128-X25519 Request    chempat-mceliece-8192128-x25519    False
     [Tags]    positive  chempat  mceliece  x25519

Invalid CHEMPAT-MCELIECE-348864-X448 Key Size    chempat-mceliece-348864-x448    True
     [Tags]    negative  chempat  mceliece  x448

Valid CHEMPAT-MCELIECE-348864-X448 Request    chempat-mceliece-348864-x448    False
     [Tags]    positive  chempat  mceliece  x448

Invalid CHEMPAT-MCELIECE-460896-X448 Key Size    chempat-mceliece-460896-x448    True
     [Tags]    negative  chempat  mceliece  x448

Valid CHEMPAT-MCELIECE-460896-X448 Request    chempat-mceliece-460896-x448    False
     [Tags]    positive  chempat  mceliece  x448

Invalid CHEMPAT-MCELIECE-6688128-X448 Key Size    chempat-mceliece-6688128-x448    True
     [Tags]    negative  chempat  mceliece  x448

Valid CHEMPAT-MCELIECE-6688128-X448 Request    chempat-mceliece-6688128-x448    False
     [Tags]    positive  chempat  mceliece  x448

Invalid CHEMPAT-MCELIECE-6960119-X448 Key Size    chempat-mceliece-6960119-x448    True
     [Tags]    negative  chempat  mceliece  x448

Valid CHEMPAT-MCELIECE-6960119-X448 Request    chempat-mceliece-6960119-x448    False
     [Tags]    positive  chempat  mceliece  x448

Invalid CHEMPAT-MCELIECE-8192128-X448 Key Size    chempat-mceliece-8192128-x448    True
     [Tags]    negative  chempat  mceliece  x448

Valid CHEMPAT-MCELIECE-8192128-X448 Request    chempat-mceliece-8192128-x448    False
     [Tags]    positive  chempat  mceliece  x448

Invalid CHEMPAT-ML-KEM-768-X25519 Key Size    chempat-ml-kem-768-x25519    True
     [Tags]    negative  chempat  ml-kem  x25519

Valid CHEMPAT-ML-KEM-768-X25519 Request    chempat-ml-kem-768-x25519    False
     [Tags]    positive  chempat  ml-kem  x25519

Invalid CHEMPAT-ML-KEM-1024-X448 Key Size    chempat-ml-kem-1024-x448    True
     [Tags]    negative  chempat  ml-kem  x448

Valid CHEMPAT-ML-KEM-1024-X448 Request    chempat-ml-kem-1024-x448    False
     [Tags]    positive  chempat  ml-kem  x448

Invalid CHEMPAT-ML-KEM-768-ECDH-SECP256R1 Key Size    chempat-ml-kem-768-ecdh-secp256r1    True
     [Tags]    negative  chempat  ml-kem  ecdh  secp256r1

Valid CHEMPAT-ML-KEM-768-ECDH-SECP256R1 Request    chempat-ml-kem-768-ecdh-secp256r1    False
     [Tags]    positive  chempat  ml-kem  ecdh  secp256r1

Invalid CHEMPAT-ML-KEM-1024-ECDH-SECP384R1 Key Size    chempat-ml-kem-1024-ecdh-secp384r1    True
     [Tags]    negative  chempat  ml-kem  ecdh  secp384r1

Valid CHEMPAT-ML-KEM-1024-ECDH-SECP384R1 Request    chempat-ml-kem-1024-ecdh-secp384r1    False
     [Tags]    positive  chempat  ml-kem  ecdh  secp384r1

Invalid CHEMPAT-ML-KEM-768-ECDH-BRAINPOOLP256R1 Key Size    chempat-ml-kem-768-ecdh-brainpoolP256r1    True
     [Tags]    negative  chempat  ml-kem  ecdh  brainpoolP256r1

Valid CHEMPAT-ML-KEM-768-ECDH-BRAINPOOLP256R1 Request    chempat-ml-kem-768-ecdh-brainpoolP256r1    False
     [Tags]    positive  chempat  ml-kem  ecdh  brainpoolP256r1

Invalid CHEMPAT-ML-KEM-1024-ECDH-BRAINPOOLP384R1 Key Size    chempat-ml-kem-1024-ecdh-brainpoolP384r1    True
     [Tags]    negative  chempat  ml-kem  ecdh  brainpoolP384r1

Valid CHEMPAT-ML-KEM-1024-ECDH-BRAINPOOLP384R1 Request    chempat-ml-kem-1024-ecdh-brainpoolP384r1    False
     [Tags]    positive  chempat  ml-kem  ecdh  brainpoolP384r1

Invalid CHEMPAT-FRODOKEM-976-AES-X25519 Key Size    chempat-frodokem-976-aes-x25519    True
     [Tags]    negative  chempat  frodokem  x25519

Valid CHEMPAT-FRODOKEM-976-AES-X25519 Request    chempat-frodokem-976-aes-x25519    False
     [Tags]    positive  chempat  frodokem  x25519

Invalid CHEMPAT-FRODOKEM-976-SHAKE-X25519 Key Size    chempat-frodokem-976-shake-x25519    True
     [Tags]    negative  chempat  frodokem  x25519

Valid CHEMPAT-FRODOKEM-976-SHAKE-X25519 Request    chempat-frodokem-976-shake-x25519    False
     [Tags]    positive  chempat  frodokem  x25519

Invalid CHEMPAT-FRODOKEM-640-AES-ECDH-BRAINPOOLP256R1 Key Size    chempat-frodokem-640-aes-ecdh-brainpoolP256r1    True
     [Tags]    negative  chempat  frodokem  ecdh  brainpoolP256r1

Valid CHEMPAT-FRODOKEM-640-AES-ECDH-BRAINPOOLP256R1 Request    chempat-frodokem-640-aes-ecdh-brainpoolP256r1    False
     [Tags]    positive  chempat  frodokem  ecdh  brainpoolP256r1

Invalid CHEMPAT-FRODOKEM-640-SHAKE-ECDH-BRAINPOOLP256R1 Key Size    chempat-frodokem-640-shake-ecdh-brainpoolP256r1    True
     [Tags]    negative  chempat  frodokem  ecdh  brainpoolP256r1

Valid CHEMPAT-FRODOKEM-640-SHAKE-ECDH-BRAINPOOLP256R1 Request    chempat-frodokem-640-shake-ecdh-brainpoolP256r1    False
     [Tags]    positive  chempat  frodokem  ecdh  brainpoolP256r1

Invalid CHEMPAT-FRODOKEM-976-AES-ECDH-BRAINPOOLP384R1 Key Size    chempat-frodokem-976-aes-ecdh-brainpoolP384r1    True
     [Tags]    negative  chempat  frodokem  ecdh  brainpoolP384r1

Valid CHEMPAT-FRODOKEM-976-AES-ECDH-BRAINPOOLP384R1 Request    chempat-frodokem-976-aes-ecdh-brainpoolP384r1    False
     [Tags]    positive  chempat  frodokem  ecdh  brainpoolP384r1

Invalid CHEMPAT-FRODOKEM-976-SHAKE-ECDH-BRAINPOOLP384R1 Key Size    chempat-frodokem-976-shake-ecdh-brainpoolP384r1    True
     [Tags]    negative  chempat  frodokem  ecdh  brainpoolP384r1

Valid CHEMPAT-FRODOKEM-976-SHAKE-ECDH-BRAINPOOLP384R1 Request    chempat-frodokem-976-shake-ecdh-brainpoolP384r1    False
     [Tags]    positive  chempat  frodokem  ecdh  brainpoolP384r1

Invalid CHEMPAT-FRODOKEM-1344-AES-ECDH-BRAINPOOLP512R1 Key Size    chempat-frodokem-1344-aes-ecdh-brainpoolP512r1    True
     [Tags]    negative  chempat  frodokem  ecdh  brainpoolP512r1

Valid CHEMPAT-FRODOKEM-1344-AES-ECDH-BRAINPOOLP512R1 Request    chempat-frodokem-1344-aes-ecdh-brainpoolP512r1    False
     [Tags]    positive  chempat  frodokem  ecdh  brainpoolP512r1

Invalid CHEMPAT-FRODOKEM-1344-SHAKE-ECDH-BRAINPOOLP512R1 Key Size    chempat-frodokem-1344-shake-ecdh-brainpoolP512r1    True
     [Tags]    negative  chempat  frodokem  ecdh  brainpoolP512r1

Valid CHEMPAT-FRODOKEM-1344-SHAKE-ECDH-BRAINPOOLP512R1 Request    chempat-frodokem-1344-shake-ecdh-brainpoolP512r1    False
     [Tags]    positive  chempat  frodokem  ecdh  brainpoolP512r1

Invalid CHEMPAT-FRODOKEM-1344-AES-X448 Key Size    chempat-frodokem-1344-aes-x448    True
     [Tags]    negative  chempat  frodokem  x448

Valid CHEMPAT-FRODOKEM-1344-AES-X448 Request    chempat-frodokem-1344-aes-x448    False
     [Tags]    positive  chempat  frodokem  x448

Invalid CHEMPAT-FRODOKEM-1344-SHAKE-X448 Key Size    chempat-frodokem-1344-shake-x448    True
     [Tags]    negative  chempat  frodokem  x448

Valid CHEMPAT-FRODOKEM-1344-SHAKE-X448 Request    chempat-frodokem-1344-shake-x448    False
     [Tags]    positive  chempat  frodokem  x448

Invalid COMPOSITE-KEM-ML-KEM-768-RSA2048 Key Size    composite-kem-ml-kem-768-rsa2048    True
     [Tags]    negative  composite-kem  ml-kem  rsa

Valid COMPOSITE-KEM-ML-KEM-768-RSA2048 Request    composite-kem-ml-kem-768-rsa2048    False
     [Tags]    positive  composite-kem  ml-kem  rsa

Invalid COMPOSITE-KEM-ML-KEM-768-RSA3072 Key Size    composite-kem-ml-kem-768-rsa3072    True
     [Tags]    negative  composite-kem  ml-kem  rsa

Valid COMPOSITE-KEM-ML-KEM-768-RSA3072 Request    composite-kem-ml-kem-768-rsa3072    False
     [Tags]    positive  composite-kem  ml-kem  rsa

Invalid COMPOSITE-KEM-ML-KEM-768-RSA4096 Key Size    composite-kem-ml-kem-768-rsa4096    True
     [Tags]    negative  composite-kem  ml-kem  rsa

Valid COMPOSITE-KEM-ML-KEM-768-RSA4096 Request    composite-kem-ml-kem-768-rsa4096    False
     [Tags]    positive  composite-kem  ml-kem  rsa

Invalid COMPOSITE-KEM-ML-KEM-768-X25519 Key Size    composite-kem-ml-kem-768-x25519    True
     [Tags]    negative  composite-kem  ml-kem  x25519

Valid COMPOSITE-KEM-ML-KEM-768-X25519 Request    composite-kem-ml-kem-768-x25519    False
     [Tags]    positive  composite-kem  ml-kem  x25519

Invalid COMPOSITE-KEM-ML-KEM-768-ECDH-SECP256R1 Key Size    composite-kem-ml-kem-768-ecdh-secp256r1    True
     [Tags]    negative  composite-kem  ml-kem  ecdh  secp256r1

Valid COMPOSITE-KEM-ML-KEM-768-ECDH-SECP256R1 Request    composite-kem-ml-kem-768-ecdh-secp256r1    False
     [Tags]    positive  composite-kem  ml-kem  ecdh  secp256r1

Invalid COMPOSITE-KEM-ML-KEM-768-ECDH-SECP384R1 Key Size    composite-kem-ml-kem-768-ecdh-secp384r1    True
     [Tags]    negative  composite-kem  ml-kem  ecdh  secp384r1

Valid COMPOSITE-KEM-ML-KEM-768-ECDH-SECP384R1 Request    composite-kem-ml-kem-768-ecdh-secp384r1    False
     [Tags]    positive  composite-kem  ml-kem  ecdh  secp384r1

Invalid COMPOSITE-KEM-ML-KEM-768-ECDH-BRAINPOOLP256R1 Key Size    composite-kem-ml-kem-768-ecdh-brainpoolP256r1    True
     [Tags]    negative  composite-kem  ml-kem  ecdh  brainpoolP256r1

Valid COMPOSITE-KEM-ML-KEM-768-ECDH-BRAINPOOLP256R1 Request    composite-kem-ml-kem-768-ecdh-brainpoolP256r1    False
     [Tags]    positive  composite-kem  ml-kem  ecdh  brainpoolP256r1

Invalid COMPOSITE-KEM-ML-KEM-1024-RSA3072 Key Size    composite-kem-ml-kem-1024-rsa3072    True
     [Tags]    negative  composite-kem  ml-kem  rsa

Valid COMPOSITE-KEM-ML-KEM-1024-RSA3072 Request    composite-kem-ml-kem-1024-rsa3072    False
     [Tags]    positive  composite-kem  ml-kem  rsa

Invalid COMPOSITE-KEM-ML-KEM-1024-ECDH-SECP384R1 Key Size    composite-kem-ml-kem-1024-ecdh-secp384r1    True
     [Tags]    negative  composite-kem  ml-kem  ecdh  secp384r1

Valid COMPOSITE-KEM-ML-KEM-1024-ECDH-SECP384R1 Request    composite-kem-ml-kem-1024-ecdh-secp384r1    False
     [Tags]    positive  composite-kem  ml-kem  ecdh  secp384r1

Invalid COMPOSITE-KEM-ML-KEM-1024-ECDH-BRAINPOOLP384R1 Key Size    composite-kem-ml-kem-1024-ecdh-brainpoolP384r1    True
     [Tags]    negative  composite-kem  ml-kem  ecdh  brainpoolP384r1

Valid COMPOSITE-KEM-ML-KEM-1024-ECDH-BRAINPOOLP384R1 Request    composite-kem-ml-kem-1024-ecdh-brainpoolP384r1    False
     [Tags]    positive  composite-kem  ml-kem  ecdh  brainpoolP384r1

Invalid COMPOSITE-KEM-ML-KEM-1024-X448 Key Size    composite-kem-ml-kem-1024-x448    True
     [Tags]    negative  composite-kem  ml-kem  x448

Valid COMPOSITE-KEM-ML-KEM-1024-X448 Request    composite-kem-ml-kem-1024-x448    False
     [Tags]    positive  composite-kem  ml-kem  x448

Invalid COMPOSITE-KEM-ML-KEM-1024-ECDH-SECP521R1 Key Size    composite-kem-ml-kem-1024-ecdh-secp521r1    True
     [Tags]    negative  composite-kem  ml-kem  ecdh  secp521r1

Valid COMPOSITE-KEM-ML-KEM-1024-ECDH-SECP521R1 Request    composite-kem-ml-kem-1024-ecdh-secp521r1    False
     [Tags]    positive  composite-kem  ml-kem  ecdh  secp521r1

Invalid COMPOSITE-KEM-FRODOKEM-976-AES-RSA2048 Key Size    composite-kem-frodokem-976-aes-rsa2048    True
     [Tags]    negative  composite-kem  frodokem  rsa

Valid COMPOSITE-KEM-FRODOKEM-976-AES-RSA2048 Request    composite-kem-frodokem-976-aes-rsa2048    False
     [Tags]    positive  composite-kem  frodokem  rsa

Invalid COMPOSITE-KEM-FRODOKEM-976-AES-RSA3072 Key Size    composite-kem-frodokem-976-aes-rsa3072    True
     [Tags]    negative  composite-kem  frodokem  rsa

Valid COMPOSITE-KEM-FRODOKEM-976-AES-RSA3072 Request    composite-kem-frodokem-976-aes-rsa3072    False
     [Tags]    positive  composite-kem  frodokem  rsa

Invalid COMPOSITE-KEM-FRODOKEM-976-AES-RSA4096 Key Size    composite-kem-frodokem-976-aes-rsa4096    True
     [Tags]    negative  composite-kem  frodokem  rsa

Valid COMPOSITE-KEM-FRODOKEM-976-AES-RSA4096 Request    composite-kem-frodokem-976-aes-rsa4096    False
     [Tags]    positive  composite-kem  frodokem  rsa

Invalid COMPOSITE-KEM-FRODOKEM-976-AES-X25519 Key Size    composite-kem-frodokem-976-aes-x25519    True
     [Tags]    negative  composite-kem  frodokem  x25519

Valid COMPOSITE-KEM-FRODOKEM-976-AES-X25519 Request    composite-kem-frodokem-976-aes-x25519    False
     [Tags]    positive  composite-kem  frodokem  x25519

Invalid COMPOSITE-KEM-FRODOKEM-976-AES-ECDH-SECP384R1 Key Size    composite-kem-frodokem-976-aes-ecdh-secp384r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  secp384r1

Valid COMPOSITE-KEM-FRODOKEM-976-AES-ECDH-SECP384R1 Request    composite-kem-frodokem-976-aes-ecdh-secp384r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  secp384r1

Invalid COMPOSITE-KEM-FRODOKEM-976-AES-ECDH-BRAINPOOLP256R1 Key Size    composite-kem-frodokem-976-aes-ecdh-brainpoolP256r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  brainpoolP256r1

Valid COMPOSITE-KEM-FRODOKEM-976-AES-ECDH-BRAINPOOLP256R1 Request    composite-kem-frodokem-976-aes-ecdh-brainpoolP256r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  brainpoolP256r1

Invalid COMPOSITE-KEM-FRODOKEM-976-SHAKE-RSA2048 Key Size    composite-kem-frodokem-976-shake-rsa2048    True
     [Tags]    negative  composite-kem  frodokem  rsa

Valid COMPOSITE-KEM-FRODOKEM-976-SHAKE-RSA2048 Request    composite-kem-frodokem-976-shake-rsa2048    False
     [Tags]    positive  composite-kem  frodokem  rsa

Invalid COMPOSITE-KEM-FRODOKEM-976-SHAKE-RSA3072 Key Size    composite-kem-frodokem-976-shake-rsa3072    True
     [Tags]    negative  composite-kem  frodokem  rsa

Valid COMPOSITE-KEM-FRODOKEM-976-SHAKE-RSA3072 Request    composite-kem-frodokem-976-shake-rsa3072    False
     [Tags]    positive  composite-kem  frodokem  rsa

Invalid COMPOSITE-KEM-FRODOKEM-976-SHAKE-RSA4096 Key Size    composite-kem-frodokem-976-shake-rsa4096    True
     [Tags]    negative  composite-kem  frodokem  rsa

Valid COMPOSITE-KEM-FRODOKEM-976-SHAKE-RSA4096 Request    composite-kem-frodokem-976-shake-rsa4096    False
     [Tags]    positive  composite-kem  frodokem  rsa

Invalid COMPOSITE-KEM-FRODOKEM-976-SHAKE-X25519 Key Size    composite-kem-frodokem-976-shake-x25519    True
     [Tags]    negative  composite-kem  frodokem  x25519

Valid COMPOSITE-KEM-FRODOKEM-976-SHAKE-X25519 Request    composite-kem-frodokem-976-shake-x25519    False
     [Tags]    positive  composite-kem  frodokem  x25519

Invalid COMPOSITE-KEM-FRODOKEM-976-SHAKE-ECDH-SECP384R1 Key Size    composite-kem-frodokem-976-shake-ecdh-secp384r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  secp384r1

Valid COMPOSITE-KEM-FRODOKEM-976-SHAKE-ECDH-SECP384R1 Request    composite-kem-frodokem-976-shake-ecdh-secp384r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  secp384r1

Invalid COMPOSITE-KEM-FRODOKEM-976-SHAKE-ECDH-BRAINPOOLP256R1 Key Size    composite-kem-frodokem-976-shake-ecdh-brainpoolP256r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  brainpoolP256r1

Valid COMPOSITE-KEM-FRODOKEM-976-SHAKE-ECDH-BRAINPOOLP256R1 Request    composite-kem-frodokem-976-shake-ecdh-brainpoolP256r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  brainpoolP256r1

Invalid COMPOSITE-KEM-FRODOKEM-1344-AES-ECDH-SECP384R1 Key Size    composite-kem-frodokem-1344-aes-ecdh-secp384r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  secp384r1

Valid COMPOSITE-KEM-FRODOKEM-1344-AES-ECDH-SECP384R1 Request    composite-kem-frodokem-1344-aes-ecdh-secp384r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  secp384r1

Invalid COMPOSITE-KEM-FRODOKEM-1344-AES-ECDH-BRAINPOOLP384R1 Key Size    composite-kem-frodokem-1344-aes-ecdh-brainpoolP384r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  brainpoolP384r1

Valid COMPOSITE-KEM-FRODOKEM-1344-AES-ECDH-BRAINPOOLP384R1 Request    composite-kem-frodokem-1344-aes-ecdh-brainpoolP384r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  brainpoolP384r1

Invalid COMPOSITE-KEM-FRODOKEM-1344-AES-X448 Key Size    composite-kem-frodokem-1344-aes-x448    True
     [Tags]    negative  composite-kem  frodokem  x448

Valid COMPOSITE-KEM-FRODOKEM-1344-AES-X448 Request    composite-kem-frodokem-1344-aes-x448    False
     [Tags]    positive  composite-kem  frodokem  x448

Invalid COMPOSITE-KEM-FRODOKEM-1344-SHAKE-ECDH-SECP384R1 Key Size    composite-kem-frodokem-1344-shake-ecdh-secp384r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  secp384r1

Valid COMPOSITE-KEM-FRODOKEM-1344-SHAKE-ECDH-SECP384R1 Request    composite-kem-frodokem-1344-shake-ecdh-secp384r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  secp384r1

Invalid COMPOSITE-KEM-FRODOKEM-1344-SHAKE-ECDH-BRAINPOOLP384R1 Key Size    composite-kem-frodokem-1344-shake-ecdh-brainpoolP384r1    True
     [Tags]    negative  composite-kem  frodokem  ecdh  brainpoolP384r1

Valid COMPOSITE-KEM-FRODOKEM-1344-SHAKE-ECDH-BRAINPOOLP384R1 Request    composite-kem-frodokem-1344-shake-ecdh-brainpoolP384r1    False
     [Tags]    positive  composite-kem  frodokem  ecdh  brainpoolP384r1

Invalid COMPOSITE-KEM-FRODOKEM-1344-SHAKE-X448 Key Size    composite-kem-frodokem-1344-shake-x448    True
     [Tags]    negative  composite-kem  frodokem  x448

Valid COMPOSITE-KEM-FRODOKEM-1344-SHAKE-X448 Request    composite-kem-frodokem-1344-shake-x448    False
     [Tags]    positive  composite-kem  frodokem  x448


*** Keywords ***
Request With PQ KEM Key
    [Documentation]  Send a valid Initialization Request for a PQ KEM key.
    [Arguments]    ${alg_name}     ${invalid_key_size}   ${extensions}=${None}    ${add_params_rand}=${False}
    ${response}    ${key}=   Build And Exchange KEM Certificate Request    ${alg_name}    ${invalid_key_size}
    ...          ${extensions}    ${add_params_rand}
    IF   ${invalid_key_size}
        PKIStatus Must Be   ${response}   rejection
        PKIStatusInfo Failinfo Bit Must Be  ${response}  badCertTemplate,badDataFormat  exclusive=False
    ELSE
        PKIStatus Must Be  ${response}   accepted
        ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
        Certificate Must Be Valid    ${cert}
    END

Build And Exchange KEM Certificate Request
    [Documentation]    Build a KEM certificate request and exchange it with the CA to get a certificate.
    ...
    ...                Only builds the Initialization Request for the encrypted cert mechanism request.
    ...
    ...                Arguments:
    ...                - ${key_alg}: The key algorithm to use for the key generation (e.g. `ml-kem-768`).
    ...                - ${invalid_key_size}: Whether to use an invalid key size. Defaults to `False`.
    ...
    ...                Returns:
    ...                - The response from the CA.
    ...                - The key used for the certificate generation.
    ...
    ...                Examples:
    ...                | ${response}= | Build and Exchange KEM Certificate Request | ml-kem-768 |
    ...                | ${response}= | Build and Exchange KEM Certificate Request | ml-kem-768 | False |
    [Arguments]    ${key_alg}    ${invalid_key_size}=False   ${extensions}=${None}   ${add_params_rand}=${False}
    ${key}=    Generate Key    ${key_alg}   by_name=True
    ${cm}=    Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}      invalid_key_size=${invalid_key_size}
    ...         add_params_rand_bytes=${add_params_rand}
    ${cert_req_msg}=    Prepare CertReqMsg  ${key}  spki=${spki}   common_name=${cm}   extensions=${extensions}
    ${ir}=    Build Ir From Key    ${key}   cert_req_msg=${cert_req_msg}   exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${PQ_ISSUING_SUFFIX}
    RETURN    ${response}   ${key}
