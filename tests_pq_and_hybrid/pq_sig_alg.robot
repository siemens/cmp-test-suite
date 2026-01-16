# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0



*** Settings ***
Documentation    Test cases for PQ Sig algorithms to check all algorithm combinations.

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

Test Tags           pq-sig   pqc  verbose-alg   verbose-tests

Suite Setup         Set Up PQ Sig Suite
Test Template     Request With PQ Sig Key

*** Test Cases ***     ALGORITHM    HASH_ALG    badPOP
Invalid PQ Sig ML-DSA-44 Request   ml-dsa-44    ${None}    True
     [Tags]    negative  ml-dsa

Valid PQ Sig ML-DSA-44 Request    ml-dsa-44    ${None}    False
     [Tags]    positive  ml-dsa

Invalid PQ Sig ML-DSA-65 Request    ml-dsa-65    ${None}    True
     [Tags]    negative  ml-dsa

Valid PQ Sig ML-DSA-65 Request    ml-dsa-65    ${None}    False
     [Tags]    positive  ml-dsa

Invalid PQ Sig ML-DSA-87 Request    ml-dsa-87    ${None}    True
     [Tags]    negative  ml-dsa

Valid PQ Sig ML-DSA-87 Request    ml-dsa-87    ${None}    False
     [Tags]    positive  ml-dsa

Invalid PQ Sig ML-DSA-44-SHA512 Request    ml-dsa-44-sha512    sha512    True
     [Tags]    negative  ml-dsa  pre_hash

Valid PQ Sig ML-DSA-44-SHA512 Request    ml-dsa-44-sha512    sha512    False
     [Tags]    positive  ml-dsa  pre_hash

Invalid PQ Sig ML-DSA-65-SHA512 Request    ml-dsa-65-sha512    sha512    True
     [Tags]    negative  ml-dsa  pre_hash

Valid PQ Sig ML-DSA-65-SHA512 Request    ml-dsa-65-sha512    sha512    False
     [Tags]    positive  ml-dsa  pre_hash

Invalid PQ Sig ML-DSA-87-SHA512 Request    ml-dsa-87-sha512    sha512    True
     [Tags]    negative  ml-dsa  pre_hash

Valid PQ Sig ML-DSA-87-SHA512 Request    ml-dsa-87-sha512    sha512    False
     [Tags]    positive  ml-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHA2-128S Request    slh-dsa-sha2-128s    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHA2-128S Request    slh-dsa-sha2-128s    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHA2-128F Request    slh-dsa-sha2-128f    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHA2-128F Request    slh-dsa-sha2-128f    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHA2-192S Request    slh-dsa-sha2-192s    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHA2-192S Request    slh-dsa-sha2-192s    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHA2-192F Request    slh-dsa-sha2-192f    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHA2-192F Request    slh-dsa-sha2-192f    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHA2-256S Request    slh-dsa-sha2-256s    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHA2-256S Request    slh-dsa-sha2-256s    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHA2-256F Request    slh-dsa-sha2-256f    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHA2-256F Request    slh-dsa-sha2-256f    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHAKE-128S Request    slh-dsa-shake-128s    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHAKE-128S Request    slh-dsa-shake-128s    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHAKE-128F Request    slh-dsa-shake-128f    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHAKE-128F Request    slh-dsa-shake-128f    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHAKE-192S Request    slh-dsa-shake-192s    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHAKE-192S Request    slh-dsa-shake-192s    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHAKE-192F Request    slh-dsa-shake-192f    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHAKE-192F Request    slh-dsa-shake-192f    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHAKE-256S Request    slh-dsa-shake-256s    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHAKE-256S Request    slh-dsa-shake-256s    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHAKE-256F Request    slh-dsa-shake-256f    ${None}    True
     [Tags]    negative  slh-dsa

Valid PQ Sig SLH-DSA-SHAKE-256F Request    slh-dsa-shake-256f    ${None}    False
     [Tags]    positive  slh-dsa

Invalid PQ Sig SLH-DSA-SHA2-128S-SHA256 Request    slh-dsa-sha2-128s-sha256    sha256    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHA2-128S-SHA256 Request    slh-dsa-sha2-128s-sha256    sha256    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHA2-128F-SHA256 Request    slh-dsa-sha2-128f-sha256    sha256    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHA2-128F-SHA256 Request    slh-dsa-sha2-128f-sha256    sha256    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHA2-192S-SHA512 Request    slh-dsa-sha2-192s-sha512    sha512    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHA2-192S-SHA512 Request    slh-dsa-sha2-192s-sha512    sha512    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHA2-192F-SHA512 Request    slh-dsa-sha2-192f-sha512    sha512    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHA2-192F-SHA512 Request    slh-dsa-sha2-192f-sha512    sha512    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHA2-256S-SHA512 Request    slh-dsa-sha2-256s-sha512    sha512    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHA2-256S-SHA512 Request    slh-dsa-sha2-256s-sha512    sha512    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHA2-256F-SHA512 Request    slh-dsa-sha2-256f-sha512    sha512    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHA2-256F-SHA512 Request    slh-dsa-sha2-256f-sha512    sha512    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHAKE-128S-SHAKE128 Request    slh-dsa-shake-128s-shake128    shake128    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHAKE-128S-SHAKE128 Request    slh-dsa-shake-128s-shake128    shake128    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHAKE-128F-SHAKE128 Request    slh-dsa-shake-128f-shake128    shake128    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHAKE-128F-SHAKE128 Request    slh-dsa-shake-128f-shake128    shake128    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHAKE-192S-SHAKE256 Request    slh-dsa-shake-192s-shake256    shake256    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHAKE-192S-SHAKE256 Request    slh-dsa-shake-192s-shake256    shake256    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHAKE-192F-SHAKE256 Request    slh-dsa-shake-192f-shake256    shake256    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHAKE-192F-SHAKE256 Request    slh-dsa-shake-192f-shake256    shake256    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHAKE-256S-SHAKE256 Request    slh-dsa-shake-256s-shake256    shake256    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHAKE-256S-SHAKE256 Request    slh-dsa-shake-256s-shake256    shake256    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig SLH-DSA-SHAKE-256F-SHAKE256 Request    slh-dsa-shake-256f-shake256    shake256    True
     [Tags]    negative  slh-dsa  pre_hash

Valid PQ Sig SLH-DSA-SHAKE-256F-SHAKE256 Request    slh-dsa-shake-256f-shake256    shake256    False
     [Tags]    positive  slh-dsa  pre_hash

Invalid PQ Sig FALCON-512 Request    falcon-512    ${None}    True
     [Tags]    negative  falcon

Valid PQ Sig FALCON-512 Request    falcon-512    ${None}    False
     [Tags]    positive  falcon

Invalid PQ Sig FALCON-PADDED-512 Request    falcon-padded-512    ${None}    True
     [Tags]    negative  falcon

Valid PQ Sig FALCON-PADDED-512 Request    falcon-padded-512    ${None}    False
     [Tags]    positive  falcon

Invalid PQ Sig FALCON-1024 Request    falcon-1024    ${None}    True
     [Tags]    negative  falcon

Valid PQ Sig FALCON-1024 Request    falcon-1024    ${None}    False
     [Tags]    positive  falcon

Invalid PQ Sig FALCON-PADDED-1024 Request    falcon-padded-1024    ${None}    True
     [Tags]    negative  falcon

Valid PQ Sig FALCON-PADDED-1024 Request    falcon-padded-1024    ${None}    False
     [Tags]    positive  falcon


*** Keywords ***
Set Up PQ Sig Suite
    [Documentation]    Initializes the test suite for PQ signature algorithm tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                PQ issuing endpoint for certificate requests using stateless PQ signature algorithms
    ...                (e.g., ML-DSA).
    ...
    ...                The CA_CMP_URL suite variable is updated to the PQ-specific endpoint.
    Set Up Test Suite
    ${url}=   Get PQ Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE

Request With PQ Sig Key
    [Documentation]  Build a PKIMessage with a PQ signature key and send it to the CA.
    ...
    ...            Arguments:
    ...            ---------
    ...            - `alg_name`: The name of the algorithm to use for the key.
    ...            - `hash_alg`: The hash algorithm to use for the key.
    ...            - `bad_pop`: A boolean indicating whether to use an invalid proof of possession.
    [Arguments]    ${alg_name}   ${hash_alg}    ${bad_pop}
    ${pq_key}=    Generate Key    ${alg_name}   by_name=True
    ${cm}=   Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${pq_key}
    ...        hash_alg=${hash_alg}
    ${cert_request}=   Prepare CertRequest  ${pq_key}  ${cm}  spki=${spki}
    ${popo}=   Prepare Signature POPO    ${pq_key}   ${cert_request}  bad_pop=${bad_pop}
    ...        hash_alg=${hash_alg}
    ${ir}=   Build Ir From Key    ${pq_key}   cert_request=${cert_request}  popo=${popo}
    ...      exclude_fields=sender,senderKID   implicit_confirm=True
    ${protected_ir}=   Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    IF   ${bad_pop}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP
    ELSE
        PKIStatus Must Be    ${response}    accepted
        Validate Certificate Was Issued For Expected Alg  ${response}  ${alg_name}
        ${cert}=   Confirm Certificate If Needed    ${response}
        Set To Dictionary    ${PQ_SIG_KEYS}    ${alg_name}=${pq_key}
        Set To Dictionary    ${PQ_SIG_CERTS}   ${alg_name}=${cert}
    END
