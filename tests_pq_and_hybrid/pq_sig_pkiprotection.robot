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

Test Tags            pq-sig  pqc  verbose-alg   pqc-sig-verbose-alg  PKIProtection  verbose-tests

Suite Setup         Set Up PQ Sig Suite
Test Template     Request With PQ Sig Key


*** Test Cases ***     ALGORITHM    HASH_ALG    BAD_PROTECTION
CA MUST Accept ML-DSA-44 Protected Request    ml-dsa-44    ${None}    False
     [Tags]    ml-dsa  ml-dsa-44  positive

CA Reject Invalid ML-DSA-44 Protected Request    ml-dsa-44    ${None}    True
     [Tags]    ml-dsa  ml-dsa-44  negative

CA MUST Accept ML-DSA-65 Protected Request    ml-dsa-65    ${None}    False
     [Tags]    ml-dsa  ml-dsa-65  positive

CA Reject Invalid ML-DSA-65 Protected Request    ml-dsa-65    ${None}    True
     [Tags]    ml-dsa  ml-dsa-65  negative

CA MUST Accept ML-DSA-87 Protected Request    ml-dsa-87    ${None}    False
     [Tags]    ml-dsa  ml-dsa-87  positive

CA Reject Invalid ML-DSA-87 Protected Request    ml-dsa-87    ${None}    True
     [Tags]    ml-dsa  ml-dsa-87  negative

CA MUST Accept ML-DSA-44-SHA512 Protected Request    ml-dsa-44-sha512    sha512    False
     [Tags]    ml-dsa-44  ml-dsa  pre-hash  positive

CA Reject Invalid ML-DSA-44-SHA512 Protected Request    ml-dsa-44-sha512    sha512    True
     [Tags]    ml-dsa-44  ml-dsa  pre-hash  negative

CA MUST Accept ML-DSA-65-SHA512 Protected Request    ml-dsa-65-sha512    sha512    False
     [Tags]    ml-dsa-65  ml-dsa  pre-hash  positive

CA Reject Invalid ML-DSA-65-SHA512 Protected Request    ml-dsa-65-sha512    sha512    True
     [Tags]    ml-dsa-65  ml-dsa  pre-hash  negative

CA MUST Accept ML-DSA-87-SHA512 Protected Request    ml-dsa-87-sha512    sha512    False
     [Tags]    ml-dsa-87  ml-dsa  pre-hash  positive

CA Reject Invalid ML-DSA-87-SHA512 Protected Request    ml-dsa-87-sha512    sha512    True
     [Tags]    ml-dsa-87  ml-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHA2-128S Protected Request    slh-dsa-sha2-128s    ${None}    False
     [Tags]    slh-dsa  slh-dsa-sha2-128s  positive

CA Reject Invalid SLH-DSA-SHA2-128S Protected Request    slh-dsa-sha2-128s    ${None}    True
     [Tags]    slh-dsa  slh-dsa-sha2-128s  negative

CA MUST Accept SLH-DSA-SHA2-128F Protected Request    slh-dsa-sha2-128f    ${None}    False
     [Tags]    slh-dsa  slh-dsa-sha2-128f  positive

CA Reject Invalid SLH-DSA-SHA2-128F Protected Request    slh-dsa-sha2-128f    ${None}    True
     [Tags]    slh-dsa  slh-dsa-sha2-128f  negative

CA MUST Accept SLH-DSA-SHA2-192S Protected Request    slh-dsa-sha2-192s    ${None}    False
     [Tags]    slh-dsa  slh-dsa-sha2-192s  positive

CA Reject Invalid SLH-DSA-SHA2-192S Protected Request    slh-dsa-sha2-192s    ${None}    True
     [Tags]    slh-dsa  slh-dsa-sha2-192s  negative

CA MUST Accept SLH-DSA-SHA2-192F Protected Request    slh-dsa-sha2-192f    ${None}    False
     [Tags]    slh-dsa  slh-dsa-sha2-192f  positive

CA Reject Invalid SLH-DSA-SHA2-192F Protected Request    slh-dsa-sha2-192f    ${None}    True
     [Tags]    slh-dsa  slh-dsa-sha2-192f  negative

CA MUST Accept SLH-DSA-SHA2-256S Protected Request    slh-dsa-sha2-256s    ${None}    False
     [Tags]    slh-dsa  slh-dsa-sha2-256s  positive

CA Reject Invalid SLH-DSA-SHA2-256S Protected Request    slh-dsa-sha2-256s    ${None}    True
     [Tags]    slh-dsa  slh-dsa-sha2-256s  negative

CA MUST Accept SLH-DSA-SHA2-256F Protected Request    slh-dsa-sha2-256f    ${None}    False
     [Tags]    slh-dsa  slh-dsa-sha2-256f  positive

CA Reject Invalid SLH-DSA-SHA2-256F Protected Request    slh-dsa-sha2-256f    ${None}    True
     [Tags]    slh-dsa  slh-dsa-sha2-256f  negative

CA MUST Accept SLH-DSA-SHAKE-128S Protected Request    slh-dsa-shake-128s    ${None}    False
     [Tags]    slh-dsa  slh-dsa-shake-128s  positive

CA Reject Invalid SLH-DSA-SHAKE-128S Protected Request    slh-dsa-shake-128s    ${None}    True
     [Tags]    slh-dsa  slh-dsa-shake-128s  negative

CA MUST Accept SLH-DSA-SHAKE-128F Protected Request    slh-dsa-shake-128f    ${None}    False
     [Tags]    slh-dsa  slh-dsa-shake-128f  positive

CA Reject Invalid SLH-DSA-SHAKE-128F Protected Request    slh-dsa-shake-128f    ${None}    True
     [Tags]    slh-dsa  slh-dsa-shake-128f  negative

CA MUST Accept SLH-DSA-SHAKE-192S Protected Request    slh-dsa-shake-192s    ${None}    False
     [Tags]    slh-dsa  slh-dsa-shake-192s  positive

CA Reject Invalid SLH-DSA-SHAKE-192S Protected Request    slh-dsa-shake-192s    ${None}    True
     [Tags]    slh-dsa  slh-dsa-shake-192s  negative

CA MUST Accept SLH-DSA-SHAKE-192F Protected Request    slh-dsa-shake-192f    ${None}    False
     [Tags]    slh-dsa  slh-dsa-shake-192f  positive

CA Reject Invalid SLH-DSA-SHAKE-192F Protected Request    slh-dsa-shake-192f    ${None}    True
     [Tags]    slh-dsa  slh-dsa-shake-192f  negative

CA MUST Accept SLH-DSA-SHAKE-256S Protected Request    slh-dsa-shake-256s    ${None}    False
     [Tags]    slh-dsa  slh-dsa-shake-256s  positive

CA Reject Invalid SLH-DSA-SHAKE-256S Protected Request    slh-dsa-shake-256s    ${None}    True
     [Tags]    slh-dsa  slh-dsa-shake-256s  negative

CA MUST Accept SLH-DSA-SHAKE-256F Protected Request    slh-dsa-shake-256f    ${None}    False
     [Tags]    slh-dsa  slh-dsa-shake-256f  positive

CA Reject Invalid SLH-DSA-SHAKE-256F Protected Request    slh-dsa-shake-256f    ${None}    True
     [Tags]    slh-dsa  slh-dsa-shake-256f  negative

CA MUST Accept SLH-DSA-SHA2-128S-SHA256 Protected Request    slh-dsa-sha2-128s-sha256    sha256    False
     [Tags]    slh-dsa-sha2-128s  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHA2-128S-SHA256 Protected Request    slh-dsa-sha2-128s-sha256    sha256    True
     [Tags]    slh-dsa-sha2-128s  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHA2-128F-SHA256 Protected Request    slh-dsa-sha2-128f-sha256    sha256    False
     [Tags]    slh-dsa-sha2-128f  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHA2-128F-SHA256 Protected Request    slh-dsa-sha2-128f-sha256    sha256    True
     [Tags]    slh-dsa-sha2-128f  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHA2-192S-SHA512 Protected Request    slh-dsa-sha2-192s-sha512    sha512    False
     [Tags]    slh-dsa-sha2-192s  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHA2-192S-SHA512 Protected Request    slh-dsa-sha2-192s-sha512    sha512    True
     [Tags]    slh-dsa-sha2-192s  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHA2-192F-SHA512 Protected Request    slh-dsa-sha2-192f-sha512    sha512    False
     [Tags]    slh-dsa-sha2-192f  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHA2-192F-SHA512 Protected Request    slh-dsa-sha2-192f-sha512    sha512    True
     [Tags]    slh-dsa-sha2-192f  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHA2-256S-SHA512 Protected Request    slh-dsa-sha2-256s-sha512    sha512    False
     [Tags]    slh-dsa-sha2-256s  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHA2-256S-SHA512 Protected Request    slh-dsa-sha2-256s-sha512    sha512    True
     [Tags]    slh-dsa-sha2-256s  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHA2-256F-SHA512 Protected Request    slh-dsa-sha2-256f-sha512    sha512    False
     [Tags]    slh-dsa-sha2-256f  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHA2-256F-SHA512 Protected Request    slh-dsa-sha2-256f-sha512    sha512    True
     [Tags]    slh-dsa-sha2-256f  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHAKE-128S-SHAKE128 Protected Request    slh-dsa-shake-128s-shake128    shake128    False
     [Tags]    slh-dsa-shake-128s  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHAKE-128S-SHAKE128 Protected Request    slh-dsa-shake-128s-shake128    shake128    True
     [Tags]    slh-dsa-shake-128s  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHAKE-128F-SHAKE128 Protected Request    slh-dsa-shake-128f-shake128    shake128    False
     [Tags]    slh-dsa-shake-128f  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHAKE-128F-SHAKE128 Protected Request    slh-dsa-shake-128f-shake128    shake128    True
     [Tags]    slh-dsa-shake-128f  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHAKE-192S-SHAKE256 Protected Request    slh-dsa-shake-192s-shake256    shake256    False
     [Tags]    slh-dsa-shake-192s  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHAKE-192S-SHAKE256 Protected Request    slh-dsa-shake-192s-shake256    shake256    True
     [Tags]    slh-dsa-shake-192s  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHAKE-192F-SHAKE256 Protected Request    slh-dsa-shake-192f-shake256    shake256    False
     [Tags]    slh-dsa-shake-192f  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHAKE-192F-SHAKE256 Protected Request    slh-dsa-shake-192f-shake256    shake256    True
     [Tags]    slh-dsa-shake-192f  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHAKE-256S-SHAKE256 Protected Request    slh-dsa-shake-256s-shake256    shake256    False
     [Tags]    slh-dsa-shake-256s  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHAKE-256S-SHAKE256 Protected Request    slh-dsa-shake-256s-shake256    shake256    True
     [Tags]    slh-dsa-shake-256s  slh-dsa  pre-hash  negative

CA MUST Accept SLH-DSA-SHAKE-256F-SHAKE256 Protected Request    slh-dsa-shake-256f-shake256    shake256    False
     [Tags]    slh-dsa-shake-256f  slh-dsa  pre-hash  positive

CA Reject Invalid SLH-DSA-SHAKE-256F-SHAKE256 Protected Request    slh-dsa-shake-256f-shake256    shake256    True
     [Tags]    slh-dsa-shake-256f  slh-dsa  pre-hash  negative

CA MUST Accept FALCON-512 Protected Request    falcon-512    ${None}    False
     [Tags]    falcon  falcon-512  positive

CA Reject Invalid FALCON-512 Protected Request    falcon-512    ${None}    True
     [Tags]    falcon  falcon-512  negative

CA MUST Accept FALCON-PADDED-512 Protected Request    falcon-padded-512    ${None}    False
     [Tags]    falcon  falcon-padded-512  positive

CA Reject Invalid FALCON-PADDED-512 Protected Request    falcon-padded-512    ${None}    True
     [Tags]    falcon  falcon-padded-512  negative

CA MUST Accept FALCON-1024 Protected Request    falcon-1024    ${None}    False
     [Tags]    falcon  falcon-1024  positive

CA Reject Invalid FALCON-1024 Protected Request    falcon-1024    ${None}    True
     [Tags]    falcon  falcon-1024  negative

CA MUST Accept FALCON-PADDED-1024 Protected Request    falcon-padded-1024    ${None}    False
     [Tags]    falcon  falcon-padded-1024  positive

CA Reject Invalid FALCON-PADDED-1024 Protected Request    falcon-padded-1024    ${None}    True
     [Tags]    falcon  falcon-padded-1024  negative


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

Validate PQ PKIProtection Response
    [Documentation]  Validate the PKIProtection response from the CA.
    ...
    ...            Arguments:
    ...            ---------
    ...            - `request`: The PKIMessage request to send.
    ...            - `bad_message_check`: Whether to check for a negative or positive response.
    ...
    [Tags]    PKIProtection
    [Arguments]    ${request}    ${bad_message_check}
    ${response}=   Exchange PKIMessage    ${request}
    IF   ${bad_message_check}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck
    ELSE
        PKIStatus Must Be    ${response}    accepted
    END

Request With PQ Sig Key
    [Documentation]  Build a PKIMessage with a PQ signature key and send it to the CA.
    ...
    ...            Arguments:
    ...            ---------
    ...            - `alg_name`: The name of the algorithm to use for the key.
    ...            - `hash_alg`: The hash algorithm to use for the key.
    ...            - `bad_message_check`: A boolean indicating whether to use an invalid PKIMessage protection.
    [Arguments]    ${alg_name}   ${hash_alg}    ${bad_message_check}
    ${sign_key}=   Get From Dictionary    ${PQ_SIG_KEYS}   ${alg_name}
    ${sign_cert}=  Get From Dictionary    ${PQ_SIG_CERTS}   ${alg_name}
    ${result}=  Is Certificate And Key Set    ${sign_cert}   ${sign_key}
    Skip If    not ${result}    The pq signature certificate and key for: ${alg_name} are not set.
    ${pq_key}=    Generate Default PQ SIG Key
    ${cm}=   Get Next Common Name
    ${ir}=    Build Ir From Key    ${pq_key}   ${cm}   recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${protected_ir}=   Protect PKIMessage    ${ir}  signature  private_key=${sign_key}
    ...                cert=${sign_cert}    bad_message_check=${bad_message_check}
    ...                hash_alg=${hash_alg}
    Validate PQ PKIProtection Response    ${protected_ir}    ${bad_message_check}
