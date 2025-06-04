# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Tests MAC protection algorithms, for ensure that the CA accepts and rejects
...                the correct algorithms. The test cases are based on the algorithm profile
...                defined in RFC 9481 and the new SHA3 OIDs defined in RFC 9688.

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
Library             ../resources/certextractutils.py

Test Template     Request With MAC Algorithm
Test Tags           mac-alg-test   mac   verbose-tests


*** Test Cases ***     PROTECTION    HASH_ALG    BAD    SEC_HASH_ALG
CA MUST Accept HMAC-SHA1 Protected Request    hmac    sha1    False    ${None}
     [Tags]    positive    hmac    sha1    deprecated

CA Reject Invalid HMAC-SHA1 Protected Request    hmac    sha1    True    ${None}
     [Tags]    negative    hmac    sha1    deprecated

CA MUST Accept HMAC-SHA224 Protected Request    hmac    sha224    False    ${None}
     [Tags]    positive    hmac    sha2

CA Reject Invalid HMAC-SHA224 Protected Request    hmac    sha224    True    ${None}
     [Tags]    negative    hmac    sha2

CA MUST Accept HMAC-SHA256 Protected Request    hmac    sha256    False    ${None}
     [Tags]    positive    hmac    sha2

CA Reject Invalid HMAC-SHA256 Protected Request    hmac    sha256    True    ${None}
     [Tags]    negative    hmac    sha2

CA MUST Accept HMAC-SHA384 Protected Request    hmac    sha384    False    ${None}
     [Tags]    positive    hmac    sha2

CA Reject Invalid HMAC-SHA384 Protected Request    hmac    sha384    True    ${None}
     [Tags]    negative    hmac    sha2

CA MUST Accept HMAC-SHA512 Protected Request    hmac    sha512    False    ${None}
     [Tags]    positive    hmac    sha2

CA Reject Invalid HMAC-SHA512 Protected Request    hmac    sha512    True    ${None}
     [Tags]    negative    hmac    sha2

CA MUST Accept HMAC-SHA3_224 Protected Request    hmac    sha3_224    False    ${None}
     [Tags]    positive    hmac    sha3    rfc9688-validation

CA Reject Invalid HMAC-SHA3_224 Protected Request    hmac    sha3_224    True    ${None}
     [Tags]    negative    hmac    sha3    rfc9688-validation

CA MUST Accept HMAC-SHA3_256 Protected Request    hmac    sha3_256    False    ${None}
     [Tags]    positive    hmac    sha3    rfc9688-validation

CA Reject Invalid HMAC-SHA3_256 Protected Request    hmac    sha3_256    True    ${None}
     [Tags]    negative    hmac    sha3    rfc9688-validation

CA MUST Accept HMAC-SHA3_384 Protected Request    hmac    sha3_384    False    ${None}
     [Tags]    positive    hmac    sha3    rfc9688-validation

CA Reject Invalid HMAC-SHA3_384 Protected Request    hmac    sha3_384    True    ${None}
     [Tags]    negative    hmac    sha3    rfc9688-validation

CA MUST Accept HMAC-SHA3_512 Protected Request    hmac    sha3_512    False    ${None}
     [Tags]    positive    hmac    sha3    rfc9688-validation

CA Reject Invalid HMAC-SHA3_512 Protected Request    hmac    sha3_512    True    ${None}
     [Tags]    negative    hmac    sha3    rfc9688-validation

CA MUST Accept KMAC-SHAKE128 Protected Request    kmac    shake128    False    ${None}
     [Tags]    positive    kmac    shake    shake128

CA Reject Invalid KMAC-SHAKE128 Protected Request    kmac    shake128    True    ${None}
     [Tags]    negative    kmac    shake    shake128

CA MUST Accept KMAC-SHAKE256 Protected Request    kmac    shake256    False    ${None}
     [Tags]    positive    kmac    shake    shake256

CA Reject Invalid KMAC-SHAKE256 Protected Request    kmac    shake256    True    ${None}
     [Tags]    negative    kmac    shake    shake256

CA MUST Accept AES128_GMAC Protected Request    aes128_gmac    ${None}    False    ${None}
     [Tags]    positive    gmac

CA Reject Invalid AES128_GMAC Protected Request    aes128_gmac    ${None}    True    ${None}
     [Tags]    negative    gmac

CA MUST Accept AES192_GMAC Protected Request    aes192_gmac    ${None}    False    ${None}
     [Tags]    positive    gmac

CA Reject Invalid AES192_GMAC Protected Request    aes192_gmac    ${None}    True    ${None}
     [Tags]    negative    gmac

CA MUST Accept AES256_GMAC Protected Request    aes256_gmac    ${None}    False    ${None}
     [Tags]    positive    gmac

CA Reject Invalid AES256_GMAC Protected Request    aes256_gmac    ${None}    True    ${None}
     [Tags]    negative    gmac

CA MUST Accept PBMAC1-HMAC-SHA1 Protected Request    pbmac1    sha1    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha1    deprecated

CA Reject Invalid PBMAC1-HMAC-SHA1 Protected Request    pbmac1    sha1    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha1    deprecated

CA MUST Accept PBMAC1-HMAC-SHA224 Protected Request    pbmac1    sha224    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha2

CA Reject Invalid PBMAC1-HMAC-SHA224 Protected Request    pbmac1    sha224    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha2

CA MUST Accept PBMAC1-HMAC-SHA256 Protected Request    pbmac1    sha256    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha2

CA Reject Invalid PBMAC1-HMAC-SHA256 Protected Request    pbmac1    sha256    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha2

CA MUST Accept PBMAC1-HMAC-SHA384 Protected Request    pbmac1    sha384    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha2

CA Reject Invalid PBMAC1-HMAC-SHA384 Protected Request    pbmac1    sha384    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha2

CA MUST Accept PBMAC1-HMAC-SHA512 Protected Request    pbmac1    sha512    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha2

CA Reject Invalid PBMAC1-HMAC-SHA512 Protected Request    pbmac1    sha512    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha2

CA MUST Accept PBMAC1-HMAC-SHA3_224 Protected Request    pbmac1    sha3_224    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA Reject Invalid PBMAC1-HMAC-SHA3_224 Protected Request    pbmac1    sha3_224    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA MUST Accept PBMAC1-HMAC-SHA3_256 Protected Request    pbmac1    sha3_256    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA Reject Invalid PBMAC1-HMAC-SHA3_256 Protected Request    pbmac1    sha3_256    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA MUST Accept PBMAC1-HMAC-SHA3_384 Protected Request    pbmac1    sha3_384    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA Reject Invalid PBMAC1-HMAC-SHA3_384 Protected Request    pbmac1    sha3_384    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA MUST Accept PBMAC1-HMAC-SHA3_512 Protected Request    pbmac1    sha3_512    False    ${None}
     [Tags]    positive    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA Reject Invalid PBMAC1-HMAC-SHA3_512 Protected Request    pbmac1    sha3_512    True    ${None}
     [Tags]    negative    pbmac1    pbkdf2    hmac    sha3    rfc9688-validation

CA MUST Accept PBM-HMAC-SHA1 Protected Request    password_based_mac    sha1    False    ${None}
     [Tags]    positive    pbm    hmac    sha1    deprecated

CA Reject Invalid PBM-HMAC-SHA1 Protected Request    password_based_mac    sha1    True    ${None}
     [Tags]    negative    pbm    hmac    sha1    deprecated

CA MUST Accept PBM-HMAC-SHA224 Protected Request    password_based_mac    sha224    False    ${None}
     [Tags]    positive    pbm    hmac    sha2

CA Reject Invalid PBM-HMAC-SHA224 Protected Request    password_based_mac    sha224    True    ${None}
     [Tags]    negative    pbm    hmac    sha2

CA MUST Accept PBM-HMAC-SHA256 Protected Request    password_based_mac    sha256    False    ${None}
     [Tags]    positive    pbm    hmac    sha2

CA Reject Invalid PBM-HMAC-SHA256 Protected Request    password_based_mac    sha256    True    ${None}
     [Tags]    negative    pbm    hmac    sha2

CA MUST Accept PBM-HMAC-SHA384 Protected Request    password_based_mac    sha384    False    ${None}
     [Tags]    positive    pbm    hmac    sha2

CA Reject Invalid PBM-HMAC-SHA384 Protected Request    password_based_mac    sha384    True    ${None}
     [Tags]    negative    pbm    hmac    sha2

CA MUST Accept PBM-HMAC-SHA512 Protected Request    password_based_mac    sha512    False    ${None}
     [Tags]    positive    pbm    hmac    sha2

CA Reject Invalid PBM-HMAC-SHA512 Protected Request    password_based_mac    sha512    True    ${None}
     [Tags]    negative    pbm    hmac    sha2

CA MUST Accept PBM-HMAC-SHA3_224 Protected Request    password_based_mac    sha3_224    False    ${None}
     [Tags]    positive    pbm    hmac    sha3    rfc9688-validation

CA Reject Invalid PBM-HMAC-SHA3_224 Protected Request    password_based_mac    sha3_224    True    ${None}
     [Tags]    negative    pbm    hmac    sha3    rfc9688-validation

CA MUST Accept PBM-HMAC-SHA3_256 Protected Request    password_based_mac    sha3_256    False    ${None}
     [Tags]    positive    pbm    hmac    sha3    rfc9688-validation

CA Reject Invalid PBM-HMAC-SHA3_256 Protected Request    password_based_mac    sha3_256    True    ${None}
     [Tags]    negative    pbm    hmac    sha3    rfc9688-validation

CA MUST Accept PBM-HMAC-SHA3_384 Protected Request    password_based_mac    sha3_384    False    ${None}
     [Tags]    positive    pbm    hmac    sha3    rfc9688-validation

CA Reject Invalid PBM-HMAC-SHA3_384 Protected Request    password_based_mac    sha3_384    True    ${None}
     [Tags]    negative    pbm    hmac    sha3    rfc9688-validation

CA MUST Accept PBM-HMAC-SHA3_512 Protected Request    password_based_mac    sha3_512    False    ${None}
     [Tags]    positive    pbm    hmac    sha3    rfc9688-validation

CA Reject Invalid PBM-HMAC-SHA3_512 Protected Request    password_based_mac    sha3_512    True    ${None}
     [Tags]    negative    pbm    hmac    sha3    rfc9688-validation


*** Keywords ***
Request With MAC Algorithm
    [Documentation]   This keyword is used to test the CA's response to a request with a traditional
    ...                signature key.
    [Tags]    alg-test   PKIProtection   trad-sig
    [Arguments]    ${protection}    ${hash_alg}    ${bad}   ${secondary_hash_alg}
    # Build the request
    ${pwd}   ${protection}=   Get Password In Size     ${protection}   ${PRE_SHARED_SECRET}  ${hash_alg}
    ${new_key}=  Generate Default Key
    ${cm}=   Get Next Common Name
    ${ir}=   Build Ir From Key    ${new_key}   ${cm}   for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    ...                sender_kid=${SENDER}    recipient=${RECIPIENT}   sender=${SENDER}
    ${protected_ir}=   Protect PKIMessage  ${ir}  ${protection}
    ...                password=${pwd}
    ...                hash_alg=${hash_alg}
    ...                bad_message_check=${bad}
    ...                mac_alg=${secondary_hash_alg}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    IF    ${ENFORCE_RFC9481} and ('${protection}' in ['kmac', 'hmac'] or "aes" in '${protection}')
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badAlg
    ELSE IF    ${ENFORCE_RFC9481} and ("sha1" == '${hash_alg}' or ("sha3" in '${hash_alg}' and '${hash_alg}' != "sha384"))
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badAlg
    ELSE IF  ${bad}
        # Validate the error response
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck
    ELSE
        PKIMessage Body Type Must Be    ${response}    ip
        PKIStatus Must Be    ${response}    accepted
    END
