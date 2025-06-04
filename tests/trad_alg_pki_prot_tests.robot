# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Tests specifically for the lightweight CMP profile

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

Test Template     Request With Trad Sig Key
Test Tags    verbose-tests   trad-sig   pki-protection

*** Test Cases ***     PROTECTION    SIGN_KEY    CERT    HASH_ALG    BAD
CA MUST Accept ED25519 Protected Request    signature    ${ED25519_KEY}    ${ED25519_CERT}    ${None}    False
     [Tags]    ed25519  rfc9483-validation  positive

CA Reject Invalid ED25519 Protected Request    signature    ${ED25519_KEY}    ${ED25519_CERT}    ${None}    True
     [Tags]    ed25519  rfc9483-validation  negative

CA MUST Accept ED448 Protected Request    signature    ${ED448_KEY}    ${ED448_CERT}    ${None}    False
     [Tags]    ed448  rfc9483-validation  positive

CA Reject Invalid ED448 Protected Request    signature    ${ED448_KEY}    ${ED448_CERT}    ${None}    True
     [Tags]    ed448  rfc9483-validation  negative

CA MUST Accept RSA-SHA1 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha1    False
     [Tags]    rsa  rfc9483-validation  positive

CA Reject Invalid RSA-SHA1 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha1    True
     [Tags]    rsa  rfc9483-validation  negative

CA MUST Accept RSA-SHA224 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha224    False
     [Tags]    rsa  rfc9483-validation  positive

CA Reject Invalid RSA-SHA224 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha224    True
     [Tags]    rsa  rfc9483-validation  negative

CA MUST Accept RSA-SHA256 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha256    False
     [Tags]    rsa  rfc9483-validation  positive

CA Reject Invalid RSA-SHA256 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha256    True
     [Tags]    rsa  rfc9483-validation  negative

CA MUST Accept RSA-SHA384 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha384    False
     [Tags]    rsa  rfc9483-validation  positive

CA Reject Invalid RSA-SHA384 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha384    True
     [Tags]    rsa  rfc9483-validation  negative

CA MUST Accept RSA-SHA512 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha512    False
     [Tags]    rsa  rfc9483-validation  positive

CA Reject Invalid RSA-SHA512 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha512    True
     [Tags]    rsa  rfc9483-validation  negative

CA MUST Accept RSA-PSS-SHA256 Protected Request    rsassa-pss    ${RSA_KEY}    ${RSA_CERT}    sha256    False
     [Tags]    rsa-pss  rsa  rfc9483-validation  positive

CA Reject Invalid RSA-PSS-SHA256 Protected Request    rsassa-pss    ${RSA_KEY}    ${RSA_CERT}    sha256    True
     [Tags]    rsa-pss  rsa  rfc9483-validation  negative

CA MUST Accept RSA-PSS-SHAKE128 Protected Request    rsassa-pss    ${RSA_KEY}    ${RSA_CERT}    shake128    False
     [Tags]    rsa-pss  rsa  robot:skip-on-failure  rfc9483-validation  positive

CA Reject Invalid RSA-PSS-SHAKE128 Protected Request    rsassa-pss    ${RSA_KEY}    ${RSA_CERT}    shake128    True
     [Tags]    rsa-pss  rsa  robot:skip-on-failure  rfc9483-validation  negative

CA MUST Accept RSA-PSS-SHAKE256 Protected Request    rsassa-pss    ${RSA_KEY}    ${RSA_CERT}    shake256    False
     [Tags]    rsa-pss  rsa  robot:skip-on-failure  rfc9483-validation  positive

CA Reject Invalid RSA-PSS-SHAKE256 Protected Request    rsassa-pss    ${RSA_KEY}    ${RSA_CERT}    shake256    True
     [Tags]    rsa-pss  rsa  robot:skip-on-failure  rfc9483-validation  negative

CA MUST Accept ECDSA-SHA224 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha224    False
     [Tags]    ecdsa  rfc9483-validation  positive

CA Reject Invalid ECDSA-SHA224 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha224    True
     [Tags]    ecdsa  rfc9483-validation  negative

CA MUST Accept ECDSA-SHA256 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha256    False
     [Tags]    ecdsa  rfc9483-validation  positive

CA Reject Invalid ECDSA-SHA256 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha256    True
     [Tags]    ecdsa  rfc9483-validation  negative

CA MUST Accept ECDSA-SHA384 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha384    False
     [Tags]    ecdsa  rfc9483-validation  positive

CA Reject Invalid ECDSA-SHA384 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha384    True
     [Tags]    ecdsa  rfc9483-validation  negative

CA MUST Accept ECDSA-SHA512 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha512    False
     [Tags]    ecdsa  rfc9483-validation  positive

CA Reject Invalid ECDSA-SHA512 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha512    True
     [Tags]    ecdsa  rfc9483-validation  negative

CA MUST Accept ECDSA-SHAKE128 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    shake128    False
     [Tags]    ecdsa  rfc9483-validation  positive

CA Reject Invalid ECDSA-SHAKE128 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    shake128    True
     [Tags]    ecdsa  rfc9483-validation  negative

CA MUST Accept ECDSA-SHAKE256 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    shake256    False
     [Tags]    ecdsa  rfc9483-validation  positive

CA Reject Invalid ECDSA-SHAKE256 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    shake256    True
     [Tags]    ecdsa  rfc9483-validation  negative

CA MUST Accept RSA-SHA3_224 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_224    False
     [Tags]    rsa  sha3  rfc9688-validation  positive

CA Reject Invalid RSA-SHA3_224 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_224    True
     [Tags]    rsa  sha3  rfc9688-validation  negative

CA MUST Accept RSA-SHA3_256 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_256    False
     [Tags]    rsa  sha3  rfc9688-validation  positive

CA Reject Invalid RSA-SHA3_256 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_256    True
     [Tags]    rsa  sha3  rfc9688-validation  negative

CA MUST Accept RSA-SHA3_384 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_384    False
     [Tags]    rsa  sha3  rfc9688-validation  positive

CA Reject Invalid RSA-SHA3_384 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_384    True
     [Tags]    rsa  sha3  rfc9688-validation  negative

CA MUST Accept RSA-SHA3_512 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_512    False
     [Tags]    rsa  sha3  rfc9688-validation  positive

CA Reject Invalid RSA-SHA3_512 Protected Request    signature    ${RSA_KEY}    ${RSA_CERT}    sha3_512    True
     [Tags]    rsa  sha3  rfc9688-validation  negative

CA MUST Accept ECDSA-SHA3_224 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_224    False
     [Tags]    ecdsa  sha3  rfc9688-validation  positive

CA Reject Invalid ECDSA-SHA3_224 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_224    True
     [Tags]    ecdsa  sha3  rfc9688-validation  negative

CA MUST Accept ECDSA-SHA3_256 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_256    False
     [Tags]    ecdsa  sha3  rfc9688-validation  positive

CA Reject Invalid ECDSA-SHA3_256 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_256    True
     [Tags]    ecdsa  sha3  rfc9688-validation  negative

CA MUST Accept ECDSA-SHA3_384 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_384    False
     [Tags]    ecdsa  sha3  rfc9688-validation  positive

CA Reject Invalid ECDSA-SHA3_384 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_384    True
     [Tags]    ecdsa  sha3  rfc9688-validation  negative

CA MUST Accept ECDSA-SHA3_512 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_512    False
     [Tags]    ecdsa  sha3  rfc9688-validation  positive

CA Reject Invalid ECDSA-SHA3_512 Protected Request    signature    ${ECDSA_KEY}    ${ECDSA_CERT}    sha3_512    True
     [Tags]    ecdsa  sha3  rfc9688-validation  negative


*** Keywords ***
Request With Trad Sig Key
    [Documentation]   This keyword is used to test the CA's response to a request with a traditional
    ...                signature key.
    [Tags]    alg-test   PKIProtection   trad-sig
    [Arguments]    ${protection}    ${sign_key}    ${cert}    ${hash_alg}    ${bad}
    # Build the request
    ${new_key}=  Generate Default Key
    ${cm}=   Get Next Common Name
    ${ir}=   Build Ir From Key    ${new_key}   ${cm}
    ${protected_ir}=   Protect PKIMessage  ${ir}  ${protection}
    ...                private_key=${sign_key}
    ...                cert=${cert}
    ...                hash_alg=${hash_alg}
    ...                bad_message_check=${bad}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    IF    ${ENFORCE_RFC9481} and ("sha1" == '${hash_alg}' or ("sha3" in '${hash_alg}' and '${hash_alg}' != "sha384"))
         PKIStatus Must Be    ${response}    rejection
         PKIStatusInfo Failinfo Bit Must Be    ${response}    badAlg
    ELSE IF    ${bad}
        # Validate the error response
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck
    ELSE
        PKIMessage Body Type Must Be    ${response}    ip
        PKIStatus Must Be    ${response}    accepted
    END
