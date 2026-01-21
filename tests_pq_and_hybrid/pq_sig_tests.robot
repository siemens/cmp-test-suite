# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

Resource            ../resources/keywords.resource
Resource            ../resources/setup_keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../pq_logic/pq_verify_logic.py

Test Tags           pq-sig   pqc
Suite Setup         Set Up PQ Sig Suite


*** Keywords ***
Initialize Global Variables
    [Documentation]    Initialize global variables for the test suite.
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR    ${OTHER_TRUSTED_PKI_CERT}  ${cert}   scope=Global
    VAR    ${OTHER_TRUSTED_PKI_KEY}   ${key}    scope=Global
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR    ${ISSUED_CERT}  ${cert}   scope=Global
    VAR    ${ISSUED_KEY}   ${key}    scope=Global
    VAR    &{CERT_CONF_DEF_VALS}    sender=${SENDER}    recipient=${RECIPIENT}    private_key=${ISSUED_KEY}
    ...     cert=${ISSUED_CERT}    password=${PRESHARED_SECRET}    protection=signature   scope=GLOBAL
    VAR    &{DEFAULT_PROTECTION_VALS}    protection=${DEFAULT_PROTECTION}   private_key=${ISSUED_KEY}
    ...   cert=${ISSUED_CERT}   password=${PRESHARED_SECRET}   scope=GLOBAL

Exchange PQ Signature PKIMessage
    [Documentation]    Exchange a PKIMessage for a PQ signature certificate.
    ...
    ...                Arguments:
    ...                - `name`:  The name of the PQ signature algorithm.
    ...                - `hash_alg`: The hash algorithm to use, for the pre-hash version. Defaults to `None`.
    ...                - `bad_pop`: Whether to invalidate the POP. Defaults to `False`.
    ...                - `invalid_key_size`: Whether to use an invalid key size. Defaults to `False`.
    ...
    ...                Returns:
    ...                - The response PKIMessage.
    ...

    ...                Examples:
    ...                | Exchange PQ Signature PKIMessage | ml-dsa-44 |
    ...                | Exchange PQ Signature PKIMessage | ml-dsa-44 | sha512 |
    ...                | Exchange PQ Signature PKIMessage | ml-dsa-44 | sha512 | True  |
    [Arguments]    ${name}    ${hash_alg}=${None}    ${bad_pop}=False   ${invalid_key_size}=False
    ${key}=   Generate Key    ${name}
    ${cm}=    Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}   hash_alg=${hash_alg}   invalid_key_size=${invalid_key_size}
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}   common_name=${cm}
    ...                 spki=${spki}
    ...                 bad_pop=${bad_pop}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   cert_req_msg=${cert_req_msg}
    ...       recipient=${RECIPIENT}
    ...       exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    RETURN    ${response}

Exchange PQ Signature PKIMessage With Extensions
    [Documentation]    Exchange a PKIMessage for a PQ signature certificate that includes specified extensions.
    ...
    ...                Arguments:
    ...                - ${name}: The name of the PQ signature algorithm.
    ...                - ${extension}: The extension to be applied (e.g., key_usage=cRLSign).
    ...
    ...                Returns:
    ...                - The response PKIMessage.
    ...
    ...                Examples:
    ...                | Exchange PQ Signature PKIMessage With Extensions | ml-dsa-44 | cRLSign |
    ...
    [Arguments]    ${name}    ${key_usages}
    ${key}=   Generate Key    ${name}
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions    key_usage=${key_usages}
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}
    ${cert_req_msg}=    Prepare CertReqMsg  ${key}   common_name=${cm}
    ...                 spki=${spki}   extensions=${extensions}
    ${ir}=    Build Ir From Key    ${key}   cert_req_msg=${cert_req_msg}
    ...       recipient=${RECIPIENT}
    ...       exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    RETURN    ${response}

Validate BadPOP
    [Documentation]    Validate that the response PKIMessage for a expected `badPOP` failInfo.
    ...
    ...                Arguments:
    ...                - `${response}`: The PKIMessage response object to be validated.
    ...
    ...                Examples:
    ...                | Validate BadPOP | ${response} |
    [Arguments]    ${response}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP


*** Variables ***
${DEFAULT_ML_DSA_ALG}    ml-dsa-44
${DEFAULT_SLH_DSA_ALG}    slh-dsa-sha2-128s


*** Test Cases ***
############################
# ML-DSA Tests
############################

CA MUST Issue A Valid ML-DSA-44 Cert
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-44 used.
    ...               We send an valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  ml-dsa
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-44
    Validate Certificate Was Issued For Expected Alg    ${response}    ml-dsa-44
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage   ${cert}
    Certificate Must Be Valid    ${cert}
    ${cert_chain}=   Build CMP Chain From PKIMessage    ${response}   ${cert}
    Verify Cert Chain OpenSSL PQC    ${cert_chain}

CA MUST Reject A Invalid ML-DSA-44 POP
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-44 used. We send an valid IR
    ...               with an valid ML-DSA public key, but the POP is invalid. The CA MUST reject the request and MAY
    ...               respond with the optional failInfo `badPOP`.
    [Tags]   negative   ml-dsa   badPOP
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-44    ${None}    True
    Validate BadPOP    ${response}

CA MUST Issue a valid ML-DSA-44 with Sha512 Certificate
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-44 with SHA512 used.
    ...               We send an valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]       positive   ml-dsa
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-44    sha512
    Validate Certificate Was Issued For Expected Alg    ${response}    ml-dsa-44-sha512
    ${cert}=   Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject ML-DSA-44 with Sha512 with Invalid POP
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-44 with Sha512 used.
    ...               We send a valid IR with an invalid POP. The CA MUST reject the request
    ...               and MAY respond with the optional failInfo `badPOP`.
    [Tags]   negative   ml-dsa   badPOP
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-44    sha512    True
    Validate BadPOP    ${response}

CA MUST Reject an Invalid ML-DSA-44 Public Key
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is the ML-DSA-44 used.
    ...               We send an valid IR with an invalid public key size. The CA MUST
    ...               reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative   ml-dsa  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-44    ${None}    False    True
    PKIStatus Must Be    ${response}    status=rejection
    ${status_info}=    Get PKIStatusInfo    ${response}
    Is Bit Set        ${status_info['failInfo']}    badCertTemplate

CA MUST Reject a ML-DSA-44 with SHA512 certificate for non-EE
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is the ML-DSA-44 with SHA512 OID used,
    ...               but inside a non end-entity certificate. The CA MUST reject the request and MAY respond with
    ...               optional failInfo `badCertTemplate`.
    [Tags]       negative   ml-dsa
    ${key}=   Generate Key   ml-dsa-44
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions    is_ca=True
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}   hash_alg=sha512
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}   common_name=${cm}
    ...                 spki=${spki}
    ...                 extensions=${extensions}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   cert_req_msg=${cert_req_msg}
    ...       recipient=${RECIPIENT}
    ...       exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    ${status_info}=    Get PKIStatusInfo    ${response}
    Is Bit Set        ${status_info['failInfo']}    badCertTemplate

CA MUST Issue A Valid ML-DSA-65 Cert
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-65 used.
    ...               We send an valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  ml-dsa
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-65
    Validate Certificate Was Issued For Expected Alg    ${response}    ml-dsa-65
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage   ${cert}

CA MUST Reject A Invalid ML-DSA-65 POP
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-65 used. We send an valid IR
    ...               with an valid ML-DSA public key, but the POP is invalid. The CA MUST reject the request and MAY
    ...               respond with the optional failInfo `badPOP`.
    [Tags]   negative   ml-dsa   badPOP
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-65    ${None}    True
    Validate BadPOP    ${response}

CA MUST Issue a valid ML-DSA-65 with Sha512 Certificate
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-65 with SHA512 used.
    ...               We send an valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]       positive   ml-dsa
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-65    sha512
    Validate Certificate Was Issued For Expected Alg    ${response}    ml-dsa-65-sha512

CA MUST Reject ML-DSA-65 with Sha512 with Invalid POP
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-65 with Sha512 used.
    ...               We send a valid IR with an invalid POP. The CA MUST reject the request
    ...               and MAY respond with the optional failInfo `badPOP`.
    [Tags]   negative   ml-dsa   badPOP
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-65    sha512    True
    Validate BadPOP    ${response}

CA MUST Reject an Invalid ML-DSA-65 Public Key
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is the ML-DSA-65 used.
    ...               We send an valid IR with an invalid public key size. The CA MUST
    ...               reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative   ml-dsa  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-65    ${None}    False    True
    PKIStatus Must Be    ${response}    status=rejection
    ${status_info}=    Get PKIStatusInfo    ${response}
    Is Bit Set        ${status_info['failInfo']}    badCertTemplate

CA MUST Issue A Valid ML-DSA-87 Cert
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-87 used.
    ...               We send an valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  ml-dsa
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-87
    Validate Certificate Was Issued For Expected Alg    ${response}    ml-dsa-87
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage   ${cert}

CA MUST Reject A Invalid ML-DSA-87 POP
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-87 used. We send an valid IR
    ...               with an valid ML-DSA public key, but the POP is invalid. The CA MUST reject the request and MAY
    ...               respond with the optional failInfo `badPOP`.
    [Tags]   negative   ml-dsa   badPOP
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-87    ${None}    True
    Validate BadPOP    ${response}

CA MUST Issue a valid ML-DSA-87 with Sha512 Certificate
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-87 with SHA512 used.
    ...               We send an valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]       positive   ml-dsa
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-87    sha512
    Validate Certificate Was Issued For Expected Alg    ${response}    ml-dsa-87-sha512

CA MUST Reject ML-DSA-87 with Sha512 with Invalid POP
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA-87 with Sha512 used.
    ...               We send a valid IR with an invalid POP. The CA MUST reject the request
    ...               and MAY respond with the optional failInfo `badPOP`.
    [Tags]   negative   ml-dsa   badPOP
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-87    sha512    True
    Validate BadPOP    ${response}

CA MUST Reject an Invalid ML-DSA-87 Public Key
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is the ML-DSA-87 used.
    ...               We send an valid IR with an invalid public key size. The CA MUST
    ...               reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative   ml-dsa  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage    ml-dsa-87    ${None}    False    True
    PKIStatus Must Be    ${response}    status=rejection
    ${status_info}=    Get PKIStatusInfo    ${response}
    Is Bit Set        ${status_info['failInfo']}    badCertTemplate

############################
# SLH-DSA Tests
############################

CA MUST Accept Valid SLH-DSA-SHA2-128S IR
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128S used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128s
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-128s
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}
    ${cert_chain}=   Build CMP Chain From PKIMessage    ${response}   ${cert}
    Verify Cert Chain OpenSSL PQC    ${cert_chain}

CA MUST Reject SLH-DSA-SHA2-128S IR with Invalid POP
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128S used.
    ...              We send an valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    [Tags]           negative   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128s    ${None}    True
    Validate BadPOP    ${response}

CA MUST Reject an Invalid SLH-DSA-SHA2-128S Public Key
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128S used.
    ...              We send a valid IR with an invalid public key size. The CA MUST
    ...              reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]           negative   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128s    ${None}    False    True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badDataFormat

CA MUST Accept Valid SLH-DSA-SHA2-128F IR
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128F used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128f
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-128f
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-128F IR with Invalid POP
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128F used.
    ...              We send an valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    [Tags]           negative   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128f    ${None}    True
    Validate BadPOP    ${response}

CA MUST Accept Valid SLH-DSA-SHAKE-128S IR
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128S used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128s
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-128s
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-128S IR with Invalid POP
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128S used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128s    ${None}    True
    Validate BadPOP    ${response}

CA MUST Accept Valid SLH-DSA-SHAKE-128F IR
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128F used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128f
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-128f
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-128F IR with Invalid POP
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128F used.
    ...              We send an valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128f    ${None}    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHA2-128S with Sha256 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128S-SHA256 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128s    sha256
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-128s-sha256
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-128S with Sha256 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128S-SHA256 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128s    sha256    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHA2-128F with Sha256 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128F-SHA256 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128f    sha256
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-128f-sha256
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-128F with Sha256 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-128F-SHA256 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-128f    sha256    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHAKE-128S with Shake128 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128S-SHAKE128 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128s    shake128
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-128s-shake128
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-128S with Shake128 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128S-SHAKE128 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128s    shake128    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHAKE-128F with Shake128 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128F-SHAKE128 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128f    shake128
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-128f-shake128
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-128F with Shake128 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-128F-SHAKE128 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-128f    shake128    True
    Validate BadPOP    ${response}

CA MUST Accept Valid SLH-DSA-SHA2-192S IR
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192S used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192s
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-192s
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-192S IR with Invalid POP
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192S used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192s    ${None}    True
    Validate BadPOP    ${response}

CA MUST Reject an Invalid SLH-DSA-SHA2-192S Public Key
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192S used.
    ...              We send a valid IR with an invalid public key size. The CA MUST
    ...              reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192s    ${None}    False    True
    PKIStatus Must Be    ${response}    status=rejection
    ${status_info}=    Get PKIStatusInfo    ${response}
    Is Bit Set         ${status_info['failInfo']}    badCertTemplate

CA MUST Accept Valid SLH-DSA-SHA2-192F IR
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192F used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192f
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-192f
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-192F IR with Invalid POP
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192F used.
    ...              We send an valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    [Tags]           negative   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192f    ${None}    True
    Validate BadPOP    ${response}

CA MUST Accept Valid SLH-DSA-SHAKE-192S IR
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192S used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192s
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-192s
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-192S IR with Invalid POP
    [Documentation]  According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192S used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192s    ${None}    True
    Validate BadPOP    ${response}

CA MUST Accept Valid SLH-DSA-SHAKE-192F IR
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192F used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192f
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-192f
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-192F IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192F used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192f    ${None}    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHA2-192S with Sha512 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192S-SHA512 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192s    sha512
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-192s-sha512
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-192S with Sha512 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192S-SHA512 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192s    sha512    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHA2-192F with Sha512 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192F-SHA512 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192f    sha512
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-192f-sha512
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-192F with Sha512 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-192F-SHA512 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-192f    sha512    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHAKE-192S with Shake256 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192S-SHAKE256 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192s    shake256
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-192s-shake256
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-192S with Shake256 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192S-SHAKE256 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192s    shake256    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHAKE-192F with Shake256 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192F-SHAKE256 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192f    shake256
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-192f-shake256
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-192F with Shake256 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-192F-SHAKE256 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-192f    shake256    True
    Validate BadPOP    ${response}

CA MUST Accept Valid SLH-DSA-SHA2-256S IR
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256S used.
    ...               We send an valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]       positive   slh-dsa
    ${response}=   Exchange PQ Signature PKIMessage    slh-dsa-sha2-256s
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-256s
    ${cert}=   Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-256S IR with Invalid POP
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256S used.
    ...               We send an valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...               the optional failInfo `badPOP`.
    ${response}=   Exchange PQ Signature PKIMessage    slh-dsa-sha2-256s    ${None}    True
    Validate BadPOP    ${response}

CA MUST Reject an Invalid SLH-DSA-SHA2-256S Public Key
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256S used.
    ...               We send an valid IR with an invalid public key size. The CA MUST
    ...               reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    ${response}=   Exchange PQ Signature PKIMessage    slh-dsa-sha2-256s    ${None}    False    True
    PKIStatus Must Be    ${response}    status=rejection
    ${status_info}=    Get PKIStatusInfo    ${response}
    Is Bit Set        ${status_info['failInfo']}    badCertTemplate

CA MUST Accept Valid SLH-DSA-SHAKE-256S IR
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256S used.
    ...               We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]            positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256s
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-256s
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-256S IR with Invalid POP
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256S used.
    ...               We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...               the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256s    ${None}    True
    Validate BadPOP    ${response}

CA MUST Accept Valid SLH-DSA-SHAKE-256F IR
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256F used.
    ...               We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]            positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256f
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-256f
    ${cert}=         Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-256F IR with Invalid POP
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256F used.
    ...               We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...               the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256f    ${None}    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHA2-256S with Sha512 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256S-SHA512 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-256s    sha512
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-256s-sha512
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-256S with Sha512 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256S-SHA512 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-256s    sha512    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHA2-256F with Sha512 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256F-SHA512 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-256f    sha512
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-sha2-256f-sha512
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHA2-256F with Sha512 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256F-SHA512 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-sha2-256f    sha512    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHAKE-256S with Shake256 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256S-SHAKE256 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256s    shake256
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-256s-shake256
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-256S with Shake256 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256S-SHAKE256 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256s    shake256    True
    Validate BadPOP    ${response}

CA MUST Issue a valid SLH-DSA-SHAKE-256F with Shake256 Certificate
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256F-SHAKE256 used.
    ...              We send a valid IR. The CA MUST process the request and issue a valid certificate.
    [Tags]           positive   slh-dsa
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256f    shake256
    Validate Certificate Was Issued For Expected Alg    ${response}    slh-dsa-shake-256f-shake256
    ${cert}=         Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage    ${cert}
    Certificate Must Be Valid    ${cert}

CA MUST Reject SLH-DSA-SHAKE-256F with Shake256 IR with Invalid POP
    [Documentation]    According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHAKE-256F-SHAKE256 used.
    ...              We send a valid IR with an invalid POP. The CA MUST reject the request and MAY respond with
    ...              the optional failInfo `badPOP`.
    ${response}=     Exchange PQ Signature PKIMessage    slh-dsa-shake-256f    shake256    True
    Validate BadPOP    ${response}

CA MUST Reject SLH-DSA-SHA2-256S with Sha512 certificate for non-EE
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA-SHA2-256S with Sha512 OID used,
    ...               but inside a non end-entity certificate. The CA MUST reject the request and MAY respond with
    ...               optional failInfo `badCertTemplate`.
    ${key}=   Generate Key   slh-dsa-sha2-256s
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions    is_ca=True
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}   hash_alg=sha512
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}   common_name=${cm}
    ...                 spki=${spki}
    ...                 extensions=${extensions}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   cert_req_msg=${cert_req_msg}
    ...       recipient=${RECIPIENT}
    ...       exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage   ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    ${status_info}=    Get PKIStatusInfo    ${response}
    Is Bit Set        ${status_info['failInfo']}    badCertTemplate

############################
# FN-DSA Tests
############################

############################
# KeyUsage Tests
############################

CA SHOULD Issue a valid ML-DSA with KeyUsage digitalSignature
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `digitalSignature`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  ml-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    digitalSignature
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    digitalSignature    STRICT

CA Should Issue a valid ML-DSA with KeyUsage keyCertSign
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `keyCertSign`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  ml-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    keyCertSign
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    keyCertSign    STRICT

CA Should Issue a valid ML-DSA with KeyUsage cRLSign
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `cRLSign`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  ml-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    cRLSign
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    cRLSign    STRICT

CA SHOULD Issue a valid ML-DSA with KeyUsage nonRepudiation
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `nonRepudiation`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  ml-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    nonRepudiation
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    nonRepudiation    STRICT

CA MUST Reject a ML-DSA with KeyUsage keyEncipherment
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `keyEncipherment`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  ml-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    keyEncipherment
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a ML-DSA with KeyUsage dataEncipherment
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `dataEncipherment`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  ml-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    dataEncipherment
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a ML-DSA with KeyUsage keyAgreement
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `keyAgreement`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  ml-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    keyAgreement
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a ML-DSA with KeyUsage encipherOnly
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `encipherOnly`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  ml-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    encipherOnly
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a ML-DSA with KeyUsage decipherOnly
    [Documentation]   According to draft-ietf-lamps-dilithium-certificates-07 is ML-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `decipherOnly`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  ml-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${DEFAULT_ML_DSA_ALG}    decipherOnly
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA Should Issue a SLH-DSA with KeyUsage digitalSignature
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `digitalSignature`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  slh-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    digitalSignature
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    digitalSignature    STRICT

CA Should Issue a SLH-DSA with KeyUsage keyCertSign
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `keyCertSign`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  slh-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    keyCertSign
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    keyCertSign    STRICT

CA Should Issue a SLH-DSA with KeyUsage cRLSign
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `cRLSign`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  slh-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    cRLSign
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    cRLSign    STRICT

CA Should Issue a SLH-DSA with KeyUsage nonRepudiation
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `nonRepudiation`.
    ...               The CA MUST process the request and issue a valid certificate.
    [Tags]   positive  slh-dsa  key_usage  robot:skip-on-failure
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    nonRepudiation
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate KeyUsage    ${cert}    nonRepudiation    STRICT

CA MUST Reject a SLH-DSA with KeyUsage keyEncipherment
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `keyEncipherment`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  slh-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    keyEncipherment
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a SLH-DSA with KeyUsage dataEncipherment
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `dataEncipherment`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  slh-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    dataEncipherment
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a SLH-DSA with KeyUsage keyAgreement
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `keyAgreement`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  slh-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    keyAgreement
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a SLH-DSA with KeyUsage encipherOnly
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `encipherOnly`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  slh-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    encipherOnly
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject a SLH-DSA with KeyUsage decipherOnly
    [Documentation]   According to draft-ietf-lamps-cms-sphincs-plus-17 is the SLH-DSA used.
    ...               We send an valid IR with the KeyUsage extension and the bit set for `decipherOnly`.
    ...               The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]   negative  slh-dsa  key_usage  badCertTemplate
    ${response}=   Exchange PQ Signature PKIMessage With Extensions    ${Default_SLH_DSA_ALG}    decipherOnly
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate
