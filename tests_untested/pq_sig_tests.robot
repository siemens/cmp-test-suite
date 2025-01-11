# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

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

#Suite Setup         Do PQ SIG Tests
Test Tags           pq-sig   pqc

Suite Setup         Initialize Global Variables

*** Keywords ***

Initialize Global Variables
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${OTHER_TRUSTED_PKI_CERT}  ${cert}   scope=Global
    VAR   ${OTHER_TRUSTED_PKI_KEY}   ${key}    scope=Global
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${ISSUED_CERT}  ${cert}   scope=Global
    VAR   ${ISSUED_KEY}   ${key}    scope=Global

*** Test Cases ***

############################
# ML-DSA Tests
############################

CA MUST Issue A Valid ML-DSA Cert P10cr
    [Documentation]   We send a P10cr Certification Request with CSR signed by a valid ML-DSA private key. The CA MUST
    ...               process the request and issue a valid certificate.
    [Tags]   ir   positive  ml-dsa  pqc
    ${key}=   Generate Key    ${DEFAULT_ML_DSA_KEY}
    ${cm}=   Get Next Common Name
    ${csr}=    Build CSR    signing_key=${key}    common_name=${cm}
    ${p10cr}=    Build P10cr From CSR
    ...    ${csr}
    ...    recipient=${RECIPIENT}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_p10cr}=    Protect PKIMessage
     ...    pki_message=${p10cr}
     ...    protection=signature
     ...    private_key=${ISSUED_KEY}
     ...    cert=${ISSUED_CERT}
     ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_p10cr}
    Verify PKIStatusInfo    ${response}   status=accepted

CA MUST Reject A Invalid CSR Signature For ML-DSA
    [Documentation]   We send a P10cr Certification Request with a CSR signed by a different ML-DSA private key.
    ...               The CA MUST reject the request and may respond with the optional failInfo `badPOP`.
    [Tags]  ir   popo   negative
    ${key}=   Generate Key    ${DEFAULT_ML_DSA_KEY}
    ${cm}=   Get Next Common Name
    ${csr}=    Build CSR    signing_key=${key}    common_name=${cm}   exclude_signature=True    hash_alg=${None}
    ${signed_csr}=   Sign CSR    ${csr}   signing_key=${key}   bad_sig=True
    ${p10cr}=    Build P10cr From CSR
    ...    ${signed_csr}
    ...    recipient=${RECIPIENT}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_p10cr}=    Protect PKIMessage
     ...    pki_message=${p10cr}
     ...    protection=signature
     ...    private_key=${ISSUED_KEY}
     ...    cert=${ISSUED_CERT}
     ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_p10cr}
    Verify PKIStatusInfo    ${response}   failinfos=badPOP

CA MUST Reject A Invalid OID within An CSR For ML-DSA
    [Documentation]   We send a P10cr Certification Request with a CSR containing an invalid OID for ML-DSA.
    ...               The CA MUST reject the request and respond with the failInfo `badPOP` and/or `badAlg`.
    [Tags]            negative    p10cr    popo  ml-dsa
    ${key}=   Generate Key    ml-dsa-87
    ${key2}=  Generate PQ Key    ml-dsa-65
    ${cm}=    Get Next Common Name
    ${csr}=    Build CSR    signing_key=${key2}    common_name=${cm}   exclude_signature=True   hash_alg=${None}
    ${signed_csr}=   Sign CSR   ${csr}   signing_key=${key2}   other_key=${key}
    ${p10cr}=    Build P10cr From CSR
    ...    ${signed_csr}
    ...    recipient=${RECIPIENT}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_p10cr}=    Protect PKIMessage
     ...    pki_message=${p10cr}
     ...    protection=signature
     ...    private_key=${ISSUED_KEY}
     ...    cert=${ISSUED_CERT}
     ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_p10cr}
    Verify PKIStatusInfo    ${response}   failinfos=badPOP,badAlg

CA MUST Accept valid IR For ML-DSA
     [Documentation]   We send an Initialization Request signed by a valid ML-DSA private key.
     ...               The CA MUST accept the request, issue a valid certificate, and verify that the issued
     ...               certificate is valid.
     [Tags]            ir    positive
     ${key}=   Generate Key    ${DEFAULT_ML_DSA_KEY}
     ${cm}=    Get Next Common Name
     ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
     ${protected_ir}=    Protect PKIMessage
     ...    pki_message=${ir}
     ...    protection=signature
     ...    private_key=${ISSUED_KEY}
     ...    cert=${ISSUED_CERT}
     ...    implicit_confirm=${True}
     ${response}=   Exchange PKIMessage    ${protected_ir}
     PKIMessage Body Type Must Be    ${response}    ip
     PKIStatus Must Be    ${response}    status=accepted
     ${cert}=   Get Cert From PKIMessage    ${response}
     Certificate Must Be Valid       ${cert}


CA MUST Accept A Valid KGA Request For ML-DSA
    [Documentation]   We send an Initialization Request indicating the CA to issue a certificate for a ML-DSA Private
    ...               Key, to be generated by the Key Generation Authority (KGA). The CA MUST process the request and
    ...               issue a valid certificate and send a encrypted private key inside the `SignedData` structure.
    [Tags]            ir    positive   kga
    ${key}=   Generate Key    ${DEFAULT_ML_DSA_KEY}
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   for_kga=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be     ${response}    status=accepted


############################
# SLH-DSA Tests
############################

CA MUST Accept Valid SLH-DSA IR
    [Documentation]    According to NIST CSOR, is a valid OID send for SLH-DSA. We send an IR with a valid SLH-DSA
    ...                private key, the CA MUST accept the request, issue a valid certificate.
    [Tags]       positive   slh-dsa 
    ${key}=   Generate Key    slh-dsa
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be       ${response}    status=accepted
    PKIMessage Body Type Must Be   ${response}    ip
    
CA MUST Reject SLH-DSA IR with Invalid POPO
    [Documentation]    We send an IR with a SLH-DSA private key signed by a different SLH-DSA private key. The CA MUST
    ...                reject the request and may respond with the optional failInfo `badPOP`.
    [Tags]       negative   slh-dsa   popo
    ${key}=   Generate Key    slh-dsa
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}  bad_pop=True  omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

############################
# Falcon Tests
############################

CA MUST Accept Valid Falcon IR
    [Documentation]    According to the oqs algorithms is a valid OID send for Falcon.
    ...                We send an IR with a valid POP signed by a Falcon Private Key, the CA MUST accept
    ...                the request and issue a valid certificate.
    [Tags]       positive   falcon
    ${key}=   Generate Key    falcon-512
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be       ${response}    status=accepted
    PKIMessage Body Type Must Be   ${response}    ip

CA MUST Reject Falcon IR with Invalid POPO
    [Documentation]    We send an IR with a Falcon private key signed by a different Falcon private key. The CA MUST
    ...                reject the request and may respond with the optional failInfo `badPOP`.
    [Tags]       negative   falcon   popo
    ${key}=   Generate Key    falcon-512
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}  bad_pop=True  omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Accept Valid Falcon-Padded Request
    [Documentation]    According to the oqs algorithms is a valid OID send for Falcon.
    ...                We send an IR with a valid POP signed by a Falcon Private Key, the CA MUST accept
    ...                the request and issue a valid certificate.
    [Tags]       positive   falcon
    ${key}=   Generate Key    falcon-padded-512
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be       ${response}    status=accepted
    PKIMessage Body Type Must Be   ${response}    ip

CA MUST Reject Falcon-Padded Request with Invalid POPO
    [Documentation]    We send an IR with a Falcon private key signed by a different Falcon private key. The CA MUST
    ...                reject the request and may respond with the optional failInfo `badPOP`.
    [Tags]       negative   falcon   popo
    ${key}=   Generate Key    falcon-padded-512
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}  bad_pop=True  omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP
