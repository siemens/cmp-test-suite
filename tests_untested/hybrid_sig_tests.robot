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
Library             ../pq_logic/pq_validation_utils.py


#Suite Setup         Do PQ SIG Tests
Test Tags           pqc  hybrid-sig

*** Variables ***

# New Tags: composite-sig, multiple-auth

#${uri_multiple_auth}=   https://localhost:8080/cmp/cert-bindings-for-multiple-authentication
${uri_multiple_auth}=   ${None}
${uri_multiple_auth_neg}=  ${None}
${DEFAULT_ML_DSA_ALG}=   ml-dsa-87
${Allowed_freshness}=   500

*** Test Cases ***

############################
# Composite Signature Tests
############################

# Technically not all parts have to be defined, because a correct combination is
# built, but for better readability included.

#### Composite Signature Positive Tests ####

CA MUST Issue A Valid Composite RSA-PSS Certificate From CSR
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with RSA-PSS as traditional algorithm and ML-DSA as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   p10cr   positive  rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    signing_key=${key}    common_name=${cm}   use_rsa_pss=True
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=           Get Cert From PKIMessage    ${response}
    Validate Migration Certificate Key Usage   ${cert}

CA MUST Issue a Valid Composite-Sig RSA Certificate
    [Documentation]    As defined in Composite Sig Draft CMS03, we send a valid IR with a POP for composite signature.
    ...                The traditional algorithm is RSA key and ML-DSA-44 as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive  rsa
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=   Build Ir From Key    ${key}   common_name=${cm}  recipient=${RECIPIENT}  omit_fields=senderKID,sender   implicit_confirm=${True}
    ${response}=       Exchange PKIMessage    ${ir}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

