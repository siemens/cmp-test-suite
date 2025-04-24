# SPDX-FileCopyrightText: Copyright 2024 Siemens AG # robocop: off=COM04
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
Library             ../resources/certextractutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_verify_logic.py

Suite Setup         Set Up Test Suite
Test Tags           pqc  hybrid-sig   chameleon  hybrid-cert


*** Variables ***
${CHAMELEON_CERT}  ${None}
${CHAMELEON_KEY}  ${None}
${CHAMELEON_DELTA_CERT}  ${None}
${CHAMELEON_DELTA_KEY}  ${None}


*** Test Cases ***
##########################
# Chameleon Tests
##########################

CA MUST Issue a valid Chameleon Cert
    [Documentation]    According to chameleon-certs-05 section 5, is a valid paired CSR send.
    ...                The CA should issue a valid chameleon certificate.
    [Tags]      positive
    ${pq_key}=  Generate Default PQ SIG Key
    ${trad_key}=  Generate Key   rsa   length=2048
    ${csr}=    Build Paired CSR   ${trad_key}   ${pq_key}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}
    ...                                 exclude_fields=sender,senderKID   implicit_confirm=True
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}  ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${delta_cert}=   Build Delta Cert From Paired Cert    ${cert}
    ${extracted_delta_cert}=   Get From List    ${response["extraCerts"]}    1
    ${der_delta}=   Encode To Der    ${delta_cert}
    ${der_extracted_delta}=   Encode To Der    ${extracted_delta_cert}
    Should Be Equal    ${der_delta}    ${der_extracted_delta}   The delta certificate should
    ...                be the same as the extracted delta certificate.
    VAR   ${CHAMELEON_CERT}    ${cert}      scope=Global
    VAR   ${CHAMELEON_KEY}    ${trad_key}   scope=Global
    VAR   ${CHAMELEON_DELTA_CERT}    ${delta_cert}   scope=Global
    VAR   ${CHAMELEON_DELTA_KEY}    ${pq_key}   scope=Global

CA MUST Detect Invalid Secondary POP in Paired CSR
    [Documentation]    According to chameleon-certs-05 section 5.2, a receiver must check that the
    ...                paired CSR is valid and can not make the assumption that the secondary
    ...                signature is valid. We send a paired CSR, but the secondary signature is invalid.
    ...                The CA **MUST** detect this and MAY respond with the optional failInfo `badPOP`.
    [Tags]   negative
    ${pq_key}=  Generate Default PQ SIG Key
    ${trad_key}=  Generate Key   rsa   length=2048
    ${csr}=    Build Paired CSR    ${pq_key}    ${trad_key}   bad_alt_pop=True
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ${protected_p10cr}=  Protect PKIMessage    ${p10cr}
    ...                                        protection=signature
    ...                                        private_key=${ISSUED_KEY}
    ...                                        cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}   ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA SHALL NOT Include Extensions in the Base Certificate
    [Documentation]    According to chameleon-certs-05 section 4.1, the base certificate should not contain
    ...                any extensions, which are not included in the delta certificate. We send a paired CSR,
    ...                which contains extensions in the base certificate, which are not included in the delta
    ...                certificate. The CA could reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate`.
    [Tags]      negative   robot:skip-on-failure
    ${pq_key}=  Generate Default PQ SIG Key
    ${trad_key}=  Generate Default Key
    ${delta_extns}=   Prepare Extensions    key_usage=digitalSignature
    ${csr}=    Build Paired CSR    ${pq_key}    ${trad_key}    delta_extensions=${delta_extns}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ${protected_p10cr}=  Protect PKIMessage    ${p10cr}
    ...                                        protection=signature
    ...                                        private_key=${ISSUED_KEY}
    ...                                        cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}   ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Detect Paired Certificate with Weak secondary Key
    [Documentation]    According to chameleon-certs-05 section 6, a receiver must check that the
    ...                paired CSR is valid and should make sure that the secondary key is not weaker,
    ...                than the primary key. We send a paired CSR, which contains a weak secondary key.
    ...                The CA **MUST** detect this and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]       negative
    ${pq_key}=  Generate Default PQ SIG Key
    ${trad_key}=  Generate Key   rsa   length=1024
    ${csr}=    Build Paired CSR    ${pq_key}    ${trad_key}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ${protected_p10cr}=  Protect PKIMessage    ${p10cr}
    ...                                        protection=signature
    ...                                        private_key=${ISSUED_KEY}
    ...                                        cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}   ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Reject Paired CSR with Same Key
    [Documentation]    According to chameleon-certs-05 section 4.1, a receiver must check that the
    ...                paired CSR is valid and should make sure that the primary and secondary key are not the same.
    ...                We send a paired CSR, which contains the same key for the primary and secondary key.
    ...                The CA **MUST** detect this and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]       negative
    ${pq_key}=  Generate Default PQ SIG Key
    ${csr}=    Build Paired CSR    ${pq_key}    ${pq_key}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ${protected_p10cr}=  Protect PKIMessage    ${p10cr}
    ...                                        protection=signature
    ...                                        private_key=${ISSUED_KEY}
    ...                                        cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}   ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Issue A Chameleon With The Extension Correctly Set
    [Documentation]    According to chameleon-certs-05 section 4, the CA MUST accept a valid paired CSR
    ...                and issue a valid chameleon certificate. The DCD extension should be set to the
    ...                correct value. Which means that the extensions have the same criticality as the base
    ...                certificate. Additionally can the Delta Certificate be built from the paired certificate.
    [Tags]       positive
    ${pq_key}=  Generate Default PQ SIG Key
    ${trad_key}=  Generate Default Key
    ${delta_extns}=   Prepare Extensions    key_usage=digitalSignature
    ${base_extns}=   Prepare Extensions    key_usage=digitalSignature
    ${csr}=    Build Paired CSR    ${pq_key}    ${trad_key}   delta_extensions=${delta_extns}
    ...                            base_extensions=${base_extns}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ${protected_p10cr}=  Protect PKIMessage    ${p10cr}
    ...                                        protection=signature
    ...                                        private_key=${ISSUED_KEY}
    ...                                        cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}   ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${delta_cert}=   Build Delta Cert From Paired Cert    ${cert}
    ${delta_extns}=   Get Asn1 Value    ${delta_cert}    tbsCertificate.extensions
    ${base_extns}=   Get Asn1 Value    ${cert}    tbsCertificate.extensions
    Validate DCD Extension   ${delta_extns}    ${base_extns}

CA SHOULD NOT Mark The DCD Extension as Critical
    [Documentation]    According to chameleon-certs-05 section 4, the DCD extension should not be marked as critical.
    ...                We send a valid paired CSR. The CA should issue a valid chameleon certificate and the
    ...                DCD extension should not be marked as critical.
    [Tags]       robot:skip-on-failure
    ${pq_key}=  Generate Default PQ SIG Key
    ${trad_key}=  Generate Default Key
    ${delta_extns}=   Prepare Extensions    key_usage=digitalSignature   critical=True
    ${csr}=    Build Paired CSR    ${pq_key}    ${trad_key}   delta_extensions=${delta_extns}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ${protected_p10cr}=  Protect PKIMessage    ${p10cr}
    ...                                        protection=signature
    ...                                        private_key=${ISSUED_KEY}
    ...                                        cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}   ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    ${cert}=   Get Cert From PKIMessage    ${response}
    Cert Contains Extension    ${cert}    dcd    must_be_non_crit=True

CA MUST Revoke a Delta Cert
    [Documentation]    When a CA receives a revoke request for a delta certificate, it should revoke the
    ...                delta certificate. We send a revoke request for a delta certificate. The CA should
    ...                revoke the delta certificate. Based on the Policy of the CA, the CA can revoke
    ...                the base certificate as well.
    [Tags]      positive  rr
    ${result}=  Is Certificate And Key Set    ${CHAMELEON_DELTA_CERT}    ${CHAMELEON_DELTA_KEY}
    Skip If    not ${result}       Delta Certificate and Key are not set.
    ${ir}=   Build CMP Revoke Request    ${CHAMELEON_DELTA_CERT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    signature
    ...    private_key=${CHAMELEON_DELTA_KEY}
    ...    cert=${CHAMELEON_DELTA_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   suffix=${issuing_suffix}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Check That The Delta Key Was Not Previously Revoked
    [Documentation]    According to chameleon-certs-05 section 6, a receiver must check that the
    ...                delta key was not previously used. We send a chameleon certificate, but the
    ...                delta key was previously revoked. The CA **MUST** detect this and MAY respond
    ...                with the optional failInfo `badCertTemplate`.
    [Tags]        negative
    ${result}=  Is Certificate And Key Set    ${CHAMELEON_CERT}    ${CHAMELEON_KEY}
    Skip If    not ${result}       Chameleon Certificate and Key are not set.
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${csr}=   Build Paired CSR    ${key}  ${CHAMELEON_DELTA_KEY}   common_name=${cm}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ${protected_p10cr}=  Protect PKIMessage    ${p10cr}
    ...                                        protection=signature
    ...                                        private_key=${ISSUED_KEY}
    ...                                        cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}   ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

##########################
# Chameleon Client Tests
##########################

Client MUST detect Invalid Signature in Delta Extension
    [Documentation]    When a client receives a Chameleon certificate, it must check that the
    ...                signature in the delta extension is valid.
    [Tags]       negative
    Skip    Not implemented yet, because another trusted CA would need to make this mistake.

Client MUST Check that the Chameleon Certificate is Valid
    [Documentation]    According to chameleon-certs-05 section 6, a receiver must check that the
    ...                certificate is valid and can not make the assumption that the reconstructed
    ...                certificate is valid. We send a chameleon certificate, but the delta certificate
    ...                is revoked. The CA **MUST** detect this and MAY respond with the optional failInfo
    ...                `signerNotTrusted`.
    [Tags]      hybrid-auth  experimental
    ${result}=  Is Certificate And Key Set    ${CHAMELEON_CERT}    ${CHAMELEON_KEY}
    Skip If    not ${result}       Chameleon Certificate and Key are not set.
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${ir}=   Build Ir From Key    ${key}   ${cm}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${CHAMELEON_KEY}
    ...    cert=${CHAMELEON_CERT}
    ...    alt_key=${CHAMELEON_DELTA_KEY}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}  ${CA_BASE_URL}  ${multi_auth_suffix}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    signerNotTrusted

# Client MUST Reject Recursively Built Paired Certificate
