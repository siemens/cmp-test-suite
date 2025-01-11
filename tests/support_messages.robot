# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

Resource            ../resources/keywords.resource
Resource            ../config/${environment}.robot
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/keyutils.py
Library             ../resources/cmputils.py
Library             ../resources/protectionutils.py
Library             ../resources/general_msg_utils.py

Test Tags           general-message    support-messages


*** Variables ***
# normally this would be provided from the command line
${environment}      cloudpki


*** Test Cases ***
##### Section 4.3

# TODO add sig based MAC tests.

## Section 4.3.1. Get CA Certificates

CA MUST Reject MAC Protected Genm With Get CA Certs
    [Documentation]    According to RFC 9483 Section 4.3.1, an End-Entity can request the CA's certificate chain using
    ...    a general message with the `id-it-caCerts` InfoType, where the `infoValue` field must not be set.
    ...    We send a MAC-protected general message containing a valid `InfoTypeAndValue` for get ca
    ...    certificates. The CA MUST respond to the message and may include the CA certificates in the response.
    [Tags]    ca-certs    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build General Message    add_messages=get_ca_certs    recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Ca Certs    ${genp}

CA MUST Respond To MAC Protected Genm With Get CA Certs With Invalid InfoValue
    [Documentation]    According to RFC 9483 Section 4.3.1, an End-Entity can request the CA's certificate chain using
    ...    a MAC-protected general message with the `id-it-caCerts` InfoType, where the `infoValue` field
    ...    must not be set. We send a MAC-protected general message with an invalid `infoValue` field.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badRequest`.
    [Tags]    ca-certs    mac    negative
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build General Message
    ...    add_messages=get_ca_certs
    ...    negative=True
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest    exclusive=True

## Section 4.3.2. Get Root CA Certificate Update

CA MUST Respond To MAC Protected Genm With Get Root CA Certificate Update
    [Documentation]    According to RFC 9483 Section 4.3.2, an End-Entity can request updated root CA certificate
    ...    information using a general message with the `id-it-rootCaKeyUpdate` InfoType. We send a
    ...    MAC-protected general message containing a valid `InfoTypeAndValue` for root CA certificate
    ...    updates. The CA MUST respond to the message and MAY include the updated root CA certificate
    ...    information in the response.
    [Tags]    general-message    get_root_ca_cert_update    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    Skip If    '${OLD_ROOT_CERT}' == 'None'    Skipped because the OLD_ROOT_CERT filepath is not set.
    ${genm}=    Build General Message
    ...    add_messages=get_root_ca_cert_update
    ...    ca_cert=${OLD_ROOT_CERT}
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Root Ca Cert Update    ${genp}    ca_cert=${OLD_ROOT_CERT}

CA MUST Reject MAC Protected Genm With Get Root CA Cert Update Without OldRootCert
    [Documentation]    According to RFC 9483 Section 4.3.2, an End-Entity requesting a root CA certificate update
    ...    using a MAC-protected general message must include the old root certificate for verification.
    ...    We send a MAC-protected general message for a root CA certificate update without including
    ...    the old root certificate. The CA MUST reject the request and may respond with the failInfo
    ...    `badRequest`.
    [Tags]    get_root_ca_cert_update    mac    negative
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build General Message
    ...    add_messages=get_root_ca_cert_update
    ...    ca_cert=${None}
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Root Ca Cert Update    ${genp}    ca_cert=${OLD_ROOT_CERT}

## Section 4.3.3. Get Certificate Request Template

CA MUST Respond MAC Protected Genm With Get Certificate Request Template
    [Documentation]    According to RFC 9483 Section 4.3.3, an End-Entity can request a certificate request template
    ...    using a general message with the `id-it-certReqTemplate` InfoType. This allows the End-Entity
    ...    to understand which values it can set. We send a MAC-protected general message containing a
    ...    valid `InfoTypeAndValue` structure, where the `infoValue` field is absent. The CA SHOULD accept
    ...    the request and, if supported, respond with the OID, but the value must not be set.
    [Tags]    get_cert_template    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build General Message    add_messages=get_cert_template    recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Certificate Request Template    ${genp}

CA MUST Accept MAC Protected Genm With Get Cert Template With CertProfile Set
    [Documentation]    According to RFC 9483 Section 4.3.3, an End-Entity can request a certificate request template
    ...    using a general message with the `id-it-certReqTemplate` InfoType. This allows the End-Entity
    ...    to understand which values it can set. We send a MAC-protected general message with a
    ...    `CertProfile` set, which the CA uses to identify the `CertTemplate` the End-Entity can build.
    ...    The CA MAY respond with the value, but MUST return the OID if supported.
    [Tags]    mac    positive    robot:skip-on-failure
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    Skip If    '${CERT_PROFILE}' == 'None'    Skipped because the CERT_PROFILE variable is not set.
    ${genm}=    Build General Message    add_messages=get_cert_template    recipient=${RECIPIENT}    sender=${SENDER}
    ${patched_genm}=    Patch GeneralInfo    ${genm}    cert_profile=${CERT_PROFILE}
    ${protected_genm}=    Protect PKIMessage
    ...    ${patched_genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Certificate Request Template    ${genp}

CA MUST Reject MAC Protected Genm With Get Cert Template With Invalid InfoValue
    [Documentation]    According to RFC 9483 Section 4.3.3, an End-Entity can request a certificate request template
    ...    using the `id-it-certReqTemplate` InfoType, where the `infoValue` field must be absent. We send
    ...    a MAC-protected general message with the `infoValue` field incorrectly set. The CA MUST reject
    ...    the request and may return an error message depending on the policy.
    [Tags]    mac    negative    robot:skip-on-failure
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build General Message
    ...    add_messages=get_cert_template
    ...    negative=True
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest    exclusive=True

## Section 4.3.4 currentCRL

CA MUST Respond To Valid MAC Protected CurrentCRL Request
    [Documentation]    According to RFC 9483 Section 4.3.4, an End-Entity can request the latest available
    ...    Certificate Revocation List (CRL) using the `id-it-currentCRL` InfoType. We send a valid
    ...    MAC-protected general message requesting the latest CRL. The CA MUST respond with the latest
    ...    CRL available if it supports CRL provisioning.
    [Tags]    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build General Message    add_messages=current_crl    recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Current Crl    ${genp}

CA MUST Reject Invalid MAC Protected CurrentCRL Request
    [Documentation]    According to RFC 9483 Section 4.3.4, an End-Entity can request the latest available
    ...    Certificate Revocation List (CRL) using the `id-it-currentCRL` InfoType, where the `infoValue`
    ...    field must be absent. We send a MAC-protected general message for the CurrentCRL with an
    ...    invalid value in the `infoValue` field. The CA MUST reject the request and MAY return an error
    ...    message based on policy.
    [Tags]    mac    negative    robot:skip-on-failure
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build General Message
    ...    add_messages=current_crl
    ...    negative=True
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest    exclusive=True

## Section 4.3.4. CRL Update Retrieval

CA MUST Respond To Valid MAC Protected CRL Update Retrieval
    [Documentation]    According to RFC 9483 Section 4.3.4, an End-Entity can request a CRL update using a
    ...    MAC-protected general message with the `id-it-crlStatusList` InfoType. The request MUST include
    ...    a CRL source, either a CRL distribution point name or issuer name. We send a MAC-protected
    ...    request for a CRL update using the issuing distribution point extracted from a certificate.
    ...    The CA MUST return the latest CRL available or leave the `infoValue` field absent if no CRL
    ...    is available.
    [Tags]    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    Skip If
    ...    not ${CRL_CERT_IDP}
    ...    Skipped because no certificate with the issuing distribution point extension was provided.
    ${genm}=    Build General Message    add_messages=crl_update_ret    recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate CRL Update Retrieval    ${genp}

CA MUST Respond To Valid MAC Protected CRL Update Retrieval With CRL File
    [Documentation]    According to RFC 9483 Section 4.3.4, an End-Entity can request a CRL update using a
    ...    MAC-protected general message with the `id-it-crlUpdateRet` InfoType. We send a MAC-protected
    ...    request for a CRL update, including an old CRL file. The CA MUST respond with a new CRL if
    ...    the provided CRL is outdated or leave the `infoValue` field absent if no update is available.
    [Tags]    mac    positive    robot:skip-on-failure
    Skip If    '${CRL_FILEPATH}' == 'None'    Skipped because the CRL_FILEPATH variable is not set.
    ${genm}=    Build General Message
    ...    add_messages=crl_update_ret
    ...    crl_file=${CRL_FILEPATH}
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Protect PKIMessage
    ...    ${genm}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate CRL Update Retrieval    ${genp}
