# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
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


*** Keywords ***
Default Protect General Message
    [Documentation]    Protects a general message with the default protection method.
    ...                based on the values defined in the configuration file.
    [Arguments]    ${genm}
    IF   ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}
        IF   ${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
            ${genm}=   Patch Sender   ${genm}    sender_name=${SENDER}
            ${genm}=   Patch SenderKID    ${genm}     for_mac=True
        END
        ${protected_genm}=    Default Protect With MAC    ${genm}
    ELSE
        ${protected_genm}=    Default Protect PKIMessage    ${genm}
    END
    RETURN    ${protected_genm}


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
    ${genm}=    Build CMP General Message    add_messages=get_ca_certs    recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Ca Certs    ${genp}

CA MUST Respond To MAC Protected Genm With Get CA Certs With Invalid InfoValue
    [Documentation]    According to RFC 9483 Section 4.3.1, an End-Entity can request the CA's certificate chain using
    ...    a MAC-protected general message with the `id-it-caCerts` InfoType, where the `infoValue` field
    ...    must not be set. We send a MAC-protected general message with an invalid `infoValue` field.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badRequest`.
    [Tags]    ca-certs    mac    negative
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build CMP General Message
    ...    add_messages=get_ca_certs
    ...    negative=True
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
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
    [Tags]    get_root_ca_cert_update    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    Skip If    '${OLD_ROOT_CERT}' == None    Skipped because the OLD_ROOT_CERT filepath is not set.
    ${genm}=    Build CMP General Message
    ...    add_messages=get_root_ca_cert_update
    ...    ca_cert=${OLD_ROOT_CERT}
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Root Ca Cert Update    ${genp}    ${OLD_ROOT_CERT}

CA MUST Reject MAC Protected Genm With Get Root CA Cert Update Without OldRootCert
    [Documentation]    According to RFC 9483 Section 4.3.2, an End-Entity requesting a root CA certificate update
    ...    using a MAC-protected general message must include the old root certificate for verification.
    ...    We send a MAC-protected general message for a root CA certificate update without including
    ...    the old root certificate. The CA MUST reject the request and may respond with the failInfo
    ...    `badRequest`.
    [Tags]    get_root_ca_cert_update    mac    negative
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build CMP General Message
    ...    add_messages=get_root_ca_cert_update
    ...    ca_cert=${None}
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Get Root Ca Cert Update    ${genp}    ${OLD_ROOT_CERT}

## Section 4.3.3. Get Certificate Request Template

CA MUST Respond MAC Protected Genm With Get Certificate Request Template
    [Documentation]    According to RFC 9483 Section 4.3.3, an End-Entity can request a certificate request template
    ...    using a general message with the `id-it-certReqTemplate` InfoType. This allows the End-Entity
    ...    to understand which values it can set. We send a MAC-protected general message containing a
    ...    valid `InfoTypeAndValue` structure, where the `infoValue` field is absent. The CA SHOULD accept
    ...    the request and, if supported, respond with the OID, but the value must not be set.
    [Tags]    get_cert_template    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTED_SUPPORT_MSG}    Skipped because MAC-protected support messages are disabled.
    ${genm}=    Build CMP General Message    add_messages=get_cert_template
    ...         recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
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
    ${genm}=    Build CMP General Message    add_messages=get_cert_template
    ...         recipient=${RECIPIENT}    sender=${SENDER}
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
    ${genm}=    Build CMP General Message
    ...    add_messages=get_cert_template
    ...    negative=True
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
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
    ${genm}=    Build CMP General Message    add_messages=current_crl    recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
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
    ${genm}=    Build CMP General Message
    ...    add_messages=current_crl
    ...    negative=True
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
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
    Skip If    '${CRL_CERT_IDP}' == 'None'
    ...    Skipped because no certificate with the issuing distribution point extension was provided.
    ${info_val}=   Prepare CRL Update Retrieval   cert=${CRL_CERT_IDP}
    ${genm}=    Build CMP General Message    info_values=${info_val}
    ...         recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate CRL Update Retrieval    ${genp}

CA MUST Respond To Valid MAC Protected CRL Update Retrieval With CRL File
    [Documentation]    According to RFC 9483 Section 4.3.4, an End-Entity can request a CRL update using a
    ...    MAC-protected general message with the `id-it-crlUpdateRet` InfoType. We send a MAC-protected
    ...    request for a CRL update, including an old CRL file. The CA MUST respond with a new CRL if
    ...    the provided CRL is outdated or leave the `infoValue` field absent if no update is available.
    [Tags]    mac    positive    robot:skip-on-failure
    Skip If    '${CRL_FILEPATH}' == 'None'    Skipped because the CRL_FILEPATH variable is not set.
    ${info_val}=   Prepare CRL Update Retrieval    crl_filepath=${CRL_FILEPATH}    exclude_this_update=True    
    ${genm}=    Build CMP General Message
    ...    info_values=${info_val}
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate CRL Update Retrieval    ${genp}

CA MUST Accept CA Protocol Encryption Certificate Request
    [Documentation]    According to RFC 4210bis-18 5.3.19.1, the EE may request the CA to return a CA
    ...    certificate which can be used to encrypt sensitive information. We send a general message with the
    ...    `id-it-protocolEncrCert` InfoType. The CA MUST respond with a CA certificate that can be used to
    ...    encrypt sensitive information.
    [Tags]    positive
    ${info_val}=   Prepare Simple InfoTypeAndValue  ca_prot_enc_cert
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate CA Protocol Encr Cert    ${genp}

CA MUST Reject CA Protocol Encryption Certificate Request with Set InfoValue
    [Documentation]    According to RFC 4210bis-18 5.3.19.1, the value must be absent in the general message with the
    ...    `id-it-protocolEncrCert` InfoType. We send a general message with the `id-it-protocolEncrCert` InfoType
    ...    with random bytes in the value field. The CA MUST reject the request and may return an error message.
    [Tags]    negative  strict
    ${info_val}=   Prepare Simple InfoTypeAndValue   ca_prot_enc_cert   True
    ${genm}=    Build CMP General Message   info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest,badDataFormat    exclusive=True

CA MUST Accept Signing Key Pair Types Request
    [Documentation]    According to RFC 4210bis-18 5.3.19.2, the EE may request the CA to return a list of supported
    ...    signature algorithms for which the CA can issue certificates. We send a general message with the
    ...    `id-it-signingKeyPairTypes` InfoType. The CA MUST respond with a list of supported signature algorithms.
    [Tags]    positive
    ${info_val}=  Prepare Simple InfoTypeAndValue    sign_key_pair_types
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Signing Key Types    ${genp}

CA MUST Reject Signing Key Pair Types Request with Set InfoValue
    [Documentation]    According to RFC 4210bis-18 5.3.19.2, the value must be absent in the general message with the
    ...    `id-it-signingKeyPairTypes` InfoType. We send a general message with the `id-it-signingKeyPairTypes` InfoType
    ...    with random bytes in the value field. The CA MUST reject the request and may return an error message.
    [Tags]    negative  strict
    ${info_val}=  Prepare Simple InfoTypeAndValue    sign_key_pair_types   True
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest,badDataFormat

CA MUST Accept Encryption KeyAgreement Key Pair Types Request
    [Documentation]    According to RFC 4210bis-18 5.3.19.3, the EE may request the CA to return a list of supported
    ...    key agreement algorithms for which the CA can issue certificates. We send a general message with the
    ...    `id-it-encKeyPairTypes` InfoType. The CA MUST respond with a list of supported key agreement algorithms.
    [Tags]    positive
    ${info_val}=  Prepare Simple InfoTypeAndValue    enc_key_pair_types
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Encryption And KeyAgreement Types    ${genp}

CA MUST Reject Encryption KeyAgreement Key Pair Types Request with Set InfoValue
    [Documentation]    According to RFC 4210bis-18 5.3.19.3, the value must be absent in the general message with the
    ...    `id-it-encKeyPairTypes` InfoType. We send a general message with the `id-it-encKeyPairTypes`
    ...     InfoType with random bytes in the value field. The CA MUST reject the request.
    [Tags]    negative  strict
    ${info_val}=  Prepare Simple InfoTypeAndValue    enc_key_pair_types   True
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest,badDataFormat

CA MUST Accept Preferred Symmetric Algorithm Request
    [Documentation]    According to RFC 4210bis-18 5.3.19.4, the EE may request the CA to return the preferred symmetric
    ...    encryption algorithm, which the CA can use inside the deprecated `EncryptedValue` structure, or the
    ...    `EnvelopedData` structure. We send a general message with the `id-it-preferredSymmAlg` InfoType.
    ...    The CA MUST respond with the preferred symmetric encryption algorithm.
    [Tags]    positive
    ${info_val}=  Prepare Simple InfoTypeAndValue    pref_sym_alg
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Preferred Symmetric Algorithm    ${genp}

CA MUST Reject Preferred Symmetric Algorithm Request with Set InfoValue
    [Documentation]    According to RFC 4210bis-18 5.3.19.4, the value must be absent in the general message with the
    ...    `id-it-preferredSymmAlg` InfoType. We send a general message with the `id-it-preferredSymmetricAlgorithm`
    ...    InfoType with random bytes in the value field. The CA MUST reject the request.
    [Tags]    negative  strict
    ${info_val}=  Prepare Simple InfoTypeAndValue    pref_sym_alg   True
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest,badDataFormat

CA MUST Accept Revocation Passphrase
    [Documentation]    According to RFC 4210bis-18 5.3.19.9, the EE may inform the CA about a passphrase that
    ...    can be used to revoke a certificate. We send a general message with the `id-it-revPassphrase` InfoType
    ...    and the encrypted passphrase. The CA MUST accept the passphrase and MAY return an acknowledgment.
    [Tags]    positive  advanced   robot:skip-on-failure  envelopedData
    ${info_val}=  Prepare Revocation Passphrase    passphrase=RevocationPassphrase   password=${PRESHARED_SECRET}
    ${genm}=    Build CMP General Message    info_values=${info_val}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID   pvno=3
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Revocation Passphrase Response   ${genp}

CA MUST Respond to Supported Language Tags Message
    [Documentation]    According to RFC 4210bis-18  5.3.19.13, The EE may request the CA to return a list of supported
    ...    language tags using a general message with the `id-it-supportedLangTags` InfoType. The CA MUST respond
    ...    with a list of supported language tags, which contains a single entry.
    [Tags]      positive
    ${info_val}=   Prepare SupportedLanguageTags    en,de,fr
    ${genm}=    Build CMP General Message    exclude_fields=sender,senderKID   info_values=${info_val}
    ...          recipient=${RECIPIENT}    sender=${SENDER}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    Validate Supported Language Tags    ${genp}

CA MUST Reject Supported Language Tags without a value
    [Documentation]    According to RFC 4210bis-18 5.3.19.13, The value must be present in the general message with the
    ...    `id-it-supportedLangTags` InfoType. We send a general message with the `id-it-supportedLangTags` InfoType
    ...    without a value. The CA MUST reject the request and may return an error message based on policy.
    [Tags]    negative
    ${info_val}=   Prepare SupportedLanguageTags    ${None}
    ${genm}=    Build CMP General Message    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ...         info_values=${info_val}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest,badDataFormat    exclusive=True

CA MUST Reject Supported Language Tags with only invalid Tags
    [Documentation]    According to RFC 4210bis-18 5.3.19.13, when only unsupported language tags are present in the
    ...    the general message with the `id-it-supportedLangTags` InfoType, the CA MUST reject the request and may
    ...    return an error message.
    [Tags]    negative   robot:skip-on-failure
    ${info_val}=   Prepare SupportedLanguageTags    unknown
    ${genm}=    Build CMP General Message    recipient=${RECIPIENT}    exclude_fields=sender,senderKID
    ...         info_values=${info_val}
    ${protected_genm}=    Default Protect General Message    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest    exclusive=True

# TODO add this test.
#CA MUST Accept Key Pair Parameters Request
#    [Documentation]    According to RFC 4210bis-18 5.3.19.8, the EE may request the CA the parameters for a
#    ...    OID for a specific algorithm/ecc curve. We send a general message with the `id-it-keyPairParamReq`
#    ...    InfoType. The CA MUST respond with the parameters for the requested OID or and absent value if
#    ...    the OID is not supported.
#    [Tags]    positive
#    Skip     This test is skipped because this is not supported.
