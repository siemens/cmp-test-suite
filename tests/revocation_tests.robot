# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP Revocation and Revive Requests logic, not necessarily specific to the
...                 lightweight profile. Includes tests which are configuration-dependent, as some PKI policies may not
...                 allow certificate revocation or may allow revocation but not certificate revival.

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             String
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py

# Runs first before any test case.
Test Setup          Regenerate Cert For RR Tests

Test Tags           rr


*** Variables ***
${REVOCATION_CERT}      ${None}
${REVOCATION_KEY}       ${None}
${REVOKED_CERT}         ${None}
${REVOKED_KEY}          ${None}
${TEST_REVIVE}          ${False}


*** Test Cases ***
# TODO add test case: valid revocation request which is strict and sets a implicit_confirm value

CA MUST Reject Revocation Request With MAC Based Protection
    [Documentation]    According to RFC 9483 Section 4.2, a revocation request must not use MAC-based protection.
    ...    The PKIMessage must be signed with the private key corresponding to the certificate being
    ...    revoked. We send a revocation request using MAC-based protection instead of a signature.
    ...    The CA MUST reject the request and may respond with the optional failInfo `wrongIntegrity`.
    [Tags]    mac    negative
    ${rr}=    Build Cmp Revoke Request
    ...    cert=${REVOCATION_CERT}
    ...    exclude_fields=${None}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${protected_rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=password_based_mac
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=wrongIntegrity   exclusive=True

CA MUST Reject Revocation Request Without Protection
    [Documentation]    According to RFC 9483 Section 4.2, a revocation request must include PKIMessage protection.
    ...    The request must be signed with the private key corresponding to the certificate being revoked.
    ...    We send a revocation request without PKIMessage protection. The CA MUST reject the request and
    ...    may respond with the optional failInfo `badMessageCheck`.
    [Tags]    negative    protection
    ${cert_template}=    Prepare CertTemplate    cert=${REVOCATION_CERT}    include_fields=serialNumber,issuer
    ${rr}=    Build CMP Revoke Request    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=${None}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True


# TODO clarify failinfo because RR

CA MUST Reject Revocation Request Without ExtraCerts
    [Documentation]    According to RFC 9483 Sections 3 the `extraCerts` field is required for proper verification in
    ...    a revocation requests. We send a revocation request omitting the `extraCerts` field. The CA MUST
    ...    reject the request and may respond with the failInfo `badMessageCheck` or `addInfoNotAvailable`.
    [Tags]    negative    protection
    ${rr}=    Build CMP Revoke Request
    ...    cert=${REVOCATION_CERT}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ...    exclude_cert=True
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck,addInfoNotAvailable

CA MUST Reject Revocation Request With Issuer As Sender
    [Documentation]    According to RFC 9483 Section 4.2, the sender of a revocation request MUST NOT be set to the
    ...    issuer. We send a revocation request where the sender is incorrectly set to the certificate
    ...    issuer. The CA MUST reject the request and MAY respond with the optional failInfo
    ...    `badMessageCheck`.
    [Tags]    negative    rfc9483-header
    ${cert_template}=    Prepare CertTemplate    cert=${REVOCATION_CERT}    include_fields=serialNumber,issuer
    ${rr}=    Build CMP Revoke Request    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ${rr}=    Patch Sender    ${rr}    cert=${REVOCATION_CERT}    subject=False
    ${rr}=    Patch SenderKID    ${rr}    cert=${REVOCATION_CERT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ...    no_patch=True
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

# CRLReason

CA MUST Reject Revocation Request With An Unknown Value As CRLReason
    [Documentation]    According to RFC 9483 Section 4.2, a revocation request must not contain an unknown or
    ...    unsupported value in the `CRLReason` field. We send a revocation request with an unknown value
    ...    in the `CRLReason` field. The CA MUST reject the request and may respond with the optional
    ...    failInfo `badRequest`.
    [Tags]    CRLReason    negative
    ${crl_entry_details}=    Prepare CRLReason Extensions    negative=True
    ${rr}=    Build CMP Revoke Request
    ...    crl_entry_details=${crl_entry_details}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

A MUST Reject Revocation Request With More Than One CRLReason Extension
    [Documentation]    According to RFC 9483 Section 4.2, a revocation request must not contain more than one
    ...    `CRLReason` extension for a single certificate to be revoked. We send a revocation request
    ...    with multiple `CRLReason` extensions for one certificate. The CA MUST reject the request and
    ...    may respond with the optional failInfo `badRequest`.
    [Tags]    CRLReason    negative
    ${crl_entry_details}=    Prepare CRLReason Extensions    reasons=unspecified,unspecified
    ${rr}=    Build CMP Revoke Request
    ...    crl_entry_details=${crl_entry_details}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

CA MUST Reject Revocation Request With Revoke And Revive CRLReason
    [Documentation]    According to RFC 9483 Section 4.2, a CMP revocation request cannot simultaneously request both
    ...    revocation and revival of a certificate. We send a revocation request containing conflicting
    ...    `CRLReason` values. The CA MUST reject the request and may respond with the optional failInfo
    ...    `badRequest`.
    [Tags]    CRLReason    negative
    ${crl_entry_details}=    Prepare CRLReason Extensions    reasons=unspecified,removeFromCRL
    ${rr}=    Build CMP Revoke Request
    ...    crl_entry_details=${crl_entry_details}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

# TODO clarify failInfo

CA MUST Reject Revocation Request With Missing Issuer
    [Documentation]    According to RFC 9483 Section 4.2, a revocation request must include the `issuer` and
    ...    `serialNumber` fields within the `CertTemplate`. We send a revocation request with a missing
    ...    `issuer` field. The CA MUST reject the request and may respond with the failInfo
    ...    `badCertTemplate` or `addInfoNotAvailable`.
    [Tags]    certTemplate    missing_info    negative
    ${cert_template}=    Prepare CertTemplate    cert=${REVOCATION_CERT}    include_fields=serialNumber
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate,addInfoNotAvailable    exclusive=True

CA MUST Reject Revocation Request With Missing SerialNumber
    [Documentation]    According to RFC 9483 Section 4.2, a revocation request MUST include the `issuer` and
    ...    `serialNumber` fields within the `CertTemplate`. We send a revocation request with a missing
    ...    `serialNumber` field. The CA MUST reject the request and may respond with the optional failInfo
    ...    `badCertTemplate` or `addInfoNotAvailable`.
    [Tags]    certTemplate    missing_info    negative
    ${cert_template}=    Prepare CertTemplate    cert=${REVOCATION_CERT}    include_fields=issuer
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate,addInfoNotAvailable    exclusive=True

CA MUST Reject Revocation Request With Invalid Issuer
    [Documentation]    According to RFC 9483 Section 4.2, the `issuer` field in the `CertTemplate` must match the
    ...    certificate being revoked. If the `issuer` field contains invalid or incorrect information,
    ...    the CA MUST reject the revocation request. The CA may respond with the optional failInfo
    ...    `badCertId`, `badCertTemplate`, or `badRequest`.
    [Tags]    certTemplate    negative
    ${modified_issuer}=    Modify Common Name Cert    ${REVOCATION_CERT}    issuer=True
    ${cert_template}=    Prepare CertTemplate
    ...    issuer=${modified_issuer}
    ...    cert=${REVOCATION_CERT}
    ...    include_fields=serialNumber,issuer
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertId,badCertTemplate,badRequest    exclusive=True

CA MUST Reject Revocation Request With Invalid Subject
    [Documentation]    According to RFC 9483 Section 4.2, when a revocation request is submitted, it MUST contain
    ...    the `issuer` and `serialNumber` fields inside the `CertTemplate`. If the `subject` field is
    ...    provided as additional information, it MUST match the subject of the certificate being revoked.
    ...    We send a revocation request with an invalid sender inside the CertTemplate.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badCertTemplate`.
    [Tags]    add-info    certTemplate    negative
    ${modified_subject}=    Modify Common Name Cert    ${REVOCATION_CERT}    issuer=False
    ${cert_template}=    Prepare CertTemplate
    ...    subject=${modified_subject}
    ...    cert=${REVOCATION_CERT}
    ...    include_fields=serialNumber,issuer,subject
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True

CA MUST Reject Revocation Request With Different PublicKey Inside CertTemplate
    [Documentation]    According to RFC 9483 Section 4.2, when a revocation request is submitted, it MUST contain
    ...    the `issuer` and `serialNumber` fields inside the `CertTemplate`. If the `publicKey` field is
    ...    provided as additional information, it MUST match the public key associated with the certificate
    ...    being revoked. We send a revocation request with an invalid public key inside the CertTemplate.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badCertTemplate`.
    [Tags]    certTemplate    negative
    ${diff_pub_key}=    Generate Different Public Key    cert=${REVOCATION_CERT}    algorithm=${DEFAULT_ALGORITHM}
    ${cert_template}=    Prepare CertTemplate
    ...    publicKey=${diff_pub_key}
    ...    cert=${REVOCATION_CERT}
    ...    include_fields=serialNumber,issuer,publicKey
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True

CA MUST Reject Revocation Request With A Different Version Number Than 2
    [Documentation]    According to RFC 9483 Section 4.2, when a revocation request is submitted, it MUST contain
    ...    the `issuer` and `serialNumber` fields inside the `CertTemplate`. If the `version` field is
    ...    provided as additional information, it MUST match the version number 2.
    ...    We send a revocation request with a version number other than 2 inside the CertTemplate.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badCertTemplate`.
    [Tags]    certTemplate    negative    robot:skip-on-failure    strict
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${cert_template}=    Prepare CertTemplate
    ...    version=0
    ...    cert=${REVOCATION_CERT}
    ...    include_fields=serialNumber,issuer,version
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True

# TODO maybe change to a legit one!

CA MUST Reject Revocation Request With Invalid Extensions
    [Documentation]    According to RFC 9483 Section 4.2, when a revocation request is submitted, it MUST contain
    ...    the `issuer` and `serialNumber` fields inside the `CertTemplate`. If the `extensions` field is
    ...    provided as additional information, it MUST match the extensions of the certificate.
    ...    We send a revocation request with a invalid extensions inside the CertTemplate.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badCertTemplate`.
    [Tags]    certTemplate    negative    robot:skip-on-failure    strict
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${extensions}=    Prepare Extensions    negative=True
    ${cert_template}=    Prepare CertTemplate
    ...    extensions=${extensions}
    ...    include_cert_extensions=False
    ...    cert=${REVOCATION_CERT}
    ...    include_fields=serialNumber,issuer,extensions
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True

CA MUST Reject Revocation Request With Valid And Invalid Extensions
    [Documentation]    According to RFC 9483 Section 4.2, when a revocation request is submitted, it MUST contain
    ...    the `issuer` and `serialNumber` fields inside the `CertTemplate`. If the `extensions` field is
    ...    provided as additional information, it MUST match the extensions of the certificate.
    ...    We send a revocation request with the valid extensions and a invalid extension inside the
    ...    CertTemplate. The CA MUST reject the request and may respond with the optional failInfo
    ...    `badCertTemplate`.
    [Tags]    certTemplate    negative    robot:skip-on-failure    strict
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${extensions}=    Modify Cert Extensions    cert=${REVOCATION_CERT}
    ${cert_template}=    Prepare CertTemplate
    ...    cert=${REVOCATION_CERT}
    ...    extensions=${extensions}
    ...    include_cert_extensions=True
    ...    include_fields=serialNumber,issuer,extensions
    ${rr}=    Build CMP Revoke Request
    ...    cert_template=${cert_template}
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True

CA Should Respond with certRevoked for Already Revoked Cert
    [Documentation]    According to RFC 9483 Section 4.2, an rr message is used to request revocation of a certificate.
    ...    The CA MUST validate that the certificate exists, was issued by the addressed CA, and is not
    ...    expired or already revoked. If the certificate is already revoked, the CA MUST respond with
    ...    an rp message and which may contain the optional failInfo `certRevoked.
    [Tags]    negative
    ${rr}=    Build CMP Revoke Request    cert=${REVOKED_CERT}    sender=${SENDER}    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOKED_CERT}
    ...    private_key=${REVOKED_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=certRevoked    exclusive=True

##### Section 5.3.2. Revoking a Certificate from PKI Entity #####
# The only difference:
#    - The `rr` message MUST be signed using the CMP protection key of the PKI
#    management entity acting on behalf of the EE for this operation.
#
# similar checks omitted

# TODO maybe copy paste checks

CA MUST Accept A Revocation Request From Trusted PKI Management Entity
    [Documentation]    According to RFC 9483 Section 5.3.2, a PKI management entity may revoke a certificate of another
    ...    PKI entity by sending a revocation request signed with its CMP protection key. We send a
    ...    revocation request from a trusted PKI management entity. The CA MUST accept the request and
    ...    revoke the certificate.
    [Tags]    positive    trust
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${rr}=    Build CMP Revoke Request
    ...    certificate=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    certificate=${OTHER_TRUSTED_PKI_CERT}
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}   status=accepted

# MUST be the last test case to run to ensure the Revive request can be run.

CA MUST Accept Valid Revocation Request
    [Documentation]    According to RFC 9483 Section 4.2, the CA MUST accept a revocation request that meets all
    ...    necessary requirements. The request must include a properly protected PKIMessage, the
    ...    `CertTemplate` containing both `issuer` and `serialNumber` fields, and a valid `CRLReason`
    ...    extension if provided. We send a valid revocation request. The CA MUST process the request and
    ...    revoke the specified certificate.
    [Tags]    positive
    ${rr}=    Build CMP Revoke Request
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}   status=accepted
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True
    VAR    ${TEST_REVIVE}    ${True}    scope=Global

#### 4.2 Revocation Revive Requests

CA MUST Reject Revive Request With Invalid Issuer
    [Documentation]    According to RFC 9483 Section 4.2, a revive request must include a CertTemplate
    ...    with correct issuer and serial number fields. We send a revive request with an
    ...    invalid issuer field. The CA MUST reject the request, potentially responding
    ...    with the failInfo `badCertTemplate`.
    [Tags]    negative    revive
    ${modified_issuer}=    Modify Common Name Cert    ${REVOKED_CERT}    issuer=True
    ${cert_template}=    Prepare CertTemplate
    ...    subject=${modified_issuer}
    ...    cert=${REVOKED_CERT}
    ...    include_fields=serialNumber,issuer
    ${rr}=    Build CMP Revive Request
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOKED_CERT}
    ...    private_key=${REVOKED_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True

CA MUST Reject Revive Request With Invalid Subject
    [Documentation]    According to RFC 9483 Section 4.2, when a revive request is submitted, it MUST contain
    ...    the `issuer` and `serialNumber` fields inside the `CertTemplate`. If the `subject` field is
    ...    provided as additional information, it MUST match the subject of the certificate being revived.
    ...    We send a revive request with an invalid sender inside the CertTemplate.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badCertTemplate`.
    [Tags]    add-info    certTemplate    negative    revive

    ${modified_subject}=    Modify Common Name Cert    ${REVOKED_CERT}    issuer=False
    ${cert_template}=    Prepare CertTemplate
    ...    subject=${modified_subject}
    ...    cert=${REVOKED_CERT}
    ...    include_fields=serialNumber,issuer,subject
    ${rr}=    Build CMP Revive Request
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOKED_CERT}
    ...    private_key=${REVOKED_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate    exclusive=True

CA MUST Reject Revive Request With Non-Revoked serialNumber
    [Documentation]    According to RFC 9483 Section 4.2, a revive request is valid only for certificates
    ...    that have been revoked. We send a revive request for a certificate that has not been
    ...    revoked. The CA MUST reject the request and may respond with the optional failInfo
    ...    `badRequest`.
    [Tags]    negative    revive
    ${rr}=    Build CMP Revive Request
    ...    cert=${ISSUED_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${ISSUED_CERT}
    ...    private_key=${ISSUED_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True


CA MUST Accept Valid Revive Request
    [Documentation]    According to RFC 9483 Section 4.2, a revive request must include a CertTemplate
    ...    containing correct issuer and serial number fields, signed with the private key
    ...    corresponding to the certificate being revived. We send a valid revive request with
    ...    all required details. The CA MUST accept the request and successfully revive the
    ...    certificate.
    [Tags]    positive    revive

    ${rr}=    Build CMP Revive Request
    ...    cert=${REVOKED_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOKED_CERT}
    ...    private_key=${REVOKED_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be   ${response}    status=accepted

#### Section 4 RR checks for issuing.

CA MUST Reject Valid IR With Already Revoked Certificate
    [Documentation]    According to RFC 9483, Section 4.1.1, the CA must reject an initialization request (ir) if the
    ...    certificate has already been revoked. We send an ir with a revoked certificate, expecting
    ...    the CA to reject the request. The CA should respond with a `certRevoked` failinfo to indicate
    ...    that the certificate cannot be used for issuance.
    [Tags]    ir    negative
    ${is_set}=    Is Certificate And Key Set    ${REVOKED_CERT}    ${REVOKED_KEY}
    Skip If    not ${is_set}    The `REVOKED_CERT` and/or `REVOKED_KEY` variables are not set.
    ${cert_template}=    Generate CertTemplate For Testing
    ${key}=    Generate Default Key
    ${ir}=    Build IR From Key
    ...    cert_template=${cert_template}
    ...    signing_key=${key}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${REVOKED_KEY}
    ...    cert=${REVOKED_CERT}
    ${response}=    Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be   ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=certRevoked    exclusive=True

CA MUST Reject Valid Key Update Request With Already Revoked Certificate
    [Documentation]    According to RFC 9483, Section 4.1.3, the CA must validate a key update request (kur) and reject
    ...    it if the certificate has been revoked. We send a kur message for a certificate that has
    ...    already been revoked, expecting the CA to reject the request. The CA should respond with a
    ...    `certRevoked` failinfo to indicate that the certificate cannot be updated.
    [Tags]    kur    negative
    ${is_set}=    Is Certificate And Key Set    ${REVOKED_CERT}    ${REVOKED_KEY}
    Skip If    not ${is_set}    The `REVOKED_CERT` and/or `REVOKED_KEY` variables are not set.
    ${new_private_key}=    Generate Default Key
    ${kur}=    Build Key Update Request
    ...    cert=${REVOKED_CERT}
    ...    signing_key=${new_private_key}
    ...    recipient=${RECIPIENT}
    ${kur}=    Protect PKIMessage
    ...    ${kur}
    ...    protection=signature
    ...    private_key=${REVOKED_KEY}
    ...    cert=${REVOKED_CERT}
    ${response}=    Exchange PKIMessage    ${kur}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be   ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=certRevoked    exclusive=True

CA MUST Accept A Revocation Revive From Trusted PKI Management Entity
    [Documentation]    According to RFC 9483 Section 5.3.2, a PKI management entity may request the revival of a
    ...    previously revoked certificate on behalf of another PKI entity by sending a revocation request
    ...    with the `revive` `CRLReason`, signed using its CMP protection key. We send a revive request
    ...    from a trusted PKI management entity. If allowed by policy, the CA MUST accept the request and
    ...    and revive the certificate. If not allowed, the CA MUST reject the request and may respond with
    ...    the optional failinfo `certRevoked`.
    [Tags]    policy-dependent    positive    revive    trust

    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${rr}=    Build CMP Revive Request
    ...    certificate=${REVOKED_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    certificate=${OTHER_TRUSTED_PKI_CERT}
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be   ${response}    status=accepted


*** Keywords ***

Issue New Cert To Test Revocation
    [Documentation]    Issue a new certificate to be used in tests for revocation. It ensures that a valid certificate
    ...    is available for testing.
    [Tags]    setup
    ${ir}=    Generate Default IR Sig Protected
    ${response}=    Exchange PKIMessage    ${ir}
    ${cert}=    Get Cert From PKIMessage    ${response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp    ${response}    recipient=${RECIPIENT}
        ${response}=    Exchange PKIMessage    ${cert_conf}
        PKIMessage Body Type Must Be    ${response}    pkiconf
    END
    # TODO fix if the load default key logic is implemented.
    # could be, should be done in python and access the key by alg name.
    # IF    ${ALLOW_IR_SAME_KEY}
    ${key}=    Get From List    ${burned_keys}    -1
    VAR    ${REVOCATION_CERT}    ${cert}    scope=GlOBAL
    VAR    ${REVOCATION_KEY}    ${key}    scope=GlOBAL

Regenerate Cert For RR Tests
    [Documentation]    Generates a new certificate to test revocation, if revocation tests are allowed.
    [Tags]    setup
    IF    not ${TEST_REVIVE}
        Issue New Cert To Test Revocation
    ELSE
        Get New Cert For Revive Request
    END

Get New Cert For Revive Request
    [Documentation]    Obtain a new certificate to be used in a certificate revive request. It ensures that a valid
    ...    certificate is available for testing revive request scenarios where the certificate has been
    ...    previously revoked.
    [Tags]    revive    setup
    Issue New Cert To Test Revocation
    ${rr}=    Build CMP Revoke Request
    ...    cert=${REVOCATION_CERT}
    ...    recipient=${RECIPIENT}
    ${rr}=    Protect PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    cert=${REVOCATION_CERT}
    ...    private_key=${REVOCATION_KEY}
    ${response}=    Exchange PKIMessage    ${rr}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be   ${response}    status=accepted
    # TODO fix if new key logic is implemented.
    ${key}=    Get From List    ${burned_keys}    -1
    VAR    ${REVOKED_CERT}    ${cert}    scope=GlOBAL
    VAR    ${REVOKED_KEY}    ${key}    scope=GlOBAL
