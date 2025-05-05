# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

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
Library             ../resources/extra_issuing_logic.py
Library             ../resources/certextractutils.py

Suite Setup         Initialize Global Variables


*** Variables ***
${ALLOW_NOT_AUTHORIZED_SENDER}    ${None}
${NOT_AUTHORIZED_SENDER_CERT}    ${None}
${NOT_AUTHORIZED_SENDER_KEY}    ${None}


*** Test Cases ***
CA Must Reject Malformed Request
    [Documentation]    When we send an invalid PKIMessage to the CA, it must respond with a 400 status code to indicate
    ...    a client-side error in the supplied input data. Ref: "3.3. General Form", "All applicable
    ...    "Client Error 4xx" or "Server Error 5xx" status codes MAY be used to inform the client
    ...    about errors."
    [Tags]    negative    rfc6712    robot:skip-on-failure    status    minimal
    ${response}=    Exchange Data With CA    this dummy input is not a valid PKIMessage
    Should Be Equal
    ...    ${response.status_code}
    ...    ${400}
    ...    We expected status code 400, but got ${response.status_code}

CA MUST Reject Requests That Feature Unknown Signature Algorithms
    [Documentation]    According to RFC 9483 Section 3, a PKIMessage protected by an unrecognized or unsupported
    ...    signature algorithm MUST be rejected by the CA. We send a valid p10cr PKIMessage with an unknown
    ...    signature algorithm. The CA MUST reject the request, potentially responding with the failInfo
    ...    `badAlg` for the unsupported algorithm or `systemFailure`.
    [Tags]    crypto    negative    p10cr  minimal
    ${data}=    Get Binary File    data/req-p10cr-prot_none-pop_sig-dilithium.pkimessage
    Log Base64    ${data}
    ${updated_pki_message}=    Patch MessageTime    ${data}
    ${prot_req}=   Default Protect PKIMessage    ${updated_pki_message}
    ${response}=   Exchange PKIMessage    ${prot_req}
    PKIMessage Body Type Must Be  ${response}  error
    PKIStatus Must Be   ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}  failinfo=badAlg,systemFailure   exclusive=True

CA Must Issue A Certificate When We Send A Valid P10cr Request
    [Documentation]    According to RFC 9483 Section 4.1.4, when a valid CSR is sent inside a p10cr PKIMessage, the CA
    ...    MUST respond with a valid certificate. We send a correctly formatted p10cr request and
    ...    verify that the CA issues a valid certificate in response.
    [Tags]    csr    p10cr    positive   minimal
    ${der_pkimessage}=    Load And Decode Pem File    data/example-rufus-01-p10cr.pem
    ${request_pki_message}=    Parse PKIMessage    ${der_pkimessage}
    ${p10cr}=    Build P10cr From CSR     ${request_pki_message["body"]["p10cr"]}
    ...          sender=${SENDER}    recipient=${RECIPIENT}  for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    ${protected_p10cr}=    Protect PKIMessage
    ...    ${p10cr}
    ...    password_based_mac
    ...    password=${PRESHARED_SECRET}
    ...    iterations=1945
    ...    salt=111111111122222222223333333333
    ...    hash_alg=sha256
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
    Validate Sender And Recipient Nonce    ${response}    ${protected_p10cr}
    ${cert}=    Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA Must Reject Request When The CSR Signature Is Invalid
    [Documentation]    According to RFC 9483 Section 4.1.4, the signature inside the CSR serves as proof-of-possession
    ...    to demonstrate that the End-Entity owns the private key. We send a CSR with a invalid signature.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badPOP`.
    [Tags]    crypto    csr    negative
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${csr}=    Build CSR    common_name=${cm}    signing_key=${key}    bad_pop=True
    ${p10cr}=    Build P10cr From Csr
    ...    ${csr}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${protected_p10cr}=    Default Protect PKIMessage    ${p10cr}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP    exclusive=True

CA Must Reject Request When The CSR Is Sent Again
    [Documentation]    According to RFC 9483 Section 3 and 5, the policy of the CA may define whether it allows a
    ...    duplicate CSR with the same details. We send a previously issued CSR. The CA may reject or
    ...    accept the request. If rejected, the CA may respond with the optional failInfo
    ...    `duplicateCertReq`.
    [Tags]    csr    negative    robot:skip-on-failure
    ${csr}   ${_}=    Generate CSR For Testing
    ${p10cr}=   Build P10cr From CSR    ${csr}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         implicit_confirm=${True}    for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    ${protected_p10cr}=    Protect PKIMessage
    ...    pki_message=${p10cr}
    ...    protection=password_based_mac
    ...    password=${PRESHARED_SECRET}
    ...    iterations=1945
    ...    salt=111111111122222222223333333333
    ...    hash_alg=sha256
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
    Sender And Recipient Nonces Must Match    ${protected_p10cr}    ${response}
    SenderNonce Must Be At Least 128 Bits Long    ${response}
    ${p10cr_2}=   Build P10cr From CSR    ${csr}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         implicit_confirm=${True}    for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    ${protected_p10cr}=   Default Protect With MAC    ${p10cr_2}
    ${response2}=    Exchange PKIMessage    ${protected_p10cr}
    PKIStatus Must Be    ${response2}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response2}    failinfo=duplicateCertReq    exclusive=True

##### Basic Certification Request

#### Basic MAC Protected Tests

CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected CR
    [Documentation]    According to RFC 9483 Section 4.1.2, when a valid Certification Request is received with
    ...    MAC-based protection, the CA MUST process the request and respond with a valid Certification
    ...    Response, issuing a valid certificate. If implicit confirmation is enabled, the PKIMessage MUST
    ...    contain the `implicitConfirm` extension. Otherwise, the `implicitConfirm` extension MUST NOT be
    ...    present in the `generalInfo` field.
    [Tags]    cr    implicit_confirm    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTION}    Skipped test because MAC protection is disabled.
    Skip If    not ${ALLOW_CR_MAC_BASED}    Skipped test because cr MAC protected is disabled.
    ${csr}    ${key}=    Generate CSR For Testing
    ${p10cr}=    Build Cr From CSR
    ...    ${csr}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ...    for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    ${protected_p10cr}=    Protect PKIMessage
    ...    ${p10cr}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    cp
    IF    ${ALLOW_IMPLICIT_CONFIRM}
        PKIMessage Must Contain ImplicitConfirm Extension    ${response}
        ${cert}=    Get Cert From PKIMessage    ${response}
        Certificate Must Be Valid    ${cert}
    ELSE
        ${result}=    Find OID In GeneralInfo    ${pki_message}    1.3.6.1.5.5.7.4.13
        Should Be True    not ${result}
    END

CA MUST Reject An Valid MAC Protected Key Update Request
    [Documentation]    According to RFC 9483 Section 4.1.3, a Key Update Request must be signature-protected for the CA
    ...    to process it. We send a valid Key Update Request that is MAC-protected. The CA MUST
    ...    reject the request to ensure integrity and compliance with the PKI policies, potentially
    ...    responding with the failInfo `wrongIntegrity`.
    [Tags]    kur    mac    negative   minimal
    ${cert}   ${_}=    Issue New Cert For Testing
    ${new_private_key}=    Generate Default Key
    ${kur}=    Build Key Update Request
    ...    ${new_private_key}
    ...    cert=${cert}
    ...    sender=${SENDER}
    ...    exclude_fields=${None}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${False}
    ...    for_mac=True
    ${protected_kur}=    Default Protect With MAC    ${kur}
    ${response}=    Exchange PKIMessage    ${protected_kur}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=wrongIntegrity

CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected P10CR
    [Documentation]    According to RFC 9483 Section 4.1.4, when a valid `Certification Request` is received with
    ...    MAC-based protection, the CA MUST process the request and respond with a valid
    ...    `Certification Response`, issuing a valid certificate. If implicit confirmation is enabled,
    ...    the PKIMessage MUST contain the `implicitConfirm` extension. Otherwise, it SHOULD NOT
    ...    be present in the `generalInfo` field.
    [Tags]    implicit_confirm    mac    p10cr    positive
    Skip If    not ${ALLOW_MAC_PROTECTION}    Skipped test because MAC based protection is disabled.
    Skip If    not ${ALLOW_P10CR_MAC_BASED}    Skipped test because P10cr MAC based protection is disabled.
    ${csr}    ${_}=    Generate CSR For Testing
    ${p10cr}=    Build P10cr From Csr
    ...    ${csr}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ...    for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    ${protected_p10cr}=    Default Protect With MAC    ${p10cr}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    cp
    IF    ${ALLOW_IMPLICIT_CONFIRM}
        PKIMessage Must Contain ImplicitConfirm Extension    ${response}
    ELSE
        ${result}=    Find OID In GeneralInfo    ${response}    1.3.6.1.5.5.7.4.13
        Should Be True    not ${result}
    END
    ${cert}=    Get Cert From PKIMessage    ${response}
    ${der_cert}=    Encode To Der    ${cert}
    Certificate Must Be Valid    ${der_cert}
    Validate Ca Message Body    ${response}    used_p10cr=True

#### Body Checks

# TODO add test case for device key and cert.

CA MUST Send A Valid IP After Receiving valid IR
    [Documentation]    According to RFC 9483 Section 4.1.1, when a valid Initialization Request is received, the CA MUST
    ...    process the request and respond with a valid Initialization Response. The response MUST
    ...    contain the issued certificate if the request meets all requirements.
    [Tags]    ip    ir    PKIBody    positive  minimal
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${key}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    cert_template=${cert_template}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Ca Message Body    ${response}    used_ir_as_cr=True

CA MUST Send A Valid CP After Receiving valid CR
    [Documentation]    According to RFC 9483 Section 4, when a valid Certification Request is received, the CA MUST
    ...    process the request and respond with a valid Certification Response. The response MUST
    ...    contain the issued certificate if the request meets all requirements.
    [Tags]    cp    cr    PKIBody    positive   minimal
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${cr}=    Build Cr From Key
    ...    signing_key=${key}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    cert_template=${cert_template}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_cr}=    Default Protect PKIMessage    ${cr}
    ${response}=    Exchange PKIMessage    ${protected_cr}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    cp
    Validate Ca Message Body    ${response}

CA MUST Send A Valid KUP After Receiving valid KUR
    [Documentation]    According to RFC 9483 Section 4.1.3, when a valid Key Update Request is received, the CA MUST
    ...    process the request and respond with a valid Key Update Response. The response MUST
    ...    include the updated certificate if the request meets all requirements.
    [Tags]    kup    kur    PKIBody    positive    setup   minimal
    ${cert}   ${kur_key}=   Issue New Cert For Testing
    ${key}=    Generate Default Key
    ${kur}=    Build Key Update Request
    ...    ${key}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    cert=${cert}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_kur}=    Protect PKIMessage    ${kur}   signature   private_key=${kur_key}   cert=${cert}
    ${response}=    Exchange PKIMessage    ${protected_kur}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    kup
    ${cert}=   Confirm Certificate If Needed   ${response}   protection=signature   url=${CA_CMP_URL}
    Validate Ca Message Body    ${response}
    VAR    ${UPDATED_CERT}    ${cert}    scope=Global
    VAR    ${UPDATED_KEY}    ${kur_key}    scope=Global
    Wait Until Server Updated Cert

CA MUST Send A Valid CP After Receiving valid P10CR
    [Documentation]    According to RFC 9483 Section 4, when a valid PKCS#10 Certification Request (P10CR) is received,
    ...    the CA MUST process the request and respond with a valid Certification Response. The response
    ...    MUST contain the issued certificate if the request meets all requirements.
    [Tags]    cp    lwcmp    p10cr    PKIBody    positive  minimal
    ${csr}    ${_}=    Generate CSR For Testing
    ${p10cr}=   Build P10cr From Csr    ${csr}    sender=${SENDER}    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${True}
    ${protected_p10cr}=    Default Protect PKIMessage    ${p10cr}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    cp
    Validate Ca Message Body    ${response}    used_p10cr=True

#### Basic Signature Protected Tests
# TODO change to single check.

CA MUST Issue A Valid Certificate Upon Receiving A Valid IR SIG-Protected
    [Documentation]    According to RFC 9483 Section 4.1.1, when a valid Initialization Request is received with
    ...    signature-based protection, the CA MUST process the request and issue a valid certificate.
    ...    If implicit confirmation is enabled, the PKIMessage MUST include the `implicitConfirm`
    ...    extension. If implicit confirmation is disabled, a certificate confirmation message MUST
    ...    be sent to complete the exchange, and the CA MUST respond with a valid PKI confirmation message.
    [Tags]    ir    positive    signature   minimal
    ${key}=    Generate Default Key
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${key}
    ...    common_name=${DEFAULT_X509NAME}
    ...    exclude_fields=sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate CA Message Body    ${response}    used_p10cr=False
    Certificate Must Be Valid    ${cert}

CA MUST Issue A Valid Certificate Upon Receiving A Valid CR SIG-Protected
    [Documentation]    According to RFC 9483 Section 4.1.2, when a valid Certification Request is received with
    ...    signature-based protection, the CA MUST process the request and issue a valid certificate.
    ...    If implicit confirmation is enabled, the PKIMessage MUST include the `implicitConfirm`
    ...    extension. If implicit confirmation is disabled, a certificate confirmation message MUST
    ...    be sent to complete the exchange, and the CA MUST respond with a valid PKI confirmation message.
    [Tags]    cr    positive    signature  minimal
    ${key}=    Generate Default Key
    ${pki_message}=    Build Cr From Key
    ...    signing_key=${key}
    ...    common_name=${DEFAULT_X509NAME}
    ...    exclude_fields=sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_cr}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cr}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    cp
    IF    ${ALLOW_IMPLICIT_CONFIRM}
        PKIMessage Must Contain ImplicitConfirm Extension    ${response}
        ${cert}=    Get Cert From PKIMessage    ${response}
        Certificate Must Be Valid    ${cert}
    ELSE
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERT}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        Signature Protection Must Match    response=${response}    pki_conf=${pki_conf}
    END

CA MUST Issue A Valid Certificate Upon Receiving A Valid KUR
    [Documentation]    According to RFC 9483 Section 4.1.3, when a valid Key Update Request is received with
    ...    signature-based protection, the CA MUST process the request and issue a new certificate.
    ...    If implicit confirmation is enabled, the PKIMessage MUST include the `implicitConfirm`
    ...    extension. If implicit confirmation is disabled, a certificate confirmation message MUST
    ...    be sent to complete the exchange, and the CA MUST respond with a valid PKI confirmation message.
    [Tags]    kur    positive   minimal
    ${cert}  ${kur_key}=   Issue New Cert For Testing
    ${new_key}=    Generate Default Key
    ${pki_message}=    Build Key Update Request
    ...    ${new_key}
    ...    cert=${cert}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_kur}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${kur_key}
    ...    cert=${cert}
    ${response}=    Exchange PKIMessage    ${protected_kur}
    PKIStatus Must Be    ${response}    accepted
    PKIMessage Body Type Must Be    ${response}    kup
    IF    ${ALLOW_IMPLICIT_CONFIRM}
        PKIMessage Must Contain ImplicitConfirm Extension    ${response}
    ELSE
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${kur_key}
        ...    cert=${cert}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        Signature Protection Must Match    response=${response}    pki_conf=${pki_conf}
    END
    VAR    ${UPDATED_CERT}    ${cert}    scope=GLOBAL
    VAR    ${UPDATED_KEY}    ${kur_key}    scope=GLOBAL
    Wait Until Server Updated Cert
    # positioned here so if the Response is incorrect, the certificate is still updated, so that it
    # can be used for other test cases.
    Validate CA Message Body    ${response}    used_p10cr=False

CA MUST Reject Valid Key Update Request With Already Updated Certificate
    [Documentation]    According to RFC 9483 Section 4.1.3, when a Key Update Request references a certificate that has
    ...    already been updated, the CA MUST reject the request to maintain PKI integrity and avoid
    ...    duplicate updates. The CA may respond with the optional failInfo `certRevoked`.
    [Tags]    kur    negative
    ${is_set}=    Is Certificate And Key Set    ${UPDATED_CERT}    ${UPDATED_KEY}
    Skip If    not ${is_set}    Skipped test because `UPDATED_CERT` and `UPDATED_KEY` are not set.
    ${new_private_key}=    Generate Default Key
    ${pki_message}=    Build Key Update Request
    ...    ${new_private_key}
    ...    cert=${UPDATED_CERT}
    ...    private_key=${new_private_key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=True
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${UPDATED_KEY}
    ...    cert=${UPDATED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatusInfo Failinfo Bit Must Be    ${response}    certRevoked    exclusive=True

CA MUST Issue A Valid Certificate Upon Receiving A Valid P10cr SIG-Protected
    [Documentation]    According to RFC 9483 Section 4.1.4, when a valid Certificate Request is received with
    ...    signature-based protection, the CA MUST process the request and issue a valid certificate.
    ...    If implicit confirmation is enabled, the PKIMessage MUST include the `implicitConfirm`
    ...    extension. If implicit confirmation is disabled, a certificate confirmation message MUST
    ...    be sent to complete the exchange, and the CA MUST respond with a valid PKI confirmation message.
    [Tags]    p10cr    positive    signature   minimal
    ${csr}    ${_}=    Generate CSR For Testing
    ${p10cr}=    Build P10cr From Csr
    ...    ${csr}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_p10cr}=    Default Protect PKIMessage    ${p10cr}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=  Confirm Certificate If Needed    ${response}   url=${CA_CMP_URL}  cert_req_id=0
    Validate CA Message Body    ${response}    used_p10cr=True
    Certificate Must Be Valid    ${cert}

#### Basic `CertTemplate` tests (extensions, validity)

# Does not include the 'ir' tag because body-independent checks are performed.
# However, as per Section 7.1, 'ir' MUST be implemented, so 'ir' is chosen as the body type.

#### BasicConstraints

CA MUST React To A Valid Cert Request With The BasicConstraints Extension
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the BasicConstraints extension
    ...    with `ca` set to True. If issuing CA certificates is allowed, the CA SHOULD issue the requested
    ...    certificate. Otherwise, the CA MUST reject the request to maintain PKI integrity.
    [Tags]    basic-constraints    config-dependent    extension  minimal
    ${new_key}=    Generate Default Key
    ${extensions}=    Prepare Extensions    key_usage=digitalSignature,keyCertSign    is_ca=True
    ${ir}=    Build Ir From Key
    ...    ${new_key}
    ...    common_name=${DEFAULT_X509_NAME}
    ...    extensions=${extensions}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    IF    not ${ALLOW_ISSUING_OF_CA_CERTS}
        PKIStatus Must Be    ${ca_response}    rejection
        PKIMessage Body Type Must Be    ${ca_response}   ip
        PKIStatusInfo Failinfo Bit Must Be    ${ca_response}    failinfo=notAuthorized
    ELSE
        PKIStatus Must Be    ${ca_response}    accepted
        PKIMessage Body Type Must Be   ${ca_response}  ip
        ${cert}=    Get Cert From PKIMessage    ${ca_response}
        IF    not ${ALLOW_IMPLICIT_CONFIRM}
            ${cert_conf}=    Build Cert Conf From Resp
            ...    ${ca_response}
            ...    exclude_fields=sender,senderKID
            ...    recipient=${RECIPIENT}
            ${protected_cert_conf}=    Protect PKIMessage
            ...    ${cert_conf}
            ...    protection=signature
            ...    private_key=${ISSUED_KEY}
            ...    cert=${ISSUED_CERT}
            ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
            PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        END
        VAR    ${CA_KEY}    ${new_key}    scope=GLOBAL
        VAR    ${CA_CERT}    ${cert}    scope=GLOBAL
    END

# TODO maybe strict

CA MUST React To A Valid Cert Request With Invalid Path-length In BasicConstraints Extension
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the BasicConstraints extension
    ...    with `ca` set to False and a specified `path_length` value. The CA MUST reject the request
    ...    to enforce certificate template constraints, as `path_length` is invalid when `ca` is False.
    [Tags]    basic-constraints    extension   minimal
    VAR    ${common_name}    CN=Hans Mustermann CA 2
    ${new_key}=    Generate Default Key
    ${extensions}=    Prepare Extensions    path_length=5    is_ca=False
    ${ir}=    Build Ir From Key
    ...    signing_key=${new_key}
    ...    common_name=${common_name}
    ...    extensions=${extensions}
    ...    implicit_confirm=True
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${ca_response}    rejection
    PKIStatusInfo Failinfo Bit Must Be  ${ca_response}    failinfo=badCertTemplate

# TODO maybe not strict

CA MAY React To Cert Request With Invalid Is_ca In BasicConstraints False But KeyUsage keyCertSign
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the BasicConstraints extension
    ...    with `ca` set to False and the KeyUsage `keyCertSign`. The CA SHOULD reject the request
    ...    to enforce certificate template constraints. If the policy allows, the CA MAY process
    ...    the request with modifications.
    [Tags]    basic-constraints    extension    strict
    VAR    ${common_name}    CN=Hans Mustermann CA 3
    ${new_key}=    Generate Default Key
    ${extensions}=    Prepare Extensions    is_ca=False    key_usage=keyCertSign,digitalSignature
    ${ir}=    Build Ir From Key    signing_key=${new_key}    common_name=${common_name}    extensions=${extensions}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    ${body}=    Get CMP Message Type    ${ca_response}
    IF    '${body} == error'
           PKIStatusInfo Failinfo Bit Must Be    ${ca_response}     failinfo=badCertTemplate
    ELSE
        ${status}=    Get PKIStatusInfo     ${ca_response}
        IF    '${status["status"]}' != rejection
            Check For GrantedWithMods    ${ca_response}    ${ir}    strict_subject_validation=False
            IF    ${STRICT}    Fail    Expected to reject this request.
        END
    END

#### KeyUsages

# Needed for KGA, IF allowed.
# Needed for 4.1.6.2. Using the Key Agreement Key Management Technique.

# TODO add negative certs: rsa with KeyAgreement and ecc with KeyEncipherment

# To also be allowed to sign the PKIMessage, because, it is advised to use the
# Appropriate method for KGA. So MAC based would imply to then also use
# The Password-Based Key Management Technique. The The inverse is true.

CA MUST Issue A Certificate With The KeyAgreement KeyUsage Extension
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the `keyAgreement` and
    ...    `digitalSignature` KeyUsage extensions. The CA MUST issue a certificate containing both
    ...    specified extensions.
    [Tags]    extension    key-usage    kga    setup   minimal
    ${new_key}=    Generate Key    algorithm=ecc    curve=${DEFAULT_ECC_CURVE}
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement,digitalSignature
    ${ir}=    Build Ir From Key
    ...    ${new_key}
    ...    common_name=${DEFAULT_X509NAME}
    ...    extensions=${extensions}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be   ${ca_response}    status=accepted
    ${cert}=    Get Cert From PKIMessage    ${ca_response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${ca_response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${pki_message}=    Protect PKIMessage
        ...    ${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERT}
        ${pki_conf}=    Exchange PKIMessage    ${pki_message}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    Validate KeyUsage   ${cert}    keyAgreement,digitalSignature    strictness=STRICT
    VAR    ${KGA_KARI_KEY}    ${new_key}    scope=Global
    VAR    ${KGA_KARI_CERT}    ${cert}    scope=Global

CA MUST Issue ECDSA Cert With KeyUsage
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the `keyAgreement` and
    ...    `digitalSignature` KeyUsage extensions. The CA MUST issue a certificate containing both
    ...    specified extensions.
    ${new_key}=    Generate Key    algorithm=ecc    curve=${DEFAULT_ECC_CURVE}
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement,digitalSignature
    ${cm}=  Get Next Common Name
    ${ir}=    Build Ir From Key
    ...    ${new_key}
    ...    common_name=${cm}
    ...    extensions=${extensions}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be   ${ca_response}    status=accepted
    ${cert}=  Confirm Certificate If Needed    ${ca_response}   request=${protected_ir}   url=${CA_CMP_URL}
    Validate KeyUsage   ${cert}    keyAgreement,digitalSignature    strictness=STRICT
    VAR    ${CLIENT_ECC_KEY}    ${new_key}    scope=Global
    VAR    ${CLIENT_ECC_CERT}    ${cert}    scope=Global

# Needed for 4.1.6.1. Using the Key Transport Key Management Technique

CA MUST Issue A Certificate With The KeyEncipherment KeyUsage Extension
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the `keyEncipherment` and
    ...    `digitalSignature` KeyUsage extensions. The CA MUST issue a certificate containing both
    ...    specified extensions.
    [Tags]    extension    key-usage    kga    setup  minimal
    ${cm}=    Get Next Common Name
    ${new_key}=    Generate Key    algorithm=rsa    length=${DEFAULT_KEY_LENGTH}
    ${extensions}=    Prepare Extensions    key_usage=keyEncipherment, digitalSignature
    ${ir}=    Build Ir From Key
    ...    signing_key=${new_key}
    ...    common_name=${cm}
    ...    extensions=${extensions}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be   ${ca_response}    status=accepted
    ${cert}=    Get Cert From PKIMessage    ${ca_response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${ca_response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${pki_message}=    Protect PKIMessage
        ...    ${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERT}
        ${pki_conf}=    Exchange PKIMessage    ${pki_message}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    Validate KeyUsage    ${cert}    keyEncipherment,digitalSignature    strictness=STRICT
    VAR    ${KGA_KTRI_KEY}    ${new_key}    scope=Global
    VAR    ${KGA_KTRI_CERT}    ${cert}    scope=Global

#### EKU

CA MAY Issue A Certificate With The Extended KeyUsage cmcRA
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the `cmcRA` ExtendedKeyUsage
    ...    extension. If the CA policy allows this extension, the CA MAY issue a certificate containing
    ...    the specified extension. Otherwise, the request is rejected, and the response may include the
    ...    optional failInfo `notAuthorized`.
    [Tags]    extended-key-usage    extension    policy-dependent    robot:skip-on-failure    setup   minimal
    ${new_key}=    Generate Key    algorithm=rsa    length=${DEFAULT_KEY_LENGTH}
    ${extensions}=    Prepare Extensions    eku=cmcRA
    ${ir}=    Build Ir From Key
    ...    signing_key=${new_key}
    ...    common_name=${DEFAULT_X509NAME}
    ...    extensions=${extensions}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    IF    not ${ALLOW_CMP_EKU_EXTENSION}
        PKIStatusInfo Failinfo Bit Must Be    ${ca_response}     failinfo=notAuthorized
    ELSE
        PKIStatus Must Be   ${ca_response}    status=accepted
        ${cert}=    Get Cert From PKIMessage    ${ca_response}
        IF    not ${ALLOW_IMPLICIT_CONFIRM}
            ${cert_conf}=    Build Cert Conf From Resp
            ...    ${ca_response}
            ...    exclude_fields=sender,senderKID
            ...    recipient=${RECIPIENT}
            ${pki_message}=    Protect PKIMessage
            ...    ${cert_conf}
            ...    protection=signature
            ...    private_key=${ISSUED_KEY}
            ...    cert=${ISSUED_CERT}
            ${pki_conf}=    Exchange PKIMessage    ${pki_message}
            PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        END
        Validate CMP ExtendedKeyUsage    ${cert}    cmcRA    STRICT
        VAR    ${CMC_RA_KEY}    ${new_key}    scope=Global
        VAR    ${CMC_RA_CERT}    ${cert}    scope=Global
    END

CA MAY Issue A Certificate With The Extended KeyUsage cmcCA
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the `cmcCA` ExtendedKeyUsage
    ...    extension. If the CA policy allows this extension, the CA MAY issue a certificate containing
    ...    the specified extension. Otherwise, the request is rejected, and the response may include the
    ...    optional failInfo `notAuthorized`.
    [Tags]    extended-key-usage    extension    policy-dependent    robot:skip-on-failure    setup   minimal
    ${new_key}=    Generate Key    algorithm=rsa    length=${DEFAULT_KEY_LENGTH}
    ${extensions}=    Prepare Extensions    eku=cmcCA
    ${ir}=    Build Ir From Key
    ...    signing_key=${new_key}
    ...    common_name=${DEFAULT_X509NAME}
    ...    extensions=${extensions}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    IF    not ${ALLOW_CMP_EKU_EXTENSION}
        PKIStatusInfo Failinfo Bit Must Be    ${ca_response}     failinfo=notAuthorized
    ELSE
        PKIStatus Must Be   ${ca_response}    status=accepted
        ${cert}=    Get Cert From PKIMessage    ${ca_response}
        IF    not ${ALLOW_IMPLICIT_CONFIRM}
            ${cert_conf}=    Build Cert Conf From Resp
            ...    ${ca_response}
            ...    exclude_fields=sender,senderKID
            ...    recipient=${RECIPIENT}
            ${pki_message}=    Protect PKIMessage
            ...    ${cert_conf}
            ...    protection=signature
            ...    private_key=${ISSUED_KEY}
            ...    cert=${ISSUED_CERT}
            ${pki_conf}=    Exchange PKIMessage    ${pki_message}
            PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        END
        Validate CMP ExtendedKeyUsage    ${cert}    cmcCA    STRICT
        VAR    ${CMC_CA_KEY}    ${new_key}    scope=Global
        VAR    ${CMC_CA_CERT}    ${cert}    scope=Global
    END

CA MAY Issue A Certificate With The Extended KeyUsage cmKGA
    [Documentation]    According to RFC 9483 Section 5, the CA responds to a certificate request based on its own
    ...    policy. We send a valid Initialization Request containing the `cmKGA` ExtendedKeyUsage
    ...    extension. If the CA policy allows this extension, the CA MAY issue a certificate containing
    ...    the specified extension. Otherwise, the request is rejected, and the response may include the
    ...    optional failInfo `notAuthorized`.
    [Tags]    extended-key-usage    extension    policy-dependent    robot:skip-on-failure
    ${new_key}=    Generate Key    algorithm=rsa    length=${DEFAULT_KEY_LENGTH}
    ${extensions}=    Prepare Extensions    eku=cmKGA
    ${ir}=    Build Ir From Key
    ...    signing_key=${new_key}
    ...    common_name=${DEFAULT_X509NAME}
    ...    extensions=${extensions}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    IF    ${ALLOW_IMPLICIT_CONFIRM}
        ${ir}=    Patch GeneralInfo    ${ir}    implicit_confirm=True
    END
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${ca_response}=    Exchange PKIMessage    ${protected_ir}
    IF    not ${ALLOW_CMP_EKU_EXTENSION}
        PKIStatusInfo Failinfo Bit Must Be    ${ca_response}     failinfo=notAuthorized
    ELSE
        PKIStatus Must Be   ${ca_response}    status=accepted
        ${cert}=    Get Cert From PKIMessage    ${ca_response}
        IF    not ${ALLOW_IMPLICIT_CONFIRM}
            ${cert_conf}=    Build Cert Conf From Resp
            ...    ${ca_response}
            ...    exclude_fields=sender,senderKID
            ...    recipient=${RECIPIENT}
            ${pki_message}=    Protect PKIMessage
            ...    ${cert_conf}
            ...    protection=signature
            ...    private_key=${ISSUED_KEY}
            ...    cert=${ISSUED_CERT}
            ${pki_conf}=    Exchange PKIMessage    ${pki_message}
            PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        END
        # must be present and contain the expected extension.
        Validate CMP ExtendedKeyUsage    ${cert}    cmKGA    STRICT
        VAR    ${CMC_RA_KEY}    ${new_key}    scope=Global
        VAR    ${CMC_RA_CERT}    ${cert}    scope=Global
    END

CA MIGHT Reject initialization requests With An Invalid Extension
    [Documentation]    According to RFC 9483 Section 5, based on the PKI Policy of the issuing CA, the CA might handle
    ...    Initialization Requests with invalid extensions differently depending on its policy. We send
    ...    an Initialization Request with an invalid extension. If strict validation is enabled, the CA
    ...    should reject the request and respond with the optional failInfo `badCertTemplate`. If the
    ...    policy allows relaxed validation, the CA may accept the request and respond with
    ...    `grantedWithMods`.
    [Tags]    certTemplate    extension    ir    policy-dependent
    ${extensions}=    Prepare Extensions    invalid_extension=True
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${pki_message}=    Build Ir From Key
    ...    ${key}
    ...    common_name=${cm}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    extensions=${extensions}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    IF    ${STRICT}
        PKIStatus Must Be    ${response}    rejection
        PKIMessage Body Type Must Be    ${response}    ip
        PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate
    ELSE
        PKIStatus Must Be    ${response}    grantedWithMods
    END

#### Basic CertTemplate

# TODO add bad validity
# check generalTime only UTCTime allowed for certificates.
# bad time already behind
# set switch not before and after locally.

CA MIGHT Allow A Validity Request with Valid IR
    [Documentation]    According to RFC 9483 Section 5, based on the PKI Policy of the issuing CA, the CA might allow a
    ...    user-defined validity period or provide a default validity. We send an Initialization Request
    ...    with a user-defined validity period. The CA may respond with `accepted` if the validity period
    ...    is allowed as-is or with `grantedWithMods` if the validity period is adjusted to comply with the
    ...    policy.
    [Tags]    certTemplate    policy-dependent    positive    validity
    ${key}=    Generate Default Key
    ${not_before}=    Get Current Date
    ${cm}=    Get Next Common Name
    ${not_after}=    Add Time To Date    ${not_before}    1000 days
    ${validity}=    Prepare Validity    not_before=${not_before}    not_after=${not_after}
    ${cert_template}=    Prepare CertTemplate    validity=${validity}    key=${key}   subject=${cm}
    Generate Default IR Sig Protected
    ${ir}=    Build Ir From Key    ${key}    common_name=${cm}    cert_template=${cert_template}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    accepted
    Check For GrantedWithMods    ${response}    ${protected_ir}    include_fields=validity

CA MIGHT Allow A Validity Request For 180 Days with Valid IR
    [Documentation]    According to RFC 9483 Section 5, based on the PKI Policy of the issuing CA, the CA might allow a
    ...    user-defined validity period or provide a default validity. We send an Initialization Request
    ...    with a user-defined validity period of 180 days. The CA may respond with `accepted` if the
    ...    validity period is allowed as-is or with `grantedWithMods` if the validity period is adjusted
    ...    to comply with the policy.
    [Tags]    certTemplate    policy-dependent    positive    validity
    ${key}=    Generate Default Key
    ${not_before}=    Get Current Date
    ${cm}=    Get Next Common Name
    ${not_after}=    Add Time To Date    ${not_before}    180 days
    ${validity}=    Prepare Validity    not_before=${not_before}    not_after=${not_after}
    ${cert_template}=    Prepare CertTemplate    validity=${validity}    key=${key}    subject=${cm}
    ${ir}=    Build Ir From Key    ${key}    common_name=${cm}    cert_template=${cert_template}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    accepted
    Check For GrantedWithMods    ${response}    ${protected_ir}    include_fields=validity

CA or RA MUST Reject Not Authorized Sender
    [Documentation]     According to RFC 9483 Section 3.5, the CA or RA must reject a PKIMessage if the sender is not
    ...    authorized to send the message. We send a PKIMessage with a sender that is not authorized to
    ...    send a message. The CA or RA MUST reject the request, and the response may include the failinfo
    ...    `notAuthorized`.
    [Tags]    negative    rfc9483-header    sender   notAuthorized
    Skip If    not ${ALLOW_NOT_AUTHORIZED_SENDER}    This test is skipped because not authorized sender is not allowed.
    ${cert_template}    ${key}=   Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key    ${key}    cert_template=${cert_template}   sender=${SENDER}    recipient=${RECIPIENT}
    # Can only be done if the check is done after the subject field of the certificate is checked.
    # Otherwise, the test will have to be done with a matching certificate or MAC protected.
    IF   '${NOT_AUTHORIZED_SENDER_CERT}' == '${None}'
        ${protected_ir}=   Default Protect PKIMessage  ${ir}  protection=mac
    ELSE
        ${protected_ir}=   Protect PKIMessage  ${ir}   protection=signature
        ...                private_key=${NOT_AUTHORIZED_SENDER_KEY}
        ...                cert=${NOT_AUTHORIZED_SENDER_CERT}
    END
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    notAuthorized    True

CA MUST Accept Cert with NULL-DN and SAN
    [Documentation]     According to RFC 9483 Section 4.1.1, the CA must accept a certificate request with a NULL-DN as
    ...    the subject and a SubjectAltName extension. We send a certificate request with a NULL-DN and a
    ...    SubjectAltName extension. The CA MUST accept the request and issue a certificate.
    [Tags]   positive    subject    null-dn    san
    ${key}=   Generate Default Key
    ${extn}=    Prepare Extensions    key=${key}    SubjectAltName=example.com
    ${ir}=    Build Ir From Key    ${key}    common_name=Null-DN   recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID   extensions=${extn}
    ${protected_ir}=   Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted

CA MUST Reject Cert with NULL-DN and not SAN set
    [Documentation]     According to RFC 9483 Section 4.1.1, the CA must reject a certificate request without
    ...    a NULL-DN as the subject and a SubjectAltName extension which contains a directoryName choice inside
    ...    a GeneralName. We send a certificate request with a subject that is not NULL-DN and a SubjectAltName
    ...    extension that contains a directoryName choice inside a GeneralName. The CA MUST reject the request.
    ...   The response may include the failinfo `badCertTemplate`.
    [Tags]    negative    subject    null-dn
    ${key}=   Generate Default Key
    ${ir}=    Build Ir From Key    ${key}    common_name=Null-DN   recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${protected_ir}=   Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be     ${response}    badCertTemplate    True


*** Keywords ***
Initialize Cert Setup
    [Documentation]    Initializes the certificate used for testing, based on the value of the ALLOW_MAC_PROTECTION
    ...     variable. It performs certificate and key validation, generates a certificate template and issued a new
    ...     certificate `(ISSUED_CERT)` and `(ISSUED_KEY)` to be able to start the test for the test suite.
    [Tags]    setup
    IF    not ${ALLOW_MAC_PROTECTION}
        VAR    ${protection}    sig
        ${tmp_cert}    ${tmp_key}=    May Load Cert And Key
        ...    cert_path=${INITIAL_CERT_PATH}
        ...    key_path=${INITIAL_KEY_PATH}
        ...    key_password=${INITIAL_KEY_PASSWORD}
        ${result}=    Is Certificate And Key Set    ${tmp_cert}    ${tmp_key}
        IF    not ${result}
            Fail    if MAC-based protection is disabled. An initial certificate and matching private key needs
            ...    to be provided.
        END
        ${cert_template}    ${key}=    Generate CertTemplate For Testing
        VAR    ${INIT_KEY}    ${tmp_key}
        VAR    ${INIT_CERT}    ${tmp_cert}
        ${ir}=    Build Ir From Key
        ...    ${key}
        ...    cert_template=${cert_template}
        ...    recipient=${Recipient}
        ...    exclude_fields=sender,senderKID
        ${protected_ir}=    Protect PKIMessage
        ...    ${ir}
        ...    protection=signature
        ...    private_key=${tmp_key}
        ...    cert=${tmp_cert}
        ${response}=    Exchange PKIMessage    ${protected_ir}
    ELSE
        VAR    ${protection}    mac
        ${message}=    Generate Default MAC Protected PKIMessage
        ${key}=    Get From List    ${burned_keys}    -1
        ${response}=    Exchange PKIMessage    ${message}
    END
    ${status}=    Get PKIStatusInfo    ${response}
    IF    '${status["status"]}' != 'accepted'
        Log Asn1    ${status}
        Fatal Error    Setup failed.
    END
    Do Cert Conf If Needed Init    ${response}    ${protection}
    ${cert}=    Get Cert From PKIMessage    ${response}
    VAR    ${ISSUED_CERT}    ${cert}    scope=GLOBAL
    VAR    ${ISSUED_KEY}    ${key}    scope=GLOBAL
    ${chain}=    Build CMP Chain From PKIMessage    ${response}    for_issued_cert=True
    Write Certs To Dir    ${chain}
    ${root}=    Get From List    ${chain}    -1
    Write Cmp Certificate To Pem    ${root}    data/trustanchors/root.pem

Do Cert Conf If Needed Init
    [Documentation]    if a certificate confirmation is needed, one will be generated an ensures that the
    ...    test certificate is valid, and can be used.
    [Arguments]    ${response}    ${protection}
    ${result}=    Find OID In GeneralInfo    ${response}    1.3.6.1.5.5.7.4.13
    IF    ${result}    RETURN
    ${cert_conf}=    Build Cert Conf From Resp    ${response}    sender=${SENDER}    recipient=${RECIPIENT}
    IF    "${protection} == mac"
        ${cert_conf}=    Protect PKIMessage
        ...    ${cert_conf}
        ...    protection=${DEFAULT_MAC_ALGORITHM}
        ...    password=${PRESHARED_SECRET}
    ELSE IF    "${protection} == sig"
        ${cert_conf}=    Protect PKIMessage
        ...    ${cert_conf}
        ...    protection=signature
        ...    private_key=${INIT_KEY}
        ...    cert=${INIT_CERT}
    END
    ${pki_conf}=    Exchange PKIMessage    ${cert_conf}
    ${body_type}=    Get CMP Message Type    ${pki_conf}
    IF    '${body_type}' != 'pkiconf'    Fatal Error    Setup failed.
    VAR    ${INIT_KEY}    ${None}
    VAR    ${INIT_CERT}    ${None}

Initialize Global Variables
    [Documentation]    Define global variables that will be used in the test suite and accessible within any test case.
    Set Up Test Suite
    # Initialize Cert Setup
    ${result}=    Is Certificate And Key Set    ${ISSUED_CERT}    ${ISSUED_KEY}
    IF    not ${result}    Fatal Error    Unable to set up the Test-Suite
    ${csr}    ${tmp_key}=    Generate CSR For Testing
    VAR    ${EXP_CSR}    ${csr}    scope=GLOBAL
    VAR    ${EXP_KEY}    ${tmp_key}    scope=GLOBAL
    # used to indicate, which common-name was already issued to just add a number at the
    # end so the issuer are different.
    # In some cases are only the sender==common_name is accepted, so for all other
    # cases this is used.
    VAR    ${TEST_INDEX}    ${1}    scope=GLOBAL
    # Generate During Runtime
    # Successfully updated certificate and key.
    VAR    ${UPDATED_KEY}    ${None}    scope=GLOBAL
    VAR    ${UPDATED_CERT}    ${None}    scope=GLOBAL
    # Certificate and key to be revoked during Runtime.
    VAR    ${REVOCATION_PRIVATE_KEY}    ${None}    scope=GLOBAL
    VAR    ${REVOCATION_CERT}    ${None}    scope=GLOBAL
    # Issuing of a CA Certificate with KeyUsage and BasicConstraint Extension
    # and the ExtendedKeyUsage `cmcCA` and `cmcRA` if granted.
    VAR    ${CA_CERT}    ${None}    scope=GLOBAL
    VAR    ${CA_KEY}    ${None}    scope=GLOBAL

    # Issuing of a CA Certificate with the ExtendedKeyUsage `cmcRA` if granted.
    # only set if granted, used as trusted RA, if not set.
    # So that the Batched Messages can be checked.
    # But there is also the possibility to set just set the
    # ${OTHER_TRUSTED_PKI_KEY} and ${OTHER_TRUSTED_PKI_CERT} inside the config file.
    # Also has the KeyUsage extension: digitalSignature
    VAR    ${RA_CERT}    ${None}    scope=GLOBAL
    VAR    ${RA_KEY}    ${None}    scope=GLOBAL

    # Successfully revoked certificate to be Revive, if allowed.
    VAR    ${REVOKED_CERT}    ${None}    scope=GLOBAL
    VAR    ${REVOKED_PRIVATE_KEY}    ${None}    scope=GLOBAL
    # Only needed to test LWCMP version, where DSA is not allowed as signing algorithm.
    
    ${dsa_cert}   ${dsa_key}=    May Load Cert And Key     ${DSA_CERT}   ${DSA_KEY}   ${DSA_KEY_PASSWORD}
    VAR    ${DSA_CERT}    ${dsa_cert}    scope=GLOBAL
    VAR    ${DSA_KEY}    ${dsa_key}    scope=GLOBAL
    # To Test with KARI, if allowed.
    VAR    ${X25519_CERT}    ${None}    scope=GLOBAL
    VAR    ${X25519_KEY}    ${None}    scope=GLOBAL
    # To Test with KARI, if allowed.
    VAR    ${ECDSA_CERT}    ${None}    scope=GLOBAL
    VAR    ${ECDSA_KEY}    ${None}    scope=GLOBAL
    # To Test with KTRI, if allowed. RSA with extension (keyEncipherment)
    VAR    ${KGA_KTRI_KEY}    ${None}    scope=GLOBAL
    VAR    ${KGA_KTRI_CERT}    ${None}    scope=GLOBAL

    # To Test KTRI, if the CA rejects a request for KGA without the keyEncipherment extension.
    VAR    ${NEG_KTRI_KEY}    ${None}    scope=Global
    VAR    ${NEG_KTRI_CERT}    ${None}    scope=Global

    # ecc key with extension. (keyAgreement)
    VAR    ${KGA_KARI_KEY}    ${None}    scope=GLOBAL   # robocop: off=VAR04
    VAR    ${KGA_KARI_CERT}    ${None}    scope=GLOBAL  # robocop: off=VAR04

    # To Test KARI, if the CA rejects a request for KGA without the keyAgreement extension.
    VAR    ${NEG_KARI_KEY}    ${None}    scope=Global   # robocop: off=VAR04
    VAR    ${NEG_KARI_CERT}    ${None}    scope=Global  # robocop: off=VAR04

    VAR    ${RR_CERT_FOR_TRUSTED}    ${None}    scope=Global  # robocop: off=VAR04

    VAR    @{GLOBAL_CERTS}    @{EMPTY}    scope=Global  # robocop: off=VAR04
    VAR    @{GLOBAL_KEYS}    @{EMPTY}    scope=Global   # robocop: off=VAR04
