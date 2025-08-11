*** Test Cases ***

#unclear status of the usefulness of the test case
CA Must Reject Request When The CSR Is Sent Again
    [Documentation]    According to RFC 9483 Section 3 and 5, the policy of the CA may define whether it allows a
    ...    duplicate CSR with the same details. We send a previously issued CSR. The CA may reject or
    ...    accept the request. If rejected, the CA may respond with the optional failInfo
    ...    `duplicateCertReq`.
    # there is no duplicateCertReq
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


# BasicConstraints

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


#KeyUsages

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
    ${cert}=  Confirm Certificate If Needed    ${ca_response}   request=${protected_ir}
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


#Basic CertTemplate

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


# Section 5.1.1
CA MAY Issue A DSA Certificate
    [Documentation]    According to RFC 9483, Section 5.1.1, the CA processes certificate requests based on its policy.
    ...    When the CA receives a valid initialization request (ir) containing a DSA public key, it should
    ...    process the request accordingly. If the CA's policy allows issuing certificates with DSA keys,
    ...    it should issue the requested certificate. Otherwise, the CA must reject the request to maintain
    ...    PKI integrity.
    [Tags]    ir    key    positive    robot:skip-on-failure    setup   minimal
    ${key}=    Generate Key    dsa    length=${DEFAULT_KEY_LENGTH}
    ${ir}=    Build Ir From Key
    ...    ${key}
    ...    common_name=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}   ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    ${cert_conf}
        ...    signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERTIFICATE}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    VAR    ${DSA_CERT}    ${cert}    scope=Global
    VAR    ${DSA_KEY}    ${key}    scope=Global
