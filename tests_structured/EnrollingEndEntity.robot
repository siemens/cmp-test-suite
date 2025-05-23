

*** Test Cases ***

*** Settings ***
Documentation

#RFC9483 Section 4
CA MUST Send A Valid CP After Receiving valid CR
    [Documentation]    According to RFC 9483 Section 4, when a valid Certification Request is received, the CA MUST
    ...    process the request and respond with a valid Certification Response. The response MUST
    ...    contain the issued certificate if the request meets all requirements.
    #Can we get this more concret?
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




#RFC9483 Section 4.1.1 Enrolling an End Entity to a New PKI
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


CA MUST Support IR With implicitConfirm And PBMAC1 Protection
    [Documentation]    According to RFC 9483, Sections 3.1 and 4, the CA must support handling Initialization Requests
    ...    that include the `implicitConfirm` extension and are protected using PBMAC1. We send a valid
    ...    Initialization Request that is PBMAC1-protected and includes the `implicitConfirm` extension.
    ...    The CA MUST process the request, respond with a valid PKI message, and issue a valid certificate.
    [Tags]    ak    ir    rfc9483-header   mac
    Skip If
    ...    not ${ALLOW_IR_MAC_BASED}
    ...    This test is skipped, because MAC-based-protection is not allowed for ir messages.
    Skip If    not ${ALLOW_IMPLICIT_CONFIRM}    This test is skipped because certificates need to be confirmed.
    ${csr_signed}    ${key}=    Generate CSR For Testing
    ${pki_message}=    Build IR From Csr
    ...    ${csr_signed}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ...    for_mac=True
    ${protected_pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=pbmac1
    ...    password=${PRESHARED_SECRET}
    ${pki_message}=    Exchange PKIMessage    ${protected_pki_message}
    ${pki_header}=    Get Asn1 Value    ${pki_message}    header
    Asn1 Must Contain Fields    ${pki_header}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce
    Validate Sender And Recipient Nonce    ${pki_message}    ${protected_pki_message}
    PKIMessage Must Contain ImplicitConfirm Extension    ${pki_message}
    ${der_cert}=    Get Asn1 Value As DER    ${pki_message}    extraCerts/0
    Log Base64    ${der_cert}
    Certificate Must Be Valid    ${der_cert}
    Response Time Must Be Fresh    ${protected_pki_message}    ${pki_message}
    MAC Protection Algorithms Must Match
    ...    ${protected_pki_message}
    ...    ${pki_message}
    ...    strict=${STRICT_MAC_VALIDATION}
    Verify PKIMessage Protection    ${pki_message}   password=${PRESHARED_SECRET}
    PKIMessage Body Type Must Be    ${pki_message}    ip


CA MUST Reject IR With More Than One CertReqMsg Inside The IR
    [Documentation]    According to RFC 9483 Section 4.1.1, an Initialization Request (IR) must contain exactly one
    ...    `CertReqMsg` to be valid. Including more than one `CertReqMsg` in an IR violates protocol
    ...    requirements. We send an IR containing two `CertReqMsg` entries, expecting the CA to reject
    ...    the request. The CA MUST reject this request and may respond with the optional failinfo
    ...    `badRequest` or `systemFailure`, as specified in Section 3.5.
    [Tags]    ir    lwcmp    negative
    Skip If   not ${LWCMP}    Skipped because this test in only for LwCMP.
    ${key}=    Generate Default Key
    ${key2}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${cm2}=    Get Next Common Name
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}    common_name=${cm}
    ${cert_req_msg2}=    Prepare CertReqMsg    ${key2}    common_name=${cm2}
    VAR    @{msgs}    ${cert_req_msg}    ${cert_req_msg2}
    ${ir}=    Build IR From Key    signing_key=${None}    cert_req_msg=${msgs}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest,systemFailure
CA MUST Reject IR Request With Untrusted Anchor
    [Documentation]    According to RFC 9483 Section 4.1.1, when an End Entity (EE) requests a certificate, it must
    ...    either use MAC-based protection or prove, using a valid certificate and the corresponding
    ...    private key, that it is authorized to make the request. In this test case, we send an IR
    ...    request using a certificate signed by an untrusted anchor. The CA MUST reject the request
    ...    and may respond with the optional failinfo `signerNotTrusted`, as specified in Section 3.5.
    [Tags]    ir    negative    trust
    ${cert}    ${key}=    Build Certificate    ski=True    common_name=${SENDER}
    ${cert_template}=    Prepare CertTemplate    cert=${cert}
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${key}
    ...    cert_template=${cert_template}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${key}
    ...    cert=${cert}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatusInfo Failinfo Bit Must Be    ${response}     failinfo=signerNotTrusted

CA MUST Reject Valid IR With Same Key
    [Documentation]    According to RFC 9483 and based on the CA's policy, a valid Initialization Request (IR) using
    ...    a key that has already been certified may either be accepted or rejected. We send a valid IR
    ...    request with a key that was previously certified. If the request is rejected, the CA may respond
    ...    with the optional failinfo `badCertTemplate`. If accepted, the CA MUST issue a new certificate.
    [Tags]    certTemplate    config-dependent    ir    negative
    Skip If    ${ALLOW_IR_SAME_KEY}    The same key is allowed for multiple certificates.
    ${cert_template}=    Prepare CertTemplate    ${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    include_fields=publicKey,subject,extensions
    ${ir}=    Build IR From Key
    ...    ${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    cert_template=${cert_template}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${prot_ir}=   Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be   ${response}   ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate

# General CertReqMsg
CA MUST Reject IR With BadPOP For Signature POPO
    [Documentation]    According to RFC 9483 Section 4.1.3, when an Initialization Request (IR) is sent for a key
    ...    capable of signing data, the Proof-of-Possession (POPO) structure must include a valid signature of the
    ...    `CertRequest` to prove that the private key is owned by the End-Entity. We send an IR message
    ...    with a key that can sign data, but invalidate the signature value in the `CertRequest`. The CA MUST
    ...    reject the request, and the response may include the optional failinfo `badPOP`.
    [Tags]    ir    negative    popo  sig-popo   minimal
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${cert_req_msg}=    Prepare CertReqMsg   ${key}   ${cm}  hash_alg=sha256  bad_pop=True
    ${pki_message}=    Build IR From Key  ${key}
    ...    cert_req_msg=${cert_req_msg}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be     ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP   exclusive=True

CA MUST Reject IR With Missing POPO Structure For Key Allowed For Signing
    [Documentation]    According to RFC 9483, Section 4.1.3, when an initialization request (ir) is received for a key
    ...    that can be used to sign data, the request must the Proof-of-Possession (POPO) structure, with
    ...    a valid signature of the `CertRequest` structure, to proof, that the private key is owned by the
    ...    End-Entity. We send a ir message with a key capable of signing but without `POPO` structure. The
    ...    CA MUST reject the request. The CA and may respond with the optional failinfo "badPOP".
    [Tags]    negative    popo   minimal
    ${cm}=    Get Next Common Name
    ${key}=    Generate Key    rsa
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}    common_name=${cm}    exclude_popo=True
    ${pki_message}=    Build IR From Key
    ...    ${key}
    ...    cert_req_msg=${cert_req_msg}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be     ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP

CA MUST Reject IR With Mismatched SignatureAlgorithm And PublicKey In CertTemplate
    [Documentation]    According to RFC 9483, Section 4.1.3, when an initialization request (ir) is submitted, the CA
    ...    expects consistency between the signature algorithm and public key specified in the CertTemplate.
    ...    We send an IR where the signature algorithm does not match the provided public key, and
    ...    expects the CA to reject the request. The CA should respond with failinfo codes `badPOP` and
    ...    `badCertTemplate` to indicate the detected inconsistency.
    [Tags]    certTemplate    negative    popo   minimal
    ${cm}=    Get Next Common Name
    ${key1}=    Generate Key    rsa
    ${key2}=    Generate Key    ecc
    ${cert_req}=    Prepare CertRequest    ${key2}    ${cm}
    ${popo}=    Prepare Signature POPO    ${key1}  ${cert_req}   hash_alg=sha256
    ${ir}=    Build IR From Key   ${key2}
    ...    popo=${popo}
    ...    cert_request=${cert_req}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP,badCertTemplate

CA MUST Reject IR With Valid Proof-of-Possession And raVerified From EE
    [Documentation]    According to RFC 9483, Section 4.1.3, when an End Entity (EE) includes a valid
    ...    Proof-of-Possession (POPO) in a certificate request but sets `raVerified` on its own, the CA must reject
    ...    the request as unauthorized. We send a Initialization request without POPO but with `raVerified` set by
    ...    the EE, expecting the CA to respond with a failinfo indicating `notAuthorized`.
    [Tags]    negative    popo   minimal
    ${cm}=    Get Next Common Name
    ${new_key}=    Generate Default Key
    ${pki_message}=    Build IR From Key
    ...    common_name=${cm}
    ...    ra_verified=True
    ...    signing_key=${new_key}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=notAuthorized

CA MUST Reject IR With Invalid CertReqId
    [Documentation]    According to RFC 9483, Section 4.1.3, the `certReqId` field in an initialization request (ir)
    ...    must be set to 0 to indicate a valid request. We send an IR with an invalid `certReqId`
    ...    value of -1, expecting the CA to reject the request. The CA should respond with a failinfo code
    ...    of `badDataFormat` or `badRequest` to signal the invalid format or content of the `certReqId`.
    [Tags]    certReqID    ir    negative  minimal
    ${cm}=    Get Next Common Name
    ${new_key}=    Generate Default Key
    ${ir}=    Build IR From Key
    ...    common_name=${cm}
    ...    cert_req_id=-1
    ...    signing_key=${new_key}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

# CertTemplate structure

CA MUST Reject IR With Missing Subject In CertTemplate
    [Documentation]    According to RFC 9483, Section 4.1.3, the `subject` field is mandatory in the CertTemplate for
    ...    a Initialization request. We send a IR with a CertTemplate that omits the `subject`
    ...    field, expecting the CA to reject the request. The CA should respond with a failinfo of
    ...    `badCertTemplate` to indicate the missing required field.
    [Tags]    certTemplate    ir    negative   minimal
    ${cm}=    Get Next Common Name
    ${new_key}=    Generate Default Key
    ${cert_template}=    Prepare CertTemplate    include_fields=publicKey    key=${new_key}
    ${pki_message}=    Build IR From Key
    ...    common_name=${cm}
    ...    signing_key=${new_key}
    ...    cert_template=${cert_template}
    ...    common_name=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate

# Key Related

CA MUST Issue A ECC Certificate With A Valid IR
    [Documentation]    According to RFC 9483, Section 4.1.3, when the CA receives a valid initialization request (ir)
    ...    containing an Elliptic Curve Cryptography (ECC) key, it should issue an ECC certificate if the
    ...    algorithm is allowed by CA policy. We send an IR with an ECC key. The CA issues a
    ...    certificate when the request meets all requirements. If ECC is unsupported, the CA should
    ...    respond with a failinfo of `badCertTemplate` or `badAlg`.
    [Tags]    ir    key    positive   robot:skip-on-failure  minimal
    Should Contain    ${ALLOWED_ALGORITHM}    ecc
    ${ecc_key}=    Generate Key    ecc    curve=${DEFAULT_ECC_CURVE}
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement,digitalSignature
    ${pki_message}=    Build IR From Key
    ...    extensions=${extensions}
    ...    signing_key=${ecc_key}
    ...    common_name=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERTIFICATE}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    VAR    ${ECDSA_CERT}    ${cert}    scope=Global
    VAR    ${ECDSA_KEY}    ${ecc_key}    scope=Global

CA MAY Issue A Ed25519 Certificate With A Valid IR
    [Documentation]    According to RFC 9483, Section 4.1.3, the CA may issue a certificate for a valid initialization
    ...    request (ir) containing an Ed25519 key if its policy allows this algorithm. We send an ir
    ...    message with an Ed25519 key and expects the CA to issue a certificate if Ed25519 is supported.
    ...    If not, the CA should respond with the failinfo set to `badCertTemplate` or `badAlg`.
    [Tags]    key    positive   robot:skip-on-failure  minimal
    Should Contain    ${ALLOWED_ALGORITHM}    ed25519
    ${ecc_key}=    Load Private Key From File    ./data/keys/private-key-ed25519.pem
    ${extensions}=    Prepare Extensions    key_usage=digitalSignature
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${ecc_key}
    ...    extensions=${extensions}
    ...    common_name=${SENDER}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERTIFICATE}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    VAR    ${Ed25519_CERT}    ${cert}    scope=Global     # robocop: off=VAR07
    VAR    ${Ed25519_KEY}    ${ecc_key}    scope=Global   # robocop: off=VAR07


CA MUST Accept ED25519 Protection
    No Operation

CA MUST Accept ED448 Protection
    No Operation

CA MUST Reject IR With Invalid Algorithm
    [Documentation]    We Send a initialization request (ir) using Diffie-Hellman (DH) as the certificate algorithm
    ...    and expect the CA to reject the request. There is no such thing as a DH-certificate, and the CA should
    ...    reject the request with failinfo codes indicating `badCertTemplate`, `badRequest`, or `badPOP`.
    [Tags]    certTemplate    ir    key    negative   minimal
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement
    ${key}=   Load Private Key From File    data/keys/private-dh-key.pem
    ${key2}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${cert_request}=  Prepare CertRequest    ${key}   ${cm}
    ${popo}=  Prepare Signature POPO    ${key2}   ${cert_request}
    ${ir}=    Build Ir From Key
    ...    ${key}
    ...    popo=${popo}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ...    exclude_fields=sender,senderKID
    ${protected_ir}=   Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be      ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate,badAlg,badPOP

CA MUST Reject IR With Too Short RSA Key In CertTemplate
    [Documentation]    We send a initialization request (ir) with a certTemplate containing an RSA key that is shorter
    ...    than the minimum allowed size and expect the CA to reject the request. The CA should reject any request
    ...    with an RSA key that does not meet security requirements, setting a badCertTemplate failinfo.
    [Tags]    certTemplate    config-dependent    ir    key    negative    robot:skip-on-failure
    # generate a key with bit size of 512
    ${bad_key}=    Generate Key    bad_rsa_key
    ${pki_message}=    Build Ir From Key
    ...    ${bad_key}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate

CA MUST Reject IR With Too Large RSA Key In CertTemplate
    [Documentation]    We send a initialization request (ir) with a certTemplate containing an RSA key that exceeds
    ...    the maximum allowed size and expect the CA to reject the request. The CA should reject any request with an
    ...    RSA key that is too large, marking the request with a badCertTemplate failinfo.
    [Tags]    certTemplate    config-dependent    ir    key    negative  sec-awareness
    Skip If  not ${LARGE_KEY_SIZE}    The `LARGE_KEY_SIZE` variable is not set, so this test is skipped.
    IF   ${LARGE_KEY_SIZE} < 18000
        ${bad_key}=    Load Private Key From File    ./data/keys/private-key-rsa-size-18000.pem
    ELSE
        ${bad_key}=    Generate Key  rsa  length=${LARGE_KEY_SIZE}
    END
    ${pki_message}=    Build Ir From Key
    ...    ${bad_key}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate

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


#RFC9483 Section 4.1.2 Enrolling an End Entity to a known PKI

CA MUST Reject CR With Other PKI Management Entity Request
    [Documentation]    According to RFC 9483 Section 4.1.2, the certificate used by the End Entity (EE) to request a
    ...    certificate must have been issued by the PKI that it is requesting the certificate from.
    ...    In this test case, we send a `cr` message that is signed by a device certificate from a
    ...    different PKI. The CA must reject the request and may respond with the optional failinfo
    ...    `notAuthorized` or `badRequest`, as specified in Section 3.5.
    [Tags]    cr    negative    robot:skip-on-failure
    ${is_set}=    Is Certificate And Key Set    ${DEVICE_CERT}    ${DEVICE_KEY}
    Skip If    not ${is_set}    The `DEVICE_CERT` and/or `DEVICE_KEY` variable is not set, skipping test.
    ${cert_chain}=    Build Cert Chain From Dir    ${DEVICE_CERT}    cert_chain_dir=./certs
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Cr From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${DEVICE_KEY}
    ...    cert=${DEVICE_CERT}
    ...    cert_chain=${cert_chain}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    cp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=notAuthorized,badRequest

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

CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected CR
    [Documentation]    According to RFC 9483 Section 4.1.2, when a valid Certification Request is received with
    ...    MAC-based protection, the CA MUST process the request and respond with a valid Certification
    ...    Response, issuing a valid certificate. If implicit confirmation is enabled, the PKIMessage MUST
    ...    contain the `implicitConfirm` extension. Otherwise, the `implicitConfirm` extension MUST NOT be
    ...    present in the `generalInfo` field.
    #Not sure if implicitConfirm->implicit Confirm and NOTimplicitConfirms->NOTimplicitConfirm is completly true
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


#RFC9483 Section 4.1.3 Updating a valid Certificate

CA MUST Either Reject Or Accept Valid KUR With Same Key
    [Documentation]    According to RFC 9483, Section 4.1.3 and 5, the CA MAY reject or accept Key Update Requests that
    ...    use the same key as the certificate being updated, depending on the PKI policy. If the policy does
    ...    not allow same-key updates, the CA MUST reject the request and may respond with the optional
    ...    failinfo `badCertTemplate`. Otherwise, the CA MUST accept the request and issue a new valid
    ...    certificate.
    [Tags]    certTemplate    kur    security
    Skip If    ${ALLOW_KUR_SAME_KEY}    Skipped because the same key is is allowed to be used.
    ${pki_message}=    Build Key Update Request
    ...    ${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    kup
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate

CA MUST Reject KUR With The Wrong Issuer Inside The Control Structure
    [Documentation]    According to RFC 9483, Section 4.1.3, the `controls` structure is recommended within a Key
    ...    Update Request to specify the certificate intended for update. This test sends a Key Update
    ...    Request where the `issuer` field inside the `controls` structure is invalid. The CA MUST reject
    ...    the request. The response may include the failinfo `badRequest`.
    [Tags]    controls    kur    negative
    ${new_private_key}=    Generate Default Key
    ${issuer}=    Modify Common Name Cert    cert=${ISSUED_CERT}    issuer=True
    ${controls}=    Prepare Controls Structure    cert=${ISSUED_CERT}    issuer=${issuer}
    ${pki_message}=    Build Key Update Request
    ...    signing_key=${new_private_key}
    ...    controls=${controls}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    kup
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertId

CA MUST Reject KUR With Invalid serialNumber In Controls Structure
    [Documentation]    According to RFC 9483, Section 4.1.3, the `controls` structure is recommended within a Key
    ...    Update Request to specify the certificate intended for update. This test sends a Key Update
    ...    Request where the `serialNumber` field inside the `controls` structure is invalid. The CA MUST
    ...    reject the request. The response may include the failinfo `badRequest`.
    [Tags]    controls    kur    negative
    ${new_private_key}=    Generate Default Key
    ${serial_number}=    Get Field From Certificate    ${ISSUED_CERT}    query=serialNumber
    ${serial_number}=    Evaluate    ${serial_number} + 1
    ${controls}=    Prepare Controls Structure    cert=${ISSUED_CERT}    serial_number=${serial_number}
    ${pki_message}=    Build Key Update Request
    ...    signing_key=${new_private_key}
    ...    controls=${controls}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    kup
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertId


CA Must Reject Valid IR With Already Updated Certificate
    [Documentation]    According to RFC 9483, Section 4.1.3, the CA must validate an initialization request (ir) to
    ...    ensure that the certificate is not already updated. We send a valid ir message using an already
    ...    updated certificate and expect the CA to reject the request. The CA should respond with a
    ...    `certRevoked` failinfo to indicate that the certificate cannot be used for issuance.
    [Tags]    ir    negative    update
    ${is_set}=    Is Certificate And Key Set    ${UPDATED_CERT}    ${UPDATED_KEY}
    Skip If    not ${is_set}    The `UPDATED_CERT` and/or `UPDATED_KEY` variables are not set.
    Sleep    3
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${pki_message}=    Build IR From Key
    ...    signing_key=${key}
    ...    cert_template=${cert_template}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${UPDATED_KEY}
    ...    cert=${UPDATED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatus Must Be      ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=certRevoked   exclusive=True

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
    # positioned here so if the Response is incorrect, the certificate is still updated, so that it
    # can be used for other test cases.
    Validate CA Message Body    ${response}    used_p10cr=False

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
    ${cert}=   Confirm Certificate If Needed   ${response}   protection=signature
    Validate Ca Message Body    ${response}
    VAR    ${UPDATED_CERT}    ${cert}    scope=Global
    VAR    ${UPDATED_KEY}    ${kur_key}    scope=Global

CA MUST Reject An Valid MAC Protected Key Update Request
    [Documentation]    According to RFC 9483 Section 4.1.3, a Key Update Request must be signature-protected for the CA
    ...    to process it. We send a valid Key Update Request that is MAC-protected. The CA MUST
    ...    reject the request to ensure integrity and compliance with the PKI policies, potentially
    ...    responding with the failInfo `wrongIntegrity`.
    #I don´t understand where this comes from
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


# RFC4849 Section 4.1.4 Enrolling an End Entity using a PKCS10 request
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
    ${cert}=  Confirm Certificate If Needed    ${response}
    Validate CA Message Body    ${response}    used_p10cr=True
    Certificate Must Be Valid    ${cert}

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


CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected P10CR
    [Documentation]    According to RFC 9483 Section 4.1.4, when a valid `Certification Request` is received with
    ...    MAC-based protection, the CA MUST process the request and respond with a valid
    ...    `Certification Response`, issuing a valid certificate. If implicit confirmation is enabled,
    ...    the PKIMessage MUST contain the `implicitConfirm` extension. Otherwise, it SHOULD NOT
    ...    be present in the `generalInfo` field.
    #Not sure if implicitConfirm->implicit Confirm and NOTimplicitConfirms->NOTimplicitConfirm is completly true
    #Check out some more
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

CA Must Reject Request When The CSR Signature Is Invalid
    [Documentation]    According to RFC 9483 Section 4.1.4, the signature inside the CSR serves as proof-of-possession
    ...    to demonstrate that the End-Entity owns the private key. We send a CSR with a invalid signature.
    ...    The CA MUST reject the request and may respond with the optional failInfo `badPOP`.
    #Why is this not minimal but above the section 4.1.4 is tagged minimal?
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

CA Must Issue A Certificate When We Send A Valid P10cr Request
    [Documentation]    According to RFC 9483 Section 4.1.4, when a valid CSR is sent inside a p10cr PKIMessage, the CA
    ...    MUST respond with a valid certificate. We send a correctly formatted p10cr request and
    ...    verify that the CA issues a valid certificate in response.
    #Why is this minimal? 4.1.4 is not a must, so other criteria
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


CA Must Issue Certificate Via P10cr Without implicitConfirm
    [Documentation]    According to RFC 9483, Section 4.1.4, the server should issue a certificate in response to a
    ...    valid p10cr request, even if implicit confirmation is not set. This test verifies that the
    ...    server correctly waits for an explicit confirmation from the End Entity (EE) before finalizing
    ...    the issuance.
    [Tags]    p10cr    positive  certConf
    ${parsed_csr}=    Load And Parse Example CSR
    ${p10cr}=    Build P10cr From CSR
    ...    csr=${parsed_csr}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    for_mac=True
    ${protected_p10cr}=    Default Protect With MAC    ${p10cr}
    ${response}=   Exchange PKIMessage    ${protected_p10cr}
    # could also be ip, kup, cp; consider examining the tag; the overall structure is CertRepMessage
    PKIMessage Body Type Must Be    ${response}    cp
    # prepare confirmation message by extracting the certificate and getting the needed
    # data from it cert_req_id must be also `0` for P10cr.
    ${conf_message}=   Build Cert Conf From Resp    ${response}   for_mac=True
    ...    cert_req_id=0
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    for_mac=True
    ${protected_conf_message}=    Default Protect With MAC    ${conf_message}
    ${pki_message}=   Exchange PKIMessage     ${protected_conf_message}
    PKIMessage Body Type Must Be    ${pki_message}    pkiconf

Response PKIMessage Header Must Include All Required Fields
    [Documentation]    According to RFC 9483, Section 3 and 4, the server must include required fields in the
    ...    PKIMessage header when responding to a PKCS #10 certificate request (p10cr). This test
    ...    verifies that the server response contains header fields such as pvno, sender, recipient,
    ...    protectionAlg, transactionID, and senderNonce.
    [Tags]    header    p10cr    rfc9483-header   minimal
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${p10cr}=    Build Ir From Key    ${key}   cert_template=${cert_template}  for_mac=True
    ...          recipient=${RECIPIENT}    sender=${SENDER}   implicit_confirm=${True}
    ${protected_p10cr}=    Protect PKIMessage    ${p10cr}    protection=pbmac1    password=${PRESHARED_SECRET}
    ${pki_message}=    Exchange PKIMessage    ${protected_p10cr}
    Asn1 Must Contain Fields    ${pki_message["header"]}   pvno,sender,recipient,protectionAlg,transactionID,senderNonce
    Sender And Recipient Nonces Must Match    ${protected_p10cr}    ${pki_message}
    SenderNonce Must Be At Least 128 Bits Long    ${pki_message}
    PKIMessage Must Contain ImplicitConfirm Extension    ${pki_message}
    ${der_cert}=    Get Asn1 Value As DER   ${pki_message}    extraCerts/0
    Log Base64    ${der_cert}
    Certificate Must Be Valid    ${der_cert}
    Response Time Must Be Fresh    ${protected_p10cr}    ${pki_message}
    MAC Protection Algorithms Must Match    ${protected_p10cr}    ${pki_message}
    Verify PKIMessage Protection    ${pki_message}   password=${PRESHARED_SECRET}
    PKIMessage Body Type Must Be    ${pki_message}    ip
