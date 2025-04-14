# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
*** Settings ***
Documentation       Keywords are often used for testing.

Resource            ../config/${environment}.robot
# Resource    ../config/local.robot
Library             RequestsLibrary
Library             Collections
Library             DateTime
Library             OperatingSystem
Library             String
Library             ../resources/asn1utils.py
Library             ../resources/cryptoutils.py
Library             ../resources/httputils.py
Library             ../resources/cmputils.py
Library             ../resources/utils.py
Library             ../resources/certutils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/py_verify_logic.py


*** Variables ***
${environment}          cloudpki
# ${environment}    local

# This variable is a collector of nonces that the server sent back to us throughout all the tests. In the end we use
# it to check that the server is not sending the same nonce twice, and that the nonces are cryptographically secure.
@{COLLECTED_NONCES}     @{EMPTY}
# all correctly issued certificates saved for testing revocation, with different certificates.
@{collected_certs}      @{EMPTY}
# the matching keys to the certificates.
@{collected_keys}       @{EMPTY}
${TestIndex}            ${0}
@{burned_keys}          @{EMPTY}
&{CERT_CONF_DEF_VALS}   sender=${SENDER}    recipient=${RECIPIENT}    private_key=${ISSUED_KEY}    cert=${ISSUED_CERT}    password=${PRESHARED_SECRET}    protection=signature

*** Keywords ***

Set Up Test Suite
    [Documentation]    This keyword is used to set up the test suite. It is called at the beginning of the test suite.
    ...                Or a test file to ensure that all prerequisites are met. As an example a first certificate is issued,
    ...                and the key is generated to be used for the tests. This ensure that a trusted certificate is present,
    ...                which will be used to issue further certificates. This method was chosen to allow to set a certificate,
    ...                which is not firstly configured, but generated with the test suite. If `MAC` protection is allowed, the
    ...                shared secret will be used to issue the first certificate `ISSUED_KEY` and `ISSUED_CERT`.
    ...                This ensure that the test suite can be run without the modification of the database.
    ...                If the `MAC` protection is not allowed, the `ISSUED_KEY` and `ISSUED_CERT` are issued with the **MUST**
    ...                be set default certificate and key. If this behaviour is not wanted, the `ISSUED_KEY` and `ISSUED_CERT`
    ...                can be set in the configuration file, and will then be loaded from there.
    [Tags]    setup
    VAR    ${TestIndex}    ${0}
    IF  '${ISSUED_KEY}' == '${None}'
        ${issued_key}=    Generate Default Key
        IF    ${ALLOW_MAC_PROTECTION}
            ${ir}=  Build Ir From Key    ${issued_key}    sender=${SENDER}    recipient=${RECIPIENT}
            ...     for_mac=True   implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
            ${protected_ir}=    Protect PKIMessage    ${ir}    password=${PRESHARED_SECRET}    protection=${DEFAULT_MAC_ALGORITHM}
        ELSE
            ${tmp_cert}    ${tmp_key}=    May Load Cert And Key
            ...    cert_path=${INITIAL_CERT_PATH}
            ...    key_path=${INITIAL_KEY_PATH}
            ...    key_password=${INITIAL_KEY_PASSWORD}
            ${result}=    Is Certificate And Key Set    ${tmp_cert}    ${tmp_key}
            IF  not ${result}
                Fatal Error    The initial certificate and key are not provided.
            END
            ${ir}=  Build Ir From Key    ${issued_key}   exclude_fields=sender,senderKID
            ...                          recipient=${RECIPIENT}    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
            ${protected_ir}=    Protect Hybrid PKIMessage     ${ir}    private_key=${tmp_key}    cert=${tmp_cert}
        END
        ${response}=   Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${INIT_SUFFIX}
        PKIStatus Must Be    ${response}   accepted
        ${issued_cert}=    Confirm Certificate If Needed    ${response}
        VAR    ${ISSUED_KEY}    ${issued_key}    scope=Global
        VAR    ${ISSUED_CERT}    ${issued_cert}    scope=Global
        LOG    Initial certificate issued, with `MAC` protection.
        VAR    &{CERT_CONF_DEF_VALS}    sender=${SENDER}    recipient=${RECIPIENT}    private_key=${issued_key}    cert=${issued_cert}    password=${PRESHARED_SECRET}    protection=signature   scope=Global
        VAR    &{DEFAULT_PROTECTION_VALS}    protection=signature   private_key=${issued_key}    cert=${issued_cert}   password=${PRESHARED_SECRET}  scope=Global
    END
    ${cert}  ${key}=   May Load Cert And Key    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    VAR    ${OTHER_TRUSTED_PKI_CERT}    ${cert}    scope=Global
    VAR    ${OTHER_TRUSTED_PKI_KEY}    ${key}    scope=Global

Increase TestIndex
    [Documentation]    Perform the incrementation of the `TestIndex` to update the sender name inside the PKIMessage,
    ...                for each test case.
    ${NUMBER}=    Evaluate    ${TestIndex} + 1
    VAR    ${TestIndex}    ${NUMBER}    scope=GLOBAL

Try To Log PKIMessage As ASN1
    [Documentation]    Tentatively parse a buffer, assuming it is a DER-encoded PKIMessage, and log its contents.
    ...    If that is not the case, ignore this and keep going. This is for convenience in logging.
    ...    DEPRECATED in favour of `try_to_log_pkimessage' in Python, which is more concise.
    [Tags]    robot:flatten
    [Arguments]    ${payload}
    ${pki_message}=    Parse PKIMessage    ${payload}
    Log Asn1    ${pki_message}

Load And Refresh PKIMessage From File
    [Documentation]    Load a PKIMessage from a PEM file, update its transactionId and messageTime, and return it
    ...    as a pyasn1 object. This is useful when sending previously sent messages, the CA will reject
    ...    them if the time is not fresh or if the transactionId is not unique.
    [Arguments]    ${path}    ${transaction_id}=${NONE}    ${message_time}=${NONE}
    ${raw}=    Load And Decode Pem File    ${path}
    ${pki_message}=    Parse PKIMessage    ${raw}
    Log Asn1    ${pki_message}
    ${pki_message}=    Patch TransactionID    ${pki_message}    ${transaction_id}
    ${pki_message}=    Patch MessageTime    ${pki_message}    ${message_time}
    RETURN    ${pki_message}

Generate CSR With RSA2048 And A Predefined Common Name
    [Documentation]    Produce a generic, valid CSR that has a correct signature
    ${key}=    Generate Key    rsa    length=2048
    ${csr}=    Build CSR    ${DEFAULT_X509NAME}    exclude_signature=True
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    Log    ${csr_signed}
    RETURN    ${csr_signed}

Load And Parse Example CSR
    [Documentation]    Load a CSR from a PEM file, and return it as a pyasn1 object.    This is for convenience, to remove
    ...    the need to generate a new keypair.
    ${csr}=    Load And Decode Pem File    data/example-csr.pem
    ${parsed_csr}=    Parse Csr    ${csr}
    RETURN    ${parsed_csr}

Exchange Data With CA
    [Documentation]    Send a HTTP POST request to a server, and return the response.
    [Arguments]    ${payload}    ${url}=${CA_CMP_URL}
#    Run Keyword And Ignore Error    Try to Log PKIMessage as ASN1    ${payload}
    Try To Log PKIMessage    ${payload}
    # TODO check if type of payload is a pyasn1 structure, and if it is, der-encode it automatically? Maybe?
    VAR    &{headers}    Content-Type=application/pkixcmp    Accept-Type=application/pkixcmp
    ${response}=    POST
    ...    url=${url}
    ...    data=${payload}
    ...    headers=&{headers}
    ...    verify=${False}
    ...    expected_status=any
    Try To Log PKIMessage    ${response.content}
    RETURN    ${response}

Sender And Recipient Nonces Must Match
    [Documentation]    Ensure that the recipient nonce in the response matches the sender nonce in the request
    [Arguments]    ${request}    ${response}
    ${request_nonce}=    Get Asn1 Value As Bytes    ${request}    header.senderNonce
    ${response_nonce}=    Get Asn1 Value As Bytes    ${response}    header.recipNonce
    Should Be Equal    ${request_nonce}    ${response_nonce}

Response Time Must Be Fresh
    [Documentation]    Ensure that the response time is not far off from the time of our request
    ...    The tolerance is given in seconds, and defaults to 120 (i.e., 2 minutes)
    [Arguments]    ${request}    ${response}    ${tolerance}=${120}
    ${request_time}=    Get Asn1 Value As Datetime    ${request}    header.messageTime
    ${response_time}=    Get Asn1 Value As Datetime    ${response}    header.messageTime

    ${delta_verbose}=    Subtract Date From Date    ${response_time}    ${request_time}    verbose
    ${delta}=    Subtract Date From Date    ${response_time}    ${request_time}
    Should Be True    ${delta} < ${tolerance}    Time between request and response exceeds tolerance

SenderNonce Must Be At Least 128 Bits Long
    [Documentation]    Ensure that the senderNonce of a PKIMessage is at least 128 bits long
    ...    Ref: 3.1. General Description of the CMP Message Header
    [Tags]    crypto
    [Arguments]    ${pki_message}
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${pki_message}    header.senderNonce
    # Use this to provoke a failure, by deliberately requesting a nonce that is longer than really needed
    # Buffer length must be at least    ${sender_nonce}    32
    # 16 bytes is 128 bits
    Buffer Length Must Be At Least    ${sender_nonce}    16

Certificate Must Be Valid
    [Documentation]    Verify if a certificate is valid and passes sanity checks. The certificate is passed as a
    ...    DER-encoded byte buffer. These checks are done by trying to parse the certificate with
    ...    OpenSSL and PKILint. OpenSSL is relatively forgiving and will accept a certificate that
    ...    may contain issues, but is good enough for practical applications - failure to load with OpenSSL
    ...    is treated as an error. PKILint is very picky and will find issues even if a certificate
    ...    is accepted by OpenSSL. PKILint's findings will be logged and reported as warnings - making
    ...    it clear that there's something of interest, but not failing the test.
    [Arguments]    ${der_certificate}
    Log Base64    ${der_certificate}
    # If OpenSSL complains, we fail the test
    Validate Certificate OpenSSL    ${der_certificate}
    # Use PKILint to check the certificate for issues, https://github.com/digicert/pkilint
    # If PKILint complains, we log a warning, but keep going
    Run Keyword And Warn On Failure
    ...    Validate Certificate PKILint    ${der_certificate}

Validate Certificate was issued for expected Alg
    [Documentation]    Validate that the certificate was issued for the expected algorithm.
    ...
    ...                Arguments:
    ...                - `${response}`: The PKIMessage response.
    ...                - `${expected_alg}`: The expected algorithm identifier (e.g., 'ml-dsa-44').
    ...                - `${index}`: The index of the certificate in the PKIMessage. Defaults to `0`.
    ...
    ...                Examples:
    ...                | Validate Certificate Was Issued For Expected Alg | ${response} | ml-dsa-44 |
    ...                | Validate Certificate Was Issued For Expected Alg | ${response} | ml-dsa-44 | 1 |
    [Arguments]    ${response}    ${expected_alg}    ${index}=0
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=    Get Cert From PKIMessage    ${response}    ${index}
    Validate Migration OID In Certificate    ${cert}    ${expected_alg}

Generate Key And CSR
    [Documentation]    This function generates a fresh Certificate Signing Request (CSR) and key, returning the DER-formatted data and the key.
    ...    Arguments:
    ...    - `key_algo_name`: The `PKIMessage` object that contains the `PKIStatusInfo` structure to be checked.
    ...    - `key_params`:The index or indices of the bits to check within the `failInfo` field
    ...    - `CN`: Determines if other bits can also be set. If set to `True`, only the specified bit index will be permitted.
    ...    However, if multiple indices are provided, only one of them can be set.
    ...
    ...    Examples:
    ...    | ${data}    ${key}=    | Generate Key and CSR    | ${key_algo_name}    |    ${CN}    |    ${key_params} |
    ...
    [Arguments]    ${key_algo_name}    ${CN}    ${key_params}
    ${key}=    Generate Key    ${key_algo_name}    ${key_params}
    ${csr_signed}    ${key}=    Generate Signed CSR    ${CN}    ${key}
    ${data}=    Decode Pem String    ${csr_signed}
    RETURN    ${data}    ${key}

PKIMessage Body Type Must Be
    [Documentation]    Ensure that the response type in a PKIMessage is of a certain type
    [Arguments]    ${pki_message}    ${expected_type}
    ${response_type}=    Get CMP Message Type    ${pki_message}
    IF    '${response_type}' != '${expected_type}'
        ${pki_status_info}=    Get PKIStatusInfo    ${pki_message}
    END
    Should Be Equal    ${response_type}    ${expected_type}    Response type mismatch

PKIMessage Must Contain ImplicitConfirm Extension
    [Documentation]    Ensure the given PKIMessage contains the implicitConfirm extension in its header.generalInfo
    [Arguments]    ${pki_message}
    ${result}=    Find OID In GeneralInfo    ${pki_message}    1.3.6.1.5.5.7.4.13
    Should Be True    ${result}    The implicitConfirm extension was not found in the message

Collect Nonce From PKIMessage
    [Documentation]    Extract the senderNonce from a PKIMessage and append it to a list, which will be used later
    ...    in a test that checks for nonces to be cryptographically strong.
    [Arguments]    ${pki_message}
    ${body_type}=    Get Cmp Message Type    ${pki_message}
    Log   ${GATHER_NONCES_FROM_MSG_BODIES}
    Log   ${body_type}
    ${is_present}=  Evaluate  '${body_type}' in '${GATHER_NONCES_FROM_MSG_BODIES}'
    IF    ${is_present}
        ${sender_nonce}=    Get Asn1 Value As Bytes    ${pki_message}    header.senderNonce
        Append To List    ${COLLECTED_NONCES}    ${sender_nonce}
        Log    ${COLLECTED_NONCES}
    END

Exchange PKIMessage
    [Documentation]    Send a PKIMessage to the CA or RA Server and then then parse the returned PKIMessage.
    ...    Expects to get a parse-able PKIMessage.
    [Tags]    exchange    http
    [Arguments]    ${request_pki_message}   ${url}=${CA_CMP_URL}
    ${encoded_request}=    Encode To Der    ${request_pki_message}
    Log Base64    ${encoded_request}
    ${response}=    Exchange Data With CA    ${encoded_request}   ${url}
    Log Base64    ${response.content}
    ${response_pki_message}=    Parse PKIMessage    ${response.content}
    Collect Nonce From PKIMessage    ${response_pki_message}
    RETURN    ${response_pki_message}

# TODO add function called Get Key, if the same key is allowed returns one of the predefined keys,
# which are already available in the test suite to save additional resources.
# Another TODO merge with the idea to build a PKIMessage dataclass, which will be used to make our
# lives easier and the code consistence, because none-tag fields are not patch-able.
# also allows more efficient unit tests.
# TODO fix

Generate Unique Key
    [Documentation]    Generates a unique cryptographic key using specified default parameters, set inside the config.
    ...
    ...                Examples:
    ...                | ${private_key}=    Generate Unique Key | rsa | length=2048 |
    [Arguments]    ${algorithm}    &{params}
    [Tags]    key
    ${max_attempts}=  Get From Dictionary    ${params}    max_attempts    ${100}
    FOR    ${index}    IN RANGE    ${max_attempts}
        ${key}=    Generate Key    algorithm=${algorithm}    &{params}
        # privates keys can not be compared so this work-around.
        ${result}=    Check If Private Key In List    keys=${BURNED_KEYS}    new_key=${key}
        IF    not ${result}
            Append To List    ${BURNED_KEYS}    ${key}
            RETURN    ${key}
        END
        Log    Generated key is burned. Regenerating... [Attempt ${index + 1}]
    END
    Fail    Unable to generate a unique key after ${max_attempts} attempts.

# TODO decide to maybe allow to set Curve also to X25519 or X448, if the algorithm is set to ECC.

Generate Default Key
    [Documentation]    Generates a default cryptographic key using specified default parameters, set inside the config.
    ...
    ...                Note:
    ...                ----
    ...                 - `DEFAULT_ALGORITHM` defines the algorithm.
    ...                 - `DEFAULT_KEY_LENGTH` defines the key length for RSA.
    ...                 - `DEFAULT_ECC_CURVE` defines the curve for ECC. Not relevant for X25519 or X448.
    ...                 Then must the `DEFAULT_ALGORITHM` be set to `x25519` or `x448`.
    ...                Examples:
    ...                | ${private_key}=    Generate Default Key |
    [Tags]    key
    ${params}=    Create Dictionary    length=${DEFAULT_KEY_LENGTH}    curve=${DEFAULT_ECC_CURVE}
    ${private_key}=    Generate Unique Key    algorithm=${DEFAULT_ALGORITHM}    &{params}
    RETURN    ${private_key}

Generate Default PQ SIG Key
    [Documentation]    Generates a default pq signature key. Set by the configuration (``DEFAULT_PQ_SIG_ALGORITHM``).
    ...
    ...                Examples:
    ...                --------
    ...                | ${key}= | Generate Default PQ Key |
    [Tags]    key   pq
    ${key}=   Generate Key    ${DEFAULT_PQ_SIG_ALGORITHM}
    RETURN    ${key}

Generate Default PQ KEM Key
    [Documentation]    Generates a default cryptographic pq key encapsulation mechanism (KEM) key.
    ...                Set by the configuration (`DEFAULT_PQ_KEM_ALGORITHM`).
    ...
    ...                Examples:
    ...                --------
    ...                | ${key}= | Generate Default KEM Key |
    [Tags]    key   pq  kem
    ${key}=   Generate Key    ${DEFAULT_PQ_KEM_ALGORITHM}
    RETURN    ${key}

Generate Default KeyAgreement Key
    [Documentation]     Generate a default cryptographic key agreement key. Could be
    ...                 an ECC key (e.g., X25519) or a key on a default curve, set by
    ...                 the configuration (`DEFAULT_ECC_CURVE`).
    ...
    ...                Examples:
    ...                --------
    ...                | ${key}= | Generate Default KeyAgreement Key |
    [Tags]    keyAgree  key
    ${key}=   Generate Unique Key    ${DEFAULT_KEY_AGREEMENT_ALG}   curve=${DEFAULT_ECC_CURVE}
    RETURN   ${key}

Generate Default KeyEncipherment Key
    [Documentation]     Generate a default cryptographic key encipherment key.
    ...                Could be RSA or a key encapsulation mechanism (KEM) key.
    ...
    ...                Examples:
    ...                --------
    ...                | ${key}= | Generate Default KeyEncipherment Key |
    [Tags]    keyEnc  key
    ${key}=   Generate Unique Key    ${DEFAULT_KEY_ENCIPHERMENT_ALG}
    RETURN   ${key}

Generate Default Composite Sig Key
    [Documentation]    Generates a default composite signature key with the traditional algorithm
    ...                and the PQ algorithm defined in the configuration.
    ...
    ...                Note:
    ...                ----
    ...                - `DEFAULT_TRAD_ALG` defines the algorithm.
    ...                - `DEFAULT_KEY_LENGTH` defines the key length for RSA.
    ...                - `DEFAULT_PQ_ALG` defines the pq algorithm.
    ...                - `DEFAULT_ECC_CURVE` defines the curve for ECC.
    ...
    ...                Returns:
    ...                --------
    ...                - key: The generated key.
    ...
    ...               Examples:
    ...               --------
    ...               | ${key}= | Generate Default Composite Sig Key |
    ...
    [Tags]         composite-sig    key
    ${params}=    Create Dictionary    trad_name=${DEFAULT_TRAD_ALG}   length=${DEFAULT_KEY_LENGTH}    curve=${DEFAULT_ECC_CURVE}   pq_name=${DEFAULT_PQ_SIG_ALG}
    ${key}=      Generate Key    algorithm=composite-sig    &{params}
    RETURN     ${key}

Default Protect PKIMessage
    [Documentation]    Protect a PKIMessage with the default protection algorithm, set inside the config
    ...                and the default parameters.
    ...
    ...                Note:
    ...                ----
    ...                - The protection algorithm is set to `signature` by default.
    ...
    ...                Examples:
    ...                | ${prot_pkimessage}=    Default Protect PKIMessage    | ${pki_message} |
    ...
    [Arguments]    ${pki_message}    &{params}
    [Tags]    protection
    ${length}=   Get Length   ${params}
    IF  ${length} == 0
        ${args}=    Copy Dictionary    ${DEFAULT_PROTECTION_VALS}
    ELSE
        ${args}=    May Patch Params    ${params}    &{DEFAULT_PROTECTION_VALS}
    END
    ${protection}=   Get From Dictionary    ${args}    protection
    IF  '${protection}' == 'signature'
        ${prot_pkimessage}=    Protect Hybrid PKIMessage    ${pki_message}  &{args}
    ELSE IF  '${protection}' == 'mac'
        ${args}=    Set To Dictionary    ${args}   protection=${DEFAULT_MAC_ALGORITHM}
        ${prot_pkimessage}=    Protect PKIMessage    ${pki_message}    &{args}
    ELSE
        ${prot_pkimessage}=    Protect PKIMessage    ${pki_message}    &{args}
    END
    RETURN    ${prot_pkimessage}

Confirm Certificate If Needed
    [Documentation]    Some Test cases need a valid certificate to work. Because not all CA's might support the
    ...                implicit confirm extension, this keyword checks if the given `PKIMessage` contains the implicit
    ...                confirm extension. If it does, the certificate is confirmed and returned. If not, the `PKIMessage`
    ...                a valid certificate confirmation message is send and the of the CA's response is checked.
    ...                If the CA's response is the `PKIMessage` `pkiconf`, then is the certificate confirmed.
    ...                Arguments:
    ...                ---------
    ...                 - `response`: The response message from the CA.
    ...                 - `params`: key=value pair to set variables for the protection.
    ...
    ...                Returns:
    ...                -------
    ...                - `cert`: The confirmed certificate.
    ...
    ...                Examples:
    ...                --------
    ...                | ${cert}= | Confirm Certificate If Needed | ${response} | &{params} |
    ...
    [Arguments]    ${response}    &{params}
    [Tags]    confirm   default   cert
    ${result}=   Find OID In GeneralInfo    ${response}   1.3.6.1.5.5.7.4.13
    IF    ${result}
        Log    The PKIMessage contains the implicit confirm extension.
        ${cert}=    Get Cert From PKIMessage    ${response}
        RETURN    ${cert}
    ELSE
        Log    The PKIMessage does not contain the implicit confirm extension.
        ${length}=   Get Length   ${params}
        IF  ${length} == 0
            ${args}=    Copy Dictionary    ${CERT_CONF_DEF_VALS}
        ELSE
            ${args}=    May Patch Params   ${params}    &{CERT_CONF_DEF_VALS}
        END
        ${params}=    May Patch Params    ${params}    pvno=3
        ${cert}=    Get Cert From PKIMessage    ${response}
        ${protection}=   Get From Dictionary    ${args}    protection
        IF  '${protection}' == 'signature'
            VAR   ${exclude_fields}    sender,senderKID
        ELSE
            VAR   ${exclude_fields}    ${None}
        END
        ${cert_conf}=   Build Cert Conf From Resp  ${response}   sender=${sender}
        ...                                         recipient=${recipient}
        ...                                         exclude_fields=${exclude_fields}
        ${cert_conf}=   Default Protect PKIMessage    ${cert_conf}    &{params}
        ${suffix}=    Get From Dictionary    ${params}    suffix    ${None}
        ${protection}=   Get From Dictionary    ${params}    protection
        ${pki_conf}=   Exchange Migration PKIMessage    ${cert_conf}    ${CA_BASE_URL}    ${suffix}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        RETURN    ${cert}
    END

Get Next Common Name
    [Documentation]    Return the common name added with the current test index and increment it afterwards.
    ...                There are may some implementation which only allow one sender name, but other ones may allow
    ...                only one allow a single certificate per name, so to have more flexibility the name is added by a
    ...                number which is incremented after every test case.
    [Tags]    setup
    IF    ${ALLOW_ONLY_ONE_SENDER}    RETURN    ${DEFAULT_X509NAME}
    VAR    ${cm}    ${DEFAULT_X509NAME} ${TestIndex}
    Increase TestIndex
    RETURN    ${cm}

Build Composite Signature Request
    [Documentation]    Build a ir composite signature request and returns the protected ir request.
    [Arguments]    ${comp_key}=${False}   &{params}
    [Tags]    composite-sig    positive   ir
    IF   ${comp_key}
        Log    Using the given composite signature key.
    ELSE
        ${comp_key}=   Generate Default Composite Sig Key
    END
    ${protection}=   Get From Dictionary    ${DEFAULT_PROTECTION_VALS}    protection   signature
    IF  '${protection}' == 'signature'
        VAR   ${exclude_fields}    sender,senderKID
    ELSE
        VAR   ${exclude_fields}    ${None}
    END
    ${cm}=    Get Next Common Name
    ${ir}=   Build Ir From Key    ${comp_key}  common_name=${cm}  sender=${SENDER}
    ...                           recipient=${RECIPIENT}   implicit_confirm=${True}
    ...                           exclude_fields=${exclude_fields}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}    &{params}
    RETURN    ${protected_ir}
    
# TODO maybe Update to create a unique key.
# because some implementations only allow new keys, if for ir or cr is the same key send.

Generate CSR For Testing
    [Documentation]    Generates a certificate signing request for testing purposes, using default parameters
    ...                and an incremented test index.
    ...
    ...                Returns:
    ...                - `csr`: The prepared certificate signing request.
    ...                - `key`: The generated cryptographic key.
    ...
    ...                Examples:
    ...                | ${csr}    ${key}= |    Generate CSR For Testing |
    [Tags]    setup
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${csr}=    Build CSR    signing_key=${key}    common_name=${cm}
    RETURN    ${csr}    ${key}

# TODO maybe change to use serialNumber or both instead for CertTemplate

Generate CertTemplate For Testing
    [Documentation]    Generates a certificate template for testing purposes, using default parameters and an
    ...                incremented test index.
    ...
    ...                Returns:
    ...                - `cert_template`: The prepared certificate template.
    ...                - `key`: The generated cryptographic key.
    ...
    ...                Examples:
    ...                | ${cert_template}    ${key}= |    Generate CertTemplate For Testing |
    ...
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${cert_template}=    Prepare CertTemplate    key=${key}    subject=${cm}
    RETURN    ${cert_template}    ${key}

Generate Default IR Sig Protected
    [Documentation]    Generates a default initialization request (ir) with signature protection.
    ...
    ...                According to RFC 9483 Section 7.1. PKI Management Operations, is the ir body the only
    ...                one which needs to be implemented by the CA and End Entity.
    ...
    ...                Arguments:
    ...                - `transaction_id`:Optional the transaction ID for the IR. Default is `${None}`.
    ...                - `sender_nonce`: Optional the sender's nonce for the IR. Default is `${None}`.
    ...
    ...                Returns:
    ...                - The signature-protected initialization request (ir)
    ...
    ...                Examples:
    ...                | ${protected_ir}=    |    Generate Default IR Sig Protected    | transaction_id=${tx_id} |    sender_nonce=${nonce} |
    ...
    [Arguments]    ${transaction_id}=${None}    ${sender_nonce}=${None}   &{params}
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key
    ...       ${key}
    ...       sender_nonce=${sender_nonce}
    ...       transaction_id=${transaction_id}
    ...       cert_template=${cert_template}
    ...       recipient=${RECIPIENT}
    ...       implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...       exclude_fields=sender,senderKID
    ...       &{params}
    ${protected_ir}=    Protect PKIMessage
    ...                 ${ir}
    ...                 protection=signature
    ...                 private_key=${ISSUED_KEY}
    ...                 cert=${ISSUED_CERT}
    ...                 &{params}
    RETURN    ${protected_ir}

# @Suggested:
# TODO verify, if this function should be introduced.
# TODO update return, if kept to return the key as well, so that both pairs can be
# saved and used to test revocation request with a new certificate so ensure that the test cases
# do not fail, because test cases before failed.
# TODo fix doc

Default Protect With MAC
    [Documentation]    Protect a PKIMessage with the default protection algorithm, set inside the config
    ...                and the default parameters.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to be protected.
    ...
    ...                Returns:
    ...                -------
    ...                - The protected PKIMessage.
    [Arguments]    ${pki_message}
    [Tags]    protection
    ${protected_pki_message}=    Protect PKIMessage    ${pki_message}    ${DEFAULT_MAC_ALGORITHM}
    ...                          password=${PRESHARED_SECRET}
    ...                          for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    RETURN    ${protected_pki_message}


Generate Default MAC Protected PKIMessage
    [Documentation]    Build a PKIMessage used for MAC based protection, based on the config file which are allowed to be used.
    ...
    ...                According to RFC 9483 Section 7.1. PKI Management Operations, is the ir body the only
    ...                one which needs to be implemented by the CA and End Entity. The PKIHeader implicit confirm
    ...                is automatically set, so this message should only be used if all config variables are allowed
    ...                to be used. As an example to test the certificate confirmation message validation.
    ...                The Body is decided, based on the following config variables:
    ...                - (`${ALLOW_IR_MAC_BASED}`)
    ...                - (`${ALLOW_CR_MAC_BASED}`)
    ...
    ...                Arguments:
    ...                - `mac_alg`: The protection algorithm to use. Defaults to the algorithm specified in the config. If `False`
    ...                is parsed, an unprotected message is returned.
    ...
    [Arguments]    ${mac_alg}=${DEFAULT_MAC_ALGORITHM}   ${allow_implicit_confirm}=${ALLOW_IMPLICIT_CONFIRM}
    VAR    ${for_mac}    ${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    IF    ${ALLOW_IR_MAC_BASED}
        # Generate the necessary certificate template and key for IR protection
        ${cert_template}    ${key}=    Generate CertTemplate For Testing
        ${pki_message}=    Build Ir From Key
        ...                ${key}
        ...                cert_template=${cert_template}
        ...                sender=${SENDER}
        ...                recipient=${RECIPIENT}
        ...                implicit_confirm=${allow_implicit_confirm}
        ...                for_mac=${for_mac}
    ELSE IF    ${ALLOW_CR_MAC_BASED}
        ${cert_template}    ${key}=    Generate CertTemplate For Testing
        ${pki_message}=    Build Cr From Key
        ...                ${key}
        ...                cert_template=${cert_template}
        ...                sender=${SENDER}
        ...                recipient=${RECIPIENT}
        ...                implicit_confirm=${allow_implicit_confirm}
        ...                for_mac=${for_mac}
    ELSE
        ${csr}    ${key}=    Generate CSR For Testing
        ${pki_message}=    Build P10cr From CSR
        ...                ${csr}
        ...                sender=${SENDER}
        ...                recipient=${RECIPIENT}
        ...                implicit_confirm=${allow_implicit_confirm}
        ...                for_mac=${for_mac}
    END
    IF   '${mac_alg}' != 'None'
        ${pki_message}=    Protect PKIMessage
        ...                      ${pki_message}
        ...                      password=${PRESHARED_SECRET}
        ...                      protection=${mac_alg}
    ELSE
        ${pki_message}=   Default Protect With MAC   ${pki_message}
    END
    RETURN    ${pki_message}

Issue New Cert For Testing
    [Documentation]    Issue a new certificate to be used in tests. It ensures that a valid certificate
    ...    is available for testing.
    ...
    ...    Returns:
    ...    - `cert`: The issued certificate.
    ...    - `key`: The key used to generate the certificate request.
    [Tags]    setup
    ${cert_template}   ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build IR From Key   ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ...                  implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}    exclude_fields=sender,senderKID
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${ir}
    ${cert}=   Confirm Certificate If Needed    ${response}
    RETURN   ${cert}    ${key}

PKIStatusInfo failinfo Bit Must Be
    [Documentation]       Validates that the given PKIMessage contains the expected `failinfo` bit(s) in the
    ...                   `PKIStatusInfo` field, to ensure that the CA/RA responds with the correct error.
    ...                    The strictness is based on the global `FAILINFO_MUST_BE_CORRECT` variable.
    ...
    ...    Arguments:
    ...    - `pki_message`: The PKIMessage to be validated. Typically, this is the response from the CA/RA.
    ...    - `failinfo`: The expected `failinfo` bit(s) that must be set in the `PKIStatusInfo` field.
    ...    - `exclusive`: When `True`, ensures that no other failinfo bits are set. Defaults to `True`.
    ...    - `index`: Specifies which `PKIStatusInfo` to validate if the message contains multiple. Defaults to `0`.
    [Arguments]    ${pki_message}    ${failinfo}    ${exclusive}=False    ${index}=0
    ${status}=    Get PKIStatusInfo    ${pki_message}    ${index}
    ${result}=    Is Bit Set    ${status["failInfo"]}    ${failinfo}    ${exclusive}
    IF    not ${result}
        IF    ${FAILINFO_MUST_BE_CORRECT}
            Log Asn1    ${status}
            Fail   The failInfo bit was not set correctly.
        ELSE
            LOG   The failInfo bit was not set correctly.
            Log Asn1    ${status}
        END
    END

PKIStatus Must Be
    [Documentation]   Verifies that the `PKIStatus` field in the `PKIMessage` matches the expected value.
    ...
    ...     Arguments:
    ...     - `pki_message`: The PKIMessage to be validated. Typically, this is the response from the CA/RA.
    ...     - `failinfo`: The expected `failinfo` bit(s) that must be set in the `PKIStatusInfo` field.
    ...     - `exclusive`: When `True`, ensures that no other failinfo bits are set. Defaults to `True`.
    ...     - `index`: Specifies which `PKIStatusInfo` to validate if the message contains multiple. Defaults to `0`.
    [Arguments]    ${pki_message}  ${status}   ${index}=0
    ${pki_status}=    Get Status From PKIMessage      ${pki_message}    ${index}
    IF  not '${pki_status}' == '${status}'
        ${pki_status_info}=   Get PKIStatusInfo    ${pki_message}    ${index}
        Fail   The PKIStatus is not as expected. Expected: `${status}`, Got: `${pki_status}`
    END

Exchange Migration PKIMessage
    [Documentation]    Exchange a PKIMessage with the Mock CA
    [Arguments]    ${ir}    ${ca_base_url}=${CA_BASE_URL}    ${suffix}=${NONE}
    ${url} =    Add URL Suffix    ${ca_base_url}    ${suffix}
    ${response} =    Exchange PKIMessage    ${ir}    ${url}
    RETURN    ${response}

Exchange Hybrid PKIMessage
    [Documentation]    Exchange a PKIMessage for a hybrid algorithm certificate.
    ...                Arguments:
    ...                - ${name}: The hybrid algorithm name (e.g., composite-kem).
     ...                - ${pq_name}: The PQ KEM algorithm name (e.g., ml-kem-768, ml-kem-1024).
    ...                - ${trad_name}: The traditional algorithm name (e.g., rsa2048, ecdh-secp384r1, x25519).
    ...                - ${invalid_key_size}: Whether to use an invalid key size. Defaults to `False`.
    ...                - ${extensions}: Additional certificate extensions (default: None).
    ...                - ${optional_args}: Optional key-value pairs to set variables for the protection.
    ...                (for the key generation, the certificate request, and the protection).
    ...                Returns:
    ...                - The response PKIMessage.
    ...                - The key used to generate the request.
    ...                Examples:
    ...                | Exchange Composite KEM PKIMessage | composite-kem | rsa | ml-kem-768 |  length=2048 |
    ...                | Exchange Composite KEM PKIMessage | composite-kem | ecdh | ml-kem-768 |  curve=secp256r1 |
    [Arguments]    ${name}    ${pq_name}    ${trad_name}    ${invalid_key_size}=False    ${extensions}=${None}    &{optional_args}
    ${length}=  Get From Dictionary    ${optional_args}    length   ${None}
    ${curve}=  Get From Dictionary    ${optional_args}    curve   ${None}
    ${key}=   Generate Key    algorithm=${name}    trad_name=${trad_name}    pq_name=${pq_name}    length=${length}    curve=${curve}
    ${cm}=    Get Next Common Name
    ${spki}=  Prepare SubjectPublicKeyInfo    ${key}    invalid_key_size=${invalid_key_size}
    ${use_pre_hash}=   Get From Dictionary    ${optional_args}    use_pre_hash    ${False}
    ${use_rsa_pss}=    Get From Dictionary    ${optional_args}    use_rsa_pss    ${False}
    ${cert_req_msg}=    Prepare CertReqMsg  ${key}  spki=${spki}    common_name=${cm}
    ...           extensions=${extensions}
    ...           use_pre_hash=${use_pre_hash}
    ${ir}=    Build Ir From Key    ${key}    cert_req_msg=${cert_req_msg}    exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${base_url}=   Get From Dictionary    ${optional_args}    base_url    ${CA_BASE_URL}
    ${suffix}=   Get From Dictionary    ${optional_args}    suffix    ${ISSUING_SUFFIX}
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}    ${base_url}    ${suffix}
    RETURN    ${response}   ${key}

Validate EncrCert For KEM
    [Documentation]    Validate that the encrypted certificate for the KEM algorithm is correct.
    ...
    ...                Arguments:
    ...                - ${response}: The response from the CA.
    ...                - ${key}: The key used for the certificate generation.
    ...
    ...                Returns:
    ...                - The certificate.
    ...
    ...                Examples:
    ...                | Validate EncrCert For KEM | ${response} | ${key} |
    [Arguments]    ${response}    ${key}
    PKIStatus Must Be       ${response}    status=accepted
    # currently not validate able, because KEM does not allow to see the
    # the certificate in the response.
    # So the user has to now, if he expected to either has the `rid` set to the SKI or IssuerAndSerialNumber.
    ${cert}=    Get EncCert From PKIMessage    ${response}    ee_private_key=${key}    exclude_rid_check=True
    Validate Kemri Rid For Encrypted Cert    ${response}   key=${key}
    Validate Migration Certificate KeyUsage    ${cert}
    RETURN    ${cert}
