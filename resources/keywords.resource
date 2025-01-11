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
Library             ../resources/cmputils.py
Library             ../resources/utils.py
Library             ../resources/certutils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py


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


*** Keywords ***

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
    [Arguments]    ${payload}
    Log Base64    ${payload}
#    Run Keyword And Ignore Error    Try to Log PKIMessage as ASN1    ${payload}
    Try To Log PKIMessage    ${payload}
    # TODO check if type of payload is a pyasn1 structure, and if it is, der-encode it automatically? Maybe?

    VAR    &{headers}    Content-Type=application/pkixcmp    Accept-Type=application/pkixcmp
    ${response}=    POST
    ...    url=${CA_CMP_URL}
    ...    data=${payload}
    ...    headers=&{headers}
    ...    verify=${False}
    ...    expected_status=any
    Log    ${response.content}
    Log Base64    ${response.content}
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
    [Documentation]    Send a PKIMessage to the CA or RA Server and then then parses the returned PKIMessage.
    ...    Expects to get a parse-able PKIMessage.
    [Tags]    exchange    http
    [Arguments]    ${request_pki_message}
    ${encoded_request}=    Encode To Der    ${request_pki_message}
    Log Base64    ${encoded_request}
    ${response}=    Exchange Data With CA    ${encoded_request}
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

Generate Default Key
    [Documentation]    Generates a default cryptographic key using specified default parameters, set inside the config.
    ...                Examples:
    ...                | ${private_key}=    Generate Default Key |
    ...
    [Tags]    crypto    key
    ${private_key}=    Generate Key
    ...                algorithm=${DEFAULT_ALGORITHM}
    ...                length=${DEFAULT_KEY_LENGTH}
    ...                curve=${DEFAULT_ECC_CURVE}
    # privates keys can not be compared so this work-around.
    ${result}=    Check If Private Key In List    keys=${burned_keys}    new_key=${private_key}
    IF    not ${result}
        Append To List    ${burned_keys}    ${private_key}
        RETURN    ${private_key}
    END

    WHILE    ${1}
        Log    "Generated key is burned. Regenerating..."
        ${private_key}=    Generate Key
        ...                algorithm=${DEFAULT_ALGORITHM}
        ...                length=${DEFAULT_KEY_LENGTH}
        ...                curve=${DEFAULT_ECC_CURVE}
        ${result}=    Check If Private Key In List    keys=${burned_keys}    new_key=${private_key}
        IF    not ${result}    RETURN    ${private_key}
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
    [Arguments]    ${transaction_id}=${None}    ${sender_nonce}=${None}
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key
    ...       ${key}
    ...       sender_nonce=${sender_nonce}
    ...       transaction_id=${transaction_id}
    ...       cert_template=${cert_template}
    ...       recipient=${RECIPIENT}
    ...       implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...       omit_fields=sender,senderKID
    ${protected_ir}=    Protect PKIMessage
    ...                 ${ir}
    ...                 protection=signature
    ...                 private_key=${ISSUED_KEY}
    ...                 cert=${ISSUED_CERT}
    RETURN    ${protected_ir}

# @Suggested:
# TODO verify, if this function should be introduced.
# TODO update return, if kept to return the key as well, so that both pairs can be
# saved and used to test revocation request with a new certificate so ensure that the test cases
# do not fail, because test cases before failed.
# TODo fix doc

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
    [Arguments]    ${mac_alg}=${DEFAULT_MAC_ALGORITHM}
    VAR    ${omit_fields}    ${None}
    IF    ${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
        VAR    ${omit_fields}    sender
    END
    IF    ${ALLOW_IR_MAC_BASED}
        # Generate the necessary certificate template and key for IR protection
        ${cert_template}    ${key}=    Generate CertTemplate For Testing
        ${pki_message}=    Build Ir From Key
        ...                ${key}
        ...                cert_template=${cert_template}
        ...                sender=${SENDER}
        ...                recipient=${RECIPIENT}
        ...                implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
        ...                omit_fields=${omit_fields}
    ELSE IF    ${ALLOW_CR_MAC_BASED}
        ${cert_template}    ${key}=    Generate CertTemplate For Testing
        ${pki_message}=    Build Cr From Key
        ...                ${key}
        ...                cert_template=${cert_template}
        ...                sender=${SENDER}
        ...                recipient=${RECIPIENT}
        ...                implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
        ...                omit_fields=${omit_fields}
    ELSE
        ${csr}    ${key}=    Generate CSR For Testing
        ${pki_message}=    Build P10cr From CSR
        ...                ${csr}
        ...                sender=${SENDER}
        ...                recipient=${RECIPIENT}
        ...                implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
        ...                omit_fields=${omit_fields}
    END
    IF   '${mac_alg}' != 'None'
        ${pki_message}=    Protect PKIMessage
        ...                      ${pki_message}
        ...                      password=${PRESHARED_SECRET}
        ...                      protection=${mac_alg}
    END
    RETURN    ${pki_message}

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
    [Arguments]    ${pki_message}    ${failinfo}    ${exclusive}=True    ${index}=0
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
    Should Be Equal    ${pki_status}    ${status}
