# SPDX-FileCopyrightText: Copyright 2024 Siemens AG   # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
*** Settings ***
Documentation       Keywords are often used for testing.

Resource            ../config/${environment}.robot
# Resource    ../config/local.robot
Library             Collections
Library             DateTime
Library             OperatingSystem
Library             String
Library             RequestsLibrary
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
Library             ../resources/general_msg_utils.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/pq_verify_logic.py

*** Variables ***
${environment}          cloudpki
# ${environment}    local

# This variable is a collector of nonces that the server sent back to us throughout all the tests. In the end we use
# it to check that the server is not sending the same nonce twice, and that the nonces are cryptographically secure.
@{COLLECTED_NONCES}     @{EMPTY}
@{COLLECTED_KEYS}       @{EMPTY}
${TEST_INDEX}            ${0}
@{BURNED_KEYS}          @{EMPTY}
&{CERT_CONF_DEF_VALS}   sender=${SENDER}    recipient=${RECIPIENT}
...        private_key=${ISSUED_KEY}    cert=${ISSUED_CERT}
...        password=${PRESHARED_SECRET}    protection=signature

*** Keywords ***
Set Up Test Suite
    [Documentation]    This keyword is used to set up the test suite. It is called at the beginning of the test suite.
    ...                Or a test file to ensure that all prerequisites are met. As an example a first certificate is
    ...                issued, and the key is generated to be used for the tests. This ensure that a trusted
    ...                certificate is present, which will be used to issue further certificates. This method was
    ...                chosen to allow to set a certificate, which is not firstly configured, but generated with
    ...                the test suite. If `MAC` protection is allowed, the shared secret will be used to issue the
    ...                first certificate `ISSUED_KEY` and `ISSUED_CERT`. This ensure that the test suite can be run
    ...                without the modification of the database. If the `MAC` protection is not allowed, the
    ...                `ISSUED_KEY` and `ISSUED_CERT` are issued with the **MUST** be set default certificate and key.
    ...                If this behaviour is not wanted, the `ISSUED_KEY` and `ISSUED_CERT` can be set in the
    ...                configuration file, and will then be loaded from there.
    [Tags]    setup
    IF  '${ISSUED_KEY}' == '${None}'
        Initialize PQ Cert And Key Variables
        ${issued_key}=    Generate Default Key
        IF    ${ALLOW_MAC_PROTECTION}
            ${extensions}=    Prepare Extensions    digitalSignature,keyEncipherment
            ${ir}=  Build Ir From Key    ${issued_key}    sender=${SENDER}    recipient=${RECIPIENT}
            ...     for_mac=True   implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}   extensions=${extensions}
            ${protected_ir}=    Protect PKIMessage    ${ir}    password=${PRESHARED_SECRET}
            ...                 protection=${DEFAULT_MAC_ALGORITHM}
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
        VAR    ${ISSUED_KEY}    ${issued_key}    scope=Global     # robocop: off=VAR04
        VAR    ${ISSUED_CERT}    ${issued_cert}    scope=Global   # robocop: off=VAR04
        LOG    Initial certificate issued, with `MAC` protection.
        ${cert_chain}=   Build CMP Chain From PKIMessage  ${response}   ee_cert=${ISSUED_CERT}
        Write Certs To Dir    ${cert_chain}
        ${root_cert}=   Get From List   ${cert_chain}  -1
        Write Cmp Certificate To Pem    ${root_cert}  data/trustanchors/issued_cert_root.pem
        VAR    &{CERT_CONF_DEF_VALS}    sender=${SENDER}    recipient=${RECIPIENT}
        ...    private_key=${ISSUED_KEY}    cert=${ISSUED_CERT}    password=${PRESHARED_SECRET}
        ...    protection=signature   scope=Global   # robocop: off=VAR04
        VAR    &{DEFAULT_PROTECTION_VALS}    protection=signature   private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERT}   password=${PRESHARED_SECRET}  scope=Global  # robocop: off=VAR04
    END
    ${cert}  ${key}=   May Load Cert And Key    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    VAR    ${OTHER_TRUSTED_PKI_CERT}    ${cert}    scope=Global  # robocop: off=VAR04
    VAR    ${OTHER_TRUSTED_PKI_KEY}    ${key}    scope=Global    # robocop: off=VAR04
    TRY
        Set Up CRR Test Cases
    EXCEPT
        Log    Failed to setup the CCR required certificate and signing key.
    END
    TRY
        Set Up Trusted PKI RA Cert Chain
    EXCEPT
        Log    Failed to setup the trusted PKI RA certificate chain.
    END

Initialize PQ Cert And Key Variables
    [Documentation]    Initialize the variables for the PQ certificate and key, to store freshly issued
    ...                certificates and keys. So that those certificates can be used to issue further certificates.
    ...                Additionally used, to verify if the PKIProtection is working as expected.
    [Tags]    setup  keys   setup-global-dict
    # Initialize the newly issued certificates and keys.
    VAR   &{PQ_SIG_CERTS}  scope=Global
    VAR   &{PQ_SIG_KEYS}   scope=Global
    VAR   &{PQ_STATEFUL_SIG_KEYS}     scope=Global
    # Used for the verbose STFL signature keys.
    VAR   &{PQ_STATEFUL_SIG_KEYS_VERBOSE}     scope=Global
    VAR   &{PQ_STATEFUL_SIG_CERTS_VERBOSE}   scope=Global
    VAR   &{PQ_STATEFUL_SIG_CERT_CONF_CERTS}    scope=Global
    Load PQ Stateful Sig Keys
    Load Verbose PQ Stateful Sig Keys

Get PQ Stateful Sig Key
    [Documentation]    Get the stateful PQ signature key from the global variable.
    ...                If the key is not set, it will be generated and returned.
    [Tags]    keys
    [Arguments]    ${algorithm}
    ${key}=    Get From Dictionary   ${PQ_STATEFUL_SIG_KEYS}   ${algorithm}   ${None}
    IF  '${key}' == '${None}'
        Log     PQ Stateful keys: '${PQ_STATEFUL_SIG_KEYS}'
        Fail    The PQ stateful signature key for algorithm '${algorithm}' is not set.
        ${key}=    Generate Unique Key    ${algorithm}
        Set To Dictionary    ${PQ_STATEFUL_SIG_KEYS}    ${algorithm}=${key}
    END
    RETURN   ${key}
    
Get PQ Stateful Sig Key Verbose
    [Documentation]    Get the stateful PQ signature key from the global variable in verbose mode.
    ...                If the key is not set, it will be generated and returned.
    [Tags]    keys
    [Arguments]    ${algorithm}   ${body_name}    ${reason}
    ${name}=    Set Variable    ${algorithm}_${body_name}_${reason}
    ${key}=    Get From Dictionary   ${PQ_STATEFUL_SIG_KEYS_VERBOSE}   ${name}   ${None}
    IF  '${key}' == '${None}'
        Fail    The verbose ${body_name} PQ stateful signature key for algorithm '${algorithm}' is not set, for 
        ...     the reason ${reason}.
    END
    RETURN    ${key}

Load PQ Stateful Sig Keys
    [Documentation]    Load every stateful PQ-signature private key in the `data/keys/xmss_xmssmt_keys` directory.
    ...                Keys are appended to the global list `${BURNED_KEYS}` and
    ...                stored in the dictionary `${PQ_STATEFUL_SIG_KEYS}` under
    ...                their algorithm names (e.g. `xmss-sha2_20_256`).
    [Tags]    setup  keys
    VAR    ${directory}    data/keys/xmss_xmssmt_keys
    ${files}=    List Files In Directory    ${directory}
    VAR  ${empty}
    FOR  ${key_file}  IN  @{files}
        ${key_name}=   Replace String     ${key_file}   _layers_    /
        ${algorithm}=   Replace String    ${key_name}   .pem    ${empty}
        ${algorithm}=   Replace String    ${algorithm}   private-key-   ${empty}
        ${key_path}=    Set Variable    ${directory}/${key_file}
        ${is_file}=    Run Keyword And Return Status    OperatingSystem.File Should Exist    ${key_path}
        IF  ${is_file}
            ${key}=    Load Private Key From File    ${key_path}
            Append To List    ${BURNED_KEYS}    ${key}
            Set To Dictionary    ${PQ_STATEFUL_SIG_KEYS}    ${algorithm}=${key}
        END
    END
    
Load Verbose PQ Stateful Sig Keys
    [Documentation]    Load every stateful PQ-signature private key in the `data/keys/xmss_xmssmt_keys` directory.
    ...                Keys are appended to the global list `${BURNED_KEYS}` and
    ...                stored in the dictionary `${PQ_STATEFUL_SIG_KEYS}` under
    ...                their algorithm names (e.g. `xmss-sha2_20_256`).
    ...                This keyword is used to load the keys in verbose mode, which means that the keys are
    ...                loaded with the `verbose=True` parameter. This is useful for debugging purposes.
    [Tags]    setup  keys
    [Arguments]
    VAR    ${directory}    data/keys/xmss_xmssmt_keys_verbose
    ${files}=    List Files In Directory    ${directory}
    VAR  ${empty}
    FOR  ${key_file}  IN  @{files}
        ${key_name}=   Replace String     ${key_file}   _layers_    /
        ${algorithm}=   Replace String    ${key_name}   .pem    ${empty}
        ${algorithm}=   Replace String    ${algorithm}   private-key-   ${empty}
        ${key_path}=    Set Variable    ${directory}/${key_file}
        ${is_file}=    Run Keyword And Return Status    OperatingSystem.File Should Exist    ${key_path}
        IF  ${is_file}
            ${key}=    Load Private Key From File    ${key_path}
            Append To List    ${BURNED_KEYS}    ${key}
            Set To Dictionary    ${PQ_STATEFUL_SIG_KEYS_VERBOSE}    ${algorithm}=${key}
        END
    END


Set Up CRR Test Cases
    [Documentation]    Prepare the environment variables for the Cross-Certification Request (CRR) tests.
    ...                By loading the trusted CA credentials and chain. Is required to correctly protect a
    ...                `PKIMessage` with the trusted CA certificate and key, so that a CRR certificate can
    ...                be issued.
    ...
    ...                Notes:
    ...                -----
    ...                - The trusted CA certificate and key are loaded from the configuration file.
    ...                - Variables `TRUSTED_CA_CERT`, `TRUSTED_CA_KEY`, and `TRUSTED_CA_KEY_PASSWORD`.
    ...
    ...                Raises:
    ...                ------
    ...                - `Error`: When the trusted CA certificate or key cannot be loaded.
    ...
    ...               Examples:
    ...               --------
    ...               | Set Up CRR Test Cases |
    ...
    [Tags]    setup  trust   ccr
    ${cert}=   May Load Cert   ${TRUSTED_CA_CERT}
    ${key}=    Load Private Key From File    ${TRUSTED_CA_KEY}   password=${TRUSTED_CA_KEY_PASSWORD}
    VAR   ${TRUSTED_CA_CERT_OBJ}    ${cert}  scope=Global
    VAR   ${TRUSTED_CA_KEY_OBJ}     ${key}  scope=Global
    ${cert_chain}=  Build Cert Chain From Dir    ${cert}   ${TRUSTED_CA_DIR}
    VAR   ${TRUSTED_CA_CERT_CHAIN}   ${cert_chain}   scope=Global

Set UP Trusted PKI RA Cert Chain
    [Documentation]    Load the trusted PKI RA certificate chain into global variables.
    ...                Use when tests rely on a preexisting RA certificate chain. As an example, the
    ...                nested PKIMessage tests require to be protected by a trusted PKI RA certificate chain,
    ...                or the POPO `raVerified` option requires a trusted RA certificate to have established
    ...                a trust relationship with sender.
    ...
    ...                Notes:
    ...                ----
    ...                - The trusted PKI RA certificate chain is loaded from the configuration file.
    ...                - Variables `OTHER_TRUSTED_PKI_CERT`, `OTHER_TRUSTED_PKI_KEY`, and `RA_CERT_CHAIN_PATH`.
    ...
    ...                Raises:
    ...                ------
    ...                - Error: When the RA certificate chain cannot be loaded.
    ...
    ...                Examples:
    ...                --------
    ...                | Set Up Trusted PKI RA Cert Chain |
    ...
    [Tags]    setup  trust   RA
    ${is_file}=    Run Keyword And Return Status    OperatingSystem.File Should Exist    ${OTHER_TRUSTED_PKI_KEY}
    IF  ${is_file}
        ${der_cert}=    Load And Decode PEM File    ${OTHER_TRUSTED_PKI_CERT}
        ${cert}=   Parse Certificate    ${der_cert}
        ${key}=    Load Private Key From File   ${OTHER_TRUSTED_PKI_KEY}
        VAR    ${OTHER_TRUSTED_PKI_CERT}    ${cert}    scope=Global
        VAR    ${OTHER_TRUSTED_PKI_KEY}    ${key}    scope=Global
    END
    VAR   ${INNER_CERT}    ${ISSUED_CERT}    scope=Global
    VAR   ${INNER_KEY}    ${ISSUED_KEY}    scope=Global
    IF  '${RA_CERT_CHAIN_PATH}' == '${None}'
        ${cert_chain}=   Build Cert Chain From Dir    ${OTHER_TRUSTED_PKI_CERT}   ${RA_CERT_CHAIN_DIR}
    ELSE
        ${cert_chain}=   Load Certificate Chain     ${RA_CERT_CHAIN_PATH}
    END
    VAR   ${RA_CERT_CHAIN}    ${cert_chain}    scope=Global

Increase TestIndex
    [Documentation]    Perform the incrementation of the `TestIndex` to update the sender name inside the PKIMessage,
    ...                for each test case.
    ${NUMBER}=    Evaluate    ${TEST_INDEX} + 1
    VAR    ${TEST_INDEX}    ${NUMBER}    scope=Global   # robocop: off=VAR04

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
    ...
    ...            Arguments:
    ...            ---------
    ...            - `path` (string): PEM file path.
    ...            - `transaction_id` (bytes): New transaction ID. Default to `None`, which means a 16-byte random value.
    ...            - `message_time` (datetime): New message time. Default to `None`, which means \
    ...            the current time will be used.
    ...
    ...            Returns:
    ...            -------
    ...            - The updated/loaded PKIMessage object.
    ...
    ...            Raises:
    ...            ------
    ...            - `FileNotFoundError`: When the PEM file is missing.
    ...            - `ValueError`: When the file content cannot be parsed as a PKIMessage.
    ...
    ...            Examples:
    ...            --------
    ...            | ${pki_message}= | Load And Refresh PKIMessage From File | ${path} |
    ...            | ${pki_message}= | Load And Refresh PKIMessage From File | ${path} |  0x001122 |
    ...            | ${pki_message}= | Load And Refresh PKIMessage From File | ${path} | ${transaction_id} | ${message_time} |
    ...
    [Arguments]    ${path}    ${transaction_id}=${NONE}    ${message_time}=${NONE}
    ${raw}=    Load And Decode Pem File    ${path}
    ${pki_message}=    Parse PKIMessage    ${raw}
    Log Asn1    ${pki_message}
    ${pki_message}=    Patch TransactionID    ${pki_message}    ${transaction_id}
    ${pki_message}=    Patch MessageTime    ${pki_message}    ${message_time}
    RETURN    ${pki_message}

Generate CSR With RSA2048 And A Predefined Common Name
    [Documentation]    Generate an RSA‑2048 key and produce a signed CSR with the default subject name.
    ...
    ...                Returns:
    ...                -------
    ...                - The signed RSA CSR object.
    ...
    ...                Raises:
    ...                ------
    ...                - `valueError`: When the key generation.
    ...
    ...                Examples:
    ...                --------
    ...                | ${csr_signed}= | Generate CSR With RSA2048 And A Predefined Common Name |
    ...
    ${key}=    Generate Unique Key    rsa    length=2048
    ${csr}=    Build CSR    ${DEFAULT_X509NAME}    exclude_signature=True
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    Log    ${csr_signed}
    RETURN    ${csr_signed}

Load And Parse Example CSR
    [Documentation]    Load a CSR from a PEM file, and return it as a pyasn1 object. This is for convenience, to remove
    ...    the need to generate a new keypair.
    ...
    ...                Returns:
    ...                -------
    ...                - The parsed `pyasn1` CSR object.
    ...
    ...                Raises:
    ...                ------
    ...                - `FileNotFoundError`: When the example CSR file is missing.
    ...                - `ValueError`: When the CSR cannot be parsed.
    ...
    ...                Examples:
    ...                --------
    ...                | ${parsed_csr}= | Load And Parse Example CSR |
    ...
    [Tags]    csr  setup  predefined
    ${csr}=    Load And Decode Pem File    data/example-csr.pem
    ${parsed_csr}=    Parse Csr    ${csr}
    RETURN    ${parsed_csr}

Exchange Data With CA
    [Documentation]    Send a HTTP POST request to a server, and return the response.
    ...
    ...                Arguments:
    ...                ---------
    ...                - payload (bytes): Data to send in the request.
    ...                - url (string): Target CMP endpoint. Defaults to `${CA_CMP_URL}`.
    ...
    ...                Returns:
    ...                -------
    ...                - The response from the server, which is a `requests.Response` object.
    ...
    ...                Examples:
    ...                --------
    ...                | ${response}= | Exchange Data With CA | ${payload} | ${url} |
    ...
    [Tags]    exchange    http
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
    ...
    ...                Arguments:
    ...                ---------
    ...                - `request` (PKIMessage): Original request message.
    ...                - `response` (PKIMessage): Response message from the server.
    ...
    ...                Raises:
    ...                ------
    ...                - AssertionError: When the nonces differ.
    ...
    ...                Examples:
    ...                --------
    ...                | Sender And Recipient Nonces Must Match | ${request} | ${response} |
    ...
    [Tags]    nonce
    [Arguments]    ${request}    ${response}
    ${request_nonce}=    Get Asn1 Value As Bytes    ${request}    header.senderNonce
    ${response_nonce}=    Get Asn1 Value As Bytes    ${response}    header.recipNonce
    Should Be Equal    ${request_nonce}    ${response_nonce}

Response Time Must Be Fresh
    [Documentation]    Ensure that the response time is not far off from the time of our request
    ...    The tolerance is given in seconds, and defaults to 120 (i.e., 2 minutes)
    ...                Arguments:
    ...                ---------
    ...                - `request` (PKIMessage): Sent message.
    ...                - `response` (PKIMessage): Received message.
    ...                - `tolerance` (str, int): Allowed difference in seconds. Defaults to `120` seconds.
    ...
    ...                Raises:
    ...                ------
    ...                - `AssertionError`: When the time difference exceeds the tolerance.
    ...
    ...                Examples:
    ...                --------
    ...                | Response Time Must Be Fresh | ${request} | ${response} |
    ...                | Response Time Must Be Fresh | ${request} | ${response} | 60 |
    ...
    [Tags]    time
    [Arguments]    ${request}    ${response}    ${tolerance}=${120}
    ${request_time}=    Get Asn1 Value As Datetime    ${request}    header.messageTime
    ${response_time}=    Get Asn1 Value As Datetime    ${response}    header.messageTime

    ${delta_verbose}=    Subtract Date From Date    ${response_time}    ${request_time}    verbose
    ${delta}=    Subtract Date From Date    ${response_time}    ${request_time}
    Should Be True    ${delta} < ${tolerance}    Time between request and response exceeds tolerance

SenderNonce Must Be At Least 128 Bits Long
    [Documentation]    Ensure that the senderNonce of a PKIMessage is at least 128 bits long
    ...    Ref: 3.1. General Description of the CMP Message Header.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message` (PKIMessage): Message to validate.
    ...
    ...                Raises:
    ...                ------
    ...                - `AssertionError`: When the nonce is shorter than 16 bytes.
    ...
    ...                Examples:
    ...                --------
    ...                | SenderNonce Must Be At Least 128 Bits Long | ${pki_message} |
    ...
    [Tags]    crypto  nonce
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
    ...
    ...    Arguments:
    ...    ---------
    ...    - `cert` (bytes, CMPCertificate): The DER-encoded certificate or `CMPCertificate` object to validate.
    ...
    ...    Examples:
    ...    --------
    ...    | Certificate Must Be Valid | ${cert} |
    ...
    [Tags]    cert   validate
    [Arguments]    ${cert}
    Log Base64    ${cert}
    # If OpenSSL complains, we fail the test
    Validate Certificate OpenSSL    ${cert}
    # Use PKILint to check the certificate for issues, https://github.com/digicert/pkilint
    # If PKILint complains, we log a warning, but keep going
    Run Keyword And Warn On Failure
    ...    Validate Certificate PKILint    ${cert}

Validate Certificate Was Issued For Expected Alg
    [Documentation]    Validate that the certificate was issued for the expected algorithm.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `response` (PKIMessage): The PKIMessage response.
    ...                - `expected_alg` (str): The expected algorithm identifier (e.g., 'ml-dsa-44').
    ...                - `index` (str, int): The index of the certificate in the PKIMessage. Defaults to `0`.
    ...
    ...                Raises:
    ...                ------
    ...                - `ValueError`: When the algorithm does not match.
    ...
    ...                Examples:
    ...                | Validate Certificate Was Issued For Expected Alg | ${response} | ml-dsa-44 |
    ...                | Validate Certificate Was Issued For Expected Alg | ${response} | ml-dsa-44 | 1 |
    [Arguments]    ${response}    ${expected_alg}    ${index}=0
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=    Get Cert From PKIMessage    ${response}    ${index}
    Validate Migration OID In Certificate    ${cert}    ${expected_alg}

Generate Key And CSR
    [Documentation]    Generate a fresh private key and a signed Certificate Signing Request (CSR)
    ...                for the given algorithm and subject. The CSR is returned in DER format.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `key_algo_name` (string): Name of the key algorithm.
    ...                - `CN` (string): Common Name for the CSR subject.
    ...                - `key_params` (dict, mapping): Algorithm‑specific parameters.
    ...
    ...                Returns:
    ...                -------
    ...                - The CRS data in DER format.
    ...                - Generated private key.
    ...
    ...                Raises:
    ...                ------
    ...                - `ValueError`: When key generation or CSR creation fails.
    ...
    ...                Examples:
    ...                --------
    ...                | ${csr_data}  ${key}= | Generate Key And CSR | rsa | ${cn} | length=2048 |
    ...
    [Tags]    csr  crypto  key
    [Arguments]    ${key_algo_name}    ${cn}    ${key_params}
    ${key}=    Generate Unique Key   ${key_algo_name}    ${key_params}
    ${csr_signed}    ${key}=    Generate Signed CSR    ${cn}    ${key}
    ${csr_data}=    Decode Pem String    ${csr_signed}
    RETURN    ${csr_data}    ${key}

PKIMessage Body Type Must Be
    [Documentation]    Ensure that the response type in a PKIMessage is of a certain type.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message` (PKIMessage): Message to check.
    ...                - `expected_type` (string): Required body type.
    ...
    ...                Raises:
    ...                ------
    ...                - `AssertionError`: When the body type differs.
    ...
    ...                Examples:
    ...                --------
    ...                | PKIMessage Body Type Must Be | ${pki_message} | error |
    ...
    [Tags]    body_type
    [Arguments]    ${pki_message}    ${expected_type}
    ${response_type}=    Get CMP Message Type    ${pki_message}
    IF    '${response_type}' != '${expected_type}'
        # For better logging.
        ${pki_status_info}=    Get PKIStatusInfo    ${pki_message}   # robocop: off=VAR02
    END
    Should Be Equal    ${response_type}    ${expected_type}    Response type mismatch

PKIMessage Contains ImplicitConfirm Extension
    [Documentation]    Checks if the implicitConfirm extension is present in the PKIMessage
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message` (PKIMessage): The PKIMessage object to check.
    ...
    ...                Returns:
    ...                -------
    ...                - `True` if the implicitConfirm extension is present, `False` otherwise.
    ...
    ...                Examples:
    ...                ------
    ...                | ${result}= | PKIMessage Contains ImplicitConfirm Extension | ${pki_message} |
    ...
    [Tags]    confirmation
    [Arguments]    ${pki_message}
    ${result}=    Find OID In GeneralInfo    ${pki_message}    1.3.6.1.5.5.7.4.13
    RETURN    ${result}

PKIMessage Must Contain ImplicitConfirm Extension
    [Documentation]    Ensure the given PKIMessage contains the implicitConfirm extension in its header.generalInfo.
    ...                Used to verify that the server supports implicit confirmation.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage object to check.
    ...
    ...                Raises:
    ...                ------
    ...                - `AssertionError`: When the implicitConfirm extension is not found.
    ...
    ...                Examples:
    ...                --------
    ...                | PKIMessage Must Contain ImplicitConfirm Extension | ${pki_message} |
    ...
    [Tags]    confirmation
    [Arguments]    ${pki_message}
    ${result}=    PKIMessage Contains ImplicitConfirm Extension    ${pki_message}
    Should Be True    ${result}    The implicitConfirm extension was not found in the message

Collect Nonce From PKIMessage
    [Documentation]    Extract the senderNonce from a PKIMessage and append it to a list, which will be used later
    ...    in a test that checks for nonces to be cryptographically strong. Used to ensure that the server does not
    ...   send the same nonce twice, and that the nonces are cryptographically secure.
    ...
    ...                Notes:
    ...                -----
    ...                - The keyword does not return anything, but appends the nonce to the
    ...                `COLLECTED_NONCES` list.
    ...                - Only collect the nonces from messages that are of set in the config variable \
    ...                `GATHER_NONCES_FROM_MSG_BODIES`.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message` (PKIMessage): The PKIMessage object to extract the nonce from.
    ...
    ...                Examples:
    ...                --------
    ...                | Collect Nonce From PKIMessage | ${pki_message} |
    ...
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
    ...
    ...                Arguments:
    ...                ---------
    ...                - `request_pki_message` (PKIMessage): The PKIMessage to send.
    ...                - `url` (str): The URL of the CA or RA server to send the PKIMessage to. Defaults to
    ...                  `CA_CMP_URL`.
    ...
    ...                Returns:
    ...                -------
    ...                - The parsed PKIMessage response from the server.
    ...
    ...                Examples:
    ...                --------
    ...                | ${response_pki_message}= | Exchange PKIMessage | ${request_pki_message} | ${url} |
    ...                | ${response_pki_message}= | Exchange PKIMessage | ${request_pki_message} |
    ...
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
    ...                Notes:
    ...                -----
    ...                 - `BURNED_KEYS` is a list of keys that have been generated
    ...
    ...                Arguments:
    ...                ---------
    ...                - `algorithm` (string): The algorithm to use for key generation (e
    ...                g., 'rsa', 'ecc').
    ...                - `params` (dict, mapping): Additional parameters for key generation, such as `length` or `curve`.
    ...                - `max_attempts` (int): Maximum number of attempts to generate a unique key. Defaults to `100`.
    ...
    ...                Examples:
    ...                | ${key}=    Generate Unique Key | rsa | length=2048 |
    [Tags]    key  crypto
    [Arguments]    ${algorithm}    &{params}
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
    ...                Notes:
    ...                ----
    ...                 - `DEFAULT_ALGORITHM` defines the algorithm.
    ...                 - `DEFAULT_KEY_LENGTH` defines the key length for RSA.
    ...                 - `DEFAULT_ECC_CURVE` defines the curve for ECC. Not relevant for X25519 or X448.
    ...                 Then must the `DEFAULT_ALGORITHM` be set to `x25519` or `x448`.
    ...
    ...                Examples:
    ...                --------
    ...                | ${private_key}=    Generate Default Key |
    [Tags]    key
    VAR     &{params}    length=${DEFAULT_KEY_LENGTH}    curve=${DEFAULT_ECC_CURVE}
    ${private_key}=    Generate Unique Key    algorithm=${DEFAULT_ALGORITHM}    &{params}
    RETURN    ${private_key}

Generate Default PQ SIG Key
    [Documentation]    Generates a default pq signature key. Set by the configuration (``DEFAULT_PQ_SIG_ALGORITHM``).
    ...
    ...                Examples:
    ...                --------
    ...                | ${key}= | Generate Default PQ SIG Key |
    [Tags]    key   pqc
    ${key}=   Generate Key    ${DEFAULT_PQ_SIG_ALGORITHM}
    RETURN    ${key}

Generate Default PQ KEM Key
    [Documentation]    Generates a default cryptographic pq key encapsulation mechanism (KEM) key.
    ...                Set by the configuration (`DEFAULT_PQ_KEM_ALGORITHM`).
    ...
    ...                Examples:
    ...                --------
    ...                | ${key}= | Generate Default PQ KEM Key |
    [Tags]    key   pqc  KEM
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
    ...                Notes:
    ...                -----
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
    VAR   &{params}  trad_name=${DEFAULT_TRAD_ALG}
    ...              length=${DEFAULT_KEY_LENGTH}    curve=${DEFAULT_ECC_CURVE}
    ...              pq_name=${DEFAULT_PQ_SIG_ALG}
    # Generates always the latest (supported) version of the algorithm.
    ${key}=      Generate Unique Key    algorithm=composite-sig    &{params}
    RETURN     ${key}

Default Protect PKIMessage
    [Documentation]    Protect a PKIMessage with the default protection algorithm, set inside the config
    ...                and the default parameters.
    ...
    ...                Notes:
    ...                ----
    ...                - The protection algorithm is set to `signature` by default.
    ...
    ...                Arguments:
    ...                ---------
    ...                 - `pki_message` (PKIMessage): The PKIMessage to protect.
    ...                 - `params` (dict, mapping): key=value pair to set variables for the protection.
    ...
    ...                Returns:
    ...                -------
    ...                - The protected PKIMessage.
    ...
    ...                Examples:
    ...                --------
    ...                | ${prot_pkimessage}=    Default Protect PKIMessage    | ${pki_message} |
    ...
    [Tags]    protection
    [Arguments]    ${pki_message}    &{params}
    ${length}=   Get Length   ${params}
    IF  not ${length}
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
    ...                confirm extension. If it does, the certificate is confirmed and returned. If not, the
    ...                `PKIMessage` a valid certificate confirmation message is send and the of the CA's response is
    ...                checked. If the CA's response is the `PKIMessage` `pkiconf`, then is the certificate confirmed.
    ...
    ...                Arguments:
    ...                ---------
    ...                 - `response` (PKIMessage): The response message from the CA.
    ...                 - `params` (dict, mapping): key=value pair to set variables for the protection.
    ...
    ...                Returns:
    ...                -------
    ...                - The confirmed certificate.
    ...
    ...                Examples:
    ...                --------
    ...                | ${cert}= | Confirm Certificate If Needed | ${response} | &{params} |
    ...
    [Tags]    confirm   default   cert
    [Arguments]    ${response}    &{params}
    ${result}=   PKIMessage Contains ImplicitConfirm Extension    ${response}
    IF    ${result}
        Log    The PKIMessage contains the implicit confirm extension.
        ${cert}=    Get Cert From PKIMessage    ${response}
        RETURN    ${cert}
    ELSE
        Log    The PKIMessage does not contain the implicit confirm extension.
        ${length}=   Get Length   ${params}
        IF  not ${length}
            ${args}=    Copy Dictionary    ${CERT_CONF_DEF_VALS}
        ELSE
            ${args}=    May Patch Params   ${params}    &{CERT_CONF_DEF_VALS}
        END
        ${params}=    May Patch Params    ${params}    pvno=3   # robocop: off=VAR08
        ${cert}=    Get Cert From PKIMessage    ${response}
        ${protection}=   Get From Dictionary    ${args}    protection
        IF  '${protection}' == 'signature'
            VAR   ${exclude_fields}    sender,senderKID
            VAR   ${for_mac}    ${False}
        ELSE
            VAR   ${exclude_fields}    ${None}
            VAR   ${for_mac}    ${True}
        END
        ${cert_req_id}=    Get From Dictionary    ${args}    cert_req_id   ${None}
        ${cert_conf}=   Build Cert Conf From Resp  ${response}   sender=${sender}
        ...                                         recipient=${recipient}
        ...                                         exclude_fields=${exclude_fields}
        ...                                         cert_req_id=${cert_req_id}
        ...                                         for_mac=${for_mac}
        ${cert_conf}=   Default Protect PKIMessage    ${cert_conf}    &{params}
        ${suffix}=    Get From Dictionary    ${params}    suffix    ${None}
        ${base_url}=    Get From Dictionary    ${params}    base_url    ${CA_BASE_URL}
        ${url}=    Get From Dictionary    ${params}    url    ${None}
        IF    '${url}' == '${None}'
            ${url}=    Get From Dictionary    ${params}    url    ${base_url}
        END
        ${pki_conf}=   Exchange Migration PKIMessage    ${cert_conf}    ${url}    ${suffix}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
        RETURN    ${cert}
    END

Confirm EncrCert Certificate If Needed
    [Documentation]    Some Test cases need a valid certificate to work. Because not all CA's might support the
    ...                implicit confirm extension, this keyword checks if the given `PKIMessage` contains the implicit
    ...                confirm extension. If it does, the certificate is confirmed and returned. First decrypt the
    ...                certificate with the given private key. If the implicit confirm extension is present, will a
    ...                valid certificate confirmation message be sent and the CA's response is checked. If the CA's
    ...                response is the `PKIMessage` `pkiconf`, then is the certificate confirmed.
    ...
    ...                Arguments:
    ...                ---------
    ...                 - `response`: The response message from the CA.
    ...                 - `ee_key`: The private key to decrypt the certificate.
    ...                 - `params`: key=value pair to set variables for the protection.
    ...
    ...                Returns:
    ...                -------
    ...                - `cert`: The confirmed certificate.
    ...
    ...                Examples:
    ...                --------
    ...                | ${cert}= | Confirm EncrCert Certificate If Needed | ${response} | ${ee_key} | &{params} |
    ...
    [Tags]    confirm   default   cert
    [Arguments]    ${response}    ${ee_key}    &{params}
    PKIStatus Must Be    ${response}    accepted
    ${result}=   PKIMessage Contains ImplicitConfirm Extension    ${response}
    ${exclude_rid_check}=    Get From Dictionary    ${params}    exclude_rid_check    ${False}
    ${expected_recip_type}=    Get From Dictionary    ${params}    expected_recip_type    ${None}
    ${cert}=    Get EncCert From PKIMessage    ${response}   ee_private_key=${ee_key}   exclude_rid_check=${exclude_rid_check}
    ...          expected_recip_type=${expected_recip_type}
    IF  ${result}  RETURN   ${cert}
    ${cert_req_id}=    Get From Dictionary    ${params}    cert_req_id   ${None}
    ${for_mac}=    Get From Dictionary    ${params}    for_mac   ${False}
    ${for_kem_based_mac}=    Get From Dictionary    ${params}    for_kem_based_mac   ${False}
    IF  ${for_mac}
        VAR   ${exclude_fields}    ${None}
    ELSE IF   ${for_kem_based_mac}
        VAR   ${for_mac}    ${True}
        VAR   ${exclude_fields}    ${None}
    ELSE
        VAR   ${exclude_fields}    sender,senderKID
    END
    ${cert_conf}=   Build Cert Conf From Resp  ${response}   cert=${cert}   recipient=${recipient}   pvno=3
    ...             sender=${SENDER}   for_mac=${for_mac}     cert_req_id=${cert_req_id}    exclude_fields=${exclude_fields}

    IF  ${for_kem_based_mac}
        ${ss}=   Get From Dictionary    ${params}    shared_secret
                ${protected_cert_conf}=  Protect PKIMessage KEMBasedMAC     ${cert_conf}    shared_secret=${ss}
    ELSE IF  ${for_mac}
        ${protected_cert_conf}=  Default Protect With MAC    ${cert_conf}
    ELSE
        ${protected_cert_conf}=  Default Protect PKIMessage    ${cert_conf}    &{params}
    END
    ${suffix}=    Get From Dictionary    ${params}    suffix    ${None}
    ${base_url}=    Get From Dictionary    ${params}    base_url    ${CA_BASE_URL}
    ${url}=    Get From Dictionary    ${params}    url    ${None}
    IF    '${url}' == '${None}'
        ${url}=    Get From Dictionary    ${params}    url    ${base_url}
    END
    ${pki_conf}=   Exchange Migration PKIMessage    ${cert_conf}    ${url}    ${suffix}
    PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    RETURN    ${cert}

Get Next Common Name
    [Documentation]    Return the common name added with the current test index and increment it afterwards.
    ...                There are may some implementation which only allow one sender name, but other ones may allow
    ...                only one allow a single certificate per name, so to have more flexibility the name is added by a
    ...                number which is incremented after every test case.
    ...
    ...                Returns:
    ...                -------
    ...                - `cm`: The common name with the current test index.
    ...
    ...                Examples:
    ...                --------
    ...                | ${cm}= | Get Next Common Name |
    ...
    [Tags]    setup
    IF    ${ALLOW_ONLY_ONE_SENDER}    RETURN    ${DEFAULT_X509NAME}
    VAR    ${cm}    ${DEFAULT_X509NAME} ${TEST_INDEX}
    Increase TestIndex
    RETURN    ${cm}

Build Composite Signature Request
    [Documentation]    Build a ir composite signature request and returns the protected ir request.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `comp_key`: Optional composite signature key to use. Default is `False`. \
    ...                If `False`, a default composite signature key is generated.
    ...                - `params` (dict, mapping): Optional key-value pairs to set parameters for the request.
    ...
    ...                Returns:
    ...                -------
    ...                - The protected initialization request (ir) with, an composite signature.
    ...
    ...                Examples:
    ...                --------
    ...                | ${protected_ir}= | Build Composite Signature Request | ${comp_key} | &{params} |
    ...                | ${protected_ir}= | Build Composite Signature Request | ${comp_key} |
    ...                | ${protected_ir}= | Build Composite Signature Request |
    ...
    [Tags]    composite-sig    positive   ir
    [Arguments]    ${comp_key}=${False}   &{params}
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
    ...                -------
    ...                - `csr`: The prepared certificate signing request.
    ...                - `key`: The generated cryptographic key.
    ...
    ...                Examples:
    ...                --------
    ...                | ${csr}    ${key}= |    Generate CSR For Testing |
    [Tags]    setup  csr
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
    ...                -------
    ...                - `cert_template`: The prepared certificate template.
    ...                - `key`: The generated cryptographic key.
    ...
    ...                Examples:
    ...                --------
    ...                | ${cert_template}    ${key}= |    Generate CertTemplate For Testing |
    ...
    [Tags]    setup  CertTemplate
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${cert_template}=    Prepare CertTemplate    key=${key}    subject=${cm}
    RETURN    ${cert_template}    ${key}

Generate CCR CertTemplate For Testing
    [Documentation]    Generates a cross-certificate req. certificate template for testing purposes,
    ...                using default parameters and an incremented test index.
    ...
    ...               Arguments:
    ...               ---------
    ...               - `key`: Optional key to use for the certificate template. Default is `None`. \
    ...               If `None`, a default key is generated.
    ...               - `cm`: Optional common name to use for the certificate template. Default is `None`. \
    ...               If `None`, a common name is generated based on the current test index.
    ...
    ...                Returns:
    ...                -------
    ...                - `cert_template`: The prepared certificate template.
    ...                - `key`: The generated cryptographic key.
    ...
    ...                Examples:
    ...                --------
    ...                | ${cert_template}    ${key}= |    Generate CertTemplate For Testing |
    ...                | ${cert_template}    ${key}= |    Generate CCR CertTemplate For Testing |    ${key}    |
    ...                | ${cert_template}    ${key}= |    Generate CCR CertTemplate For Testing |    ${key}   | ${cm} |
    ...
    [Tags]    setup  CertTemplate  ccr
    [Arguments]  ${key}=${None}   ${cm}=${None}
    IF  '${key}' == '${None}'
        ${key}=    Generate Default Key
    END
    IF    $cm is None
        ${cm}=    Get Next Common Name
    END
    ${sig_alg}=   Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    # -1 day
    ${date}=   Get Current Date   UTC   increment=-86400
    ${date_after}=   Get Current Date  UTC  increment=10000000
    ${validity}=   Prepare Validity   ${date}   ${date_after}
    ${cert_template}=  Prepare CertTemplate   ${key}    validity=${validity}   subject=${cm}   issuer=${SENDER}
    ...       sign_alg=${sig_alg}    version=v3  include_fields=subject,issuer,validity,publicKey,version,signingAlg
    RETURN    ${cert_template}    ${key}

Generate Default IR Sig Protected
    [Documentation]    Generates a default initialization request (ir) with signature protection.
    ...
    ...                According to RFC 9483 Section 7.1. PKI Management Operations, is the ir body the only
    ...                one which needs to be implemented by the CA and End Entity.
    ...
    ...                Arguments:
    ...                ----------
    ...                - `transaction_id` (str, bytes) :Optional the transaction ID for the IR. Default is `None`.
    ...                - `sender_nonce` (str, bytes): Optional the sender's nonce for the IR. Default is `None`.
    ...                - `params` (dict, mapping): Optional key-value pairs to set additional parameters for the IR.
    ...
    ...                Returns:
    ...                -------
    ...                - The signature-protected initialization request (ir)
    ...
    ...                Examples:
    ...                | ${protected_ir}=    |    Generate Default IR Sig Protected    | transaction_id=${tx_id} |    \
    ...                sender_nonce=${nonce} |
    ...
    [Tags]    ir    signature   setup
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
    ...                - `pki_message` (PKIMessage): The PKIMessage to be protected.
    ...
    ...                Returns:
    ...                -------
    ...                - The protected PKIMessage.
    ...
    ...                Examples:
    ...                --------
    ...                | ${protected_pki_message}= | Default Protect With MAC | ${pki_message} |
    ...
    [Tags]    protection  MAC
    [Arguments]    ${pki_message}
    ${protected_pki_message}=    Protect PKIMessage    ${pki_message}    ${DEFAULT_MAC_ALGORITHM}
    ...                          password=${PRESHARED_SECRET}
    ...                          for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    RETURN    ${protected_pki_message}

Default Protect PKIMessage With Trusted CA Cert
    [Documentation]    Protects the PKIMessage with the trusted CA certificate. used for
    ...                Cross-Certification Requests (CCR) tests.
    ...
    ...                Arguments:
    ...                ----------
    ...                - `pki_message` (PKIMessage): The PKIMessage to be protected.
    ...
    ...                Returns:
    ...                -------
    ...                - The protected PKIMessage.
    ...
    ...                Examples:
    ...                --------
    ...                | ${response}= | Default Protect PKIMessage With Trusted CA Cert | ${pki_message} |
    ...
    [Tags]    protection  trust  signature  CA
    [Arguments]    ${pki_message}
    ${response}=  Protect PKIMessage    ${pki_message}    signature
    ...           private_key=${TRUSTED_CA_KEY_OBJ}    cert_chain=${TRUSTED_CA_CERT_CHAIN}
    RETURN    ${response}

Default Protect With Trusted Cert
    [Documentation]    Protect a PKIMessage with the default signature protection.
    ...
    ...                Arguments:
    ...                ----------
    ...                - `pki_message` (PKIMessage): The PKIMessage to be protected.
    ...
    ...                Returns:
    ...                -------
    ...                - The protected PKIMessage.
    ...
    ...                Examples:
    ...                --------
    ...                | ${protected}= | Default Protect With Trusted Cert | ${pki_message} |
    ...
    [Tags]    protection  trust  signature
    [Arguments]    ${pki_message}
    ${protected}=    Protect PKIMessage    ${pki_message}    signature   private_key=${OTHER_TRUSTED_PKI_KEY}
    ...              cert_chain=${RA_CERT_CHAIN}
    RETURN    ${protected}

Generate Default MAC Protected PKIMessage
    [Documentation]    Build a PKIMessage used for MAC based protection, based on the config file
    ...                which are allowed to be used.
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
    ...                - `mac_alg`: The protection algorithm to use. Defaults to the algorithm specified in the config.
    ...                If `False` is parsed, an unprotected message is returned.
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
        ${csr}    ${_}=    Generate CSR For Testing
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
    ...    Arguments:
    ...    ---------
    ...    - `url` (str): The URL of the CA to send the request to. Defaults to `${CA_CMP_URL}`.
    ...    - `key` (PrivateKey): The key to use for the certificate request. If not provided, \
    ...    a new default key will be generated.
    ...
    ...    Returns:
    ...    -------
    ...    - `cert`: The issued certificate.
    ...    - `key`: The key used to generate the certificate request.
    ...
    ...    Examples:
    ...    --------
    ...    | ${cert}  ${key}= | Issue New Cert For Testing |
    ...    | ${cert}  ${key}= | Issue New Cert For Testing | ${url} |
    ...    | ${cert}  ${key}= | Issue New Cert For Testing | ${url} | ${key} |
    ...
    [Tags]    setup
    [Arguments]    ${url}=${CA_CMP_URL}    ${key}=${None}
    IF    '${key}' == '${None}'
        ${cert_template}   ${key}=    Generate CertTemplate For Testing
    ELSE
        VAR   ${cert_template}   ${None}
    END
    ${ir}=    Build IR From Key   ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ...                  implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}    exclude_fields=sender,senderKID
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}   ${url}
    PKIStatus Must Be   ${response}   accepted
    ${cert}=   Confirm Certificate If Needed    ${response}
    RETURN   ${cert}    ${key}

Issue And Revoke A Fresh Cert
    [Documentation]    Issue a new certificate and then revoke it. This is useful for testing purposes.
    ...                The function ensures that a valid certificate is available for testing.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `reason` (str): The reason for revocation. Defaults to `keyCompromise`.
    ...
    ...                Returns:
    ...                -------
    ...                - `cert`: The revoked certificate.
    ...                - `key`: The revoked key
    [Tags]    setup  revocation
    [Arguments]    ${reason}=keyCompromise
    ${cert}    ${key}=   Issue New Cert For Testing
    ${rr}=   Build CMP Revoke Request   ${cert}   recipient=${RECIPIENT}   reason=${reason}
    ${protected_rr}=   Default Protect PKIMessage    ${rr}
    ${protected_rr}=   Protect PKIMessage    ${protected_rr}    protection=signature
    ...                                         private_key=${key}    cert=${cert}
    ${response}=   Exchange PKIMessage    ${protected_rr}
    PKIMessage Body Type Must Be   ${response}   rp
    PKIStatus Must Be   ${response}   accepted
    RETURN   ${cert}    ${key}

PKIStatusInfo failinfo Bit Must Be
    [Documentation]       Validates that the given PKIMessage contains the expected `failinfo` bit(s) in the
    ...                   `PKIStatusInfo` field, to ensure that the CA/RA responds with the correct error.
    ...                    The strictness is based on the global `FAILINFO_MUST_BE_CORRECT` variable.
    ...
    ...
    ...    Notes:
    ...    -----
    ...    - If the `failinfo` bit(s) are invalid logs the `PKIStatusInfo` in a human-readable format.
    ...    - If `FAILINFO_MUST_BE_CORRECT` is `True`, the keyword will fail if the `failinfo` bit is not set correctly.
    ...    - If `FAILINFO_MUST_BE_CORRECT` is `False`, the keyword will log a warning instead of failing.
    ...
    ...    Arguments:
    ...    ---------
    ...    - `pki_message` (PKIMessage): The PKIMessage to be validated. Typically, this is the response from the CA/RA.
    ...    - `failinfo` (str, int): The expected `failinfo` bit(s) that must be set in the `PKIStatusInfo` field.
    ...    - `exclusive` (bool): When `True`, ensures that no other failinfo bits are set. Defaults to `True`.
    ...    - `index` (str, int): Specifies which `PKIStatusInfo` to validate if the message contains multiple. Defaults to `0`.
    ...
    ...    Raises:
    ...    ------
    ...    - `ValueError`: If the `pki_message` does not contain a `PKIStatusInfo` object.
    ...    - `ValueError`: If the `failinfo` bit is not set correctly.
    ...
    ...    Examples:
    ...    --------
    ...    | PKIStatusInfo failinfo Bit Must Be | ${pki_message} | failinfo=badAlg |
    ...    | PKIStatusInfo failinfo Bit Must Be | ${pki_message} | failinfo=badAlg | exclusive=True |
    ...
    [Arguments]    ${pki_message}    ${failinfo}    ${exclusive}=False    ${index}=0
    ${status}=    Get PKIStatusInfo    ${pki_message}    ${index}
    ${result}=    Is Bit Set    ${status["failInfo"]}    ${failinfo}    ${exclusive}
    IF    not ${result}
        IF    ${FAILINFO_MUST_BE_CORRECT}
            ${_}=   Display PKIStatusInfo   ${status}
            Fail   The failInfo bit was not set correctly.
        ELSE
            LOG   The failInfo bit was not set correctly.
            ${_}=   Display PKIStatusInfo   ${status}
        END
    END

PKIStatus Must Be
    [Documentation]   Verifies that the `PKIStatus` field in the `PKIMessage` matches the expected value.
    ...
    ...     Arguments:
    ...     ---------
    ...     - `pki_message` (PKIMessage): The PKIMessage to be validated. Typically, this is the response from the CA/RA.
    ...     - `failinfo` (str, int): The expected `failinfo` bit(s) that must be set in the `PKIStatusInfo` field.
    ...     - `exclusive` (bool): When `True`, ensures that no other failinfo bits are set. Defaults to `True`.
    ...     - `index` (str, int): Specifies which `PKIStatusInfo` to validate if the message contains multiple. Defaults to `0`.
    ...
    ...     Raises:
    ...     ------
    ...     - `ValueError`: If the `pki_message` does not contain a `PKIStatusInfo` object.
    ...     - `ValueError`: If the `PKIStatus` does not match the expected value.
    ...
    ...     Examples:
    ...     --------
    ...     | PKIStatus Must Be | ${pki_message} | accepted |
    ...     | PKIStatus Must Be | ${pki_message} | rejected | 1
    ...
    [Arguments]    ${pki_message}  ${status}   ${index}=0
    ${pki_status}=    Get Status From PKIMessage      ${pki_message}    ${index}
    IF  not '${pki_status}' == '${status}'
        ${pki_status_info}=   Display PKIStatusInfo    ${pki_message}    ${index}   # robocop: off=VAR02
        Fail   The PKIStatus is not as expected. Expected: `${status}`, Got: `${pki_status}`
    END

Exchange Migration PKIMessage
    [Documentation]    Exchange a PKIMessage with the Mock CA
    [Arguments]    ${ir}    ${ca_base_url}=${CA_BASE_URL}    ${suffix}=${NONE}
    ${url}=    Add URL Suffix    ${ca_base_url}    ${suffix}
    ${response}=    Exchange PKIMessage    ${ir}    ${url}
    RETURN    ${response}

Exchange Hybrid PKIMessage
    [Documentation]    Exchange a PKIMessage for a hybrid algorithm certificate.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `name` (str): The hybrid algorithm name (e.g., composite-kem).
    ...                - `pq_name` (str): The PQ KEM algorithm name (e.g., ml-kem-768, ml-kem-1024).
    ...                - `trad_name` (str): The traditional algorithm name (e.g., rsa2048, ecdh-secp384r1, x25519).
    ...                - `invalid_key_size` (bool): Whether to use an invalid key size. Defaults to `False`.
    ...                - `extensions` (Extensions): Additional certificate extensions (default: None).
    ...                - `optional_args` (dict, mapping): Optional key-value pairs to set variables for the protection.
    ...                (for the key generation, the certificate request, and the protection).
    ...
    ...                Returns:
    ...                -------
    ...                - The response PKIMessage.
    ...                - The key used to generate the request.
    ...
    ...                Examples:
    ...                --------
    ...                | ${response} ${key}= | Exchange Composite KEM PKIMessage | composite-kem | rsa | ml-kem-768 |  length=2048 |
    ...                | ${response} ${key}= | Exchange Composite KEM PKIMessage | composite-kem | ecdh | ml-kem-768 |  curve=secp256r1 |
    ...
    [Arguments]    ${name}    ${pq_name}    ${trad_name}    ${invalid_key_size}=False    ${extensions}=${None}    &{optional_args}
    ${length}=  Get From Dictionary    ${optional_args}    length   ${None}
    ${curve}=  Get From Dictionary    ${optional_args}    curve   ${None}
    ${key}=   Generate Key    algorithm=${name}    trad_name=${trad_name}    pq_name=${pq_name}
    ...       length=${length}    curve=${curve}
    ${cm}=    Get Next Common Name
    ${spki}=  Prepare SubjectPublicKeyInfo    ${key}    invalid_key_size=${invalid_key_size}
    ${use_pre_hash}=   Get From Dictionary    ${optional_args}    use_pre_hash    ${False}
    ${use_rsa_pss}=    Get From Dictionary    ${optional_args}    use_rsa_pss    ${False}
    ${cert_req_msg}=    Prepare CertReqMsg  ${key}  spki=${spki}    common_name=${cm}
    ...           extensions=${extensions}
    ...           use_pre_hash=${use_pre_hash}
    ...           use_rsa_pss=${use_rsa_pss}
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
    ...                ---------
    ...                - `response` (PKIMessage): The response from the CA.
    ...                - `key` (KEMPrivateKey): The key used for the certificate generation.
    ...
    ...                Returns:
    ...                -------
    ...                - The certificate.
    ...
    ...                Examples:
    ...                --------
    ...                | ${cert} | Validate EncrCert For KEM | ${response} | ${key} |
    ...
    [Tags]    envelopedData  KEM  validate  cert
    [Arguments]    ${response}    ${key}
    PKIStatus Must Be       ${response}    accepted
    # currently not validate able, because KEM does not allow to see the
    # the certificate in the response.
    # So the user has to now, if he expected to either has the `rid` set to the SKI or IssuerAndSerialNumber.
    ${cert}=    Get EncCert From PKIMessage    ${response}    ee_private_key=${key}    exclude_rid_check=True
    Validate KEMRI Rid For Encrypted Cert    ${response}   key=${key}
    Validate Migration Certificate KeyUsage    ${cert}
    RETURN    ${cert}

Issued NEG RSA KTRI CERT
    [Documentation]    Issue a new RSA negative KTRI certificate for the EnvelopedData tests.
    ...                This certificate is negative, because the keyEncipherment KeyUsage bit is missing.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `url` (str): The URL to the CA CMP server. Defaults to `${CA_CMP_URL}`.
    ...
    ...                Notes:
    ...                -----
    ...                - Set's the ${NEG_KTRI_CERT} and ${NEG_KTRI_KEY} variables.
    ...
    [Tags]    envelopedData  KGA  negative  rsa  ktri
    [Arguments]    ${url}=${CA_CMP_URL}
    ${is_set}=    Is Certificate And Key Set    ${NEG_KTRI_CERT}    ${NEG_KTRI_KEY}
    IF  ${is_set}   RETURN
    ${key}=   Generate Key    rsa   length=${DEFAULT_KEY_LENGTH}
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions  digitalSignature
    ${ir}=  Build Ir From Key    ${key}   ${cm}   extensions=${extensions}
    ...    exclude_fields=sender,senderKID   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Confirm Certificate If Needed    ${response}  url=${url}
    Must Not Contain KeyUsage    ${cert}   keyEncipherment
    VAR   ${NEG_KTRI_CERT}     ${cert}  scope=Global  # robocop: off=VAR04
    VAR   ${NEG_KTRI_KEY}      ${key}   scope=Global  # robocop: off=VAR04

ISSUE POS RSA KTRI Cert
    [Documentation]    Issue a new RSA positive KTRI certificate for the EnvelopedData tests.
    ...                This certificate is positive, because the keyEncipherment and digitalSignature
    ...                KeyUsage bits are set.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `url` (str): The URL to the CA CMP server. Defaults to `${CA_CMP_URL}`.
    ...
    ...                Notes:
    ...                -----
    ...                - Set's the ${KGA_KTRI_CERT} and ${KGA_KTRI_KEY} variables.
    ...
    [Tags]    envelopedData  KGA  positive  rsa  ktri
    [Arguments]    ${url}=${CA_CMP_URL}
    ${is_set}=    Is Certificate And Key Set    ${KGA_KTRI_CERT}    ${KGA_KTRI_KEY}
    IF   ${is_set}   RETURN
    ${key}=   Generate Key    rsa   length=${DEFAULT_KEY_LENGTH}
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions  keyEncipherment,digitalSignature
    ${ir}=  Build Ir From Key    ${key}   ${cm}  extensions=${extensions}
    ...    exclude_fields=sender,senderKID   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Confirm Certificate If Needed    ${response}  url=${url}
    VAR   ${KGA_KTRI_CERT}     ${cert}  scope=Global  # robocop: off=VAR04
    VAR   ${KGA_KTRI_KEY}      ${key}   scope=Global  # robocop: off=VAR04

Issue NEG ECC KARI Cert
    [Documentation]    Issue a new ECC negative KARI certificate for the EnvelopedData tests.
    ...                This certificate is negative, because the keyAgreement KeyUsage bit is missing.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `url` (str): The URL to the CA CMP server. Defaults to `${CA_CMP_URL}`.
    ...
    ...                Notes:
    ...                -----
    ...               - Set's the ${NEG_KARI_CERT} and ${NEG_KARI_KEY} variables.
    ...
    [Tags]    envelopedData  KGA  negative  ecc  kari
    [Arguments]    ${url}=${CA_CMP_URL}
    ${is_set}=    Is Certificate And Key Set    ${NEG_KARI_CERT}    ${NEG_KARI_KEY}
    IF  ${is_set}   RETURN
    ${key}=   Generate Key    ecc   curve=${DEFAULT_ECC_CURVE}
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions  digitalSignature
    ${ir}=  Build Ir From Key    ${key}   ${cm}   extensions=${extensions}
    ...    exclude_fields=sender,senderKID   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Confirm Certificate If Needed    ${response}  url=${url}
    Must Not Contain KeyUsage    ${cert}   keyAgreement
    VAR   ${NEG_KARI_CERT}     ${cert}  scope=Global   # robocop: off=VAR04
    VAR   ${NEG_KARI_KEY}      ${key}   scope=Global   # robocop: off=VAR04

Issue POS ECC KARI Cert   # robocop: off=LEN03
    [Documentation]    Issue a new ECC positive KARI certificate for the EnvelopedData tests.
    ...                This certificate is positive, because the keyAgreement and digitalSignature
    ...                KeyUsage bits are set.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `url` (str): The URL to the CA CMP server. Defaults to `${CA_CMP_URL}`.
    ...
    ...                Notes:
    ...                -----
    ...                - Set's the ${KGA_KARI_CERT} and ${KGA_KARI_KEY} variables.
    ...
    [Tags]    envelopedData  KGA  positive  ecc  kari
    [Arguments]    ${url}=${CA_CMP_URL}
    ${is_set}=    Is Certificate And Key Set    ${KGA_KARI_CERT}    ${KGA_KARI_KEY}
    IF   ${is_set}   RETURN
    ${key}=   Generate Key    ecc   curve=${DEFAULT_ECC_CURVE}
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions  keyAgreement,digitalSignature
    ${ir}=  Build Ir From Key    ${key}   ${cm}  extensions=${extensions}
    ...    exclude_fields=sender,senderKID   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Confirm Certificate If Needed    ${response}  url=${url}
    VAR   ${KGA_KARI_CERT}     ${cert}  scope=Global   # robocop: off=VAR04
    VAR   ${KGA_KARI_KEY}      ${key}   scope=Global   # robocop: off=VAR04

Set Up EnvelopedData Certs For Tests
    [Documentation]    Set up the KGA certs for the tests. This is done by creating a new key and
    ...               certificate for the KGA. Currently only RSA and ECC are supported.
    [Tags]    setup   envelopedData   KGA
    Issued NEG RSA KTRI CERT
    Issue POS RSA KTRI Cert
    Issue NEG ECC KARI Cert
    Issue POS ECC KARI Cert

Wait Until Server Revoked Cert
    [Documentation]    Wait time until the server revoked a certificate so that testing can be begin.
    Sleep    ${REVOKED_WAIT_TIME}

Wait Until Server Updated Cert
    [Documentation]    Wait time until the server updated a certificate so that testing can be begin.
    ...                Needed in some cases, if a updated certificate is treated as a revoked certificate,
    ...                so that no new certificates can be issued.
    Sleep    ${UPDATE_WAIT_TIME}

Wait Until Server Revived Cert
    [Documentation]    Wait time until the server revived a certificate so that testing can be begin.
    Sleep    ${REVOKED_WAIT_TIME}

Wait Until Server Deletes Update Request
    [Documentation]    Wait time until the server deleted a update request, which was not confirmed.
    ...                Needed to raise awareness that the request was not confirmed and how the implementation
    ...                handles the request. Should raise awareness that if a requests was not confirmed,
    ...                that the request handles it as a revoked certificate or successfully does not
    ...                marks it as a revoked certificate.
    Sleep    ${WAIT_UNTIL_UPDATED_CONFIRMATION_IS_EXPIRED}

Get PQ Issuing URL
    [Documentation]    Return the URL for the PQ issuing endpoint.
    ...
    ...                Returns:
    ...                -------
    ...                - The URL for the PQ issuing endpoint.
    ...
    ...                Examples:
    ...                --------
    ...                | ${url}= |    Get PQ Issuing URL |
    ...
    [Tags]    pqc
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${PQ_ISSUING_SUFFIX}
    RETURN  ${url}

Get PQ Stateful Issuing URL
    [Documentation]    Return the URL for the PQ stateful issuing endpoint.
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${PQ_STATEFUL_ISSUING_SUFFIX}
    RETURN  ${url}

Get Composite Issuing URL
    [Documentation]    Return the URL for the composite issuing endpoint.
    ...
    ...                Returns:
    ...                -------
    ...                - The URL for the composite issuing endpoint.
    ...
    ...                Examples:
    ...                --------
    ...                | ${url}= |    Get Composite Issuing URL |
    ...
    [Tags]   composite   hybrid
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    RETURN  ${url}

Prepare Related Cert URL
    [Documentation]    Prepare the URL for the related certificate, by adding the serial number to the URL.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `cert` (CMPCertificate): The certificate to extract the serial number from.
    ...
    ...                Returns:
    ...                -------
    ...                - The URL for the related certificate.
    ...
    ...                Examples:
    ...                --------
    ...                | ${url}= |    Prepare Related Cert URL    | ${cert} |
    ...
    [Tags]    related-cert   hybrid-cert
    [Arguments]    ${cert}
    ${ser_num}=   Get Asn1 Value As Number    ${cert}   tbsCertificate.serialNumber  False
    ${url}=   Add URL Suffix    ${URI_RELATED_CERT}   ${ser_num}
    RETURN  ${url}

Get Related Cert URL
    [Documentation]    Get the URL for the related certificate issuing endpoint, to send the request to.
    ...
    ...                Returns:
    ...                -------
    ...                - The URL for the related certificate issuing endpoint.
    ...
    ...                Examples:
    ...                --------
    ...                | ${url}= |    Get Related Cert URL |
    ...
    [Tags]    related-cert   hybrid-cert
    ${url}=   Add URL Suffix    ${CA_BASE_URL}   ${RELATED_CERT_SUFFIX}
    RETURN  ${url}

Setup PQ Sig Cert
    [Documentation]    Issue a new PQ signature certificate for the tests.
    ...                This certificate is used for the signature and used to save the
    ...                certificate chain for the correct request.
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=    Get Next Common Name
    ${extensions}=  Prepare Extensions  digitalSignature
    IF  ${ALLOW_MAC_PROTECTION}
        VAR   ${protection}    ${DEFAULT_MAC_ALGORITHM}
        ${ir}=  Build Ir From Key    ${pq_key}   ${cm}   extensions=${extensions}
        ...     recipient=${RECIPIENT}   sender=${sender}   for_mac=True
        ${prot_ir}=    Default Protect With MAC      ${ir}
    ELSE
        VAR   ${protection}    signature
        ${ir}=  Build Ir From Key    ${pq_key}   ${cm}   extensions=${extensions}
        ...     recipient=${RECIPIENT}   exclude_fields=sender,senderKID
        ${prot_ir}=    Default Protect PKIMessage    ${ir}
    END
    ${url}=  Get PQ Issuing URL
    ${response}=    Exchange PKIMessage    ${prot_ir}   url=${url}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${pq_cert}=   Confirm Certificate If Needed    ${response}   url=${url}   protection=${protection}
    ${cert_chain}=   Build CMP Chain From PKIMessage    ${response}  ${pq_cert}
    Write Certs To Dir    ${cert_chain}  pq_sig_chain
    VAR   ${PQ_SIG_CERT}     ${pq_cert}  scope=Global  # robocop: off=VAR04
    VAR   ${PQ_SIG_KEY}      ${pq_key}  scope=Global  # robocop: off=VAR04

Setup Composite Sig Cert
    [Documentation]    Issue a new composite signature certificate for the tests.
    ...                This certificate is used for the signature and used to save the
    ...                certificate chain for the correct request. Always uses the latest
    ...                composite signature version.
    ${comp_key}=   Generate Unique Key    composite-sig
    ${cm}=    Get Next Common Name
    ${url}=   Get Composite Issuing URL
    ${extensions}=  Prepare Extensions  digitalSignature
    IF  ${ALLOW_MAC_PROTECTION}
        VAR   ${protection}    ${DEFAULT_MAC_ALGORITHM}
        ${ir}=  Build Ir From Key    ${comp_key}   ${cm}   extensions=${extensions}
        ...     recipient=${RECIPIENT}   sender=${sender}   for_mac=True
        ${prot_ir}=    Default Protect With MAC      ${ir}
    ELSE
        VAR   ${protection}    signature
        ${ir}=  Build Ir From Key    ${comp_key}   ${cm}   extensions=${extensions}
        ...     recipient=${RECIPIENT}   exclude_fields=sender,senderKID
        ${prot_ir}=    Default Protect PKIMessage    ${ir}
    END
    ${response}=    Exchange PKIMessage    ${prot_ir}   url=${url}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${comp_cert}=   Confirm Certificate If Needed    ${response}   url=${url}   protection=${protection}
    ${cert_chain}=   Build CMP Chain From PKIMessage    ${response}  ${comp_cert}
    Write Certs To Dir    ${cert_chain}  composite_sig_chain
    VAR   ${COMPOSITE_SIG_CERT}     ${comp_cert}  scope=Global  # robocop: off=VAR04
    VAR   ${COMPOSITE_SIG_KEY}      ${comp_key}  scope=Global  # robocop: off=VAR04

Build KEMBasedMAC General Message
    [Documentation]    Build a KEMBasedMAC General Message, to establish a KEM shared secret.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `kem_key` (KEMPrivateKey): The KEM key to use for the message.
    ...                - `kem_cert` (CMPCertificate): The KEM certificate to use for the message.
    ...                - `random_value` (str, bytes) : Optional random value to use for the message, for negative tests.
    ...                The `infoValue` field **MUST** be absent.
    ...
    ...                Returns:
    ...                -------
    ...                - The built KEMBasedMAC General Message.
    ...
    ...                Examples:
    ...                --------
    ...                | ${genm}= |    Build KEMBasedMAC General Message    | ${kem_key} | ${kem_cert} |
    ...                | ${genm}= |    Build KEMBasedMAC General Message    | ${kem_key} | ${kem_cert} | ${random_value} |
    ...
    [Tags]    KEM   genm
    [Arguments]    ${kem_key}    ${kem_cert}   ${random_value}=${None}
    ${info_val}=    Prepare KEMCiphertextInfo   ${kem_key}    ${random_value}
    ${genm}=   Build CMP General Message   info_values=${info_val}
    ...        sender=${SENDER}   recipient=${RECIPIENT}
    ${cert_chain}=   Build Cert Chain From Dir    ${kem_cert}     cert_chain_dir=./data/cert_logs
    ${genm}=   Patch ExtraCerts    ${genm}    ${cert_chain}
    RETURN    ${genm}
