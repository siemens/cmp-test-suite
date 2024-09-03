*** Variables ***
${environment}    cloudpki
#${environment}    local

*** Settings ***
Resource         ../config/${environment}.robot
#Resource         ../config/local.robot
#Resource         ../config/local.robot


Library   RequestsLibrary
Library   OperatingSystem
Library   DateTime
Library   Collections
Library   ../resources/asn1utils.py
Library   ../resources/cryptoutils.py
Library   ../resources/cmputils.py
Library   ../resources/utils.py
Library   ../resources/certutils.py
Library   ../resources/keyutils.py


*** Keywords ***
Try to Log PKIMessage as ASN1
    [Documentation]    Tentatively parse a buffer, assuming it is a DER-encoded PKIMessage, and log its contents.
    ...                If that is not the case, ignore this and keep going. This is for convenience in logging.
    ...                DEPRECATED in favour of `try_to_log_pkimessage' in Python, which is more concise.
    [Tags]             robot:flatten
    [Arguments]         ${payload}
    ${pki_message}=     Parse Pki Message    ${payload}
    Log Asn1            ${pki_message}


Load and refresh PKIMessage from file
    [Documentation]    Load a PKIMessage from a PEM file, update its transactionId and messageTime, and return it
    ...                as a pyasn1 object. This is useful when sending previously sent messages, the CA will reject
    ...                them if the time is not fresh or if the transactionId is not unique.
    [Arguments]        ${path}    ${transaction_id}=${NONE}    ${message_time}=${NONE}
    ${raw}=            Load And Decode Pem File    ${path}
    ${pki_message}=    Parse Pki Message    ${raw}
    Log Asn1           ${pki_message}
    ${pki_message}=    Patch transaction id   ${pki_message}    ${transaction_id}
    ${pki_message}=    Patch message time     ${pki_message}    ${message_time}
    RETURN             ${pki_message}




Generate CSR with RSA2048 and a predefined common name
    [Documentation]    Produce a generic, valid CSR that has a correct signature
    ${key}=    Generate key    rsa    length=2048
    ${csr}=    Generate CSR    ${DEFAULT_X509NAME}
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    Log    ${csr_signed}
    RETURN    ${csr_signed}


Load and parse example CSR
    [Documentation]    Load a CSR from a PEM file, and return it as a pyasn1 object.  This is for convenience, to remove
    ...                the need to generate a new keypair.
    ${csr}=  Load And Decode Pem File    data/example-csr.pem
    ${parsed_csr}=     Parse Csr    ${csr}
    RETURN             ${parsed_csr}

Exchange data with CA
    [Documentation]    Send a HTTP POST request to a server, and return the response.
    [Arguments]     ${payload}
    Log Base64    ${payload}
#    Run Keyword And Ignore Error     Try to Log PKIMessage as ASN1    ${payload}
    Try to Log PKIMessage    ${payload}
    # TODO check if type of payload is a pyasn1 structure, and if it is, der-encode it automatically? Maybe?

    &{headers}=     Create Dictionary    Content-Type=application/pkixcmp    Accept-Type=application/pkixcmp
    ${response}=    POST    url=${CA_CMP_URL}     data=${payload}    headers=&{headers}     verify=${False}     expected_status=any
    Log             ${response.content}
    Log base64      ${response.content}
    Try to Log PKIMessage    ${response.content}
    RETURN        ${response}

Sender and Recipient nonces must match
    [Documentation]     Ensure that the recipient nonce in the response matches the sender nonce in the request
    [Arguments]         ${request}    ${response}
    ${request_nonce}=   Get Asn1 Value As Bytes    ${request}  header.senderNonce
    ${response_nonce}=  Get Asn1 Value As Bytes    ${response}  header.recipNonce
    Should Be Equal     ${request_nonce}    ${response_nonce}


Response time must be fresh
    [Documentation]     Ensure that the response time is not far off from the time of our request
    ...                 The tolerance is given in seconds, and defaults to 120 (i.e., 2 minutes)
    [Arguments]         ${request}    ${response}   ${tolerance}=${120}
    ${request_time}=    Get Asn1 Value as datetime     ${request}   header.messageTime
    ${response_time}=   Get Asn1 Value as datetime     ${response}  header.messageTime

    ${delta_verbose}=   Subtract Date From Date    ${response_time}    ${request_time}     verbose
    ${delta}=           Subtract Date From Date    ${response_time}    ${request_time}
    Should Be True      ${delta} < ${tolerance}    Time between request and response exceeds tolerance


Protection algorithms must match
    [Documentation]    Ensure that the protection algorithms in the request and response match
    ...                Ref: 1.6. Compatibility with Existing CMP Profiles
    [Tags]    consistency   crypto
    [Arguments]         ${request}    ${response}
    ${request_algo}=    Get Asn1 Value    ${request}    header.protectionAlg.algorithm
    ${response_algo}=   Get Asn1 Value    ${response}   header.protectionAlg.algorithm
    Should be equal     ${request_algo}   ${response_algo}      Protection algorithm mismatch, we sent ${request_algo}, we got ${response_algo}
    # TODO also check the parameters, if any


Protection must be valid
    [Documentation]     Ensure that the protection in the PKIMessage is cryptographically valid
    [Arguments]         ${pki_message}
    # TODO
    No Operation



SenderNonce must be at least 128 bits long
    [Documentation]    Ensure that the senderNonce of a PKIMessage is at least 128 bits long
    ...                Ref: 3.1. General Description of the CMP Message Header
    [Tags]    crypto
    [Arguments]         ${pki_message}
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${pki_message}   header.senderNonce
    # Use this to provoke a failure, by deliberately requesting a nonce that is longer than really needed
    # Buffer length must be at least    ${sender_nonce}    32
    # 16 bytes is 128 bits
    Buffer length must be at least    ${sender_nonce}    16


Collect nonce from PKIMessage
    [Documentation]    Extract the senderNonce from a PKIMessage and append it to a list, which will be used later
    ...                in a test that checks for nonces to be cryptographically strong.
    [Arguments]        ${pki_message}   ${collector}
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${pki_message}   header.senderNonce
    Append To List     ${collector}    ${sender_nonce}
    Log    ${collector}



Certificate must be valid
    [Documentation]    Verify if a certificate is valid and passes sanity checks. The certificate is passed as a
    ...                DER-encoded byte buffer. These checks are done by trying to parse the certificate with
    ...                OpenSSL and PKILint. OpenSSL is relatively forgiving and will accept a certificate that
    ...                may contain issues, but is good enough for practical applications - failure to load with OpenSSL
    ...                is treated as an error. PKILint is very picky and will find issues even if a certificate
    ...                is accepted by OpenSSL. PKILint's findings will be logged and reported as warnings - making
    ...                it clear that there's something of interest, but not failing the test.
    [Arguments]        ${der_certificate}
    Log base64         ${der_certificate}
    # If OpenSSL complains, we fail the test
    ${result_openssl}=  Validate Certificate OpenSSL   ${der_certificate}
    Should be true      ${result_openssl}    Certificate failed OpenSSL validation

    # Use PKILint to check the certificate for issues, https://github.com/digicert/pkilint
    # If PKILint complains, we log a warning, but keep going
    Run Keyword And Warn On Failure     Validate Certificate PKILint   ${der_certificate}

Generate Key and CSR
     [Documentation]    This function generates a fresh Certificate Signing Request (CSR) and key, returning the DER-formatted data and the key.
     ...                Arguments:
     ...                - ${key_algo_name}: The name of the key algorithm (e.g., RSA, ECDSA).
     ...                - ${key_params}: Parameters required for the key generation (e.g., key size, curve name).
     ...                - ${CN}: Common Name (CN) for the certificate.
     ...
     ${key}=    Generate key    ${key_algo_name}    ${key_params}
     ${csr}=    Generate CSR    ${CN}
     ${csr_signed}=    Sign CSR    ${csr}    ${key}
     ${data}=    Decode pem string   ${csr_signed}
     RETURN    ${data}   ${key}


PKIMessage body type must be
    [Documentation]    Ensure that the response type in a PKIMessage is of a certain type
    [Arguments]        ${pki_message}    ${expected_type}
    ${response_type}=  Get CMP response type    ${pki_message}
    Should Be Equal    ${response_type}    ${expected_type}    Response type mismatch

PKIMessage must contain implicitConfirm extension
    [Documentation]    Ensure the given PKIMessage contains the implicitConfirm extension in its header.generalInfo
    [Arguments]        ${pki_message}
    ${result}=         Find OID in General Info    ${pki_message}      1.3.6.1.5.5.7.4.13
    Should Be True     ${result}    The implicitConfirm extension was not found in the message



PKIMessage Has Set Failure Bit or Bits
    [Documentation]    This keyword checks for a specific single failure bit in the `failInfo` field of the `PKIStatusInfo` structure within a `PKIMessage`.
    ...                The check can be configured to verify if the bit is set exclusively (only one of the Indices Option is set or
    ...                   or non-exclusively (at least one bit is set).
    ...                Arguments:
    ...                - `${pki_message}`: The `PKIMessage` object that contains the `PKIStatusInfo` structure to be checked.
    ...                - `${bit_index}`: The index of the bit to check within the `failInfo` field.
    ...                - `${exclusive}`: Determines whether other bits can also be set. If set to true, only the specified bit index will be allowed.
    ...
    ...                Example Usage:
    ...                | ${bit_status}=    PKIMessage Has Set Either Failure Bit    | ${pki_message}    | ${badAlg}    |    exclusive=${True}
    ...
    [Arguments]        ${pki_message}     ${bit_index}    ${exclusive}=${True}
    ${pki_header}=       asn1utils.Get asn1 value   ${pki_message}    header
    Asn1 Must Contain Fields    ${pki_header}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce
    ${failInfo}=        asn1utils.Get asn1 value    ${pki_message}    body.error.pKIStatusInfo.failInfo
    ${bit_status}=      Is bit set    ${failInfo}    ${bit_index}    ${exclusive}
    Should be true    ${bit_status}

