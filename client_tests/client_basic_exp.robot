# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       This is a example file, how a user could use the Test-Suite to send responses.

Resource            ../config/${environment}.robot
Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../resources/ca_kga_logic.py
Library             ../resources/ca_ra_utils.py
Library             ../resources/httputils.py

Test Tags           client-test

*** Variables ***
${CLIENT_URL}    ${None}
${SERVER_IP}     ${None}
${SERVER_PORT}   ${None}
${MOCK_CLIENT}   New PKI Client
${CA_CERT}   data/unittest/root_cert_ed25519.pem
${CA_KEY}    data/unittest/root_key_ed25519.pem
${CA_KEY_PASSWORD}    11111

*** Keywords ***
Send PKIMessage To Client
    [Documentation]    Send the PKIMessage response to the client.
    [Arguments]    ${pki_message}    url=${CLIENT_URL}
    [Tags]    exchange
    Skip    Not implemented how to use the Server side to send the response.
    
Set Up Client Test
    [Documentation]    Set up the client test by setting the `CA_CERT` and `CA_KEY`.
    ${der_data}=  Load And Decode PEM File   ${CA_CERT}
    ${ca_cert}=   Parse Certificate   ${der_data}
    ${root_key}=  Load Private Key From File    ${CA_KEY}   ${CA_KEY_PASSWORD}
    VAR  ${CA_CERT}  ${ca_cert}  scope=TEST
    VAR  ${CA_KEY}   ${root_key}  scope=TEST
    

*** Test Cases ***
Client MUST Check the signature of the Issued Certificate
    [Documentation]    According to RFC 9483 Section 4.1 the client can send a valid `ir` message
    ...    to the CA and ask for a new certificate. The Client MUST check the signature of the issued
    ...    certificate. We issue a new certificate with an invalid signature and the client MUST
    ...    reject the certificate.
    [Tags]    cert-req   bad-sig  ir
    ${der_data}=   Start Unsafe TCP Server   ${SERVER_IP}    ${SERVER_PORT}
    ${request}=    Parse PKIMessage    ${der_data}
    ${response}=   Build IP CMP Message     recipient=${MOCK_CLIENT}
    ...            ca_cert=${CA_CERT}   ca_key=${CA_KEY}  bad_sig=True
    Send PKIMessage To Client    ${response}    url=${CLIENT_URL}
    ${der_data}=   Start Unsafe TCP Server   ${SERVER_IP}    ${SERVER_PORT}
    ${cert_conf}=   Parse PKIMessage    ${der_data}
    PKIStatus Must Be    ${cert_conf}    rejection
    # Client should not respond with `error` message.
    PKIMessage Body Type Must Be    ${cert_conf}    certConf
