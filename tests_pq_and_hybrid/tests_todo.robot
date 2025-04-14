# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation    General tests for CMP logic, not necessarily specific to the lightweight profile

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

Suite Setup         Initialize Global Variables

*** Keywords ***

Initialize Global Variables
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${OTHER_TRUSTED_PKI_CERT}  ${cert}   scope=Global
    VAR   ${OTHER_TRUSTED_PKI_KEY}   ${key}    scope=Global
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${ISSUED_CERT}  ${cert}   scope=Global
    VAR   ${ISSUED_KEY}   ${key}    scope=Global

*** Test Cases ***


# TODO: add test cases without a SKI extension value.

# TODO: there is not enough info for the server to formulate a proper PKIMessage, so we should send a malformed request
# which is more sophisticated, to make sure there is a bare minimum of info that can be used to send back a PKIMessage
# error
#PKI entity must respond with a PKIStatusInfo structure when a malformed request is received
#    [Documentation]    When we send an invalid PKIMessage to a PKI entity, it MUST indicate the error condition in
#    ...                the PKIStatusInfo structure
#    ...                Ref:  3.6.2. Reporting Error Conditions Downstream
#    ...                   "In case the PKI management entity detects any other error condition on requests [..]
#    ...                   from downstream [..], it MUST report them downstream in the form of an error message as
#    ...                   described in Section 3.6.4.
#    ...
#    [Tags]    negative  rfc9483
#    ${response}=  Exchange data with CA    this dummy input is not a valid PKIMessage
#    Should Be Equal    ${response.status_code}  ${400}      We expected status code 400, but got ${response.status_code}
#
#    ${asn1_response}=  Parse PKIMessage    ${response.content}
#    ${response_type}=  Get Cmp Response Type    ${asn1_response}
#    Should Be Equal    error    ${response_type}


#
#
#Messages without protection must be rejected, except if not possible for error messages
#    [Documentation]    Protection must always be used, unless dealing with the case of an error message where
#    ...                it is impossible, as described in Section 3.6.4:
#    ...                     "Protecting the error message may not be technically feasible if it is not clear which
#    ...                     credential the recipient will be able to use when validating this protection, e.g.,
#    ...                     in case the request message was fundamentally broken. In these exceptional cases,
#    ...                     the protection of the error message MAY be omitted"
#    ...                Ref: 3.2. General Description of the CMP Message Protection
#    [Tags]    consistency
#    No Operation
#

#
#PKIStatusInfo must be set when an error occurred
#    [Documentation]    When a negative response is sent by the RA/CA, the error details must be shown in PKIStatusInfo.
#    ...                operation.
#    ...                Ref: 3.6.4
#    [Tags]    consistency
#    No Operation

#CA MUST reject CR with poposkInput
#    [Documentation]  poposkInput MUST NOT be used; it is not needed because subject and
#    ...              publicKey are both present in the certTemplate.
#    [Tags]    cr   negative  popo
#    ${pki_message}=  Build Negative CMP Request  body=cr  bad=sigAlg  private_key=${ISSUDE_KEY}  ee_cert=${ISSUDE_CERT}  sender=${SENDER}    recipient=${RECIPIENT}
#    ${resp_pki_message}=  Send And Exchange PKIMessage   ${pki_message}
#    Verify PKIStatusInfo and PKIFailInfo  ${resp_pki_message}  body=cp  failinfo_names=badPOP, notAuthorized


# CA MUST check the validity of a CertTemplate in a CR
# send a validity and check if the request was different and then grantedWithMods was returned.
