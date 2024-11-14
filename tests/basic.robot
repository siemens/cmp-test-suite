# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation        General tests for CMP logic, not necessarily specific to the lightweight profile
Resource    ../resources/keywords.resource
Library     OperatingSystem
Library     ../resources/utils.py
Library     ../resources/asn1utils.py
Library     ../resources/keyutils.py
Library     ../resources/cmputils.py
Library      ../resources/protectionutils.py
Library     ../resources/httputils.py



*** Test Cases ***
CA must reject malformed reqest
    [Documentation]    When we send an invalid PKIMessage to the CA, it must respond with a 400 status code to indicate
    ...                a client-side error in the supplied input data.
    ...                Ref: "3.3.  General Form",  "All applicable "Client Error 4xx" or "Server Error 5xx" status codes
    ...                MAY be used to inform the client about errors."
    [Tags]    negative  status  rfc6712     robot:skip-on-failure
    ${response}=  Exchange data with CA    this dummy input is not a valid PKIMessage
    Should Be Equal    ${response.status_code}  ${400}      We expected status code 400, but got ${response.status_code}


CA must reject requests that feature unknown signature algorithms
    [Documentation]    When we send a valid PKIMessage to the CA, but the signature algorithms used in the request are
    ...                unknown to the server, it should reject the request and respond with a 400 status code to
    ...                indicate a client-side error in the supplied input data.
    [Tags]    negative  crypto  p10cr
    ${data}=  Get Binary File  data/req-p10cr-prot_none-pop_sig-dilithium.pkimessage
    Log base64    ${data}
    ${updated_pki_message}=  Patch message time    ${data}
    ${encoded}=  Encode To Der    ${updated_pki_message}
    ${response}=  Exchange data with CA    ${encoded}
    # Should Be Equal    ${response.status_code}  ${400}      We expected status code 400, but got ${response.status_code}

    ${pki_message}=  Parse Pki Message    ${response.content}
    PKIMessage body type must be              ${pki_message}    error



CA must issue a certificate when we send a valid p10cr request
    [Documentation]    When we send a valid CSR inside a p10cr, the CA should respond with a valid certificate.
    [Tags]    csr    p10cr  positive
    ${der_pkimessage}=  Load And Decode Pem File    data/example-rufus-01-p10cr.pem
    ${request_pki_message}=  Parse Pki Message    ${der_pkimessage}
    ${request_pki_message}=  Patch message time    ${request_pki_message}
    # NOTE that we are patching the transaction id so the message looks like a new one
    ${request_pki_message}=  Patch transaction id    ${request_pki_message}     prefix=11111111111111111111
    ${protected_p10cr}=     protect_pki_message    pki_message=${request_pki_message}    protection=password_based_mac    password=${PRESHARED_SECRET}      iterations=${1945}    salt=111111111122222222223333333333   hash_alg=sha256
    ${der_pkimessage}=  Encode To Der    ${protected_p10cr}

    ${response}=  Exchange data with CA    ${der_pkimessage}
    ${response_pki_message}=     Parse Pki Message    ${response.content}
    Should Be Equal    ${response.status_code}  ${200}      We expected status code 200, but got ${response.status_code}

    Sender and Recipient nonces must match    ${request_pki_message}      ${response_pki_message}
    SenderNonce must be at least 128 bits long  ${response_pki_message}
    PKIMessage body type must be              ${response_pki_message}    cp

    ${response_status}=    Get CMP status from PKIMessage    ${response_pki_message}
    Should be equal     ${response_status}    accepted      We expected status `accepted`, but got ${response_status}
    ${cert}=    Get Asn1 value    ${response_pki_message}    body.cp.response/0.certifiedKeyPair.certOrEncCert.certificate
    ${cert}=    Transform asn1 tagged certificate to certificate    ${cert}
    ${der_cert}=    Encode to der    ${cert}
    Certificate must be valid    ${der_cert}

CA must reject a valid p10cr request if the transactionId is not new
    [Documentation]    When we send a valid p10cr that uses a transactionId that was already used, the CA should
    ...                reject the request
    [Tags]    csr    p10cr  negative
    ${der_pkimessage}=  Load And Decode Pem File    data/example-rufus-01-p10cr.pem
    ${request_pki_message}=  Parse Pki Message    ${der_pkimessage}
    Try to log pkimessage    ${request_pki_message}
    # first we send a good request, ensuring the time is fresh and the transactionId is new
    ${request_pki_message}=  Patch message time    ${request_pki_message}
    ${request_pki_message}=  Patch transaction id    ${request_pki_message}     0123456789012345678901234567891
    ${request_pki_message}=  Add implicit confirm    ${request_pki_message}
#    xxx
    Try to log pkimessage    ${request_pki_message}

    ${protected_p10cr}=     protect_pki_message    pki_message=${request_pki_message}    protection=password_based_mac    password=${PRESHARED_SECRET}      iterations=${1945}    salt=111111111122222222223333333333   hash_alg=sha256
    ${encoded}=  Encode To Der    ${protected_p10cr}
    ${response}=  Exchange data with CA    ${encoded}

    # then send the same thing again and expect an error with failInfo = transactionIdInUse
    ${response_new}=  Exchange data with CA    ${encoded}
    ${response_pki_message}=     Parse Pki Message    ${response_new.content}

    Sender and Recipient nonces must match    ${request_pki_message}      ${response_pki_message}
    SenderNonce must be at least 128 bits long  ${response_pki_message}
    PKIMessage body type must be              ${response_pki_message}    error

    ${pki_status}=     Get ASN1 value    ${response_pki_message}    body.error.pKIStatusInfo.status
    Should Be Equal    ${pki_status}  ${2}      We expected status `(2) rejection`, but got ${pki_status}

    # TODO PKIFailureInfo is optional, but if it is set, then it must contain the specific values we check for
    PKIMessage Has Set Failure Bits    ${response_pki_message}    transactionIdInUse    exclusive=${True}
    #Should Be Equal    ${pki_fail_info}  ${21}      We expected status `(21) transactionIdInUse`, but got ${pki_status}
#    Check if optional error info in PKIMessage equals    ${response_pki_message}    ${21}
    #Should Be Equal    ${response.status_code}  ${400}      We expected status code 200, but got ${response.status_code}


CA must reject request when the CSR signature is invalid
     [Documentation]    When we send a CSR with a broken signature, the CA must respond with an error.
     [Tags]    csr    negative   crypto    robot:skip-on-failure
     ${csr_signed}    ${key}=    Generate signed csr    ${DEFAULT_X509NAME}
     ${data}=    Decode pem string   ${csr_signed}
     # needs to be changed so that it is still a Valid Asn1 Structure
     ${data}=    Parse Csr    ${data}
     ${modified_csr_der}=    Modify Csr cn  ${data}    Hans MustermanNG11
     Log base64       ${modified_csr_der}
     ${p10cr}=    Build P10cr From Csr    ${modified_csr_der}     sender=${SENDER}    recipient=${RECIPIENT}      implicit_confirm=${True}
     ${protected_p10cr}=     protect_pki_message    ${p10cr}    protection=Pbmac1    password=${PRESHARED_SECRET}
     Log Asn1    ${protected_p10cr}
     ${encoded}=  Encode To Der    ${protected_p10cr}
     ${response}=  Exchange data with CA    ${encoded}
     # checks if the Implementation returns a Status Code or a Status Code with a PKI Message

     ${contains_msg}=    Http response contains pki message    ${response}
     # TODO ADD Http Check! Status Code and No PKIMessage
     IF    ${contains_msg}
     #TODO needs to decided if the message should return badPOP or badMessageCheck
     ${pkimessage}=    Parse pki message    ${response.content}
     PKIMessage Has Set Failure Bits    ${pkimessage}    badPOP,badMessageCheck    exclusive=${1}
     END
     IF    not ${contains_msg}    LOG  "The Server Response did not Contained a PKI Message"



CA must reject request when the csr is sent again
    [Documentation]    Ensure that the Certification Authority (CA) correctly rejects a Certificate Signing Request (csr) if it has already been submitted and processed, preventing duplicate certificate issuance.
    [Tags]    csr    negative   asn1    robot:skip-on-failure
    ${der_pkimessage}=  Load And Decode Pem File    data/example-rufus-01-p10cr.pem
    ${request_pki_message}=  Parse Pki Message    ${der_pkimessage}
    ${request_pki_message}=  Patch message time    ${request_pki_message}
    # NOTE that we are patching the transaction id so the message looks like a new one
    ${request_pki_message}=  Patch transaction id    ${request_pki_message}     prefix=11111111111111111111
    ${protected_p10cr}=     protect_pki_message    pki_message=${request_pki_message}    protection=password_based_mac    password=${PRESHARED_SECRET}      iterations=${1945}    salt=111111111122222222223333333333   hash_alg=sha256
    ${der_pkimessage}=  Encode To Der    ${protected_p10cr}

    ${response}=  Exchange data with CA    ${der_pkimessage}
    ${response_pki_message}=     Parse PKI Message    ${response.content}
    Should Be Equal    ${response.status_code}  ${200}      We expected status code 200, but got ${response.status_code}

    Sender and Recipient nonces must match    ${request_pki_message}      ${response_pki_message}
    SenderNonce must be at least 128 bits long  ${response_pki_message}
    PKIMessage body type must be              ${response_pki_message}    cp

    ${response3}=  Exchange data with CA    ${der_pkimessage}
                                        #Returns duplicateCertReq    (26) but exclusively
    # this check is a CA Configuration.
    # some Configuration may accept the same Request, but some will allowed it.
    ${pkimessage}=    Parse pki message    ${response3.content}
    PKIMessage Has Set Failure Bits    ${pkimessage}    duplicateCertReq,badMessageCheck    exclusive=${True}


