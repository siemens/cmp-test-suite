*** Settings ***
Documentation        General tests for CMP logic, not necessarily specific to the lightweight profile
Resource    ../resources/keywords.resource
Library     OperatingSystem
Library     ../resources/utils.py
Library     ../resources/asn1utils.py


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
    Should Be Equal    ${response.status_code}  ${400}      We expected status code 400, but got ${response.status_code}

    ${pki_message}=  Parse Pki Message    ${response.content}
    PKIMessage body type must be              ${pki_message}    error



CA must issue a certificate when we send a valid p10cr request
    [Documentation]    When we send a valid CSR inside a p10cr, the CA should respond with a valid certificate.
    [Tags]    csr    p10cr  positive
    ${der_pkimessage}=  Load And Decode Pem File    data/example-rufus-01-p10cr.pem
    ${request_pki_message}=  Parse Pki Message    ${der_pkimessage}
    ${response}=  Exchange data with CA    ${der_pkimessage}
    ${response_pki_message}=     Parse Pki Message    ${response.content}
    Should Be Equal    ${response.status_code}  ${200}      We expected status code 200, but got ${response.status_code}

    Sender and Recipient nonces must match    ${request_pki_message}      ${response_pki_message}
    SenderNonce must be at least 128 bits long  ${response_pki_message}
    PKIMessage body type must be              ${response_pki_message}    cp

    ${response_status}=    Get Asn1 value as string    ${response_pki_message}    body.cp.response/0.status
    Should be equal     ${response_status}    accepted      We expected status `accepted`, but got ${response_status}

    # TODO check the remaining part for correctness
    ${der_cert}=    Get Asn1 value as DER    ${response_pki_message}    body.cp.response/0.certifiedKeyPair.certOrEncCert.certificate.tbsCertificate
    Certificate must be valid    ${der_cert}


#CA must reject request when the CSR signature is invalid
#    [Documentation]    When we send a CSR with a broken signature, the CA must respond with an error.
#    [Tags]    csr    negative   crypto
#    No Operation
#
#CA must reject request when the CSR is not valid asn1
#    [Documentation]    When we send a structure that is not valid DER-encoded ASN1, the CA must respond with an error.
#    [Tags]    csr    negative   asn1
#    No Operation


#CA must reject request with an invalid signature
#    [Documentation]    Demonstrate how to use some keywords
#    ...                just an example
#    [Tags]    csr    crypto    negative
#    ${csr_signed}=    Generate CSR with RSA2048 and a predefined common name
#    Log    ${csr_signed}
#    ${parsed_csr}=    Parse CSR    ${csr_signed}
#    Log    ${parsed_csr}
#    ${p10_pkimessage}=      Build P10cr From Csr    ${parsed_csr}
#    ${ca_response}=    Get Binary File    data/example-p10r.pkimessage
#    ${result}=    Parse PKI Message    ${ca_response}
#    ${status}=     Get CMP status from PKI Message    ${result}
#    Should be equal    ${status}    rejection
