# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

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
Library             ../pq_logic/hybrid_sig/cert_binding_for_multi_auth.py


#Suite Setup         Do PQ SIG Tests
Test Tags           pqc  hybrid-sig

*** Variables ***

# disable legacy, composite-sig, falcon, composite-sig-old

#${uri_multiple_auth}=   https://localhost:8080/cmp/cert-bindings-for-multiple-authentication
${uri_multiple_auth}=   ${None}
${uri_multiple_auth_neg}=  ${None}
${DEFAULT_ML_DSA_ALG}=   ml-dsa-87
${Allowed_freshness}=   500


*** Test Cases ***

############################
# Composite Signature Tests
############################

#### Composite Signature Positive Tests ####

CA MUST Issue A Valid Composite RSA Certificate From CSR
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite   p10cr   positive
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    signing_key=${key}    common_name=${cm}
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    Verify PKIStatusInfo    ${response}    status=accepted


CA MUST Issue A Valid Composite RSA Certificate
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite   csr   positive
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${csr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    Verify PKIStatusInfo    ${response}    status=accepted


CA MUST Issue A Valid Composite EC Certificate
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a EC key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite   csr   positive
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ec
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${csr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    Verify PKIStatusInfo    ${response}    status=accepted

CA MUST Issue A Valid Composite ED448 Certificate From CSR
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a ED key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite   csr   positive
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    signing_key=${key}    common_name=${cm}
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    Verify PKIStatusInfo    ${response}    status=accepted



#### Composite Signature Negative Tests ####

# TODO fix for IR-BODY.

### Invalid Signature Tests ###

CA MUST Reject Invalid POP For Composite RSA
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badPOP`.
    [Tags]             composite   csr   negative
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    signing_key=${key}    common_name=${cm}   exclude_signature=True   bad_sig=True
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA MUST Reject Invalid POP For Composite EC
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a EC key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badPOP`.
    [Tags]             composite   csr   negative
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ec
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    signing_key=${key}    common_name=${cm}   exclude_signature=True    bad_sig=True
    ${p10cr}=          Build P10cr From CSR   ${signed_csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA MUST Reject Invalid POP For Composite ED448
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a ED key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badPOP`.
    [Tags]             composite   csr   negative
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    signing_key=${key}    common_name=${cm}   exclude_signature=True   bad_sig=True
    ${p10cr}=          Build P10cr From CSR   ${signed_csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection


### Invalid Key Combination Tests ###

CA MUST Reject Invalid OID for RSA KEY LENGTH
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badAlg`.
    [Tags]             composite   csr   negative
    Skip If    NOT-Implemented: rsa-key-length
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa    pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA MUST Reject Invalid Composite Key Combination For ED448
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a ED448 key as traditional algorithm and a ML-DSA-67 as pq algorithm.
    ...                Which is not a valid combination. The CA MUST reject the request and MAY respond with the
    ...                optional failInfo `badAlg`.
    [Tags]             composite   csr   negative
    Skip If    NOT-Implemented: ed448-ml-dsa-65.
    # Correct combination is ed448 and ml-dsa-87.
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448    pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA MUST Reject Invalid Composite Key Combination For EC
    [Documentation]    As defined in Composite Sig Draft CMS03, we generate a CSR with a composite signature.
    ...                The CSR is signed with a EC key as traditional algorithm and a ML-DSA-67 as pq algorithm.
    ...                Which is not a valid combination. The CA MUST reject the request and MAY respond with the
    ...                optional failInfo `badAlg`.
    [Tags]             composite   csr   negative
    Skip If    NOT-Implemented: ec-ml-dsa-65.
    # Correct combination is ec and ml-dsa-87.
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ec    pq_name=ml-dsa-65  curve=secp256r1
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection


#### Security Related #####

CA MUST Reject Composite Sig with Traditional Revoked key Due Compromise
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 11.2, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]             composite-sig   negative  security
    Skip    NOT-Implemented to get a revoked key.
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${REVOKED_KEY}
    ...                cert=${REVOKED_CERT}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA SHOULD Reject Issuing Already in use Traditional Key
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 11.3, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA SHOULD reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]             composite-sig   negative  robot:skip-on-failure   security
    Skip    NOT-Implemented to get a key already in use.
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection


###########################################
# Cert-bindings-for-multiple-authentication
###########################################

##### positive tests #####

CA MUST Accept valid Request with CSR with related CSR
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, and an valid related certificate
    ...                from the same CA. The CA MUST accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive
    Skip if   not ${uri_multiple_auth}    The URI for multiple auth is not defined.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}    
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate Related Cert Extension    ${cert}    ${ISSUED_CERT}
   

CA SHOULD Accept CSR with related cert from different CA
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an valid related certificate
    ...                from a different CA. The CA SHOULD accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive   different-ca
    Skip if   not ${uri_multiple_auth}    The URI for multiple auth is not defined.
    # TODO uncomment, if needed.
    # get a new cert, if the CA requires to issue a related cert in time.
    # ${ir}=    Generate Default IR Sig Protected
    # ${response}=   Exchange PKIMessage    ${ir}
    # PKIMessage Body Type Must Be    ${response}    ip
    # PKIStatus Must Be    ${response}    accepted
    # ${new_cert}=   Get Cert From PKIMessage    ${response}
    # ${key}=    Get From List    ${burned_keys}    -1
    # must then change the variables.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
 


# TODO decide how to handle the multiple auth in CertTemplate!
# Technically one to one for x509 inside the CertTemplate.
# But not defined, so either added in a experimental file or excluded.

##### negative tests #####

CA MUST Reject Invalid POP for Cert A
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an invalid POPO for the signature inside the
    ...                `RequesterCertificate` structure. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badPOP`.
    [Tags]         multiple-auth   csr   negative   popo
    Skip if   not ${uri_multiple_auth}    The URI for multiple auth is not defined.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   bad_pop=True
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}    exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP
    
# TODO may change the failInfo to a more fitting one.
    
CA MUST Validate that the URI is reachable
    Skip if   not ${uri_multiple_auth_neg}    The Not reachable URI for multiple auth is not defined.
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an 
    ...                unreachable URI for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badRequest`.
    [Tags]         multiple-auth   csr   negative   uri
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth_neg}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest
    
    
CA MUST Reject Cert B Request with invalid serialNumber
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an
    ...                invalid serialNumber for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badCertTemplate` or `badRequest`.
    [Tags]         multiple-auth   csr   negative   serialNumber
    # increments the serial number by one
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   invalid_serial_number=True
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cert B Request with invalid issuer
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an
    ...                invalid issuer for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badCertTemplate` or `badRequest`.
    [Tags]         multiple-auth   csr   negative   issuer
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   invalid_issuer=True
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check the Freshness of the BinaryTime
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid freshness
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badTime`.
    [Tags]         multiple-auth   csr   negative   freshness   policy-dependent
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   freshness=${Allowed_freshness}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badTime

# As defined in Section 3.2
# maybe some parallel test should be implement, were two request are send.
# or send CertTemplate with a serialNumber set and this number is used for the second request.
RA MUST only allow Previously issued certificate to be a related one.
    [Documentation]
    [Tags]         multiple-auth   csr   negative   security   policy-dependent
    Skip     NOT-Implemented, user must defined what previous certificate means. Could either be
    ...      up to a week or maybe just some time ago and valid at the time of the request.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ALREADY_ISSUED_CERT}    cert_a_key=${ALREADY_ISSUED_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest


CA MUST Check If The Related Certificate Is Not Revoked.
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative   rr
    ${result}=   Is Certificate And Key Set    ${REVOKED_CERT}    ${REVOKED_KEY}
    Skip If    ${result}    The revoked certificate and key are not set.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${REVOKED_CERT}    cert_a_key=${REVOKED_KEY}   uri=${uri_multiple_auth}   
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,certRevoked
    Verify StatusString        ${response}    any_text=certificate, not valid  all_text=revoked


CA MUST Check If The Related Certificate Is Not Updated
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative   rr
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,certRevoked
    Verify StatusString        ${response}    any_text=certificate, not valid, update, updated

CA MUST Reject Related Cert For Non-EE Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but the Certificates is not for
    ...                an end entity. The CA MUST detect this error and reject the request and MAY respond with the
    ...                optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative
    ${req_cert}=   Prepare Requester Certificate  cert_a=${CA_CERT}    cert_a_key=${CA_KEY}   uri=${uri_multiple_auth}   
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${extensions}=   Prepare Extensions    is_ca=True
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True   extensions=${extensions}
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest


# CA SHOULD Reject Multi-Auth For Traditional Keys


###########################################
# Hybrid Sun Tests
###########################################

