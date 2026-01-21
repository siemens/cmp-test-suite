# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Contains tests for hybrid signatures which are currently not part of the
...                of active standards or just some additional hybrid signature draft mechanism test cases.

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/certextractutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../resources/general_msg_utils.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_verify_logic.py


Test Tags           pqc  mock-ca  experimental   hybrid
Suite Setup         Setup Certs For Migration Tests

*** Variables ***
${uri_multiple_auth}=   ${None}

${ISSUED_KEY}=   ${None}
${ISSUED_CERT}=   ${None}

${COMPOSITE_KEM_KEY}=   ${None}
${COMPOSITE_KEM_CERT}=   ${None}
${REVOKED_COMP_KEM_KEY}=   ${None}
${REVOKED_COMP_KEM_CERT}=   ${None}

${COMPOSITE_SIG_KEY}=   ${None}
${COMPOSITE_SIG_CERT}=   ${None}

${REVOKED_COMP_KEY}=   ${None}
${REVOKED_COMP_CERT}=   ${None}
${UPDATED_COMP_SIG_KEY}=   ${None}
${UPDATED_COMP_SIG_CERT}=   ${None}

${CHAMELEON_CERT}=   ${None}
${CHAMELEON_KEY}=   ${None}
${CHAMELEON_DELTA_CERT}=   ${None}
${CHAMELEON_DELTA_KEY}=   ${None}

${RELATED_CERT}=   ${None}
${RELATED_KEY}=   ${None}
${RELATED_CERT_SEC}=   ${None}
${RELATED_KEY_SEC}=   ${None}

${SUN_HYBRID_CERT}=   ${None}
${SUN_HYBRID_KEY}=    ${None}
${SUN_HYBRID_CERT_CHAIN}=   ${None}

${SUN_HYBRID_CERT_REVOKED}=   ${None}
${SUN_HYBRID_KEY_REVOKED}=    ${None}
${SUN_HYBRID_REVOKED_CERT_CHAIN}=   ${None}


*** Test Cases ***

###########################
# The tests are sorted by the different hybrid signature/issuing mechanisms,
# to clearly distinguish between the different mechanisms.
# The different between Catalyst-Signature and Catalyst-Issuing are the following:
#### Catalyst:
# - Catalyst-Issuing: The CA uses a different key for issuing, so that two keys can be authenticated,
# with a single request and a single certificate.
# - Catalyst-Signature: The CA uses a different signature algorithm for signing, so that two signature
# algorithms protect the same certificate.
# In this experimental tests has the client the option to ask for a specific signature algorithm.
##### Sun-Hybrid:
# - Also supports Hybrid KEM and Hybrid Signature Issuing.
# - The CA will only present the certificate in form1, if the certificate was correctly
# confirmed by the client, if a HybridKEM mechanism was used.
##### Hybrid-Authentication:
# Allows the user to use different mechanisms for authentication.
# Either allows alternative signatures inside the generalInfo field of the pkimessage,
# or allows a Composite Signature from two certificates.

##### Related-Cert:
# Allows the User to issue a related certificate.
# And adds the hash of the related certificate to the certificate.

##### Cert-Discovery:
# Allows the User to issue a related certificate.
# And adds the location and maybe the public key and/or signature algorithm
# inside the certificate.

##### Chameleon:
# Allows the User to issue a certificate with the POP described in the Related certificates,
# or by using a paired certificate.

###########################

##########################
# Catalyst Signature Tests
###########################

CA MUST issue a valid Catalyst Signed Certificate
    [Documentation]    When a Catalyst CA issues a certificate, the certificate must be valid
    ...                and contains a signature with an alternative key.
    [Tags]    catalyst-sig
    ${key}=   Generate Default Key
    ${ir}=   Build Ir From Key    ${key}   exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_SIGNATURE}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${cert_chain}=   Build CMP Chain From PKIMessage    ${response}   for_issued_cert=True
    Verify Catalyst Signature    ${cert}   ${cert_chain[1]}

CA MUST issue a valid Catalyst Signed Certificate with Wished Signature Algorithm
    [Documentation]    When a Catalyst CA issues a certificate, the certificate must be valid
    ...                and contains a signature with an alternative key. When the signature algorithm
    ...                is wished, the CA should use the wished signature algorithm.
    [Tags]    catalyst-sig   hybrid-sig
    ${new_key}=    Generate Default Key
    ${key}=   Generate Key    ml-dsa-87
    ${extension}=   Prepare AltSignatureAlgorithm Extension   key=${key}    hash_alg=sha512
    ${extensions}=   Create List     ${extension}
    ${subject}=    Get Next Common Name
    ${cert_template}=   Prepare CertTemplate   subject=${subject}    extensions=${extensions}   key=${new_key}   
    ${ir}=   Build Ir From Key    ${new_key}   cert_template=${cert_template}
    ...      exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   suffix=${CATALYST_SIGNATURE}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${extensions}=    Validate Catalyst Extensions     cert=${cert}   sig_alg_must_be=ml-dsa-87-sha512
    ${cert_chain}=   Build CMP Chain From PKIMessage    ${response}   for_issued_cert=True
    Verify Catalyst Signature    ${cert}   ${cert_chain[1]}
    

##########################
# Catalyst Issuing Tests
##########################
    

CA Could Support Valid 2 POP For Signing Keys
    [Documentation]    The Catalyst extension could be used to support two POPs for the signing keys.
    ...                We send a certificate request, which contains two signing keys. The CA should
    ...                issue a certificate, which contains the two signing keys.
    [Tags]    catalyst-issuing  hybrid-sig
    ${key1}=   Generate Default Key
    ${alt_key}=   Generate Default PQ Sig Key
    ${cert_req_msg}=   Prepare Catalyst CertReqMsg Approach  ${key1}    ${alt_key}
    ${ir}=   Build Ir From Key    ${key1}   cert_req_msg=${cert_req_msg}  recipient=${RECIPIENT}
    ...       exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_ISSUING}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${pub_key}=    Load Catalyst Public Key    ${cert}
    Should Be Equal    ${pub_key}    ${alt_key.public_key()}   The public key should be the same as the alternative key.

CA MUST Detect BadPOP For First POP
    [Documentation]    The Catalyst extension could be used to support two POPs for the signing keys.
    ...                We send a certificate request, which contains two signing keys, but the first
    ...                proof-of-possession is invalid. The CA should reject the request and MAY respond with the
    ...                optional failInfo `badPOP`.
    [Tags]    catalyst-issuing
    ${key1}=   Generate Default Key
    ${alt_key}=   Generate Default PQ Sig Key
    ${cert_req_msg}=   Prepare Catalyst CertReqMsg Approach  ${key1}    ${alt_key}   bad_pop=True
    ${ir}=   Build Ir From Key    ${key1}   cert_req_msg=${cert_req_msg}
    ...       exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_ISSUING}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA Could Detect Invalid alternative POP
    [Documentation]    The Catalyst extension could be used to support two POPs for the signing keys.
    ...                We send a certificate request, which contains two signing keys, but the alternative
    ...                proof-of-possession is invalid. The CA should reject the request and MAY respond with the
    ...                optional failInfo `badPOP`.
    [Tags]    catalyst-issuing
    ${key1}=   Generate Default Key
    ${alt_key}=   Generate Default PQ Sig Key
    ${cert_req_msg}=   Prepare Catalyst CertReqMsg Approach  ${key1}    ${alt_key}   bad_alt_pop=True
    ${ir}=   Build Ir From Key    ${key1}   cert_req_msg=${cert_req_msg}
    ...       exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_ISSUING}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA Could support Hybrid KEM issuing with Catalyst First Key being RSA and second key being KEM
    [Documentation]    The Catalyst extension could be used to support two keys issued in one certificate.
    ...                We send a certificate request, which contains two keys. The first key is a signing key
    ...                and the second key is a KEM-key. The CA should issue a certificate, which contains the two keys.
    ...                The CA response should contain the encrypted certificate.
    [Tags]    catalyst-issuing  positive
    ${key1}=   Generate key   rsa   length=2048
    ${alt_key}=   Generate Default PQ KEM Key
    ${cert_req_msg}=   Prepare Catalyst CertReqMsg Approach  ${key1}    ${alt_key}
    ${ir}=   Build Ir From Key    ${None}   cert_req_msg=${cert_req_msg}
    ...       exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_ISSUING}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get EncCert From PKIMessage    ${response}    ee_private_key=${alt_key}   exclude_rid_check=True
    ${pub_key}=    Load Catalyst Public Key    ${cert}
    Should Be Equal    ${pub_key}    ${alt_key.public_key()}   The public key should be the same as the alternative key.

CA Could support Hybrid KEM issuing with Catalyst First Key being KEM and second key being RSA
    [Documentation]    The Catalyst extension could be used to support two keys issued in one certificate.
    ...                We send a certificate request, which contains two keys. The first key is a KEM-key
    ...                and the second key is a signing key. The CA should issue a certificate, which contains the two
    ...                keys. The CA response should contain the encrypted certificate.
    [Tags]    catalyst-issuing  positive
    ${key1}=   Generate Default PQ KEM Key
    ${alt_key}=   Generate key   rsa   length=2048
    ${cert_req_msg}=   Prepare Catalyst CertReqMsg Approach  ${key1}    ${alt_key}
    ${ir}=   Build Ir From Key    ${key1}   cert_req_msg=${cert_req_msg}
    ...       exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_ISSUING}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get EncCert From PKIMessage    ${response}    ee_private_key=${key1}   exclude_rid_check=True
    ${pub_key}=    Load Catalyst Public Key    ${cert}
    Should Be Equal    ${pub_key}    ${alt_key.public_key()}   The public key should be the same as the alternative key.

CA Could Detect The Hybrid-KEM Catalyst Invalid POP
    [Documentation]    The Catalyst extension could be used to support two keys issued in one certificate.
    ...                We send a certificate request, which contains two keys. The first key is a signing key
    ...                and the second key is a KEM-key. The first key is invalid. The CA should reject the request
    ...                and MAY respond with the optional failInfo `badPOP`.
    [Tags]    catalyst-issuing  negative
    ${key1}=   Generate Default Key
    ${alt_key}=   Generate Default PQ KEM Key
    ${cert_req_msg}=   Prepare Catalyst CertReqMsg Approach  ${key1}    ${alt_key}   bad_pop=True
    ${ir}=   Build Ir From Key    ${key1}   cert_req_msg=${cert_req_msg}
    ...       exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_ISSUING}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA Could Detect The Hybrid-KEM Catalyst Invalid alternative POP
    [Documentation]    The Catalyst extension could be used to support two keys issued in one certificate.
    ...                We send a certificate request, which contains two keys. The first key is a KEM key
    ...                and the second key is RSA, but the alternative POP is invalid. The CA should reject
    ...                the request and MAY respond with the optional failInfo `badPOP`.
    [Tags]    catalyst-issuing  negative
    ${key1}=   Generate Default PQ KEM Key
    ${alt_key}=   Generate Default Key
    ${cert_req_msg}=   Prepare Catalyst CertReqMsg Approach  ${key1}    ${alt_key}   bad_alt_pop=True
    ${ir}=   Build Ir From Key    ${key1}   cert_req_msg=${cert_req_msg}
    ...       exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${CATALYST_ISSUING}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

##########################
# Sun-Hybrid Tests
##########################

CA MUST Include the Sun-Hybrid Extensions
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. The CA should process the valid CSR and issue a valid certificate.
    ...                The CA MUST include the Sun-Hybrid extensions in the certificate.
    [Tags]    sun-hybrid   hybrid-sig  positive
    ${key}=   Generate Key   composite-sig
    ${ir}=   Build Ir From Key    ${key}  exclude_fields=senderKID,sender
    ...      implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${ir}    ${CA_BASE_URL}   ${SUN_HYBRID_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Cert Contains Sun Hybrid Extensions    ${cert}

CA MUST Issue Sun Hybrid Non-Critical Extensions
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. The CA should process the valid CSR and issue a valid certificate.
    ...                The CA should include the Sun-Hybrid extensions in the certificate.
    [Tags]    sun-hybrid   hybrid-sig
    ${key}=   Generate Key   composite-sig
    ${ir}=   Build Ir From Key    ${key}  exclude_fields=senderKID,sender
    ...      implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${ir}    ${CA_BASE_URL}   ${SUN_HYBRID_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Extension Must Be Non Critical    ${cert}    sun_hybrid_alt_pubkey
    Extension Must Be Non Critical    ${cert}    sun_hybrid_alt_sig

CA MUST Issue a Valid Sun Hybrid Certificate
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. The CA should process the valid CSR and issue a valid certificate. 
    [Tags]    sun-hybrid   hybrid-sig  
    ${key}=   Generate Unique Key    composite-sig
    ${ir}=   Build Ir From Key   ${key}   exclude_fields=senderKID,sender   recipient=${RECIPIENT}
    ...      implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${ir}    ${CA_BASE_URL}   ${SUN_HYBRID_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${issuer_cert}=  Find Sun Hybrid Issuer Cert   ${cert}    ${response["extraCerts"]}
    Verify Sun Hybrid Cert    ${cert}    ${issuer_cert}

CA MUST Send the Certificate in Form 1 or 3 as well
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. The CA should process the valid CSR and issue a valid certificate.
    ...                The CA should send the certificate in form 1 or 3 as well, so that the has the original
    ...                alternative signature.
    [Tags]    sun-hybrid   hybrid-sig
    ${response}=   Exchange Composite Request    ${SUN_HYBRID_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Contains Sun Hybrid Cert Form 1 Or 3    ${cert}   ${response["extraCerts"]}

CA MUST Support Sun Hybrid Valid Certificate Confirmation
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. The CA should process the valid CSR and issue a valid certificate.
    ...                The CA should support the Sun-Hybrid confirmation mechanism.
    [Tags]    sun-hybrid   hybrid-sig
    ${key}=   Generate Key   composite-sig
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${SUN_HYBRID_SUFFIX}
    ${ir}=   Build Ir From Key    ${key}  exclude_fields=senderKID,sender
    ...      recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage  ${protected_ir}   ${url}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${cert_chain}=   Build Sun Hybrid Cert Chain    ${cert}    ${response["extraCerts"]}
    Write Certs To Dir    ${cert_chain}
    ${cert_conf}=  Build Cert Conf From Resp    ${response}   recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${prot_cert_conf}=  Default Protect PKIMessage    ${cert_conf}
    ${response}=   Exchange Migration PKIMessage    ${prot_cert_conf}   ${CA_BASE_URL}  ${SUN_HYBRID_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    pkiconf
    VAR   ${SUN_HYBRID_CERT_CHAIN}=   ${cert_chain}   scope=Global
    VAR   ${SUN_HYBRID_CERT}=   ${cert}   scope=Global
    VAR   ${SUN_HYBRID_KEY}=   ${key}   scope=Global

CA MUST Revoked a Valid Sun Hybrid Certificate
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. The CA should process the valid CSR and issue a valid certificate.
    ...                The CA should revoke the certificate.
    [Tags]    sun-hybrid   hybrid-sig
    ${key}=   Generate Unique Key    composite-sig
    ${response}=   Exchange Composite Request    ${SUN_HYBRID_SUFFIX}   ${key}
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${SUN_HYBRID_SUFFIX}
    ${cert}=  Confirm Certificate If Needed    ${response}   url=${url}
    ${cert_chain}=   Build Sun Hybrid Cert Chain    ${cert}    ${response["extraCerts"]}
    ${rr}=   Build CMP Revoke Request    ${cert}   recipient=${RECIPIENT}
    ${protected_rr}=    Protect Hybrid PKIMessage
    ...    ${rr}
    ...    protection=signature
    ...    private_key=${key.trad_key}
    ...    cert=${cert}
    ${protected_ir}=    Patch ExtraCerts    ${protected_rr}    ${cert_chain}
    ${response}=   Exchange Migration PKIMessage    ${protected_rr}   ${CA_BASE_URL}  ${SUN_HYBRID_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    status=accepted
    VAR   ${SUN_HYBRID_REVOKED_CERT_CHAIN}=   ${cert_chain}   scope=Global
    VAR   ${SUN_HYBRID_CERT_REVOKED}=   ${cert}   scope=Global
    VAR   ${SUN_HYBRID_KEY_REVOKED}=   ${key}   scope=Global

CA MUST Reject Request With Revoked Sun Hybrid Request
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. We send a certificate request, which is signed with a revoked hybrid sun
    ...                certificate and key. The CA should reject the request and MAY respond with the optional
    ...                failInfo `certRevoked`.
    [Tags]    sun-hybrid   hybrid-sig
    ${result}=   Is Certificate And Key Set    ${SUN_HYBRID_CERT_REVOKED}    ${SUN_HYBRID_KEY_REVOKED}   for_sun_hybrid=True
    SKIP IF    not ${result}    The Sun Hybrid Certificate and Key are not set.
    ${key}=   Generate Key   composite-sig
    ${ir}=   Build Ir From Key    ${key}  exclude_fields=senderKID,sender  recipient=${RECIPIENT}
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${SUN_HYBRID_KEY_REVOKED}
    ...    cert=${SUN_HYBRID_CERT_REVOKED}
    ${protected_ir}=    Patch ExtraCerts    ${protected_ir}    ${SUN_HYBRID_REVOKED_CERT_CHAIN}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${SUN_HYBRID_SUFFIX}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    certRevoked

CA MUST Update a Sun Hybrid Certificate
    [Documentation]    According to draft-sun-lamps-hybrid-scheme-00 is a valid composite signature CSR send
    ...                to the CA. The CA should process the valid CSR and issue a valid certificate.
    ...                The CA should update the certificate.
    [Tags]    sun-hybrid   hybrid-sig
    ${key}=   Generate Key   composite-sig
    ${response}=   Exchange Composite Request    ${SUN_HYBRID_SUFFIX}   ${key}   True
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${SUN_HYBRID_SUFFIX}
    ${cert}=   Confirm Certificate If Needed    ${response}   url=${url}
    ${new_key}=   Generate Key   composite-sig
    ${kur}=   Build Key Update Request    ${new_key}    ${cert}
    ...       exclude_fields=senderKID,sender  recipient=${RECIPIENT}
    ${protected_kur}=    Protect Hybrid PKIMessage
    ...    ${kur}
    ...    protection=composite
    ...    private_key=${key}
    ...    cert=${cert}
    ${response}=   Exchange Migration PKIMessage    ${protected_kur}   ${CA_BASE_URL}  ${SUN_HYBRID_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be    ${response}    status=accepted
    
##############################
# Hybrid-Authentication Tests
##############################

CA Could Support Additional Catalyst Signature
    [Documentation]    The Catalyst method can be used to alternative sing a PKIMessage. We send
    ...                a certificate request, which is additionally signed by a alternative key.
    ...                The CA should correctly validate the signature and issue the certificate.
    [Tags]    hybrid-auth
    ${key1}=   Generate Default Key
    ${alt_key}=   Generate Default PQ Sig Key
    ${ir}=   Build Ir From Key    ${key1}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=catalyst
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    alt_signing_key=${alt_key}
    ...    include_alt_pub_key=True
    ...    bad_message_check=False
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}    ${MULTI_AUTH_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection

CA Could Detect Bad alternative message check
    [Documentation]    The Catalyst method can be used to alternative sing a PKIMessage. We send
    ...                a certificate request, which is additionally signed by a alternative key,
    ...                but the alternative signature is invalid. The CA should reject the request
    ...                and MAY respond with the optional failInfo `badMessageCheck`.
    [Tags]    hybrid-auth
    ${key1}=   Generate Default Key
    ${alt_key}=   Generate Default PQ Sig Key
    ${ir}=   Build Ir From Key    ${key1}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=catalyst
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    alt_signing_key=${alt_key}
    ...    include_alt_pub_key=True
    ...    bad_message_check=True
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}    ${MULTI_AUTH_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection

CA MUST Issue a valid Chameleon Cert
    [Documentation]    According to chameleon-certs-05 section 5, is a valid paired CSR send.
    ...                The CA should issue a valid chameleon certificate.
    [Tags]      positive
    ${pq_key}=  Generate Default PQ SIG Key
    ${trad_key}=  Generate Key   rsa   length=2048
    ${csr}=    Build Paired CSR   ${trad_key}   ${pq_key}
    ${p10cr}=  Build P10cr From CSR    ${csr}    recipient=${RECIPIENT}
    ...                                 exclude_fields=sender,senderKID   implicit_confirm=True
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${response}=   Exchange Migration PKIMessage    ${protected_p10cr}  ${CA_BASE_URL}   ${CHAMELEON_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    ${delta_cert}=   Build Delta Cert From Paired Cert    ${cert}
    ${extracted_delta_cert}=   Get From List    ${response["extraCerts"]}    1
    ${der_delta}=   Encode To Der    ${delta_cert}
    ${der_extracted_delta}=   Encode To Der    ${extracted_delta_cert}
    Should Be Equal    ${der_delta}    ${der_extracted_delta}   The delta certificate should
    ...                be the same as the extracted delta certificate.
    VAR   ${CHAMELEON_CERT}    ${cert}      scope=Global
    VAR   ${CHAMELEON_KEY}    ${trad_key}   scope=Global
    VAR   ${CHAMELEON_DELTA_CERT}    ${delta_cert}   scope=Global
    VAR   ${CHAMELEON_DELTA_KEY}    ${pq_key}   scope=Global

CA Could Support Composite Signature with Chameleon Cert
    [Documentation]    A CA could support a PKIMessage signed with composite signature with a chameleon 
    ...                certificate. We send a certificate request, which is signed with a composite signature.
    ...                The CA should correctly validate the signature and issue the certificate.
    [Tags]    hybrid-auth
    ${result}=  Is Certificate And Key Set    ${CHAMELEON_CERT}   ${CHAMELEON_KEY}
    SKIP IF    not ${result}    The Chameleon Certificate and Key are not set.
    ${key}=   Generate Default Key
    ${ir}=   Build Ir From Key  ${key}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${CHAMELEON_KEY}
    ...    cert=${CHAMELEON_CERT}
    ...    alt_signing_key=${CHAMELEON_DELTA_KEY}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}    ${MULTI_AUTH_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA Could Detect Bad Composite Signature with Chameleon Cert
    [Documentation]    A CA could support a PKIMessage signed with composite signature with a chameleon
    ...                certificate. We send a certificate request, which is signed with a composite signature,
    ...                but the signature is invalid. The CA should reject the request and MAY respond with the
    ...                optional failInfo `badMessageCheck`.
    [Tags]    hybrid-auth
    ${result}=  Is Certificate And Key Set    ${CHAMELEON_CERT}   ${CHAMELEON_KEY}
    SKIP IF    not ${result}    The Chameleon Certificate and Key are not set.
    ${key}=   Generate Default Key
    ${ir}=   Build Ir From Key  ${key}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${CHAMELEON_KEY}
    ...    cert=${CHAMELEON_CERT}
    ...    alt_signing_key=${CHAMELEON_DELTA_KEY}
    ...    bad_message_check=True
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}    ${MULTI_AUTH_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection

###########################################
# Cert-bindings-for-multiple-authentication
###########################################

##### positive tests #####

CA MUST Accept valid Request with CSR with related Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, and an valid related certificate
    ...                from the same CA. The CA MUST accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${PQ_SIG_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${PQ_SIG_CERT}
    ...            cert_a_key=${PQ_SIG_KEY}   uri=${cert_url}
    ${trad_key}=   Generate Default Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${trad_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${trad_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate Related Cert Extension    ${cert}    ${PQ_SIG_CERT}
    VAR   ${RELATED_KEY}    ${trad_key}   scope=Global
    VAR   ${RELATED_CERT}    ${cert}    scope=Global
    VAR   ${RELATED_KEY_SEC}    ${PQ_SIG_KEY}   scope=Global
    VAR   ${RELATED_CERT_SEC}   ${PQ_SIG_CERT}   scope=Global

CA SHOULD Accept CSR with related cert from different CA
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an valid related certificate
    ...                from a different CA. The CA SHOULD accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive   different-ca
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    # TODO uncomment, if needed.
    # get a new cert, if the CA requires to issue a related cert in time.
    # ${ir}=    Generate Default IR Sig Protected
    # ${response}=   Exchange PKIMessage    ${ir}
    # PKIMessage Body Type Must Be    ${response}    ip
    # PKIStatus Must Be    ${response}    accepted
    # ${new_cert}=   Get Cert From PKIMessage    ${response}
    # ${key}=    Get From List    ${burned_keys}    -1
    # must then change the variables.
    ${cert_url}=  Prepare Related Cert URL    ${ISSUED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${cert_url}
    ${pq_key}=    Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
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
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${ISSUED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${cert_url}   bad_pop=True
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

# TODO may change the failInfo to a more fitting one.

CA MUST Validate that the URI is reachable
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an
    ...                unreachable URI for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badRequest`.
    [Tags]         multiple-auth   csr   negative   uri
    Skip if   '${NEG_URI_RELATED_CERT}' == None    The Not reachable URI for multiple auth is not defined.
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${NEG_URI_RELATED_CERT}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    systemFailure,badPOP

CA MUST Check If The Related Certificate Is Not Revoked.
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative   rr
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${REVOKED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${REVOKED_CERT}
    ...            cert_a_key=${REVOKED_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
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
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${UPDATED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${UPDATED_CERT}
    ...            cert_a_key=${UPDATED_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   ${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,certRevoked
    Verify StatusString        ${response}    any_text=certificate, not valid, update, updated

CA MUST Reject Related Cert With Non-EE Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but the Certificates is not for
    ...                an end entity. The CA MUST detect this error and reject the request and MAY respond with the
    ...                optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${CA_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${CA_CERT}
    ...            cert_a_key=${CA_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

CA MUST Reject Related Cert For Non-EE Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, and an valid related certificate
    ...                from the same CA. The CA MUST accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${ISSUED_CERT}
    ${extns}=   Prepare Extensions    is_ca=True
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True   extensions=${extns}
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

CA Could Support Composite Signature with Related Cert
    [Documentation]    A CA could support a PKIMessage signed with composite signature with a related
    ...                certificate. We send a certificate request, which is signed with a composite signature.
    ...                The CA should correctly validate the signature and issue the certificate.
    [Tags]    hybrid-auth  composite-sig
    ${result}=  Is Certificate And Key Set    ${RELATED_CERT}    ${RELATED_KEY}
    SKIP IF    not ${result}    The Related Certificate and Key are not set.
    ${key}=   Generate Default Key
    ${ir}=   Build Ir From Key  ${key}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${RELATED_KEY}
    ...    cert=${RELATED_CERT}
    ...    alt_signing_key=${RELATED_KEY_SEC}
    ${protected_ir}=   Add Certs To PKIMessage  ${protected_ir}    ${RELATED_CERT_SEC}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}    ${MULTI_AUTH_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA Could Detect Bad Composite Signature with Related Cert
    [Documentation]    A CA could support a PKIMessage signed with composite signature with a related
    ...                certificate. We send a certificate request, which is signed with a composite signature,
    ...                but the signature is invalid. The CA should reject the request and MAY respond with the
    ...                optional failInfo `badMessageCheck`.
    [Tags]    hybrid-auth  composite-sig
    ${result}=  Is Certificate And Key Set    ${RELATED_CERT}    ${RELATED_KEY}
    SKIP IF    not ${result}    The Related Certificate and Key are not set.
    ${key}=   Generate Default Key
    ${ir}=   Build Ir From Key  ${key}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${RELATED_KEY}
    ...    cert=${RELATED_CERT}
    ...    alt_signing_key=${RELATED_KEY_SEC}
    ...    bad_message_check=True
    ${protected_ir}=   Add Certs To PKIMessage  ${protected_ir}    ${RELATED_CERT_SEC}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}    ${MULTI_AUTH_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection


##########################
# BadCertTemplate Tests
##########################

CA Should not allow Key Update with same key
    [Documentation]    The CA should not allow a key update with the same key.
    ...                We send a certificate request, which contains the same key as the previous certificate.
    ...                The CA should reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    bad-cert-template   composite-sig
    ${result}=  Is Certificate And Key Set    ${COMPOSITE_SIG_CERT}   ${COMPOSITE_SIG_KEY}    
    SKIP IF    not ${result}    The Composite Certificate and Key are not set.
    ${ir}=   Build Key Update Request    ${COMPOSITE_SIG_KEY}    ${COMPOSITE_SIG_CERT}
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${COMPOSITE_SIG_KEY}
    ...    cert=${COMPOSITE_SIG_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA Should not allow Key Update with revoked key
    [Documentation]    The CA should not allow a key update with a revoked composite-sig key.
    ...                We send a certificate request, which contains a revoked composite-sig key.
    ...                The CA should reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate`.
    [Tags]    badCertTemplate   composite-sig
    ${result}=  Is Certificate And Key Set    ${REVOKED_COMP_CERT}   ${REVOKED_COMP_KEY}
    SKIP IF    not ${result}    The Revoked Composite Certificate and Key are not set.
    ${ir}=   Build Key Update Request    ${REVOKED_COMP_KEY}    ${REVOKED_COMP_CERT}
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${REVOKED_COMP_KEY}
    ...    cert=${REVOKED_COMP_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    certRevoked

CA MUST Reject A Revoked Composite Sig Key
    [Documentation]    According to composite-sig-cms07 the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a already revoked key.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    composite-sig  badCertTemplate
    ${result}=  Is Certificate And Key Set    ${REVOKED_COMP_CERT}    ${REVOKED_COMP_KEY}
    SKIP IF    not ${result}    The Revoked Composite Certificate and Key are not set.
    ${key}=  Generate Default Key
    ${ir}=   Build Ir From Key    ${REVOKED_COMP_KEY}   exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Accept A Valid Composite Sig Update Request
    [Documentation]    The CA should accept a valid composite-sig key update request.
    ...                We send a composite-sig certificate request, which contains a new key,
    ...                the CA should accept the request and issue a valid certificate.
    [Tags]    composite-sig
    ${key}=  Generate Unique Key    composite-sig
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    ${cert}  ${_}=   Issue New Cert For Testing    ${url}   ${key}
    ${key_up}=  Generate Unique Key   composite-sig
    ${cm}=   Get Next Common Name
    ${kur}=   Build Key Update Request    ${key_up}    ${cert}   exclude_fields=senderKID,sender
    ...           common_name=${cm}
    ${protected_kur}=    Protect PKIMessage    ${kur}   signature   private_key=${key}   cert=${cert}
    ${response}=   Exchange PKIMessage    ${protected_kur}   ${url}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be    ${response}    accepted
    ${_}=   Confirm Certificate If Needed    ${response}   url=${url}   protection=signature
    ...        private_key=${key}    cert=${cert}
    Wait Until Server Updated Cert
    VAR   ${UPDATED_COMP_SIG_CERT}    ${cert}   scope=Global
    VAR   ${UPDATED_COMP_SIG_KEY}    ${key}   scope=Global

CA MUST Reject A Update Composite Sig Key
    [Documentation]    According to composite-sig-cms07 the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a already updated key.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    composite-sig
    ${result}=  Is Certificate And Key Set    ${UPDATED_COMP_SIG_CERT}   ${UPDATED_COMP_SIG_KEY}
    SKIP IF    not ${result}    The Updated Composite Certificate and Key are not set.
    ${key}=  Generate Default Key
    ${cert_template}=   Prepare CertTemplate  ${UPDATED_COMP_SIG_KEY}  cert=${UPDATED_COMP_SIG_CERT}   include_fields=subject,publicKey
    ${ir}=   Build Ir From Key    ${UPDATED_COMP_SIG_KEY}   cert_template=${cert_template}    exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject A Revoked Composite KEM Key
    [Documentation]    According to composite-kem-pki07 the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a already revoked key.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    composite-kem
    ${result}=  Is Certificate And Key Set   ${REVOKED_COMP_KEM_CERT}   ${REVOKED_COMP_KEM_KEY}
    SKIP IF    not ${result}    The Revoked Composite KEM Certificate and Key are not set.
    ${key}=  Generate Default Key
    ${ir}=   Build Ir From Key    ${REVOKED_COMP_KEM_KEY}   exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject A Update Composite KEM Key
    [Documentation]    According to composite-kem-pki07 the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a already updated key.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    composite-kem
    ${result}=  Is Certificate And Key Set    ${COMPOSITE_KEM_CERT}   ${COMPOSITE_KEM_KEY}
    SKIP IF    not ${result}    The Updated Composite KEM Certificate and Key are not set.
    ${key}=  Generate Default Key
    ${ir}=   Build Ir From Key    ${COMPOSITE_KEM_KEY}   exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check That The ML-DSA Key Is Not Used Inside Another Cert
    [Documentation]    According to composite-sig-cms07 the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a ML-DSA key, which is already used
    ...                inside another certificate. The CA MUST reject the request and MAY respond with the optional
    ...                failInfo `badCertTemplate`.
    [Tags]    composite-sig  composite
    ${result}=  Is Certificate And Key Set    ${COMPOSITE_SIG_CERT}   ${COMPOSITE_SIG_KEY}    
    SKIP IF    not ${result}    The Composite Certificate and Key are not set.
    ${key}=   Generate Key  algorithm=composite-sig  pq_key=${COMPOSITE_SIG_KEY.pq_key}
    ${cert_template}=   Prepare CertTemplate  ${key}  cert=${COMPOSITE_SIG_CERT}   include_fields=subject,publicKey
    ${ir}=   Build Ir From Key    ${key}   exclude_fields=senderKID,sender   cert_template=${cert_template}
    ${protected_ir}=   Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check that the traditional key is not used inside another Cert
    [Documentation]    According to composite-sig-cms07 the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a traditional key, which is
    ...                already used inside another certificate. The CA MUST reject the request and MAY respond with
    ...                the optional failInfo `badCertTemplate`.
    [Tags]    composite-sig  composite
    ${result}=  Is Certificate And Key Set    ${COMPOSITE_SIG_CERT}   ${COMPOSITE_SIG_KEY}
    SKIP IF    not ${result}    The Composite Certificate and Key are not set, the setup failed.
    ${key}=   Generate Key  algorithm=composite-sig  trad_key=${COMPOSITE_SIG_KEY.trad_key}
    ${cert_template}=   Prepare CertTemplate  ${key}  cert=${COMPOSITE_SIG_CERT}   include_fields=subject,publicKey
    ${ir}=   Build Ir From Key    ${key}   exclude_fields=senderKID,sender   cert_template=${cert_template}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check that the ML-KEM key is not used inside another Cert
    [Documentation]    According to composite-kem-pki07 the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a ML-KEM key, which is already used
    ...                inside another certificate. The CA MUST reject the request and MAY respond with the optional
    ...                failInfo `badCertTemplate`.
    [Tags]    composite-kem
    ${result}=  Is Certificate And Key Set    ${COMPOSITE_KEM_CERT}    ${COMPOSITE_KEM_KEY}
    SKIP IF    not ${result}    The Composite KEM Certificate and Key are not set.
    ${key}=   Generate Key  algorithm=composite-kem  pq_key=${COMPOSITE_KEM_KEY.pq_key}
    ${ir}=   Build Ir From Key    ${key}   exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect Composite Sig   ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check That The Composite SIG ML-DSA Key Is Not Revoked
    [Documentation]    According to composite-sig the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a ML-DSA key, which is already revoked.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    composite-sig
    ${result}=  Is Certificate And Key Set    ${REVOKED_COMP_CERT}   ${REVOKED_COMP_KEY}
    SKIP IF    not ${result}    The Revoked Composite Certificate and Key are not set.
    ${key}=   Generate Key  algorithm=composite-sig  pq_key=${REVOKED_COMP_KEY.pq_key}
    ${ir}=   Build Ir From Key    ${key}   exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect Composite Sig  ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check that the Composite KEM traditional key is not revoked
    [Documentation]    According to composite-kem the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a traditional key, which is
    ...                already revoked. The CA MUST reject the request and MAY respond with the optional
    ...                failInfo `badCertTemplate`.
    [Tags]     composite-kem
    ${result}=  Is Certificate And Key Set    ${REVOKED_COMP_CERT}    ${REVOKED_COMP_KEY}
    SKIP IF    not ${result}    The Revoked Composite Certificate and Key are not set.
    ${key}=   Generate Key  algorithm=composite-sig  trad_key=${REVOKED_COMP_KEY.trad_key}
    ${cert_template}=   Prepare CertTemplate  ${key}  cert=${REVOKED_COMP_CERT}   include_fields=subject,publicKey
    ${ir}=   Build Ir From Key    ${key}   exclude_fields=senderKID,sender   cert_template=${cert_template}
    ...        recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect Composite Sig    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check that the Composite KEM ML-KEM key is not revoked
    [Documentation]    According to composite-kem the keys should not be used inside another certificate.
    ...                We send a composite-sig certificate request, which contains a ML-KEM key, which is already revoked.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    composite-kem  composite
    ${result}=  Is Certificate And Key Set    ${REVOKED_COMP_KEM_CERT}    ${REVOKED_COMP_KEM_KEY}
    Skip If    not ${result}    The Revoked Composite KEM Key is not set.
    ${key}=   Generate Key  algorithm=composite-kem  pq_key=${REVOKED_COMP_KEM_KEY.pq_key}
    ${cert_template}=   Prepare CertTemplate  ${key}  cert=${REVOKED_COMP_KEM_CERT}   include_fields=subject,publicKey
    ${ir}=   Build Ir From Key    ${key}   exclude_fields=senderKID,sender   cert_template=${cert_template}
    ...        recipient=${RECIPIENT}
    ${protected_ir}=    Default Protect Composite Sig    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Support Composite Sig Signed PKIMessage
    [Documentation]    The CA MUST support a PKIMessage signed with composite signature. We send a certificate request,
    ...                which is signed with a composite signature. The CA MUST correctly validate the signature and
    ...                issue a new certificate.
    [Tags]    composite-sig  composite
    ${key}=  Generate Fresh Composite Sig Key
    ${ir}=   Build Ir From Key    ${key}  exclude_fields=senderKID,sender  recipient=${RECIPIENT}
    ${response}=    Protect And Exchange Composite Sig  ${ir}  ${COMPOSITE_SIG_KEY}  ${COMPOSITE_SIG_CERT}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted

CA MUST Detect Invalid Composite Sig PKIProtection
    [Documentation]    The CA MUST support a PKIMessage signed with composite signature. We send a certificate request,
    ...                which is invalid signed with a composite signature. The CA MUST reject the request and MAY respond
    ...                with the optional failInfo `badMessageCheck`.
    [Tags]    composite-sig  composite
    # Always the latest version of the algorithm.
    ${key}=  Generate Fresh Composite Sig Key
    ${ir}=   Build Ir From Key    ${key}  exclude_fields=senderKID,sender  
    ...      recipient=${RECIPIENT}
    ${protected_ir}=    Protect Hybrid PKIMessage    ${ir}   ${COMPOSITE_SIG_KEY}
    ...                 cert=${COMPOSITE_SIG_CERT}   bad_message_check=True
    ${url}=  Get Composite Issuing URL
    ${response}=   Exchange PKIMessage    ${protected_ir}   ${url}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck

CA MUST Revoke a Composite Sig Cert
    [Documentation]    The CA MUST revoke a composite-sig certificate in accordance with RFC 4210.
    ...                We send a certificate request, which contains a composite-sig key. The CA MUST revoke the
    ...                certificate and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]    composite-sig  composite
    # Always the latest version of the algorithm.
    ${key}=  Generate Fresh Composite Sig Key
    ${url}=   Get Composite Issuing URL
    ${cert}  ${_}=  Issue New Cert For Testing   ${url}   ${key}
    ${rr}=   Build CMP Revoke Request    cert=${cert}   reason=keyCompromise
    ${response}=    Protect And Exchange Composite Sig  ${rr}  ${key}  ${cert}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    accepted


*** Keywords ***
Setup Certs For Migration Tests
    [Documentation]    Set up the related certificate tests.
    Set Up Test Suite
    Setup PQ Sig Cert
    Issue Relevant Certs
    Issue New Composite Certs

Default Protect Composite Sig
    [Documentation]    Protect a PKIMessage with a composite signature key and certificate.
    ...                The PKIMessage is protected with the composite signature.
    [Tags]    composite-sig  protection
    [Arguments]    ${pki_message}
    ${protected_msg}=    Protect PKIMessage    ${pki_message}  signature  private_key=${COMPOSITE_SIG_KEY}
    ...    cert=${COMPOSITE_SIG_CERT}
    RETURN  ${protected_msg}

Exchange Composite Request
    [Documentation]    Exchange a composite signature request.
    [Arguments]     ${suffix}=${COMPOSITE_SUFFIX}   ${key}=${None}   ${implicit_confirm}=${ALLOW_IMPLICIT_CONFIRM}
    IF   '${key}'=='${None}'
        ${key}=   Generate Key    composite-sig
    END
    ${ir}=   Build Ir From Key    ${key}  exclude_fields=senderKID,sender
    ...      recipient=${RECIPIENT}    implicit_confirm=${implicit_confirm}
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}   ${suffix}
    RETURN    ${response}

Issue Relevant Certs
    [Documentation]    Issue the relevant certificates for the tests.
    ${pq_key}=   Generate Default PQ SIG Key
    ${pq_url}=  Get PQ Issuing URL
    ${pq_cert}  ${_}=   Issue New Cert For Testing    ${pq_url}   ${pq_key}
    ${rr}=   Build CMP Revoke Request   cert=${pq_cert}   reason=keyCompromise
    ...           recipient=${RECIPIENT}
    ${prot_rr}=  Protect PKIMessage    ${rr}   signature   private_key=${pq_key}   cert=${pq_cert}
    ${response}=  Exchange PKIMessage    ${prot_rr}   ${pq_url}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    accepted
    Wait Until Server Revoked Cert
    VAR   ${REVOKED_CERT}   ${pq_cert}   scope=Global
    VAR   ${REVOKED_KEY}   ${pq_key}   scope=Global
    ${kur_key}=   Generate Default PQ SIG Key
    ${pq_url}=  Get PQ Issuing URL
    ${pq_cert}  ${_}=   Issue New Cert For Testing    ${pq_url}   ${kur_key}
    ${cm}=  Get Next Common Name
    ${up_key}=   Generate Default PQ SIG Key
    ${kur}=  Build Key Update Request  ${up_key}    ${pq_cert}   recipient=${RECIPIENT}
    ...          exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${prot_kur}=  Protect PKIMessage    ${kur}   signature   private_key=${kur_key}   cert=${pq_cert}
    ${response}=  Exchange PKIMessage    ${prot_kur}   ${pq_url}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be    ${response}    accepted
    ${_}=   Confirm Certificate If Needed    ${response}   url=${pq_url}
    Wait Until Server Updated Cert
    VAR   ${UPDATED_CERT}   ${pq_cert}   scope=Global
    VAR   ${UPDATED_KEY}   ${kur_key}   scope=Global
    ${ca_key}=   Generate Default PQ SIG Key
    ${extns}=   Prepare Extensions    is_ca=True
    ${ir}=   Build Ir From Key    ${ca_key}   recipient=${RECIPIENT}   extensions=${extns}
    ...      exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${prot_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=  Exchange PKIMessage    ${prot_ir}   ${pq_url}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${ca_cert}=   Confirm Certificate If Needed    ${response}   url=${pq_url}
    VAR   ${CA_CERT}   ${ca_cert}   scope=Global
    VAR   ${CA_KEY}   ${ca_key}   scope=Global

Protect PKIMessage with Composite Sig
    [Documentation]    Protect a PKIMessage with a composite signature key and certificate.
    ...                The PKIMessage is protected with the composite signature.
    [Tags]    composite-sig  protection
    [Arguments]    ${pki_message}  ${key}  ${cert}
    ${protected_msg}=    Protect Hybrid PKIMessage    ${pki_message}   ${key}   cert=${cert}
    RETURN  ${protected_msg}

Generate Fresh Composite Sig Key
    [Documentation]    Generate a fresh composite signature key, which is not burned at all.
    [Tags]    composite-sig
    # Generates always the latest version of the algorithm.
    ${key}=   Generate Unique Key  composite-sig
    RETURN  ${key}
    
Issue Or Get Composite Sig Cert And Key
    [Documentation]    Get an already issued composite signature key and certificate, or generate 
    ...                a new one if not already issued. Used to save resources, Could be turned off.
    [Tags]    composite-sig
    ${result}=  Is Certificate And Key Set    ${COMPOSITE_SIG_CERT}   ${COMPOSITE_SIG_KEY}
    IF  ${result}
        RETURN   ${COMPOSITE_SIG_CERT}   ${COMPOSITE_SIG_KEY}
    ELSE
        ${key}=  Generate Fresh Composite Sig Key
        ${url}=   Get Composite Issuing URL
        ${cert}  ${_}=  Issue New Cert For Testing   ${url}   ${key}
        VAR   ${COMPOSITE_SIG_CERT}=   ${cert}   scope=Global
        VAR   ${COMPOSITE_SIG_KEY}=   ${key}   scope=Global
        RETURN  ${cert}  ${key}
    END

Protect And Exchange Composite Sig
    [Documentation]    Protect a PKIMessage with a composite signature key and certificate and exchange it with the CA.
    ...                The PKIMessage is protected with the composite signature and exchanged with the CA.
    [Tags]    composite-sig  protection
    [Arguments]    ${pki_message}  ${key}  ${cert}
    ${protected_msg}=    Protect Hybrid PKIMessage     ${pki_message}   ${key}   cert=${cert}
    ${url}=   Get Composite Issuing URL
    ${response}=   Exchange PKIMessage    ${protected_msg}   ${url}
    RETURN  ${response}

Setup Composite KEM Certs
    [Documentation]    Issue new composite KEM certificates for the tests.
    [Tags]    composite-kem
    ${comp_kem_cert}  ${comp_kem_key}=  Issue new Composite KEM Cert
    VAR   ${COMPOSITE_KEM_CERT}   ${comp_kem_cert}   scope=Global   # robocop: off=VAR04
    VAR   ${COMPOSITE_KEM_KEY}   ${comp_kem_key}   scope=Global   # robocop: off=VAR04
    Setup Revoke Composite KEM Cert
    Setup Update Composite KEM Cert

Establish New Composite KEM SS
    [Documentation]    Establish a new composite KEM shared secret.
    ...                The PKIMessage is protected with the composite KEM signature and exchanged with the CA.
    ...
    ...               Returns:
    ...               - ${ss}  The established shared secret.
    ...               - ${tx_id}  The transaction ID of the established shared secret.
    [Tags]    composite-kem
    [Arguments]    ${kem_key}   ${kem_cert}
    ${genm}=   Build KEMBasedMAC General Message   ${kem_key}    ${kem_cert}
    ${url}=   Get PQ Issuing URL
    ${genp}=   Exchange PKIMessage    ${genm}   ${url}
    ${ss}=   Validate Genp KEMCiphertextInfo    ${genp}    ${kem_key}
    ${tx_id}=   Get Asn1 Value As Bytes   ${genm}  header.transactionID
    RETURN  ${ss}  ${tx_id}

Issue new Composite KEM Cert
    [Documentation]    Issue new composite KEM certificates for the tests.
    ...                The PKIMessage is protected with the composite KEM signature and exchanged with the CA.
    ...
    ...                Returns:
    ...                - ${comp_kem_cert}  The composite KEM certificate.
    ...                - ${comp_kem_key}   The composite KEM key.
    [Tags]    composite-kem
    ${comp_kem_key}=  Generate Unique Key    composite-kem
    ${ir}=  Build Ir From Key    ${comp_kem_key}   recipient=${RECIPIENT}
    ...     exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${prot_ir}=  Default Protect Composite Sig    ${ir}
    ${composite_url}=  Get Composite Issuing URL
    ${response}=  Exchange PKIMessage    ${prot_ir}   ${composite_url}
    PKIMessage Body Type Must Be    ${response}    ip
    ${comp_kem_cert}=   Confirm EncrCert Certificate If Needed    ${response}  ${comp_kem_key}
    ...                 url=${composite_url}   exclude_rid_check=${True}   private_key=${COMPOSITE_SIG_KEY}
    ...                 cert=${COMPOSITE_SIG_CERT}
    RETURN  ${comp_kem_cert}  ${comp_kem_key}

Setup Update Composite KEM Cert
    [Documentation]    Update a certificate with a KEM key.
    ...
    ...                Returns:
    ...                - ${comp_kem_cert}  The updated composite KEM certificate.
    ...                - ${comp_kem_key}   The updated composite KEM key.
    [Tags]    kem
    ${comp_kem_cert}  ${comp_kem_key}=  Issue new Composite KEM Cert
    ${ss}  ${tx_id}=   Establish New Composite KEM SS   ${comp_kem_key}  ${comp_kem_cert}
    ${comp_kem_key2}=  Generate Unique Key    composite-kem
    ${kur}=  Build Key Update Request    ${comp_kem_key2}   recipient=${RECIPIENT}   for_mac=True
    ...     exclude_fields=${None}   implicit_confirm=${True}  transaction_id=${tx_id}   sender=${SENDER}
    ${prot_ir}=  Protect PKIMessage KEMBasedMAC    ${kur}   shared_secret=${ss}
    ${cert_chain}=   Build Cert Chain From Dir    ${comp_kem_cert}   data/cert_logs
    ${prot_ir}=  Patch ExtraCerts    ${prot_ir}   ${cert_chain}
    ${composite_url}=  Get Composite Issuing URL
    ${response}=  Exchange PKIMessage    ${prot_ir}   ${composite_url}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be    ${response}    accepted
    ${comp_kem_cert2}=   Confirm EncrCert Certificate If Needed    ${response}  ${comp_kem_key2}
    ...                 url=${composite_url}   exclude_rid_check=${True}   shared_secret=${ss}
    ...                 for_kem_based_mac=True
    VAR   ${UPDATED_COMP_KEM_CERT}   ${comp_kem_cert2}   scope=Global   # robocop: off=VAR04
    VAR   ${UPDATED_COMP_KEM_KEY}   ${comp_kem_key2}   scope=Global   # robocop: off=VAR04

Setup Revoke Composite KEM Cert
    [Documentation]    Revoke a composite KEM certificate.
    ${comp_kem_cert3}  ${comp_kem_key3}=  Issue new Composite KEM Cert
    ${composite_url}=  Get Composite Issuing URL
    ${ss}  ${tx_id}=   Establish New Composite KEM SS   ${comp_kem_key3}  ${comp_kem_cert3}
    ${ir}=  Build CMP Revoke Request    ${comp_kem_cert3}   reason=keyCompromise   sender=${SENDER}
    ...     recipient=${RECIPIENT}   for_mac=True   exclude_fields=${None}
    ...     transaction_id=${tx_id}
    ${prot_ir}=  Protect PKIMessage KEMBasedMAC    ${ir}   shared_secret=${ss}
    ${cert_chain}=   Build Cert Chain From Dir    ${comp_kem_cert3}   data/cert_logs
    ${prot_ir}=  Patch ExtraCerts    ${prot_ir}   ${cert_chain}
    ${response}=  Exchange PKIMessage    ${prot_ir}   ${composite_url}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    accepted
    Wait Until Server Revoked Cert
    VAR   ${REVOKED_COMP_KEM_CERT}   ${comp_kem_cert3}   scope=Global   # robocop: off=VAR04
    VAR   ${REVOKED_COMP_KEM_KEY}   ${comp_kem_key3}   scope=Global   # robocop: off=VAR04

Issue New Composite Certs
    [Documentation]    Issue new composite certificates for the tests.
    [Tags]    composite-sig
    Setup Composite Sig Cert
    ${composite_url}=  Get Composite Issuing URL
    ${rr_comp_key}=  Generate Fresh Composite Sig Key
    ${rr_comp_cert}  ${_}=   Issue New Cert For Testing    ${composite_url}   ${rr_comp_key}
    ${rr}=   Build CMP Revoke Request   cert=${rr_comp_cert}   reason=keyCompromise
    ...           recipient=${RECIPIENT}
    ${prot_rr}=  Protect PKIMessage    ${rr}   signature   private_key=${rr_comp_key}   cert=${rr_comp_cert}
    ${response}=  Exchange PKIMessage    ${prot_rr}   ${composite_url}
    Wait Until Server Revoked Cert
    VAR   ${REVOKED_COMP_CERT}   ${rr_comp_cert}   scope=Global   # robocop: off=VAR04
    VAR   ${REVOKED_COMP_KEY}   ${rr_comp_key}   scope=Global     # robocop: off=VAR04
    Setup Composite KEM Certs
