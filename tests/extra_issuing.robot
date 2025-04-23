# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Tests for extra issuing logic.

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             String
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../resources/certextractutils.py
Library             ../resources/envdatautils.py
Library             ../resources/compareutils.py

Suite Setup         Set Up Extra Issuing Logic Test Suite
Test Tags    non-signing-key


*** Variables ***
${regToken}   SuperSecretRegToken   # robocop: off=NAME08


*** Keywords ***
Set Up Extra Issuing Logic Test Suite
    [Documentation]     Set up the test suite by generating a key and a certificate for the CA.
    [Tags]    setup
    Set Up Test Suite
    ${x25519_cert}=   May Load Cert   ${CA_X25519_CERT}
    VAR    ${CA_X25519_CERT}    ${X25519_cert}  scope=Global
    ${x448_cert}=   May Load Cert   ${CA_X448_CERT}
    VAR    ${CA_X448_CERT}    ${x448_cert}  scope=Global
    ${ecc_cert}=   May Load Cert   ${CA_ECC_CERT}
    VAR    ${CA_ECC_CERT}    ${ecc_cert}   scope=Global
    ${hybrid_kem_cert}=   May Load Cert   ${CA_HYBRID_KEM_CERT}
    VAR    ${CA_HYBRID_KEM_CERT}    ${hybrid_kem_cert}   scope=Global
    ${kem_cert}=   May Load Cert   ${CA_KEM_CERT}
    VAR    ${CA_KEM_CERT}    ${kem_cert}   scope=Global

Build Encrypted Key Request
    [Documentation]    Build an request with an encrypted key as POPO.
    [Tags]     popo  encryptedKey
    [Arguments]    ${key}   ${ca_cert}   ${cmp_protection}   ${ecc_key}=${None}   &{args}
    ${cm}=   Get Next Common Name
    ${sender}=   Get From Dictionary    ${args}   sender   default=${cm}
    ${for_agreement}=   Get From Dictionary    ${args}   for_agreement   default=True
    ${use_string}=   Get From Dictionary    ${args}   use_string   default=False
    ${enc_key_id}=   Prepare EncKeyWithID    ${key}  sender=${sender}   use_string=${use_string}
    ${popo}=   Prepare EncryptedKey For POPO    ${enc_key_id}   ${None}   ${ca_cert}
    ...        for_agreement=${for_agreement}   cmp_protection_cert=${cmp_protection}
    ...        private_key=${key}   private_key=${ecc_key}
    ${ir}=   Build Ir From Key    ${key}    common_name=${cm}   popo=${popo}
    ...              recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    RETURN   ${ir}


*** Test Cases ***
#########################
# KeyAgreement POPO
##########################

############################
## Challenge POPO
############################

CA Must Accept EncrCert POPO For Request With X25519 Key
    [Documentation]    According to RFC 4210-bis18 5.2.8.4 the CA must accept a request with a X25519 key with the
    ...    inclusion of the `encrCert` challenge to issue a valid request. We send a valid request with a
    ...    X25519 key and the `encrCert` challenge. The CA must issue a certificate for the request.
    [Tags]    ir    key    popo    positive    robot:skip-on-failure  x25519  keyAgree
    Should Contain    ${ALLOWED_ALGORITHM}    x25519
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement
    ${new_key}=    Generate Unique Key    x25519
    ${popo}=   Prepare POPO Challenge For Non Signing Key    True   False
    ${ir}=    Build Ir From Key
    ...    ${new_key}
    ...    common_name=${SENDER}
    ...    popo=${popo}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get EncCert From PKIMessage    ${response}   ee_private_key=${new_key}
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    cert=${cert}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ${protected_cert_conf}=    Default Protect PKIMessage    ${cert_conf}
    ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    VAR    ${CLIENT_X25519_CERT}    ${cert}    scope=GLOBAL
    VAR    ${CLIENT_X25519_KEY}    ${new_key}    scope=GLOBAL

CA Must Accept EncrCert POPO For Request With X448 Key
    [Documentation]    According to RFC 4210-bis18 5.2.8.4 the CA must accept a request with a x448 key with the
    ...    inclusion of the `encrCert` challenge to issue a valid request. We send a valid request with a
    ...    x448 key and the `encrCert` challenge. The CA must issue a certificate for the request.
    [Tags]    ir    key    popo    positive    robot:skip-on-failure  x448  keyAgree
    Should Contain    ${ALLOWED_ALGORITHM}    x448
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement
    ${new_key}=    Generate Unique Key    x448
    ${popo}=   Prepare POPO Challenge For Non Signing Key    True   False
    ${ir}=    Build Ir From Key
    ...    ${new_key}
    ...    common_name=${SENDER}
    ...    popo=${popo}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get EncCert From PKIMessage    ${response}   ee_private_key=${new_key}
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    cert=${cert}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ${protected_cert_conf}=    Default Protect PKIMessage    ${cert_conf}
    ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    VAR    ${CLIENT_X448_CERT}    ${cert}    scope=GLOBAL
    VAR    ${CLIENT_X448_KEY}    ${new_key}    scope=GLOBAL

CA Must Accept EncrCert POPO For Request With ECC Key
    [Documentation]    According to RFC 4210-bis18 5.2.8.4 the CA must accept a request with a ECC key with the
    ...    inclusion of the `encrCert` challenge to issue a valid request. We send a valid request with a
    ...    ECC key and the `encrCert` challenge. The CA must issue a certificate for the request.
    [Tags]    ir    key    popo    positive    robot:skip-on-failure  ecc  keyAgree  advanced
    Should Contain    ${ALLOWED_ALGORITHM}    ecc
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement
    ${new_key}=    Generate Unique Key    ecc
    ${popo}=   Prepare POPO Challenge For Non Signing Key    True   False
    ${ir}=    Build Ir From Key
    ...    ${new_key}
    ...    common_name=${SENDER}
    ...    popo=${popo}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get EncCert From PKIMessage    ${response}   ee_private_key=${new_key}
    ...        server_cert=${CA_ECC_CERT}  exclude_rid_check=True
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    cert=${cert}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ${protected_cert_conf}=    Default Protect PKIMessage    ${cert_conf}
    ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    VAR    ${CLIENT_ECC_CERT}    ${cert}    scope=GLOBAL
    VAR    ${CLIENT_ECC_KEY}    ${new_key}    scope=GLOBAL

CA Must Accept ChallengeResp POPO For Request With X25519 Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a X25519
    ...     SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  robot:skip-on-failure  advanced  x25519
    ...       challenge-response  envData
    Should Contain    ${ALLOWED_ALGORITHM}    x25519
    ${key}=   Generate Key     x25519
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   False
    ${ir}=   Build Ir From Key    ${key}    popo=${popo}   pvno=3   common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${key}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}   protection=signature
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA Must Accept ChallengeResp POPO For Request With X448 Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a X448
    ...     SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  robot:skip-on-failure  advanced  x448  challenge-response  envData
    Should Contain    ${ALLOWED_ALGORITHM}    x448
    ${key}=   Generate Key     x448
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   False
    ${ir}=   Build Ir From Key    ${key}    popo=${popo}   pvno=3  common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${key}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}   protection=signature
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA Must Accept ChallengeResp POPO For Request With ECC Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a ECC
    ...     SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  robot:skip-on-failure  advanced  ecc  challenge-response  envData
    Should Contain    ${ALLOWED_ALGORITHM}    ecc
    ${key}=   Generate Key     ecc
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   False
    ${ir}=   Build Ir From Key    ${key}    popo=${popo}   pvno=3  common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${key}   kari_cert=${CA_ECC_CERT}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}   protection=signature
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key    ${cert}  ${key}

############################
## AgreeMac POPO
############################

CA MUST Accept Valid X25519 AgreeMac POP
    [Documentation]     According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the AgreeMac POP to
    ...    prove possession of the private key. We send a PKIMessage with an X25519 agreeMac POP. The CA MUST accept
    ...    the request and issue a certificate.
    [Tags]    positive    agreeMAC   popo  issuing  advanced  x25519
    ${result}=   Is Certificate Set  ${CA_X25519_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA x25519 certificate is not set.
    ${key}=   Generate Key     x25519
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    ${popo}=   Prepare PKMAC POPO  ${cert_request}  ${CA_X25519_CERT}  ${key}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}   popo=${popo}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Reject Invalid X25519 agreeMAC POP
    [Documentation]   According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the agreeMAC POP to
    ...    prove possession of the private key. We send a PKIMessage with an invalid X25519 agreeMac POP. The CA
    ...    MUST reject the request and may respond with the failinfo `badPOP`.
    [Tags]    negative    agreeMAC   popo  issuing  advanced  x25519
    ${result}=   Is Certificate Set  ${CA_X25519_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA x25519 certificate is not set.
    ${key}=   Generate Key     x25519
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    ${popo}=   Prepare PKMAC POPO  ${cert_request}  ${CA_X25519_CERT}  ${key}  bad_pop=True
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}   popo=${popo}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP   True

CA MUST Accept Valid X448 AgreeMac POP
    [Documentation]     According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the AgreeMac POP to
    ...    prove possession of the private key. We send a PKIMessage with an X448 agreeMac POP. The CA MUST accept
    ...    the request and issue a certificate.
    [Tags]    positive    agreeMAC   popo  issuing  advanced  x448
    ${result}=   Is Certificate Set  ${CA_X448_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA x448 certificate is not set.
    ${key}=   Generate Key     x448
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    ${popo}=   Prepare PKMAC POPO  ${cert_request}  ${CA_X448_CERT}  ${key}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}   popo=${popo}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Reject Invalid X448 agreeMAC POP
    [Documentation]     According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the agreeMAC POP to
    ...    prove possession of the private key. We send a PKIMessage with an invalid X448 agreeMac POP. The CA
    ...    MUST reject the request and may respond with the failinfo `badPOP`.
    [Tags]    negative    agreeMAC   popo  issuing  advanced  x448
    ${result}=   Is Certificate Set  ${CA_X448_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA x448 certificate is not set.
    ${key}=   Generate Key     x448
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    ${popo}=   Prepare PKMAC POPO  ${cert_request}  ${CA_X448_CERT}  ${key}  bad_pop=True
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}   popo=${popo}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP   True

CA MUST Accept Valid ECC AgreeMac POP
    [Documentation]     According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the AgreeMac POP to
    ...    prove possession of the private key. We send a PKIMessage with an ECC agreeMac POP. The CA MUST accept
    ...    the request and issue a certificate.
    [Tags]    positive    agreeMAC   popo  issuing  advanced  ecc
    ${result}=   Is Certificate Set  ${CA_ECC_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA ecc certificate is not set.
    ${key}=   Generate Key     ecc   curve=secp256r1
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    ${popo}=   Prepare PKMAC POPO  ${cert_request}  ${CA_ECC_CERT}  ${key}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}   popo=${popo}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Reject Invalid ECC agreeMAC POP
    [Documentation]     According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the agreeMAC POP to
    ...    prove possession of the private key. We send a PKIMessage with an invalid ECC agreeMac POP. The CA
    ...    MUST reject the request and may respond with the failinfo `badPOP`.
    [Tags]    negative    agreeMAC   popo  issuing  advanced  ecc
    ${result}=   Is Certificate Set  ${CA_ECC_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA ecc certificate is not set.
    ${key}=   Generate Key     ecc   curve=secp256r1
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    ${popo}=   Prepare PKMAC POPO  ${cert_request}  ${CA_ECC_CERT}  ${key}  bad_pop=True
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}   popo=${popo}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP   True

############################
### Encrypted Key POPO
############################

CA MUST Accept Valid KeyAgree Encrypted Key with PWRI
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a MAC protected PKIMessage with a `PWRI` keyAgreement
    ...    encryptedKey as POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  mac  pwri
    ${key}=   Generate Default KeyAgreement Key
    ${cm}=   Get Next Common Name
    ${cek}=   Generate Unique Byte Values    1   32
    ${pwri}=  Prepare PasswordRecipientInfo    ${PRE_SHARED_SECRET}   cek=${cek[0]}
    ${enc_key_id}=   Prepare EncKeyWithID    ${key}  sender=${cm}
    ${popo}=   Prepare EncryptedKey For POPO    ${enc_key_id}   ${None}
    ...         recip_info=${pwri}   cek=${cek[0]}  for_agreement=True
    ${ir}=   Build Ir From Key    ${key}    common_name=${cm}   popo=${popo}
    ...               recipient=${RECIPIENT}   sender=${SENDER}  for_mac=True
    ${protected_ir}=   Default Protect PKIMessage  ${ir}   protection=${DEFAULT_MAC_ALGORITHM}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Issue A Cert if the KeyAgree Encrypted Key was present
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a PKIMessage with an encryptedKey as POPO. The CA MUST accept
    ...    the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced
    ${ca_cert}=   May Load Cert   ${CA_RSA_ENCR_CERT}
    ${result}=   Is Certificate Set  ${ca_cert}
    SKIP IF    not ${result}    This test is skipped because the CA RSA encryption certificate is not set.
    ${key}=   Generate Default KeyAgreement Key
    ${ir}=  Build Encrypted Key Request   ${key}   ${ca_cert}   ${ISSUED_CERT}
    ...     for_agreement=True
    ${protected_ir}=   Default Protect PKIMessage  ${ir}   protection=signature
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Reject Invalid KeyAgree Encrypted Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a PKIMessage with a different key in the
    ...    encryptedKey as in the `CertRequest`. The CA MUST reject the request and may respond with the
    ...    failinfo `badCertTemplate` or `badPOP`.
    [Tags]    negative    encryptedKey   popo  issuing  advanced
    ${ca_cert}=   May Load Cert   ${CA_RSA_ENCR_CERT}
    ${result}=   Is Certificate Set  ${ca_cert}
    SKIP IF    not ${result}    This test is skipped because the CA RSA encryption certificate is not set.
    ${key}=   Generate Default KeyAgreement Key
    ${cm}=   Get Next Common Name
    ${pub_key}=  Generate Different Public Key   ${key}  x25519
    ${cert_request}=   Prepare CertRequest   ${pub_key}  ${cm}
    ${enc_key_id}=   Prepare EncKeyWithID    ${key}   sender=${SENDER}   use_string=False
    ${rid}=   Prepare Recipient Identifier    ${ISSUED_CERT}
    ${popo}=   Prepare EncryptedKey For POPO    ${enc_key_id}   ${rid}   ${ca_cert}   for_agreement=True
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}   popo=${popo}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=   Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badPOP

CA MUST Accept Valid KeyAgree Encrypted Key With X448
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a PKIMessage with an X448 encryptedKey as POPO.
    ...    The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  x448
    ${result}=   Is Certificate Set  ${CA_X448_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA x448 certificate is not set.
    ${new_key}=   Generate Key     x25519
    ${ir}=   Build Encrypted Key Request    ${new_key}   ${CA_X448_CERT}   ${CLIENT_X448_CERT}
    ...       ${CLIENT_X448_KEY}      for_agreement=True
    ${protected_ir}=   Protect PKIMessage  ${ir}   dh   private_key=${CLIENT_X448_KEY}
    ...                peer=${CA_X448_CERT}   cert=${CLIENT_X448_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${new_key}

CA MUST Accept Valid KeyAgree Encrypted Key With X25519
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a PKIMessage with an X25519 encryptedKey as POPO.
    ...    The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  x25519
    ${result}=   Is Certificate Set  ${CA_X25519_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA x25519 certificate is not set.
    ${key}=   Generate Default KeyAgreement Key
    ${ir}=   Build Encrypted Key Request    ${key}   ${CA_X25519_CERT}   ${CLIENT_X25519_CERT}   ${CLIENT_X25519_KEY}
    ...      for_agreement=True
    ${protected_ir}=   Protect PKIMessage  ${ir}   dh   private_key=${CLIENT_X25519_KEY}
    ...                peer=${CA_X25519_CERT}   cert=${CLIENT_X25519_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Accept Valid KeyAgree Encrypted Key With ECC
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a PKIMessage with an ECC encryptedKey as POPO.
    ...    The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  ecc
    ${result}=   Is Certificate Set  ${CA_ECC_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA ecc certificate is not set.
    ${key}=   Generate Default KeyAgreement Key
    ${ir}=   Build Encrypted Key Request    ${key}   ${CA_ECC_CERT}   ${CLIENT_ECC_CERT}   ${CLIENT_ECC_KEY}
    ...      for_agreement=True
    ${protected_ir}=   Protect PKIMessage  ${ir}   dh   private_key=${CLIENT_ECC_KEY}
    ...                peer=${CA_ECC_CERT}   cert=${CLIENT_ECC_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Accept Valid KeyAgree Encrypted Key With KEM Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a PKIMessage with an KEM encryptedKey as POPO.
    ...    The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  kem
    ${result}=   Is Certificate Set  ${CA_KEM_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA kem certificate is not set.
    ${key}=   Generate Default KeyAgreement Key
    ${ir}=   Build Encrypted Key Request    ${key}   ${CA_KEM_CERT}   ${ISSUED_CERT}
    ...      for_agreement=True
    ${protected_ir}=   Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Accept Valid KeyAgree Encrypted Key With Hybrid KEM Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a PKIMessage with an hybrid KEM encryptedKey as POPO.
    ...    The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  hybrid-kem  kem
    ${result}=   Is Certificate Set  ${CA_HYBRID_KEM_CERT}
    SKIP IF    not ${result}    This test is skipped because the CA hybrid kem certificate is not set.
    ${key}=   Generate Default KeyAgreement Key
    ${ir}=  Build Encrypted Key Request   ${key}   ${CA_HYBRID_KEM_CERT}   ${ISSUED_CERT}
    ...     for_agreement=True
    ${protected_ir}=   Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

############################
# KeyEncipherment POPO
############################

CA MUST Accept Valid KeyEnc Encrypted Key with PWRI
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send a MAC protected PKIMessage with a `PWRI` keyEncipherment
    ...    encryptedKey as POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  mac  pwri  keyEnc
    ${key}=   Generate Default KeyEncipherment Key
    ${cm}=   Get Next Common Name
    ${cek}=   Generate Unique Byte Values    1   32
    ${pwri}=  Prepare PasswordRecipientInfo    ${PRE_SHARED_SECRET}   cek=${cek[0]}
    ${enc_key_id}=   Prepare EncKeyWithID    ${key}  sender=${cm}
    ${popo}=   Prepare EncryptedKey For POPO    ${enc_key_id}   ${None}
    ...         recip_info=${pwri}   cek=${cek[0]}  for_agreement=False
    ${ir}=   Build Ir From Key    ${key}    common_name=${cm}   popo=${popo}
    ...               recipient=${RECIPIENT}   sender=${SENDER}  for_mac=True
    ${protected_ir}=   Default Protect PKIMessage  ${ir}   protection=mac
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Issue A Cert if the KeyEnc Encrypted Key was present
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3. the Client can use the encryptedKey to
    ...    prove possession of the private key. We send PKIMessage with a `KTRI` keyEncipherment
    ...    encryptedKey as POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    encryptedKey   popo  issuing  advanced  ktri  keyEnc  envData
    ${ca_cert}=   May Load Cert   ${CA_RSA_ENCR_CERT}
    ${result}=   Is Certificate Set  ${ca_cert}
    SKIP IF    not ${result}    This test is skipped because the CA encrypted key certificate is not set.#
    ${key}=   Generate Default KeyEncipherment Key
    ${ir}=   Build Encrypted Key Request   ${key}   ${ca_cert}   ${ISSUED_CERT}
    ...     for_agreement=False
    ${protected_ir}=   Default Protect PKIMessage  ${ir}   protection=signature
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA Must Accept ChallengeResp POPO For KeyEnc
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a KeyEncipherment key
    ...     and SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  robot:skip-on-failure  advanced  keyEnc
    ...       challenge-response  envData
    ${new_key}=   Generate Default KeyEncipherment Key
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   True
    ${ir}=   Build Ir From Key    ${new_key}    popo=${popo}   pvno=3  common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${new_key}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}   protection=signature
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${new_key}

############################
### Encrypted Key POPO
############################

CA MUST Accept Encrypted Key For ML-KEM Private Key As POPO
    [Documentation]   We send an Initialization Request (IR) containing an encrypted ML-KEM private key as
    ...               Proof-of-Possession (POPO). The encrypted key is prepared using the CA's KEM certificate, the
    ...               specified key derivation function (KDF). The CA MUST process the request, accept it, and issue a
    ...               valid certificate for the ML-KEM private key.
    [Tags]   ir  positive  popo  pq  kem
    ${ca_cert}=   May Load Cert   ${CA_RSA_ENCR_CERT}
    ${result}=   Is Certificate Set  ${ca_cert}
    SKIP IF    not ${result}    This test is skipped because the CA RSA encryption certificate is not set.
    ${key}=   Generate Key    ${DEFAULT_ML_KEM_ALG}
    ${ir}=  Build Encrypted Key Request   ${key}   ${ca_cert}   ${ISSUED_CERT}  for_agreement=False
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   status=accepted

##############################
# Controls
##############################

CA MUST Accept One Time regToken
    [Documentation]    According to RFC 4211 section-6.1 the Client can send a one time regToken to the CA.
    ...    The CA MUST accept the request and issue a certificate.
    [Tags]    positive   regToken  issuing  advanced  robot:skip-on-failure  controls
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${reg_token_attr}=   Prepare RegToken Controls   ${regToken}
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${reg_token_attr}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${_}=   Get Cert From PKIMessage    ${response}

CA MUST Reject duplicate regToken
    [Documentation]    According to RFC 4211 section-6.1 the Client can send a one time regToken to the CA.
    ...    The CA MUST reject the request and issue a certificate.
    [Tags]    negative  issuing  advanced  robot:skip-on-failure  controls
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${reg_token_attr}=   Prepare RegToken Controls   ${regToken}
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${reg_token_attr}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection

CA Should Accept Authenticator controls Request
    [Documentation]    According to RFC 4211 section-6.2 the Client can send a Authenticator Control `controls`
    ...                to the CA. The Client can send a long term information to the CA, to authenticate itself/himself.
    ...                The CA MUST accept the request and issue a certificate.
    [Tags]    positive   controls  issuing  advanced  robot:skip-on-failure
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${auth}=   Prepare Authenticator Control   MaidenName
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${auth}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA MUST Reject Invalid Authenticator controls Request
    [Documentation]    According to RFC 4211 section-6.2 the Client can send a Authenticator Control `controls`
    ...                to the CA. The Client can send a long term information to the CA, to authenticate itself/himself.
    ...                The CA MUST reject the request and issue a certificate.
    [Tags]    negative   controls  issuing  advanced  robot:skip-on-failure
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${auth}=   Prepare Authenticator Control   MaidenName1
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${auth}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection

CA Could Accept PKIPublicationInformation Control
    [Documentation]    According to RFC 4211 section-6.3 the Client can send a Publication Information Control
    ...                to the CA to tell the CA to not publish or to publish the certificate. We send a
    ...                PKIMessage with a PKIPublicationInformation Control. The CA MUST accept the request
    ...                and issue a certificate.
    [Tags]    positive   publication  issuing  advanced  robot:skip-on-failure  controls
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${pub_info}=   Prepare PKIPublicationInformation Control   pleasePublish   pub_method=x500   pub_location=http://example.com
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${pub_info}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}
    Skip    NotImplemented to validate if the certificate was correctly published

CA MUST Reject Invalid PKIPublicationInformation pleasePublish And dontCare Method
    [Documentation]    According to RFC 4211 section-6.3 the Client can send a Publication Information Control
    ...                to the CA to tell the CA to not publish or to publish the certificate. We send a
    ...                PKIMessage with an invalid PKIPublicationInformation Action and Method. The CA MUST reject
    ...                the request and may respond with the failinfo `badDataFormat` or `badRequest`.
    [Tags]    negative   publication  issuing  advanced  robot:skip-on-failure  controls
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${pub_info}=   Prepare PKIPublicationInformation Control   pleasePublish   pub_method=dontCare
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${pub_info}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badDataFormat,badRequest

CA MUST Reject Invalid PKIPublicationInformation dontPublish And Method
    [Documentation]    According to RFC 4211 section-6.3 the Client can send a Publication Information Control
    ...                to the CA to tell the CA to not publish or to publish the certificate. We send a
    ...                PKIMessage with an dontPublish action and a publication method. The CA MUST reject the request
    ...                and may respond with the failinfo `badDataFormat` or `badRequest`.
    [Tags]    negative   publication  issuing  advanced  robot:skip-on-failure  controls
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${pub_info}=   Prepare PKIPublicationInformation Control   dontPublish   pub_method=x500
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${pub_info}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badDataFormat,badRequest

CA MUST Reject Invalid PKIPublicationInformation Action
    [Documentation]    According to RFC 4211 section-6.3 the Client can send a Publication Information Control
    ...                to the CA to tell the CA to not publish or to publish the certificate. We send a
    ...                PKIMessage with an invalid PKIPublicationInformation Action. The CA MUST reject the request
    ...                and may respond with the failinfo `badDataFormat` or `badRequest`.
    [Tags]    negative   publication  issuing-advanced  robot:skip-on-failure  controls
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${pub_info}=   Prepare PKIPublicationInformation Control   badAction
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${pub_info}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badDataFormat,badRequest

CA MUST Reject Invalid PKIPublicationInformation method
    [Documentation]    According to RFC 4211 section-6.3 the Client can send a Publication Information Control
    ...                to the CA to not publish or to publish the certificate. We send a
    ...                PKIMessage with an invalid PKIPublicationInformation Method. The CA MUST reject the request
    ...                and may respond with the failinfo `badDataFormat` or `badRequest`.
    [Tags]    negative   publication  issuing  advanced  robot:skip-on-failure  controls
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${pub_info}=   Prepare PKIPublicationInformation Control   pleasePublish   pub_method=badMethod
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${pub_info}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badDataFormat,badRequest

CA Could Accept Valid Archive Options Control
    [Documentation]    According to RFC 4211 section-6.4 the Client can send a Archive Options Control
    ...                to send the private key to the CA so that it can be archived. We send a
    ...                PKIMessage with a Archive Options Control. The CA MUST accept the request
    ...                and issue a certificate.
    [Tags]    positive   archive  issuing  advanced  robot:skip-on-failure  controls  mac
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${archive}=   Prepare PKIArchiveOptions Controls   password=${PRE_SHARED_SECRET}    private_key=${key}
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}  controls=${archive}
    ${ir}=   Build Ir From Key    ${key}   cert_request=${cert_request}   sender=${SENDER}
    ...               recipient=${RECIPIENT}   for_mac=${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}
    ${protected_ir}=  Default Protect PKIMessage  ${ir}  protection=mac
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${_}=   Get Cert From PKIMessage    ${response}

##############################
# reqInfo
##############################

CA May Process The UTF8Pairs String
    [Documentation]    According to RFC 4211 section-7.1 can the Client use this control to convey text-based
    ...                information to the RA or CA issuing a certificate. We send some UTF8Pairs string inside the
    ...                `CertRequest`. The CA MUST accept the request and issue a certificate and may use the
    ...                 information to issue a certificate.
    [Tags]    positive   reqInfo  issuing  advanced  robot:skip-on-failure
    Skip    The reqInfo requires the User to be set.
    ${key}=   Generate Default Key
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    # TODO maybe the user needs to decide, if the value is set to be to something else,
    # because the policy will probably be different.
    ${cert_request2}=   Prepare CertRequest   ${key}  ${cm}  extensions=${extensions}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${alt_cert_req}=  Prepare Utf8Pairs reqInfo    ${cert_request2}   utf8Pairs=CN=Test   # robocop: off=NAME02
    ${ir}=   Add regInfo To PKIMessage   ${ir}    ${alt_cert_req}   # robocop: off=NAME02
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${_}=   Get Cert From PKIMessage    ${response}

CA MUST Used the CertRequest Inside the reqInfo
    [Documentation]    According to RFC 4211 section-7.2 the RA can modify the CertTemplate, but if the RA want to
    ...                let the POPO be valid, it can use the reqInfo field to set the CertTemplate which should be
    ...                issued. We send a PKIMessage with a CertRequest inside the reqInfo. The CA MUST accept the
    ...                request and use the `reqInfo` CertRequest to issue the certificate.
    [Tags]    positive   reqInfo  issuing  advanced  robot:skip-on-failure
    ${key}=   Generate Key    ecc   curve=${DEFAULT_ECC_CURVE}
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    # TODO maybe the user needs to decide, if the value is set to be to something else,
    # because the policy will probably be different.
    ${extensions}=  Prepare Extensions   key_usage=keyAgreement,digitalSignature
    ${cert_request2}=   Prepare CertRequest   ${key}  ${cm}  extensions=${extensions}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${alt_cert_req}=  Prepare CertReq ReqInfo    ${cert_request2}
    ${ir}=   Add regInfo To PKIMessage   ${ir}    ${alt_cert_req}    # robocop: off=NAME02
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    # MUST be present and contains the expected key usages.
    Validate KeyUsage  ${cert}   keyAgreement,digitalSignature   STRICT

CA MUST Reject different Public Key in Alt CertReq
    [Documentation]    According to RFC 4211 section-7.2 the RA can modify the CertTemplate, but if the RA want to
    ...                let the POPO be valid, it can use the reqInfo field to set the CertTemplate which should be
    ...                issued. We send a PKIMessage with a CertRequest with a different public key inside the
    ...                `CertTemplate`. The CA MUST reject the request and may respond with the failinfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]    negative   reqInfo  issuing  advanced  robot:skip-on-failure
    ${key}=   Generate Default Key
    ${diff_key}=   Generate Different Public Key   ${key}
    ${cm}=   Get Next Common Name
    ${cert_request}=   Prepare CertRequest   ${key}  ${cm}
    # TODO maybe the user needs to decide, if the value is set to be to something else,
    # because the policy will probably be different.
    ${cert_request2}=   Prepare CertRequest   ${diff_key}  ${cm}
    ${ir}=   Build Ir From Key    ${key}    cert_request=${cert_request}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${alt_cert_req}=  Prepare CertReq ReqInfo    ${cert_request2}
    ${ir}=   Add regInfo To PKIMessage   ${ir}    ${alt_cert_req}  # robocop: off=NAME02
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest
