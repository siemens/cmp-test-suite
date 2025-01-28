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
Library             ../resources/certutils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/general_msg_utils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../pq_logic/py_verify_logic.py
Library             ../pq_logic/pq_validation_utils.py

Test Tags           kem   pqc

Suite Setup         Initialize Global Variables

*** Variables ***

${DEFAULT_ML_KEM_KEY}   ml-kem-768
${KEM_CERT_PATH}   ${None}
*** Keywords ***

Initialize Global Variables
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${OTHER_TRUSTED_PKI_CERT}  ${cert}   scope=Global
    VAR   ${OTHER_TRUSTED_PKI_KEY}   ${key}    scope=Global
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${ISSUED_CERT}  ${cert}   scope=Global
    VAR   ${ISSUED_KEY}   ${key}    scope=Global


*** Test Cases ***


CA MUST Accept A Valid IR FOR ML-KEM
    [Documentation]   According to fips203 is ML-KEM ObjectIdentifier and the algorithm used. We send a valid
    ...               IR Initialization Request with a valid ML-KEM private key. The CA MUST process the request
    ...               and issue a valid certificate. Which is deprypted with our public key and the KEMRecipientInfo.
    [Tags]         positive    ml-kem
    ${key}=  Generate Key    ml-kem-768
    ${cm}=   Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}
    ...    common_name=${cm}
    ...    recipient=${RECIPIENT}
    ...    omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be       ${response}    status=accepted
    PKIMessage Body Type Must Be   ${response}    ip
    ${cert}=   Get EncCert From PKIMessage    ${response}   private_key=${key}
    Validate Migration Certificate Key Usage   ${cert}




CA MUST respond with KEMRecipInfo
    [Documentation]   We send a nested PKIMessage containing a Initialization Request indicating to generate a ML-KEM private key.
    ...               The CA MUST process the request, issue a valid certificate, and include the KEM recipient information in the response,
    ...               to compute the shared secret, to decrypt the newly generated private key.
    [Tags]            ir    positive    kga
    ${key}=   Generate Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   for_kga=True   sender=${SENDER}    recipient=${RECIPIENT}
    ${transaction_id}=    Get Asn1 Value As Bytes    ${ir}    header.transactionID
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${ir}    header.senderNonce
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${ir}
    ...    sender_nonce=${sender_nonce}
    ...    transaction_id=${transaction_id}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    Verify PKIStatusInfo    ${response}   status=accepted


CA MUST Accept Challenge For ML-KEM
    [Documentation]   When the client sends a certificate request without a key used for signing, can the client
    ...               indicate to encrypt the newly issued certificate so that the client can prove the possession of
    ...               the corresponding private key. We send a valid Initialization Request. The CA MUST process the
    ...               request and issue a new certificate which is encrypted, with the KEM recipient information.
    [Tags]   ir  positive  challenge
    ${key}=   Generate Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name
    ${popo}=  Prepare Popo Challenge For Non Signing Key    use_encr_cert=False    use_key_enc=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo_structure=${popo}   pvno=3   sender=${SENDER}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${der_data}=    Encode To Der    ${protected_ir}
    Log Base64    ${der_data}
    ${response}=    Exchange Data With CA    ${der_data}
    Log Base64    ${response.content}
    ${request}=  Process PKIMessage With Popdecc    ${response.content}    ee_key=${key}  request=${protected_ir}
    ${response}=   Exchange PKIMessage    ${request}
    PKIMessage Body Type Must Be   ${response}    ip
    PKIStatus Must Be    ${response}   status=accepted
    
CA MUST Accept A Valid KGA Request For ML-KEM
    [Documentation]   We send an Initialization Request indicating the CA to issue a certificate for a ML-KEM Private
    ...               Key, to be generated by the Key Generation Authority (KGA). The CA MUST process the request and
    ...               issue a valid certificate and send a encrypted private key inside the `SignedData` structure.
    [Tags]            positive   kga  ml-kem
    ${key}=   Generate Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   for_kga=True   sender=${SENDER}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}

CA MUST Accept Encrypted Key For ML-KEM Private Key As POPO
    [Documentation]   We send an Initialization Request (IR) containing an encrypted ML-KEM private key as
    ...               Proof-of-Possession (POPO). The encrypted key is prepared using the CA's KEM certificate, the
    ...               specified key derivation function (KDF). The CA MUST process the request, accept it, and issue a
    ...               valid certificate for the ML-KEM private key.
    [Tags]   ir  positive  popo
    Skip If    not ${KEM_CERT_PATH}   Skipped, because KEM_CERT was not set to calculate the KEM recipient info structure.
    ${der_data}=   Load And Decode PEM File    ${KEM_CERT_PATH}
    ${server_cert}=    Parse Certificate    ${der_data}
    ${key}=   Generate Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare KEM Env Data For POPO   ca_cert=${server_cert}   client_key=${key}
    ${ir}=    Build Ir From Key    ${key}   ${cm}
    ...     popo_structure=${popo}
    ...     sender=${SENDER}
    ...     omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   status=accepted


CA MUST Accept PKMACValue For ML-KEM
    [Documentation]   We send an Initialization Request (IR) containing a PKMACValue for a ML-KEM private key.
    ...               The CA MUST process the request and respond with an `accepted` status.
    [Tags]            ir    positive    kga
    Skip If    not ${KEM_CERT_PATH}   Skipped, because KEM_CERT was not set to calculate the KEM recipient info structure.
    ${der_data}=   Load And Decode PEM File    ${KEM_CERT_PATH}
    ${server_cert}=    Parse Certificate    ${der_data}
    ${key}=   Generate Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name
    ${cert_request}=    Prepare CertRequest    ${key}   common_name=${cm}
    ${popo}=  Prepare PKMAC POPO    ca_cert=${server_cert}   cert_request=${cert_request}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   sender=${SENDER}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}   ip
    PKIStatus Must Be    ${response}   accepted
    



##### KEM BASED MAC #####


CA MUST support KEMBasedMAC
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation
    ...                The CA MUST perform the encapsulation of the shared secret and
    ...                return the ciphertext to the client. We send then a valid KEMBasedMAC protected
    ...                message. The CA MUST process the request and respond with an `accepted` status.
    [Tags]    kem-based-mac   genm
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${info_val}=    Prepare KEM CiphertextInfo   ${KEM_KEY}
    ${genm}=   Build General Message   ${info_val}   sender=${SENDER}   recipient=${RECIPIENT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp Kem Ct Info    ${genp}    ${KEM_KEY}
    ${key}=  Generate Default Key
    ${ir}=    Build ir from key  ${key}   ${cm}    sender=${SENDER}   recipient=${RECIPIENT}
    ${protected_ir}=  Protect Pkimessage Kem Based Mac    ${ir}    shared_secret=${ss}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   accepted

CA Reject invalid KEMBasedMAC Protected Message
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation
    ...                The CA MUST perform the encapsulation of the shared secret and
    ...                return the ciphertext to the client. We send then a invalid KEMBasedMAC protected
    ...                message. The CA MUST detected the invalid protection and MAY return the
    ...                optional failInfo `badMessageCheck`.
    [Tags]    kem-based-mac   genm
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${info_val}=    Prepare KEM CiphertextInfo   ${KEM_KEY}
    ${genm}=   Build General Message   ${info_val}   sender=${SENDER}   recipient=${RECIPIENT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp Kem Ct Info    ${genp}    ${KEM_KEY}
    ${key}=  Generate Default Key
    ${ir}=    Build ir from key  ${key}   ${cm}    sender=${SENDER}   recipient=${RECIPIENT}
    ${protected_ir}=  Protect Pkimessage Kem Based Mac    ${ir}    shared_secret=${ss}    bad_message_check=True
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}   badMessageCheck
    

CA MUST not reuse the same ss for KEMBASEDMAC
    Skip    Not implemented yet




