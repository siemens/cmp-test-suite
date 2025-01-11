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
Library             ../resources/pq_key_factory.py
Library             ../resources/extra_issuing.py
Library             ../resources/kemutils.py
Library             ../resources/nestedutils.py

#Suite Setup         Do KEM Tests
Test Tags           kem

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

CA MUST Reject A CSR For ML-KEM with Signature
    [Documentation]   We send a P10cr Certification Request with a CSR containing a ML-KEM public key, but signed by a
    ...               ML-DSA private key. The CA MUST reject the request and respond with the failInfo `badPOP`.
    [Tags]            p10cr    popo    negative
    ${key}=   Generate Key    ${DEFAULT_ML_DSA_KEY}
    ${key2}=  Generate Key    ml-dsa-87
    ${cm}=   Get Next Common Name
    ${csr}=    Build CSR    signing_key=${key}    common_name=${cm}   exclude_signature=True    hash_alg=${None}
    ${signed_csr}=   Sign CSR    ${csr}   signing_key=${key2}
    ${p10cr}=    Build P10cr From CSR
    ...    ${signed_csr}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_p10cr}=    Protect PKIMessage
    ...    pki_message=${p10cr}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_p10cr}
    Verify PKIStatusInfo    ${response}   failinfos=badPOP

CA MUST Accept A Valid KGA Request For ML-KEM
    [Documentation]   We send an Initialization Request indicating the CA to issue a certificate for a ML-KEM Private
    ...               Key, to be generated by the Key Generation Authority (KGA). The CA MUST process the request and
    ...               issue a valid certificate and send a encrypted private key inside the `SignedData` structure.
    [Tags]            ir    positive   kga
    ${key}=   Generate PQ Key    ${DEFAULT_ML_KEM_KEY}
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

CA MUST respond with KEM Recip Info
    [Documentation]   We send a nested PKIMessage containing a Initialization Request indicating to generate a ML-KEM private key.
    ...               The CA MUST process the request, issue a valid certificate, and include the KEM recipient information in the response,
    ...               to compute the shared secret, to decrypt the newly generated private key.
    [Tags]            ir    positive    kga
    ${key}=   Generate PQ Key    ${DEFAULT_ML_KEM_KEY}
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

#### POPO

CA MUST Accept Challenge EncCert
    [Documentation]   When the client sends a certificate request without a key used for signing, can the client
    ...               indicate to encrypt the newly issued certificate so that the client can prove the possession of
    ...               the corresponding private key. We send a valid Initialization Request. The CA MUST process the
    ...               request and issue a new certificate which is encrypted, with the KEM recipient information.
    [Tags]   ir  positive  challenge
    ${key}=   Generate PQ Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name
    ${popo}=  Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   sender=${SENDER}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get EncCert From PKIMessage   ${response}
    

CA MUST Accept Encrypted Key For ML-KEM Private Key As POPO
    [Documentation]   We send an Initialization Request (IR) containing an encrypted ML-KEM private key as
    ...               Proof-of-Possession (POPO). The encrypted key is prepared using the CA's KEM certificate, the
    ...               specified key derivation function (KDF). The CA MUST process the request, accept it, and issue a
    ...               valid certificate for the ML-KEM private key.
    [Tags]   ir  positive  popo
    Skip If    not ${KEM_CERT_FILE_PATH}   Skipped, because KEM_CERT was not set to calculate the KEM recipient info structure.
    ${der_data}=   Load And Decode PEM File    ${KEM_CERT_FILE_PATH}
    ${server_cert}=    Parse Certificate    ${der_data}
    ${key}=   Generate PQ Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name
    ${kem_recip_info}=   Build Kem Recip Info    ee_private_key=${key}     ca_cert=${server_cert}   kdf_name=${DEFAULT_KEM_KDF}    hash_alg=${DEFAULT_KDF_HASH_ALG}
    ${cert_chain}=   Build Cert Chain From Dir    ${ISSUED_CERT}    cert_dir=./data/cert_logs
    ${popo}=   Prepare KEM Env Data For POPO   ${ISSUED_CERT}  ${cert_chain}  ${ISSUED_KEY}  private_keys=${key}   kem_recip_info=${kem_recip_info}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   sender=${SENDER}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted

CA MUST Accept PKMACValue For ML-KEM
    [Documentation]   We send an Initialization Request (IR) containing a PKMACValue for a ML-KEM private key.
    ...               The CA MUST process the request and respond with an `accepted` status.
    [Tags]            ir    positive    kga
    Skip If    not ${KEM_CERT_FILE_PATH}   Skipped, because KEM_CERT was not set to calculate the KEM recipient info structure.
    ${der_data}=   Load And Decode PEM File    ${KEM_CERT_FILE_PATH}
    ${server_cert}=    Parse Certificate    ${der_data}
    ${key}=   Generate PQ Key    ${DEFAULT_ML_KEM_KEY}
    ${cm}=    Get Next Common Name

    ${popo}=  Prepare Agree Key Popo   ca_cert=${server_cert}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   sender=${SENDER}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted

#############################
# Hybrid KEM Keys
#############################


#### Composite KEM KEYS ####

CA MUST Accept A Valid IR FOR Composite KEM
    [Documentation]
    [Tags]             positive    composite-kem   hybrid-kem   kem
    ${key}=   Generate Key    algorithm=composite-kem
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Enc Cert From PKIMessage    ${response}     private_key=${ISSUED_KEY}

#### XWING KEY ####

CA MUST Accept A Valid IR FOR XWING
    [Documentation]
    [Tags]             positive    xwing   hybrid-kem   kem
    ${key}=   Generate Key    algorithm=xwing
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Enc Cert From PKIMessage    ${response}     private_key=${ISSUED_KEY}

#### Chempat KEYS ####

CA MUST Accept A Valid IR FOR Chempat Sntrup761
    [Documentation]
    [Tags]             positive    chempat   hybrid-kem   kem   sntrup761
    ${key}=   Generate Key    algorithm=chempat    pq_name=sntrup761
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Enc Cert From PKIMessage    ${response}     private_key=${ISSUED_KEY}

CA MUST Accept A Valid IR FOR Chempat ML-KEM
    [Documentation]
    [Tags]             positive    chempat   hybrid-kem   kem   ml-kem
    ${key}=   Generate Key    algorithm=chempat    pq_name=ml-kem-768
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Enc Cert From PKIMessage    ${response}     private_key=${ISSUED_KEY}

CA MUST Accept A Valid IR FOR Chempat McEliece
    [Documentation]
    [Tags]             positive    chempat   hybrid-kem   kem   mceliece
    ${key}=   Generate Key    algorithm=chempat    pq_name=mceliece8192128   trad_name=x25519
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Enc Cert From PKIMessage    ${response}     private_key=${ISSUED_KEY}



##### KEM BASED MAC #####


CA MUST support KEMBasedMAC
    Skip    Not implemented yet

CA MUST not reuse the same ss for KEMBASEDMAC
    Skip    Not implemented yet




