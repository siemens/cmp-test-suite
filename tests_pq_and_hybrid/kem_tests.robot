# SPDX-FileCopyrightText: Copyright 2024 Siemens AG # robocop: off=COM04
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
Library             ../pq_logic/pq_verify_logic.py

Test Tags           kem   pqc

Suite Setup          Set Up Test Suite


*** Keywords ***
Request With PQ KEM Key
    [Documentation]  Send a valid Initialization Request for a PQ KEM key.
    [Arguments]    ${alg_name}     ${invalid_key_size}
    ${response}    ${key}=   Build And Exchange KEM Certificate Request    ${alg_name}    ${invalid_key_size}
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Certificate Must Be Valid    ${cert}

Build And Exchange KEM Certificate Request
    [Documentation]    Build a KEM certificate request and exchange it with the CA to get a certificate.
    ...
    ...                Only builds the Initialization Request for the encrypted cert mechanism request.
    ...
    ...                Arguments:
    ...                - ${key_alg}: The key algorithm to use for the key generation (e.g. `ml-kem-768`).
    ...                - ${invalid_key_size}: Whether to use an invalid key size. Defaults to `False`.
    ...
    ...                Returns:
    ...                - The response from the CA.
    ...                - The key used for the certificate generation.
    ...
    ...                Examples:
    ...                | ${response}= | Build and Exchange KEM Certificate Request | ml-kem-768 |
    ...                | ${response}= | Build and Exchange KEM Certificate Request | ml-kem-768 | False |
    [Arguments]    ${key_alg}    ${invalid_key_size}=False   ${extensions}=${None}
    ${key}=    Generate Key    ${key_alg}
    ${cm}=    Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}      invalid_key_size=${invalid_key_size}
    ${cert_req_msg}=    Prepare CertReqMsg  ${key}  spki=${spki}   common_name=${cm}   extensions=${extensions}
    ${ir}=    Build Ir From Key    ${key}   cert_req_msg=${cert_req_msg}   exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${PQ_ISSUING_SUFFIX}
    RETURN    ${response}   ${key}


*** Test Cases ***
CA MUST Accept A Valid IR FOR ML-KEM-768
    [Documentation]   According to draft-ietf-lamps-kyber-certificates-07 is ML-KEM-768 used. We send an valid
    ...               IR. The CA MUST process the request and issue a valid certificate. Which is encrypted with our
    ...               public key and the KEMRecipientInfo.
    [Tags]         positive    ml-kem
    ${response}  ${key}=    Build And Exchange KEM Certificate Request    ml-kem-768
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Certificate Must Be Valid    ${cert}
    VAR   ${KEM_CERT}   ${cert}  scope=GLOBAL
    VAR   ${KEM_KEY}   ${key}         scope=GLOBAL
    ${certs}=   Build CMP Chain From PKIMessage    ${response}   ${cert}
    Write Certs To Dir     ${certs}

CA MUST Reject ML-KEM with Invalid KeyUsage
    [Documentation]   According to draft-ietf-lamps-kyber-certificates-07 is ML-KEM-768 used. We send an IR with a
    ...               invalid key usage (only keyEncipherment is allowed). The CA MUST detect the invalid key usage
    ...               and respond with a `rejection´ and MAY return the optional failInfo `badCertTemplate`.
    [Tags]         negative    ml-kem   robot:skip-on-failure   key_usage
    ${extensions}=    Prepare Extensions     key_usage=digitalSignature
    ${response}  ${_}=    Build And Exchange KEM Certificate Request    ml-kem-768
    ...    extensions=${extensions}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA Should Issue a ML-KEM with keyEncipherment KeyUsage
    [Documentation]   According to draft-ietf-lamps-kyber-certificates-07 is ML-KEM-768 used. We send an IR with a
    ...               the KeyUsage `keyEncipherment`. The CA MUST process the request and issue a valid certificate.
    [Tags]         positive    ml-kem  key_usage
    ${extensions}=    Prepare Extensions     key_usage=keyEncipherment
    ${response}  ${key}=    Build And Exchange KEM Certificate Request    ml-kem-768
    ...    extensions=${extensions}
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Certificate Must Be Valid    ${cert}
    Validate KeyUsage    ${cert}    keyEncipherment  STRICT

##### KEM BASED MAC #####

CA MUST support KEMBasedMAC
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation,
    ...                the CA MUST perform the encapsulation of the shared secret and
    ...                return the ciphertext to the client. We send then a valid KEMBasedMAC protected
    ...                message. The CA MUST process the request and respond with an `accepted` status.
    [Tags]    kem-based-mac   genm
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${genm}=   Build KEMBasedMAC General Message   ${KEM_KEY}    ${KEM_CERT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp KEMCiphertextInfo    ${genp}    ${KEM_KEY}
    ${tx_id}=   Get Asn1 Value As Bytes   ${genm}  header.transactionID
    ${protected_ir}=   Build IR Request KEMBasedMac Protected
    ...       ${tx_id}   ${ss}   True
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   accepted

CA MUST Support KEMBasedMAC Until Certificate Is Confirmed
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation,
    ...                the CA MUST perform the encapsulation of the shared secret and
    ...                return the ciphertext to the client. We send then a valid KEMBasedMAC protected
    ...                message and then a certificate confirmation message. The CA MUST process the request and
    ...                respond with an `accepted` status.
    [Tags]    kem-based-mac   genm  certConf
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${PQ_ISSUING_SUFFIX}
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${genm}=   Build KEMBasedMAC General Message   ${KEM_KEY}    ${KEM_CERT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp KEMCiphertextInfo    ${genp}    ${KEM_KEY}
    ${tx_id}=   Get Asn1 Value As Bytes   ${genm}  header.transactionID
    ${protected_ir}=   Build IR Request KEMBasedMac Protected
    ...       ${tx_id}   ${ss}   True
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   accepted
    ${cert_conf}=  Build Cert Conf From Resp    ${response}   sender=${SENDER}
    ...            recipient=${RECIPIENT}    for_mac=True
    ${cert_conf}=  Protect PKIMessage KEMBasedMAC    ${cert_conf}    shared_secret=${ss}
    ${response}=   Exchange PKIMessage    ${cert_conf}
    PKIMessage Body Type Must Be    ${response}    pkiconf
    
CA Should Respond with the a valid KEMBasedMAC Protected Message
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation,
    ...                the CA MUST perform the encapsulation of the shared secret and
    ...                return the ciphertext to the client. We send then a valid KEMBasedMAC protected
    ...                message. The CA MUST process the request and respond with an `accepted` status
    ...                and the KEMBasedMAC protected message.
    [Tags]    kem-based-mac   genm
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${genm}=   Build KEMBasedMAC General Message   ${KEM_KEY}    ${KEM_CERT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp KEMCiphertextInfo    ${genp}    ${KEM_KEY}
    ${tx_id}=   Get Asn1 Value As Bytes   ${genm}  header.transactionID
    ${protected_ir}=   Build IR Request KEMBasedMac Protected
    ...       ${tx_id}   ${ss}   True
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   accepted
    ${prot_type}=   Get Protection Type From PKIMessage    ${response}
    IF   not '${prot_type}' == 'kem_based_mac'
        Fail    The protection type is not KEMBasedMac. Got: ${prot_type}
    END
    Verify PKIMessage Protection    ${response}    shared_secret=${ss}

CA MUST Protect pkiconf message with KEMBasedMAC
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation,
    ...                the CA MUST perform the encapsulation of the shared secret and
    ...                return the ciphertext to the client. We send then a valid KEMBasedMAC protected
    ...                message and then a certificate confirmation message. The CA MUST protect the
    ...                pkiconf message with the KEMBasedMAC.
    [Tags]    kem-based-mac   genm  certConf
    ${url}=  Add URL Suffix    ${CA_BASE_URL}   ${PQ_ISSUING_SUFFIX}
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${genm}=   Build KEMBasedMAC General Message   ${KEM_KEY}    ${KEM_CERT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp KEMCiphertextInfo    ${genp}    ${KEM_KEY}
    ${tx_id}=   Get Asn1 Value As Bytes   ${genm}  header.transactionID
    ${protected_ir}=   Build IR Request KEMBasedMac Protected
    ...       ${tx_id}   ${ss}   True
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   accepted
    ${cert_conf}=  Build Cert Conf From Resp    ${response}   sender=${SENDER}
    ...            recipient=${RECIPIENT}    for_mac=True
    ${cert_conf}=  Protect PKIMessage KEMBasedMAC    ${cert_conf}    shared_secret=${ss}
    ${response}=   Exchange PKIMessage    ${cert_conf}
    PKIMessage Body Type Must Be    ${response}    pkiconf
    ${prot_type}=   Get Protection Type From PKIMessage    ${response}
    IF   not '${prot_type}' == 'kem_based_mac'
        Fail    The protection type is not KEMBasedMac. Got: ${prot_type}
    END
    Verify PKIMessage Protection    ${response}    shared_secret=${ss}

CA Reject invalid KEMBasedMAC Protected Message
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation
    ...                The CA MUST perform the encapsulation of the shared secret and
    ...                return the ciphertext to the client. We send then a invalid KEMBasedMAC protected
    ...                message. The CA MUST detected the invalid protection and MAY return the
    ...                optional failInfo `badMessageCheck`.
    [Tags]    kem-based-mac   genm
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${genm}=   Build KEMBasedMAC General Message   ${KEM_KEY}    ${KEM_CERT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp KEMCiphertextInfo    ${genp}    ${KEM_KEY}
    ${tx_id}=   Get Asn1 Value As Bytes   ${genm}  header.transactionID
    ${protected_ir}=   Build IR Request KEMBasedMac Protected
    ...       ${tx_id}   ${ss}   True  ${None}   True
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}   badMessageCheck

CA MUST not reuse the same ss for KEMBASEDMAC
    [Documentation]    According to rfc4210bis16 Section 5.1.3.4. Key Encapsulation,
    ...                the establishment of a shared secret MUST only be used once.
    ...                We send a valid KEMBasedMAC protected message with the same shared secret.
    ...                The CA MUST detect the reuse of the shared secret and MAY return the
    ...                optional failInfo `badMessageCheck,badRequest,systemFailure`.
    [Tags]    kem-based-mac   genm
    ${result}=   Is Certificate And Key Set    ${KEM_CERT}   ${KEM_KEY}
    SKIP IF  not ${result}    KEM Certificate and Key not set
    ${url}=   Get PQ Issuing URL
    ${cm}=    Get Next Common Name
    ${genm}=   Build KEMBasedMAC General Message   ${KEM_KEY}    ${KEM_CERT}
    ${genp}=   Exchange PKIMessage    ${genm}
    ${ss}=   Validate Genp KEMCiphertextInfo    ${genp}    ${KEM_KEY}
    ${key}=  Generate Default Key
    ${tx_id}=   Get Asn1 Value As Bytes   ${genm}  header.transactionID
    ${protected_ir}=   Build IR Request KEMBasedMac Protected
    ...       ${tx_id}   ${ss}   True  ${None}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   accepted
    ${protected_ir}=   Build IR Request KEMBasedMac Protected
    ...       ${tx_id}   ${ss}   True  ${None}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}   badMessageCheck,badRequest,systemFailure

#####################
# Other PQ KEMs
#####################

CA MUST ISSUE A Valid FrodoKEM Certificate
    [Documentation]    According to the FrodoKEM specification, is a valid IR CMP message send.
    ...                The CA MUST accept the request and response with a encrypted certificate.
    [Tags]    frodoKEM
    ${response}  ${key}=    Build And Exchange KEM Certificate Request    frodokem-640-aes
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert}=  Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    frodokem-640-aes

CA MUST ISSUE A Valid McEliece Certificate
    [Documentation]    According to the McEliece specification, is a valid IR CMP message send.
    ...                The CA MUST accept the request and response with a encrypted certificate.
    [Tags]    mceliece
    ${response}  ${key}=    Build And Exchange KEM Certificate Request    mceliece-348864
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert}=  Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    mceliece-348864

CA MUST ISSUE A Valid sntrup761 Certificate
    [Documentation]    According to the NTRU specification, is a valid IR CMP message send.
    ...                The CA MUST accept the request and response with a encrypted certificate.
    [Tags]    sntrup761
    ${response}  ${key}=    Build And Exchange KEM Certificate Request    sntrup761
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert}=  Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    sntrup761


*** Keywords ***
Build IR Request KEMBasedMac Protected
    [Documentation]    Build a IR request with KEMBasedMac protected.
    ...
    ...                Arguments:
    ...                - ${tx_id}: The transaction ID to use for the request.
    ...                - ${ss}: The shared secret to use for the request.
    ...                - ${for_mac}: Whether to use the request for MAC or SIG.
    ...                - ${cert_chain}: The certificate chain to use for the request.
    ...                - ${bad_message_check}: Whether to invalidate the protection.
    ...
    ...                Returns:
    ...                - The protected IR request.
    ...
    ...                Examples:
    ...                | ${protected_ir}= | Build IR Request KEMBasedMac Protected | ${tx_id} | ${ss} |
    ...                | ${protected_ir}= | Build IR Request KEMBasedMac Protected | ${tx_id} | ${ss} | for_mac=True |
    ...
    [Arguments]    ${tx_id}    ${ss}    ${for_mac}=False  ${cert_chain}=${None}   ${bad_message_check}=False
    ${cm}=    Get Next Common Name
    ${key}=  Generate Default Key
    IF   ${for_mac}
        VAR   ${exclude_fields}  ${None}
    ELSE
        VAR   ${exclude_fields}  senderKID,sender
    END
    # TODO decide if both options are allowed, or the `GeneralName` must be for MAC or SIG.
    ${ir}=    Build Ir From Key  ${key}   ${cm}   for_mac=${for_mac}
    ...       sender=${SENDER}   recipient=${RECIPIENT}   transaction_id=${tx_id}
    ...       exclude_fields=${exclude_fields}
    IF   ${cert_chain} is not None
        ${ir}=   Patch ExtraCerts    ${ir}    ${cert_chain}
        ${ir}=    Patch Sender    ${ir}    ${cert_chain}[0]
        ${ir}=    Patch SenderKID    ${ir}    ${cert_chain}[0]
    END
    ${protected_ir}=  Protect PKIMessage KemBasedMac    ${ir}    shared_secret=${ss}
    ...    bad_message_check=${bad_message_check}
    RETURN    ${protected_ir}