# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Tests which are deprecated and should be removed in the future.

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

Test Tags    robot:skip-on-failure   deprecated

*** Test Cases ***

CA Must Accept ChallengeResp POPO For Request With X25519 Key
   [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a X25519
    ...     SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  advanced  x25519   challenge-response  encrValue
    Should Contain    ${ALLOWED_ALGORITHM}    x25519
    ${key}=   Generate Key     x25519
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   False
    ${ir}=   Build Ir From Key    ${key}    popo=${popo}   pvno=2   common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${key}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA Must Accept ChallengeResp POPO For Request With X448 Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a X448
    ...     SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  advanced  x448  challenge-response  encrValue
    Should Contain    ${ALLOWED_ALGORITHM}    x448
    ${key}=   Generate Key     x448
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   False
    ${ir}=   Build Ir From Key    ${key}    popo=${popo}   pvno=2  common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${key}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}

CA Must Accept ChallengeResp POPO For Request With ECC Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a ECC
    ...     SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  advanced  ecc  challenge-response  encrValue
    Should Contain    ${ALLOWED_ALGORITHM}    ecc
    ${key}=   Generate Key     ecc
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   False
    ${ir}=   Build Ir From Key    ${key}    popo=${popo}   pvno=2  common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${key}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key    ${cert}  ${key}

CA Must Accept ChallengeResp POPO For Request With RSA Key
    [Documentation]    According to RFC 4210bis-18 Section 5.2.8.3.3. the Client can use the `challengeResp`
    ...     POPO to prove possession of the private key. We send a PKIMessage with a RSA keyEncipherment key
    ...     and SubsequentMessage POPO. The CA MUST accept the request and issue a certificate.
    [Tags]    positive    challenge   popo  issuing  advanced  rsa  challenge-response  encrValue
    Should Contain    ${ALLOWED_ALGORITHM}    rsa
    ${key}=   Generate Key     rsa
    ${cm}=   Get Next Common Name
    ${popo}=   Prepare POPO Challenge For Non Signing Key    False   True
    ${ir}=   Build Ir From Key    ${key}    popo=${popo}   pvno=2  common_name=${cm}
    ...               recipient=${RECIPIENT}   exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    popdecc
    ${popdecr}=   Process PKIMessage With Popdecc   ${response}   ee_key=${key}
    ${prot_popdecr}=   Default Protect PKIMessage    ${popdecr}
    ${response}=   Exchange PKIMessage    ${prot_popdecr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Certificate Public Key   ${cert}  ${key}




    
    
