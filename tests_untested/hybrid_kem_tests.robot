# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Test cases for Hybrid KEM methods.

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
Library             ../pq_logic/py_verify_logic.py
Library             ../pq_logic/pq_validation_utils.py

Test Tags    hybrid-kem

*** Test Cases ***

################################
# Composite KEM
################################


################################
# XWing
################################

CA MUST Accept A Valid IR FOR XWING
    [Documentation]    According to draft XWing: general-purpose hybrid post-quantum KEM, we send a valid
    ...
    [Tags]             positive    xwing   kem
    ${key}=   Generate Key    algorithm=xwing
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}
    ...       popo_structure=${popo}   
    ...       pvno=3
    ...       recipient=${RECIPIENT}   
    ...       exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get EncCert From PKIMessage    ${response}     private_key=${ISSUED_KEY}



################################
# Chempat
################################


#### Composite KEM KEYS ####

CA MUST Accept A Valid IR FOR Composite KEM
    [Documentation]
    [Tags]             positive    composite-kem   hybrid-kem   kem
    ${key}=   Generate Key    algorithm=composite-kem
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Enc Cert From PKIMessage    ${response}     private_key=${ISSUED_KEY}

#### XWING KEY ####


#### Chempat KEYS ####

CA MUST Accept A Valid IR FOR Chempat Sntrup761
    [Documentation]
    [Tags]             positive    chempat   hybrid-kem   kem   sntrup761
    ${key}=   Generate Key    algorithm=chempat    pq_name=sntrup761
    ${cm}=    Get Next Common Name
    ${popo}=   Prepare Agree Key Popo   use_encr_cert=True
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
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
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
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
    ${ir}=    Build Ir From Key    ${key}   ${cm}   popo=${popo}   pvno=3   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   status=accepted
    ${cert}=   Get Enc Cert From PKIMessage    ${response}     private_key=${ISSUED_KEY}

