# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

Resource            ../config/${environment}.robot
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
Library             ../resources/ca_kga_logic.py

Test Tags           kga

*** Test Cases ***
## 4.1.6.1. Using the Key Transport Key Management Technique

# TODO maybe add test cases for all key types, which are allowed.

CA MUST Support Key Transport Management Technique With IR
    [Documentation]    According to RFC 9483 Section 4.1.6.1, Key Transport ensures secure transport of private keys
    ...    using ktri and a client certificate with the `keyEncipherment` KeyUsage extension. The CA MUST
    ...    use the public key from the client certificate to encrypt the CEK, which is used to encrypt the
    ...    `SignedData` structure containing the private key. A valid initialization request is sent
    ...    specifying the use of a certificate that supports key transport. The CA MUST respond with a
    ...    valid `EnvelopedData` structure. The extracted private key MUST match the public key in the
    ...    issued certificate.
    [Tags]    ir    ktri    positive
    ${is_set}=    Is Certificate And Key Set    ${KGA_KTRI_CERT}    ${KGA_KTRI_KEY}
    Skip If    not ${is_set}    Skipped because KGA_KTRI_CERT and KGA_KTRI_KEY are not set.
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${ir}=    Build Ir From Key
    ...    signing_key=${key}
    ...    cert=${KGA_KTRI_CERT}
    ...    for_kga=True
    ...    pvno=3
    ...    subject=${cm}
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    private_key=${KGA_KTRI_KEY}
    ...    protection=signature
    ...    cert=${KGA_KARI_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Not Local Key Gen    ${response}    must_be=ktri

CA MUST Support Key Transport Management Technique With KUR
    [Documentation]    According to RFC 9483 Section 4.1.6.1, Key Transport ensures secure transport of private keys
    ...    using ktri and a client certificate with the `keyEncipherment` KeyUsage extension. The CA MUST
    ...    use the public key from the client certificate to encrypt the CEK, which is used to encrypt the
    ...    `SignedData` structure containing the private key. A valid key update request is sent
    ...    specifying the use of a certificate that supports key transport. The CA MUST respond with a
    ...    valid `EnvelopedData` structure. The extracted private key MUST match the public key in the newly
    ...    issued certificate.
    [Tags]    ktri    kur    positive
    ${is_set}=    Is Certificate And Key Set    ${KGA_KTRI_CERT}    ${KGA_KTRI_KEY}
    Skip If    not ${is_set}    Skipped because KGA_KTRI_CERT and KGA_KTRI_KEY are not set.
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${kur}=    Build Key Update Request
    ...    signing_key=${key}
    ...    cert=${KGA_KTRI_CERT}
    ...    for_kga=True
    ...    subject=${cm}
    ...    recipient=${RECIPIENT}
    ${protected_kur}=    Protect PKIMessage
    ...    ${kur}
    ...    private_key=${KGA_KTRI_KEY}
    ...    protection=signature
    ...    cert=${KGA_KTRI_CERT}
    ${response}=    Exchange PKIMessage    ${protected_kur}
    PKIMessage Body Type Must Be    ${response}    kup
    Validate Not Local Key Gen    ${response}    must_be=ktri

CA MUST Reject KGA Request For KTRI Without keyEncipherment KeyUsage
    [Documentation]    According to RFC 9483 Section 4.1.6.1, Key Transport ensures secure transport of private keys
    ...    using ktri, which requires the client certificate to include the `keyEncipherment` KeyUsage
    ...    extension. A request is sent using a client certificate that lacks the `keyEncipherment`
    ...    KeyUsage extension, which is mandatory for key transport operations. The CA MUST detect the
    ...    missing key usage, reject the request and may respond with the optional failInfo `badRequest`
    ...    or `notAuthorized`
    [Tags]    key-usage    ktri    negative
    ${is_set}=    Is Certificate And Key Set    ${NEG_KTRI_CERT}    ${NEG_KTRI_KEY}
    Skip If    not ${is_set}    Skipped because NEG_KTRI_CERT and NEG_KTRI_KEY are not set.
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${ir}=    Build Ir From Key
    ...    signing_key=${key}
    ...    cert=${NEG_KTRI_CERT}
    ...    for_kga=True
    ...    pvno=3
    ...    subject=${cm}
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    private_key=${NEG_KTRI_KEY}
    ...    protection=signature
    ...    cert=${NEG_KTRI_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=notAuthorized    exclusive=True

## 4.1.6.2. Using the Key Agreement Key Management Technique

CA MUST Support KeyAgreement Key Management Technique With IR
    [Documentation]    According to RFC 9483 Section 4.1.6.2, Key Agreement ensures secure transport of private keys
    ...    using kari and a client certificate with the `keyAgreement` KeyUsage extension. The CA MUST
    ...    use the provided public key to establish a shared CEK through a key agreement method described
    ...    in RFC 9481. The CEK then is used to encrypt the `SignedData` structure containing the private
    ...    key. A valid initialization request is sent specifying the use of a certificate that supports
    ...    key agreement. The CA MUST respond with a valid `EnvelopedData` structure. The extracted private
    ...    key MUST match the public key in the newly issued certificate.
    [Tags]    ir    kari    positive
    ${is_set}=    Is Certificate And Key Set    ${KGA_KARI_CERT}    ${NEG_KTRI_KEY}
    Skip If    not ${is_set}    Skipped because NEG_KTRI_CERT and NEG_KTRI_KEY are not set.
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key
    ...    signing_key=${None}
    ...    cert=${KGA_KARI_CERT}
    ...    for_kga=True
    ...    common_name=${cm}
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    private_key=${KGA_KARI_KEY}
    ...    protection=signature
    ...    cert=${KGA_KARI_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Not Local Key Gen    ${response}    must_be=kari

CA MUST Support KeyAgreement Key Management Technique With KUR
    [Documentation]    According to RFC 9483 Section 4.1.6.2, Key Agreement ensures secure transport of private keys
    ...    using kari and a client certificate with the `keyAgreement` KeyUsage extension. The CA MUST
    ...    use the provided public key to establish a shared CEK through a key agreement method described
    ...    in RFC 9481. The CEK is the used to encrypt the `SignedData` structure containing the private
    ...    key. A valid key update request is sent specifying the use of a certificate that supports key
    ...    agreement. The CA MUST respond with a valid `EnvelopedData` structure. The extracted private
    ...    key MUST match the public key in the newly issued certificate.
    [Tags]    kari    kur    positive
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${kur}=    Build Key Update Request
    ...    signing_key=${key}
    ...    cert=${KGA_KARI_CERT}
    ...    for_kga=True
    ...    common_name=${cm}
    ...    recipient=${RECIPIENT}
    ${protected_kur}=    Protect PKIMessage
    ...    ${kur}
    ...    private_key=${KGA_KARI_KEY}
    ...    protection=signature
    ...    cert=${KGA_KARI_CERT}

    ${response}=    Exchange PKIMessage    ${protected_kur}
    PKIMessage Body Type Must Be    ${response}    kup
    Validate Not Local Key Gen    ${response}    must_be=kari

A MUST Reject KGA IR Request For KARI Without keyAgreement KeyUsage
    [Documentation]    According to RFC 9483 Section 4.1.6.2, Key Agreement ensures secure transport of private keys
    ...    using kari and a shared CEK established through a key agreement method described in RFC 9481.
    ...    The CEK is used to encrypt the `EnvelopedData` structure containing the private key. A valid
    ...    initialization request is sent using a client certificate that lacks the `keyAgreement`
    ...    KeyUsage extension, which is required for key agreement operations. The CA MUST detect the
    ...    missing key usage, reject the request and may respond with the optional failInfo `badRequest`
    ...    or `notAuthorized`.
    [Tags]    ir    key-usage    negative
    ${is_set}=    Is Certificate And Key Set    ${NEG_KARI_CERT}    ${NEG_KARI_KEY}
    Skip If    not ${is_set}    Skipped because NEG_KARI_CERT and NEG_KARI_KEY are not set.
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${ir}=    Build Ir From Key
    ...    signing_key=${key}
    ...    cert=${NEG_KARI_CERT}
    ...    for_kga=True
    ...    common_name=${cm}
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    private_key=${NEG_KARI_KEY}
    ...    protection=signature
    ...    cert=${NEG_KTRI_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=notAuthorized    exclusive=True

## Section 4.1.6.3 Using the Password-Based Key Management Technique
# TODO maybe change to default MAC-based-body.

CA MUST Support Password-Based Key Management Technique With IR For ECC
    [Documentation]    According to RFC 9483 Section 4.1.6.2, Password-Based Key Management ensures secure transport
    ...    of private keys using the pwri structure, which relies on a pre-shared secret and a kdf to
    ...    derive the key for unwrapping the CEK. The CEK is the used to encrypt the `SignedData` structure
    ...    containing the private key. A valid initialization request is sent specifying the need for an
    ...    ECC key. The CA MUST use the pre-shared secret to establish the CEK and respond with a valid
    ...    `EnvelopedData` structure. The extracted private key MUST match the public key in the newly
    ...    issued ECC certificate.
    [Tags]    ir    positive    pwri
    Skip If    not ${ALLOW_IR_MAC_BASED}    Skipped this test because IR MAC protection is disabled.
    ${key}=    Generate Key    ecc
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key
    ...    signing_key=${key}
    ...    for_kga=True
    ...    common_name=${cm}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    password=${PRESHARED_SECRET}
    ...    protection=${DEFAULT_MAC_ALGORITHM}

    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Not Local Key Gen    ${response}    must_be=pwri

# TODO maybe change to default MAC-based-body.

CA MUST Support Password-Based Key Management Technique For IR Without Algorithm
    [Documentation]    According to RFC 9483 Section 4.1.6.2, Password-Based Key Management ensures secure transport
    ...    of private keys using the pwri structure, which relies on a pre-shared secret and a kdf to
    ...    derive the key for unwrapping the CEK. The CEK is then used to encrypt the `SignedData` structure
    ...    containing the private key. A valid initialization request is sent without specifying an
    ...    algorithm for the private key. The CA MUST use the pre-shared secret to establish the CEK and
    ...    respond with a valid `EnvelopedData` structure. The extracted private key MUST match the public
    ...    key in the newly issued certificate.
    [Tags]    ir    positive    pwri
    Skip If    not ${ALLOW_IR_MAC_BASED}    Skipped this test because IR MAC protection is disabled.
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key
    ...    signing_key=${None}
    ...    for_kga=True
    ...    common_name=${cm}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    password=${PRESHARED_SECRET}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    Validate Not Local Key Gen    ${response}    must_be=pwri

CA MUST Reject Kur KGA PWRI Message
    [Documentation]    According to RFC 9483 Section 4.1.6.2, Password-Based Key Management ensures secure transport
    ...    of private keys using pwri and a kdf to derive the key for unwrapping the CEK. The server
    ...    prepares the pwri structure with the encrypted CEK, and the client uses a shared secret to
    ...    derive the key to unwrap it. A mac-protected key update request that violates
    ...    proof-of-possession rules is sent. The CA MUST reject this reject the request and may respond
    ...    with the optional failInfo `badRequest` or `notAuthorized`.
    [Tags]    kur    negative    pwri
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${kur}=    Build Key Update Request
    ...    signing_key=${key}
    ...    cert=${ISSUED_CERT}
    ...    exclude_fields=${None}
    ...    for_kga=True
    ...    common_name=${cm}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${protected_kur}=    Protect PKIMessage    ${kur}    password=${PRESHARED_SECRET}    protection=password_based_mac
    ${response}=    Exchange PKIMessage    ${protected_kur}
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest,wrongIntegrity    exclusive=True
