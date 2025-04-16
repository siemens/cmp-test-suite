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


Suite Setup         Set Up Test Suite
Test Tags           pqc  hybrid-sig

*** Variables ***

# New Tags: composite-sig, multiple-auth

#${uri_multiple_auth}=   https://localhost:8080/cmp/cert-bindings-for-multiple-authentication
${uri_multiple_auth}=   ${None}
${uri_multiple_auth_neg}=  ${None}
${DEFAULT_ML_DSA_ALG}=   ml-dsa-87
${Allowed_freshness}=   500

*** Test Cases ***

############################
# Composite Signature Tests
############################

# Technically not all parts have to be defined, because a correct combination is
# built, but for better readability included.

#### Composite Signature Positive Tests ####

# Normally, you would use `ir` as usual; this is just to demonstrate that csr can be used in almost the same way.

CA MUST Issue A Valid Composite RSA-PSS Certificate From CSR
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid CSR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA-PSS and ML-DSA-44 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    ${key}    common_name=${cm}   use_rsa_pss=True
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=           Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage   ${cert}

CA MUST Issue a Valid Composite-Sig RSA Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=   Build Ir From Key    ${key}   common_name=${cm}  recipient=${RECIPIENT}  omit_fields=senderKID,sender
    ...      implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage   ${ir}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the secp256r1 curve
    ...                and ML-DSA-44 as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ec
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite EC-brainpool Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the brainpoolP256r1
    ...                curve and ML-DSA-65 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             composite-sig   positive   ec  brainpool
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED25519 Certificate
    [Documentation]   Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...               composite signature version. The traditional algorithm used is ED25519 and ML-DSA-65 as pq
    ...               algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]            composite-sig   positive   ed25519
    ${key}=           Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=            Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED448 Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is ED448 and ML-DSA-87 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed448
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

############################
## Pre-Hashed Versions
############################

CA MUST Issue A Valid Composite RSA-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as
    ...                pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True  use_rsa_pss=False
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite RSA-PSS-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is RSA-PSS and ML-DSA-44
    ...                as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa-pss  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True   use_rsa_pss=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is EC key on the secp256r1
    ...                curve and ML-DSA-44 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             composite-sig   positive   ec  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC-brainpool-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is EC key on the
    ...                brainpoolP256r1 curve and ML-DSA-65 as pq algorithm. The CA MUST process the valid request
    ...                and issue a valid certificate.
    [Tags]             composite-sig   positive   ec  prehashed  brainpool
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite ED25519-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is ED25519 and ML-DSA-65
    ...                as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed25519   prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite ED448-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is ED448 and ML-DSA-87 as
    ...                pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed448  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted


#### Composite Signature Mixed/Security Tests ####

CA MUST Reject Composite RSA with invalid RSA key length
    [Documentation]    As defined in Composite Sig Draft CMS03, we send a valid IR with a POP for composite signature.
    ...                The traditional algorithm is RSA key with an invalid length (512-bits) and ML-DSA-44 as pq
    ...                algorithm. The CA MUST reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             composite-sig   negative  rsa
    # generates a rsa key with length 512 bits.
    ${trad_key}=   Generate Key       algorithm=bad_rsa_key
    ${pq_key}=     Generate Key       algorithm=ml-dsa-44
    ${key}=            Generate Key    algorithm=composite-sig   trad_key=${trad_key}   pq_key=${pq_key}
    ${cm}=             Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo   ${trad_key}
    ${ir}=    Build Ir From Key    ${key}  ${cm}  
    ...         spki=${spki}  recipient=${RECIPIENT}  exclude_fields=sender,senderKID
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

#### Security Related #####

CA MUST Reject Composite Sig with Traditional Revoked key Due Compromise
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 11.2, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]             composite-sig   negative  security   revocation
    ${revoked_cert}  ${revoked_key}=   Issue And Revoke A Fresh Cert    reason=keyCompromise
    ${cm}=             Get Next Common Name        
    ${key}=            Generate Key    algorithm=composite-sig  trad_key=${revoked_key}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${revoked_key}
    ...                cert=${revoked_cert}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA SHOULD Reject Issuing Already in use Traditional Key
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 11.3, we generate a valid IR with a composite
    ...                signature algorithm. The traditional algorithm is already in use and a matching ML-DSA key is
    ...                generated. The CA SHOULD reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             composite-sig   negative  security
    ${key}=            Generate Key    algorithm=composite-sig  trad_key=${ISSUED_KEY}
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest