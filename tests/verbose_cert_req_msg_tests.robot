# SPDX-FileCopyrightText: Copyright 2025 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Tests specifically for the lightweight CMP profile

Resource            ../config/${environment}.robot
Resource            ../resources/keywords.resource
Resource            ../resources/rf_verbose_keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../resources/certextractutils.py

Suite Setup    Set Up Test Suite
Test Tags    rfc9483-validation  verbose-tests  verbose-cert-req-msg

*** Keywords ***
Build CertConf For Implicit Test
    [Documentation]   Builds a certificate confirmation for implicit confirmation tests.
    ...                The confirmation is built with the specified body name and implicit confirmation flag.
    ...                If the implicit confirmation is `True`, the confirmation will include an implicit confirmation.
    ...                If `False`, it will not include an implicit confirmation.
    [Arguments]    ${body_name}    ${response}   &{params}
    VAR   ${cert_req_id}   ${None}
    IF  'p10cr' in '${body_name}'
        VAR   ${cert_req_id}   0
    END
    ${old_cert}=   Get From Dictionary    ${params}    old_cert    ${None}
    ${old_key}=   Get From Dictionary    ${params}    old_key    ${None}
    ${for_mac}=   Get From Dictionary    ${params}    for_mac    False
    IF  ${for_mac}
        VAR   ${exclude_fields}   ${None}
    ELSE
        VAR   ${exclude_fields}   sender,senderKID
    END
    ${cert_conf}=   Build Cert Conf From Resp    ${response}    cert_req_id=${cert_req_id}
    ...             recipient=${RECIPIENT}   for_mac=${for_mac}    exclude_fields=${exclude_fields}
    ...             sender=${SENDER}   recipient=${RECIPIENT}
    IF  'added-protection-inner' in '${body_name}'
        VAR   ${empty_data}
        ${inner_name}=   Replace String    ${body_name}    added-protection-inner-    ${empty_data}
        ${protected_inner}=    Protect Body ByName    ${inner_name}   ${cert_conf}   ${for_mac}  ${old_cert}   ${old_key}
        ${nested}=    Build Nested PKIMessage
        ...    recipient=${RECIPIENT}
        ...    other_messages=${protected_inner}
        ...    for_added_protection=True
        ${prot_cert_conf}=   Protect Body ByName    ${body_name}   ${nested}
    ELSE
        ${prot_cert_conf}=   Protect Body ByName    ${body_name}   ${cert_conf}   ${for_mac}  ${old_cert}   ${old_key}
    END
    RETURN    ${prot_cert_conf}

Validate Protection MUST Match
    [Documentation]    Validates that the protection of the PKIMessage matches the expected protection.
    ...                This keyword checks if the MAC or signature protection algorithms match the expected values.
    [Arguments]    ${body_name}    ${body}    ${response}    ${pkiconf}   &{params}
    IF  'added-protection-inner' in '${body_name}'
        ${inner_body}=  Get Inner PKIMessage    ${body}
    ELSE
        VAR  ${inner_body}   ${body}
    END
    ${for_mac}=   Get From Dictionary    ${params}    for_mac    False
    IF  ${for_mac}
        MAC Protection Algorithms Must Match    ${inner_body}   ${response}    ${pkiconf}   enforce_lwcmp=${LWCMP}   strict=${STRICT}
    ELSE
        Signature Protection Must Match    ${response}    ${pkiconf}
    END

Build ImplicitConfirm Request
    [Documentation]    Builds a certificate request with an implicit confirmation.
    ...                The request is built with the specified body name and implicit confirmation flag.
    ...                If the implicit confirmation is `True`, the request will include an implicit confirmation.
    ...                If `False`, it will not include an implicit confirmation.
    [Arguments]    ${body_name}    ${implicit_confirm}   ${for_mac}=False
    VAR   ${old_cert}   ${None}
    VAR   ${old_key}   ${None}
    IF  'kur' in '${body_name}'
        ${old_cert}  ${old_key}=   Issue New Cert For Testing
    END
    ${body}=   Build Request For ImplicitConfirm    ${body_name}    ${implicit_confirm}
    ...    for_mac=${for_mac}   old_cert=${old_cert}   old_key=${old_key}
    ${response}=   Exchange PKIMessage    ${body}
    Validate CMP Body Types   ${response}    ${body}   error=False
    IF  ${implicit_confirm}
        PKIMessage Must Contain ImplicitConfirm Extension   ${response}
    ELSE
        ${result}=    PKIMessage Contains ImplicitConfirm Extension    ${response}
        Should Be True   not ${result}    ImplicitConfirm extension should not be present in the response
    END
    ${prot_cert_conf}=   Build CertConf For Implicit Test    ${body_name}    ${response}   for_mac=${for_mac}   old_cert=${old_cert}   old_key=${old_key}
    ${pkiconf}=   Exchange PKIMessage    ${prot_cert_conf}
    IF  ${implicit_confirm}
         PKIStatusInfo Failinfo Bit Must Be    ${pkiconf}    certConfirmed   True
    ELSE
        ${resp_name}=   Get CMP Message Type    ${pkiconf}
        Should Be Equal As Strings    ${resp_name}    pkiconf
        Validate Protection MUST Match    ${body_name}    ${body}    ${response}    ${pkiconf}   for_mac=${for_mac}
    END

Build Bad Request ID Request
    [Documentation]    Builds a certificate request with an request ID unequal to `0`.
    [Arguments]    ${body_name}    ${cert_req_id}
    VAR   ${old_cert}   ${None}
    VAR   ${old_key}   ${None}
    IF  'kur' in '${body_name}'
        ${old_cert}  ${old_key}=   Issue New Cert For Testing
    END
    ${key}=  Generate Default Key
    ${cm}=  Get Next Common Name
    ${protected_body}=   Build Single Body By Name    ${body_name}    ${key}   common_name=${cm}
    ...        sender=${SENDER}    recipient=${RECIPIENT}   cert_req_id=${cert_req_id}
    ...        old_cert=${old_cert}   old_key=${old_key}
    ${response}=   Exchange PKIMessage    ${protected_body}
    Validate CMP Body Types   ${response}    ${protected_body}   error=False
    IF  'batch' not in '${body_name}'
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest   True
    ELSE
        ${inner_body}=  Get Inner PKIMessage    ${response}    2
        PKIStatusInfo Failinfo Bit Must Be    ${inner_body}    badRequest  True
    END

Build Bad CSR Version Request
    [Documentation]    Builds a certificate request with a CSR version unequal to `0`.
    [Arguments]    ${body_name}    ${csr_version}
    IF  'p10cr' not in '${body_name}'
        Fail  CSR version is only applicable for P10CR requests.
    END
    ${key}=  Generate Default Key
    ${cm}=  Get Next Common Name
    ${protected_body}=   Build Single Body By Name    ${body_name}    ${key}   common_name=${cm}
    ...        sender=${SENDER}    recipient=${RECIPIENT}   version=${csr_version}
    ${response}=   Exchange PKIMessage    ${protected_body}
    Validate CMP Body Types   ${response}    ${protected_body}   error=False
    IF  'batch' not in '${body_name}'
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    ELSE
        ${inner_body}=  Get Inner PKIMessage    ${response}    2
        PKIStatusInfo Failinfo Bit Must Be    ${inner_body}    badCertTemplate  True
    END

Build BadPOP Request
    [Documentation]    Builds a certificate request with a bad proof of possession.
    [Arguments]    ${body_name}
    VAR   ${old_cert}   ${None}
    VAR   ${old_key}   ${None}
    IF  'kur' in '${body_name}'
        ${old_cert}  ${old_key}=   Issue New Cert For Testing
    END
    ${key}=  Generate Default Key
    ${cm}=  Get Next Common Name
    ${protected_body}=   Build Single Body By Name    ${body_name}    ${key}   common_name=${cm}
    ...        sender=${SENDER}    recipient=${RECIPIENT}   old_cert=${old_cert}   old_key=${old_key}
    ...        bad_pop=True
    ${response}=   Exchange PKIMessage    ${protected_body}
    Validate CMP Body Types   ${response}    ${protected_body}   error=False
    IF  'batch' not in '${body_name}'
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP   True
    ELSE
        ${inner_body}=  Get Inner PKIMessage    ${response}    2
        PKIStatusInfo Failinfo Bit Must Be    ${inner_body}    badPOP   True
    END

Build Null-DN And No SAN Request
    [Documentation]    Builds a certificate request with a null DN and no SAN.
    [Arguments]    ${body_name}
    VAR   ${old_cert}   ${None}
    VAR   ${old_key}   ${None}
    IF  'kur' in '${body_name}'
        ${old_cert}  ${old_key}=   Issue New Cert For Testing
    END
    ${key}=  Generate Default Key
    VAR   ${cm}  Null-DN
    ${protected_body}=   Build Single Body By Name    ${body_name}    ${key}   common_name=${cm}
    ...        sender=${SENDER}    recipient=${RECIPIENT}   old_cert=${old_cert}   old_key=${old_key}
    ${response}=   Exchange PKIMessage    ${protected_body}
    Validate CMP Body Types   ${response}    ${protected_body}   error=False
    IF   'batch' not in '${body_name}'
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    ELSE
        ${inner_body}=  Get Inner PKIMessage    ${response}    2
        PKIStatusInfo Failinfo Bit Must Be    ${inner_body}    badCertTemplate   True
    END

Build Same Key Request2
    [Documentation]    Builds a certificate request with the same key as the previous request.
    ...                If the implicit confirmation is `True`, the request will include an implicit confirmation.
    ...                If `False`, it will not include an implicit confirmation.
    [Arguments]    ${body_name}
    VAR   ${old_cert}   ${None}
    VAR   ${old_key}   ${None}
    IF  'kur' in '${body_name}'
        ${old_cert}  ${old_key}=   Issue New Cert For Testing
        VAR   ${key}  ${old_key}
        VAR   ${cm}  ${old_cert["tbsCertificate"]["subject"]}
    ELSE IF  'ccr' in '${body_name}'
        VAR   ${key}  ${TRUSTED_CA_KEY_OBJ}
        VAR   ${cm}   ${TRUSTED_CA_CERT_CHAIN[0]["tbsCertificate"]["subject"]}
    ELSE
        VAR  ${key}  ${ISSUED_KEY}
        VAR  ${cm}  ${ISSUED_CERT["tbsCertificate"]["subject"]}
    END
    Log Asn1    ${cm}
    ${protected_body}=   Build Single Body By Name    ${body_name}    ${key}   common_name=${cm}
    ...        sender=${SENDER}    recipient=${RECIPIENT}
    ...        old_cert=${old_cert}   old_key=${old_key}
    ${response}=   Exchange PKIMessage    ${protected_body}
    Validate CMP Body Types   ${response}    ${protected_body}   error=False
    IF  'batch' not in '${body_name}'
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    ELSE
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    END

Build Same Key Request
    [Documentation]    Builds a certificate request with the same key as the previous request.
    [Arguments]    ${body_name}   ${for_mac}=False
    ${old_cert}  ${old_key}=   Issue New Cert For Testing
    VAR  ${cm}   ${old_cert["tbsCertificate"]["subject"]}
    ${protected_body}=   Build Single Body By Name    ${body_name}    ${old_key}
    ...        common_name=${cm}
    ...        sender=${SENDER}    recipient=${RECIPIENT}
    ...        old_cert=${old_cert}   old_key=${old_key}
    ...        new_key=${old_key}   # Set the key for the kur requests.
    ${response}=   Exchange PKIMessage    ${protected_body}
    Validate CMP Body Types   ${response}    ${protected_body}   error=False
    IF  'batch' not in '${body_name}'
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    ELSE
        ${inner_body}=  Get Inner PKIMessage    ${response}    2
        PKIStatusInfo Failinfo Bit Must Be    ${inner_body}    badCertTemplate   True
    END

Prepare Null-DN CSR Or CertTemplate
    [Documentation]    Prepare a CSR or CertTemplate with a null DN and no SAN.
    ...
    ...            Arguments:
    ...            ---------
    ...                - body_name: The type of body to prepare (e.g., 'ir', 'cr', 'kur', 'krr', 'p10cr').
    ...                - key: The key to use for the request.
    ...
    ...            Returns:
    ...            -------
    ...                - result: The prepared CSR or CertTemplate.
    ...
    ...            Examples:
    ...            --------
    ...            ${template}=   Prepare Null-DN CSR Or CertTemplate    ir    ${key}
    ...
    [Tags]    san  null-dn
    [Arguments]    ${body_name}    ${key}
    ${allowed}=    Create List    ir    cr    kur    krr    p10cr   ccr
    Run Keyword Unless    '${body_name}' in ${allowed}
    ...    Fail    Unsupported body_name: ${body_name}
    IF   '${body_name}' == 'p10cr'
         ${result}=    Build CSR           signing_key=${key}    common_name=Null-DN
    ELSE IF   '${body_name}' == 'ccr'
         ${result}=    Generate CCR CertTemplate For Testing     ${key}    Null-DN
    ELSE
         ${result}=    Prepare CertTemplate    ${key}    subject=Null-DN
    END
    RETURN    ${result}


*** Test Cases ***