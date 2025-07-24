# SPDX-FileCopyrightText: Copyright 2024 Siemens AG   # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
*** Settings ***
Documentation      Contains keywords for verbose test cases so that keywords can be reused in other test cases.
...                To ensure that similar logic and shared keywords, which are easier to change
...                and maintainable, are used.

Resource            ../config/${environment}.robot
# Resource    ../config/local.robot
Library             Collections
Library             DateTime
Library             OperatingSystem
Library             String
Library             RequestsLibrary
Resource             ../resources/keywords.resource
Library             ../resources/asn1utils.py
Library             ../resources/cryptoutils.py
Library             ../resources/httputils.py
Library             ../resources/cmputils.py
Library             ../resources/utils.py
Library             ../resources/certutils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../resources/general_msg_utils.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/pq_verify_logic.py


*** Keywords ***
Validate PKI Failinfo For Verbose Testing
    [Documentation]    Validates the PKI failinfo in the response.
    ...                Checks if the failinfo is present and matches the expected value.
    ...                If the failinfo is not present or does not match, it raises an error.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `body_name`: The name of the body to be validated (e.g., "ir", "cr", "ccr", "kur", "krr", "p10cr").
    ...                - `response`: The response containing the PKI message to be validated.
    ...                - `expected_failinfo`: The expected failinfo value to be checked against the response.
    ...                - `exclusive`: Whether to check the failinfo bit exclusively. Defaults to `True`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Validate PKI Failinfo For Verbose Testing | ir | ${response} | badPOP |
    ...                | Validate PKI Failinfo For Verbose Testing | cr | ${response} | badPOP | True |
    ...                | Validate PKI Failinfo For Verbose Testing | batch-inner-ir | ${response} | badPOP |
    ...
    [Tags]    failinfo  validate  verbose_testing
    [Arguments]    ${body_name}    ${response}    ${expected_failinfo}   ${exclusive}=${True}
    IF  'batch-inner' in '${body_name}'
        ${inner_body}=    Get Inner PKIMessage    ${response}   2
        PKIStatusInfo Failinfo Bit Must Be    ${inner_body}    ${expected_failinfo}    ${exclusive}
    ELSE
        PKIStatusInfo Failinfo Bit Must Be    ${response}    ${expected_failinfo}    ${exclusive}
    END

Build Request With BadPOP
    [Documentation]    Builds a request with a bad proof of possession (POP) for the given body name,
    ...                key, and hash algorithm. Expects a signature algorithm to be provided.
    ...                The request is built with the specified parameters and **unprotected** returned.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `body_name`: The name of the body to be used in the request (e.g., "ir").
    ...                - `alg_name`: The name of the signature algorithm to be used (e.g., "rsa"
    ...                "ml-dsa-44-sha512") (the `by_name` flag is used to determine the key type).
    ...                - `hash_alg`: The name of the hash algorithm to be used. Defaults to "sha256".
    ...                - `use_rsa_pss`: Whether to use RSA-PSS. Defaults to `False`.
    ...                - `use_pre_hash`: Whether to use pre-hashing for composite keys. Defaults to `False`.
    ...
    ...                Returns:
    ...                -------
    ...                - The built request with a bad POP, which is **unprotected**.
    ...
    ...                Examples:
    ...                --------
    ...                | Build Request With BadPOP | ir | rsa | sha256 |
    ...                | Build Request With BadPOP | ir | ml-dsa-44-sha512 | sha512 |
    ...                | Build Request With BadPOP | ir | rsa | sha256 | True |
    ...
    [Tags]    build_request    bad_pop
    [Arguments]    ${body_name}    ${alg_name}   ${hash_alg}=sha256   ${use_rsa_pss}=${False}   ${use_pre_hash}=${False}
    ${key}=   Generate Unique Key    ${alg_name}   by_name=True
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}   use_rsa_pss=${use_rsa_pss}
    ...        use_pre_hash=${use_pre_hash}
    ${cm}=   Get Next Common Name
    ${cert_req}=   Prepare CertRequest   ${key}   common_name=${cm}   spki=${spki}
    ${popo}=   Prepare Signature POPO    ${key}   ${cert_req}    ${hash_alg}   bad_pop=True
    ...        use_rsa_pss=${use_rsa_pss}    use_pre_hash=${use_pre_hash}
    IF  '${body_name}' == 'ir'
        ${body}=   Build Ir From Key    ${key}   ${cm}  sender=${SENDER}  recipient=${RECIPIENT}
        ...      popo=${popo}   cert_request=${cert_req}
    ELSE IF    '${body_name}' == 'cr'
        ${body}=   Build Cr From Key    ${key}   ${cm}  sender=${SENDER}  recipient=${RECIPIENT}
        ...      popo=${popo}   cert_request=${cert_req}
    ELSE IF    '${body_name}' == 'ccr'
        ${body}=   Build Ccr From Key    ${key}   ${cm}  sender=${SENDER}  recipient=${RECIPIENT}
        ...      popo=${popo}  cert_request=${cert_req}
    ELSE IF    '${body_name}' == 'kur'
        ${body}=   Build Key Update Request      ${key}   common_name=${cm}   sender=${SENDER}  recipient=${RECIPIENT}
        ...      popo=${popo}  cert_request=${cert_req}
    ELSE IF    '${body_name}' == 'krr'
        ${body}=   Build Krr From Key    ${key}   ${cm}  sender=${SENDER}  recipient=${RECIPIENT}
        ...      popo=${popo}   cert_request=${cert_req}
    ELSE IF    '${body_name}' == 'p10cr'
        ${body}=   Build P10Cr From Key    ${key}   ${cm}  sender=${SENDER}  recipient=${RECIPIENT}
        ...      popo=${popo}
    ELSE
        Fail    Invalid body name: '${body_name}', valid options are: ir, cr, ccr, kur, krr, p10cr.
    END
    RETURN    ${body}

Build Added Protection Body Inner
    [Documentation]    Build a PKIMessage with added protection.
    [Arguments]    ${name}   &{params}
    VAR    ${empty_data}
    ${key}=   Get From Dictionary   ${params}    key
    ${inner_name}=   Replace String    ${name}    added-protection-inner-   ${empty_data}
    ${protected_ir}=    Build Single Body By Name   ${inner_name}    &{params}
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    for_added_protection=True
    ${prot_body}=    Default Protect With Trusted Cert   ${nested}
    RETURN    ${prot_body}

Build Batch Inner Body
    [Documentation]    Build a PKIMessage with batch inner body for testing.
    ...                This keyword builds a batch inner body with the specified parameters and returns it.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `name`: The name of the batch inner body to be built.
    ...                - `params`: Additional key=value pairs for the batch inner body.
    ...
    ...                Returns:
    ...                -------
    ...                - The built batch inner body.
    ...
    ...                Examples:
    ...                --------
    ...                | ${prot_body} | Build Batch Inner Body | batch-inner-ir | key=${key} |
    ...                | ${prot_body} | Build Batch Inner Body | batch-inner-cr | key=${key} |
    ...
    [Arguments]    ${name}   &{params}
    VAR    ${empty_data}
    ${key}=   Get From Dictionary   ${params}    key
    ${inner_name}=   Replace String    ${name}    batch-inner-   ${empty_data}
    ${tx_ids}=  Generate Unique Byte Values    4   16
    ${nonces}=  Generate Unique Byte Values    4   16
    ${params}=   Set To Dictionary    ${params}    transaction_id=${tx_ids[0]}    sender_nonce=${nonces[0]}
    ${protected_ir3}=    Build Single Body By Name   ${inner_name}    &{params}
    ${key1}=   Generate Unique Key    ${DEFAULT_ALGORITHM}
    ${key2}=   Generate Unique Key    ${DEFAULT_ALGORITHM}
    ${cm1}=   Get Next Common Name
    ${ir}=   Build Ir From Key    ${key1}   ${cm1}    sender=${SENDER}  recipient=${RECIPIENT}
    ${protected_ir1}=   Default Protect PKIMessage    ${ir}   protection=signature
    ${ir2}=   Build Ir From Key    ${key1}   ${cm1}    sender=${SENDER}  recipient=${RECIPIENT}
    ${protected_ir2}=   Default Protect PKIMessage    ${ir2}   protection=signature
    VAR    @{messages}    ${protected_ir1}   ${protected_ir2}    ${protected_ir3}
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${messages}
    ...    transaction_ids=${tx_ids}    sender_nonces=${nonces}
    ${prot_body}=    Default Protect With Trusted Cert   ${nested}
    RETURN    ${prot_body}

Get Or Generate Kur Key
    [Documentation]    Retrieves or generates a key for the Key Update Request (KUR).
    ...                Either it returns the `new_key` to be used for the KUR or a unique key based on the `old_key`.
    ...
    ...                Arguments:
    ...                ---------
    ...                - params: The key=value pairs containing the parameters for the KUR.
    ...
    ...                Returns:
    ...                -------
    ...                - The key to be used for the KUR.
    ...
    ...                Examples:
    ...                --------
    ...                | ${new_key}= | Get Or Generate Kur Key | ${params} |
    ...
    [Tags]    build_request   key   kur
    [Arguments]     &{params}
    ${key}=   Get From Dictionary    ${params}    new_key   ${None}
    IF  '${key}' != '${None}'
        RETURN   ${key}
    END
    ${old_key}=   Get From Dictionary    ${params}    old_key
    ${key_name}=   Get Key Name    ${old_key}
    ${new_key}=   Generate Unique Key    ${key_name}
    RETURN    ${new_key}

Build Single Body By Name
    [Documentation]    Builds a single body by the given name and returns it.
    ...                The body is built based on the specified body name and the default key.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `body_name`: The name of the body to be built (e.g., "ir", "cr", "ccr", "kur", "krr", "p10cr").
    ...                - `key`: The key to be used for building the request for the body.
    ...                - `params`: Additional parameters to be passed for building the body.
    ...
    ...                Returns:
    ...                -------
    ...                - The built body.
    ...
    ...                Examples:
    ...                --------
    ...                | Build Single Body By Name | ir |
    ...                | Build Single Body By Name | cr |
    ...
    [Tags]    build_request   build_body
    [Arguments]    ${body_name}   ${key}   &{params}
    IF  '${body_name}' == 'ir'
        ${body}=   Build Ir From Key    ${key}   sender=${SENDER}  recipient=${RECIPIENT}   &{params}
    ELSE IF    '${body_name}' == 'cr'
        ${body}=   Build Cr From Key    ${key}   sender=${SENDER}  recipient=${RECIPIENT}   &{params}
    ELSE IF    '${body_name}' == 'ccr'
        ${cert_template}=   Get From Dictionary    ${params}    cert_template   ${None}
        IF  '${cert_template}' == '${None}'
            ${cm}=   Get From Dictionary    ${params}    common_name   ${None}
            ${cert_template}  ${_}=  Generate CCR CertTemplate For Testing   ${key}   ${cm}
            ${params}=   Set To Dictionary    ${params}    cert_template=${cert_template}
        END
        ${body}=   Build Ccr From Key    ${key}   sender=${SENDER}  recipient=${RECIPIENT}   &{params}
    ELSE IF    '${body_name}' == 'kur'
        ${old_cert}=   Get From Dictionary    ${params}    old_cert
        ${old_key}=   Get From Dictionary    ${params}    old_key
        ${key}=  Get Or Generate Kur Key   &{params}
        REMOVE From Dictionary    ${params}    new_key
        ${body}=   Build Key Update Request   ${key}   recipient=${RECIPIENT}   &{params}
        ${protected_body}=   Protect PKIMessage    ${body}   signature    cert=${old_cert}  private_key=${old_key}
        RETURN    ${protected_body}
    ELSE IF    '${body_name}' == 'krr'
        ${body}=   Build Krr From Key    ${key}   recipient=${RECIPIENT}   &{params}
    ELSE IF    '${body_name}' == 'p10cr'
        ${body}=   Build P10Cr From Key    ${key}   sender=${SENDER}  recipient=${RECIPIENT}   &{params}
    ELSE IF    'added-protection' in '${body_name}'
        ${body}=   Build Added Protection Body Inner   ${body_name}   key=${key}   sender=${SENDER}
        ...        recipient=${RECIPIENT}   &{params}
    ELSE IF    'batch-inner' in '${body_name}'
        ${body}=   Build Batch Inner Body   ${body_name}   key=${key}   sender=${SENDER}
        ...        recipient=${RECIPIENT}   &{params}
    ELSE
        Fail    Invalid body name: '${body_name}', valid options are: ir, cr, ccr, kur, krr, p10cr.
    END
    ${for_mac}=   Get From Dictionary    ${params}    for_mac   False
    ${protected_body}=   Protect Body ByName    ${body_name}    ${body}   ${for_mac}
    RETURN    ${protected_body}

Protect Body ByName
    [Documentation]    Protects a body by its name using the provided key and returns the protected body.
    ...                The body is built based on the specified body name and the default key.
    ...
    ...                Arguments:
    ...                ---------
    ...                - body_name: The name of the body to be protected (e.g., "ir", "cr", "ccr", "kur", "krr", "p10cr").
    ...
    ...                Returns:
    ...                -------
    ...                - The protected body.
    ...
    ...                Examples:
    ...                --------
    ...                | Protect Body By Name | ir |
    ...                | Protect Body By Name | cr |
    [Tags]    build_request   protect_body  protection
    [Arguments]    ${body_name}   ${body}   ${for_mac}=${False}   ${old_cert}=${None}   ${old_key}=${None}
    IF   'added-protection' in '${body_name}' or 'batch-inner' in '${body_name}'
            ${prot_body}=   Default Protect With Trusted Cert    ${body}
    ELSE IF  ${for_mac}
        ${prot_body}=   Default Protect With MAC    ${body}
    ELSE IF    'ccr' == '${body_name}'
        ${prot_body}=   Default Protect PKIMessage With Trusted CA Cert   ${body}
    ELSE IF  'kur' in '${body_name}'
        ${prot_body}=   Protect PKIMessage    ${body}   signature    private_key=${old_key}   cert=${old_cert}
    ELSE
        ${prot_body}=   Default Protect PKIMessage    ${body}   protection=signature
    END
    RETURN    ${prot_body}

Build Request For ImplicitConfirm
    [Documentation]    Builds a request for implicit confirmation with the given body name,
    ...                key, and hash algorithm. Expects a signature algorithm to be provided.
    ...                The request is built with the specified parameters and **unprotected** returned.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `body_name`: The name of the body to be used in the request (e.g., "ir").
    ...                - `alg_name`: The name of the signature algorithm to be used (e.g., "rsa"
    ...                "ml-dsa-44-sha512") (the `by_name` flag is used to determine the key type).
    ...                - `hash_alg`: The name of the hash algorithm to be used. Defaults to "sha256".
    ...                - `use_rsa_pss`: Whether to use RSA-PSS. Defaults to `False`.
    ...                - `use_pre_hash`: Whether to use pre-hashing for composite keys. Defaults to `False`.
    ...
    ...                Returns:
    ...                -------
    ...                - The built request for implicit confirmation, which is **unprotected**.
    ...
    ...                Examples:
    ...                --------
    ...                | Build Request For ImplicitConfirm | ir |  True |
    ...                | Build Request For ImplicitConfirm | ir |  False |
    ...                | Build Request For ImplicitConfirm | ir | True | ml-dsa-44-sha512 |
    ...
    [Tags]    build_request   implicit_confirm
    [Arguments]    ${body_name}    ${implicit_confirm}   ${key_alg}=${None}   &{params}
    ${cm}=   Get Next Common Name
    IF  '${key_alg}' == '${None}'
        ${key}=   Generate Default Key
    ELSE
        ${key}=   Generate Unique Key    ${key_alg}   by_name=True
    END
    ${protected_body}=   Build Single Body By Name    ${body_name}    ${key}   common_name=${cm}   implicit_confirm=${implicit_confirm}
    ...        sender=${SENDER}    recipient=${RECIPIENT}   &{params}
    RETURN    ${protected_body}
