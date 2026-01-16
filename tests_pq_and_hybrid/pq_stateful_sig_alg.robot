# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0


*** Settings ***
Documentation    Test cases for PQ Sig algorithms to check all algorithm combinations.

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
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_verify_logic.py

Test Tags           pq-stateful-sig   pqc  pq-sig  verbose-alg   verbose-tests   deterministic-fail
Suite Setup         Set Up PQ Stateful Sig Suite
Suite Teardown      Clean Verbose STFL Mappings


*** Keywords ***
Set Up PQ Stateful Sig Suite
    [Documentation]    Initializes the test suite for PQ stateful signature algorithm tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                PQ stateful issuing endpoint for certificate requests using XMSS, XMSSMT, or HSS algorithms.
    ...
    ...                The CA_CMP_URL suite variable is updated to the PQ stateful-specific endpoint.
    Set Up Test Suite
    ${url}=   Get PQ Stateful Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE

Clean Verbose STFL Mappings
    [Documentation]   Remove all verbose mappings for stateful signature algorithms, to save
    ...                memory and avoid conflicts in the test suite.
    # Uncomment the next line to disable the cleaning of verbose mappings.
    # RETURN
    VAR    &{PQ_STATEFUL_SIG_CERT_CONF_CERTS}    scope=Global
    VAR    &{PQ_STATEFUL_SIG_KEYS_VERBOSE}     scope=Global
    VAR    &{PQ_STATEFUL_SIG_CERTS_VERBOSE}   scope=Global

Get Reason Name
    [Documentation]    Determine the correct reason string for a request.
    ...                The returned value is used to load a prepared key representing
    ...                this failure scenario so that different error paths can be tested.
    ...                Arguments:
    ...                ---------
    ...                - `${bad_pop}`: Set to `True` when an invalid proof of possession is required.
    ...                - `${exhausted}`: Indicates that the key should be used up before the request.
    ...                - `${invalid_param}`: Request should contain invalid algorithm parameters.
    ...                - `${invalid_key_size}`: Use a key with an invalid size in the request.
    ...                - `${already_in_use}`: Simulate a request with a key that already has a certificate.
    ...                Returns:
    ...                -------
    ...                - A string representing the reason to load the key for.
    [Arguments]    ${bad_pop}   ${exhausted}   ${invalid_param}   ${invalid_key_size}   ${already_in_use}
    IF   ${exhausted}
        VAR   ${reason}    exhausted
    ELSE IF   ${already_in_use}
        VAR   ${reason}    popo
    ELSE IF   ${bad_pop}
        VAR   ${reason}    bad_pop
    ELSE IF   ${invalid_param}
        VAR   ${reason}    bad_params
    ELSE IF   ${invalid_key_size}
        VAR   ${reason}    bad_key_size
    ELSE
        VAR   ${reason}    popo
    END
    RETURN    ${reason}

Build P10cr Request For STFL Sig Key
    [Documentation]    Prepare a `p10cr` request body using a stateful PQ signature key.
    ...                This helper assembles all fields so that the resulting request
    ...                can be used in the tests requesting certificates.
    ...                Arguments:
    ...                ---------
    ...                - `${pq_key}`: The stateful signature key object used for the request.
    ...                - `${cm}`: Common name that will be embedded in the certificate request.
    ...                - `${spki}`: SubjectPublicKeyInfo representation of `${pq_key}`.
    ...                - `${bad_pop}`: If `True`, a malformed proof of possession is created.
    ...                Returns:
    ...                -------
    ...                - A unprotected `p10cr` request body that can be used to request a certificate.
    [Arguments]    ${pq_key}   ${cm}   ${spki}   ${bad_pop}
    ${extensions}=   Prepare Extensions    digitalSignature    critical=${False}
    ${p10cr}=   Build P10cr From Key    ${pq_key}   common_name=${cm}   bad_pop=${bad_pop}
    ...      spki=${spki}   extensions=${extensions}   exclude_fields=sender,senderKID
    ...      implicit_confirm=True    recipient=${RECIPIENT}
    RETURN    ${p10cr}

Request For PQ Stateful Sig Key
    [Documentation]  Build and send a certificate request using a PQ stateful signature key.
    ...              This keyword covers the complete test flow: creation of the request,
    ...              sending it to the CA and validating the response.
    ...
    ...            Arguments:
    ...            ---------
    ...            - `alg_name`: The name of the algorithm to use for the key.
    ...            - `body_name`: The type of body to use for the request, e.g., `p10cr` or `ir`.
    ...            - `bad_pop`: A boolean indicating whether to use an invalid proof of possession.
    ...            - `exhausted`: A boolean indicating whether to exhaust the key.
    ...            - `invalid_param`: A boolean indicating whether to use invalid parameters in the request.
    ...            - `invalid_key_size`: A boolean indicating whether to use an invalid key size.
    ...            - `already_in_use`: A boolean indicating whether to use a key that already has a certificate.
    [Arguments]    ${alg_name}   ${body_name}    ${bad_pop}   ${exhausted}   ${invalid_param}   ${invalid_key_size}   ${already_in_use}
    ${reason}=   Get Reason Name    ${bad_pop}   ${exhausted}   ${invalid_param}   ${invalid_key_size}   ${already_in_use}
    ${pq_key}=   Get PQ Stateful Sig Key Verbose    ${alg_name}   ${body_name}    ${reason}
    ${cm}=   Get Next Common Name
    IF  ${exhausted}
        ${pq_key}=   Modify PQ Stateful Sig Private Key    ${pq_key}
    ELSE IF    ${already_in_use}
        ${pq_cert}=   Get From Dictionary    ${PQ_STATEFUL_SIG_CERTS_VERBOSE}    ${alg_name}_${body_name}    ${None}
        ${result}=   Is Certificate And Key Set    ${pq_cert}    ${pq_key}
        Skip If   not ${result}    PQ Stateful Sig Key ${alg_name} is not in use.
        ${cm}=  Get Common Name    ${pq_cert}
    END
    ${spki}=   Prepare SubjectPublicKeyInfo    ${pq_key}    invalid_key_size=${invalid_key_size}
    ...        add_params_rand_bytes=${invalid_param}
    ${extensions}=   Prepare Extensions    digitalSignature    critical=${False}
    IF  '${body_name}' == 'p10cr'
        ${request_body}=    Build P10cr Request For STFL Sig Key   ${pq_key}  ${cm}  ${spki}   ${bad_pop}
    ELSE IF  '${body_name}' == 'ir'
        ${cert_request}=   Prepare CertRequest  ${pq_key}  ${cm}  spki=${spki}   extensions=${extensions}
        ${popo}=   Prepare Signature POPO    ${pq_key}   ${cert_request}  bad_pop=${bad_pop}
        ${request_body}=   Build Ir From Key    ${pq_key}   cert_request=${cert_request}  popo=${popo}
            ...      exclude_fields=sender,senderKID   implicit_confirm=True    recipient=${RECIPIENT}
    ELSE
        Fail    Unsupported body name: ${body_name}
    END
    ${protected_ir}=   Default Protect PKIMessage    ${request_body}
    ${url}=  Get PQ Stateful Issuing URL
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Validate Response For PQ Stateful Sig Key    ${response}   ${body_name}   ${alg_name}
    ...      ${bad_pop}   ${exhausted}
    ...     ${already_in_use}   ${invalid_param}   ${invalid_key_size}

Validate Response For PQ Stateful Sig Key
    [Documentation]    Validate the response of a request for a PQ stateful signature key.
    ...                This keyword contains the actual test assertions verifying
    ...                success or specific error conditions.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `${response}`: The PKIMessage returned from the CA.
    ...                - `${body_name}`: Type of the request body (`p10cr` or `ir`).
    ...                - `${alg_name}`: Name of the algorithm used for the request.
    ...                - `${bad_pop}`: Indicates an intentionally wrong PoP.
    ...                - `${exhausted}`: Specifies if the key was exhausted beforehand.
    ...                - `${already_in_use}`: Whether the request reuses a key that already has a certificate.
    ...                - `${invalid_param}`: Request carried invalid algorithm parameters.
    ...                - `${invalid_key_size}`: Request used a key with an invalid size.
    [Arguments]    ${response}   ${body_name}   ${alg_name}   ${bad_pop}   ${exhausted}   ${already_in_use}   ${invalid_param}   ${invalid_key_size}
    ${url}=   Get PQ Stateful Issuing URL
    IF  ${exhausted}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP   False
    ELSE IF    ${already_in_use}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    ELSE IF   ${bad_pop}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP   True
    ELSE IF   ${invalid_param}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    ELSE IF    ${invalid_key_size}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate   True
    ELSE
        PKIStatus Must Be    ${response}    accepted
        Validate Certificate Was Issued For Expected Alg  ${response}  ${alg_name}
        ${cert}=   Confirm Certificate If Needed    ${response}   url=${url}
        Set To Dictionary    ${PQ_STATEFUL_SIG_CERTS_VERBOSE}   ${alg_name}_${body_name}=${cert}
    END

Request For NIST Disapproved PQ Stateful Sig Key
    [Documentation]    Build and send a request with a stateful signature algorithm that
    ...                is not approved by NIST. The request should be rejected by the CA.
    ...                The not approved algorithm is specified in SP 800-208.
    ...
    ...                Arguments:
    ...                - `${algorithm}`: Identifier of the disapproved algorithm.
    ...                - `${body_name}`: Name of the request body (`p10cr` or `ir`).
    [Arguments]    ${algorithm}   ${body_name}
    ${pq_key}=   Get PQ Stateful Sig Key Verbose    ${algorithm}    ${body_name}   bad_pop
    ${cm}=   Get Next Common Name
    ${ir}=   Build Ir From Key    ${pq_key}   exclude_fields=sender,senderKID   implicit_confirm=True
    ...      recipient=${RECIPIENT}
    ${protected_ir}=   Default Protect PKIMessage    ${ir}
    ${url}=  Get PQ Stateful Issuing URL
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badAlg,badCertTemplate   False

Request For Only HSS Stateful Sig Key
    [Documentation]    Prepare and return a PKIProtected request for an HSS stateful signature key.
    ...                The caller can then send the request and validate the response separately.
    ...
    ...                Arguments:
    ...                - `${algorithm}`: The HSS algorithm to use for the key.
    ...                - `${body_name}`: The request body type.
    ...                - `${invalid_key_size}`: If `True`, create a key with an invalid size.
    ...                - `${zero_length}`: If `True`, use a zero-length key for negative testing.
    [Arguments]    ${algorithm}   ${body_name}   ${invalid_key_size}   ${zero_length}
    [Arguments]    ${algorithm}   ${body_name}   ${invalid_key_size}   ${zero_length}
    IF  ${invalid_key_size}
        # Length must be less than 9 for HSS.
        ${pq_key}=   Generate Unique Key    ${algorithm}   length=9
        # ${pq_key}=   Get PQ Stateful Sig Key Verbose    ${algorithm}    ${body_name}   invalid_key_size
    ELSE IF   ${zero_length}
        ${pq_key}=    ${pq_key}=   Generate Unique Key    ${algorithm}
        #${pq_key}=   Get PQ Stateful Sig Key Verbose    ${algorithm}    ${body_name}   zero_length
    ELSE
        ${pq_key}=   Get PQ Stateful Sig Key Verbose    ${algorithm}    ${body_name}
    END
    ${cm}=   Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${pq_key}   invalid_key=${zero_length}
    ${extensions}=   Prepare Extensions    digitalSignature    critical=${False}
    IF  '${body_name}' == 'p10cr'
        ${p10cr}=   Build P10cr From Key    ${pq_key}   common_name=${cm}   spki=${spki}
        ...      extensions=${extensions}   exclude_fields=sender,senderKID
        ...      implicit_confirm=True    recipient=${RECIPIENT}
        ${protected}=   Default Protect PKIMessage    ${p10cr}
    ELSE IF  '${body_name}' == 'ir'
        ${cert_request}=   Prepare CertRequest  ${pq_key}  ${cm}  spki=${spki}   extensions=${extensions}
        ${popo}=   Prepare Signature POPO    ${pq_key}   ${cert_request}
        ${ir}=   Build Ir From Key    ${pq_key}   cert_request=${cert_request}  popo=${popo}
            ...      exclude_fields=sender,senderKID   implicit_confirm=True    recipient=${RECIPIENT}
        ${protected}=   Default Protect PKIMessage    ${ir}
    ELSE
        Fail    Unsupported body name: ${body_name}
    END
    RETURN    ${protected}

Validate PKIProtected Response
    [Documentation]    Validate the server response of a PKIProtected request.
    ...                The assertions here verify that the protection value and request
    ...                parameters are handled correctly.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `${response}`: The received PKIMessage to check.
    ...                - `${bad_message_check}`: Expect an invalid message signature or MAC.
    ...                - `${invalid_parameters}`: Request contained bogus parameters.
    ...                - `${exhausted}`: Indicates that the signing key had been exhausted.
    ...                - `${used_index}`: Request uses an already consumed key index.
    ...                - `${popo_exhausted_key}`: Proof of possession signed with an exhausted key.
    [Arguments]    ${response}   ${bad_message_check}   ${invalid_parameters}   ${exhausted}   ${used_index}   ${popo_exhausted_key}
    IF  ${exhausted}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck   True
        ${_}=   Display PKIStatusInfo    ${response}
    ELSE IF   ${bad_message_check}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck   True
        ${_}=   Display PKIStatusInfo    ${response}
    ELSE IF   ${invalid_parameters}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck,badDataFormat   False
        ${_}=   Display PKIStatusInfo    ${response}
    ELSE IF   ${used_index}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck,badRequest   False
        ${_}=   Display PKIStatusInfo    ${response}

    ELSE IF    ${popo_exhausted_key}
        PKIStatus Must Be    ${response}    rejection
        PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck,badRequest   False
        ${_}=   Display PKIStatusInfo    ${response}
    ELSE
        PKIStatus Must Be    ${response}    accepted
    END

Request With PKIProtected Stateful Sig Key
    [Documentation]    Send a certificate request signed with a PQ stateful signature key.
    ...                The keyword prepares the PKIProtected message and then
    ...                validates the response using `Validate PKIProtected Response`.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `${algorithm}`: Algorithm used for the signing key.
    ...                - `${body_name}`: Request body type.
    ...                - `${bad_message_check}`: Whether to intentionally corrupt the signature/MAC.
    ...                - `${invalid_parameters}`: Include invalid parameters when set to `True`.
    ...                - `${exhausted}`: Exhaust the key before signing the request.
    ...                - `${used_index}`: Use a previously consumed key index.
    ...                - `${popo_exhausted_key}`: The key was already used at the time, the key was used to \
    ...                sign the proof of possession.
    [Arguments]    ${algorithm}   ${body_name}   ${bad_message_check}    ${invalid_parameters}   ${exhausted}   ${used_index}   ${popo_exhausted_key}
    ${pq_key}=   Get PQ Stateful Sig Key Verbose     ${algorithm}    ${body_name}   popo
    ${pq_cert}=   Get From Dictionary    ${PQ_STATEFUL_SIG_CERTS_VERBOSE}    ${algorithm}_${body_name}    ${None}
    ${result}=   Is Certificate And Key Set    ${pq_cert}    ${pq_key}
    IF  not ${result}
        Skip    For the PQ Stateful Sig Key ${algorithm} was no certificate created.
    END
    IF  ${exhausted}
        ${pq_key}=   Modify PQ Stateful Sig Private Key    ${pq_key}
    ELSE IF  ${used_index}
        ${pq_key}=   Modify PQ Stateful Sig Private Key    ${pq_key}   used_index=${used_index}  index=-4
    ELSE IF    ${popo_exhausted_key}
        ${pq_key}=   Modify PQ Stateful Sig Private Key    ${pq_key}   index=0
    END
    ${cert_template}   ${new_key}=   Generate CertTemplate For Testing
    ${ir}=   Build Ir From Key    ${new_key}   cert_template=${cert_template}
    ...       exclude_fields=sender,senderKID    recipient=${RECIPIENT}
    ${protected_ir}=   Protect PKIMessage    ${ir}   signature   bad_message_check=${bad_message_check}
    ...                add_params_rand_val=${invalid_parameters}   private_key=${pq_key}   cert=${pq_cert}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Validate PKIProtected Response    ${response}   ${bad_message_check}   ${invalid_parameters}   ${exhausted}   ${used_index}   ${popo_exhausted_key}

Build Certificate Confirmation Test
    [Documentation]    Issue a certificate using a PQ stateful signature key and immediately
    ...                build a certificate confirmation request for it. This covers the positive
    ...                confirmation.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `${algorithm}`: Algorithm for the stateful key to request the certificate.
    ...                - `${body_name}`: Request body type for the initial certificate request.
    [Arguments]    ${algorithm}   ${body_name}
    ${new_key}=   Get PQ Stateful Sig Key Verbose     ${algorithm}   ${body_name}   cert_conf
    ${ir}=   Build Ir From Key    ${new_key}
        ...       exclude_fields=sender,senderKID    recipient=${RECIPIENT}   implicit_confirm=False
    ${protected_ir}=   Default Protect PKIMessage    ${ir}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    accepted
    ${cert}=  Get Cert From PKIMessage    ${response}
    ${cert_conf}=  Build Cert Conf From Resp    ${response}
    ${prot_cert_conf}=   Default Protect PKIMessage    ${cert_conf}
    ${exchange_conf}=   Exchange PKIMessage    ${cert_conf}
    PKIMessage Body Type Must Be    ${exchange_conf}    pkiconf
    ${name}=  Set Variable    ${algorithm}_${body_name}
    Set To Dictionary    ${PQ_STATEFUL_SIG_CERT_CONF_CERTS}   ${name}=${cert}

Build Certificate Confirmation Used Key Test
    [Documentation]    Attempt a certificate confirmation using an already consumed
    ...                key index, the key index was already used to establish a certificate.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `${algorithm}`: Algorithm used for the stateful signature key.
    ...                - `${body_name}`: Request body type for the certificate issuance.
    [Arguments]    ${algorithm}   ${body_name}
    ${new_key}=   Get PQ Stateful Sig Key Verbose     ${algorithm}   ${body_name}   cert_conf
    ${name}=  Set Variable    ${algorithm}_${body_name}
    ${pq_cert}=   Get From Dictionary    ${PQ_STATEFUL_SIG_CERT_CONF_CERTS}    ${name}    ${None}
    ${result}=   Is Certificate And Key Set    ${pq_cert}    ${new_key}
    IF  not ${result}
        Skip    For the PQ Stateful Sig Key ${algorithm} was no certificate created.
    END
    # To avoid a already in use key, failure.
    ${key}=   Generate Default Key
    ${ir}=   Build Ir From Key    ${key}
    ...       exclude_fields=sender,senderKID    recipient=${RECIPIENT}
    # To check if the index of the POPO signature was also saved.
    ${exhausted_key}=   Modify PQ Stateful Sig Private Key    ${new_key}   used_index=0
    ${protected_ir}=   Protect PKIMessage    ${ir}   signature
    ...                private_key=${exhausted_key}   cert=${pq_cert}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badMessageCheck,badRequest   False


*** Test Cases ***
Invalid Stateful Sig XMSS-SHA2_10_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_10_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_256 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_256 IR Key Size
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_10_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_256 Already In Use IR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_10_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_10_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_10_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_10_256    certConf
    Build Certificate Confirmation Test    xmss-sha2_10_256    ir

Invalid Cert Conf for XMSS-SHA2_10_256 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_10_256    ir

Invalid Stateful Sig XMSS-SHA2_16_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_16_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_256 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_256 IR Key Size
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_16_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_256 Already In Use IR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_16_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_16_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_16_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_16_256    certConf
    Build Certificate Confirmation Test    xmss-sha2_16_256    ir

Invalid Cert Conf for XMSS-SHA2_16_256 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_16_256    ir

Invalid Stateful Sig XMSS-SHA2_20_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_20_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_256 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_256 IR Key Size
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_20_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_256 Already In Use IR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_20_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_20_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 IR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_20_256 IR Request
    [Tags]    positive    xmss    xmss-sha2_20_256    certConf
    Build Certificate Confirmation Test    xmss-sha2_20_256    ir

Invalid Cert Conf for XMSS-SHA2_20_256 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_20_256    ir

Invalid NIST Disapproved XMSS-SHAKE_10_256 IR Request
    [Tags]    negative    xmss    xmss-shake_10_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_10_256    ir

Invalid NIST Disapproved XMSS-SHAKE_16_256 IR Request
    [Tags]    negative    xmss    xmss-shake_16_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_16_256    ir

Invalid NIST Disapproved XMSS-SHAKE_20_256 IR Request
    [Tags]    negative    xmss    xmss-shake_20_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_20_256    ir

Invalid NIST Disapproved XMSS-SHA2_10_512 IR Request
    [Tags]    negative    xmss    xmss-sha2_10_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-sha2_10_512    ir

Invalid NIST Disapproved XMSS-SHA2_16_512 IR Request
    [Tags]    negative    xmss    xmss-sha2_16_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-sha2_16_512    ir

Invalid NIST Disapproved XMSS-SHA2_20_512 IR Request
    [Tags]    negative    xmss    xmss-sha2_20_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-sha2_20_512    ir

Invalid NIST Disapproved XMSS-SHAKE_10_512 IR Request
    [Tags]    negative    xmss    xmss-shake_10_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_10_512    ir

Invalid NIST Disapproved XMSS-SHAKE_16_512 IR Request
    [Tags]    negative    xmss    xmss-shake_16_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_16_512    ir

Invalid NIST Disapproved XMSS-SHAKE_20_512 IR Request
    [Tags]    negative    xmss    xmss-shake_20_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_20_512    ir

Invalid Stateful Sig XMSS-SHA2_10_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_10_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_192 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_192 IR Key Size
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_10_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_192 Already In Use IR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_10_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_10_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_10_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_10_192    certConf
    Build Certificate Confirmation Test    xmss-sha2_10_192    ir

Invalid Cert Conf for XMSS-SHA2_10_192 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_10_192    ir

Invalid Stateful Sig XMSS-SHA2_16_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_16_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_192 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_192 IR Key Size
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_16_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_192 Already In Use IR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_16_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_16_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_16_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_16_192    certConf
    Build Certificate Confirmation Test    xmss-sha2_16_192    ir

Invalid Cert Conf for XMSS-SHA2_16_192 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_16_192    ir

Invalid Stateful Sig XMSS-SHA2_20_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_20_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_192 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_192 IR Key Size
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_20_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_192 Already In Use IR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_20_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_20_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 IR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_20_192 IR Request
    [Tags]    positive    xmss    xmss-sha2_20_192    certConf
    Build Certificate Confirmation Test    xmss-sha2_20_192    ir

Invalid Cert Conf for XMSS-SHA2_20_192 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_20_192    ir

Invalid Stateful Sig XMSS-SHAKE256_10_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_10_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_192 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_192 IR Key Size
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_10_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_192 Already In Use IR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_10_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_10_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_10_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_10_192    certConf
    Build Certificate Confirmation Test    xmss-shake256_10_192    ir

Invalid Cert Conf for XMSS-SHAKE256_10_192 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_10_192    ir

Invalid Stateful Sig XMSS-SHAKE256_16_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_16_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_192 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_192 IR Key Size
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_16_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_192 Already In Use IR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_16_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_16_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_16_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_16_192    certConf
    Build Certificate Confirmation Test    xmss-shake256_16_192    ir

Invalid Cert Conf for XMSS-SHAKE256_16_192 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_16_192    ir

Invalid Stateful Sig XMSS-SHAKE256_20_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_20_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_192 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_192 IR Key Size
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_20_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_192 Already In Use IR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_20_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_20_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 IR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_20_192 IR Request
    [Tags]    positive    xmss    xmss-shake256_20_192    certConf
    Build Certificate Confirmation Test    xmss-shake256_20_192    ir

Invalid Cert Conf for XMSS-SHAKE256_20_192 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_20_192    ir

Invalid Stateful Sig XMSS-SHAKE256_10_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_10_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_256 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_256 IR Key Size
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_10_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_256 Already In Use IR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_10_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_10_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_10_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_10_256    certConf
    Build Certificate Confirmation Test    xmss-shake256_10_256    ir

Invalid Cert Conf for XMSS-SHAKE256_10_256 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_10_256    ir

Invalid Stateful Sig XMSS-SHAKE256_16_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_16_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_256 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_256 IR Key Size
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_16_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_256 Already In Use IR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_16_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_16_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_16_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_16_256    certConf
    Build Certificate Confirmation Test    xmss-shake256_16_256    ir

Invalid Cert Conf for XMSS-SHAKE256_16_256 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_16_256    ir

Invalid Stateful Sig XMSS-SHAKE256_20_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_20_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_256 IR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_256 IR Key Size
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_20_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_256 Already In Use IR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_20_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_20_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 IR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 IR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 IR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 IR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_20_256 IR Request
    [Tags]    positive    xmss    xmss-shake256_20_256    certConf
    Build Certificate Confirmation Test    xmss-shake256_20_256    ir

Invalid Cert Conf for XMSS-SHAKE256_20_256 IR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_20_256    ir

Invalid Stateful Sig XMSS-SHA2_10_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_10_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_256 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_256 P10CR Key Size
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_10_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_256 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_10_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_10_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_10_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_10_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_10_256    certConf
    Build Certificate Confirmation Test    xmss-sha2_10_256    p10cr

Invalid Cert Conf for XMSS-SHA2_10_256 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_10_256    p10cr

Invalid Stateful Sig XMSS-SHA2_16_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_16_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_256 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_256 P10CR Key Size
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_16_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_256 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_16_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_16_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_16_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_16_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_16_256    certConf
    Build Certificate Confirmation Test    xmss-sha2_16_256    p10cr

Invalid Cert Conf for XMSS-SHA2_16_256 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_16_256    p10cr

Invalid Stateful Sig XMSS-SHA2_20_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_20_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_256 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_256 P10CR Key Size
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_20_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_256 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_20_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_20_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_20_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_20_256 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_20_256    certConf
    Build Certificate Confirmation Test    xmss-sha2_20_256    p10cr

Invalid Cert Conf for XMSS-SHA2_20_256 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_20_256    p10cr

Invalid NIST Disapproved XMSS-SHAKE_10_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake_10_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_10_256    p10cr

Invalid NIST Disapproved XMSS-SHAKE_16_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake_16_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_16_256    p10cr

Invalid NIST Disapproved XMSS-SHAKE_20_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake_20_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_20_256    p10cr

Invalid NIST Disapproved XMSS-SHA2_10_512 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-sha2_10_512    p10cr

Invalid NIST Disapproved XMSS-SHA2_16_512 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-sha2_16_512    p10cr

Invalid NIST Disapproved XMSS-SHA2_20_512 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-sha2_20_512    p10cr

Invalid NIST Disapproved XMSS-SHAKE_10_512 P10CR Request
    [Tags]    negative    xmss    xmss-shake_10_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_10_512    p10cr

Invalid NIST Disapproved XMSS-SHAKE_16_512 P10CR Request
    [Tags]    negative    xmss    xmss-shake_16_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_16_512    p10cr

Invalid NIST Disapproved XMSS-SHAKE_20_512 P10CR Request
    [Tags]    negative    xmss    xmss-shake_20_512    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmss-shake_20_512    p10cr

Invalid Stateful Sig XMSS-SHA2_10_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_10_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_192 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_192 P10CR Key Size
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_10_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_10_192 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_10_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_10_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_10_192 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_10_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_10_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_10_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_10_192    certConf
    Build Certificate Confirmation Test    xmss-sha2_10_192    p10cr

Invalid Cert Conf for XMSS-SHA2_10_192 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_10_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_10_192    p10cr

Invalid Stateful Sig XMSS-SHA2_16_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_16_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_192 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_192 P10CR Key Size
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_16_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_16_192 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_16_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_16_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_16_192 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_16_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_16_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_16_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_16_192    certConf
    Build Certificate Confirmation Test    xmss-sha2_16_192    p10cr

Invalid Cert Conf for XMSS-SHA2_16_192 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_16_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_16_192    p10cr

Invalid Stateful Sig XMSS-SHA2_20_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHA2_20_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_192 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_192 P10CR Key Size
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHA2_20_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHA2_20_192 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHA2_20_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_20_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 P10CR Request
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHA2_20_192 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-sha2_20_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-sha2_20_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHA2_20_192 P10CR Request
    [Tags]    positive    xmss    xmss-sha2_20_192    certConf
    Build Certificate Confirmation Test    xmss-sha2_20_192    p10cr

Invalid Cert Conf for XMSS-SHA2_20_192 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-sha2_20_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-sha2_20_192    p10cr

Invalid Stateful Sig XMSS-SHAKE256_10_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_10_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_192 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_192 P10CR Key Size
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_10_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_10_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_192 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_10_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_10_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_192 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_10_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_10_192    certConf
    Build Certificate Confirmation Test    xmss-shake256_10_192    p10cr

Invalid Cert Conf for XMSS-SHAKE256_10_192 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_10_192    p10cr

Invalid Stateful Sig XMSS-SHAKE256_16_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_16_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_192 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_192 P10CR Key Size
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_16_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_16_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_192 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_16_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_16_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_192 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_16_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_16_192    certConf
    Build Certificate Confirmation Test    xmss-shake256_16_192    p10cr

Invalid Cert Conf for XMSS-SHAKE256_16_192 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_16_192    p10cr

Invalid Stateful Sig XMSS-SHAKE256_20_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_20_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_192 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_192 P10CR Key Size
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_20_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_20_192    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_192 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_20_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_20_192    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_192 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_192    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_192    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_20_192 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_20_192    certConf
    Build Certificate Confirmation Test    xmss-shake256_20_192    p10cr

Invalid Cert Conf for XMSS-SHAKE256_20_192 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_192    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_20_192    p10cr

Invalid Stateful Sig XMSS-SHAKE256_10_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_10_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_256 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_256 P10CR Key Size
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_10_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_10_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_10_256 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_10_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_10_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_10_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_10_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_10_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_10_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_10_256    certConf
    Build Certificate Confirmation Test    xmss-shake256_10_256    p10cr

Invalid Cert Conf for XMSS-SHAKE256_10_256 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_10_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_10_256    p10cr

Invalid Stateful Sig XMSS-SHAKE256_16_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_16_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_256 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_256 P10CR Key Size
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_16_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_16_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_16_256 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_16_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_16_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_16_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_16_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_16_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_16_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_16_256    certConf
    Build Certificate Confirmation Test    xmss-shake256_16_256    p10cr

Invalid Cert Conf for XMSS-SHAKE256_16_256 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_16_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_16_256    p10cr

Invalid Stateful Sig XMSS-SHAKE256_20_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSS-SHAKE256_20_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_256 P10CR Algorithm Parameters
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_256 P10CR Key Size
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSS-SHAKE256_20_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_20_256    nist_approved
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSS-SHAKE256_20_256 Already In Use P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSS-SHAKE256_20_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_20_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 P10CR Request
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSS-SHAKE256_20_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmss    xmss-shake256_20_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmss-shake256_20_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSS-SHAKE256_20_256 P10CR Request
    [Tags]    positive    xmss    xmss-shake256_20_256    certConf
    Build Certificate Confirmation Test    xmss-shake256_20_256    p10cr

Invalid Cert Conf for XMSS-SHAKE256_20_256 P10CR Request With Used Key Index
    [Tags]    negative    xmss    xmss-shake256_20_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmss-shake256_20_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_20/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_20/2_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_20/2_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_20/2_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/2_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_20/2_256    ir

Invalid Cert Conf for XMSSMT-SHA2_20/2_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_20/2_256    ir

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_20/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_20/4_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_20/4_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_20/4_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/4_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_20/4_256    ir

Invalid Cert Conf for XMSSMT-SHA2_20/4_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_20/4_256    ir

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_40/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_40/2_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_40/2_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_40/2_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/2_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_40/2_256    ir

Invalid Cert Conf for XMSSMT-SHA2_40/2_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_40/2_256    ir

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_40/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_40/4_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_40/4_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_40/4_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/4_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_40/4_256    ir

Invalid Cert Conf for XMSSMT-SHA2_40/4_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_40/4_256    ir

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_40/8_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_40/8_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/8_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_40/8_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_40/8_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/8_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_40/8_256    ir

Invalid Cert Conf for XMSSMT-SHA2_40/8_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_40/8_256    ir

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_60/3_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_60/3_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/3_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_60/3_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_60/3_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/3_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_60/3_256    ir

Invalid Cert Conf for XMSSMT-SHA2_60/3_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_60/3_256    ir

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_60/6_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_60/6_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/6_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_60/6_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_60/6_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/6_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_60/6_256    ir

Invalid Cert Conf for XMSSMT-SHA2_60/6_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_60/6_256    ir

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_60/12_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    ir    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 IR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    ir    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 IR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    ir    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_60/12_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/12_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 Already In Use IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    ir    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_60/12_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 IR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 IR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 IR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 IR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    ir    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_60/12_256 IR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/12_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_60/12_256    ir

Invalid Cert Conf for XMSSMT-SHA2_60/12_256 IR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_60/12_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_20/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_20/2_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_20/2_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_20/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_20/4_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_20/4_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_40/2_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_40/2_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_40/2_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_40/4_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_40/4_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_40/4_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_40/8_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_40/8_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_40/8_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_60/3_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_60/3_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_60/3_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_60/6_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_60/6_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_60/6_256    ir

Invalid NIST Disapproved XMSSMT-SHAKE_60/12_256 IR Request
    [Tags]    negative    xmssmt    xmssmt-shake_60/12_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_60/12_256    ir

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_20/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_20/2_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/2_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_20/2_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/2_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/2_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_20/2_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/2_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_20/2_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_20/2_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/2_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_20/2_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_20/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_20/4_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_20/4_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_20/4_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_20/4_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_20/4_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_20/4_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_20/4_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_20/4_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_20/4_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_20/4_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_20/4_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_40/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_40/2_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/2_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/2_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_40/2_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/2_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/2_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_40/2_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/2_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_40/2_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_40/2_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/2_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_40/2_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_40/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_40/4_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/4_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/4_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_40/4_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/4_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/4_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_40/4_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/4_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_40/4_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_40/4_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/4_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_40/4_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_40/8_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_40/8_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/8_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_40/8_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_40/8_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_40/8_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_40/8_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_40/8_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_40/8_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_40/8_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_40/8_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_40/8_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_40/8_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_60/3_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_60/3_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/3_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/3_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_60/3_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/3_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/3_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_60/3_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/3_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_60/3_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_60/3_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/3_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_60/3_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_60/6_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_60/6_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/6_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/6_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${False}    ${False}
    ...    ${True}

Valid PKIProtected XMSSMT-SHA2_60/6_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/6_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/6_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_60/6_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/6_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_60/6_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_60/6_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/6_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_60/6_256    p10cr

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${True}    ${False}    ${False}    ${False}
    ...    ${False}

Exhausted Stateful Sig XMSSMT-SHA2_60/12_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    p10cr    exhausted
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${True}    ${False}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 P10CR Algorithm Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    p10cr    invalid_parameters
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${True}    ${False}
    ...    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 P10CR Key Size
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    p10cr    invalid_key_size
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${False}    ${True}
    ...    ${False}

Valid Stateful Sig XMSSMT-SHA2_60/12_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/12_256    nist_approved
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid Stateful Sig XMSSMT-SHA2_60/12_256 Already In Use P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    p10cr    already_in_use    same_key
    Request For PQ Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid PKIProtected XMSSMT-SHA2_60/12_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    bad_message_check
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${True}    ${False}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 P10CR Request with Invalid Parameters
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    invalid_parameters
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${True}    ${False}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 P10CR Request with Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    exhausted
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${True}
    ...    ${False}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 P10CR Request with Already Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    exhausted
    ...    used_stfl_key_index
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${False}
    ...    ${True}    ${False}

Invalid PKIProtected XMSSMT-SHA2_60/12_256 P10CR Request with POPO Exhausted Key
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    nist_approved    PKIProtection    exhausted
    ...    popo_exhausted_key
    Request With PKIProtected Stateful Sig Key    xmssmt-sha2_60/12_256    p10cr    ${False}    ${False}    ${False}
    ...    ${False}    ${True}

Valid Cert Conf for XMSSMT-SHA2_60/12_256 P10CR Request
    [Tags]    positive    xmssmt    xmssmt-sha2_60/12_256    certConf
    Build Certificate Confirmation Test    xmssmt-sha2_60/12_256    p10cr

Invalid Cert Conf for XMSSMT-SHA2_60/12_256 P10CR Request With Used Key Index
    [Tags]    negative    xmssmt    xmssmt-sha2_60/12_256    certConf    used_stfl_key_index
    Build Certificate Confirmation Used Key Test    xmssmt-sha2_60/12_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_20/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_20/2_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_20/2_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_20/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_20/4_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_20/4_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_40/2_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_40/2_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_40/2_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_40/4_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_40/4_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_40/4_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_40/8_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_40/8_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_40/8_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_60/3_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_60/3_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_60/3_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_60/6_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_60/6_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_60/6_256    p10cr

Invalid NIST Disapproved XMSSMT-SHAKE_60/12_256 P10CR Request
    [Tags]    negative    xmssmt    xmssmt-shake_60/12_256    nist_disapproved
    Request For NIST Disapproved PQ Stateful Sig Key    xmssmt-shake_60/12_256    p10cr
