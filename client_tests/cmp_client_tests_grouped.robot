*** Settings ***
Documentation       Modular client-side CMP tests using OpenSSL inline parameters.
Library             Process
Library             Collections
Library             OperatingSystem
Library             String

Suite Setup         Ensure Environment Clean

*** Variables ***
${CMP_URL}          http://127.0.0.1:5000/issuing
${CMP_KEY}          certs/client_key.pem
${CMP_SECRET}       pass:SiemensIT
${CMP_MAC}          hmac-sha1
${CMP_RECIPIENT}    /CN=Mock CA
${REQ_OUT}          certs/req1.der
${RSP_OUT}          certs/rsp1.der
${CERT_OUT}         certs/received_cert.pem

*** Keywords ***
Ensure Environment Clean
    Remove File    ${REQ_OUT}
    Remove File    ${RSP_OUT}
    Remove File    ${CERT_OUT}

Run CMP Inline Request
    [Arguments]    ${cmd}    ${subject}    ${ref}    @{opts}
    ${should_fail}=    Set Variable    False
    ${must_contain}=    Create List
    ${extra_args}=      Create List
    
    FOR    ${opt}    IN    @{opts}
        Run Keyword If    'ERR::' in '${opt}'    Append To List    ${must_contain}    ${opt.replace('ERR::', '')}
        ...    ELSE IF    '${opt}' == 'FAIL'    
        ...       Set Test Variable    ${should_fail}    True
        ...    ELSE                                Append To List    ${extra_args}    ${opt}
    END

    ${args}=    Create List
    ...    cmp
    ...    -cmd    ${cmd}
    ...    -server    ${CMP_URL}
    ...    -ref    ${ref}
    ...    -subject    ${subject}
    ...    -mac    ${CMP_MAC}
    ...    -secret    ${CMP_SECRET}
    ...    -recipient    ${CMP_RECIPIENT}
    ...    -reqout    ${REQ_OUT}
    ...    -rspout    ${RSP_OUT}
    ...    -certout    ${CERT_OUT}
    Append To List    ${args}    @{extra_args}
    Log    CMD: ${cmd}
    Log    SUBJECT: ${subject}
    Log    REF: ${ref}
    Log    SHOULD_FAIL: ${should_fail}
    Log    EXTRA_ARGS: ${extra_args}
    Log    MUST_CONTAIN: ${must_contain}
    Log    FINAL OPENSSL ARGS: ${args}
    



    Run Process    openssl    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    Log    ${output.stdout}
    ${output_lower}=    Convert To Lowercase    ${output.stdout}

    Run Keyword If    '${should_fail}' == 'False'    Should Not Contain    ${output_lower}    cmp error
    Run Keyword If    "${should_fail}" == "True" and len(${must_contain}) > 0    Should Contain Any    ${output_lower}    ${must_contain}


Should Contain Any
    [Arguments]    ${text}    ${expected_words}
    Log    expected_words: ${expected_words}
    FOR    ${word}    IN    @{expected_words}
        Log    Checking if output contains: ${word}
        Log    message: ${text}
        Run Keyword And Return If    "${text.replace('\n','')}".find("${word}") != -1    No Operation
    END
    Fail    Output did not contain any of: ${expected_words}




*** Test Cases ***

# === IR Tests ===
IR 01 - Valid IR CMP Request Should Pass
    [Tags]    ir    valid    positive
    Run CMP Inline Request    ir    /CN=IR-Client-1    IR-Client-1     -newkey    ${CMP_KEY}


IR 02 - IR Request With Wrong Secret Should Fail
    [Tags]    ir    negative    secret
    Run CMP Inline Request
    ...    ir
    ...    /CN=IR-Client-2
    ...    IR-Client-2
    ...    -secret    pass:WrongPassword
    ...    FAIL
    ...    ERR::error
    ...    ERR::secret

# === P10CR Tests ===
P10CR 01 - P10CR Unprotected Request Should Fail
    [Tags]    p10cr    negative    unprotected
    Run CMP Inline Request
    ...    p10cr
    ...    /CN=P10CR-Client-1
    ...    P10CR-Client-1
    ...    -csr    certs/csr.pem
    ...    -unprotected_requests
    ...    FAIL
    ...    ERR::error
    ...    ERR::protection

P10CR 02 - P10CR With Missing CSR Should Fail
    [Tags]    p10cr    negative    malformed
    Run CMP Inline Request
    ...    p10cr
    ...    /CN=P10CR-Client-2
    ...    P10CR-Client-2
    ...    FAIL
    ...    ERR::missing
    ...    ERR::csr

P10CR 03 - Valid P10CR With CSR Should Pass
    [Tags]    p10cr    positive   validation
    Run CMP Inline Request
    ...    p10cr
    ...    /CN=P10CR-Client-3
    ...    -csr    certs/csr_p10cr-client-3.pem
