*** Settings ***
Documentation        An example test suite that demonstrates the general principle of using
...                  a library of primitives to construct complex test scenarios
Resource    ../resources/keywords.resource



*** Test Cases ***

CSR must be generated with subjectAltName support
    [Documentation]    Demonstrate how to use some keywords
    ...                just an example
    [Tags]    csr
    ${key}=    Generate keypair    rsa    2048
    ${csr}=    Generate CSR    C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Hans Mustermann        hans.com,www.hans.com
    ${csr_signed}=    Sign CSR    ${csr}    ${key}

    # [Teardown]    to do
