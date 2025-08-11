# SPDX-FileCopyrightText:
#
# TODO: Add copyright information

*** Settings ***
Documentation

Resource
Library
#TODO: Add the necessary libraries and resources


Suite Setup         Initialize Global Variables



***Variables***
#TODO: Define any necessary variables here



*** Test Cases ***
### Signatured-based protection and decentral key generation
### Needed sections of the RFC:
### - 4.1.1

PKI mgmt entity MUST Reject Certificate From Non External Source
    [Documentation]    "The certificate of the EE MUST have been enrolled by an external PKI, e.g., a manufacturer-issued device certificate."
    Input: EE sends certificate from non-external source
    Expected: PKI management entity rejects the certificate
    ...                 Ref.: Section 4.1.1 Enrolling an End Entity to a New PKI
    [Tags]    ir 
    #TODO: Add tags
    

