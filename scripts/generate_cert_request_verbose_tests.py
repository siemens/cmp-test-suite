"""Create Robot Framework test cases for certificate template and CSR validation.

This script programmatically builds a list of verbose test cases used to verify
certificate request handling as defined in RFC 9483.  It covers proof of
possession requirements, NULL distinguished names, implicit confirmation flags,
certificate request identifiers, CSR version numbers, and key reuse across
batch requests.
Running this module writes the cases to:
``cert_template_verbose_tests.txt``.
"""

from typing import List

from scripts.gen_test_case_utils import TestCase, get_body_name_tags

MAC_BODY_NAMES = [
    "ir",
    "cr",
    "p10cr",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-p10cr",
    "batch-inner-ir",
    "batch-inner-cr",
    "batch-inner-p10cr",
]
ALL_BODY_NAMES = [
    "ir",
    "cr",
    "kur",
    "p10cr",
    "ccr",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-kur",
    "added-protection-inner-p10cr",
    "added-protection-inner-ccr",
    "batch-inner-ir",
    "batch-inner-cr",
    "batch-inner-kur",
    "batch-inner-p10cr",
    "batch-inner-ccr",
]


def _generate_bad_pop_cert_template():
    """Generate a certificate template with a bad proof of possession (PoP)."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A certificate request **MUST** have a valid "
        "Proof-of-Possession to verify the possession of the private key.\nRef: RFC 9483, Section 4."
    )
    for case, func in [
        (
            "CA MUST Reject {} With BadPOP",
            "Build BadPOP Request",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "badPOP"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)

    return test_cases


def _generate_null_dn_and_no_san_cert_template():
    """Generate a certificate template with a null DN and no Subject Alternative Name (SAN)."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A certificate request **MUST** have subject alternative "
        "name (SAN) set, if the subject field is set to the NULL-DN.\nRef: RFC 9483, Section 4."
    )
    for case, func in [
        (
            "CA MUST Reject {} With Null-DN And No SAN",
            "Build Null-DN And No SAN Request",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "NULL-DN", "san"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)

    return test_cases


def _generate_implicit_confirm_sig_test() -> List[TestCase]:
    """Generate a test case for implicit confirmation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A certificate request **MUST** have an implicit confirmation "
        "if the request is not a confirmation request.\nRef: RFC 9483, Section 4."
    )
    for case, func, flag in [
        (
            "CA MUST Accept {} With Implicit Confirmation",
            "Build ImplicitConfirm Request",
            "True",
        ),
        (
            "CA MUST Accept {} Without Implicit Confirmation",
            "Build ImplicitConfirm Request",
            "False",
        ),
    ]:
        for body_name in body_names:
            if "batch" in body_name:
                continue

            if "ccr" in body_names and flag == "True":
                continue

            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name, flag]],
                description=description,
                tags=["positive", "implicit_confirm", "for_mac=False"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)

    return test_cases


def _generate_implicit_confirm_mac_test() -> List[TestCase]:
    """Generate a test case for implicit confirmation with MAC."""
    body_names = MAC_BODY_NAMES
    test_cases = []
    description = (
        "A certificate request **MUST** have an implicit confirmation if the "
        "request is not a confirmation request.\nRef: RFC 9483, Section 4."
    )
    for case, func, flag in [
        (
            "CA MUST Accept MAC {} With Implicit Confirmation",
            "Build ImplicitConfirm Request",
            "True",
        ),
        (
            "CA MUST Accept MAC {} Without Implicit Confirmation",
            "Build ImplicitConfirm Request",
            "False",
        ),
    ]:
        for body_name in body_names:
            if "batch" in body_name:
                continue

            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name, flag, "for_mac=True"]],
                description=description,
                tags=["positive", "implicit_confirm_mac"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)

    return test_cases


def _generate_bad_cert_req_id():
    """Generate a test case for a bad certificate request ID."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A certificate request **MUST** have the request ID set to `0`.\nRef: RFC 9483, Section 4."
    for case, func, arg in [
        (
            "CA MUST Reject {} With CertReqID Set To -1",
            "Build Bad Request ID Request",
            "-1",
        ),
        (
            "CA MUST Reject {} With CertReqID Set To 1",
            "Build Bad Request ID Request",
            "1",
        ),
    ]:
        for body_name in body_names:
            if "p10cr" in body_name:
                continue

            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name, arg]],
                description=description,
                tags=["negative", "certReqID"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)

    return test_cases


def _generate_bad_csr_version_test():
    """Generate a test case for a bad CSR version."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A certificate request **MUST** have the CSR version set to `0`.\nRef: RFC 9483, Section 4."
    for case, func, arg in [
        (
            "CA MUST Reject {} With CSR Version Set To -1",
            "Build Bad CSR Version Request",
            "-1",
        ),
        (
            "CA MUST Reject {} With CSR Version Set To 1",
            "Build Bad CSR Version Request",
            "1",
        ),
    ]:
        for body_name in body_names:
            if "p10cr" not in body_name:
                continue

            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name, arg]],
                description=description,
                tags=["negative", "csr_version"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)

    return test_cases


def _generate_same_key_cert_template_tests():
    """Generate test cases for certificate templates with the same key."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A certificate request **MUST** have the same key for all requests in a batch.\nRef: RFC 9483, Section 4."
    )
    for case, func in [
        (
            "CA MUST Accept {} With Same Key",
            "Build Same Key Request",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["positive", "same_key"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)

    return test_cases


def generate_cert_template_or_csr_verbose_tests():
    """Generate verbose test cases for certificate template generation."""
    test_cases = []

    # Generate bad PoP certificate template tests
    test_cases.extend(_generate_bad_cert_req_id())
    test_cases.extend(_generate_bad_csr_version_test())
    test_cases.extend(_generate_bad_pop_cert_template())
    test_cases.extend(_generate_null_dn_and_no_san_cert_template())
    test_cases.extend(_generate_same_key_cert_template_tests())
    # Add more test cases as needed.
    return test_cases


if __name__ == "__main__":
    # Generate the test cases
    test_cases = _generate_implicit_confirm_sig_test()
    test_cases.extend(_generate_implicit_confirm_mac_test())
    test_cases.extend(generate_cert_template_or_csr_verbose_tests())
    # Print the test cases
    cases = [case.create_test_case() for case in test_cases]
    with open("../cert_template_verbose_tests.txt", "w") as f:
        f.write("\n".join(cases))
