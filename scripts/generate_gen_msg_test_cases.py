# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Generate test cases for CMP PKIHeader validation."""

import copy
from dataclasses import dataclass, field
from typing import List


@dataclass
class TestCase:
    """Dataclass to represent a test case for CMP PKIHeader validation.

    Attributes:
        name: The name of the test case.
        description: A description of the test case.
        args: Arguments for the test case, each argument is a list of strings.
        tags: Tags associated with the test case.
        functions: Functions associated with the test case.

    """

    name: str
    description: str
    args: List[List[str]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)

    def create_test_case(self) -> str:
        """Create a test case string."""
        indent = " " * 4
        docstring = f"{indent}{self.description}\n"

        if self.description:
            if "\n" not in self.description:
                docstring = "\n" + " " * 5 + f"[Documentation]{indent}{self.description}"
            else:
                init_doc = "\n" + " " * 5 + f"[Documentation]{indent}" + self.description.split("\n")[0]
                for line in self.description.split("\n")[1:]:
                    init_doc += "\n" + " " * 5 + f"...{indent}" + line
                docstring = init_doc

        next_line = "\n" + " " * 5 + f"[Tags]{indent}"
        tags_line = f"{indent}".join(self.tags) + "\n"
        data = f"{self.name}{indent}{docstring}{next_line}{tags_line}"
        for func, args in zip(self.functions, self.args):
            data += " " * 5 + func + f"{indent}"
            args = f"{indent}".join(args)
            data += args

        return data + "\n"


def _get_tags(body_name: str) -> List[str]:
    """Get tags based on the body name."""
    if body_name in ["added-protection", "batch"]:
        return ["nested", body_name]
    if body_name.startswith("added-protection-inner"):
        inner_name = body_name.replace("added-protection-inner", "")
        return ["nested", "added-protection", inner_name]
    if body_name.startswith("batch_inner"):
        inner_name = body_name.replace("batch_inner_", "")
        return ["nested", "batch", inner_name]
    return [body_name]


ALL_BODY_NAMES = [
    "ir",
    "p10cr",
    "cr",
    "kur",
    "genm",
    "ccr",
    "rr",
    "added-protection",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-kur",
    "added-protection-inner-p10cr",
    "added-protection-inner-ccr",
    "batch",
    "batch_inner_ir",
    "batch_inner_cr",
    "batch_inner_kur",
    "batch_inner_p10cr",
    "batch_inner_ccr",
]
MAC_BODY_NAMES = [
    "ir",
    "p10cr",
    "cr",
    "genm",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-p10cr",
    "batch_inner_ir",
    "batch_inner_cr",
    "batch_inner_p10cr",
]


def _generate_sender_nonce_test_cases() -> List[TestCase]:
    """Generate test cases for sender nonce validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Reject {} Without SenderNonce",
            "Build Without senderNonce",
        ),
        ("CA MUST Reject {} With Too Short SenderNonce", "Build With Too Short senderNonce"),
        ("CA MUST Reject {} With Too Long SenderNonce", "Build With Too Long senderNonce"),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "senderNonce"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_recip_nonce_test_cases() -> List[TestCase]:
    """Generate test cases for recipient nonce validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** not have a `recipNonce` set. Ref: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Reject {} With RecipNonce",
            "Build With recipNonce",
        ),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)
            if body_name == "batch":
                # This requires the CA to verify that this is an initial batch message.
                tags += ["strict", "robot:skip-on-failure"]

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "recipNonce"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_transaction_id_test_cases() -> List[TestCase]:
    """Generate test cases for transaction ID validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} Without TransactionID",
            "Build Without transactionID",
        ),
        ("CA MUST Reject {} With Too Short TransactionID", "Build With Too Short transactionID"),
        ("CA MUST Reject {} With Too Long TransactionID", "Build With Too Long transactionID"),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "transactionID"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_message_time_test_cases() -> List[TestCase]:
    """Generate test cases for message time validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.\nRef: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Reject {} Without MessageTime",
            "Build Without messageTime",
        ),
        ("CA MUST Reject {} With MessageTime In Future", "Build With MessageTime In Future"),
        ("CA MUST Reject {} With MessageTime In Past", "Build With MessageTime In Past"),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "messageTime"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_mac_in_konsistent_test_cases() -> List[TestCase]:
    """Generate test cases for inconsistent MAC message validation."""
    body_names = MAC_BODY_NAMES
    test_cases = []
    description = (
        "A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.\n"
        "Ref: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With MAC Algorithm without Protection",
            "Build With MAC Alg Without Protection",
        ),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "inconsistent", "protection", "mac"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_in_konsistent_test_cases() -> List[TestCase]:
    """Generate test cases for inconsistent message validation."""
    body_names = copy.copy(ALL_BODY_NAMES)
    test_cases = []
    description = (
        "A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.\n"
        "Ref: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With Protection without Algorithm",
            "Build With Protection Without Alg",
        ),
        ("CA MUST Reject {} With Sig Algorithm without Protection", "Build With Sig Alg Without Protection"),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            tag = ["protection", "sig"] if "Sig" in func else ["protection"]

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "inconsistent"] + tag + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_sig_protected_test_cases() -> List[TestCase]:
    """Generate test cases for signature protected validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A PKIMessage **MUST** contain the complete cert chain and be valid protected.\nRef: RFC 9483, Section 3.1."
    )
    for case, func, add_tags in [
        ("CA MUST Reject {} With Invalid Sig Protection", "Build With Bad Sig Protection", []),
        (
            "CA MUST Reject {} Without extraCerts",
            "Build Without extraCerts",
            ["extraCerts"],
        ),
        ("CA MUST Reject {} Without Cert Chain", "Build Without Cert Chain", ["extraCerts"]),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "sig", "protection"] + tags + add_tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_neg_validate_header_test_cases() -> List[TestCase]:
    """Generate test cases for validating the CMP PKIHeader."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a valid `PKIHeader`.\nRef: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Return For NEG {} A Valid PKIHeader",
            "Build Message For Negative Header Validation",
        ),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "PKIHeader"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_pos_validate_header_test_cases() -> List[TestCase]:
    """Generate test cases for validating the CMP PKIHeader."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a valid `PKIHeader`.\nRef: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Return For POS {} A Valid PKIHeader",
            "Build Message For Positive Header Validation",
        ),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["positive", "PKIHeader"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_sig_sender_kid_test_cases() -> List[TestCase]:
    """Generate test cases for signature sender and senderKID validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A signature protected PKIMessage **MUST** have the senderKID set "
        "the SKI of the protection cert, if present."
        "\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        ("CA MUST Reject {} With Invalid SKI SenderKID", "Build With Bad Sig SenderKID"),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "sig", "senderKID"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_sig_sender_test_cases() -> List[TestCase]:
    """Generate test cases for signature sender validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A signature protected PKIMessage **MUST** have the"
        " `sender` field set to the `subject`.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With Invalid Sig Sender",
            "Build With Bad Sig Sender",
        ),
        ("CA MUST Reject {} With Issuer As Sender", "Build With Bad Issuer As Sender"),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "sig", "sender"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_mac_sender_test_cases() -> List[TestCase]:
    """Generate test cases for MAC sender validation."""
    body_names = MAC_BODY_NAMES
    test_cases = []
    description = (
        "A MAC protected PKIMessage **MUST** have the `sender` "
        "field set to the `directoryName` choice.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With Invalid MAC Sender",
            "Build With Bad MAC Sender Choice",
        ),
        ("CA MUST Reject {} Which is Invalid Protected", "Build Bad MAC Protected Message"),
        ("CA MUST Reject {} With Bad MAC SenderKID", "Build With Bad MAC SenderKID"),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)

            tag = "sender" if "SenderKID" not in func else "senderKID"

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "mac", tag] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_mac_wrong_integrity_test_cases() -> List[TestCase]:
    """Generate test cases for MAC sender validation."""
    body_names = [
        "added-protection",
        "batch",
        "batch_inner_ccr",
        "batch_inner_kur",
        "added-protection-inner-kur",
        "added-protection-inner-ccr",
        "ccr",
        "kur",
        "rr",
    ]

    test_cases = []
    description = (
        "A MAC protected PKIMessage is not allowed for a `rr` "
        "or `kur`,`ccr` and `nested` messages.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} Which Is MAC Protected",
            "Build Not Allowed MAC-Protected Message",
        ),
    ]:
        for body_name in body_names:
            tags = _get_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "mac"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def generate_test_case() -> List[str]:
    """Generate all test cases for the CMP `PKIHeader` validation."""
    out = _generate_sender_nonce_test_cases()
    out += _generate_recip_nonce_test_cases()
    out += _generate_transaction_id_test_cases()
    out += _generate_message_time_test_cases()
    out += _generate_sig_protected_test_cases()
    out += _generate_in_konsistent_test_cases()
    out += _generate_mac_in_konsistent_test_cases()
    out += _generate_sig_sender_test_cases()
    out += _generate_sig_sender_kid_test_cases()
    out += _generate_mac_sender_test_cases()
    out += _generate_mac_wrong_integrity_test_cases()
    out += _generate_neg_validate_header_test_cases()
    out += _generate_pos_validate_header_test_cases()
    return [case.create_test_case() for case in out]


if __name__ == "__main__":
    # Generate test cases and write them to a file
    test_cases = generate_test_case()
    with open("./pki_header_verbose_tests.txt", "w") as f:
        for test_case in test_cases:
            f.write(test_case + "\n")
