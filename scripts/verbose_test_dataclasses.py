# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Abstract base classes for test cases in Robot Framework format.

Defines different abstract classes for creating test cases, including handling function calls,
arguments, and tags. The classes are designed to be extended for specific test case implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple, Union

NEXT_LINE_INDENT = " " * 5
ARGUMENT_INDENT = " " * 4
INDENT = " " * 4

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

ALL_REQUEST_BODY_NAMES = [
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


def get_body_name_tags(body_name: str) -> List[str]:
    """Return tags based on the body name."""
    if body_name in ["added-protection", "batch"]:
        return ["nested", body_name]
    if body_name.startswith("added-protection-inner-"):
        inner = body_name.replace("added-protection-inner-", "")
        return ["nested", "added-protection", inner]
    if body_name.startswith("batch-inner-"):
        inner = body_name.replace("batch-inner-", "")
        return ["nested", "batch", inner]
    return [body_name]


class AbstractTestCase(ABC):
    """Abstract base class for test cases."""

    args_as_kwargs: bool = False  # New field to indicate if args should be treated as kwargs
    name: str
    tags: List[str]

    @abstractmethod
    def create_test_case(self) -> str:
        """Create a test case in Robot Framework format."""

    @staticmethod
    def _create_next_line() -> str:
        """Create the next line prefix for a wrapped argument line."""
        return NEXT_LINE_INDENT + "..." + ARGUMENT_INDENT

    def _get_function(self, function: Tuple[str, Dict[str, str]]) -> str:
        """Return the formatted function call string with arguments, wrapped if needed."""
        function_name, params_list = function
        indent = ARGUMENT_INDENT
        first_indent = NEXT_LINE_INDENT

        if self.args_as_kwargs:
            param_strs = [f"{k}={v}" for k, v in params_list.items()]
        else:
            param_strs = list(params_list.values())

        full_line = f"{first_indent}{function_name}{indent}"
        current_line = full_line
        lines = []

        for i, param in enumerate(param_strs):
            if len(current_line) + len(param) + len(indent) <= 120:
                current_line += param + indent
            else:
                lines.append(current_line.rstrip())
                current_line = self._create_next_line() + param + indent

        lines.append(current_line.rstrip())
        return "\n".join(lines)

    @abstractmethod
    def get_args(self) -> str:
        """Return the arguments for the test case in Robot Framework format."""

    def get_tags(self) -> str:
        """Return the tags for the test case in Robot Framework format, wrapped to 120 chars."""
        if not hasattr(self, "tags") or not isinstance(self.tags, Sequence):
            raise ValueError("Test case must have a 'tags' attribute of type `Sequence`.")

        lines = []
        current_line = f"{NEXT_LINE_INDENT}[Tags]{INDENT}"

        for tag in self.tags:
            # +INDENT for the space that would be added after the tag
            if len(current_line) + len(tag) + len(INDENT) <= 120:
                current_line += tag + INDENT
            else:
                lines.append(current_line.rstrip())
                current_line = NEXT_LINE_INDENT + "..." + INDENT + tag + INDENT

        lines.append(current_line.rstrip())
        return "\n".join(lines)

    @staticmethod
    def _convert_value_to_robot(value: Union[str, None, bool]) -> str:
        """Convert a value to its Robot Framework representation."""
        if value is None:
            return "${None}"
        elif isinstance(value, bool):
            return "${True}" if value else "${False}"
        else:
            return value


class AbstractSingleTestCase(AbstractTestCase):
    """Abstract base class for single function called in the test case."""

    function: List[Tuple[str, Dict[str, str]]]

    @abstractmethod
    def generate_test_case(self) -> str:
        """Generate the test case in Robot Framework format."""

    def create_test_case(self) -> str:
        """Create a test case string."""
        data = self.name + "\n"
        data += self.get_tags() + "\n"
        param_str = ""
        for keyword, param_dicts in self.function:
            param_str += self._get_function((keyword, param_dicts)) + "\n"
        return data + param_str
