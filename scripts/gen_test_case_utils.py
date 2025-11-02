"""Utility to help generate verbose RF test cases."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class TestCase:
    """Representation of a single Robot Framework test case.

    Each instance stores the name and description of the test, together with the
    keywords, arguments and tags required to build the final Robot Framework
    entry.

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

    def __str__(self):
        """Return a string representation of the test case."""
        return f"TestCase(name={self.name}, description={self.description})"

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


def get_body_name_tags(body_name: str) -> List[str]:
    """Get tags based on the body name."""
    if body_name in ["added-protection", "batch"]:
        return ["nested", body_name]
    if body_name.startswith("added-protection-inner-"):
        inner_name = body_name.replace("added-protection-inner-", "")
        return ["nested", "added-protection", inner_name]
    if body_name.startswith("batch_inner"):
        inner_name = body_name.replace("batch_inner_", "")
        return ["nested", "batch", inner_name]
    return [body_name]
