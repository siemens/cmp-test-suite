# ADD Copywrite here

"""Define the compare function to compare tags in the suite with baseline of tags."""

from robot.api import TestSuiteBuilder
import os
import sys
from typing import List, Set


def get_suite_tags(suite) -> Set[str]:
    """
    Recursively collect tags from a test suite and its child suites.

    Args:
        suite: Robot Framework test suite object

    Returns:
        Set[str]: Set of unique tags found in the suite
    """
    tags = set()

    # Collect tags from test cases in current suite
    for test in suite.tests:
        tags.update(test.tags)

    # Recursively collect tags from child suites
    for child_suite in suite.suites:
        tags.update(get_suite_tags(child_suite))

    return tags


def collect_tags(folder_path: str) -> Set[str]:
    """
    Collect tags from all .robot files in the specified folder.

    Args:
        folder_path (str): Path to the folder containing .robot files

    Returns:
        Set[str]: Set of unique tags found in all test files
    """
    all_tags = set()

    try:
        # Walk through all files in the directory
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.robot'):
                    file_path = os.path.join(root, file)
                    try:
                        suite = TestSuiteBuilder().build(file_path)
                        suite_tags = get_suite_tags(suite)
                        all_tags.update(suite_tags)
                    except Exception as e:
                        print(f"Error processing file {file_path}: {str(e)}")

        return all_tags

    except Exception as e:
        print(f"Error walking through directory {folder_path}: {str(e)}")
        return set()

def compare_tags_with_file(collected_tags, reference_file_path):
    """
    Compare collected tags with tags in a reference file.

    Args:
        collected_tags (Set[str]): Tags collected from the test suite.
        reference_file_path (str): Path to the file containing reference tags.

    Returns:
        int: 0 if no new tags are found, 1 otherwise.
    """
    try:
        with open(reference_file_path, 'r') as f:
            reference_tags = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Reference file '{reference_file_path}' not found.")
        return 1

    new_tags = collected_tags - reference_tags

    if new_tags:
        print("New tags found:")
        for tag in sorted(new_tags):
            print(f"- {tag}")
        return 1
    else:
        print("No new tags found.")
        return 0


def main():
    """Main function to compare collected tags with a baseline and warn if new ones are found."""
    if len(sys.argv) != 3:
        print("Usage: python get_tags.py <path_to_tests_folder> <baseline_file>")
        sys.exit(1)

    folder_path = sys.argv[1]
    baseline_file = "output_tags.txt"

    if not os.path.exists(folder_path):
        print(f"Error: Input folder '{folder_path}' does not exist")
        sys.exit(1)

    print(f"Collecting tags from: {folder_path}")
    tags = collect_tags(folder_path)

    if not tags:
        print("No tags found in the test suite")
        sys.exit(1)

    # Compare with baseline
    exit_code = compare_tags_with_file(tags, baseline_file)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()