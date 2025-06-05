# ADD Copywrite here

"""Define the get_tags function to retrieve tags. Script to collect all tags from Robot Framework test cases in a test suite."""

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


def write_tags_to_file(tags: Set[str], output_file: str) -> bool:
    """
    Write collected tags to the output file.
    
    Args:
        tags (Set[str]): Set of tags to write
        output_file (str): Path to the output file
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Write sorted tags to file
        with open(output_file, 'w') as f:
            f.write('\n'.join(sorted(tags)))
        return True
    
    except Exception as e:
        print(f"Error writing to output file {output_file}: {str(e)}")
        return False


def main():
    """Main function to run the tag collection process."""
    if len(sys.argv) != 3:
        print("Usage: python get_tags.py <path_to_tests_folder> <output_file>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(folder_path):
        print(f"Error: Input folder '{folder_path}' does not exist")
        sys.exit(1)
    
    print(f"Collecting tags from: {folder_path}")
    tags = collect_tags(folder_path)
    
    if tags:
        if write_tags_to_file(tags, output_file):
            print(f"Successfully wrote {len(tags)} tags to: {output_file}")
        else:
            print("Failed to write tags to output file")
            sys.exit(1)
    else:
        print("No tags found in the test suite")
        sys.exit(1)


if __name__ == "__main__":
    main()