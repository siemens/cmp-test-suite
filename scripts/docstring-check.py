# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Look for improperly Capitalized words in the docstrings and comments."""

import ast
import os
import argparse
import re

def load_exceptions(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return {line.strip() for line in file if line.strip()}

def is_camel_case(word):
    # Regular expression to match camelCase words
    # This pattern looks for a lowercase letter followed by one or more uppercase letters and more lowercase letters
    camel_case_re = re.compile(r'^[a-z]+(?:[A-Z][a-z]+)+$')
    return bool(camel_case_re.match(word))

def check_capitalization(line, exceptions):
    words = line.split()
    issues = []

    for word in words:
        # breakpoint()
        if word in exceptions or is_camel_case(word):
            continue
        if word[0].isupper() and not word.isupper():
            issues.append(word)

    return issues

def process_docstring(docstring, exceptions, debug=False):
    results = []
    for line in docstring.splitlines():
        stripped_line = line.lstrip()

        if debug:
            print(f"Analyzing line: {stripped_line}")

        # Skip lines with the pipe symbol
        if '|' in stripped_line:
            if debug:
                print(f"Skipping line due to pipe character: {stripped_line}")
            continue

        if stripped_line.startswith((":param", ":return", ":rtype")):
            parts = stripped_line.split(' ', 1)
            if len(parts) > 1:
                line_to_check = parts[1]
            else:
                continue
        else:
            line_to_check = stripped_line

        issues = check_capitalization(line_to_check, exceptions)
        if issues:
            results.append((line, issues))

    return results

def find_incorrect_capitalization(file_path, exceptions, debug=False):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError as e:
        print(f"SyntaxError while parsing {file_path}: {e}")
        return

    for node in ast.walk(tree):
        # breakpoint()
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
            docstring = ast.get_docstring(node)
            if docstring:
                if debug:
                    print(f"Processing docstring in {file_path}:\n{docstring}\n---")
                results = process_docstring(docstring, exceptions, debug=debug)
                for line, issues in results:
                    print(f"In {file_path}: '{line.strip()}' contains capitalized mid-sentence words: {issues}")

def scan_directory_for_issues(directory, exceptions, debug=False):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                find_incorrect_capitalization(os.path.join(root, file), exceptions, debug=debug)

def main():
    parser = argparse.ArgumentParser(description="Check for unnecessary capitalized words mid-sentence in docstrings.")
    parser.add_argument('directory', nargs='?', default='.', help='Directory to scan (default: current directory)')
    parser.add_argument('--exceptions', default='exceptions.txt', help='Path to exceptions file (default: exceptions.txt)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()

    exceptions = load_exceptions(args.exceptions)
    scan_directory_for_issues(args.directory, exceptions, debug=args.debug)

if __name__ == '__main__':
    main()