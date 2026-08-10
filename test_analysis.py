#!/usr/bin/env python3
"""Analyze sigil-core test results and generate structured output."""

import re
from collections import defaultdict
from typing import Dict, List, Tuple

def parse_test_results(file_path: str) -> Tuple[Dict, List[str]]:
    """Parse test output file and extract results."""
    passed_tests = []
    failed_tests = []
    ignored_tests = []
    timeout_tests = []

    # Patterns
    test_pattern = r'^test (.+?) \.\.\. (\w+)$'
    timeout_pattern = r'^test (.+?) has been running for over 60 seconds$'

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()

            # Check for timeout
            timeout_match = re.match(timeout_pattern, line)
            if timeout_match:
                test_name = timeout_match.group(1)
                timeout_tests.append(test_name)
                continue

            # Check for normal test result
            test_match = re.match(test_pattern, line)
            if test_match:
                test_name = test_match.group(1)
                status = test_match.group(2)

                if status == 'ok':
                    passed_tests.append(test_name)
                elif status == 'FAILED':
                    failed_tests.append(test_name)
                elif status == 'ignored':
                    ignored_tests.append(test_name)

    return {
        'passed': passed_tests,
        'failed': failed_tests,
        'ignored': ignored_tests,
        'timeout': timeout_tests
    }

def categorize_by_module(tests: List[str]) -> Dict[str, List[str]]:
    """Categorize tests by their module."""
    categories = defaultdict(list)

    for test in tests:
        # Extract module from test name (format: module::submodule::tests::test_name)
        parts = test.split('::')
        if len(parts) >= 3:
            module = parts[0]
            categories[module].append(test)
        else:
            categories['other'].append(test)

    return dict(categories)

def generate_summary(results: Dict) -> str:
    """Generate comprehensive test summary."""
    total = len(results['passed']) + len(results['failed']) + len(results['ignored'])

    summary = f"""
# SIGIL-Core Test Results Analysis

## Summary Statistics
- **Total Tests**: {total}
- **Passed**: {len(results['passed'])} ({len(results['passed'])/total*100:.1f}%)
- **Failed**: {len(results['failed'])} ({len(results['failed'])/total*100:.1f}%)
- **Ignored**: {len(results['ignored'])} ({len(results['ignored'])/total*100:.1f}%)
- **Timeouts**: {len(results['timeout'])}

## Test Success Rate: {(len(results['passed'])/(len(results['passed']) + len(results['failed']))*100):.1f}%

"""

    if results['failed']:
        summary += "## Failed Tests ({})\n\n".format(len(results['failed']))
        failed_by_module = categorize_by_module(results['failed'])
        for module, tests in sorted(failed_by_module.items()):
            summary += f"### {module} ({len(tests)} tests)\n"
            for test in tests:
                summary += f"- `{test}`\n"
            summary += "\n"

    if results['timeout']:
        summary += "## Timeout Tests ({})\n\n".format(len(results['timeout']))
        summary += "The following tests are still running after 60 seconds:\n\n"
        for test in results['timeout']:
            summary += f"- `{test}`\n"
        summary += "\n"

    if results['ignored']:
        summary += "## Ignored Tests ({})\n\n".format(len(results['ignored']))
        summary += "The following tests were marked as ignored:\n\n"
        for test in results['ignored']:
            summary += f"- `{test}`\n"
        summary += "\n"

    summary += "## Module-Level Results\n\n"

    # Get all modules from all tests
    all_tests = results['passed'] + results['failed']
    all_modules = categorize_by_module(all_tests)

    for module in sorted(all_modules.keys()):
        module_tests = all_modules[module]
        module_passed = len([t for t in module_tests if t in results['passed']])
        module_failed = len([t for t in module_tests if t in results['failed']])
        module_total = module_passed + module_failed

        if module_total > 0:
            success_rate = (module_passed / module_total) * 100
            status = "✅" if module_failed == 0 else "⚠️" if module_failed < 5 else "❌"
            summary += f"### {status} {module}: {module_passed}/{module_total} ({success_rate:.1f}%)\n"

    return summary

def main():
    input_file = '/home/coding/SIGIL/sigil-core-test-output.log'
    output_file = '/home/coding/SIGIL/test_results_analysis.md'

    print(f"Analyzing test results from {input_file}...")

    results = parse_test_results(input_file)
    summary = generate_summary(results)

    # Write to file
    with open(output_file, 'w') as f:
        f.write(summary)

    print(f"Analysis complete. Results written to {output_file}")
    print(summary)

    # Print just the key statistics to stdout
    total = len(results['passed']) + len(results['failed']) + len(results['ignored'])
    print(f"\n=== KEY STATISTICS ===")
    print(f"Total Tests: {total}")
    print(f"Passed: {len(results['passed'])} ({len(results['passed'])/total*100:.1f}%)")
    print(f"Failed: {len(results['failed'])} ({len(results['failed'])/total*100:.1f}%)")
    print(f"Ignored: {len(results['ignored'])} ({len(results['ignored'])/total*100:.1f}%)")
    print(f"Timeouts: {len(results['timeout'])}")

if __name__ == '__main__':
    main()