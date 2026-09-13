# Validator diagnostics

Validation errors identify the affected repository-relative file without printing
matched secret values or YAML parser source excerpts. A missing YAML parser or
an unreadable scan input fails validation. A failed secret scan does not print
the clean-scan success message.

Four regression tests in tests/test_validator_diagnostics.py cover these cases.
Run them with python -m pytest tests/test_validator_diagnostics.py.

## CodeQL alert 1 review, 2026-09-13

The reported secret-scanner path calls format_secret_warning with a constant
pattern label and a relative path. It does not pass the match object or file
contents to the logger. A synthetic matching value is detected but absent from
captured stdout and stderr. This supports dismissing that specific path as a
false positive, not suppressing the logging rule.

A separate real exposure was found in YAML exception rendering: the parser can
include source excerpts. Those exception details are now omitted. Missing parser
dependencies and unreadable scan files also fail rather than silently skipping.
Revert this change through a PR if rollback is needed; reopen the alert through
GitHub's security UI if new evidence changes the path assessment.
