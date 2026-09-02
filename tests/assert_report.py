#!/usr/bin/env python3
"""Asserts a PHPwn report.json matches the expected findings for
tests/fixtures/vuln_project (see run_smoke_test.sh)."""
import json
import sys


def main():
    if len(sys.argv) != 2:
        print("usage: assert_report.py <report.json>")
        return 1

    with open(sys.argv[1]) as f:
        report = json.load(f)

    by_type = {entry["name"]: entry for entry in report}
    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    expect("SQLI" in by_type, "no SQLI finding in report")
    expect("XSS" in by_type, "no XSS finding in report")
    expect("missingAccessControl" in by_type, "no missingAccessControl finding in report")

    if "SQLI" in by_type:
        files = {f["name"] for v in by_type["SQLI"]["children"] for f in v["children"]}
        expect("sqli.php" in files, f"SQLI finding missing for sqli.php, got {files}")

    if "XSS" in by_type:
        files = {f["name"] for v in by_type["XSS"]["children"] for f in v["children"]}
        expect("xss.php" in files, f"XSS finding missing for xss.php, got {files}")

    if "missingAccessControl" in by_type:
        flagged = set(by_type["missingAccessControl"]["children"])
        for expected in ("unguarded.php", "xss.php", "sqli.php"):
            expect(expected in flagged, f"missingAccessControl missing expected file {expected!r}, got {flagged}")
        for safe in ("guarded_by_function.php", "guarded_by_include.php"):
            expect(safe not in flagged, f"missingAccessControl incorrectly flagged guarded file {safe!r}")

    if failures:
        print("REPORT ASSERTIONS FAILED:")
        for f in failures:
            print(f" - {f}")
        return 1

    print("Report assertions passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
