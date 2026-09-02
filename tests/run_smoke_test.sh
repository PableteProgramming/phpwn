#!/usr/bin/env bash
# Builds PHPwn's release archive and runs it end-to-end against the small
# synthetic vulnerable project in tests/fixtures/vuln_project, from a working
# directory other than PHPwn's own install directory. Asserts the final
# report contains exactly the expected findings.
#
# This is a regression guard for:
#   - PHPwn being invoked from outside its own install directory (subprocess
#     calls used to resolve sibling scripts relative to the caller's cwd)
#   - excludes (e.g. ".phpwn") that don't exist in the target project, which
#     used to make Psalm/PHPStan's config parsers fail outright
#   - `--configure` overwriting an existing, customized phpwn.config.json
#   - the SQLI / XSS / missing-guard detection pipeline itself
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== Building release archive =="
(cd "$REPO_ROOT" && python3 release.py)
INSTALL_DIR="$WORK_DIR/install"
mkdir -p "$INSTALL_DIR"
unzip -q "$REPO_ROOT/PHPwn.zip" -d "$INSTALL_DIR"

echo "== Setting up the target project (a copy of the fixture) =="
PROJECT_DIR="$WORK_DIR/vuln_project"
cp -r "$REPO_ROOT/tests/fixtures/vuln_project" "$PROJECT_DIR"

# Everything below runs from a directory that is neither the PHPwn install
# dir nor the target project dir, to catch any lingering cwd assumptions.
cd "$WORK_DIR"

echo "== Configure (first run: should create the config) =="
python3 "$INSTALL_DIR/PHPwn.py" --configure "$PROJECT_DIR"
test -f "$PROJECT_DIR/phpwn.config.json"

echo "== Configure (second run: must NOT overwrite a customized config) =="
python3 - "$PROJECT_DIR/phpwn.config.json" <<'PYEOF'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["_regression_marker"] = "must-survive-reconfigure"
json.dump(d, open(p, "w"), indent=2)
PYEOF
python3 "$INSTALL_DIR/PHPwn.py" --configure "$PROJECT_DIR"
python3 -c "
import json
d = json.load(open('$PROJECT_DIR/phpwn.config.json'))
assert d.get('_regression_marker') == 'must-survive-reconfigure', 'BUG: --configure overwrote an existing config'
"
python3 -c "
import json
p = '$PROJECT_DIR/phpwn.config.json'
d = json.load(open(p))
del d['_regression_marker']
json.dump(d, open(p, 'w'), indent=2)
"

echo "== First analysis run: variable discovery =="
set +e
python3 "$INSTALL_DIR/PHPwn.py" "$PROJECT_DIR"
code=$?
set -e
if [ "$code" -ne 2 ]; then
    echo "FAIL: expected exit code 2 (variables need classification), got $code"
    exit 1
fi
test -f "$PROJECT_DIR/phpwn.vars.json"

echo "== Classifying discovered variables =="
python3 - "$PROJECT_DIR/phpwn.vars.json" <<'PYEOF'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["request"]["children"]["get"]["taint"] = {"xss": True, "sql": True}
json.dump(d, open(p, "w"), indent=2)
PYEOF

echo "== Second analysis run: full analysis =="
python3 "$INSTALL_DIR/PHPwn.py" "$PROJECT_DIR"

echo "== Verifying the report =="
python3 "$REPO_ROOT/tests/assert_report.py" "$PROJECT_DIR/out/report.json"

echo "ALL CHECKS PASSED"
