# PHPwn

PHPwn is a static analysis pipeline for PHP security auditing. It combines **Psalm** (taint analysis for SQL injection and XSS) and **PHPStan** (structural detection of missing access guards) into a unified tool that produces deduplicated, cross-referenced vulnerability reports.

Source code, issue tracker, and the VS Code extension: https://github.com/PableteProgramming/phpwn

---

## How It Works

PHPwn runs in three stages:

1. **Setup** — copies the target codebase into a working directory, installs Psalm and PHPStan via Composer, configures them for the target, and runs a preprocessing step to identify and classify global variables as taint sources or safe.
2. **Analysis** — runs Psalm taint analysis, PHPStan custom rules, and (optionally) an `.htaccess` reachability check.
3. **Reporting** — merges and deduplicates all findings into JSON and CSV reports.

---

## Requirements

- Python 3.x
- PHP 8.x
- Composer
- `lxml` Python package (`pip install -r requirements.txt`)

---

## Installation & Usage

1. Extract this archive into a directory of your choice, e.g. `.phpwn/` inside your project or anywhere on your machine.
2. Create and activate a virtual environment, then install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Run the configure command, pointing it at your PHP project root:
   ```bash
   python3 PHPwn.py --configure "/path/to/your/project"
   ```
   This automatically creates `phpwn.config.json` in your project root. Open it and adapt the configuration to your codebase (see [Configuration](#configuration) below).
4. Run the analysis:
   ```bash
   python3 PHPwn.py "/path/to/your/project"
   ```

**Variable classification:** if `phpwn.vars.json` does not exist yet, PHPwn will create it automatically on the first run and exit. Open it, review the discovered global variables, set each variable's `taint.xss` and `taint.sql` as appropriate (see [Variable Classification](#variable-classification-phpwnvarsjson) below), then re-run the same command to perform the full analysis. If the file already exists, PHPwn proceeds directly to analysis.

A VS Code extension that wraps this same workflow (Command Palette: **PHPwn: Configure** / **PHPwn: Run Analysis**) is also available — see the [GitHub repository](https://github.com/PableteProgramming/phpwn) for installation instructions.

---

## Output

After a successful run, the `outputDir` will contain:

| File | Description |
|---|---|
| `report.json` | Full findings in JSON format |
| `report.csv` | Full findings in CSV format |

Each finding includes the vulnerability type, file, line number, code snippet, taint source variable, and full taint trace.

---

## Vulnerability Types

| Type | Tool | Description |
|---|---|---|
| `SQLI` | Psalm | Tainted data flows into a SQL query |
| `XSS` | Psalm | Tainted data flows into an HTML output sink |
| `missingAccessControl` | PHPStan + codebaseCheck | Sensitive operation in a publicly reachable file with no auth guard |

---

## Configuration

`phpwn.config.json` must be placed at the root of the project to analyze.

```json
{
  "target": ".",
  "outputDir": "out/",
  "outputJson": "report.json",
  "outputCsv": "report.csv",
  "excludes": ["vendor", ".phpwn"],
  "variablesFile": "phpwn.vars.json",
  "accessibleFiles": {
    "enabled": true,
    "directServing": true,
    "htaccessPath": ".htaccess"
  }
}
```

| Field | Description |
|---|---|
| `target` | Path to the PHP codebase to analyze, relative to this file. Use `"."` for the entire workspace root. |
| `outputDir` | Directory where all output files will be written. |
| `outputJson` | Filename for the JSON report, written inside `outputDir`. |
| `outputCsv` | Filename for the CSV report, written inside `outputDir`. |
| `excludes` | Directories to skip during analysis. Typically vendor code and PHPwn's own working directory. |
| `variablesFile` | JSON file where PHPwn stores discovered global variables for user review and categorization. |
| `accessibleFiles.enabled` | Whether reachability filtering is active. When enabled, `missingAccessControl` findings are limited to files reachable by unauthenticated users. |
| `accessibleFiles.directServing` | If `true`, any PHP file directly under the webroot is considered reachable regardless of routing rules. |
| `accessibleFiles.htaccessPath` | Path to the `.htaccess` file used to determine rewrite rules and access restrictions. Relative to `target`. |

---

## Variable Classification (`phpwn.vars.json`)

On first run, PHPwn discovers all PHP global variables in the codebase via AST traversal and saves them to `variablesFile`. Each entry looks like:

```json
{
  "name": "request",
  "taint": { "xss": null, "sql": null },
  "children": {
    "post": { "name": "request.post", "taint": { "xss": false, "sql": true }, "children": {} }
  }
}
```

You must review and set `taint.xss` and `taint.sql` for each variable before the full analysis can run:

| Value | Meaning |
|---|---|
| `true` | Variable is tainted for that Taint Kind — will be treated as a taint source |
| `false` | Variable is safe for that Taint Kind — will not be tainted |
| `null` | Not yet classified |

`xss` and `sql` are classified independently, so a variable can be a source for one and safe for the other. `children` lets array keys of the same global (e.g. `request.post` vs. `request.db`) be classified independently too — but only if the parent itself is left `null`; setting a parent's `taint` to a non-null value cascades that classification down to all of its children, overwriting any of their individual settings.

---

## License

PHPwn is released under the MIT License — see `LICENSE` in this archive for the full text.
