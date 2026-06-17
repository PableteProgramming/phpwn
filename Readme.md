# PHPwn

PHPwn is a static analysis pipeline for PHP security auditing. It combines **Psalm** (taint analysis for SQL injection and XSS) and **PHPStan** (structural detection of missing access guards) into a unified tool that produces deduplicated, cross-referenced vulnerability reports.

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

### Command Line

1. Download and extract the PHPwn `.zip` into a directory of your choice, e.g. `.phpwn/` inside your project or anywhere on your machine.
2. Create and activate a virtual environment, then install dependencies:
   ```bash
   cd .phpwn
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

**Variable classification:** if `phpwn.vars.json` does not exist yet, PHPwn will create it automatically on the first run and exit. Open it, review the discovered global variables, set each `"type"` to `"safe"` or `"input"` as appropriate (see [Variable Classification](#variable-classification-phpwnvarsjson) below), then re-run the same command to perform the full analysis. If the file already exists, PHPwn proceeds directly to analysis.

### VS Code Extension

1. Open your PHP project in VS Code.
2. Press `Ctrl+Shift+P` and run **PHPwn: Configure**. This creates `phpwn.config.json` in your workspace root — open it and adapt it to your codebase.
3. Press `Ctrl+Shift+P` and run **PHPwn: Run Analysis**.

The same variable classification step applies: if `phpwn.vars.json` does not exist, it will be created on the first run and you will be prompted to review it before running the analysis again.

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
{ "name": "request", "type": "unknown" }
```

You must review and set the `"type"` for each variable before the full analysis can run:

| Type | Meaning |
|---|---|
| `"input"` | Variable may contain user-controlled data — will be treated as a taint source |
| `"safe"` | Variable is internal/config data — will not be tainted |
| `"unknown"` | Treated the same as `"input"` (conservative default) |

---

## Architecture

```
PHPwn.py          ← entry point, reads phpwn.config.json
  └── wrapper.py  ← orchestrates setup and run, handles vars flow
        ├── setup.py        ← prepares working copy, installs tools, runs preprocess.php
        │     ├── preprocess.php       ← AST traversal: discovers globals, configures psalm.xml and globalVarTainter.php
        │     ├── globalVarTainter.php ← Psalm plugin: injects taint sources for user-input globals
        │     └── defs.php             ← Psalm stubs: mysqli sink annotation, HTMLPurifier escape annotation
        └── run.py          ← runs Psalm, PHPStan, codebaseCheck; feeds results to report.py
              └── report.py ← merges, deduplicates, and formats findings
```

### Psalm (SQLi & XSS)

PHPwn uses Psalm's taint analysis mode. A custom plugin (`globalVarTainter.php`) solves a fundamental limitation in Psalm's global variable handling: Psalm's `GlobalAnalyzer` severs taint chains by overwriting parent nodes on every `global` statement. The plugin hooks into `AfterStatementAnalysisInterface`, creates a `TaintSource` node in the `TaintFlowGraph`, and re-attaches it to the scoped variable — restoring end-to-end taint tracking across global variables.

Custom stubs (`defs.php`) annotate `mysqli::query` as a SQL sink and `HTMLPurifier::purify` as an HTML taint escape, improving accuracy on codebases that use these directly.

### PHPStan (Missing Access Guards)

A custom PHPStan rule (`MissingGuardsDetection`) analyzes each PHP file as a whole using `FileNode`. It performs two passes:

1. **Guard discovery** — finds the earliest line where a known guard function (e.g. `checkAuth`) or a guard include (e.g. `global.php`, `session_handling.php`) is called, recursively resolving user-defined function bodies.
2. **Sensitive operation check** — flags any sensitive call (output, file system, DB, command execution, network) that occurs before the guard line, or when no guard is found at all.

### Reachability Filter (`codebaseCheck.py`)

Parses `.htaccess` to determine which PHP files are reachable by an unauthenticated user. PHPStan findings are then intersected with this set: only files that are both unguarded *and* publicly reachable are reported as `missingAccessControl` vulnerabilities.