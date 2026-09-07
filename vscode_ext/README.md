# PHPwn

PHPwn is a static analysis pipeline for PHP security auditing. It combines **Psalm** (taint analysis for SQL injection and XSS) and **PHPStan** (structural detection of missing access guards) into a unified tool that produces deduplicated, cross-referenced vulnerability reports — right inside VS Code.

Source code and issue tracker: https://github.com/PableteProgramming/phpwn

---

## Requirements

- Python 3.x
- PHP 8.x
- Composer

The extension bundles PHPwn itself and manages its own Python virtual environment automatically — you don't need to install PHPwn separately.

---

## Usage

1. Open your PHP project in VS Code.
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and run **PHPwn: Configure**. This extracts PHPwn, sets up its virtual environment, and creates `phpwn.config.json` in your workspace root — open it and adapt it to your codebase (see [Configuration](#configuration) below).
3. Run **PHPwn: Run Analysis**.
4. On the first run, PHPwn discovers your codebase's global variables and opens the **PHPwn Variables** panel (in the PHPwn activity bar icon) so you can classify each one as an XSS/SQL taint source using the inline buttons. Re-run **PHPwn: Run Analysis** once you're done.
5. Results appear in the **PHPwn Results** panel — expand a finding to see its taint trace, and click any entry to jump straight to that line in your code.

Whenever the extension is updated to a newer bundled PHPwn version, the next **PHPwn: Run Analysis** on an existing project automatically picks it up — no need to delete anything or reconfigure.

---

## Vulnerability Types

| Type | Tool | Description |
|---|---|---|
| `SQLI` | Psalm | Tainted data flows into a SQL query |
| `XSS` | Psalm | Tainted data flows into an HTML output sink |
| `missingAccessControl` | PHPStan + codebaseCheck | Sensitive operation in a publicly reachable file with no auth guard |

---

## Configuration

`phpwn.config.json` is created in your workspace root by **PHPwn: Configure**.

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
| `variablesFile` | JSON file where PHPwn stores discovered global variables for review and categorization. |
| `accessibleFiles.enabled` | Whether reachability filtering is active. When enabled, `missingAccessControl` findings are limited to files reachable by unauthenticated users. |
| `accessibleFiles.directServing` | If `true`, any PHP file directly under the webroot is considered reachable regardless of routing rules. |
| `accessibleFiles.htaccessPath` | Path to the `.htaccess` file used to determine rewrite rules and access restrictions. Relative to `target`. |

---

## Variable Classification

Each discovered global variable can be classified independently for XSS and SQL taint in the **PHPwn Variables** panel:

| State | Meaning |
|---|---|
| XSS / SQL / Both | Tainted for that kind — treated as a source |
| None | Safe — never tainted |
| Unclassified | Not yet reviewed |

Classifying a variable that has children (e.g. array keys of the same global) cascades that classification to all of them, unless you leave the parent unclassified so its children can be set independently.

---

## Commands

| Command | Description |
|---|---|
| `PHPwn: Configure` | Sets up PHPwn and creates `phpwn.config.json` |
| `PHPwn: Run Analysis` | Runs the full analysis pipeline |
| `PHPwn: Load Report` | Reloads the results panel from the last report on disk |

---

## License

MIT — see `LICENSE`.
