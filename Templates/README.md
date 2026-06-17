# PHPwn Configuration Reference

The `phpwn.config.json` file must be placed at the workspace root. It controls how PHPwn discovers, analyzes, and reports on your PHP codebase.

---

## Fields

**`target`**
Path to the PHP codebase to analyze, relative to this file. Use `"."` to analyze the entire workspace root.

**`outputDir`**
Directory where all output files will be written.

**`outputJson`**
Filename for the full JSON report, written inside `outputDir`.

**`outputCsv`**
Filename for the CSV report, written inside `outputDir`.

**`excludes`**
List of directories to skip during analysis. Typically used to exclude third-party vendor code and PHPwn's own working directory.

**`variablesFile`**
JSON file where PHPwn stores discovered taint-source variables for user review and categorization.

**`accessibleFiles`**
Controls which PHP files are considered reachable by an unauthenticated attacker. Used to filter findings by exposure.

| Field | Description |
|---|---|
| `enabled` | Whether reachability filtering is active. |
| `directServing` | If `true`, any PHP file directly under the webroot is considered reachable regardless of routing rules. |
| `htaccessPath` | Path to the `.htaccess` file used to determine rewrite rules and access restrictions. Relative to `target`. |

---

## Example

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