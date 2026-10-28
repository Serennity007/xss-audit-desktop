# Repeatable scans and review history

These changes are in the development source on `main`. Published v0.3.0 executables do not include them.

## Project configuration

Place `.xss-audit.toml` in the selected project root. Both desktop scans and CLI scans load it automatically. Missing default configuration uses the existing budgets. The repository includes `.xss-audit.example.toml` as a starting point.

```toml
[scan]
include = ["src/**/*.js", "src/**/*.ts", "server/**/*.py"]
exclude = ["src/generated/**", "reports/**"]
max_file_bytes = 1048576
max_total_bytes = 104857600
max_files = 10000
max_matches = 10000
strict = true
```

Patterns use `/` and match from the project root. `*` stays within one path component, and `**` matches zero or more directories. `src/**/*.js` includes both `src/app.js` and nested files. Empty `include` means all supported source formats. Exclusions win over inclusions, and excluding a directory excludes its descendants. Existing dependency/build/link exclusions still apply. Configuration does not execute project files or load custom Python code. Unknown settings, malformed TOML and invalid budgets are errors.

Budgets can be raised up to fixed ceilings: 16 MiB per file, 512 MiB total, 50,000 files and 50,000 matches. Configuration is limited to 64 KiB; each glob is limited to 512 characters and 64 components.

```powershell
python -m xss_audit D:\project --config audit-settings.toml --format json -o audit.json
```

An explicit relative configuration path is resolved against the scanned project root. An explicit missing file is an error. The effective settings are saved with each report and visible in the desktop scope tab.

## Coverage policy

Reports now distinguish `ast_and_patterns`, `patterns_only`, `ast_incomplete`, `read_failed`, `binary_source` and `file_budget`. Intentionally excluded files remain in the skipped list. Languages supported only by pattern search are explicitly labeled and do not by themselves fail the scan.

Strict mode is the default. A supported source file that cannot be read, exceeds the per-file budget, or contains binary/non-UTF-8 content makes the scan incomplete. No readable supported source is also incomplete. The CLI preserves the report and returns 2 for incomplete scans. Existing parse failures, cancellation and total-budget limits remain incomplete. SARIF `executionSuccessful` and report completeness use the same coverage state.

For a deliberate partial-scope workflow, set `strict=false` or pass `--allow-partial`. Coverage failures remain visible in every report and SARIF still records incomplete execution. This opt-out affects the CLI completeness exit policy; `--fail-on-match` still returns 1 for matching results.

Generated JSON and HTML reports carry a format marker and are skipped when scanned again. Legitimate business JSON remains supported, including files named `xss-audit-report.json` without a report marker. Older reports without the marker can be excluded explicitly using project globs.

## Review decisions

Each repeated finding instance has a separate identity. Decisions retain source-file evidence hashes; changes anywhere in that source file conservatively require fresh review. This also invalidates decisions for comment/formatting changes. It does not track dependencies in other files. Returning to an identical previously reviewed source snapshot restores that snapshot's decision.

Saving one snapshot merges its changed decisions with stored records. Records from other snapshots or from a partial scan are retained. Independent desktop windows can save different findings without overwriting unchanged rows from the other window. Clearing a decision clears that evidence version only. The existing 2 MiB state-file limit still applies; saves that exceed it fail without replacing the previous file.

Legacy v1 records are restored only when their old fingerprint is unambiguous in the current scan. They are upgraded with evidence metadata when saved. Ambiguous duplicate legacy matches require fresh review. Until an old record is upgraded, its original nearby-code-only validation boundary still applies.

The desktop status filter supports pending, confirmed, false-positive and fixed decisions. Existing desktop exports still contain the complete scan; category, priority, status and search filters affect the view.

## Additional flow models

HTML evidence includes `srcdoc` and direct `$(...).html(value)` / `jQuery(...).html(value)` setters when the factory is not locally shadowed. Arbitrary objects' `.html()` methods and jQuery `.text()` are not treated as HTML setters. This does not infer arbitrary jQuery aliases, stored receivers or plugin chains.

Python analysis resolves static `import` / `from ... import ...` aliases for modeled calls and visits `with` / `async with` context expressions. Local bindings can shadow known imported calls. JavaScript local declarations and overrides of modeled sanitizer names no longer automatically suppress HTML evidence. The analysis remains bounded and does not establish complete inter-file or interprocedural coverage.
