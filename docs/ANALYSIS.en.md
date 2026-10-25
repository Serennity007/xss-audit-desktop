# Analysis and evidence boundaries

This tool assists human source review. It does not establish verified vulnerabilities, promise detection rates or equate review priority with severity.

## Limited AST flow analysis

JavaScript/JSX use Tree-sitter JavaScript, TypeScript/TSX use the corresponding grammars, and Python uses the standard-library AST.

Selected browser, messaging, request and storage sources propagate through identifiers, string composition and conservative unknown-call argument handling. Recognized destinations include HTML writes, navigation and dynamic execution. Python also covers selected SQL construction, `shell=True`/shell APIs, paths used for I/O, HTTP clients, deserialization and template interfaces.

Constant reassignment clears a variable's flow. Function parameters shadow outer names; branches merge conservatively and loops are analyzed finitely. SQL parameter values alone do not constitute query-string construction. A `shell=False` argument array is not treated as shell-string execution.

Known HTML sanitizer calls reduce HTML-flow priority, while sanitizer/output pattern signals remain for review. This does not verify effective sanitizer configuration or establish URL-context safety.

Evidence records the source line, a bounded number of assignment steps and the final call/write. Per-file AST evidence is capped at 1,000 findings; depth/node budgets, parse errors and missing dependencies are reported. Source alternatives and propagation histories are also bounded.

## Incomplete modeling

There is no complete inter-file/interprocedural analysis, import-alias resolution, dynamic-property resolution, object-field-sensitive analysis, precise control-flow graph or runtime type inference. Closures, asynchronous timing, framework lifecycles and custom wrappers are not fully modeled. Common names and syntax identify sources/calls; unrelated objects with those names can produce false positives. Unknown-call propagation can be overly conservative.

Vue, Svelte, Astro and MDX currently use pattern search without extracting script blocks for AST parsing. Python syntax support depends on the runtime version. Parse failure is not treated as proof of safety.

## Credential masking

Selected token prefixes and quoted sensitive assignments such as `api_key` / `password` are recognized, with some explicit placeholders excluded. Recognized values become `[REDACTED]` in display/export and AI source payloads. Keys are not validated, revoked or rotated. Masking cannot identify every secret; `.env`, binary and excluded/minified files are outside this scan's supported scope.

## References

- [Tree-sitter Python bindings](https://github.com/tree-sitter/py-tree-sitter)
- [GitHub ZIP archive API](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-zip)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)

`examples/demo-project/` is synthetic training data, not a real vulnerability report or a model-quality benchmark.
