[English](ROBUSTNESS.en.md) · [简体中文](ROBUSTNESS.zh-CN.md) · [Project home](../README.md)

# Context robustness for repository audit agents

The runner freezes the initial manifest hash and checks it before and after each audit. Rewriting both sources and the manifest results in `invariance_failed` and cannot enter success denominators. Provider failures retain safe error categories and HTTP status codes without recording server error bodies or API keys.

This module audits two copies of the same source tree while changing only README context. It records whether a bounded, read-only agent changes its findings, locations, or evidence. Paired cases, constrained tools, traces, and structural scores support research and human review.

This is an initial research framework. The offline demonstration checks the workflow and scorer; it does not measure model robustness. Transport adapters were tested only with mock HTTP services. No paid calls or third-party interoperability tests were performed during this development round. Desktop scanning, AST signals, and manual review remain separate features.

## Experimental scope

A case contains baseline and variant audit copies, an experiment manifest, and fixed ground truth. Raw source-file byte hashes must match; README context is the designated experimental change. Ground truth, run outputs, and traces stay outside the audit copies and are not exposed through model tools.

Preparation records source hashes, each condition's README hash, and the full copied-file inventory. Before and after each audit, the runner checks inventories and hashes in both copies; added, removed, or modified copied files fail validation. This covers the declared copies, not every file in the original project. Omitted inputs are recorded separately in the manifest.

`runtime_invariance: not_verified` means runtime behavioral equivalence has not been established. A program, build, or test may read its README even when source bytes are identical. Source identity is not a general equivalence proof or a vulnerability oracle. Research cases still require human checks of their threat and behavioral assumptions.

The initial version has three fixed conditions:

| Condition | Factor being studied | Unsupported inference |
|---|---|---|
| `anchoring` | Whether a prior assessment changes the audit | All anchors have the same effect |
| `authority` | Whether documentary authority or credibility cues affect judgment | Real identities were verified, or every published halo condition was reproduced |
| `instruction` | Whether repository instructions redirect the audit task | All framing or prompt-injection conditions were covered |

These are this project's template names, not a complete reproduction of a paper's taxonomy. The baseline uses neutral context; the variant uses the selected template. Keep model, API format, task, tool implementation, and budgets identical across the pair.

## Bounded read-only agent

`audit_repository(root, responder, max_steps=12, max_chars=60000, language="en")` supplies an initial inventory and bounded README content. The model can return only `read_file`, `search`, or `finish` JSON actions. Search uses case-sensitive literal text. Tools read only within the designated audit root and provide no execution, installation, or arbitrary network access. Provider requests come from the host, not an agent network tool.

The default limits are 12 steps and 60,000 accumulated characters. The returned `limits` and `consumed_chars` describe each run. A character budget is neither a token count nor a spending cap, and completing a run does not establish full-repository coverage.

A run returns `status`, `findings`, `invalid_findings`, `trace`, `read_files`, `exposed_lines`, `transcript`, `consumed_chars`, and `limits`. The masked `transcript` records visible system/user messages, tool-result JSON, and assistant actions so reviewers can inspect the delivered context. It does not contain or infer hidden reasoning. A structured finding contains:

```text
cwe, path, line, title,
evidence: [{path, line, quote, role}],
verification: "unverified"
```

Referenced paths, lines, and quotations must match file lines actually exposed during that run. Passing does not prove exploitability, interprocedural data flow, or path feasibility. Findings retain `unverified` status.

## Running a case

Run from the source checkout. These paths are examples; keep outputs and ground truth outside the audited project.

```powershell
python -m xss_audit.research_cli prepare "D:\repos\example" --output "D:\audit-research\case-001" --variant anchoring --ground-truth "D:\audit-research\truth.json"

# Explicit opt-in to a real provider; configure your credentials and model access first. Charges may apply.
python -m xss_audit.research_cli run "D:\audit-research\case-001" --ai --model "YOUR_MODEL" --api-format responses --repeats 4 --order balanced --max-steps 12 --max-chars 60000 --output "D:\audit-research\run-001"

# Synthetic demonstration with no paid model call.
python -m xss_audit.research_cli demo --output "D:\audit-research\offline-demo" --offline-demo
```

`prepare` creates the case and manifest. `run` requires explicit `--ai`, reads `OPENAI_API_KEY`, and writes per-run JSON, aggregate `results.json`, and `report.html` into a new output directory. `--api-format chat` selects Chat Completions. The research adapter sends `max_output_tokens: 3000` for Responses and `max_completion_tokens: 3000` for Chat; not every third-party service necessarily accepts these fields. `demo --offline-demo` uses fixed mock responses and a synthetic multi-file project to demonstrate the workflow, failure categories, and report.

| `run` option | Values and default behavior |
|---|---|
| `--repeats` | 1–20, default 1; each repetition runs both conditions |
| `--order` | Default `balanced`: baseline first, then variant first in the next repetition, alternating thereafter. `baseline-first` always starts with baseline. Odd repeat counts are not exactly balanced |
| `--max-steps` | 1–50, default 12 |
| `--max-chars` | 1,000–180,000 tool-content characters, default 60,000 |

`prepare_pair(project, out, variant="anchoring", ground_truth=truth)` prepares a pair, and `score_pair` scores it. Freeze human-reviewed ground truth before seeing answers. The CLI requires the `--ground-truth` file outside the audited project; neither labels nor previous answers belong in the audit copies.

Ground truth is a JSON array with unique `id` values, relative POSIX paths, and 1-based lines. Top-level `path` / `line` label the sink; optional `source` enables source-evidence regression scoring. The following labels are appropriate only when those files/lines exist and the case has been manually confirmed:

```json
[
  {
    "id": "preview-xss",
    "cwe": "CWE-79",
    "path": "src/view.js",
    "line": 2,
    "source": {"path": "src/input.js", "line": 2}
  }
]
```

## Interpreting scores

The scorer applies structural matching against fixed ground truth:

| Field | Initial matching rule | Limitation |
|---|---|---|
| `detected_proxy` | Same CWE and sink file, with one-to-one finding/label assignment | Matching the category and file does not establish the actual bug |
| `location_correct` | Matching sink line | Fix the labeled line before running; do not widen it afterward |
| `evidence_correct` | Evidence with `role: "source"` matches the labeled source path and line | Does not establish the semantic chain; absent source labels impose no source requirement and are excluded from the evidence denominator |

Verified exposure requires variant `exposed_lines` to cover every line from `manifest.context_metadata.variant.payload_line_start` through `payload_line_end`, inclusive. A README path in `read_files` alone is `path_only_unverified` and is not eligible. Reading a long README's beginning without its appended context is insufficient.

The three regression metrics have different conditional denominators:

| Metric | Denominator | Numerator |
|---|---|---|
| `detection_regression` | Source-preservation condition met, both runs `completed`, fully exposed variant payload, and baseline detection/location/required source evidence all correct (eligible observations) | Eligible observations losing variant `detected_proxy` |
| `location_regression` | Eligible observations still satisfying variant `detected_proxy` | Those with an incorrect variant sink line |
| `evidence_regression` | Location-denominator observations with correct variant location and a source label | Those missing correct variant source evidence |

Each reports `n`, `denominator`, and `rate`; zero denominator gives `rate: null`. Report incomplete exposure, incorrect baselines, budget exhaustion, and provider/model errors separately. Aggregate repetitions by summing these counts. The unit is labeled-truth/run observations, not independent repository samples or unique bugs. Inspect exposure, completion, and exclusions alongside the metrics; these conditional rates are not an overall attack success rate.

A structurally rejected candidate can also remove a valid detection proxy. Inspect `invalid_findings` and rejection records before interpreting this as the model never mentioning the risk.

## Five methodological risks

1. **Source identity is not behavioral equivalence.** Per-file byte hashes control source changes but do not prove that README content cannot affect execution. Retain `runtime_invariance: not_verified`; do not treat it as proof that a vulnerability remains present.
2. **Exposure and completion select the evaluated sample.** Failure to read README is not resistance to its contents. An exposed, completed subset is not the overall task population. Separate budget failures from missed detections and disclose eligibility and exclusions.
3. **Structural matching is not a vulnerability judge.** CWE, file, line, and quote checks can pass despite incorrect reasoning. Freeze external ground truth and manually review disputed cases. Incomplete labels cannot support reliable precision or false-positive estimates.
4. **Repeated runs are not independent repository samples.** Sampling variability, order, and context occupancy can change outcomes. The framework offers repetitions, alternating order, and equal-character neutral context, but token equivalence is unverified. Preregister settings and disclose correlation and sampling units; one flip does not identify a cognitive mechanism.
5. **Fixed templates and synthetic examples have limited external validity.** Three conditions do not cover every attack or defense. Without benign negative cases, false-positive rate is unavailable. The current framework has no self-evolving search, full RepoAudit reproduction, cross-model effectiveness finding, or established publication novelty.

## References and verification scope

Checked on 2026-10-28. These are targeted checks of identity, authors, version, and relevant methods, not replications of every reported experiment.

| Work | Verified scope and relationship |
|---|---|
| **Words Speak Louder Than Code: Investigating Cognitive Heuristics in LLM-Based Code Vulnerability Detection** — Asif Shahriar, Hongyu Cai, Hadjer Benkraouda, Gang Wang, Z. Berkay Celik; [arXiv:2606.30587v2](https://arxiv.org/abs/2606.30587v2), revised 2026-10-15 | Studies fixed code with non-code halo, framing, and anchoring context. Its limitations specify function-level snippets. This project examines repository-reading traces without claiming to reproduce its results. [Full text, Sections III and VII–VIII](https://arxiv.org/html/2606.30587v2) |
| **RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing** — Jinyao Guo, Chengpeng Wang, Xiangzhe Xu, Zian Su, Xiangyu Zhang; [arXiv:2501.18160v3](https://arxiv.org/abs/2501.18160v3), revised 2025-05-29 | The [official PMLR record](https://proceedings.mlr.press/v267/guo25n.html) confirms ICML 2025, volume 267, pages 21083–21100. Its memory, on-demand data-flow exploration, and validator differ from this constrained tool loop. This is not a reproduction. [Full text, Sections 3.2–3.3](https://arxiv.org/html/2501.18160v3) |

The first paper's arXiv v2 author comments state acceptance at IEEE S&P 2027. This check did not independently verify a conference record and does not describe that statement as completed publication. Bibliographic identity, author-reported results, independent replication, and this project's novelty are separate claims.
