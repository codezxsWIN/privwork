# HANDOFF — state of the project as of 2026-09-18

Written for a developer/agent resuming work with knowledge of the repository's
**earlier state** (before commit `c88e822`). Read this top to bottom; it maps
old→new, documents the machine the work ran on, and lays out the continuation
plan in phases with acceptance criteria. The project's own rules still govern:
`.github/copilot-instructions.md` (evidence ladder, no unpinned pip, scope
fence) and `docs/decisions.md`, which now also contains the dated entries for
everything below (CLEANUP-01, FEED-01/02, CI-01, TEST-01, DEMO-01, SCAN-01/02).

---

## 1. Where the project now stands (one paragraph)

The engine is unchanged in its scoring semantics and still fully tested
(233 tests, 87.6% coverage, pyright 0 errors incl. strict mode on
scoring/schema, ruff clean, gate green, enforced in CI). Around it, four
structural gaps closed: the narrative bloat is deleted, the offline feeds are
REAL (NVD 376,424 / EPSS 375,610 / KEV 1,713 records), real Nmap captures
exist (loopback lab, honestly zero-CVE), and the quality gate runs in GitHub
Actions on 3.11+3.12. A separate demo repo presents it. What remains open is
what only humans or more tooling can supply: web-scanner captures, LLM
rationale, and the research inputs (expert rankings, labels, context truth)
that gate every RQ1–RQ4 claim.

## 2. What changed vs. the old state (old → new)

| Old state (pre-`c88e822`) | New state |
| --- | --- |
| `legacy/` full duplicate package | **Deleted**; git history preserves it (BUILD-01 superseded by CLEANUP-01) |
| `project-starter-kit/` with Copilot `PROMPT.md` | **Deleted**; only its `docs/DESIGN.md` retained as `docs/DESIGN.md` (3 docs cite it) |
| `PROJECT_PROVISIONING_COMPLETE.md`, `PROVISIONING_SUMMARY.md` | **Deleted** (claimed pip-installed feeds the charter forbade) |
| Root-level `SCAN_FORMAT_REFERENCE.md`, `FIXTURE_*_GUIDE.md` | Moved into `docs/` |
| Feeds `[MISSING]`, synthetic only | **Real snapshots** under gitignored `data/feeds/`; fetchers `scripts/fetch_feeds.py` + `scripts/fetch_nvd.py` (rate-limited, resumable); provenance `docs/FEED_PROVENANCE.md`; curated committed subset `tests/fixtures/intel/` + `tests/test_real_intel.py` |
| No CI; `.github/` only had copilot-instructions | `.github/workflows/ci.yml`: ruff lint+format, pyright, pytest `--cov-fail-under=75`, pinned versions, 3.11+3.12 |
| `pyproject.toml` had no lint/type config | `[tool.ruff]` explicit ruleset (`E4,E7,E9,F,I`, line-length 100) — **required**: ruff ≥0.16 broadened implicit defaults; `[tool.pyright]` include vulnassess+scripts, **strict** on `scoring.py`/`schema.py` per charter |
| Reader rejected ALL real Nmap XML | `vulnassess/readers/_input.py`: only `<!ENTITY` and DOCTYPE-with-internal-subset rejected; bare `<!DOCTYPE nmaprun>` accepted (real Nmap always writes it; synthetic fixtures never did — found by the first real scan) |
| UI tests needed author's leftover DB (18 failures on fresh clone) | `tests/test_ui.py` `setUpModule` self-provisions via `run_demo.py` + inserts the `verify` runs row; `DEMO_RUN = "demo"` |
| No real captures | `tests/fixtures/nmap/real-lab-*.xml` ×2 (provenance rows in that README) + `tests/test_real_captures.py`; executed via `vulnassess scan --execute` with empty canary log |
| `models/` trained on self-generated synthetic | unchanged (shadow-only by design) — still synthetic, still honest |
| Dense README | Rewritten: quickstart (incl. `run_real_demo.py` over `examples/real_lab_nmap.xml`), real-vs-not table, safety model |
| `DOWNLOADS_REQUIRED.txt` everything `[MISSING]` | Rewritten status: feeds PROVISIONED, gate PASSING, human-only items still MISSING |

**Commits** (branch `audit-no-assumptions`): `c88e822` (cleanup + feeds + CI +
gate fixes), `6f4e323` (first real captures + reader DOCTYPE fix). **Not yet
pushed to GitHub.**

**Separate demo repo** `C:\Users\aksha\Downloads\vulnassess-demo` (own git):
`2c0ad7a` Streamlit showcase (6 tabs, live sandbox on production
`scoring.environmental_vector`/`risk`), `002adcc` self-contained HTML
workbenches in `standalone/` (single file, zero dependencies, offline; sandbox
arithmetic embedded + Python-parity vectors). Demo DB is built by
`prepare_data.py` through the production CLI. Streamlit runs loopback-only:
`streamlit run app.py --server.address 127.0.0.1`.

## 3. Machine state this ran on (not in any repo)

**Scope note:** this section describes the operator machine where the session ran
(`C:\Users\aksha\Downloads\fragmented`). A fresh clone of the repository contains
**no `data/` directory** (gitignored: feeds, captures, lab, demo database) and no
machine tools — re-provision with `python scripts/fetch_feeds.py` plus the gate
tooling, which CI installs for itself from the pinned versions. Do not assume
another machine's inventory matches this one: this machine has Nmap but no
Java/Docker; other environments reported the exact reverse.

- Windows 11, Python 3.12.10 at `%LOCALAPPDATA%\Programs\Python\Python312`.
- Gate tools installed: ruff 0.16.6, pyright 1.1.411, pytest 9.1.1,
  pytest-cov 7.1.0, streamlit 1.61. CI pins these exact versions.
- **Known local quirk:** the `hypothesis` pytest plugin is installed but broken
  (Windows App Control blocks its `_native` DLL). It is NOT a project
  dependency. Run tests locally with `-p no:hypothesispytest` (or
  `PYTEST_ADDOPTS="-p no:hypothesispytest"`); CI is unaffected.
- Nmap 7.80 (`C:\Program Files (x86)\Nmap`) + `vulners.nse` in its scripts dir
  (keyless → no CVE output; a free key at `~/.nmap/vulners.key` unlocks it).
- Loopback aliases on "Loopback Pseudo-Interface 1": 172.28.0.10/.11/.12
  (matches `config/scope.yaml`; canary .250 unbound). Undo:
  `netsh interface ipv4 delete address "Loopback Pseudo-Interface 1" <ip>`.
- Lab apps under gitignored `data/lab/`: OWASP Juice Shop 20.2.0 portable
  (`juice-shop/`), portable Node v22.21.1, canary log `canary.log` (empty).
- **Security lessons (do not repeat):**
  - Juice Shop's `server.listen(port)` takes no host; `--host` is ignored. The
    lab copy is patched in `build/server.js` to bind `172.28.0.12` ONLY. First
    launch bound `0.0.0.0` for ~25 min — killed. Always `netstat -ano | grep
    LISTEN` after starting any listener and confirm the bind address.
  - Its startup reachability probes (Alchemy/LLM) hang on flaky networks; the
    lab copy short-circuits them in
    `build/lib/startup/validatePreconditions.js`. If it stalls anyway: delete
    `data/juiceshop.sqlite*` and restart.
- Background services may or may not still be running: Juice Shop
  (172.28.0.12:3000), Python http.server (172.28.0.10:8000), Streamlit
  (127.0.0.1:8601). All loopback-bound; safe.

## 4. Rules that still govern (unchanged charter)

Evidence ladder `VERIFIED / TESTED WITH MOCKS / NOT RUN / MISSING`; synthetic
data never proves a real claim; no unpinned pip installs as supply-chain
approval (CI's pinned dev-deps are the deliberate, documented exception —
CI-01); scope fence checked before any file read; canary refused by name;
scanner execution only via human `--execute`; LLM may reword a rationale but
never a rank. New decisions get dated entries in `docs/decisions.md`.

## 5. Continuation plan

### Phase 0 — publish (≤30 min, do first)
1. Push `audit-no-assumptions` to GitHub (origin exists: `codezxsWIN/privwork`);
   open PR to main so CI runs on the PR. **Accept:** both 3.11 and 3.12 matrix
   jobs green. If pyright/ruff drift in CI vs local, align pins in
   `.github/workflows/ci.yml` (they are the passing set).
2. Optionally publish the demo repo similarly (separate repo or `demo/` subdir
   later).

### Phase 1 — unlock real CVE findings (minutes of human time)
3. Human registers at vulners.com, puts the free key in `~/.nmap/vulners.key`.
4. Ensure lab targets up (Juice Shop on .12; optionally another banner-rich
   service on .10), then rerun:
   `python -m vulnassess --config config --db data/lab.db scan --run-id lab3
   --target-ip 172.28.0.12 --tool nmap --canary-log data/lab/canary.log
   --out-dir data/captures --execute`
   then the usual `import/enrich/context/rank/report`.
   **Accept:** ≥1 finding with a real CVE enriched from real NVD/EPSS/KEV;
   provenance row appended in `tests/fixtures/nmap/README.md`; commit capture
   if useful.
5. For version-rich targets, consider running a deliberately old portable app
   (e.g., an old Python/OpenSSL/Node build serving on .11) so `-sV` yields a
   version NVD can CPE-match — that exercises `match_method=cpe_range` on real
   data end to end.

### Phase 2 — web-scanner evidence (Nikto/ZAP)
6. Options on this machine (no Docker/WSL/Java present): install Temurin JRE
   (winget) for ZAP, and either Strawberry Perl for Nikto or use ZAP only.
   Prefer ZAP-only if you must pick one: `zap-baseline.py -t URL -J out.json`
   matches the orchestrator's planned command exactly.
7. Run `scan --tool zap` after Nmap proves the endpoint (orchestration already
   handles this), commit captures under `tests/fixtures/zap/` with provenance.
   **Accept:** `parse_zap_json` verified on real output (the reader's
   `tests/fixtures/zap/README.md` table gets its first rows); findings flow
   through enrich→rank.

### Phase 3 — LLM rationale (optional but cheap)
8. Install Ollama, pull ONE model (charter default `llama3.2:3b`), record the
   decision in `docs/decisions.md` (model, digest, license, smoke test).
9. `vulnassess explain --run-id ... --ollama-host http://127.0.0.1:11434`.
   **Accept:** report footer shows the model reworded sentences AND the
   validation/fallback counts; scores byte-identical to `--no-model` run.

### Phase 4 — research evidence (the real blocker: humans)
10. Recruit 2–3 practitioners for expert rankings (format: `experts: [{name,
    ranking}]` + `expert_critical`); freeze the cohort with `research
    cohort-freeze`; run `eval/context-eval`, `eval/ranking-eval`, `ablate`,
    `stability`. **Accept:** RQ1–RQ4 move from NOT RUN to actual decisions —
    the first time any hypothesis claim becomes eligible.
11. Human role-model labels via `model labels` → disjoint splits → `model
    train/evaluate`. Promotion out of shadow mode stays gated by the existing
    manifest workflow (do not bypass).

### Phase 5 — polish (as needed)
12. Demo upkeep: after any pipeline change, `python prepare_data.py` and
    re-export `standalone/*.html` (commands in the demo repo README/commit).
13. Optional: `uv`/venv documentation for newcomers, PDF export (deferred by
    decision), pre-commit hooks (deferred).

### Standing don'ts
- Don't reintroduce "provisioning complete" style manifests; status lives in
  `DOWNLOADS_REQUIRED.txt` + evidence ladder only.
- Don't loosen the reader's security checks to make a capture parse; if a real
  scanner format trips them, extend the allowlist narrowly (SCAN-01 pattern)
  with a test.
- Don't let anything bind non-loopback without an explicit reason and a
  netstat check.
- Don't upgrade ruff/pyright pins casually; the ruleset is version-stable by
  config, but re-run the full gate before pushing.

## Execution ledger - 2026-09-23

This ledger records the new end-to-end audit. Earlier machine inventories and
completion statements above are historical, not evidence for this machine.
Scope: PROJECT.md stages 1-8, trained context inference, deterministic ranking,
and independent evaluation. The final user directive requests an adversarial
audit; no product completion or policy approval is inferred from its goals.

### Cycle 1 - locate the target-first execution path

- Objective: trace a new authorized target from application input to report.
- Current blocker: no joined target-first path has been established.
- Evidence: VERIFIED, `git status --short --branch` returned
  `## audit-no-assumptions...privwork/audit-no-assumptions` with nine modified
  files; `git log -6 --format="%h %s"` identified HEAD as
  `89ec696 docs: database schema, data flow, retention, and migration summary`.
  Existing UI work is preserved.
- Evidence: VERIFIED, local source reads of `vulnassess/ui/server.py` show
  `if self.command != "GET"` returning `405, "UI supports GET only"`;
  `vulnassess/cli.py::cmd_scan` emits outcomes after `orchestrator.orchestrate`
  without invoking `pipeline.do_import` or downstream processing.
- Change made: this ledger only; no runtime, scope, provider, dependency, or
  fixed-interface change.
- Test performed: NOT RUN, isolated target-intake and orchestration probes are
  next; the source observations do not establish runtime integration.
- Result: NOT RUN, end-to-end acceptance remains unproved. A writable assessment
  API, new authorization schema, and remote reasoning would require resolving
  the standing fixed-contract and local-only restrictions, not silently
  replacing them with a new document.
- Next action: verify installed tooling, run the supported local gate, and
  exercise target intake and scanner-to-import boundaries without network use.

### Cycle 2 - execute the target and scanner boundaries

- Objective: distinguish a real assessment lifecycle from scanner-only success.
- Current blocker: the HTTP application is a viewer; scan execution has no
  automatic handoff to import or persistence.
- Evidence: TESTED WITH MOCKS, socket-free `UiApplication`/`request` probes
  returned `INTAKE {"new_assessment_get": 404, "create_post": 405}`. Planning
  `portal.example.invalid` raised `ScopeError`, with `DNS_CALLS 0`. A configured
  CIDR contains `192.168.0.116`, but the planner rejects it because it is not an
  explicitly listed target. The canary was also rejected before execution.
- Evidence: TESTED WITH MOCKS, the injected scanner probe returned
  `MOCK_SCAN_HANDOFF {"exit": 0, "complete": true, "database_created": false,
  "summary_created": true, "outcomes": 1}`. A second probe returned
  `complete: true` while both web tools said
  `successful Nmap output did not contain target 172.28.0.11`.
- Change made: copied 228 tracked paths, including current edits, into a local
  temporary source snapshot; backed up SQLite with a read-only source
  connection. No original data or runtime code changed.
- Test performed: TESTED WITH MOCKS, system Python ran pytest against
  `tests/test_orchestrator.py tests/test_operations_cli.py
  tests/test_reader_security.py tests/test_intel_trace.py
  tests/test_settings_strict.py`, with socket creation and DNS blocked.
- Result: TESTED WITH MOCKS, `39 passed, 4 subtests passed in 5.50s` and
  `OFFLINE_FOCUSED_EXIT 0`. This is not live scanner verification.
- Result: MISSING, `nmap`, `nikto`, `zap-baseline.py`, `ollama`, `make`,
  `data/feeds`, `data/lab/canary.log`, and `lab/canary_access.log` were absent
  from the checked PATH or paths. Both inspected Python environments lack
  Ruff, Pyright, pytest-cov, and psycopg; only system Python has pytest.
- Result: VERIFIED, system Python `scripts/check.py` exited 1 with
  `GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright,
  pytest + coverage`. Coverage is unmeasured, not a passing threshold.
- Next action: audit AI1 source, dataset independence, and the AI1-to-AI2
  uncertainty handoff; run the broader suite in the isolated snapshot.

### Cycle 3 - test the trained-context claim

- Objective: determine which model is present and whether canonical use is
  gated by independent validation.
- Current blocker: the only artifact in `models/` is synthetic, and the
  optional canonical-context path bypasses the promotion workflow.
- Evidence: VERIFIED, structured reads of `models/synthetic-role-model.json`
  returned hash `d1a13c5e7302dca5`, task `asset_role_shadow`, 9 classes, 134
  features, 54 synthetic examples/54 declared groups, and temperature 0.25
  selected on 18 synthetic calibration examples/18 declared groups.
- Evidence: VERIFIED, system Python evaluated the existing synthetic datasets:
  `TRAINING` and `CALIBRATION` both returned accuracy/macro-F1/coverage 1.0,
  abstention 0.0 and ECE 0.0000003. These are synthetic replay measurements,
  not independent model-quality evidence. `SPLITS` returned
  `shared_group_ids: 0`, `identical_feature_vectors_across_splits: 17`, and
  `evaluate_accepts_training_dataset: true`.
- Evidence: VERIFIED, `pipeline.do_context(..., model_path=...)` on the isolated
  stored synthetic demo changed two role sources from `rule` to `model` without
  a promotion manifest. The persisted role has only `confidence`, `evidence`,
  `source`, and `value`; it drops model hash, margin, abstention, coverage, and
  OOV details. This contradicts an unconditional shadow-only claim.
- Change made: no runtime/model changes; observations recorded here. The
  isolated demo context was restored through the default rule path afterward.
- Test performed: VERIFIED, artifact loading checked its hash; real model
  inference was executed only against existing synthetic records. No training
  labels, scanner evidence, approvals, or real-world metrics were invented.
- Result: MISSING, independently human-labelled train/calibration/held-out data
  and an unseen-environment evaluation have not been found in the inspected
  model/data locations. Their absence is not permission to promote this model.
- Next action: inspect structured analyst grounding, persistence and report
  paths, then execute the available real-capture replay with its limits stated.

### Cycle 4 - probe the reasoning analyst

- Objective: determine whether AI2 is a grounded analyst and whether its
  guards hold under adversarial input.
- Current blocker: the case builder loses model uncertainty, and three guards
  fail on bounded synthetic probes.
- Evidence: TESTED WITH MOCKS, `analyst.build_case` produced a structured case
  with `services`, `context`, `findings`, per-item `evidence_id` citations,
  CVSS/EPSS/KEV/`match_method` intelligence and the deterministic score. This is
  more than sentence rewriting. The role object carried only `confidence`,
  `evidence`, `evidence_id`, `source`, `value`: no model hash, margin,
  abstention, feature coverage, or OOV list reaches AI2.
- Evidence: TESTED WITH MOCKS, `required_untrusted_prefix: false`. The analyst
  prompt uses `<untrusted_evidence>` and never emits contract I2's required
  `untrusted data follows` prefix, unlike `explain.build_prompt`.
- Evidence: TESTED WITH MOCKS, with 140 synthetic services the evidence budget
  filled and the finding cited `E128`, whose stored text is a service banner.
  A citation can therefore point at unrelated evidence instead of failing.
- Evidence: TESTED WITH MOCKS, a 24,043-character service banner with a
  `\x01` control character reached the case unsanitised and closed the
  untrusted block early: `closing_delimiters: 2`. `_clean` is applied to the
  finding/score/intel text, not to `services`.
- Evidence: TESTED WITH MOCKS, `validate_analysis` accepted a summary claiming
  a fabricated CVE and a replacement priority, because only citation IDs and
  field shapes are checked. Stored scores were unchanged.
- Evidence: TESTED WITH MOCKS, a mocked 66,560-byte structured response was
  accepted although `MAX_RESPONSE_BYTES` is 65,536: the streaming path never
  enforces the declared limit.
- Evidence: TESTED WITH MOCKS, an unavailable provider raised `LLMUnavailable`
  and left the assessment byte-identical, with no structured fallback.
- Change made: none in runtime code; the probes used synthetic inputs and a
  non-forwarding mocked transport. No model endpoint was contacted.
- Result: TESTED WITH MOCKS, AI2 is grounded but not defended; provider
  selection is also hard-coded to `OllamaClient` at the analyst boundary.
- Next action: replay the available real captures through the report path.

### Cycle 5 - replay real captures end to end

- Objective: measure how far the current pipeline runs on recorded evidence.
- Current blocker: live scanning and live inference cannot run here.
- Evidence: VERIFIED, in the isolated copy the existing `demo` command replayed
  the three committed real Nmap captures plus the real ZAP capture against the
  curated real feed subset and exited 0: 3 hosts, 225 findings, 225 scores,
  `epss 3, kev 3, nvd 3`, `enrich: 3/225 findings matched`, and a 191,267-byte
  report. Re-ranking reproduced byte-identical stored scores
  (`repeat_rank_equal: true`), and the three baseline orders each had 225 items.
- Evidence: VERIFIED, the same run printed `No CVE appears on two or more hosts
  in this run; the two-machine comparison needs one.` The signature experiment
  currently has no real-capture instance.
- Evidence: VERIFIED, the hash-verified model predicted `file_share` for the
  Juice Shop web host `172.28.0.12` at confidence 0.855 without abstaining
  (coverage 0.348, 15 OOV features), and `file_share` for `172.28.0.10` at
  0.994. The rule path independently produced `file_share` for `172.28.0.12`,
  and the stored reason reads `internet-facing file share`. This is a real
  generalisation failure on real evidence, not a fixture artifact.
- Result: MISSING, live target intake, resolution, scanner execution and model
  inference remain unproved. `nmap`, `nikto`, `zap-baseline.py` and `ollama`
  are absent from PATH and the checked install locations, and nothing is
  listening on the local model port.
- Result: NOT RUN, no scan, DNS query, feed download, or model request was
  issued during this audit; a socket/DNS guard was active for every probe.

### Audit verdict - 2026-09-23

STATUS: EXTERNAL BLOCKER for the live end-to-end objective, plus repository
defects that are fixable here. The acceptance criteria are NOT met.

Blocked outside the repository, with the exact human action required:

1. Scanner execution: install Nmap, and Nikto or ZAP, then supply an empty
   canary log path for `scan --execute`.
2. Reasoning provider: run a local model service, or supply approved
   credentials and an approved policy change for a remote provider. The
   current documents require local-only inference.
3. Quality gate: provision Ruff, Pyright and pytest-cov; `scripts/check.py`
   reports `GATE INCOMPLETE` and coverage is unmeasured.
4. Real labels and expert rankings: no human-labelled role dataset and no
   expert judgment file exist, so AI1 promotion and RQ2/RQ3 stay unevaluated.
5. Authorisation: a new unseen target requires an owner-approved scope entry.

Requires human decision before implementation, because the request conflicts
with recorded contracts:

1. Writable target intake contradicts the GET-only viewer contract in
   `docs/ui-contract.md`; the assessment schema already has the tables, but no
   approved write path or ADR exists.
2. Canonical model-derived context is blocked by MODEL-06 and OPERATIONS-01,
   yet `context --model` already overrides the rule role without a manifest.

Repository defects to fix under existing contracts, in priority order:

1. `orchestrate` reports `complete: true` when discovery omits the requested
   target; incomplete coverage must not read as success.
2. `cmd_scan --execute` writes a summary but never imports or persists; the
   scan-to-store handoff is missing.
3. Analyst evidence overflow reuses the last ID, service text is unsanitised,
   the I2 prefix is absent, the response-size limit is unenforced on the
   streaming path, and validation permits fabricated CVEs and scores in prose.
4. `context --model` bypasses `model_governance.validate_promotion` and drops
   model hash, margin, abstention, coverage and OOV from the stored profile.
5. `tests/test_assessment_store.py::NoBrowserWriteAccess` opens real sockets,
   contradicting invariant I4; three `test_ui` contract tests still fail from
   the earlier merge.
6. The bundled model is synthetic-only: 54 training and 18 calibration
   examples, all `label_source: synthetic`, with 17 identical feature vectors
   shared across the two splits despite distinct group IDs.

## Full two-prompt recheck - 2026-09-23

This pass reopens the entire original implementation directive and the complete
second-pass audit, not only the UI checkpoint. Earlier verdicts are historical;
the final A-J review below will distinguish repaired paths from unproved claims.

### Cycle 6 - truthful discovery and scan-to-store handoff

- Objective: PROJECT.md stages 1-4; connect authorized scan execution to
  normalized evidence and retain honest outcomes for the ranking experiment.
- Current blocker: new hostname intake and real scanner execution are not
  established. No authorization, download, or fixed-interface approval is
  implied by this repair.
- Evidence for the blocker: TESTED WITH MOCKS, the added missing-host test
  failed with `AssertionError: True is not false`; the expanded scan CLI test
  failed with `False is not true : executed captures must reach the store`.
- Change made: missing requested-host evidence marks discovery failed while
  preserving its exit code and raw path. `scan --execute` stores its outcomes
  and imports successful captures. Web imports retain prior Nmap host services.
  CLI shapes, exit codes and table layouts are unchanged.
- Test performed: TESTED WITH MOCKS, `python -m pytest -q --tb=short
  -p no:cacheprovider
  tests/test_orchestrator.py::TestOrchestrator::test_scan_cli_execute_uses_injected_nmap_first_path
  tests/test_orchestrator.py::TestOrchestrator::test_discovery_without_requested_host_is_not_complete`.
- Result: TESTED WITH MOCKS, `2 passed, 2 subtests passed in 0.78s`; injected
  scanner calls only, with a temporary database. This is not live integration
  evidence and does not yet establish the complete target-to-report flow.
- Next action: verify partial-run persistence, then examine context-model
  promotion, independent labels, uncertainty retention and the analyst boundary.

### Cycle 7 - model governance and actual dataset evidence

- Objective: PROJECT.md stage 5 and RQ1; prevent an unevaluated model from
  bypassing the approved context boundary while preserving shadow inference.
- Current blocker: canonical learned-role activation still requires the
  context-source ADR. A promotion manifest alone authorizes only a candidate.
- Evidence for the blocker: TESTED WITH MOCKS, the new canonical-context test
  initially returned `ConfigError not raised`. VERIFIED, an offline
  `load_model`/`load_examples`/`evaluate` probe reported 54 training examples,
  18 validation examples, 72 synthetic labels, zero shared group IDs and 17
  shared feature vectors. Both datasets reported accuracy/macro-F1/coverage
  1.0 and ECE `3e-07`; these are not human-held-out quality measurements.
- Change made: `build_profile` now refuses the unapproved model activation
  explicitly. Existing rule context remains unchanged; model prediction,
  training, evaluation and hybrid candidate generation remain available.
- Test performed: TESTED WITH MOCKS, `python -m pytest -q --tb=short
  -p no:cacheprovider tests/test_model_governance.py tests/test_role_model.py
  tests/test_context_eval.py`.
- Result: TESTED WITH MOCKS, `26 passed, 10 subtests passed in 1.19s`.
- Next action: keep independent human labels and unseen-environment evaluation
  separate from the synthetic replay; examine AI2 case and provider boundaries.

### Cycle 8 - analyst input, output and transport boundaries

- Objective: PROJECT.md stage 5; preserve grounding without changing numerical
  ranking or disguising partial analysis as a complete assessment.
- Current blocker: a live local model is unavailable. Remote-provider runtime
  use remains outside the current local-only policy.
- Evidence for the blocker: TESTED WITH MOCKS, regressions reproduced citation
  ID reuse, an uncapped 24,047-character service banner, unsupported CVE/number
  claims, malformed citation exceptions, false Ollama provenance, and unbounded
  or incomplete streamed responses.
- Change made: all model-facing strings are cleaned and capped; JSON delimiters
  are escaped and the required untrusted-data prefix is present. Cases use
  stored-risk ordering, bounded evidence and explicit coverage counts. Omitted
  records force a partial-coverage notice and low confidence, not silent loss.
  Case evidence includes scanner provenance, match confidence, feed dates and
  weight hashes. Providers are injectable, identify themselves, and are contacted
  only after case validation. Unsupported CVEs/numbers and malformed citations
  are rejected. Streaming uses the supplied schema, bounded event/content/wire
  sizes and explicit completion. Broader prose truth is still not proven by IDs.
- Test performed: TESTED WITH MOCKS, isolated-copy `python -m pytest -q
  --tb=short -p no:cacheprovider tests/test_analyst.py tests/test_all.py::TestExplain`.
- Result: TESTED WITH MOCKS, `31 passed, 15 subtests passed in 2.34s`.
- Next action: replay real captures through these bounds and inspect report,
  model and evaluation provenance rather than extrapolating from fake replies.

### Cycle 9 - offline integration-test integrity

- Objective: cross-cutting reproducibility and invariant I4; exercise actual
  request handlers without test-generated network traffic.
- Current blocker: the old full suite required loopback sockets for five
  assessment-store tests, contrary to the standing no-network test rule.
- Evidence for the blocker: TESTED WITH MOCKS, the previous guarded full run
  reported five `NoBrowserWriteAccess` failures at socket creation.
- Change made: those tests now use the existing in-memory HTTP request harness
  and retain every response/write-refusal assertion. An autouse pytest fixture
  blocks Python socket connection, binding, sending and DNS operations. This
  guard is not permission to run network-capable child processes.
- Test performed: TESTED WITH MOCKS, `python -m pytest -q --tb=short
  -p no:cacheprovider tests/test_assessment_store.py tests/test_orchestrator.py`.
- Result: TESTED WITH MOCKS, `39 passed, 7 subtests passed in 16.39s`.
- Next action: recheck the complete offline suite; do not weaken the remaining
  old-UI assertions or claim that HTTP transport mocks establish live operation.

## Complete source publication checkpoint - 2026-09-23

PROJECT.md Stage 7 publication, including the pending stages 1-5 safety repairs.
The user requested all current UI and related source changes be pushed. This is
a review checkpoint, not acceptance of the UI or certification of the research.

VERIFIED: before this checkpoint, `git ls-remote --symref privwork HEAD
'refs/heads/*'` returned default branch `audit-no-assumptions` at
`fc2ba67e04242645cbcf9b61fc83e9afa38b96cd`, matching local HEAD. The new UI,
globe renderer, fonts and workflow were already included in that committed tree.
`git ls-files --others --ignored --exclude-standard -- vulnassess/ui scripts tests docs`
listed only Python caches, not omitted UI source or assets. Eight tracked files
had newer uncommitted changes at the initial check. The analyst and explanation
implementations and their tests changed during publication preparation and were
included as well: twelve changed files in this checkpoint.

TESTED WITH MOCKS: current tracked worktree files were copied to an owned
temporary directory, with both the process working directory and import path
set to that copy. Socket creation, connections and name resolution were patched
to fail. The workspace assessment database was not used. The executed test call:

```python
pytest.main(
    [
        "-q",
        "-ra",
        "--tb=no",
        "-p",
        "no:cacheprovider",
        "tests/test_analyst.py",
        "tests/test_model_governance.py",
        "tests/test_orchestrator.py",
        "tests/test_ui.py::TestUiExport",
        "tests/test_ui.py::TestUiAssets",
    ]
)
```

```text
FAILED tests/test_ui.py::TestUiExport::test_export_is_self_contained
AssertionError: 'font-src data:' not found
1 failed, 65 passed, 34 subtests passed in 13.56s
```

There were zero skips and no skip reasons in this focused run. The pending
export edit removes the previously published globe/font bundling; the failed
test is retained, not weakened. This publication preserves the user's current
edits rather than silently undoing them. NOT RUN: the broader suite, real
scanner/model execution or repairs to the export regression in this push task.

TESTED WITH MOCKS: after copying the subsequently changed explanation files into
the same isolated source tree, the additional focused test call was:

```python
pytest.main(
    [
        "-q",
        "-ra",
        "--tb=short",
        "-p",
        "no:cacheprovider",
        "tests/test_all.py::TestExplain",
        "-k",
        "structured_stream",
    ]
)
```

```text
4 passed, 10 deselected, 3 subtests passed in 0.78s
```

These tests used fake stream bodies and patched transport, not a real model.

MISSING: the required gate tools. The existing command returned exit 1:

```text
& 'C:\Users\amitdamle\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check.py
MISSING ruff lint: ruff is not installed; a human must provision it
MISSING ruff format: ruff is not installed; a human must provision it
MISSING pyright: pyright is not installed; a human must provision it
MISSING pytest + coverage: pytest_cov is not installed; a human must provision it
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

STATUS: source checkpoint prepared for the requested publication; build
acceptance remains blocked. BRANCH / COMMIT: `audit-no-assumptions`, based on
`fc2ba67`; the final publication hash is verified after push. GATE: focused
failure and missing tools above; source coverage is unmeasured. BUILT: no new
product features during publication. CHANGED: pending `vulnassess/`, `tests/`
and this existing `docs/HANDOFF.md` entry. DECIDED: publish the complete current
source checkpoint, not silently roll back the pending export change.
DECISIONS: publication only; no contract, scope or dependency approval granted.
EVIDENCE: quoted Git, test and gate results above. DEFERRED: build certification
and real-integration evidence are separate from source synchronization and
cannot be inferred from a successful push. NEXT: repair the offline-export
regression in an authorized follow-up and provide reviewed quality tooling.

### Cycle 10 - numerical, corpus and report evidence

- Objective: PROJECT.md stages 5-7 and RQ1-RQ4; prevent hidden ranking omissions,
  supervision validation bypasses, threat-data loss and missing model uncertainty.
- Current blocker: real runtime and research inputs remain absent; the old
  four-stage UI and concurrently removed export bundling remain separate failures.
- Evidence for the blocker: TESTED WITH MOCKS, regressions reproduced accepted
  unsupported corpus claims, discarded KEV without CVSS, automatic run-based
  grouping, stored learned-context scoring and silently dropped findings.
- Change made: corpus supervision reuses grounding validation; groups require
  review; known threat facts survive missing CVSS; baselines do not inherit final
  risk; ranking prevalidates context; detailed reports expose all shadow uncertainty.
- Test performed: TESTED WITH MOCKS, the focused scoring/governance command
  `python -m pytest -q --tb=short -p no:cacheprovider tests/test_all.py::TestScoring
  tests/test_experiments.py tests/test_evaluate_research.py tests/test_model_governance.py`
  returned `33 passed, 34 subtests passed in 2.19s`.
- Result: VERIFIED, the fixture replay command
  `python -m pytest -q -s --tb=short -p no:cacheprovider
  tests/test_real_captures.py::TestRealCaptures::test_recorded_evidence_replays_to_ranked_report_without_network`
  returned `1 passed in 4.89s` and printed `findings: 225`, `identical_rerank: true`,
  `matched_identifiers: 3`, `cached_nvd_records: 0`, `run_endpoint: 200` and
  analyst coverage `findings_included: 5`, `findings_omitted: 217` of 222.
- Next action: publish the complete audit and checkpoint without claiming live
  end-to-end acceptance, model generalisation or a passing quality gate.

## Full two-prompt audit - 2026-09-23

Scope: the original target-to-report implementation directive and every item in
the second-pass adversarial prompt. PROJECT.md stages 1-7 plus ranking,
evaluation and reproducibility. Mobile work was excluded at the user's request.
Initial revision: fc2ba67. Concurrent checkpoints 6f51bb5 and b3e5dae were
preserved; some repairs from this pass were included in those commits while the
recheck continued. Statements in earlier audits are historical, not current proof.

### A. EXECUTIVE VERDICT

**NO: the requested new-target, live, trained-context-to-reasoning-to-report
product is not demonstrated end to end.**

VERIFIED: recorded-capture processing produces 225 normalized findings, 225
repeatable scores and an audit-aware HTML report. The new replay test quoted
above makes that result reproducible. It is not a new-target scan or an LLM run.

TESTED WITH MOCKS: this pass repaired scan-to-store persistence, false discovery
completion, inconsistent scope checks, model-governance bypasses, analyst input,
output and streaming guards, partial-case disclosure, baseline isolation, and
network-using tests. Those results establish the tested code paths only.

MISSING: scanner/model executables, runtime feed snapshots, genuine canary
evidence, human role labels, held-out environments and expert judgments. Target
intake/resolution, one assessment coordinator, model activation and durable AI2
report integration remain incomplete, not completed by the repairs.

### B. COMPLETION CLAIMS VERIFIED

| Claim | Evidence and exact check | Owning code |
| --- | --- | --- |
| Requested-host absence is not success; partial scans retain outcomes and successful evidence | TESTED WITH MOCKS: `python -m pytest -q --tb=short -p no:cacheprovider tests/test_orchestrator.py tests/test_operations_cli.py` -> `18 passed, 7 subtests passed in 3.62s` | `orchestrator.py`, `cli.py`, `pipeline.py`, `store.py` |
| Explicit target checks cover the legacy runner/importer too | TESTED WITH MOCKS: `python -m pytest -q --tb=short -p no:cacheprovider tests/test_all.py::TestRunner tests/test_orchestrator.py tests/test_reader_security.py` -> `30 passed, 14 subtests passed in 1.88s` | `runner.py`, `pipeline.py`, `orchestrator.py` |
| Real recorded formats reach normalized findings, rankings, the run API and a report | VERIFIED: `TestRealCaptures.test_recorded_evidence_replays_to_ranked_report_without_network` -> `1 passed`; printed 225 findings, identical rerank, API 200 and zero cached NVD matches | `readers/`, `intel.py`, `pipeline.py`, `report.py`, `ui/server.py` |
| Canonical numerical calculations reject learned-context bypasses and missing host context | TESTED WITH MOCKS: focused scoring/ablation/evaluation/governance run -> `33 passed, 34 subtests passed` | `scoring.py`, `pipeline.py`, `context.py` |
| Bounded analyst, provider and transport guards execute without a real model | TESTED WITH MOCKS: isolated `python -m pytest -q --tb=short -p no:cacheprovider tests/test_analyst.py tests/test_all.py::TestExplain` -> `31 passed, 15 subtests passed`; subsequent corpus/analyst run -> `19 passed` | `analyst.py`, `explain.py`, `finetune/build_corpus.py` |
| Model training, shadow prediction and governance are actual implementations | TESTED WITH MOCKS: `python -m pytest -q --tb=short -p no:cacheprovider tests/test_role_model.py tests/test_model_governance.py tests/test_context_eval.py` -> `27 passed, 10 subtests passed` | `role_model.py`, `model_governance.py`, `context_eval.py` |
| Detailed report exposes shadow uncertainty without activating it | TESTED WITH MOCKS: `python -m pytest -q -s --tb=short -p no:cacheprovider tests/test_audit_report.py tests/test_real_captures.py::TestRealCaptures::test_recorded_evidence_replays_to_ranked_report_without_network` -> `2 passed in 3.06s` | `audit.py`, `report.py` |

### C. COMPLETION CLAIMS THAT ARE MISLEADING OR FALSE

| Claimed behavior | Actual behavior and why the claim fails | Severity |
| --- | --- | --- |
| New target to complete assessment through the app | TESTED WITH MOCKS: in-memory handlers returned `new_target_get: 404`, `target_post: 405`, `legacy_run_get: 200`, `expanded_runs_get: 409` on the replay database. Viewing an existing run is not target onboarding. | BLOCKER |
| Three matched CVEs prove intelligence coverage | VERIFIED: the replay has three explicit scanner IDs but `cached_nvd_records: 0`, `cvss31_vectors: 0`, `epss_values: 0`. Association confidence is not independent vulnerability confirmation. | HIGH |
| Perfect classifier metrics prove generalisation | VERIFIED: 54 train + 18 calibration examples are all synthetic; 17 feature vectors overlap across splits. Accuracy/macro-F1/coverage 1.0 and ECE `3e-07` are replay measurements, not independent quality evidence. | BLOCKER |
| Complete grounded target analysis | VERIFIED: the real web case includes 5/222 findings within the budget. TESTED WITH MOCKS: the response now discloses omitted records and lowers confidence; complete-case reasoning remains unproved. | HIGH |
| A trained reasoning model exists | VERIFIED: corpus inspection found two supervision rows, one marked synthetic in its prompt, with no reviewer/approval metadata keys. MISSING: a completed training artifact and independent analyst evaluation. | HIGH |
| Every context quote is verbatim raw evidence | VERIFIED: the `RAW_QUOTE_CHECK` probe found all three role and exposure strings absent as literal substrings from the copied raw artifacts; the strings are normalized descriptions or scope-derived explanations. | HIGH |
| Full report includes all structured AI2 reasoning | NOT RUN: `analyze_target` is transient/read-only; the existing report binds stored rationales and optional research artifacts, not a persisted structured analyst response. | HIGH |
| The gate is green or the offline export remains repaired | MISSING: Ruff/Pyright/coverage tools. TESTED WITH MOCKS: the full run retains old-UI failures and the export regression reintroduced by concurrent commit 6f51bb5. | HIGH |

### D. TOP 10 TECHNICAL FAILURES

Ranked by impact on the requested product/research acceptance, not by amount of code.

| Rank | Failure and root cause | Affected modules | Exact next correction |
| --- | --- | --- | --- |
| 1 | TESTED WITH MOCKS: no writable new-target intake or hostname resolution; the app is a stored-run viewer | `cli.py`, `settings.py`, `ui/server.py` | Approve the target-intake/resolution contract, then preserve requested name, all reviewed resolved addresses, timestamp and actual scan identity; authorize before execution. |
| 2 | NOT RUN: no single coordinator advances an authorized target through every stage; repaired scanning stops after normalized persistence | `cli.py`, `pipeline.py` | Add the approved assessment lifecycle that sequences enrichment, context, ranking, reasoning and report, preserving partial/error states. |
| 3 | TESTED WITH MOCKS: legacy pipeline storage and expanded assessment storage are disconnected; expanded route returned 409 on the pipeline run | `store.py`, `repository.py`, `ui/server.py` | Agree the authoritative store/migration contract and connect writers/readers; do not fabricate assessment rows to make the dashboard appear populated. |
| 4 | MISSING: live scanners, local model service and runtime inputs | scanner executables, Ollama, `data/feeds`, canary evidence | Human-provision approved tools/models/snapshots and actual lab instrumentation; demonstrate one explicitly authorized target without downloading or inventing inputs. |
| 5 | MISSING: independent role truth, held-out environments and expert rankings | `role_model.py`, `context_eval.py`, `cohort.py`, `evaluate.py` | Collect reviewed host/clone groups, separate train/calibration/test environments, and expert rankings for a frozen cohort before claiming RQ1-RQ4 results. |
| 6 | NOT RUN: learned context remains shadow-only by policy; activation cannot be inferred from a valid manifest | `context.py`, `model_governance.py`, `scoring.py` | Obtain the context-source ADR and real promotion evidence, then carry full prediction uncertainty/provenance through the approved canonical interface. |
| 7 | VERIFIED: observed CVEs and supplied intelligence do not overlap | `intel.py`, fixture/runtime snapshots | Supply provenance-pinned snapshots containing the observed identifiers; distinguish extracted candidates, cached facts and confirmed findings. |
| 8 | VERIFIED: normalized context descriptions are presented as verbatim evidence | `readers/`, `context.py`, `role_model.py`, report provenance | Bind context features to exact source spans/records under the required interface review; keep derived explanations separate and verify I3 on real captures. |
| 9 | VERIFIED: bounded analyst coverage is partial; NOT RUN: useful full-case reasoning, provider switching and durable report integration | `analyst.py`, `explain.py`, `report.py` | Implement and evaluate complete-coverage batching/aggregation and an approved structured-analysis artifact binding; retain explicit omissions/failures and independent prose review. |
| 10 | TESTED WITH MOCKS: full suite is not green, including a concurrent export regression; MISSING: required gate tools | `tests/test_ui.py`, `ui/export.py`, quality tooling | Resolve UI/export direction without weakening assertions, provision the reviewed tools, then rerun lint, format, types, tests and coverage. |

### E. AI1 AUDIT — TRAINED CONTEXT MODEL

VERIFIED: `load_model`, `load_examples`, `extract_features` and `evaluate` on
`models/synthetic-role-model.json` printed:

```text
algorithm=multinomial_logistic_regression; model_hash=d1a13c5e7302dca5
classes=9; features=134; temperature=0.25
train_examples=54; train_groups=54; validation_examples=18; validation_groups=18
label_sources={synthetic:72}; group_overlap=0; vector_overlap=17
train/calibration accuracy=1.0; macro_f1=1.0; coverage=1.0; abstention_rate=0.0
train/calibration expected_calibration_error=3e-07; log_loss=3e-07
```

VERIFIED: features are binary port/protocol/service/product/banner/CPE/OS/TLS
tokens, not IP/hostname identifiers. Calibration is temperature-grid log-loss
selection. The temperature sharpens probabilities; it is not evidence of good
real-world calibration. Distinct declared group IDs do not establish independent
machines, especially with duplicated feature vectors. New label templates no
longer manufacture group IDs from run names.

TESTED WITH MOCKS: grouped cross-validation, hash checking, malformed-input refusal,
reviewer requirements, abstention and shadow non-mutation paths pass their tests.
MISSING: human role labels, a untouched test environment and independently
verified host/clone grouping. Confirmed independent real training groups: none
provided. Canonical deployment use is not justified by this evidence.

**AI1 STATUS: DEMO-ONLY.** The learning implementation is genuine; measured
real-world model quality and research readiness are not established.

### F. AI2 AUDIT — REASONING ANALYST

TESTED WITH MOCKS: a typed `AnalystProvider` can supply a model and source without
rewriting case construction or validation. The default remains loopback-only
Ollama. There is no implemented/configurable remote-provider factory, credential
workflow or cloud approval; injection is not live multi-provider verification.

VERIFIED: the real-capture case now fits 10,970 prompt characters with 21 unique
evidence records and coverage 5/222 findings. Model-facing fields include services,
context, findings, available intelligence, deterministic scores and provenance.
TESTED WITH MOCKS: delimiter/text caps, schema transmission, response-size and
completion guards, unknown citations, unsupported CVEs/numbers and provider
failure isolation passed. Cases are validated before provider access.

NOT RUN: useful live reasoning and full-target aggregation. Correlations are
within one supplied host, not cross-host attack paths. The returned confidence is
conservatively capped for partial coverage, not independently calibrated. Missing
provider service raises `LLMUnavailable`; it does not mutate the assessment or
fabricate an analyst response. Deterministic rationale fallback is a separate path.
Citation membership and numeric whitelists do not prove semantic entailment or
that a recommended version is a verified fix. AI2 is more than a sentence wrapper
in design, but its non-trivial practical value has not been measured.

**AI2 STATUS: USEFUL BUT LIMITED**, describing the implemented structure, not
a successful live-model evaluation.

### G. GENERALISATION AUDIT

VERIFIED: the committed capture README describes an owner-controlled Windows
loopback lab using three IP aliases. No second independently reviewed environment
was supplied. File names, IP counts and repeated fingerprints are not independent
proof of physical-host identity. Production-code search found the hard-coded lab
addresses/names in the explicitly named visual simulation, not a target-specific
branch in the scanner readers or classifier.

VERIFIED: shadow replay reported `(coverage, OOV count, confidence)` of
`(.260870,17,.993953)`, `(.405405,22,.999975)` and `(.347826,15,.854620)`;
none abstained. All three role labels agreed with the rules. Every replay score
used a native fallback, so this run cannot establish the ranking value of learned
roles even if their labels were different.

MISSING: untouched environment evaluation and human per-host role truth.
Correction to earlier audit wording: a `file_share` label on the Juice Shop
alias is not by itself a proven misclassification; the capture also exposes SMB,
and no independently reviewed host-role truth was provided. Likewise, identical
rule/model rankings on this cohort do not prove the model has no value generally.

**GENERALISATION STATUS: NOT PROVEN.**

### H. LIVE PRODUCT FLOW AUDIT

| Stage | Status | Evidence boundary |
| --- | --- | --- |
| New target | BROKEN | TESTED WITH MOCKS: no intake route; only existing named scope targets are accepted. |
| Resolution/identity | BROKEN | NOT RUN: no resolver call chain or original-name/address/time binding; a scanner hostname is not the requested-target record. |
| Authorization | WORKING for tested refusals | TESTED WITH MOCKS: explicit-target/canary checks precede the tested command/import paths; live authorization evidence remains required. |
| Scanning | PARTIAL | TESTED WITH MOCKS: Nmap-first selection, observed web endpoints, partial outcomes and missing-host refusal. MISSING: scanner binaries and real canary evidence. |
| Normalization/storage | WORKING for recorded replay | VERIFIED: 225 findings, raw provenance and retained services; TESTED WITH MOCKS: scan handoff works. No live scanner-to-store proof. |
| Enrichment | PARTIAL | VERIFIED: three extracted IDs, zero matching cached NVD/EPSS records; missing facts are not substituted. |
| Trained context | PARTIAL/shadow only | VERIFIED: classifier inference runs; MISSING: human validation and canonical activation approval. |
| Scoring | WORKING for tested inputs | VERIFIED: two CLI `rank --json` calls exited 0 with byte-identical output for 225 findings. TESTED WITH MOCKS: missing-data, threat and baseline invariants pass. |
| Reasoning | PARTIAL | TESTED WITH MOCKS: grounded structured boundary and failure isolation; NOT RUN: real inference, complete-case aggregation or provider switching. |
| Report/review | PARTIAL | VERIFIED: detailed HTML includes raw paths, feed dates, weights and model hash; TESTED WITH MOCKS: full shadow uncertainty renders. NOT RUN: persisted AI2 artifact; export regression remains. |

The first prompt's additional acceptance requirements are not lost in this table:
MISSING: human-labelled model evaluation, unseen-environment proof and real expert
rankings. VERIFIED: the real replay has no CVE shared across hosts, so it does not
demonstrate the signature two-machine experiment. TESTED WITH MOCKS: model/AI
failures leave canonical records unchanged and all three baseline orders retain
the cohort. NOT RUN: complete uncertainty handoff from AI1 into AI2 and durable
reasoning provenance in a final new-target report.

### I. TEST QUALITY AUDIT

| Class | What is exercised | What it does not prove |
| --- | --- | --- |
| Unit | TESTED WITH MOCKS: pure CVSS/risk/metrics, data validation, source policy and grouping logic | Live scanner/model quality or real labels |
| Mocked integration | TESTED WITH MOCKS: fake scanner executor -> real importer/store; fake model transport; in-memory HTTP -> actual handlers | External tools, local-model behavior or new-target orchestration |
| Fixture integration | VERIFIED: committed Nmap/ZAP captures and curated feed formats -> stored evidence, rankings, run API and report | An unseen environment, fresh scanning or useful intelligence coverage |
| Real integration | NOT RUN: scanners and reasoning runtime unavailable | No claim of live integration success |
| End-to-end | NOT RUN: new target -> final persisted AI2 report | The requested product acceptance remains unmet |

TESTED WITH MOCKS: default pytest guards now reject Python socket connections,
binds, sends and DNS. Five former loopback tests use the existing in-memory
transport without losing assertions. These guards are not a network sandbox for
arbitrary child processes. Synthetic fixtures and corpus rows remain synthetic;
fixture-specific count assertions are regression checks, not generalisation proof.

MISSING: the real Nikto capture, independent labels/rankings, current runtime
feeds, and Ruff/Pyright/pytest-cov. Coverage is unmeasured. Old-UI assertions and
the concurrent offline-export regression remain visible; no skip/xfail or
assertion weakening was used. Final full-suite counts are recorded below after
the last validation run.

### J. REQUIRED FIX PLAN

1. Obtain the target-intake/resolution and assessment-lifecycle contract approval;
  define requested name, reviewed addresses, timestamp, scope decision and scan
  identity without weakening explicit authorization or the canary wall.
2. Reconcile the authoritative store and connect one coordinator through all
  existing stages, retaining failed/partial outcomes and durable report bindings.
3. Human-provision approved scanners, local model artifacts, matching intelligence
  snapshots and genuine lab/canary evidence. An empty file alone is not scan-safety proof.
4. Bind inferred features to raw source spans and distinguish normalized/rule/
  manual descriptions from literal evidence; prove I3 on genuine captures.
5. Collect independent human role/clone groups, calibrate separately and evaluate
  an untouched environment. Obtain the context-source approval before canonical
  activation; retain all prediction uncertainty and model identity.
6. Implement and evaluate complete-case analyst aggregation and persistent
  structured reasoning/report provenance. Add other providers only within an
  explicitly approved data-flow policy; no remote credentials are requested here.
7. Freeze a real same-CVE comparison and cohort, collect expert rankings, and run
  the existing tie-aware baselines/ablations without tuning on the test judgments.
8. Resolve the UI/export regression direction, provision the reviewed quality
  tools, and run the entire gate plus a witnessed new-authorized-target assessment.

**Evaluation infrastructure exists, but research evidence is still missing.**

### Pre-integration verification and publication boundary

TESTED WITH MOCKS: current source and tests were copied to an owned temporary
directory; its working directory, database and generated reports were isolated
from the workspace assessment. The pre-integration command was:

```text
python -m pytest -q --tb=no -ra -p no:cacheprovider
4 failed, 326 passed, 388 subtests passed in 29.88s
FINAL_OFFLINE_SUITE_EXIT 1
```

There were zero skips and no skip reasons. The four retained failures are:

- `TestUiContract.test_decision_hero_leads_with_the_stored_top_priority`
- `TestUiContract.test_decision_hero_names_missing_scores_instead_of_inventing_one`
- `TestUiContract.test_workflow_is_independent_and_does_not_run_analyst`
- `TestUiExport.test_export_is_self_contained`

The first three refer to the previously removed UI. The fourth remains because
concurrent commit 6f51bb5 removed the earlier globe/font export bundling. This
pass does not silently undo that edit, suppress tests or resume mobile work.

MISSING: `python scripts/check.py` reported Ruff lint, Ruff format, Pyright and
pytest-cov unavailable, ending with `GATE INCOMPLETE`. Source coverage is
unmeasured against the required 75% floor. `make`, `nmap`, `nikto`,
`zap-baseline.py` and `ollama` were missing from PATH. Runtime `data/feeds`,
`data/lab/canary.log`, `lab/canary_access.log` and a real Nikto capture were not
provided. VERIFIED: local listener inventory returned `OLLAMA_LISTENERS_11434 0`.

VERIFIED: the separate CLI rank probe invoked `main` twice with
`['--db','data/audit-real-replay.db','rank','--run-id','audit-real-replay','--json']`
and returned `first_exit: 0`, `second_exit: 0`, `byte_identical: true`,
`findings: 225`. Report and route probes returned `DETAILED_REPORT_EXIT 0`,
`new_target_get: 404`, `target_post: 405`, `legacy_run_get: 200`,
`expanded_runs_get: 409`. These are local artifact/handler checks, not live scans.

STATUS: EXTERNAL BLOCKER for live end-to-end acceptance, with remaining code and
research gaps listed in A-J. BRANCH / COMMIT: `audit-no-assumptions`, based on
concurrent checkpoint b3e5dae; the final push hash is verified separately.
GATE: 326 passed / 4 failed / 0 skipped; lint/format/type/coverage prerequisites
missing. BUILT: tested pipeline handoff, stronger inference/scoring boundaries,
offline test enforcement and reproducible real-capture replay.
CHANGED: `vulnassess/` pipeline/model/analyst/scoring/report code, `tests/`
regressions and guard, `finetune/` validation/runbook, and these existing `docs/`.
DECIDED: preserve evidence and explicit failure over fabricated completion;
reject unsafe activation and baselines contaminated by final risk.
DECISIONS: RECHECK-01 through RECHECK-07 in decisions.md.
EVIDENCE: quoted executions above; no scanner, model-service, credential,
download or cloud operation was performed by this recheck.
DEFERRED: mobile work and existing UI direction; missing real inputs and approvals
prevent live/research certification, not the demonstrated local code-path repairs.
NEXT: supply the reviewed runtime/research artifacts and explicit contract
approvals in J, resolve the four retained failures, and run a witnessed new-target
assessment plus the full quality gate before claiming the project is complete.

### Remote model-work integration - 2026-09-23

VERIFIED: `git fetch privwork audit-no-assumptions` reported
`b3e5dae..5b13059`. The incoming b5c4565/b436104/f16e59b changes add feature-family
filtering, grouped family ablations, a model-ablation CLI and optional dataset/
training-run registration. The local unpublished recheck was rebased on top;
no remote commits were dropped and no force push was used.

TESTED WITH MOCKS: the first combined isolated suite returned
`4 failed, 337 passed, 388 subtests passed in 55.07s`, retaining the same four
UI/export failures. Two additional integration regressions then reproduced
`None != 7` for ignored ablation epochs and `real_authorised != synthetic` for
mixed-label provenance. Both were repaired; conflicting family selectors now
fail explicitly. `python -m pytest -q --tb=short -p no:cacheprovider
tests/test_role_training.py tests/test_role_model.py tests/test_model_governance.py`
returned `34 passed, 10 subtests passed in 24.91s`.

The A-J verdict remains NO. The incoming work improves research infrastructure,
not the missing new-target lifecycle, real datasets or live inference. Registered
validation metrics are not an untouched test-set evaluation, and family-ablation
results still require interpretation under the model's abstention/coverage policy.
RECHECK-08 records the integration choice; final combined totals follow below.

TESTED WITH MOCKS: after the incoming-work repairs, the final isolated command
`python -m pytest -q --tb=no -ra -p no:cacheprovider` returned:

```text
4 failed, 340 passed, 388 subtests passed in 58.09s
PUBLISHABLE_SUITE_EXIT 1
```

There are zero skips; the same four UI/export failures listed above remain.
MISSING: the integrated `python scripts/check.py` run again reported Ruff lint,
Ruff format, Pyright and pytest-cov unavailable, ending with `GATE INCOMPLETE`.
No coverage percentage is claimed. This supersedes the earlier test totals, not
the recorded failures or the A-J acceptance verdict.

STATUS: recheck checkpoint ready to publish, live acceptance blocked.
BRANCH / COMMIT: `audit-no-assumptions`, integrating remote 5b13059; final hashes
are checked after push. GATE: 340 passed / 4 failed / 0 skipped; required tools
missing. BUILT / CHANGED: the full backend/research repairs above plus the incoming
model-infrastructure corrections. DECIDED / DECISIONS: preserve incoming work and
honest provenance; RECHECK-01 through RECHECK-08. EVIDENCE: the quoted combined
suite and gate executions. DEFERRED / NEXT: resolve the recorded acceptance,
approval, runtime, research-input and UI/export blockers before certification.
