# AI assessment upgrade roadmap

## Current behavior

The live path authorizes a pinned IP, runs one bounded Nmap scan, derives context,
and sends its evidence to one analyst model. Nikto and Nessus are separate evidence
paths; the live Nmap button does not run them. Recorded assessments can contain
normalized findings, NVD, EPSS, KEV and deterministic scores. The model can explain
and suggest one investigation, but it cannot request new evidence or change scope,
canonical findings or scores.

The model request is bounded, and output passes schema, ID, number, context and
unknown-control checks. The workflow shows actual progress events. This is a useful
foundation, but it is not an autonomous assessment system.

## Changes in this increment

- An action, correlation or investigation naming a finding must cite evidence
  belonging to that finding: its scanner observation, attached intelligence or
  stored score. A different service citation cannot make the claim valid.
- The decision frame now contains explicit evidence-coverage limits and unknown
  controls. The workflow displays those limits and the recorded scanner coverage.
- A coverage-review progress stage runs after the evidence case is built. The review
  is included in the model request and visible before a model response exists.

These checks establish evidence links. They cannot prove that arbitrary prose is
semantically true; the proposed verifier below must be evaluated against labeled
examples before it can be treated as such.

## Recommended implementation order

| Priority | Capability | Required behavior | Acceptance evidence |
| --- | --- | --- | --- |
| 1 | Evidence request and scan plan | AI proposes typed, bounded checks from prior evidence. A human confirms the target and plan; the deterministic scope gate pins all addresses. | A proposed tool call cannot execute before approval, change the pinned target or exceed the scan budget. Every skipped tool has a reason. |
| 2 | Scanner integration | Connect available tools through a typed runner, with timeouts, execution records and normalized output. Add Nikto for authorized web services and Nessus imports or a configured Nessus API path. Evaluate Nuclei and httpx only after their scope and output contracts are defined. | A run records exact tools, commands or import identifiers, timing, status, raw output references and parsed evidence. A missing tool is never shown as complete. |
| 3 | Evidence and context reasoning | AI proposes resolutions for conflicting banners and context signals. Store the original observations and an explicit confidence and reason for each proposal. | Conflicting evidence remains visible; a proposed resolution cannot overwrite scanner records or approved asset metadata. |
| 4 | CVE and exploitability hypotheses | AI may suggest candidate CVEs, prerequisites, reachability and possible chains beside deterministic matching and scoring. | Every candidate has supporting observations, source dates, a rejection path and a verification action. A candidate alone cannot become a confirmed finding or alter a score. |
| 5 | Selective critique | For high-impact or low-confidence cases, a second pass challenges claims and coverage against the original evidence. A deterministic verifier enforces IDs, source binding and numbers. | Unsupported claims are rejected or marked for human review; cost and latency are measured against the one-call baseline. |
| 6 | Memory and evaluation | Retrieve verified prior runs for the same authorized asset, then compare changes. Build a labeled corpus of scans, true findings, false positives, rankings and missing evidence. | Holdout results show improved precision, recall, ranking and citation correctness on unseen targets. New runs do not automatically become training labels. |

## Shared constraints

- AI proposes; deterministic code authorizes, launches scoped tools, parses strict
  formats, calculates scores and persists canonical records.
- Tool calls are typed requests to a runner with an allowlist, pinned target,
  per-tool limits and an approval record. Untrusted scan output cannot supply
  instructions to that runner.
- Retrieval should start with versioned vendor advisories and primary vulnerability
  records. Each retrieved statement needs source, date and license handling.
- Model decisions need request and response hashes, model identifier, evidence IDs,
  validation outcome, timing and cost. Secrets and full prompts must not enter logs.
- Use additional model calls only where measured benefit exceeds the rate-limit and
  latency cost. A debate between several models is not itself proof of correctness.
- A prompt-injection canary can be a diagnostic signal, but cannot serve as the
  security boundary. Typed tool permissions and output validation remain mandatory.

## Evaluation gate before calling this context aware

Test on held-out, human-labeled targets that differ from the development fixtures.
Report citation precision, unsupported-claim rate, false-positive rate, missed
findings, priority ranking quality, useful verification actions, per-run cost and
latency. Include zero-finding scans and contradictory evidence. Compare each new
capability with the current deterministic-plus-one-model baseline. A feature that
only makes the workflow look more active does not pass this gate.
