# Increment 1: AI boundary

This change hardens the existing analyst and CLI explanation calls. It does **not** add a
planner, scanner tool use, CVE ranking, or any later-increment agent.

## Design

- The scope engine and stored scoring records remain outside the model boundary. Models
  receive bounded, escaped evidence envelopes and server-issued IDs. A separate system
  message explicitly denies authority to anything inside those envelopes.
- The analyst now requests `analyst.v2` JSON. Every model-authored prose field has one claim
  metadata entry keyed by its field path. Entries include a label, confidence, finding
  and evidence IDs, at least one quote, an optional verification action, and an optional
  score. The smaller CLI rewriter uses `rationale.v1` JSON with one such claim.
- Validation is all-or-nothing: schema and identifier checks, content-aligned quotes,
  citation scoping to each finding, allowed CVEs and numbers, and exact equality for
  any model-stated canonical score. Hypotheses need a verification action. A validator
  for multiple samples rejects disagreement; this increment does not request extra
  samples. No partially validated analyst result is returned.
- A model sentinel, if returned, rejects the run and flags evidence IDs containing
  recognized instruction-breakout syntax. The prompt strips recognized role/control
  tokens and escapes markup, but these are defense-in-depth, not a proof that prompt
  injection is impossible.
- Every attempted model generation appends a hash-only audit record to
  `data/ai_audit.jsonl` (ignored by Git). It records model, stage, prompt/input/output
  hashes where a response exists, decision, and outcome. No prompt or evidence body is
  stored in the audit file. A transport failure before a response has a null output
  hash, not a fictional one.
- Rejected analyst output becomes **Needs review** in the workflow. Rejected CLI
  rewording records `needs_review` and displays only the deterministic sentence.

## Compatibility and limits

The model response format is intentionally incompatible with legacy `analyst.v1`
responses and existing hand-authored supervision files. Those files must be upgraded
and revalidated before fine-tuning; the corpus builder now rejects the old format.
No live provider call or attack-site scan is used as evidence of this increment's
correctness. Quote alignment proves text appears in the bounded server evidence record;
it does not prove the model's interpretation is true. Multi-sample generation,
independent critic review, and agents belong to later increments.

## Verification

`tests/adversarial/` covers prompt breakouts, canary rejection, fabricated quotes,
invented CVEs and finding IDs, score mismatch, malformed or unknown schemas,
hypotheses without verification actions, and conflicting samples. The full test suite,
lint, type check, and coverage gate must pass before this increment is considered
verified. No later increment is included in this change.
