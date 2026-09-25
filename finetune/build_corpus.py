"""Build analyst fine-tune examples from stored cases and supplied supervision.

Each corpus example pairs the exact prompt the product sends to the local model
with a supervision assessment for the same case. Supervision assessments are
authored offline (a human or a stronger reviewer) and stored under
``finetune/assessments/``. Before an example is written, the assessment is put
through the same citation, CVE and numeric-fact checks used at inference time.
These checks do not establish human authorship, semantic truth, independent
evaluation, or a completed training run. Nothing is synthesized here.

Usage:

    python finetune/build_corpus.py --run reallab --host 127.0.0.1 \
        --assessment finetune/assessments/reallab-127.0.0.1.json \
        --out finetune/corpus/sft.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulnassess import analyst  # noqa: E402
from vulnassess.errors import VulnAssessError  # noqa: E402
from vulnassess.ui.reader import ReadOnlyStore  # noqa: E402


def build_example(db: str | Path, run_id: str, host_ip: str, assessment: dict) -> dict:
    """Package one stored case with shape- and fact-checked supervision."""
    with ReadOnlyStore(db) as store:
        payload = store.run(run_id)
    case, evidence, alias_map = analyst.build_case(payload, host_ip)
    validated = analyst.validate_analysis(
        assessment,
        set(alias_map),
        {item["id"] for item in evidence},
    )
    analyst.validate_grounding(validated, case, evidence)
    return {
        "prompt": analyst.build_prompt(case, evidence, len(alias_map)),
        "response": json.dumps(validated, separators=(",", ":"), ensure_ascii=True),
        "meta": {
            "run_id": run_id,
            "host_ip": host_ip,
            "findings": len(alias_map),
            "evidence": len(evidence),
            "base_model": analyst.DEFAULT_MODEL,
            "citation_note": "finding_ids are case aliases F<n>; the product maps them back to canonical ids",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "Build analyst corpus").splitlines()[0]
    )
    parser.add_argument("--db", default="data/vulnassess.db")
    parser.add_argument("--run", required=True)
    parser.add_argument("--host", required=True, dest="host_ip")
    parser.add_argument("--assessment", required=True, type=Path)
    parser.add_argument("--out", default="finetune/corpus/sft.jsonl", type=Path)
    args = parser.parse_args(argv)

    assessment = json.loads(args.assessment.read_text(encoding="utf-8"))
    example = build_example(args.db, args.run, args.host_ip, assessment)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(example, ensure_ascii=True) + "\n")
    meta = example["meta"]
    print(
        f"validated and appended: {args.run}/{args.host_ip} "
        f"({meta['findings']} findings, {meta['evidence']} evidence records) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except VulnAssessError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        sys.exit(2)
