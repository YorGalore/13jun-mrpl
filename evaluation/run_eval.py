from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from backend.config import DEFAULT_MODEL
from backend.sources.sparql import kg_retrieve
from evaluation.questions import TEST_CASES

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = Path(__file__).resolve().parent
CSV_PATH = OUT_DIR / "evaluation_results.csv"
JSON_PATH = OUT_DIR / "evaluation_results.json"

_PREVIEW = 220 


def _evaluate_one(case: Dict[str, str], model: str) -> Dict[str, Any]:
    question = case["question"]
    start = time.perf_counter()
    try:
        res = kg_retrieve(question, model=model)
        latency = round(time.perf_counter() - start, 3)
        return {
            "question": question,
            "category": case.get("category", ""),
            "expect": case.get("expect", ""),
            "method": res["method"],
            "row_count": res["row_count"],
            "columns": ", ".join(res["columns"]),
            "status": "success" if res["ok"] else "empty",
            "latency": latency,
            "sparql": res["sparql"][:_PREVIEW].replace("\n", " "),
            "context_preview": res["context"][:_PREVIEW].replace("\n", " "),
            "error": "",
        }
    except Exception as e:  # kg_retrieve tak pernah raise; jaring pengaman saja
        return {
            "question": question,
            "category": case.get("category", ""),
            "expect": case.get("expect", ""),
            "method": "",
            "row_count": 0,
            "columns": "",
            "status": "failed",
            "latency": round(time.perf_counter() - start, 3),
            "sparql": "",
            "context_preview": "",
            "error": str(e),
        }


def _summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(results) or 1
    success = sum(1 for r in results if r["status"] == "success")
    empty = sum(1 for r in results if r["status"] == "empty")
    failed = sum(1 for r in results if r["status"] == "failed")
    methods: Dict[str, int] = {}
    for r in results:
        methods[r["method"] or "n/a"] = methods.get(r["method"] or "n/a", 0) + 1
    avg_latency = round(sum(r["latency"] for r in results) / n, 3)
    return {
        "total": len(results),
        "success": success,
        "empty": empty,
        "failed": failed,
        "success_rate": round(success / n, 3),
        "method_distribution": methods,
        "avg_latency_sec": avg_latency,
    }


def _save(results: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    JSON_PATH.write_text(
        json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    cols = ["question", "category", "expect", "method", "row_count", "columns",
            "status", "latency", "sparql", "context_preview", "error"]
    try:
        import pandas as pd  # tercantum di backend/requirements.txt
        pd.DataFrame(results, columns=cols).to_csv(CSV_PATH, index=False)
    except Exception:
        import csv
        with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k, "") for k in cols})


def evaluate(model: str = DEFAULT_MODEL) -> Dict[str, Any]:
    print(f"[eval] NL2SPARQL pada {len(TEST_CASES)} pertanyaan (model={model})\n")
    results = [_evaluate_one(c, model) for c in TEST_CASES]

    for i, r in enumerate(results, 1):
        print(f"{i:>2}. [{r['status']:^7}] method={r['method'] or '-':<16} "
              f"rows={r['row_count']:<3} {r['latency']}s  {r['question']}")

    summary = _summarize(results)
    print("\n=== Ringkasan ===")
    print(f"sukses {summary['success']}/{summary['total']} "
          f"(rate {summary['success_rate']}), empty {summary['empty']}, failed {summary['failed']}")
    print(f"distribusi metode : {summary['method_distribution']}")
    print(f"latency rata-rata : {summary['avg_latency_sec']}s")

    _save(results, summary)
    print(f"\n[eval] Hasil ditulis ke:\n  {CSV_PATH}\n  {JSON_PATH}")
    return {"summary": summary, "results": results}


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluasi NL2SPARQL (Issue #3).")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="Model LLM untuk jalur nl2sparql (mis. gemini:gemini-2.5-flash).")
    args = parser.parse_args(argv)
    evaluate(model=args.model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())