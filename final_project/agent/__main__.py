from __future__ import annotations

import argparse
import json
from pathlib import Path

from .react_agent import run_agent
from .report import build_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ReAct static-analysis agent.")
    parser.add_argument("--binary", default="./logrotate", help="Path to the ELF binary.")
    parser.add_argument("--out", default="output", help="Output directory.")
    parser.add_argument("--log", default="logs/run.txt", help="ReAct log path.")
    parser.add_argument("--model", default="gpt-5.5", help="Preferred OpenAI model.")
    parser.add_argument("--no-llm", action="store_true", help="Use deterministic offline finalization.")
    parser.add_argument("--skip-report", action="store_true", help="Do not generate the PDF report.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    binary = Path(args.binary).resolve()
    out_dir = Path(args.out).resolve()
    log_path = Path(args.log).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    result = run_agent(
        binary=binary,
        out_dir=out_dir,
        log_path=log_path,
        preferred_model=args.model,
        use_llm=not args.no_llm,
    )

    if not args.skip_report:
        report_path = build_report(
            binary=binary,
            out_dir=out_dir,
            log_path=log_path,
            final_result=result["final"],
            metadata=result["metadata"],
        )
        result["metadata"]["report_path"] = str(report_path)
        metadata_path = out_dir / "evidence" / "run_metadata.json"
        metadata_path.write_text(
            json.dumps(result["metadata"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    print(json.dumps(result["final"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
