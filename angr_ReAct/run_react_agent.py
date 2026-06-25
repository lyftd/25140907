"""Run the ReAct angr agent with an OpenAI-compatible model."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from angr_tools import build_agent_tools
from react_agent import (
    DeterministicDemoModel,
    OpenAIChatModel,
    ReActAgent,
    ReActLogger,
)


DEFAULT_GOAL = """\
Analyze the crackme with angr and find an input that reaches output containing
"Success!". Avoid any path related to "trapped" or the deliberate dead loop.
Use bounded exploration, then solve and report the concrete input, its required
prefix, and the successful stdout evidence.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(__file__).with_name("crackme"),
    )
    parser.add_argument("--goal", default=DEFAULT_GOAL)
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL"))
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL"))
    parser.add_argument(
        "--log",
        type=Path,
        default=Path(__file__).with_name("logs") / "react_run.log",
    )
    parser.add_argument(
        "--offline-demo",
        action="store_true",
        help="Use a deterministic model double to test the loop without an API call.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    _, tools = build_agent_tools(args.binary)
    if args.offline_demo:
        model = DeterministicDemoModel()
    else:
        if not args.model:
            raise SystemExit(
                "Set OPENAI_MODEL or pass --model with a Tool Calling model."
            )
        model = OpenAIChatModel(
            args.model,
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=args.base_url,
        )

    agent = ReActAgent(
        model,
        tools,
        logger=ReActLogger(args.log),
    )
    result = agent.run(args.goal.strip())
    print(json.dumps(result, indent=2, ensure_ascii=True))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
