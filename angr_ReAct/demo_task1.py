"""Demonstrate the two angr tools without requiring an LLM."""

from __future__ import annotations

import json
from pathlib import Path

from angr_tools import build_agent_tools


def main() -> None:
    binary = Path(__file__).with_name("crackme")
    _, tools = build_agent_tools(binary)
    explore_tool, solve_tool = tools

    for round_number in range(1, 11):
        observation = explore_tool.invoke({"max_steps": 4})
        print(f"\nRound {round_number}: controlled_explore")
        print(json.dumps(observation, indent=2, ensure_ascii=True))
        if observation["status"] == "target_found":
            break
    else:
        raise RuntimeError("The target was not found within 40 execution steps")

    solution = solve_tool.invoke({})
    print("\nsolve_input")
    print(json.dumps(solution, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
