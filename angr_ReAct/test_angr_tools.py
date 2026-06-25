from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from angr_tools import AngrToolbox, build_agent_tools


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "crackme"


class AngrToolboxTests(unittest.TestCase):
    def test_controlled_exploration_and_input_solving(self) -> None:
        toolbox = AngrToolbox(BINARY)

        for _ in range(10):
            observation = toolbox.controlled_explore(max_steps=4)
            if observation["status"] == "target_found":
                break

        self.assertEqual(observation["status"], "target_found")
        self.assertGreaterEqual(observation["stash_sizes"]["avoid"], 1)

        solution = toolbox.solve_input()
        self.assertEqual(solution["status"], "solved")
        self.assertEqual(solution["required_prefix"], "AZcE")

        process = subprocess.run(
            [str(BINARY)],
            input=solution["concrete_input"] + "\n",
            text=True,
            capture_output=True,
            timeout=3,
            check=True,
        )
        self.assertIn("Success! Flag is found.", process.stdout)

    def test_langchain_tool_metadata(self) -> None:
        _, tools = build_agent_tools(BINARY)
        self.assertEqual(
            [agent_tool.name for agent_tool in tools],
            ["controlled_explore", "solve_input"],
        )
        self.assertIn("max_steps", tools[0].args)
        self.assertIn("stash", tools[1].args)


if __name__ == "__main__":
    unittest.main()
