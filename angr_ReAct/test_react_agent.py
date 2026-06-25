from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from angr_tools import build_agent_tools
from react_agent import (
    DeterministicDemoModel,
    ReActAgent,
    ReActLogger,
    ToolCall,
)


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "crackme"


class ReActAgentTests(unittest.TestCase):
    def test_full_loop_produces_solution_and_three_or_more_rounds(self) -> None:
        _, tools = build_agent_tools(BINARY)
        with tempfile.TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "react.log"
            agent = ReActAgent(
                DeterministicDemoModel(),
                tools,
                logger=ReActLogger(log_path),
            )

            result = agent.run("Find the successful crackme input and avoid traps.")

            self.assertEqual(result["status"], "completed")
            self.assertGreaterEqual(result["tool_rounds"], 3)
            self.assertEqual(result["solution"]["required_prefix"], "AZcE")
            self.assertIn("Success!", result["solution"]["stdout"])

            text_log = log_path.read_text(encoding="utf-8")
            self.assertIn("Thought:", text_log)
            self.assertIn("Action: controlled_explore", text_log)
            self.assertIn("Observation:", text_log)
            self.assertIn("Action: solve_input", text_log)

            jsonl_records = [
                json.loads(line)
                for line in log_path.with_suffix(".jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            tool_records = [
                record
                for record in jsonl_records
                if record["event"] == "tool_round"
            ]
            self.assertEqual(len(tool_records), result["tool_rounds"])

    def test_unknown_tool_becomes_observation_instead_of_crashing(self) -> None:
        _, tools = build_agent_tools(BINARY)
        with tempfile.TemporaryDirectory() as temporary_directory:
            agent = ReActAgent(
                DeterministicDemoModel(),
                tools,
                logger=ReActLogger(Path(temporary_directory) / "react.log"),
            )
            observation = agent._dispatch(
                ToolCall("missing_1", "missing_tool", {})
            )
            self.assertEqual(observation["status"], "tool_error")

    def test_openai_tool_schema_contains_function_parameters(self) -> None:
        _, tools = build_agent_tools(BINARY)
        with tempfile.TemporaryDirectory() as temporary_directory:
            agent = ReActAgent(
                DeterministicDemoModel(),
                tools,
                logger=ReActLogger(Path(temporary_directory) / "react.log"),
            )
            schemas = {
                schema["function"]["name"]: schema
                for schema in agent.tool_schemas
            }
            explore_properties = schemas["controlled_explore"]["function"][
                "parameters"
            ]["properties"]
            self.assertIn("max_steps", explore_properties)
            self.assertIn("target_output", explore_properties)


if __name__ == "__main__":
    unittest.main()
