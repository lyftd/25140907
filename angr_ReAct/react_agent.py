"""ReAct loop that connects a tool-calling model to the angr tools."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from langchain_core.tools import BaseTool
from openai import OpenAI


SYSTEM_PROMPT = """\
You are the decision layer of an automated reverse-engineering agent.

Goal:
- Guide angr toward a state whose stdout contains "Success!".
- Avoid states related to "trapped", gadget_trap, or dead loops.
- Once a target state exists, call solve_input and report the concrete input,
  required prefix, and stdout evidence.

Operating rules:
- Use exactly one tool call per response.
- Use controlled_explore with max_steps=4 so progress is observable over
  multiple bounded rounds.
- Inspect each Observation before choosing the next Action.
- Before a tool call, put a short high-level decision summary in the response
  content. Do not provide hidden chain-of-thought or detailed private reasoning.
- Do not claim success until solve_input returns status "solved".
- After solving, respond without a tool call and summarize the result.
"""


@dataclass(frozen=True)
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]

    def as_message_value(self) -> dict[str, Any]:
        return {
            "id": self.call_id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": json.dumps(self.arguments, ensure_ascii=True),
            },
        }


@dataclass(frozen=True)
class ModelReply:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)

    def as_message(self) -> dict[str, Any]:
        message: dict[str, Any] = {
            "role": "assistant",
            "content": self.content or None,
        }
        if self.tool_calls:
            message["tool_calls"] = [
                tool_call.as_message_value() for tool_call in self.tool_calls
            ]
        return message


class ToolCallingModel(Protocol):
    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelReply:
        """Return the next assistant message and optional tool call."""


class OpenAIChatModel:
    """Small adapter around OpenAI-compatible Chat Completions."""

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        if not model:
            raise ValueError("model must not be empty")
        client_options: dict[str, Any] = {}
        if api_key:
            client_options["api_key"] = api_key
        if base_url:
            client_options["base_url"] = base_url
        self.model = model
        self.client = OpenAI(**client_options)

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelReply:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0,
        )
        message = response.choices[0].message
        parsed_calls = []
        for tool_call in message.tool_calls or []:
            try:
                arguments = json.loads(tool_call.function.arguments or "{}")
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Model returned invalid JSON for {tool_call.function.name}: "
                    f"{tool_call.function.arguments}"
                ) from error
            if not isinstance(arguments, dict):
                raise ValueError(
                    f"Tool arguments for {tool_call.function.name} must be an object"
                )
            parsed_calls.append(
                ToolCall(
                    call_id=tool_call.id,
                    name=tool_call.function.name,
                    arguments=arguments,
                )
            )
        return ModelReply(content=message.content or "", tool_calls=parsed_calls)


class ReActLogger:
    """Persist human-readable and machine-readable ReAct traces."""

    def __init__(self, text_path: str | Path) -> None:
        self.text_path = Path(text_path)
        self.jsonl_path = self.text_path.with_suffix(".jsonl")
        self.text_path.parent.mkdir(parents=True, exist_ok=True)
        self.text_path.write_text("", encoding="utf-8")
        self.jsonl_path.write_text("", encoding="utf-8")

    def start(self, goal: str) -> None:
        self._append_text(f"Goal: {goal}\n")
        self._append_json({"event": "goal", "goal": goal})

    def tool_round(
        self,
        round_number: int,
        thought: str,
        tool_call: ToolCall,
        observation: dict[str, Any],
    ) -> None:
        rendered_observation = json.dumps(
            observation,
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        )
        self._append_text(
            f"\n=== Round {round_number} ===\n"
            f"Thought: {thought}\n"
            f"Action: {tool_call.name}\n"
            f"Action Input: "
            f"{json.dumps(tool_call.arguments, ensure_ascii=True, sort_keys=True)}\n"
            f"Observation:\n{rendered_observation}\n"
        )
        self._append_json(
            {
                "event": "tool_round",
                "round": round_number,
                "thought": thought,
                "action": tool_call.name,
                "action_input": tool_call.arguments,
                "observation": observation,
            }
        )

    def final(self, content: str) -> None:
        self._append_text(f"\n=== Final Answer ===\n{content}\n")
        self._append_json({"event": "final", "content": content})

    def _append_text(self, text: str) -> None:
        with self.text_path.open("a", encoding="utf-8") as stream:
            stream.write(text)

    def _append_json(self, payload: dict[str, Any]) -> None:
        with self.jsonl_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=True) + "\n")


class ReActAgent:
    """Dispatch model actions to tools and feed observations back to the model."""

    def __init__(
        self,
        model: ToolCallingModel,
        tools: list[BaseTool],
        *,
        logger: ReActLogger,
        max_model_turns: int = 12,
    ) -> None:
        if max_model_turns < 1:
            raise ValueError("max_model_turns must be positive")
        self.model = model
        self.tools = {agent_tool.name: agent_tool for agent_tool in tools}
        if len(self.tools) != len(tools):
            raise ValueError("Tool names must be unique")
        self.tool_schemas = [self._tool_schema(agent_tool) for agent_tool in tools]
        self.logger = logger
        self.max_model_turns = max_model_turns

    def run(self, goal: str) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": goal},
        ]
        self.logger.start(goal)
        tool_round = 0
        last_solution: dict[str, Any] | None = None

        for _ in range(self.max_model_turns):
            reply = self.model.complete(messages, self.tool_schemas)
            messages.append(reply.as_message())

            if not reply.tool_calls:
                final_content = reply.content.strip() or "Model returned no final text."
                self.logger.final(final_content)
                return {
                    "status": "completed" if last_solution else "stopped_without_solution",
                    "final_answer": final_content,
                    "solution": last_solution,
                    "tool_rounds": tool_round,
                    "log_path": str(self.logger.text_path),
                    "jsonl_path": str(self.logger.jsonl_path),
                }

            thought = reply.content.strip() or "No decision summary supplied."
            for tool_call in reply.tool_calls:
                tool_round += 1
                observation = self._dispatch(tool_call)
                if (
                    tool_call.name == "solve_input"
                    and observation.get("status") == "solved"
                ):
                    last_solution = observation
                self.logger.tool_round(
                    tool_round,
                    thought,
                    tool_call,
                    observation,
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.call_id,
                        "content": json.dumps(observation, ensure_ascii=True),
                    }
                )

        final_content = (
            f"Stopped after {self.max_model_turns} model turns without a final answer."
        )
        self.logger.final(final_content)
        return {
            "status": "turn_limit_reached",
            "final_answer": final_content,
            "solution": last_solution,
            "tool_rounds": tool_round,
            "log_path": str(self.logger.text_path),
            "jsonl_path": str(self.logger.jsonl_path),
        }

    def _dispatch(self, tool_call: ToolCall) -> dict[str, Any]:
        agent_tool = self.tools.get(tool_call.name)
        if agent_tool is None:
            return {
                "status": "tool_error",
                "error": f"Unknown tool: {tool_call.name}",
                "available_tools": sorted(self.tools),
            }
        try:
            result = agent_tool.invoke(tool_call.arguments)
        except Exception as error:
            return {
                "status": "tool_error",
                "error_type": type(error).__name__,
                "error": str(error),
            }
        if isinstance(result, dict):
            return result
        return {"status": "ok", "result": result}

    @staticmethod
    def _tool_schema(agent_tool: BaseTool) -> dict[str, Any]:
        if agent_tool.args_schema is None:
            parameters: dict[str, Any] = {
                "type": "object",
                "properties": {},
            }
        else:
            parameters = agent_tool.args_schema.model_json_schema()
        return {
            "type": "function",
            "function": {
                "name": agent_tool.name,
                "description": agent_tool.description,
                "parameters": parameters,
            },
        }


class DeterministicDemoModel:
    """Offline model double used to verify the complete ReAct dispatcher."""

    def __init__(self) -> None:
        self.call_number = 0

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelReply:
        del tools
        self.call_number += 1
        last_observation = self._last_observation(messages)

        if last_observation is None or last_observation.get("status") == (
            "step_limit_reached"
        ):
            return self._call(
                "The bounded search has not reached the target, so I will "
                "continue for four more steps while avoiding trap states.",
                "controlled_explore",
                {
                    "max_steps": 4,
                    "target_output": "Success!",
                    "avoid_output": "trapped",
                    "max_active_states": 64,
                },
            )
        if last_observation.get("status") == "target_found":
            return self._call(
                "A target state now contains the success output, so I will "
                "concretize its symbolic password.",
                "solve_input",
                {"state_index": 0, "stash": "found"},
            )
        if last_observation.get("status") == "solved":
            concrete = last_observation["concrete_input"]
            prefix = last_observation["required_prefix"]
            stdout = last_observation["stdout"].strip()
            return ModelReply(
                content=(
                    f"Solved input: {concrete}. Required prefix: {prefix}. "
                    f"Execution evidence: {stdout}"
                )
            )
        return ModelReply(
            content=f"Stopped because the last observation was: {last_observation}"
        )

    def _call(
        self,
        thought: str,
        name: str,
        arguments: dict[str, Any],
    ) -> ModelReply:
        return ModelReply(
            content=thought,
            tool_calls=[
                ToolCall(
                    call_id=f"demo_call_{self.call_number}",
                    name=name,
                    arguments=arguments,
                )
            ],
        )

    @staticmethod
    def _last_observation(
        messages: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        for message in reversed(messages):
            if message["role"] == "tool":
                return json.loads(message["content"])
        return None
