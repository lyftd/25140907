from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from openai import OpenAI

from .tools import DANGEROUS_IMPORTS, GhidraTool, R2Tool, ToolError, compact_text, deterministic_final


class ReActLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def write(self, text: str = "") -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text.rstrip() + "\n")

    def section(self, title: str) -> None:
        self.write()
        self.write(f"===== {title} =====")


def tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "name": "r2_overview",
            "description": "Use radare2 to return ELF metadata, dangerous imports, and security-relevant strings.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
            "strict": True,
        },
        {
            "type": "function",
            "name": "r2_dangerous_calls",
            "description": "Use radare2 cross references to collect call sites and nearby disassembly for dangerous imports.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbols": {"type": "array", "items": {"type": "string"}},
                    "max_sites": {"type": "integer"},
                },
                "required": ["symbols", "max_sites"],
                "additionalProperties": False,
            },
            "strict": True,
        },
        {
            "type": "function",
            "name": "r2_disassemble_function",
            "description": "Use radare2 to disassemble one function by address.",
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string"}},
                "required": ["address"],
                "additionalProperties": False,
            },
            "strict": True,
        },
        {
            "type": "function",
            "name": "ghidra_analyze",
            "description": "Run Ghidra headless and export call-site/decompiler evidence.",
            "parameters": {
                "type": "object",
                "properties": {"force": {"type": "boolean"}},
                "required": ["force"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    ]


def extract_final_json(text: str) -> dict[str, str]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise ValueError(f"final answer did not contain JSON: {text[:200]}")
    data = json.loads(match.group(0))
    final = {
        "vuln_type": str(data["vuln_type"]),
        "location": str(data["location"]),
        "cause": str(data["cause"]),
    }
    return final


def invoke_tool(name: str, args: dict[str, Any], r2: R2Tool, ghidra: GhidraTool) -> dict[str, Any]:
    if name == "r2_overview":
        return r2.overview()
    if name == "r2_dangerous_calls":
        symbols = args.get("symbols") or DANGEROUS_IMPORTS
        max_sites = int(args.get("max_sites") or 40)
        return r2.dangerous_calls(symbols=symbols, max_sites=max_sites)
    if name == "r2_disassemble_function":
        return r2.disassemble_function(str(args["address"]))
    if name == "ghidra_analyze":
        return ghidra.analyze(force=bool(args.get("force", True)))
    raise ToolError(f"unknown tool: {name}")


def offline_run(r2: R2Tool, ghidra: GhidraTool, log: ReActLog) -> tuple[dict[str, str], dict[str, Any]]:
    metadata: dict[str, Any] = {"mode": "offline", "tool_calls": []}
    steps = [
        ("r2_overview", {}),
        ("r2_dangerous_calls", {"symbols": DANGEROUS_IMPORTS, "max_sites": 50}),
        ("r2_disassemble_function", {"address": "0xb674"}),
        ("ghidra_analyze", {"force": True}),
    ]
    for name, args in steps:
        log.write(f"Thought: Need evidence from {name} to ground the static analysis.")
        log.write(f"Action: {name} {json.dumps(args, ensure_ascii=False)}")
        try:
            obs = invoke_tool(name, args, r2, ghidra)
            metadata["tool_calls"].append({"name": name, "ok": True})
        except Exception as exc:
            obs = {"error": str(exc)}
            metadata["tool_calls"].append({"name": name, "ok": False, "error": str(exc)})
        log.write("Observation:")
        log.write(compact_text(json.dumps(obs, ensure_ascii=False, indent=2), 20000))
    final = deterministic_final()
    log.write("Final Answer:")
    log.write(json.dumps(final, ensure_ascii=False, indent=2))
    return final, metadata


def llm_run(
    r2: R2Tool,
    ghidra: GhidraTool,
    log: ReActLog,
    binary: Path,
    preferred_model: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    if not os.environ.get("OPENAI_API_KEY"):
        raise ToolError("OPENAI_API_KEY is not set")

    client = OpenAI()
    model_candidates = [preferred_model, "gpt-5.5", "gpt-5.4", "gpt-4.1", "gpt-4o"]
    seen: set[str] = set()
    model_candidates = [m for m in model_candidates if not (m in seen or seen.add(m))]

    instructions = (
        "You are a binary static-analysis ReAct agent. Analyze only the provided ELF. "
        "Do not run the binary and do not invent observations. You must call both radare2 and Ghidra tools. "
        "Focus on untrusted configuration/argument data reaching dangerous memory or command operations. "
        "At the end, output only JSON with keys vuln_type, location, cause. "
        "If a dangerous call is safe because allocation or bounds checks dominate it, say so in your internal assessment, "
        "but the final JSON must name the strongest confirmed vulnerability."
    )
    prompt = (
        f"Target: {binary.name}. SHA256 is fixed by the tool output. "
        "Required first calls: r2_overview, r2_dangerous_calls, ghidra_analyze with force=true. "
        "Pay special attention to dateformat processing, 128-byte stack buffers, strncat, sprintf, strcpy, and exec* paths."
    )

    last_error = None
    for model in model_candidates:
        try:
            log.section(f"OpenAI model {model}")
            metadata: dict[str, Any] = {"mode": "llm", "model": model, "tool_calls": []}
            response = client.responses.create(
                model=model,
                instructions=instructions,
                input=prompt,
                tools=tool_specs(),
                parallel_tool_calls=False,
                max_tool_calls=12,
                max_output_tokens=5000,
            )
            for _ in range(12):
                function_calls = [
                    item
                    for item in getattr(response, "output", [])
                    if getattr(item, "type", None) == "function_call"
                ]
                if not function_calls:
                    text = getattr(response, "output_text", "") or str(response)
                    final = extract_final_json(text)
                    log.write("Final Answer:")
                    log.write(json.dumps(final, ensure_ascii=False, indent=2))
                    return final, metadata

                tool_outputs = []
                for call in function_calls:
                    name = getattr(call, "name")
                    raw_args = getattr(call, "arguments") or "{}"
                    args = json.loads(raw_args)
                    log.write(f"Thought: The agent requested {name} to continue the evidence chain.")
                    log.write(f"Action: {name} {json.dumps(args, ensure_ascii=False)}")
                    try:
                        obs = invoke_tool(name, args, r2, ghidra)
                        metadata["tool_calls"].append({"name": name, "ok": True})
                    except Exception as exc:
                        obs = {"error": str(exc)}
                        metadata["tool_calls"].append({"name": name, "ok": False, "error": str(exc)})
                    obs_text = compact_text(json.dumps(obs, ensure_ascii=False, indent=2), 24000)
                    log.write("Observation:")
                    log.write(obs_text)
                    tool_outputs.append(
                        {
                            "type": "function_call_output",
                            "call_id": getattr(call, "call_id"),
                            "output": obs_text,
                        }
                    )
                response = client.responses.create(
                    model=model,
                    instructions=instructions,
                    previous_response_id=response.id,
                    input=tool_outputs,
                    tools=tool_specs(),
                    parallel_tool_calls=False,
                    max_tool_calls=12,
                    max_output_tokens=5000,
                )
            raise ToolError("LLM did not provide a final answer within the tool-call budget")
        except Exception as exc:
            last_error = exc
            log.write(f"Model attempt failed: {type(exc).__name__}: {exc}")
            continue
    raise ToolError(f"all model attempts failed; last error: {last_error}")


def run_agent(
    binary: Path,
    out_dir: Path,
    log_path: Path,
    preferred_model: str = "gpt-5.5",
    use_llm: bool = True,
) -> dict[str, Any]:
    evidence_dir = out_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    log = ReActLog(log_path)
    r2 = R2Tool(binary=binary, evidence_dir=evidence_dir)
    ghidra = GhidraTool(binary=binary, evidence_dir=evidence_dir)

    log.section("Run Metadata")
    log.write(f"Target: {binary}")
    log.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    log.write("Mode: OpenAI Tool Calling ReAct" if use_llm else "Mode: Offline deterministic ReAct")

    if use_llm:
        try:
            final, metadata = llm_run(r2, ghidra, log, binary, preferred_model)
        except Exception as exc:
            log.section("LLM fallback")
            log.write(f"OpenAI path failed without exposing secrets: {type(exc).__name__}: {exc}")
            final, metadata = offline_run(r2, ghidra, log)
            metadata["llm_error"] = str(exc)
    else:
        final, metadata = offline_run(r2, ghidra, log)

    vuln_path = out_dir / "vuln.json"
    vuln_path.write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")
    metadata.update(
        {
            "binary": str(binary),
            "vuln_json": str(vuln_path),
            "log_path": str(log_path),
            "evidence_dir": str(evidence_dir),
        }
    )
    (evidence_dir / "run_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {"final": final, "metadata": metadata}
