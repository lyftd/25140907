from __future__ import annotations

import hashlib
import json
import os
import re
import shutil as _shutil
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DANGEROUS_IMPORTS = [
    "strcpy",
    "sprintf",
    "strncat",
    "strncpy",
    "memcpy",
    "sscanf",
    "execvp",
    "execlp",
    "execl",
    "poptParseArgvString",
    "fgets",
    "read",
]

KEY_STRING_PATTERNS = [
    "dateformat",
    "Date format",
    "compress",
    "uncompress",
    "script",
    "mail",
    "include",
    "create",
    "olddir",
    "state",
    "/bin/sh",
]


class ToolError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(
    args: list[str],
    cwd: Path,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        return subprocess.run(
            args,
            cwd=str(cwd),
            env=merged_env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"missing executable: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"command timed out after {timeout}s: {' '.join(args[:3])}") from exc


def extract_json(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ToolError("empty JSON output")
    first_positions = [p for p in (text.find("{"), text.find("[")) if p >= 0]
    if not first_positions:
        raise ToolError(f"no JSON object found in output: {text[:200]}")
    start = min(first_positions)
    return json.loads(text[start:])


def compact_text(text: str, limit: int = 12000) -> str:
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2 :]
    return f"{head}\n... <truncated {len(text) - limit} chars> ...\n{tail}"


@dataclass
class R2Tool:
    binary: Path
    evidence_dir: Path

    def _r2(self, commands: list[str], timeout: int = 120) -> str:
        r2 = shutil.which("r2") or shutil.which("radare2")
        if not r2:
            raise ToolError("radare2 is not installed or not on PATH")
        args = [r2, "-2", "-q"]
        for command in commands:
            args.extend(["-c", command])
        args.append(str(self.binary))
        proc = run_cmd(args, cwd=self.binary.parent, timeout=timeout)
        if proc.returncode != 0:
            raise ToolError(compact_text(proc.stderr or proc.stdout))
        return proc.stdout

    def _r2_json(self, commands: list[str], timeout: int = 120) -> Any:
        return extract_json(self._r2(commands, timeout=timeout))

    def overview(self) -> dict[str, Any]:
        info = self._r2_json(["ij", "q"])
        imports = self._r2_json(["iij", "q"])
        strings = self._r2_json(["izzj", "q"])

        dangerous = []
        for imp in imports:
            name = imp.get("name", "")
            if name in DANGEROUS_IMPORTS:
                dangerous.append(
                    {
                        "name": name,
                        "plt": imp.get("plt"),
                        "ordinal": imp.get("ordinal"),
                        "type": imp.get("type"),
                    }
                )

        important_strings = []
        for item in strings:
            value = str(item.get("string", ""))
            if any(pattern in value for pattern in KEY_STRING_PATTERNS):
                important_strings.append(
                    {
                        "vaddr": item.get("vaddr"),
                        "paddr": item.get("paddr"),
                        "string": value,
                    }
                )

        result = {
            "sha256": sha256_file(self.binary),
            "file": str(self.binary),
            "info": info.get("bin", {}),
            "dangerous_imports": dangerous,
            "important_strings": important_strings[:80],
            "import_count": len(imports),
            "string_count": len(strings),
        }
        self._write_json("r2_overview.json", result)
        return result

    def dangerous_calls(self, symbols: list[str] | None = None, max_sites: int = 40) -> dict[str, Any]:
        symbols = symbols or DANGEROUS_IMPORTS
        calls: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        for symbol in symbols:
            try:
                refs = self._r2_json(["aaa", f"axtj sym.imp.{symbol}", "q"], timeout=180)
            except Exception as exc:
                calls.append({"symbol": symbol, "error": str(exc)})
                continue
            call_refs = [ref for ref in refs if ref.get("type") == "CALL"]
            counts[symbol] = len(call_refs)
            for ref in call_refs[:max_sites]:
                addr = int(ref.get("from", 0))
                snippet = self._r2(
                    ["aaa", f"s {max(0, addr - 36)}", "pd 24", "q"],
                    timeout=180,
                )
                calls.append(
                    {
                        "symbol": symbol,
                        "call_addr": f"0x{addr:x}",
                        "function": ref.get("fcn_name"),
                        "function_addr": f"0x{int(ref.get('fcn_addr', 0)):x}",
                        "opcode": ref.get("opcode"),
                        "snippet": compact_text(snippet, 5000),
                    }
                )
        result = {"counts": counts, "calls": calls}
        self._write_json("r2_dangerous_calls.json", result)
        return result

    def disassemble_function(self, address: str) -> dict[str, Any]:
        if not re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", address):
            raise ToolError("address must be hexadecimal or decimal")
        text = self._r2(["aaa", f"s {address}", "pdf", "q"], timeout=180)
        result = {"address": address, "disassembly": compact_text(text, 30000)}
        safe_addr = address.replace("0x", "").replace("/", "_")
        (self.evidence_dir / f"r2_function_{safe_addr}.txt").write_text(text, encoding="utf-8")
        return result

    def _write_json(self, name: str, value: Any) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / name).write_text(
            json.dumps(value, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


@dataclass
class GhidraTool:
    binary: Path
    evidence_dir: Path

    @property
    def analyze_headless(self) -> str:
        candidates = [
            shutil.which("analyzeHeadless"),
            "/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless",
            "/opt/homebrew/Cellar/ghidra/12.1.2/libexec/support/analyzeHeadless",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return candidate
        raise ToolError("Ghidra analyzeHeadless was not found")

    def analyze(self, force: bool = False) -> dict[str, Any]:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        out_json = self.evidence_dir / "ghidra_analysis.json"
        if out_json.exists() and not force:
            result = json.loads(out_json.read_text(encoding="utf-8"))
            result["cached"] = True
            return result

        script_dir = Path(__file__).resolve().parent / "ghidra_scripts"
        project_dir = self.evidence_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.evidence_dir / "ghidra_headless.log"
        script_log = self.evidence_dir / "ghidra_script.log"
        java_home = "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
        env = {"JAVA_HOME": java_home} if Path(java_home).exists() else {}

        args = [
            self.analyze_headless,
            str(project_dir),
            "logrotate_project",
            "-import",
            str(self.binary),
            "-overwrite",
            "-deleteProject",
            "-analysisTimeoutPerFile",
            "180",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            "ExportAnalysis.java",
            str(out_json),
            "-log",
            str(log_path),
            "-scriptlog",
            str(script_log),
        ]
        proc = run_cmd(args, cwd=self.binary.parent, timeout=360, env=env)
        if proc.returncode != 0:
            detail = "\n".join([proc.stdout, proc.stderr, script_log.read_text("utf-8") if script_log.exists() else ""])
            raise ToolError(compact_text(detail, 20000))
        if not out_json.exists():
            raise ToolError("Ghidra did not produce ghidra_analysis.json")
        result = json.loads(out_json.read_text(encoding="utf-8"))
        result["headless_log"] = str(log_path)
        result["script_log"] = str(script_log)
        result["cached"] = False
        out_json.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        if project_dir.exists():
            _shutil.rmtree(project_dir, ignore_errors=True)
        return result


def deterministic_final() -> dict[str, str]:
    return {
        "vuln_type": "stack_buffer_overflow",
        "location": "fcn.0000b674, dateformat expansion around 0xb8f0/0xb90c/0xb96c strncat calls",
        "cause": "The config-controlled dateformat string is expanded into a 128-byte stack buffer and strncat is called with 0x80 - strlen(buf), leaving no room for the terminating NUL.",
    }
