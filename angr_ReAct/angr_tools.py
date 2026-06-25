"""Stateful angr tools for the ReAct crackme experiment."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import angr
import claripy
from langchain_core.tools import BaseTool, tool


class AngrToolbox:
    """Own an angr project and preserve symbolic execution state across calls."""

    def __init__(
        self,
        binary_path: str | Path,
        *,
        input_length: int = 9,
        entry_symbol: str = "check_password",
    ) -> None:
        self.binary_path = Path(binary_path).resolve()
        if not self.binary_path.is_file():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
        if input_length < 1:
            raise ValueError("input_length must be positive")

        self.input_length = input_length
        self.project = angr.Project(str(self.binary_path), auto_load_libs=False)
        self._symbols = self._collect_symbols()
        self.entry_address = self._symbol_address(entry_symbol)
        self.trap_address = self._optional_symbol_address("gadget_trap")
        self.input_bytes: list[claripy.ast.BV] = []
        self.simgr: angr.SimulationManager
        self.total_steps = 0
        self.reset()

    def reset(self) -> dict[str, Any]:
        """Reset execution to a symbolic call of check_password."""
        self.input_bytes = [
            claripy.BVS(f"password_{index}", 8)
            for index in range(self.input_length)
        ]
        password = claripy.Concat(*self.input_bytes, claripy.BVV(0, 8))
        buffer_address = 0x70000000
        state = self.project.factory.call_state(
            self.entry_address,
            buffer_address,
            prototype="int check_password(char *)",
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        state.memory.store(buffer_address, password)

        # scanf("%9s") accepts non-whitespace bytes. Printable bytes make the
        # generated model directly usable from a terminal.
        for symbolic_byte in self.input_bytes:
            state.solver.add(symbolic_byte >= 0x21, symbolic_byte <= 0x7E)

        self.simgr = self.project.factory.simgr(state)
        for stash in ("found", "avoid", "deferred"):
            self.simgr.stashes.setdefault(stash, [])
        self.total_steps = 0
        return self._observation("reset")

    def controlled_explore(
        self,
        max_steps: int = 5,
        target_output: str = "Success!",
        avoid_output: str = "trapped",
        max_active_states: int = 64,
    ) -> dict[str, Any]:
        """Advance execution while separating target, trap, and excess states."""
        if not 1 <= max_steps <= 100:
            raise ValueError("max_steps must be between 1 and 100")
        if max_active_states < 1:
            raise ValueError("max_active_states must be positive")

        target_bytes = target_output.encode()
        avoid_bytes = avoid_output.encode()
        steps_run = 0

        self._classify_active_states(target_bytes, avoid_bytes)
        while (
            steps_run < max_steps
            and self.simgr.active
            and not self.simgr.stashes["found"]
        ):
            self.simgr.step(stash="active")
            steps_run += 1
            self.total_steps += 1
            self._classify_active_states(target_bytes, avoid_bytes)
            self._limit_active_states(max_active_states)

        if self.simgr.stashes["found"]:
            status = "target_found"
        elif not self.simgr.active:
            status = "search_exhausted"
        else:
            status = "step_limit_reached"

        return self._observation(status, steps_run=steps_run)

    def solve_input(
        self,
        state_index: int = 0,
        stash: str = "found",
    ) -> dict[str, Any]:
        """Concretize the symbolic password from a selected execution state."""
        states = self.simgr.stashes.get(stash)
        if states is None:
            raise ValueError(f"Unknown stash: {stash}")
        if not states:
            return {
                "status": "no_state",
                "message": f"Stash '{stash}' is empty; explore to the target first.",
            }
        if not 0 <= state_index < len(states):
            raise IndexError(
                f"state_index {state_index} is outside stash '{stash}' "
                f"(size {len(states)})"
            )

        state = states[state_index]
        concrete = bytes(state.solver.eval(byte) for byte in self.input_bytes)
        fixed_prefix = bytearray()
        for symbolic_byte, value in zip(self.input_bytes, concrete, strict=True):
            if not state.solver.unique(symbolic_byte):
                break
            fixed_prefix.append(value)

        return {
            "status": "solved",
            "stash": stash,
            "state_index": state_index,
            "concrete_input": concrete.decode("ascii"),
            "concrete_input_hex": concrete.hex(),
            "required_prefix": fixed_prefix.decode("ascii"),
            "stdout": self._stdout(state),
            "address": hex(state.addr),
            "constraints": len(state.solver.constraints),
        }

    def _classify_active_states(
        self,
        target_output: bytes,
        avoid_output: bytes,
    ) -> None:
        for state in list(self.simgr.active):
            stdout = state.posix.dumps(1)
            if target_output and target_output in stdout:
                destination = "found"
            elif (
                self.trap_address is not None
                and state.addr == self.trap_address
            ) or (avoid_output and avoid_output in stdout):
                destination = "avoid"
            else:
                continue

            self.simgr.move(
                from_stash="active",
                to_stash=destination,
                filter_func=lambda candidate, selected=state: candidate is selected,
            )

    def _limit_active_states(self, maximum: int) -> None:
        if len(self.simgr.active) <= maximum:
            return
        overflow = set(id(state) for state in self.simgr.active[maximum:])
        self.simgr.move(
            from_stash="active",
            to_stash="deferred",
            filter_func=lambda state: id(state) in overflow,
        )

    def _observation(
        self,
        status: str,
        *,
        steps_run: int = 0,
    ) -> dict[str, Any]:
        stash_sizes = {
            name: len(states)
            for name, states in self.simgr.stashes.items()
            if states or name in {"active", "found", "avoid", "deferred", "errored"}
        }
        active_preview = [
            self._state_summary(state) for state in self.simgr.active[:5]
        ]
        found_preview = [
            self._state_summary(state)
            for state in self.simgr.stashes["found"][:3]
        ]
        return {
            "status": status,
            "steps_run": steps_run,
            "total_steps": self.total_steps,
            "stash_sizes": stash_sizes,
            "active_states": active_preview,
            "found_states": found_preview,
        }

    def _state_summary(self, state: angr.SimState) -> dict[str, Any]:
        return {
            "address": hex(state.addr),
            "symbol": self._symbols.get(state.addr),
            "stdout": self._stdout(state),
            "constraints": len(state.solver.constraints),
        }

    @staticmethod
    def _stdout(state: angr.SimState) -> str:
        return state.posix.dumps(1).decode("utf-8", errors="replace")

    def _collect_symbols(self) -> dict[int, str]:
        symbols: dict[int, str] = {}
        for symbol in self.project.loader.main_object.symbols:
            if symbol.rebased_addr:
                symbols[symbol.rebased_addr] = symbol.name.lstrip("_")
        return symbols

    def _optional_symbol_address(self, name: str) -> int | None:
        normalized = name.lstrip("_")
        for address, symbol_name in self._symbols.items():
            if symbol_name == normalized:
                return address
        return None

    def _symbol_address(self, name: str) -> int:
        address = self._optional_symbol_address(name)
        if address is None:
            available = ", ".join(sorted(set(self._symbols.values())))
            raise ValueError(
                f"Symbol '{name}' was not found in {self.binary_path}. "
                f"Available symbols include: {available}"
            )
        return address


def build_agent_tools(
    binary_path: str | Path,
) -> tuple[AngrToolbox, list[BaseTool]]:
    """Create one stateful toolbox and its two LangChain-callable tools."""
    toolbox = AngrToolbox(binary_path)

    @tool
    def controlled_explore(
        max_steps: int = 5,
        target_output: str = "Success!",
        avoid_output: str = "trapped",
        max_active_states: int = 64,
    ) -> dict[str, Any]:
        """Advance symbolic execution toward target output while avoiding traps."""
        return toolbox.controlled_explore(
            max_steps=max_steps,
            target_output=target_output,
            avoid_output=avoid_output,
            max_active_states=max_active_states,
        )

    @tool
    def solve_input(
        state_index: int = 0,
        stash: str = "found",
    ) -> dict[str, Any]:
        """Solve a concrete password from a target state found by exploration."""
        return toolbox.solve_input(state_index=state_index, stash=stash)

    return toolbox, [controlled_explore, solve_input]
