# ReAct Agent Binary Static Analysis

This project analyzes the provided `logrotate` ELF with a read-only ReAct workflow.

## Environment

Required tools:

- `r2` / `radare2`
- Ghidra headless analyzer (`analyzeHeadless`)
- Python 3 with packages from `requirements.txt`
- `OPENAI_API_KEY` in the environment when using the LLM path

On this machine, Homebrew installed:

- radare2: `/opt/homebrew/bin/r2`
- Ghidra: `/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless`
- Java: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`

## Run

```bash
python -m agent --binary ./logrotate --out output --log logs/run.txt
```

Useful options:

```bash
python -m agent --binary ./logrotate --out output --log logs/run.txt --model gpt-5.5
python -m agent --binary ./logrotate --out output --log logs/run.txt --no-llm
```

Outputs:

- `logs/run.txt`: complete ReAct-style interaction log
- `output/vuln.json`: structured final result
- `output/evidence/`: raw tool evidence
