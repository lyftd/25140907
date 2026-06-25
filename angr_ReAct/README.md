# angr ReAct Lab

## Task 1: angr tool wrappers

`angr_tools.py` provides two stateful tools:

1. `controlled_explore(max_steps=5, target_output="Success!",
   avoid_output="trapped", max_active_states=64)`: advances symbolic execution
   by a bounded number of steps, recognizes the target, avoids
   `gadget_trap`/`trapped`, and caps the active-state count.
2. `solve_input(state_index=0, stash="found")`: concretizes the symbolic
   password from a selected state and reports both a full model and its
   uniquely constrained prefix.

The analysis starts directly at `check_password(char *)`. This keeps Task 1
focused on the target logic and avoids depending on platform-specific
`scanf` startup behavior. The password consists of nine printable symbolic
bytes followed by a null terminator, matching the target's `%9s` buffer.

Both wrappers are exposed as LangChain structured tools by
`build_agent_tools()`. They share one `AngrToolbox`, so execution state is
preserved between Agent calls.

## Task 2: ReAct main loop

`react_agent.py` implements the complete model-to-tool loop:

1. Send the explicit success and trap-avoidance goal plus JSON tool schemas to
   a Tool Calling model.
2. Parse the model's decision summary and function call.
3. Dispatch the call to the stateful angr tools.
4. Serialize the structured Observation as a `tool` message.
5. Repeat until `solve_input` succeeds and the model returns a final answer.

Each tool interaction is saved as `Thought -> Action -> Observation` in a text
log and as structured JSONL. Here, `Thought` means a short decision summary
provided for the experiment log; the prompt does not request private
chain-of-thought.

## Run

```bash
conda activate angr-react
clang crackme.c -o crackme
python demo_task1.py
python run_react_agent.py --offline-demo --log logs/react_demo.log
python -m unittest -v
```

The offline demo verifies the whole dispatcher deterministically and produces
more than three complete rounds. To use a real OpenAI-compatible model:

```bash
export OPENAI_API_KEY="..."
export OPENAI_MODEL="your-tool-calling-model"
python run_react_agent.py --log logs/react_api.log
```

For a compatible local or third-party service, also set `OPENAI_BASE_URL`.
