# 二进制 ReAct Agent 静态挖掘实验

本项目使用 LLM 编排只读的 radare2 与 Ghidra 工具，对 `challenge`
进行静态分析，并生成实验要求的两个运行产物：

- `vuln.json`
- `logs/run.txt`

Agent 源码为 `agent.py`、`ghidra_scripts/`、`schemas/`、`scripts/`、
`run.sh` 与 `requirements.txt`。

## 一键运行

```bash
./run.sh
```

默认模型为 `gpt-5.4-mini`，通过已登录的 Codex CLI 使用结构化 JSON
协议完成 Thought -> Action -> Observation 循环。运行日期会自动写入日志。

## 工具路径

程序按以下顺序查找工具：

1. 环境变量 `R2_BIN`、`GHIDRA_HEADLESS`
2. `PATH` 中的 `r2`、`analyzeHeadless`
3. `scripts/setup_tools.sh` 下载到 `.tools/` 的本地工具

当前自动安装配置为 radare2 6.1.6 与 Ghidra 11.0.3。Ghidra 11.0.3
要求 JDK 17 或更高版本。macOS 上强制使用
`-Djava.awt.headless=true`，避免 headless 分析初始化图形界面。

也可显式指定已有安装：

```bash
R2_BIN=/path/to/r2 \
GHIDRA_HEADLESS=/path/to/ghidra/support/analyzeHeadless \
CODEX_MODEL=gpt-5.4-mini \
./run.sh
```

工具封装不执行目标程序，不写目标文件，仅调用 radare2 分析命令和 Ghidra
headless 导入/反编译。`.tools/` 与 `.runtime/` 已忽略，不应提交；API Key
也不应写入任何项目文件。
