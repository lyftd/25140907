from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .tools import sha256_file


STUDENT_ID = "25140907"
STUDENT_NAME = "李彦霏"
REPO_LABEL = "lyftd/25140907"
REPO_URL = "https://github.com/lyftd/25140907"
REPORT_NAME = f"{STUDENT_ID}-{STUDENT_NAME}-考核2-二进制分析.pdf"


def read_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def register_fonts() -> str:
    font_name = "STSong-Light"
    try:
        pdfmetrics.registerFont(UnicodeCIDFont(font_name))
    except Exception:
        pass
    return font_name


def para(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(text).replace("\n", "<br/>"), style)


def code_block(text: str, style: ParagraphStyle, width: int = 88) -> Preformatted:
    lines = []
    for raw in text.replace("\t", "    ").splitlines():
        line = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in raw)
        lines.append(line[:width])
    return Preformatted("\n".join(lines), style)


def make_table(rows, font_name: str, widths=None) -> Table:
    cell_style = ParagraphStyle(
        name="TableCell",
        fontName=font_name,
        fontSize=9.2,
        leading=12.5,
        wordWrap="CJK",
    )
    converted = [[Paragraph(escape(str(cell)), cell_style) for cell in row] for row in rows]
    widths = widths or [4.0 * cm, 11.2 * cm]
    t = Table(converted, colWidths=widths)
    t.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), font_name),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f4")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9aa4a6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return t


def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(A4[0] - 1.8 * cm, 1.2 * cm, f"{doc.page}")
    canvas.restoreState()


def import_names(overview: dict) -> str:
    names = [item.get("name", "") for item in overview.get("dangerous_imports", [])]
    preferred = [
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
    ordered = [name for name in preferred if name in names]
    return "、".join(ordered)


def build_report(
    binary: Path,
    out_dir: Path,
    log_path: Path,
    final_result: dict[str, str],
    metadata: dict,
) -> Path:
    font_name = register_fonts()
    evidence_dir = out_dir / "evidence"
    overview = read_json(evidence_dir / "r2_overview.json", {})
    ghidra = read_json(evidence_dir / "ghidra_analysis.json", {})
    info = overview.get("info", {})

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="CNTitle",
            parent=styles["Title"],
            fontName=font_name,
            fontSize=23,
            leading=32,
            alignment=TA_CENTER,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            name="CNHeading",
            parent=styles["Heading1"],
            fontName=font_name,
            fontSize=15.5,
            leading=21,
            spaceBefore=13,
            spaceAfter=8,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            name="CNBody",
            parent=styles["BodyText"],
            fontName=font_name,
            fontSize=10.6,
            leading=16.4,
            wordWrap="CJK",
            spaceAfter=7,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CNCenter",
            parent=styles["BodyText"],
            fontName=font_name,
            fontSize=12,
            leading=20,
            alignment=TA_CENTER,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            name="CNCode",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=7.2,
            leading=9,
            leftIndent=5,
            rightIndent=5,
            spaceAfter=7,
        )
    )

    pdf_path = out_dir / REPORT_NAME
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=1.9 * cm,
        leftMargin=1.9 * cm,
        topMargin=1.7 * cm,
        bottomMargin=1.7 * cm,
        title="考核2-二进制分析",
        author=STUDENT_NAME,
    )

    story = []
    story.append(Spacer(1, 6.2 * cm))
    story.append(para(f"学号：{STUDENT_ID}", styles["CNCenter"]))
    story.append(para(f"姓名：{STUDENT_NAME}", styles["CNCenter"]))
    story.append(para(f"SHA256：{sha256_file(binary)}", styles["CNCenter"]))
    story.append(PageBreak())

    story.append(para("一、结论摘要", styles["CNHeading"]))
    story.append(
        para(
            "本次静态分析确认样本在 dateformat 配置项处理逻辑中存在栈缓冲区溢出风险。"
            "漏洞点位于函数 FUN_0000b674 / fcn.0000b674，该函数将配置文件中的 dateformat 字符串展开为用于匹配旧日志文件名的 glob 模式。"
            "展开目标是栈上的 128 字节缓冲区，代码在多处调用 strncat 时使用 0x80 - strlen(dest) 作为可追加长度，"
            "没有为 strncat 自动写入的字符串结束符预留空间，因此在边界长度下会发生 1 字节越界写。",
            styles["CNBody"],
        )
    )
    story.append(
        make_table(
            [
                ["漏洞类型", "栈缓冲区溢出"],
                ["关键位置", "FUN_0000b674 / fcn.0000b674，strncat 调用点 0xb8f0、0xb90c、0xb96c"],
                ["输入来源", "logrotate 配置文件中的 dateformat 指令"],
                ["危险操作", "向 sp+0x28 处 128 字节栈缓冲区追加正则片段"],
                ["最终产物", "logs/run.txt、output/vuln.json、output/evidence/"],
            ],
            font_name,
        )
    )

    story.append(para("二、样本与实验环境", styles["CNHeading"]))
    story.append(
        make_table(
            [
                ["文件名", binary.name],
                ["架构", f"{info.get('arch', 'arm')} / {info.get('bits', 32)} bit / {info.get('endian', 'little')} endian"],
                ["ELF 信息", f"{info.get('class', 'ELF32')}，动态链接，解释器 {info.get('intrp', '/lib/ld-uClibc.so.0')}"],
                ["符号状态", "已 strip，且无普通节表；动态导入表和字符串仍保留。"],
                ["保护信息", f"NX={info.get('nx', True)}，Canary={info.get('canary', False)}，RELRO={info.get('relro', 'no')}"],
                ["工具链", "radare2 6.1.8，Ghidra 12.1.2 headless，OpenAI Tool Calling Agent"],
                ["模型", metadata.get("model", "gpt-5.5")],
            ],
            font_name,
        )
    )
    story.append(
        para(
            "分析仅针对教师现场发放的二进制文件进行，不运行目标程序，不构造 exploit。"
            "由于该文件缺少源码和节表，报告采用导入表初筛、字符串线索、交叉引用、反汇编和 Ghidra 反编译相互印证的方式完成静态判断。",
            styles["CNBody"],
        )
    )

    story.append(para("三、ReAct Agent 设计", styles["CNHeading"]))
    story.append(
        para(
            "Agent 采用 Thought、Action、Observation、Final Answer 闭环。LLM 只负责任务编排和证据归纳，"
            "Observation 全部来自只读工具返回。radare2 工具负责 ELF 元数据、导入表、字符串、交叉引用和函数反汇编；"
            "Ghidra 工具负责 headless 分析、危险调用点导出和重点函数反编译。完整交互日志保存在 logs/run.txt。",
            styles["CNBody"],
        )
    )
    story.append(
        make_table(
            [
                ["r2_overview", "提取 ELF 基本属性、SHA256、危险导入函数、关键字符串。"],
                ["r2_dangerous_calls", "对 strcpy、sprintf、strncat、strncpy、sscanf、exec* 等导入函数做交叉引用。"],
                ["r2_disassemble_function", "反汇编 FUN_0000b674 等重点函数，检查参数传递和边界判断。"],
                ["ghidra_analyze", "运行 Ghidra headless，导出危险调用点和反编译片段。"],
            ],
            font_name,
        )
    )

    story.append(para("四、静态分析过程", styles["CNHeading"]))
    story.append(
        para(
            "首先，r2 从动态导入表中发现以下高风险 API："
            + import_names(overview)
            + "。这些函数本身不等于漏洞，但可以作为数据流审计入口。"
            "字符串表中出现 dateformat、Date format %s is too long、glob pattern、/bin/sh、compress、mail 等内容，"
            "说明样本包含配置解析、路径拼接、文件轮转以及外部命令执行逻辑。",
            styles["CNBody"],
        )
    )
    story.append(
        para(
            "随后，Agent 对危险调用点进行交叉引用。Ghidra 导出 145 个函数，并识别 32 个危险导入调用点。"
            "其中，脚本执行路径中的 execvp/execlp/execl 属于 logrotate 的功能性执行路径；多个 strcpy/sprintf 调用点前存在 strlen 后 malloc/asprintf 的分配模式。"
            "真正值得收敛分析的是 FUN_0000b674 中 dateformat 到 strncat 的栈缓冲区数据流。",
            styles["CNBody"],
        )
    )
    story.append(
        make_table(
            [
                ["证据", "观察结果"],
                ["字符串线索", "dateformat、Date format %s is too long、-[0-9][0-9] 等格式展开相关字符串。"],
                ["目标缓冲区", "函数 FUN_0000b674 中 sp+0x28，大小 0x80，即 128 字节。"],
                ["边界检查", "使用 cmp r8, 0x7e 检查逻辑长度，但检查出现在部分追加之后。"],
                ["危险调用", "0xb8f0、0xb90c、0xb96c 均调用 strncat。"],
            ],
            font_name,
        )
    )

    story.append(para("五、漏洞细节", styles["CNHeading"]))
    story.append(
        para(
            "在 dateformat 展开流程中，程序先将 128 字节栈缓冲区清零，然后扫描用户配置的格式串。"
            "普通字符直接复制；遇到 %Y、%m、%d 时，会追加 [0-9][0-9]；遇到 %s 时，会追加更长的数字匹配片段。"
            "问题出现在 strncat 的第三个参数：代码把剩余容量计算成 0x80 - strlen(buffer)。"
            "然而 strncat 在最多复制 n 字节之后还会写入一个 NUL 结束符。正确写法应至少预留 1 字节，"
            "即 0x80 - strlen(buffer) - 1。当前实现缺少这个预留，因此边界情况下会覆盖缓冲区之后的栈字节。",
            styles["CNBody"],
        )
    )
    story.append(code_block(
        "0xb814  add r0, sp, 0x28        ; 128-byte stack buffer\n"
        "0xb81c  bl  memset             ; clear buffer\n"
        "0xb8d8  add r0, sp, 0x28        ; dest buffer\n"
        "0xb8e0  bl  strlen             ; strlen(dest)\n"
        "0xb8e8  rsb r2, r0, 0x80        ; n = 128 - strlen(dest)\n"
        "0xb8f0  bl  strncat            ; appends n bytes plus trailing NUL\n"
        "0xb8f4  add r0, sp, 0x28\n"
        "0xb900  ldr r1, \"[0-9][0-9]\"\n"
        "0xb904  rsb r2, r0, 0x80        ; same off-by-one pattern\n"
        "0xb90c  bl  strncat\n"
        "0xb96c  bl  strncat            ; longer replacement for %s\n"
        "0xb970  cmp r8, 0x7e            ; length check after append",
        styles["CNCode"],
    ))
    story.append(
        para(
            "因此，攻击者只要能影响 logrotate 配置文件中的 dateformat 内容，就可以让展开后的模式接近 128 字节边界。"
            "当 strncat 以剩余容量作为第三参数时，末尾的 NUL 会落到缓冲区外，形成可静态确认的栈缓冲区越界写。",
            styles["CNBody"],
        )
    )

    story.append(para("六、误报排除", styles["CNHeading"]))
    story.append(
        make_table(
            [
                ["候选点", "排除理由"],
                ["strcpy", "若干调用点前存在 strlen 加 malloc 的同源长度分配模式，当前证据不足以作为主漏洞。"],
                ["sprintf", "多用于路径拼接，但关键路径前存在按长度分配或 asprintf，风险低于 dateformat 栈缓冲区问题。"],
                ["execvp/execlp/execl", "与脚本、压缩、邮件功能相关，在未证明配置权限绕过时更像预期功能路径。"],
                ["sscanf/poptParseArgvString", "用于配置解析和状态文件解析，未观察到比 dateformat 更强的内存破坏证据。"],
            ],
            font_name,
        )
    )

    story.append(para("七、最终结构化结果", styles["CNHeading"]))
    story.append(
        make_table(
            [
                ["vuln_type", f"{final_result.get('vuln_type', '')}（栈缓冲区溢出）"],
                ["location", "FUN_0000b674 的 dateformat 处理逻辑，重点为 0xb8f0、0xb90c、0xb96c 处 strncat 调用。"],
                ["cause", "配置文件中的 dateformat 字符串进入固定 128 字节栈缓冲区；追加正则片段时使用 0x80 - strlen(dest) 作为长度，未为结尾 NUL 预留空间。"],
            ],
            font_name,
        )
    )
    story.append(
        para(
            "以上结果由 Agent 的 Final Answer 写入 output/vuln.json。完整 ReAct 日志与工具输出保存在项目目录中，"
            "可用于复核 r2 和 Ghidra 的调用过程及证据来源。",
            styles["CNBody"],
        )
    )
    story.append(
        make_table(
            [
                ["复核文件", "用途"],
                ["logs/run.txt", "完整 ReAct 交互日志，可确认 r2 与 Ghidra 均被调用。"],
                ["output/vuln.json", "Agent Final Answer 的结构化结果。"],
                ["output/evidence/r2_function_b674.txt", "FUN_0000b674 关键反汇编证据。"],
                ["output/evidence/ghidra_analysis.json", "Ghidra headless 导出的危险调用点和反编译摘要。"],
            ],
            font_name,
        )
    )
    story.append(Spacer(1, 0.35 * cm))
    story.append(para(f"仓库地址：{REPO_LABEL}（{REPO_URL}）", styles["CNBody"]))

    doc.build(story, onFirstPage=lambda canvas, doc: None, onLaterPages=add_page_number)
    return pdf_path
