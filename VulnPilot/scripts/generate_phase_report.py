#!/usr/bin/env python3
"""
Generate three-phase Vulhub experiment reports from existing VulnPilot logs.

This script is intentionally report-only. It does not run targets and does not
change the agent workflow. It reconstructs stages from log markers:

1. Information gathering: auto recon + Vulhub README context.
2. Vulnerability analysis: Advisor/Main planning + Intelligence Playbook.
3. Exploitation: ExploitDetector and final Vulhub result.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"

STATUS_SUCCESS = "成功"
STATUS_PARTIAL = "部分完成"
STATUS_FAILURE = "失败"
STATUS_TIMEOUT = "超时"
STATUS_UNKNOWN = "未知"


@dataclass
class PhaseResult:
    status: str = STATUS_UNKNOWN
    success: Optional[bool] = None
    summary: str = ""
    details: dict[str, str] = field(default_factory=dict)


@dataclass
class TargetAnalysis:
    target: str = ""
    cve: str = ""
    app: str = ""
    target_url: str = ""
    log_file: str = ""
    start_time: str = ""
    end_time: str = ""
    elapsed_seconds: Optional[int] = None
    phase1: PhaseResult = field(default_factory=PhaseResult)
    phase2: PhaseResult = field(default_factory=PhaseResult)
    phase3: PhaseResult = field(default_factory=PhaseResult)
    overall_status: str = STATUS_UNKNOWN


def read_log(log_file: str | Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "gbk"):
        try:
            return Path(log_file).read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return Path(log_file).read_text(encoding="utf-8", errors="replace")


def _first(pattern: str, text: str, flags: int = 0) -> str:
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else ""


def _safe_json_blocks_after(text: str, marker: str, window: int = 3000) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    start = 0
    while True:
        idx = text.find(marker, start)
        if idx < 0:
            break
        snippet = text[idx : idx + window]
        brace = snippet.find("{")
        if brace >= 0:
            obj = _extract_json_object(snippet[brace:])
            if obj:
                blocks.append(obj)
        start = idx + len(marker)
    return blocks


def _extract_json_object(text: str) -> Optional[dict[str, Any]]:
    depth = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_string:
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(text[: i + 1])
                    return value if isinstance(value, dict) else None
                except json.JSONDecodeError:
                    return None
    return None


def _timestamps(text: str) -> tuple[str, str]:
    stamps = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", text)
    return (stamps[0], stamps[-1]) if stamps else ("", "")


def _elapsed(start: str, end: str) -> Optional[int]:
    if not start or not end:
        return None
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        return int((datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds())
    except ValueError:
        return None


def parse_metadata(log_content: str, fallback_target: str = "") -> dict[str, Any]:
    challenge_code = _first(r"challenge_code[\"']?\s*[:=]\s*[\"']?(vulhub_[A-Za-z0-9_.-]+_CVE-\d{4}-\d+)", log_content)
    if not challenge_code:
        challenge_code = _first(r"题目:\s*(vulhub_[A-Za-z0-9_.-]+_CVE-\d{4}-\d+)", log_content)
    if not challenge_code:
        challenge_code = _first(r"(vulhub_[A-Za-z0-9_.-]+_CVE-\d{4}-\d+)", log_content)

    cve = _first(r"(CVE-\d{4}-\d+)", fallback_target) or _first(r"(CVE-\d{4}-\d+)", log_content)
    app = ""
    target = fallback_target

    if challenge_code:
        m = re.match(r"vulhub_(.+?)_(CVE-\d{4}-\d+)", challenge_code)
        if m:
            app = m.group(1)
            cve = cve or m.group(2)
            target = target or f"{app}/{m.group(2)}"

    if not app and fallback_target and "/" in fallback_target:
        app = fallback_target.split("/", 1)[0]

    target_url = (
        _first(r'"URL"\s*:\s*"(http[^"]+)"', log_content)
        or _first(r'"_target_url"\s*:\s*"(http[^"]+)"', log_content)
        or _first(r"(https?://host\.docker\.internal:\d+)", log_content)
    )

    ports = []
    port_text = _first(r"ports:\s*\[([^\]]+)\]", log_content)
    if not port_text:
        port_text = _first(r'"host_ports"\s*:\s*\[([^\]]+)\]', log_content)
    if port_text:
        ports = [int(p) for p in re.findall(r"\d+", port_text)]

    readme_lengths = [int(x) for x in re.findall(r'"readme_length"\s*:\s*(\d+)', log_content)]

    return {
        "target": target or fallback_target,
        "cve": cve,
        "app": app,
        "challenge_code": challenge_code,
        "target_url": target_url,
        "ports": ports,
        "readme_length": max(readme_lengths, default=0),
    }


def parse_phase1(log_content: str, meta: dict[str, Any]) -> PhaseResult:
    details: dict[str, str] = {}

    recon_jsons = _safe_json_blocks_after(log_content, "[自动侦察] ✅ 成功获取目标信息")
    port_done = re.findall(r"\[自动侦察\].*?端口\s+(\d+)\s+信息收集完成", log_content)
    recon_started = "[自动侦察] 开始收集目标信息" in log_content
    recon_timeout = "自动侦察" in log_content and "超时" in log_content
    recon_error = "自动侦察" in log_content and any(x in log_content for x in ("失败", "异常"))

    if recon_jsons:
        last = recon_jsons[-1]
        details["HTTP 状态码"] = str(last.get("status_code", "N/A"))
        details["响应长度"] = str(last.get("content_length", last.get("html_length", "N/A")))
        details["页面标题"] = str(last.get("title") or "无标题")
        details["Server"] = str(last.get("server") or "未知")
        details["表单数量"] = str(last.get("forms_detected", 0))

    ports = meta.get("ports") or [int(p) for p in port_done]
    if ports:
        details["探测端口"] = ", ".join(str(p) for p in sorted(set(ports)))

    readme_len = int(meta.get("readme_length") or 0)
    readme_injected = "已注入完整 Vulhub README 情报" in log_content
    details["Vulhub README"] = f"已注入 ({readme_len} 字符)" if readme_injected else "未发现注入记录"

    if recon_jsons and readme_injected:
        status = STATUS_SUCCESS
        success = True
        summary = f"完成 HTTP 侦察并注入 Vulhub README，目标服务返回 {details.get('HTTP 状态码', 'N/A')}"
    elif recon_jsons or port_done:
        status = STATUS_PARTIAL
        success = True
        summary = "完成基础 HTTP/端口侦察，但 README 注入记录不完整"
    elif recon_timeout:
        status = STATUS_TIMEOUT
        success = False
        summary = "自动侦察阶段超时"
    elif recon_started or recon_error:
        status = STATUS_FAILURE
        success = False
        summary = "自动侦察启动但未得到有效目标信息"
    else:
        status = STATUS_UNKNOWN
        success = None
        summary = "日志中未发现自动侦察记录"

    return PhaseResult(status=status, success=success, summary=summary, details=details)


def _latest_raw_preview(log_content: str) -> str:
    matches = re.findall(r'"raw_content_preview"\s*:\s*"((?:[^"\\]|\\.)*)"', log_content)
    if not matches:
        return ""
    try:
        return json.loads(f'"{matches[-1]}"')
    except json.JSONDecodeError:
        return matches[-1]


def parse_phase2(log_content: str, meta: dict[str, Any]) -> PhaseResult:
    details: dict[str, str] = {}

    playbook_counts = [int(x) for x in re.findall(r'"playbook_count"\s*:\s*(\d+)', log_content)]
    playbook_count = max(playbook_counts, default=0)
    details["情报 Playbook"] = f"{playbook_count} 个"

    intel_routed = "流转至情报节点搜集 CVE PoC" in log_content
    if intel_routed:
        details["情报节点"] = "已触发 CVE PoC 搜集"

    skills = re.findall(r"\[Skills\].*?加载 Skill:\s*([A-Za-z0-9_.-]+)", log_content)
    if skills:
        details["加载技能"] = ", ".join(dict.fromkeys(skills))

    cves = sorted(set(re.findall(r"CVE-\d{4}-\d+", log_content)))
    if cves:
        details["识别 CVE"] = ", ".join(cves[:5])

    advice_count = log_content.count("[MiniMax] 提供建议")
    if advice_count:
        details["Advisor 建议"] = f"{advice_count} 次"

    plan_preview = _latest_raw_preview(log_content)
    if plan_preview:
        first_line = re.sub(r"\s+", " ", plan_preview).strip()
        details["最终规划摘要"] = first_line[:160] + ("..." if len(first_line) > 160 else "")

    has_dispatch = '"has_dispatch": true' in log_content or "[DISPATCH_TASK]" in log_content
    if has_dispatch:
        details["执行计划"] = "已形成并下发执行任务"

    if playbook_count > 0 and has_dispatch:
        status = STATUS_SUCCESS
        success = True
        summary = f"生成 {playbook_count} 个攻击 Playbook，并形成可执行利用计划"
    elif playbook_count > 0:
        status = STATUS_PARTIAL
        success = True
        summary = f"生成 {playbook_count} 个攻击 Playbook，但未看到明确任务下发"
    elif has_dispatch or advice_count:
        status = STATUS_PARTIAL
        success = True
        summary = "完成漏洞方向研判并给出利用思路，但未发现结构化 Playbook"
    else:
        status = STATUS_FAILURE
        success = False
        summary = "未发现有效漏洞分析或攻击 Playbook"

    return PhaseResult(status=status, success=success, summary=summary, details=details)


def parse_phase3(log_content: str) -> PhaseResult:
    details: dict[str, str] = {}

    final_success = "Vulhub 渗透测试成功" in log_content or "[✓] Vulhub 漏洞利用成功" in log_content
    final_failure = "Vulhub 渗透测试未成功" in log_content or "测试结束 - Agent 主动宣告测试完成" in log_content
    final_timeout = "TimeoutExpired" in log_content or "超时保护触发" in log_content

    llm_success = re.findall(r"\[EXPLOITATION_SUCCESS[:：]\s*([^\]\n]+)", log_content)
    llm_failed = "[EXPLOITATION_FAILED]" in log_content
    rule_hits = re.findall(r'"rule"\s*:\s*"([^"]+)"', log_content)

    if rule_hits:
        details["规则命中"] = rule_hits[-1]
    if llm_success:
        details["LLM 判定"] = llm_success[-1].strip()
    elif llm_failed:
        details["LLM 判定"] = "EXPLOITATION_FAILED"

    attempts = _first(r"尝试次数.*?:\s*(\d+)", log_content) or _first(r'"attempts"\s*:\s*(\d+)', log_content)
    if attempts:
        details["尝试次数"] = attempts

    flag_line = _first(r'\[Vulhub利用成功\]\s*([^"\n]+)', log_content)
    if flag_line:
        details["成功证据"] = flag_line[:220] + ("..." if len(flag_line) > 220 else "")

    if final_success or llm_success:
        status = STATUS_SUCCESS
        success = True
        summary = details.get("LLM 判定") or details.get("成功证据") or "ExploitDetector 确认漏洞利用成功"
    elif final_timeout:
        status = STATUS_TIMEOUT
        success = False
        summary = "利用阶段触发超时保护"
    elif final_failure or llm_failed:
        status = STATUS_FAILURE
        success = False
        summary = "利用尝试未被 ExploitDetector 判定为成功"
    else:
        status = STATUS_UNKNOWN
        success = None
        summary = "日志中未发现明确利用结论"

    return PhaseResult(status=status, success=success, summary=summary, details=details)


def analyze_log(log_file: str | Path, fallback_target: str = "") -> TargetAnalysis:
    content = read_log(log_file)
    meta = parse_metadata(content, fallback_target=fallback_target)
    start, end = _timestamps(content)

    analysis = TargetAnalysis(
        target=meta["target"],
        cve=meta["cve"],
        app=meta["app"],
        target_url=meta["target_url"],
        log_file=str(log_file),
        start_time=start,
        end_time=end,
        elapsed_seconds=_elapsed(start, end),
    )
    analysis.phase1 = parse_phase1(content, meta)
    analysis.phase2 = parse_phase2(content, meta)
    analysis.phase3 = parse_phase3(content)

    if analysis.phase3.status == STATUS_SUCCESS:
        analysis.overall_status = STATUS_SUCCESS
    elif analysis.phase3.status in (STATUS_FAILURE, STATUS_TIMEOUT):
        analysis.overall_status = analysis.phase3.status
    elif analysis.phase1.success or analysis.phase2.success:
        analysis.overall_status = STATUS_PARTIAL
    else:
        analysis.overall_status = STATUS_UNKNOWN

    return analysis


def _md(text: Any, limit: int = 300) -> str:
    value = "" if text is None else str(text)
    value = value.replace("|", "\\|").replace("\n", " ").strip()
    return value[:limit] + ("..." if len(value) > limit else "")


def phase_summary_cells(analysis: TargetAnalysis) -> tuple[str, str, str]:
    return (
        f"{analysis.phase1.status}: {_md(analysis.phase1.summary, 80)}",
        f"{analysis.phase2.status}: {_md(analysis.phase2.summary, 80)}",
        f"{analysis.phase3.status}: {_md(analysis.phase3.summary, 80)}",
    )


def phase_details_markdown(analysis: TargetAnalysis, heading_level: int = 3) -> str:
    lines: list[str] = []
    for title, phase in (
        ("阶段一：情报收集", analysis.phase1),
        ("阶段二：脆弱性分析", analysis.phase2),
        ("阶段三：最终利用", analysis.phase3),
    ):
        hashes = "#" * heading_level
        lines += ["", f"{hashes} {title}（{phase.status}）", "", f"> {_md(phase.summary, 500)}", ""]
        if phase.details:
            lines += ["| 项目 | 内容 |", "|------|------|"]
            for key, value in phase.details.items():
                lines.append(f"| {_md(key, 80)} | {_md(value, 500)} |")
    return "\n".join(lines)


def generate_single_report(analysis: TargetAnalysis, output_path: Optional[Path] = None) -> str:
    elapsed = f"{analysis.elapsed_seconds}s" if analysis.elapsed_seconds is not None else "N/A"
    log_name = Path(analysis.log_file).name if analysis.log_file else "N/A"

    p1, p2, p3 = phase_summary_cells(analysis)
    lines = [
        "# VulnPilot 三阶段渗透测试分析报告",
        "",
        f"> **靶机**: `{analysis.target or 'N/A'}`  ",
        f"> **CVE**: `{analysis.cve or 'N/A'}`  ",
        f"> **目标 URL**: {analysis.target_url or 'N/A'}  ",
        f"> **测试时间**: {analysis.start_time or 'N/A'} ~ {analysis.end_time or 'N/A'} ({elapsed})  ",
        f"> **日志文件**: `{log_name}`  ",
        f"> **总体结论**: {analysis.overall_status}",
        "",
        "## 阶段总览",
        "",
        "| 阶段 | 状态与摘要 |",
        "|------|-----------|",
        f"| 情报收集 | {_md(p1, 220)} |",
        f"| 脆弱性分析 | {_md(p2, 220)} |",
        f"| 最终利用 | {_md(p3, 220)} |",
        "",
        phase_details_markdown(analysis, heading_level=2),
        "",
        "---",
        "",
        "*本报告由 `scripts/generate_phase_report.py` 基于现有日志自动生成，未改变原始 Agent 执行流程。*",
        "",
    ]
    content = "\n".join(lines)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(f"[REPORT] {output_path}")
    return content


def generate_multi_report(analyses: list[TargetAnalysis], output_path: Path) -> Path:
    lines = [
        "# VulnPilot 历史日志三阶段汇总报告",
        "",
        f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> 日志数量: {len(analyses)}",
        "",
        "## 阶段总览",
        "",
        "| # | 靶机 | CVE | 情报收集 | 脆弱性分析 | 最终利用 | 总体结论 | 日志 |",
        "|---|------|-----|----------|------------|----------|----------|------|",
    ]

    for idx, analysis in enumerate(analyses, start=1):
        p1, p2, p3 = phase_summary_cells(analysis)
        log_path = Path(analysis.log_file)
        try:
            log_ref = log_path.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            log_ref = log_path.as_posix()
        lines.append(
            f"| {idx} | `{_md(analysis.target or 'N/A', 80)}` | `{_md(analysis.cve or 'N/A', 30)}` "
            f"| {_md(p1, 140)} | {_md(p2, 140)} | {_md(p3, 140)} "
            f"| {analysis.overall_status} | [{log_path.name}]({log_ref}) |"
        )

    lines += ["", "---", "", "## 三阶段详情", ""]
    for analysis in analyses:
        lines += [
            f"### `{analysis.target or Path(analysis.log_file).stem}`",
            "",
            f"> **CVE**: `{analysis.cve or 'N/A'}`  ",
            f"> **目标 URL**: {analysis.target_url or 'N/A'}  ",
            f"> **测试时间**: {analysis.start_time or 'N/A'} ~ {analysis.end_time or 'N/A'}  ",
            f"> **总体结论**: {analysis.overall_status}",
            "",
            phase_details_markdown(analysis, heading_level=4),
            "",
            "---",
            "",
        ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[REPORT] {output_path}")
    return output_path


def _log_candidates(log_dir: Path) -> list[Path]:
    files = list(log_dir.glob("vulnpilot_*.log"))
    files += list((log_dir / "challenges").glob("vulhub_*_CVE-*.log"))
    return sorted(set(files), key=lambda p: p.stat().st_mtime)


def _find_log_for_target(target: str, log_dir: Path) -> Optional[Path]:
    app, _, cve = target.partition("/")
    best: Optional[Path] = None
    for lf in _log_candidates(log_dir):
        content = read_log(lf)
        if target in content or (app and cve and f"vulhub_{app}_{cve}" in content):
            best = lf
    return best


def generate_batch_enhanced_report(
    batch_report_path: Path,
    log_dir: Path,
    output_path: Optional[Path] = None,
) -> Path:
    original = batch_report_path.read_text(encoding="utf-8")
    targets = list(dict.fromkeys(re.findall(r"`([A-Za-z0-9_.-]+/CVE-\d{4}-\d+)`", original)))
    analyses: list[TargetAnalysis] = []

    for target in targets:
        log_file = _find_log_for_target(target, log_dir)
        if log_file:
            analyses.append(analyze_log(log_file, fallback_target=target))
        else:
            analyses.append(TargetAnalysis(target=target, overall_status=STATUS_UNKNOWN))

    lines = [
        original.rstrip(),
        "",
        "---",
        "",
        "# 三阶段实验结果分析",
        "",
        f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "| 靶机 | 情报收集 | 脆弱性分析 | 最终利用 |",
        "|------|----------|------------|----------|",
    ]

    for analysis in analyses:
        p1, p2, p3 = phase_summary_cells(analysis)
        lines.append(f"| `{analysis.target}` | {_md(p1, 140)} | {_md(p2, 140)} | {_md(p3, 140)} |")

    for analysis in analyses:
        lines += ["", "---", "", f"## {analysis.target}", ""]
        if analysis.log_file:
            rel = Path(analysis.log_file)
            try:
                rel_text = rel.relative_to(PROJECT_ROOT).as_posix()
            except ValueError:
                rel_text = rel.as_posix()
            lines.append(f"> 日志: [{rel.name}]({rel_text})")
            lines.append("")
            lines.append(phase_details_markdown(analysis, heading_level=3))
        else:
            lines.append("> 未找到对应日志，无法生成三阶段分析。")

    if output_path is None:
        output_path = batch_report_path.parent / f"{batch_report_path.stem}_phase_enhanced.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[REPORT] {output_path}")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate VulnPilot three-phase experiment reports from logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run python scripts/generate_phase_report.py logs/challenges/vulhub_xstream_CVE-2021-29505_*.log
  uv run python scripts/generate_phase_report.py --batch logs/batch_test/batch_report_20260429_154045.md
        """,
    )
    parser.add_argument("logs", nargs="*", help="Log files or glob patterns")
    parser.add_argument("--batch", metavar="REPORT", help="Enhance an existing batch report")
    parser.add_argument("--output", "-o", metavar="PATH", help="Output file or directory")
    parser.add_argument("--log-dir", metavar="DIR", default=str(LOGS_DIR), help="Log directory for --batch")
    parser.add_argument("--no-llm", action="store_true", help="Kept for compatibility; this script does not call LLMs")
    args = parser.parse_args()

    if args.batch:
        generate_batch_enhanced_report(
            Path(args.batch),
            Path(args.log_dir),
            Path(args.output) if args.output else None,
        )
        return

    log_files: list[Path] = []
    for pat in args.logs:
        path = Path(pat)
        if path.exists():
            log_files.append(path)
        else:
            log_files.extend(PROJECT_ROOT.glob(pat))

    if not log_files:
        parser.error("Please provide at least one log file, or use --batch.")

    output = Path(args.output) if args.output else LOGS_DIR / "phase_reports"
    if len(log_files) > 1 and args.output and output.suffix:
        analyses = [analyze_log(log_file) for log_file in log_files]
        generate_multi_report(analyses, output)
    elif len(log_files) == 1 and args.output and output.suffix:
        generate_single_report(analyze_log(log_files[0]), output)
    else:
        output.mkdir(parents=True, exist_ok=True)
        for log_file in log_files:
            analysis = analyze_log(log_file)
            generate_single_report(analysis, output / f"{log_file.stem}_phase.md")

    print(f"[DONE] {len(log_files)} report(s) generated.")


if __name__ == "__main__":
    main()
