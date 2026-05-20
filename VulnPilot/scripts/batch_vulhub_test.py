#!/usr/bin/env python3
"""
Vulhub 批量自动化渗透测试脚本
==============================

用法:
    uv run python scripts/batch_vulhub_test.py --targets targets.txt
    uv run python scripts/batch_vulhub_test.py --targets targets.txt --retry 1 --output results/my_report.md

targets.txt 格式（每行一个靶机，空格或斜杠分隔均可）:
    cacti CVE-2022-46169
    uwsgi CVE-2018-7490
    unomi/CVE-2020-13942
"""
import argparse
import io
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from generate_phase_report import (
    STATUS_UNKNOWN as PHASE_STATUS_UNKNOWN,
    analyze_log as analyze_phase_log,
    phase_details_markdown,
    phase_summary_cells,
)

ABLATION_ENV_KEYS = ("ENABLE_PROCESS_NOTEBOOK", "ENABLE_SKILLS")


def _env_switch(name: str, default: str = "true") -> str:
    return os.getenv(name, default).strip().lower()


def get_ablation_config() -> dict[str, str]:
    return {key: _env_switch(key, "true") for key in ABLATION_ENV_KEYS}


def avoid_report_overwrite(path: Path) -> Path:
    """Return a timestamped path if the requested report already exists."""
    if not path.exists():
        return path

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = path.with_name(f"{path.stem}_{timestamp}{path.suffix or '.md'}")
    counter = 2
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}_{timestamp}_{counter}{path.suffix or '.md'}")
        counter += 1
    print(f"[REPORT] 输出文件已存在，改写到: {candidate}")
    return candidate

# Windows terminals may default to GBK while reports and status text are UTF-8.
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ⭐ 修复一：在读取任何环境变量前，先加载项目根目录的 .env 文件
# 原因：main.py 内部也会 load_dotenv()，但外层脚本如果不提前加载，
# os.getenv("SINGLE_TASK_TIMEOUT") 会取到默认值 900s，导致外层超时总比内层早触发
_PROJECT_ROOT_FOR_ENV = Path(__file__).parent.parent
_ENV_FILE = _PROJECT_ROOT_FOR_ENV / ".env"
if _ENV_FILE.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=_ENV_FILE)
    except ImportError:
        # python-dotenv 未安装时降级处理：手动解析 .env（只处理简单 KEY=VALUE 格式）
        with open(_ENV_FILE, encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _, _v = _line.partition("=")
                    os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))


# ==================== 常量配置 ====================

# 项目根目录（此脚本位于 scripts/ 下，父目录即项目根）
PROJECT_ROOT = Path(__file__).parent.parent

# logs/ 目录路径
LOGS_DIR = PROJECT_ROOT / "logs"

# 默认 Vulhub 仓库目录
DEFAULT_VULHUB_DIR = "D:/vulhub"

# 单靶机测试外层超时保护（秒）
# 注：main.py 内部有 SINGLE_TASK_TIMEOUT（默认900s），此处额外再预留 300s 作为启动/清理阶段的缓冲
# 因此外层超时设置略大于内部超时，避免因网络等情况导致的卡死
OUTER_TIMEOUT_BUFFER = 300  # 额外缓冲秒数

# 结果状态符号，让报告一目了然
STATUS_SUCCESS = "✅ 成功"
STATUS_FAILURE = "❌ 失败"
STATUS_TIMEOUT = "⏱️ 超时"
STATUS_ERROR   = "🚨 异常"


# ==================== 输入解析函数 ====================

def parse_targets_from_file(filepath: str) -> list[str]:
    """
    从文本文件中解析靶机列表。

    支持以下格式（每行一个靶机），会自动清洗和格式化：
    - cacti CVE-2022-46169   (空格分隔) → cacti/CVE-2022-46169
    - uwsgi CVE-2018-7490    (空格分隔) → uwsgi/CVE-2018-7490
    - unomi/CVE-2020-13942   (斜杠分隔) → 保持不变
    - 以 # 开头的行会被当作注释跳过
    - 空行自动忽略

    Args:
        filepath: targets.txt 文件的路径

    Returns:
        格式化后的靶机路径列表（如 ['cacti/CVE-2022-46169', ...]）
    """
    targets = []
    filepath = Path(filepath)

    if not filepath.exists():
        print(f"[ERROR] 靶机列表文件不存在: {filepath}")
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            # 去除首尾空白
            line = raw_line.strip()

            # 忽略空行和注释行
            if not line or line.startswith("#"):
                continue

            # 将"多个空格"或"制表符"统一替换为单个空格，再转换为斜杠格式
            # 支持:  "cacti CVE-2022-46169" → "cacti/CVE-2022-46169"
            # 支持:  "unomi/CVE-2020-13942" → 保持不变（斜杠格式已兼容）
            normalized = re.sub(r'\s+', '/', line)

            # 简单校验：格式应该是 "应用名/CVE-XXXX-XXXXX"
            parts = normalized.split("/")
            if len(parts) < 2:
                print(f"  [WARN] 第 {line_no} 行格式异常，已跳过: {repr(raw_line.strip())}")
                continue

            targets.append(normalized)

    return targets


def get_outer_timeout() -> int:
    """
    计算外层超时（从环境变量读取 SINGLE_TASK_TIMEOUT 并加上缓冲）。
    这样如果项目内部超时配置有调整，外层也能自适应。
    """
    internal_timeout = int(os.getenv("SINGLE_TASK_TIMEOUT", "900"))
    return internal_timeout + OUTER_TIMEOUT_BUFFER


# ==================== 日志文件追踪函数 ====================

def snapshot_existing_logs() -> set[str]:
    """
    拍摄当前 logs/ 目录下已有日志文件的快照（文件名集合）。
    在每次子进程启动前调用，用于对比找出本次新生成的日志。

    Returns:
        当前已有的日志文件名集合（如 {'vulnpilot_20260325_171022.log', ...}）
    """
    if not LOGS_DIR.exists():
        return set()
    # 只匹配主日志文件，格式: vulnpilot_YYYYMMDD_HHMMSS.log
    return {
        f.name for f in LOGS_DIR.iterdir()
        if f.is_file() and f.name.startswith("vulnpilot_") and f.name.endswith(".log")
    }


def find_new_log(before_snapshot: set[str]) -> str | None:
    """
    通过对比快照前后 logs/ 目录的变化，找出本次测试新生成的日志文件。

    Args:
        before_snapshot: 测试开始前的日志文件名快照

    Returns:
        新日志文件的完整路径字符串，如未找到则返回 None
    """
    if not LOGS_DIR.exists():
        return None

    after_snapshot = {
        f.name for f in LOGS_DIR.iterdir()
        if f.is_file() and f.name.startswith("vulnpilot_") and f.name.endswith(".log")
    }

    # 找出新增的日志文件
    new_files = after_snapshot - before_snapshot

    if not new_files:
        return None

    # 如果有多个（理论上不会），取最新的那个
    newest = sorted(new_files)[-1]
    return str(LOGS_DIR / newest)


# ==================== 结果判定函数 ====================

def analyze_output(output: str) -> tuple[str, str]:
    """
    分析 main.py 的控制台输出，判断测试结果并提取关键证据。

    判定逻辑（与 main.py 中的日志关键词严格对应）:
    - 成功: 包含 "Vulhub 渗透测试成功"
    - 失败: 包含 "Vulhub 渗透测试未成功"
    - 其他: 认为失败（程序异常退出等）

    Args:
        output: 子进程的标准输出 + 标准错误合并文本

    Returns:
        (status, evidence) 元组，status 是状态字符串，evidence 是证据摘要
    """
    # 判定成功
    if "Vulhub 渗透测试成功" in output:
        # 提取利用成功的证据信息（如 CVE、利用方式等）
        evidence = _extract_evidence(output)
        return STATUS_SUCCESS, evidence

    # 判定失败（程序正常退出但未成功）
    if "Vulhub 渗透测试未成功" in output:
        return STATUS_FAILURE, "程序正常退出，未找到漏洞利用方式"

    # 其他（异常退出、KeyboardInterrupt 等）
    if "KeyboardInterrupt" in output:
        return STATUS_ERROR, "进程被外部中断"

    if "配置加载失败" in output or "❌ 配置" in output:
        return STATUS_ERROR, "配置加载失败，请检查 .env 文件"

    # 兜底：无法识别的输出归类为失败
    return STATUS_FAILURE, "未匹配到标准结束标记，可能为程序异常"


def _extract_evidence(output: str) -> str:
    """
    从成功输出中提取关键证据字符串。

    Args:
        output: 子进程输出文本

    Returns:
        证据描述字符串（如 "利用成功，命令执行回显..."）
    """
    # 尝试提取 "FLAG/证据" 行（main.py 中的格式：'FLAG/证据': '...'）
    match = re.search(r'FLAG/证据.*?:\s*(.+?)(?:\n|$)', output)
    if match:
        return match.group(1).strip()

    # 尝试提取 Vulhub 利用成功的描述信息
    match = re.search(r'\[Vulhub利用成功\]\s*(.+?)(?:[\n\r]|$)', output)
    if match:
        return match.group(1).strip()[:150]  # 截断避免过长

    return "漏洞利用成功（详见日志）"


def extract_attempts(output: str) -> str:
    """
    从输出中提取尝试次数信息。

    Args:
        output: 子进程输出文本

    Returns:
        尝试次数字符串，如 "45" 或 "N/A"
    """
    # 匹配格式: "尝试次数: 45"
    match = re.search(r'尝试次数.*?:\s*(\d+)', output)
    if match:
        return match.group(1)
    return "N/A"


# ==================== 报告生成函数 ====================

def generate_markdown_report(results: list[dict], output_path: Path) -> None:
    """
    生成 Markdown 格式的测试报告。

    报告格式:
    - 标题 + 时间戳
    - 总体统计（成功数 / 总数）
    - 详细结果表格（靶机 | 状态 | 证据 | 尝试次数 | 耗时 | 日志文件）

    Args:
        results: 每个靶机的结果字典列表
        output_path: 报告文件输出路径
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    success_count = sum(1 for r in results if r["status"] == STATUS_SUCCESS)
    failure_count = total - success_count
    ablation_config = get_ablation_config()

    phase_analyses = {}
    for r in results:
        log_file = r.get("log_file")
        if not log_file:
            continue
        try:
            phase_analyses[r["target"]] = analyze_phase_log(log_file, fallback_target=r["target"])
        except Exception as phase_err:
            print(f"[WARN] 三阶段分析失败: {r['target']} - {phase_err}")

    # ==================== 构建报告内容 ====================
    lines = [
        f"# VulnPilot · Vulhub 批量渗透测试报告",
        f"",
        f"> **生成时间**: {now}  ",
        f"> **测试工具**: VulnPilot (`main.py --vulhub`)  ",
        f"> **Vulhub 仓库**: `{DEFAULT_VULHUB_DIR}`",
        f"> **过程笔记**: `{ablation_config['ENABLE_PROCESS_NOTEBOOK']}`  ",
        f"> **Skills**: `{ablation_config['ENABLE_SKILLS']}`",
        f"",
        f"---",
        f"",
        f"## 📊 总体统计",
        f"",
        f"| 指标 | 数量 |",
        f"|------|------|",
        f"| 总靶机数 | {total} |",
        f"| ✅ 成功 | {success_count} |",
        f"| ❌ 失败/超时 | {failure_count} |",
        f"| 成功率 | {success_count / total * 100:.1f}% |" if total > 0 else "| 成功率 | N/A |",
        f"",
        f"---",
        f"",
        f"## 📋 详细结果",
        f"",
        f"| # | 靶机 | 状态 | 情报收集 | 脆弱性分析 | 最终利用 | 证据/原因 | 尝试次数 | 耗时(s) | 日志文件 |",
        f"|---|------|------|----------|------------|----------|-----------|----------|---------|---------|",
    ]

    for idx, r in enumerate(results, start=1):
        # 日志文件列：取文件名即可，不用显示完整路径（避免过长）
        log_display = "N/A"
        if r.get("log_file"):
            log_path = Path(r["log_file"])
            # 格式: [文件名](相对路径) 方便在 Markdown 中点击
            relative = log_path.relative_to(PROJECT_ROOT) if log_path.is_absolute() else log_path
            log_display = f"[{log_path.name}]({relative.as_posix()})"

        # 证据文本：转义 Markdown 特殊字符，并截断
        evidence = r.get("evidence", "N/A")
        evidence_display = evidence.replace("|", "\\|").replace("\n", " ")[:80]
        if len(evidence) > 80:
            evidence_display += "..."

        analysis = phase_analyses.get(r["target"])
        if analysis:
            phase1, phase2, phase3 = phase_summary_cells(analysis)
        else:
            phase1 = phase2 = phase3 = PHASE_STATUS_UNKNOWN
        phase1 = phase1.replace("|", "\\|").replace("\n", " ")[:120]
        phase2 = phase2.replace("|", "\\|").replace("\n", " ")[:120]
        phase3 = phase3.replace("|", "\\|").replace("\n", " ")[:120]

        lines.append(
            f"| {idx} | `{r['target']}` | {r['status']} | {phase1} | {phase2} | {phase3} | {evidence_display} "
            f"| {r.get('attempts', 'N/A')} | {r.get('elapsed', 'N/A')} | {log_display} |"
        )

    if phase_analyses:
        lines.extend([
            f"",
            f"---",
            f"",
            f"## 三阶段详情",
            f"",
        ])
        for r in results:
            analysis = phase_analyses.get(r["target"])
            if not analysis:
                continue
            lines.extend([
                f"### `{r['target']}`",
                f"",
                phase_details_markdown(analysis, heading_level=4),
                f"",
            ])

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 🗒️ 备注",
        f"",
        f"- 日志文件均位于项目 `logs/` 目录下，可通过上方链接快速跳转",
        f"- 每个靶机的详细攻击过程参见 `logs/challenges/` 目录中对应的题目日志",
        f"- 超时阈值由环境变量 `SINGLE_TASK_TIMEOUT` 控制（默认 900s）",
        f"",
    ])

    # ==================== 写入文件 ====================
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n[REPORT] ✅ 报告已生成: {output_path}")


# ==================== 单靶机执行函数 ====================

def run_single_target(target: str, retry: int, vulhub_dir: str, outer_timeout: int) -> dict:
    """
    启动子进程对单个靶机执行渗透测试，阻塞等待其完成，并返回结果。

    Args:
        target:        靶机路径（如 cacti/CVE-2022-46169）
        retry:         最大重试次数（传给 main.py 的 --retry 参数）
        vulhub_dir:    Vulhub 仓库目录
        outer_timeout: 外层超时（稍大于内部超时，作为最终兜底）

    Returns:
        结果字典 {target, status, evidence, attempts, elapsed, log_file}
    """
    # 在启动前记录 logs/ 的文件快照，用于事后找到新日志
    log_snapshot_before = snapshot_existing_logs()

    # 构造命令行
    cmd = [
        "uv", "run", "python", "main.py",
        "--vulhub", target,
        "--vulhub-dir", vulhub_dir,
    ]
    if retry > 0:
        cmd.extend(["--retry", str(retry)])

    start_time = time.time()
    result = {
        "target": target,
        "status": STATUS_FAILURE,
        "evidence": "未开始",
        "attempts": "N/A",
        "elapsed": "N/A",
        "log_file": None,
    }

    try:
        # 使用 subprocess 阻塞执行（等待 main.py 自然退出或超时）
        # stdout 和 stderr 都合并到 stdout，方便统一匹配关键词
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),      # 必须在项目根目录下运行
            capture_output=False,        # 不捕获，让输出实时滚动到当前终端
            text=True,
            timeout=outer_timeout,       # 外层超时保护
        )

        # 注意：由于没有捕获输出，我们无法直接对 stdout 做关键词匹配
        # 转而使用 returncode 和日志文件内容来进行结果判定
        elapsed = int(time.time() - start_time)
        result["elapsed"] = str(elapsed)

        # 找到本次新生成的日志文件
        log_file = find_new_log(log_snapshot_before)
        result["log_file"] = log_file

        # 从日志文件中读取内容（因为我们没有捕获 stdout）
        if log_file:
            try:
                with open(log_file, "r", encoding="utf-8") as lf:
                    log_content = lf.read()
                status, evidence = analyze_output(log_content)
                attempts = extract_attempts(log_content)
                result.update({
                    "status": status,
                    "evidence": evidence,
                    "attempts": attempts,
                })
            except Exception as read_err:
                result["status"] = STATUS_ERROR
                result["evidence"] = f"无法读取日志文件: {read_err}"
        else:
            # 没有找到日志文件，只凭 returncode 判断
            if proc.returncode == 0:
                result["status"] = STATUS_FAILURE
                result["evidence"] = "程序正常退出，但未找到日志文件确认结果"
            else:
                result["status"] = STATUS_ERROR
                result["evidence"] = f"进程异常退出 (returncode={proc.returncode})"

    except subprocess.TimeoutExpired:
        # ⭐ 修复二：外层超时触发时，main.py 被强制杀死，其 finally 块不会执行
        # 必须由我们主动清理 Docker 容器，否则残留容器会占用端口导致下一个靶机启动失败
        elapsed = int(time.time() - start_time)
        result["status"] = STATUS_TIMEOUT
        result["evidence"] = f"外层超时保护触发（{outer_timeout}s），进程已被强制终止"
        result["elapsed"] = str(elapsed)
        result["log_file"] = find_new_log(log_snapshot_before)
        _force_docker_cleanup(target, vulhub_dir)

    except KeyboardInterrupt:
        # 用户手动 Ctrl+C 中断整个批量脚本
        # 同样需要清理 Docker 容器，防止残留
        print("\n\n[INTERRUPT] 🛑 用户中断，正在清理 Docker 容器并保存已完成的结果...")
        result["status"] = STATUS_ERROR
        result["evidence"] = "用户手动中断 (Ctrl+C)"
        result["elapsed"] = str(int(time.time() - start_time))
        result["log_file"] = find_new_log(log_snapshot_before)
        _force_docker_cleanup(target, vulhub_dir)
        raise  # 继续向上抛出，让主循环感知并退出

    except Exception as e:
        result["status"] = STATUS_ERROR
        result["evidence"] = f"脚本执行异常: {e}"
        result["elapsed"] = str(int(time.time() - start_time))
        result["log_file"] = find_new_log(log_snapshot_before)
        _force_docker_cleanup(target, vulhub_dir)

    return result


# ==================== Docker 兜底清理函数 ====================

def _force_docker_cleanup(target: str, vulhub_dir: str) -> None:
    """
    强制执行 Docker 兜底清理（仅在外层强制终止进程时调用）。

    背景：
    - main.py 的 finally 块负责常规清理（teardown）
    - 当我们的外层超时/Ctrl+C 强制杀死 main.py 进程时，该 finally 块不会执行
    - 此函数作为终极兜底，确保 Docker 容器被关闭、端口被释放
    - 这样下一个靶机启动时不会因端口冲突而失败

    Args:
        target:     靶机路径（如 cacti/CVE-2022-46169）
        vulhub_dir: Vulhub 仓库根目录
    """
    # 构造靶机的 docker-compose 目录路径
    target_compose_dir = Path(vulhub_dir) / target

    if not target_compose_dir.exists():
        print(f"  [CLEANUP] ⚠️ 目录不存在，跳过清理: {target_compose_dir}")
        return

    print(f"  [CLEANUP] 🧹 正在强制清理 Docker 容器: {target}")
    print(f"  [CLEANUP]    目录: {target_compose_dir}")

    try:
        cleanup_proc = subprocess.run(
            ["docker", "compose", "down", "-v"],
            cwd=str(target_compose_dir),
            capture_output=True,   # 捕获输出，避免与主界面混淆
            text=True,
            timeout=60,            # 给 docker compose down 最多 60 秒
        )
        if cleanup_proc.returncode == 0:
            print(f"  [CLEANUP] ✅ Docker 容器已清理完毕")
        else:
            # compose down 失败，打印错误供用户参考
            err = cleanup_proc.stderr.strip() or cleanup_proc.stdout.strip()
            print(f"  [CLEANUP] ⚠️ docker compose down 返回非零退出码: {err[:200]}")
    except subprocess.TimeoutExpired:
        print(f"  [CLEANUP] ⚠️ docker compose down 超时（60s），请手动执行:")
        print(f"  [CLEANUP]    cd \"{target_compose_dir}\" && docker compose down -v")
    except FileNotFoundError:
        # docker 命令不在 PATH 里
        print(f"  [CLEANUP] ⚠️ 未找到 docker 命令，请手动执行:")
        print(f"  [CLEANUP]    cd \"{target_compose_dir}\" && docker compose down -v")
    except Exception as e:
        print(f"  [CLEANUP] ⚠️ 清理时发生异常: {e}")
        print(f"  [CLEANUP]    请手动执行: cd \"{target_compose_dir}\" && docker compose down -v")


# ==================== 打印进度函数 ====================

def print_separator(char: str = "=", length: int = 70) -> None:
    """打印分隔线"""
    print(char * length)


def print_progress_header(current: int, total: int, target: str) -> None:
    """打印当前靶机测试的进度标题"""
    print_separator()
    print(f"  [{current}/{total}] 🎯 正在测试: {target}")
    print(f"  开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator()


def print_result_summary(result: dict) -> None:
    """打印单个靶机测试完成后的简要摘要"""
    print_separator("-", 70)
    print(f"  结果: {result['status']}")
    print(f"  证据: {result['evidence'][:80]}")
    print(f"  耗时: {result['elapsed']} 秒")
    if result.get("log_file"):
        print(f"  日志: {result['log_file']}")
    print_separator("-", 70)


def print_final_summary(results: list[dict]) -> None:
    """打印全部测试完成后的总结报告到终端"""
    total = len(results)
    success_count = sum(1 for r in results if r["status"] == STATUS_SUCCESS)

    print_separator()
    print(f"  🏁 批量测试完成！")
    print(f"  总计: {total} 个靶机  |  成功: {success_count}  |  失败: {total - success_count}")
    print(f"  成功率: {success_count / total * 100:.1f}%" if total > 0 else "  成功率: N/A")
    print_separator()

    # 列出成功的靶机
    successful = [r for r in results if r["status"] == STATUS_SUCCESS]
    if successful:
        print("\n  ✅ 成功的靶机:")
        for r in successful:
            print(f"     - {r['target']}")

    # 列出失败/超时的靶机
    failed = [r for r in results if r["status"] != STATUS_SUCCESS]
    if failed:
        print("\n  ❌ 失败/异常的靶机:")
        for r in failed:
            print(f"     - {r['target']}  ({r['status']})")

    print()


# ==================== 主入口 ====================

def main():
    """主函数 - 解析参数、遍历靶机队列、生成报告"""
    parser = argparse.ArgumentParser(
        description="VulnPilot - Vulhub 批量自动化渗透测试脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用默认设置跑 targets.txt 中的所有靶机
  uv run python scripts/batch_vulhub_test.py --targets targets.txt

  # 每个靶机允许 1 次重试，自定义报告输出路径
  uv run python scripts/batch_vulhub_test.py --targets targets.txt --retry 1 --output logs/batch_test/my_report.md

targets.txt 格式（每行一个靶机）:
  cacti CVE-2022-46169
  uwsgi CVE-2018-7490
  # 这是注释，会被忽略
  unomi/CVE-2020-13942
        """,
    )

    parser.add_argument(
        "--targets",
        required=True,
        metavar="FILE",
        help="包含靶机列表的 .txt 文件路径（每行一个靶机，格式: '应用名 CVE-XXXX-XXXXX'）"
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=0,
        metavar="N",
        help="每个靶机的最大重试次数（默认 0，不重试）"
    )
    parser.add_argument(
        "--vulhub-dir",
        type=str,
        default=DEFAULT_VULHUB_DIR,
        metavar="DIR",
        help=f"Vulhub 仓库本地路径（默认 {DEFAULT_VULHUB_DIR}）"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="PATH",
        help="报告输出路径（默认: logs/batch_test/batch_report_时间戳.md）"
    )
    parser.add_argument(
        "--disable-process-notebook",
        action="store_true",
        help="消融实验：关闭过程笔记注入和更新。"
    )
    parser.add_argument(
        "--disable-skills",
        action="store_true",
        help="消融实验：关闭 SKILL.md 知识库按需加载。"
    )

    args = parser.parse_args()

    if args.disable_process_notebook:
        os.environ["ENABLE_PROCESS_NOTEBOOK"] = "false"
    else:
        os.environ.setdefault("ENABLE_PROCESS_NOTEBOOK", "true")

    if args.disable_skills:
        os.environ["ENABLE_SKILLS"] = "false"
    else:
        os.environ.setdefault("ENABLE_SKILLS", "true")

    # ==================== 1. 解析靶机列表 ====================
    targets = parse_targets_from_file(args.targets)

    if not targets:
        print("[ERROR] 靶机列表为空，请检查 targets.txt 文件内容")
        sys.exit(1)

    total = len(targets)
    print_separator()
    print(f"  🚀 VulnPilot 批量渗透测试")
    print(f"  靶机总数: {total} 个")
    print(f"  每题重试: {args.retry} 次")
    print(f"  Vulhub 仓库: {args.vulhub_dir}")
    print(f"  过程笔记: {os.environ.get('ENABLE_PROCESS_NOTEBOOK')}")
    print(f"  Skills: {os.environ.get('ENABLE_SKILLS')}")
    print_separator()
    print(f"\n  靶机队列:")
    for i, t in enumerate(targets, 1):
        print(f"    {i:2d}. {t}")
    print()

    # ==================== 2. 确定外层超时 ====================
    outer_timeout = get_outer_timeout()
    print(f"  外层超时保护: {outer_timeout}s（内部超时 + {OUTER_TIMEOUT_BUFFER}s 缓冲）\n")

    # ==================== 3. 确定报告输出路径 ====================
    if args.output:
        report_path = avoid_report_overwrite(Path(args.output))
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = LOGS_DIR / "batch_test" / f"batch_report_{timestamp}.md"

    # ==================== 4. 遍历执行每个靶机 ====================
    all_results: list[dict] = []

    try:
        for idx, target in enumerate(targets, start=1):
            print_progress_header(idx, total, target)

            result = run_single_target(
                target=target,
                retry=args.retry,
                vulhub_dir=args.vulhub_dir,
                outer_timeout=outer_timeout,
            )

            all_results.append(result)
            print_result_summary(result)

            # ⭐ 无论当前靶机测试结果如何（成功/失败/超时/异常），
            # 在进入下一个靶机之前，始终主动执行一次容器清理。
            #
            # 设计理由：
            # - 情况 A（main.py 正常退出）：其内部 finally 块已执行 teardown()，
            #   此处再次 docker compose down 是幂等操作（无任何影响）
            # - 情况 B（main.py 被外层强制杀死）：其 finally 不会执行，
            #   此处是唯一的清理机会，缺少它会导致孤儿容器占用端口
            # → 因此"始终清理"比"有条件清理"更稳健，副作用极小
            print(f"\n  [LIFECYCLE] 🔄 靶机 {target} 测试结束，执行收尾清理...")
            _force_docker_cleanup(target, args.vulhub_dir)

            # 靶机之间短暂等待，给 Docker 网络资源彻底释放留足时间
            if idx < total:
                wait_secs = 10  # 从 5s 调整为 10s，给 docker 网络释放留足缓冲
                print(f"\n  ⏳ 等待 {wait_secs} 秒后开始下一个靶机...\n")
                time.sleep(wait_secs)

    except KeyboardInterrupt:
        # 用户中断时，保存已有的结果
        print(f"\n  共完成 {len(all_results)} / {total} 个靶机的测试")

    # ==================== 5. 生成报告 ====================
    if all_results:
        print_final_summary(all_results)
        generate_markdown_report(all_results, report_path)
    else:
        print("[WARN] 没有任何测试结果，跳过报告生成")


if __name__ == "__main__":
    main()
