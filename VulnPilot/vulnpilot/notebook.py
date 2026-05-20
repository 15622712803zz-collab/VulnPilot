"""
过程笔记模块（ProcessNotebook）
================================

参考结构化过程笔记 的 Context 分层设计，为 VulnPilot 实现
单题目内部的结构化动态笔记。

核心功能：
- 从工具输出自动提取关键信息（规则驱动，无需LLM）
- 合并笔记增量到现有笔记
- 格式化笔记供各 Agent 读取

设计原则（参考结构化过程笔记 task.py）：
- 每次工具输出 → 自动提取信息写入笔记（对应 add_cell_content）
- 每次失败 → 自动记录失败原因（对应 add_error）
- 笔记随题目生命周期，题目结束即清空
"""

import re
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from vulnpilot.common import log_system_event
from vulnpilot.ablation_config import process_notebook_enabled


# ==================== 初始化 ====================

def init_notebook(state: Dict) -> Dict:
    """
    初始化一个空白笔记（每道题开始时调用）

    Args:
        state: 当前 Agent 状态

    Returns:
        初始化的空白笔记字典
    """
    if not process_notebook_enabled():
        return None

    challenge_code = ""
    target_url = ""

    if state.get("current_challenge"):
        challenge_code = state["current_challenge"].get("challenge_code", "")
        target_info = state["current_challenge"].get("target_info", {})
        ip = target_info.get("ip", "")
        ports = target_info.get("port", [])
        if ip and ports:
            target_url = f"http://{ip}:{ports[0]}"

    return {
        "meta": {
            "challenge_code": challenge_code,
            "target_url": target_url,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "round_count": 0,
        },
        "assets": [],           # 发现的资产（端点/文件/参数/服务）
        "verified_vulns": [],   # 已验证的漏洞
        "failed_attempts": [],  # 已失败的尝试（避免重复）
        "round_log": [],        # 每轮行动记录
        "current_hypothesis": "",  # 当前攻击假设
        "key_findings": [],     # 关键发现摘要
    }


# ==================== 提取器（规则驱动，参考结构化过程笔记 add_cell_content）====================

def extract_from_tool_output(
    tool_name: str,
    tool_output: str,
    round_num: int
) -> Dict:
    """
    从工具输出中自动提取关键信息（无LLM，纯规则）

    对应过程笔记的 add_cell_content() 机制：
    每次工具执行完成后自动调用，提取有价值信息。

    Args:
        tool_name: 工具名称
        tool_output: 工具输出内容
        round_num: 当前轮次

    Returns:
        笔记增量字典（只包含本次提取到的内容）
    """
    if not process_notebook_enabled():
        return {}

    delta = {
        "assets": [],
        "verified_vulns": [],
        "failed_attempts": [],
        "round_log": [],
        "key_findings": [],
        "current_hypothesis": None,  # None 表示不更新
    }

    if not tool_output or len(tool_output) < 5:
        return delta

    output = tool_output
    output_lower = output.lower()

    # ---------- 提取 API 端点（资产） ----------
    # 匹配 /api/xxx、/admin/xxx 等路径
    api_patterns = [
        r'(/api/[a-zA-Z0-9_/\-?=&]+)',
        r'(/admin[a-zA-Z0-9_/\-?=&]*)',
        r'(/user[a-zA-Z0-9_/\-?=&]+)',
        r'(/login[a-zA-Z0-9_/\-?=&]*)',
        r'(/upload[a-zA-Z0-9_/\-?=&]*)',
        r'(/flag[a-zA-Z0-9_/\-?=&]*)',
        r'路径[：:]\s*([/a-zA-Z0-9_\-?=&.]+)',
        r'endpoint[：:]\s*([/a-zA-Z0-9_\-?=&.]+)',
    ]
    found_endpoints = set()
    for pattern in api_patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        for m in matches:
            # 过滤掉太短或明显不是端点的匹配
            if len(m) > 2 and m not in found_endpoints:
                found_endpoints.add(m.split("?")[0])  # 去掉查询参数

    for endpoint in found_endpoints:
        delta["assets"].append({
            "type": "endpoint",
            "value": endpoint,
            "detail": {"tool": tool_name},
            "round": round_num,
        })

    # ---------- 提取状态码信息 ----------
    status_match = re.search(r'(?:状态码|status[_\s]?code)[：:\s]*(\d{3})', output, re.IGNORECASE)
    status_code = None
    if status_match:
        status_code = int(status_match.group(1))

    # ---------- 提取关键发现 ----------
    # 发现类关键词
    discovery_keywords = [
        "发现", "找到", "检测到", "存在漏洞", "可利用",
        "注入成功", "绕过成功", "获取到", "泄露",
    ]
    seen_snippets = set()
    for kw in discovery_keywords:
        idx = output.find(kw)
        if idx == -1:
            continue
        # 提取关键词附近的上下文（前10字符 + 后60字符，控制长度）
        snippet = output[max(0, idx-10):idx+60].strip().replace("\n", " ")
        # 去重：跳过与已有条目高度重叠的内容
        is_dup = any(snippet in s or s in snippet for s in seen_snippets)
        if snippet and not is_dup:
            delta["key_findings"].append(snippet)
            seen_snippets.add(snippet)

    # ---------- 提取敏感信息 ----------
    # 邮箱
    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', output)
    for email in emails[:2]:  # 最多2个
        finding = f"邮箱泄露: {email}"
        if finding not in delta["key_findings"]:
            delta["key_findings"].append(finding)

    # 版本信息
    version_matches = re.findall(r'(?:version|ver)[：:\s]*([\d.]+)', output, re.IGNORECASE)
    for ver in version_matches[:2]:
        finding = f"版本信息: {ver}"
        if finding not in delta["key_findings"]:
            delta["key_findings"].append(finding)

    # ---------- 判断是否失败，提取失败原因 ----------
    failure_keywords = {
        "waf": "WAF防护拦截",
        "403": "403 Forbidden",
        "401": "401 Unauthorized",
        "invalid": "输入验证拒绝",
        "syntax error": "语法错误",
        "permission denied": "权限拒绝",
        "filtered": "被过滤拦截",
        "编码": "输出被编码",
    }
    failure_reason = None
    for kw, reason in failure_keywords.items():
        if kw in output_lower:
            failure_reason = reason
            break

    if status_code and status_code in (403, 401, 500) and not failure_reason:
        failure_reason = f"HTTP {status_code} 响应"

    # ---------- 失败时自动写入 failed_attempts ----------
    if failure_reason:
        # 提取目标路径
        target_match = re.search(r'(https?://[^\s]+|/[a-zA-Z0-9_/\-?.&=]+)', output)
        target = target_match.group(1) if target_match else "未知目标"
        # 提取payload（如 OR 1=1、<script>等）
        payload_match = re.search(
            r"(?:payload|尝试)[：:\s]*([^\n]{1,50})", output, re.IGNORECASE
        )
        payload = payload_match.group(1).strip() if payload_match else ""
        delta["failed_attempts"].append({
            "method": tool_name,
            "target": target,
            "payload": payload,
            "reason": failure_reason,
            "round": round_num,
        })

    # ---------- 记录本轮行动 ----------
    output_preview = output[:150].replace("\n", " ").strip()
    round_entry = {
        "round": round_num,
        "tool": tool_name,
        "status_code": status_code,
        "preview": output_preview,
        "endpoints_found": len(found_endpoints),
        "failed": failure_reason is not None,
    }
    delta["round_log"].append(round_entry)

    log_system_event(
        "[📓] 笔记提取完成",
        {
            "tool": tool_name,
            "round": round_num,
            "assets_found": len(found_endpoints),
            "key_findings": len(delta["key_findings"]),
            "failure_detected": failure_reason is not None,
        }
    )

    return delta


def extract_failed_attempt(
    tool_name: str,
    tool_output: str,
    round_num: int,
    method_hint: str = ""
) -> Optional[Dict]:
    """
    从失败的工具输出中提取失败记录

    对应过程笔记的 add_error() 机制

    Args:
        tool_name: 工具名称
        tool_output: 工具输出
        round_num: 当前轮次
        method_hint: 失败的方法提示（如 sqli/xss 等）

    Returns:
        失败记录字典，若无法判断失败则返回 None
    """
    if not tool_output:
        return None

    output_lower = tool_output.lower()

    # 判断是否失败
    failure_indicators = [
        "error", "exception", "failed", "failure",
        "拒绝", "失败", "错误", "无法", "invalid",
        "403", "401", "waf", "blocked", "filtered"
    ]
    is_failure = any(ind in output_lower for ind in failure_indicators)

    if not is_failure:
        return None

    # 提取失败原因
    reason = "未知原因"
    reason_patterns = {
        "WAF拦截": ["waf", "blocked", "filtered"],
        "权限拒绝": ["403", "forbidden", "permission denied"],
        "未授权": ["401", "unauthorized"],
        "输入验证": ["invalid", "syntax error", "validation"],
        "编码防护": ["encoded", "编码", "html entity"],
    }
    for reason_text, keywords in reason_patterns.items():
        if any(kw in output_lower for kw in keywords):
            reason = reason_text
            break

    # 提取目标（查找URL或路径）
    target_match = re.search(r'(https?://[^\s]+|/[a-zA-Z0-9_/\-?.&=]+)', tool_output)
    target = target_match.group(1) if target_match else "未知目标"

    return {
        "method": method_hint or tool_name,
        "target": target,
        "reason": reason,
        "round": round_num,
        "preview": tool_output[:100].replace("\n", " "),
    }


# ==================== 合并器 ====================

def merge_notebook(existing: Dict, delta: Dict) -> Dict:
    """
    将笔记增量合并到现有笔记

    对应过程笔记的 context.update() 机制

    Args:
        existing: 现有笔记
        delta: 本次提取的增量

    Returns:
        合并后的笔记
    """
    if not process_notebook_enabled() or not existing:
        return existing

    import copy
    result = copy.deepcopy(existing)

    # 更新轮次计数
    result["meta"]["round_count"] = result["meta"].get("round_count", 0) + 1

    # 合并资产（去重）
    existing_asset_values = {a["value"] for a in result.get("assets", [])}
    for asset in delta.get("assets", []):
        if asset["value"] not in existing_asset_values:
            result.setdefault("assets", []).append(asset)
            existing_asset_values.add(asset["value"])

    # 合并失败记录（去重，同目标+同方法视为重复）
    existing_fail_keys = {
        (f.get("method", ""), f.get("target", ""))
        for f in result.get("failed_attempts", [])
    }
    for fail in delta.get("failed_attempts", []):
        key = (fail.get("method", ""), fail.get("target", ""))
        if key not in existing_fail_keys:
            result.setdefault("failed_attempts", []).append(fail)
            existing_fail_keys.add(key)

    # 追加轮次记录（保留最近30条）
    result.setdefault("round_log", []).extend(delta.get("round_log", []))
    if len(result["round_log"]) > 30:
        result["round_log"] = result["round_log"][-30:]

    # 合并关键发现（去重，最多20条）
    existing_findings = set(result.get("key_findings", []))
    for finding in delta.get("key_findings", []):
        if finding not in existing_findings and len(existing_findings) < 20:
            result.setdefault("key_findings", []).append(finding)
            existing_findings.add(finding)

    # 合并已验证漏洞
    result.setdefault("verified_vulns", []).extend(delta.get("verified_vulns", []))

    # 更新当前假设（若增量有新假设）
    if delta.get("current_hypothesis"):
        result["current_hypothesis"] = delta["current_hypothesis"]

    return result


def add_failed_attempt(notebook: Dict, failed: Dict) -> Dict:
    """
    向笔记中添加一条失败记录

    Args:
        notebook: 当前笔记
        failed: 失败记录

    Returns:
        更新后的笔记
    """
    if not process_notebook_enabled() or not notebook:
        return notebook

    import copy
    result = copy.deepcopy(notebook)

    existing_fail_keys = {
        (f.get("method", ""), f.get("target", ""))
        for f in result.get("failed_attempts", [])
    }
    key = (failed.get("method", ""), failed.get("target", ""))
    if key not in existing_fail_keys:
        result.setdefault("failed_attempts", []).append(failed)

    return result


# ==================== 格式化器 ====================

def format_notebook_for_context(notebook: Optional[Dict], max_items: int = 5) -> str:
    """
    将笔记格式化为 Markdown 字符串，供 Agent 读取

    对应过程笔记的 context.get_cell_context_summary() 机制

    Args:
        notebook: 过程笔记
        max_items: 每个分类最多显示条数

    Returns:
        格式化后的 Markdown 字符串
    """
    if not process_notebook_enabled():
        return ""

    if not notebook:
        return ""

    sections = []
    sections.append("## 📓 攻击进度笔记\n")

    # --- 已发现资产 ---
    assets = notebook.get("assets", [])
    if assets:
        sections.append("### 🎯 已发现资产")
        for a in assets[-max_items:]:  # 最近N条
            detail = a.get("detail", {})
            method = detail.get("method", "")
            method_str = f" [{method}]" if method else ""
            sections.append(f"- `{a['value']}`{method_str} [第{a.get('round', '?')}轮]")
        sections.append("")

    # --- 已失败方法（勿重复） ---
    failed = notebook.get("failed_attempts", [])
    if failed:
        sections.append("### ❌ 已失败方法（**禁止重复**）")
        for f in failed[-max_items:]:
            sections.append(
                f"- `{f.get('method', '?')}` → `{f.get('target', '?')}` "
                f"→ {f.get('reason', '未知')} [第{f.get('round', '?')}轮]"
            )
        sections.append("")

    # --- 已验证漏洞 ---
    vulns = notebook.get("verified_vulns", [])
    if vulns:
        sections.append("### ✅ 已验证漏洞")
        for v in vulns[-max_items:]:
            conf = int(v.get("confidence", 0) * 100)
            sections.append(
                f"- **{v.get('type', '?')}**: `{v.get('target', '?')}` "
                f"(置信度{conf}%) [第{v.get('round', '?')}轮]"
            )
        sections.append("")

    # --- 关键发现 ---
    findings = notebook.get("key_findings", [])
    if findings:
        sections.append("### 💡 关键发现")
        for f in findings[-max_items:]:
            sections.append(f"- {f}")
        sections.append("")

    # --- 当前假设 ---
    hypothesis = notebook.get("current_hypothesis", "")
    if hypothesis:
        sections.append(f"### 🔍 当前假设\n{hypothesis}\n")

    # --- 最近轮次行动 ---
    round_log = notebook.get("round_log", [])
    if round_log:
        sections.append("### 📋 最近行动记录")
        recent = round_log[-3:]  # 只显示最近3轮
        for entry in recent:
            status = f"[HTTP {entry['status_code']}]" if entry.get("status_code") else ""
            sections.append(
                f"- 第{entry.get('round', '?')}轮 `{entry.get('tool', '?')}` "
                f"{status}: {entry.get('preview', '')[:60]}..."
            )
        sections.append("")

    return "\n".join(sections)


def format_notebook_for_auditor(notebook: Optional[Dict]) -> str:
    """
    为 Auditor Agent 格式化笔记（只需失败记录和轮次记录）

    Args:
        notebook: 过程笔记

    Returns:
        格式化后的 Markdown 字符串
    """
    if not process_notebook_enabled():
        return ""

    if not notebook:
        return ""

    sections = ["## 📓 历史失败记录（审计参考）\n"]

    failed = notebook.get("failed_attempts", [])
    if failed:
        for f in failed[-8:]:
            sections.append(
                f"- `{f.get('method', '?')}` → {f.get('reason', '未知')} "
                f"[第{f.get('round', '?')}轮]"
            )
    else:
        sections.append("_暂无失败记录_")

    return "\n".join(sections)
