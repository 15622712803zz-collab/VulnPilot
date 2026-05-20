"""
情报工具模块 - Intelligence Tools（纯 HTTP 方案，兼容 Windows）
===============================================================

为情报智能体（Intelligence Agent）提供漏洞情报搜集工具。

【架构说明】
本项目运行于 Windows + Docker Desktop 环境，没有 Kali Linux 环境，
因此所有情报搜集均通过公开的 HTTP API 完成：

1. ExploitDB 公开搜索 API（无需 API Key）
   - 搜索 URL：https://www.exploit-db.com/search?cve=CVE-XXXX-XXXX
   - 详情 URL：https://www.exploit-db.com/raw/{edb_id}

2. GitHub 公开搜索 API（可选，需要 GITHUB_TOKEN 环境变量）
   - 搜索已知的 CVE PoC 仓库

3. NVD（美国国家漏洞数据库）API
   - 获取 CVE 详细描述和 CVSS 分数

所有工具使用 requests 库发送 HTTP 请求，Windows/Linux 均可使用。
"""

import os
import re
import json
import logging
import time
from typing import Optional
import requests
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# HTTP 请求超时（秒）
HTTP_TIMEOUT = 15

# 模拟浏览器 User-Agent，避免被反爬
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


@tool
def searchsploit_cve(cve_id: str) -> str:
    """
    通过 ExploitDB 公开搜索接口排查指定 CVE 的已公开利用代码（PoC/Exploit）。
    返回搜索结果列表，包含 ExploitDB 编号、漏洞标题和 Exploit 类型。
    在确认目标存在特定 CVE 漏洞后调用此工具获取情报。

    Args:
        cve_id: 要搜索的 CVE 编号，例如 "CVE-2021-22205"
    """
    cve_upper = cve_id.strip().upper()
    logger.info(f"[情报工具] 通过 ExploitDB API 搜索 CVE: {cve_upper}")

    # 方法一：ExploitDB 搜索 API
    try:
        # ExploitDB 官方提供了 JSON 格式的搜索接口
        api_url = f"https://www.exploit-db.com/search"
        params = {
            "cve": cve_upper.replace("CVE-", ""),  # ExploitDB 接受不带 "CVE-" 前缀的格式
            "type": "exploits",
            "platform": "",
        }
        response = requests.get(
            api_url,
            params=params,
            headers={**HEADERS, "Accept": "application/json"},
            timeout=HTTP_TIMEOUT
        )

        if response.status_code == 200:
            try:
                data = response.json()
                # ExploitDB 的 JSON 响应格式
                records = data.get("data", [])
                if records:
                    results = []
                    for r in records[:5]:  # 最多取前 5 条
                        edb_id = r.get("id", "")
                        title = r.get("description", "")
                        exp_type = r.get("type", {}).get("name", "")
                        platform = r.get("platform", {}).get("name", "")
                        results.append(
                            f"EDB-{edb_id} | {title} | 类型: {exp_type} | 平台: {platform}"
                        )

                    if results:
                        result_text = "\n".join(results)
                        logger.info(f"[情报工具] ExploitDB 找到 {len(results)} 个结果")
                        return (
                            f"[ExploitDB 搜索结果 - {cve_upper}]\n"
                            f"（找到 {len(records)} 个利用，显示前 {len(results)} 个）\n\n"
                            f"{result_text}\n\n"
                            f"提示：使用 fetch_exploitdb_poc 工具获取具体 EDB 编号的 PoC 源码。"
                        )
            except (json.JSONDecodeError, KeyError):
                # JSON 解析失败，尝试从 HTML 中提取
                pass
    except requests.RequestException as e:
        logger.warning(f"[情报工具] ExploitDB API 请求失败: {e}")

    # 方法二：使用 NVD API 获取漏洞基本信息（作为 PoC 搜索的补充）
    nvd_info = _get_nvd_info(cve_upper)
    if nvd_info:
        return (
            f"[CVE 情报 - {cve_upper}]\n\n"
            f"未在 ExploitDB 中找到公开 PoC，但获取到以下 CVE 详情：\n\n"
            f"{nvd_info}\n\n"
            f"建议：根据以上漏洞描述，由 LLM 推断攻击方式并构造 Playbook。"
        )

    # 方法三：返回基础信息，让 LLM 根据训练知识构造
    return (
        f"ExploitDB 和 NVD 均未能获取 {cve_upper} 的公开情报（可能是网络问题或漏洞较新）。\n"
        f"请根据 CVE 编号的已知信息和你的安全知识，直接推断该漏洞的攻击方式并生成 Playbook。"
    )


@tool
def fetch_exploitdb_poc(edb_id: str, cve_id: str = "") -> str:
    """
    从 ExploitDB 直接获取指定 EDB-ID 的 Exploit 源代码全文（通过 HTTP API，Windows 兼容）。
    在 searchsploit_cve 工具返回了 EDB 编号之后，使用此工具去抓取具体脚本的内容。
    读取源码后分析发包格式（接口路径、参数名称、HTTP 方法）来生成攻击指导书。

    Args:
        edb_id: ExploitDB 的 Exploit 编号，如 "50220"
        cve_id: 关联的 CVE 编号（可选，用于日志记录）
    """
    # 清理 EDB ID（去掉可能的 "EDB-" 前缀）
    clean_id = str(edb_id).strip().upper().replace("EDB-", "").replace("EDB", "")
    logger.info(f"[情报工具] 从 ExploitDB 获取 EDB-{clean_id} 源码（CVE: {cve_id}）")

    # ExploitDB 的 RAW 内容直接访问接口（无需登录）
    raw_url = f"https://www.exploit-db.com/raw/{clean_id}"

    try:
        response = requests.get(
            raw_url,
            headers=HEADERS,
            timeout=HTTP_TIMEOUT
        )

        if response.status_code == 200:
            poc_content = response.text

            # 截取最多 3000 字符（避免超过 LLM 上下文限制）
            truncated = poc_content[:3000]
            truncate_note = (
                f"\n\n...[内容已截断，共 {len(poc_content)} 字符，仅显示前 3000 字符]"
                if len(poc_content) > 3000 else ""
            )

            logger.info(f"[情报工具] 成功获取 EDB-{clean_id}，共 {len(poc_content)} 字节")
            return (
                f"[EDB-{clean_id} PoC 源码]\n"
                f"来源：{raw_url}\n"
                f"---\n"
                f"```\n{truncated}{truncate_note}\n```"
            )

        elif response.status_code == 404:
            return (
                f"EDB-{clean_id} 不存在或已被移除。"
                f"请尝试其他 EDB 编号，或根据 CVE {cve_id} 的知识手动构造 Playbook。"
            )
        else:
            logger.warning(f"[情报工具] ExploitDB 返回状态码: {response.status_code}")
            return f"获取 EDB-{clean_id} 失败，HTTP 状态码: {response.status_code}。请根据 CVE 知识直接生成 Playbook。"

    except requests.RequestException as e:
        logger.error(f"[情报工具] 请求 ExploitDB 异常: {e}")
        return (
            f"网络请求失败（{type(e).__name__}: {e}）。"
            f"可能是网络问题。请根据 {cve_id or 'CVE'} 的已知知识直接生成 Playbook。"
        )


@tool
def extract_cve_from_target_info(target_description: str) -> str:
    """
    从目标描述文字（如 nmap 输出、banner 信息、应用报错页面）中自动识别
    可能关联的 CVE 编号，返回逗号分隔的 CVE 列表字符串。
    当侦察阶段获取到目标的版本信息，且需要快速判断是否存在已知漏洞时使用。

    Args:
        target_description: 包含目标信息的文本，如 nmap 输出、应用版本号等
    """
    # 使用正则直接提取 CVE 编号
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    found = cve_pattern.findall(target_description)

    if found:
        unique_cves = list(dict.fromkeys([c.upper() for c in found]))  # 去重保序
        return f"在目标信息中识别到以下 CVE 编号：{', '.join(unique_cves)}"
    else:
        return (
            "未在目标描述中直接找到 CVE 编号。\n"
            "请根据版本信息（如 GitLab 13.10.2、Liferay 7.2.0 等）"
            "联系已知历史漏洞进行分析，并直接生成对应的攻击 Playbook。"
        )


@tool
def search_github_poc(cve_id: str) -> str:
    """
    通过 GitHub 搜索 API 查找指定 CVE 的公开 PoC 仓库，返回仓库名称、描述和链接。
    作为 ExploitDB 的补充手段，尤其适合较新的 CVE（ExploitDB 可能尚未收录）。
    需要 GITHUB_TOKEN 环境变量（可选，无 Token 也能搜索但有速率限制）。

    Args:
        cve_id: 要搜索的 CVE 编号，例如 "CVE-2021-22205"
    """
    cve_upper = cve_id.strip().upper()
    logger.info(f"[情报工具] 通过 GitHub 搜索 CVE PoC: {cve_upper}")

    # 构造 GitHub 搜索请求
    search_url = "https://api.github.com/search/repositories"
    params = {
        "q": f"{cve_upper} exploit poc",
        "sort": "stars",
        "order": "desc",
        "per_page": 5
    }

    # 可选：使用 GitHub Token 提高速率限制
    github_token = os.getenv("GITHUB_TOKEN")
    req_headers = {**HEADERS}
    if github_token:
        req_headers["Authorization"] = f"token {github_token}"

    try:
        response = requests.get(
            search_url,
            params=params,
            headers=req_headers,
            timeout=HTTP_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])

            if not items:
                return f"GitHub 上未找到关于 {cve_upper} 的公开 PoC 仓库。"

            results = []
            for repo in items[:5]:
                name = repo.get("full_name", "")
                desc = repo.get("description", "") or "（无描述）"
                stars = repo.get("stargazers_count", 0)
                url = repo.get("html_url", "")
                results.append(f"⭐{stars} | [{name}]({url}) - {desc[:100]}")

            result_text = "\n".join(results)
            return (
                f"[GitHub PoC 搜索 - {cve_upper}]\n"
                f"（找到 {data.get('total_count', 0)} 个相关仓库，显示前 {len(results)} 个）\n\n"
                f"{result_text}\n\n"
                f"注意：这些仓库可能包含可直接运行的 PoC 脚本，请分析其中的 HTTP 请求格式。"
            )

        elif response.status_code == 403:
            return (
                f"GitHub API 速率限制（请设置 GITHUB_TOKEN 环境变量提高限制）。"
                f"请根据 {cve_upper} 的知识直接生成 Playbook。"
            )
        else:
            return f"GitHub API 返回: {response.status_code}，请根据 CVE 知识直接生成 Playbook。"

    except requests.RequestException as e:
        logger.error(f"[情报工具] GitHub 搜索请求失败: {e}")
        return f"网络请求失败（{e}），请根据 CVE 知识直接生成 Playbook。"


def _get_nvd_info(cve_id: str) -> str:
    """
    辅助函数：从 NVD API 获取 CVE 的漏洞描述和 CVSS 评分（英文）

    Args:
        cve_id: CVE 编号（如 "CVE-2021-22205"）

    Returns:
        CVE 描述字符串，获取失败则返回空字符串
    """
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    try:
        # NVD API 有速率限制，单次请求加少量延迟
        time.sleep(0.5)
        response = requests.get(nvd_url, params=params, timeout=HTTP_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                vuln = vulnerabilities[0].get("cve", {})
                descriptions = vuln.get("descriptions", [])
                # 优先取英文描述
                desc_en = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    ""
                )
                # 获取 CVSS 分数
                metrics = vuln.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) \
                          if metrics.get("cvssMetricV31") else {}
                base_score = cvss_v3.get("baseScore", "未知")
                severity = cvss_v3.get("baseSeverity", "未知")

                return (
                    f"漏洞描述：{desc_en[:500]}\n"
                    f"CVSS 评分：{base_score}（{severity}）"
                )
    except Exception as e:
        logger.debug(f"[情报工具] NVD API 请求失败（非关键路径）: {e}")

    return ""
