"""
工具模块
========

导出所有可用的工具函数。

核心理念：
- 提供统一的工具入口
- 工具函数直接返回原始输出，由 LLM 自主决策
- 支持多类工具：Shell 命令、Python PoC、记忆工具、Web 工具
"""
from vulnpilot.tools.shell import execute_command
from vulnpilot.tools.shell_enhanced import execute_python_poc
from vulnpilot.tools.memory_tools import get_memory_tools
from vulnpilot.tools.web_tools import extract_web_form_fields
from vulnpilot.tools.exploit_tools import searchsploit_search, searchsploit_read, msf_exploit
from vulnpilot.tools.oob_tools import get_attack_ip, start_jndi_server, check_jndi_callback, stop_jndi_server


# 导出所有可用工具
__all__ = [
    "execute_command",
    "execute_python_poc",
    "get_memory_tools",
    "extract_web_form_fields",
    "searchsploit_search",
    "searchsploit_read",
    "msf_exploit",
    # OOB 外带攻击基础设施
    "get_attack_ip",
    "start_jndi_server",
    "check_jndi_callback",
    "stop_jndi_server",
]


def get_all_tools():
    """
    获取所有渗透测试工具列表

    不包括记忆和评测工具（这些由 langmem_memory.py 统一管理）

    Returns:
        工具函数列表
    """
    return [
        execute_command,
        execute_python_poc,
        extract_web_form_fields,
        searchsploit_search,
        searchsploit_read,
        msf_exploit,
        # OOB 外带攻击工具（JNDI 注入类漏洞专用）
        get_attack_ip,
        start_jndi_server,
        check_jndi_callback,
        stop_jndi_server,
    ]
