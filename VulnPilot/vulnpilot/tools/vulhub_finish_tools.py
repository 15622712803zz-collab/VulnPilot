"""
Vulhub 测试结束工具
===================

允许 Agent 在穷尽利用手段后体面地宣告测试失败/结束，
而无需捏造一个 Flag 来蒙混过关。

借鉴 pentest-agent 的设计原则：
  - 当 executable 返回 "None" 时代理可以合规退出
  - 允许代理说 "I give up" 是一种负责任的行为
  - 防止 LLM 为了"完成任务"而产生幻觉

使用场景：
  - 经过多轮尝试后，无法成功利用目标漏洞
  - ExploitDetector 持续返回 EXPLOITATION_FAILED
  - 目标环境不符合 CVE 的漏洞利用条件（版本已修复、配置不同等）
"""
import logging
from langchain_core.tools import tool
from vulnpilot.common import log_system_event


@tool
def finish_testing(reason: str, summary: str = "") -> str:
    """
    宣告当前靶机漏洞测试结束（无论成功还是失败）。

    ⚠️ 重要：在 Vulhub 渗透测试中，当你穷尽了所有合理的利用手段后，
    应当调用此工具宣告测试结束，而不是捏造一个 Flag 来蒙混过关！

    判断何时应该调用此工具：
    - ExploitDetector 连续多次判定 [EXPLOITATION_FAILED]
    - 同一利用方法失败超过 3 次，且没有新的思路
    - 目标服务返回持续的 502/503/404，表明环境本身异常
    - 已经穷举了 CVE 官方文档描述的所有标准利用步骤，均无效

    Args:
        reason: 测试结束的原因（必填），例如：
                "所有 CVE-2019-5418 的 Accept 头注入 payload 均返回 406，
                 且响应体仅为 Rails 报错页，未能读取真实文件内容"
        summary: 测试过程的简要总结（选填），
                 包括已尝试的方法、发现的有用信息等

    Returns:
        测试结束确认信息
    """
    # 记录"体面投降"事件
    log_system_event(
        "[🏳️] 测试结束 - Agent 主动宣告测试完成",
        {
            "reason": reason[:300],
            "summary_length": len(summary),
            "action": "标记测试为 FINISHED(不成功利用)"
        }
    )

    result_msg = (
        f"✅ 测试结束确认\n\n"
        f"**结束原因**: {reason}\n"
    )
    if summary:
        result_msg += f"\n**过程总结**:\n{summary}\n"

    result_msg += (
        "\n---\n"
        "⚠️ 注意：此工具不代表漏洞利用成功。\n"
        "本次测试已以「利用失败/测试终止」状态记录。\n"
        "系统将据此标记本靶机测试结果为 FAILED，并继续下一个目标。"
    )

    return result_msg


# 导出工具
VULHUB_FINISH_TOOLS = [finish_testing]


def get_vulhub_finish_tools():
    """获取 Vulhub 模式下的测试结束工具"""
    return VULHUB_FINISH_TOOLS
