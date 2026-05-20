"""
重试策略模块
============

实现失败题目的智能重试策略：
- 角色互换（主 Agent 和 Advisor 轮流使用相同模型对）
- 历史记录传承
- 多模型协作（支持 DeepSeek / OpenAI）
"""
import os
import logging
import asyncio
import time
from typing import Tuple, Optional

from vulnpilot.common import log_system_event
from vulnpilot.model import create_model


class RetryStrategy:
    """重试策略管理器"""

    def __init__(self, config):
        """
        初始化重试策略

        Args:
            config: Agent 配置
            
        Raises:
            ValueError: 缺少必需的配置信息
        """
        self.config = config
        provider = getattr(config, "llm_provider", "deepseek")

        # 主 Agent LLM（标准参数）
        self.deepseek_llm = create_model(config=config)

        # Advisor LLM：稍高温度，获得更多样化建议
        self.minimax_llm = create_model(config=config, temperature=0.7)

        log_system_event(
            "[重试策略] 初始化完成",
            {
                "provider": provider,
                "main_model": config.llm_model_name,
                "advisor_model": config.llm_model_name,
                "advisor_temperature": 0.7,
                "max_retries": 10,
                "timeout": 300,
            },
        )

    def get_llm_pair(self, retry_count: int) -> Tuple[object, object, str]:
        """
        根据重试次数返回 LLM 对（主 Agent, 顾问 Agent, 策略描述）

        策略（共 5 次机会，4 次重试）：
        - 第 0 次（首次）：主 LLM（主）+ Advisor LLM（顾问）
        - 第 1 次（重试 1）：Advisor LLM（主）+ 主 LLM（顾问） ★ 角色互换
        - 第 2 次（重试 2）：主 LLM（主）+ Advisor LLM（顾问） ★ 回到原始
        - 第 3 次（重试 3）：Advisor LLM（主）+ 主 LLM（顾问） ★ 再次互换
        - 第 4 次（重试 4）：主 LLM（主）+ Advisor LLM（顾问） ★ 最终尝试

        Args:
            retry_count: 当前重试次数（0 = 首次尝试）

        Returns:
            (main_llm, advisor_llm, strategy_description)
        """
        provider = getattr(self.config, "llm_provider", "deepseek")
        model_name = self.config.llm_model_name

        # 偶数次用主 LLM 作主，奇数次用 Advisor LLM 作主（轮流）
        is_even = retry_count % 2 == 0
        
        if is_even:
            strategy_desc = f"{provider.upper()}:{model_name} (主) + Advisor (顾问)"
            if retry_count > 0:
                strategy_desc += f" [重试 {retry_count}]"
            return (
                self.deepseek_llm,
                self.minimax_llm,
                strategy_desc
            )
        else:
            log_system_event(
                f"[重试策略] 🔄 角色互换：Advisor 作为主 Agent",
                {"retry_count": retry_count}
            )
            return (
                self.minimax_llm,
                self.deepseek_llm,
                f"Advisor (主) + {provider.upper()}:{model_name} (顾问) [重试 {retry_count}]"
            )

    @staticmethod
    def format_attempt_history(attempt_history: list) -> str:
        """
        格式化历史尝试记录，供新 Agent 参考

        Args:
            attempt_history: 历史尝试记录列表

        Returns:
            格式化的历史记录字符串
        """
        if not attempt_history:
            return ""

        formatted_parts = [
            "## 📜 历史尝试记录（请避免重复这些失败的方法）\n"
        ]

        for i, attempt in enumerate(attempt_history, 1):
            strategy = attempt.get("strategy", "未知策略")
            attempts_count = attempt.get("attempts", 0)
            failed_methods = attempt.get("failed_methods", [])
            key_findings = attempt.get("key_findings", [])

            formatted_parts.append(f"### 尝试 {i}：{strategy}\n")
            formatted_parts.append(f"- **尝试次数**: {attempts_count}\n")

            if failed_methods:
                formatted_parts.append("- **已失败的方法**:\n")
                for method in failed_methods[:10]:  # 最多显示 10 个
                    formatted_parts.append(f"  - ❌ {method}\n")

            if key_findings:
                formatted_parts.append("- **关键发现**:\n")
                for finding in key_findings[:5]:  # 最多显示 5 个
                    formatted_parts.append(f"  - 💡 {finding}\n")

            formatted_parts.append("\n")

        formatted_parts.append(
            "**⚠️ 重要提示**: 上述方法均已失败，请尝试完全不同的攻击角度！\n"
        )

        return "".join(formatted_parts)

    @staticmethod
    def extract_attempt_summary(final_state: dict, strategy: str) -> dict:
        """
        从最终状态中提取本次尝试的摘要

        Args:
            final_state: Agent 执行后的最终状态
            strategy: 使用的策略描述

        Returns:
            尝试摘要字典
        """
        action_history = final_state.get("action_history", [])
        messages = final_state.get("messages", [])

        # 提取失败的方法（从 action_history 中）
        failed_methods = []
        for action in action_history:
            if any(keyword in str(action).lower() for keyword in ["失败", "错误", "error", "failed"]):
                failed_methods.append(str(action))

        # 提取关键发现（从 potential_vulnerabilities 中）
        key_findings = final_state.get("potential_vulnerabilities", [])

        # 统计尝试次数
        attempts_count = len([m for m in messages if hasattr(m, 'tool_calls') and m.tool_calls])

        return {
            "strategy": strategy,
            "attempts": attempts_count,
            "failed_methods": failed_methods,
            "key_findings": [str(v) for v in key_findings] if key_findings else [],
            "timestamp": final_state.get("start_time")
        }
