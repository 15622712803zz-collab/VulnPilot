import os
import json
from langchain_core.language_models import BaseChatModel
from vulnpilot.common import log_system_event
from vulnpilot.config import AgentConfig


def create_model(
    config: AgentConfig,
    temperature: float = 0.5,
    max_tokens: int = 8192,
    timeout: int = 600,
    max_retries: int = 20,
) -> BaseChatModel:
    """
    创建模型实例

    根据 config.llm_provider 自动选择使用 DeepSeek 或 OpenAI 的 LangChain 封装。

    Args:
        config: AgentConfig 实例，包含 LLM 配置及 llm_provider 标识。
        temperature: 温度参数。
        max_tokens: 最大 token 数。
        timeout: 超时时间（秒）。
        max_retries: 重试次数（应对并发速率限制）。

    Returns:
        BaseChatModel: 模型实例。
    """
    model_name = config.llm_model_name
    provider = getattr(config, "llm_provider", "deepseek").lower()

    # ----------------------------------------------------------------
    # OpenAI 提供商
    # ----------------------------------------------------------------
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        model_config = {
            "model": model_name,
            "api_key": config.llm_api_key,
            "base_url": config.llm_base_url,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "max_retries": max_retries,
        }

        model = ChatOpenAI(**model_config)

        log_system_event(
            "✅ 创建 OpenAI 模型实例",
            {
                "provider": "openai",
                "model": model_name,
                "base_url": config.llm_base_url,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "timeout": timeout,
                "max_retries": max_retries,
            },
        )

    # ----------------------------------------------------------------
    # DeepSeek 提供商（默认）
    # ----------------------------------------------------------------
    else:
        from langchain_deepseek import ChatDeepSeek

        # 限制 max_tokens 不超过 8192（deepseek-chat 的上限）
        max_tokens = min(max_tokens, 8192)

        # 检查是否使用 reasoner 模型（需要 thinking 模式）
        use_thinking = "reasoner" in model_name.lower()

        model_config = {
            "api_base": config.llm_base_url,
            "api_key": config.llm_api_key,
            "model": model_name,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "max_retries": max_retries,
            "streaming": False,  # 禁用流式输出以支持结构化输出
        }

        # 只有 reasoner 模型才启用 thinking 模式
        if use_thinking:
            model_config["extra_body"] = {
                "thinking": {
                    "type": "enabled",
                    "enable_search": True,
                }
            }

        model = ChatDeepSeek(**model_config)

        log_system_event(
            "✅ 创建 DeepSeek 模型实例",
            {
                "provider": "deepseek",
                "model": model_name,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "timeout": timeout,
                "max_retries": max_retries,
                "thinking_enabled": use_thinking,
            },
        )

    return model
