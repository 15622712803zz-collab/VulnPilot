import os
from typing import Optional
from dotenv import load_dotenv

# ============================================================
# 支持的 LLM 提供商
# ============================================================
SUPPORTED_PROVIDERS = ["deepseek", "openai"]


class AgentConfig:
    def __init__(self,
                 llm_api_key: str,
                 llm_base_url: str,
                 llm_model_name: str = "deepseek-v3.1-terminus",
                 # LLM 提供商：deepseek | openai
                 llm_provider: str = "deepseek",
                 # 环境模式配置（已移除 test 模式，只支持 challenge）
                 env_mode: str = "challenge",
                 # Docker 配置（用于 Kali Linux）
                 docker_container_name: Optional[str] = None,
                 # Microsandbox 配置（用于 Python 代码） 云环境还不支持这个
                 sandbox_enabled: bool = False,
                 sandbox_name: str = "VulnPilot-sandbox"):
        self.llm_api_key = llm_api_key
        self.llm_base_url = llm_base_url
        self.llm_model_name = llm_model_name
        # LLM 提供商标识（决定使用哪个 LangChain 封装）
        self.llm_provider = llm_provider
        # 环境模式（只支持 challenge）
        self.env_mode = env_mode
        # Docker 配置
        self.docker_container_name = docker_container_name
        # Microsandbox 配置
        self.sandbox_enabled = sandbox_enabled
        self.sandbox_name = sandbox_name


def load_agent_config() -> AgentConfig:
    load_dotenv()  # 确保 .env 文件被加载

    # ============================================================
    # 读取 LLM 提供商选择
    # LLM_PROVIDER=deepseek  → 使用 DeepSeek API
    # LLM_PROVIDER=openai    → 使用 OpenAI GPT API
    # ============================================================
    llm_provider = os.getenv("LLM_PROVIDER", "deepseek").lower().strip()
    if llm_provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"配置错误: LLM_PROVIDER 必须是 {SUPPORTED_PROVIDERS} 之一，"
            f"当前值: '{llm_provider}'"
        )

    # ============================================================
    # 根据 provider 读取对应的 API Key 和 Base URL
    # ============================================================
    if llm_provider == "openai":
        # --- OpenAI 配置 ---
        llm_api_key = os.getenv("OPENAI_API_KEY")
        if not llm_api_key:
            raise ValueError(
                "配置错误: 使用 OpenAI 提供商时必须设置 OPENAI_API_KEY。"
            )
        # 支持自定义 Base URL（兼容 Azure OpenAI 或代理）；默认使用官方 API
        llm_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        # 默认模型：gpt-4o
        llm_model_name = os.getenv("LLM_MODEL_NAME", "gpt-4o")
    else:
        # --- DeepSeek 配置（默认）---
        llm_api_key = os.getenv("DEEPSEEK_API_KEY")
        if not llm_api_key:
            # 兼容旧版：回退到 OPENAI_API_KEY
            llm_api_key = os.getenv("OPENAI_API_KEY")
        if not llm_api_key:
            raise ValueError(
                "配置错误: 使用 DeepSeek 提供商时必须设置 DEEPSEEK_API_KEY。"
            )
        llm_base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.lkeap.cloud.tencent.com/v1")
        # 默认模型：deepseek-chat
        llm_model_name = os.getenv("LLM_MODEL_NAME", "deepseek-chat")

    # ============================================================
    # 公共配置
    # ============================================================
    # 加载环境模式（只支持 challenge）
    env_mode = os.getenv("ENV_MODE", "challenge").lower()
    if env_mode not in ["challenge"]:
        raise ValueError(f"配置错误: ENV_MODE 必须是 'challenge'，当前值: {env_mode}")

    # 加载 Docker 配置（传统方案）
    docker_container_name = os.getenv("DOCKER_CONTAINER_NAME")

    # 加载沙箱配置（Microsandbox）
    sandbox_enabled = os.getenv("SANDBOX_ENABLED", "false").lower() == "true"
    sandbox_name = os.getenv("SANDBOX_NAME", "VulnPilot-sandbox")

    return AgentConfig(
        llm_api_key=llm_api_key,
        llm_base_url=llm_base_url,
        llm_model_name=llm_model_name,
        llm_provider=llm_provider,
        env_mode=env_mode,
        docker_container_name=docker_container_name,
        sandbox_enabled=sandbox_enabled,
        sandbox_name=sandbox_name
    )