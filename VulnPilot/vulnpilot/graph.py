"""
多 Agent 协作图 V2（三层架构）
=====================================

三层架构：
- 规划层：Advisor Agent (MiniMax) + Main Agent (DeepSeek) - 只负责规划与决策
- 执行层：PoC Agent + Docker Agent - 专注执行
- 知识层：Skills (SKILL.md) - 按需加载漏洞知识库

架构图：
┌──────────────────────────────────────────────────────────────┐
│                        规划层                                 │
│  ┌──────────────┐         ┌──────────────┐                   │
│  │ Advisor      │ ──────> │ Main Agent   │                   │
│  │ (MiniMax)    │ 提供建议 │ (DeepSeek)   │                   │
│  │ +Skills加载  │         │ 规划与决策    │                   │
│  └──────────────┘         └──────┬───────┘                   │
└──────────────────────────────────┼───────────────────────────┘
                                   │ 分发任务
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│                        执行层                                 │
│  ┌──────────────┐         ┌──────────────┐                   │
│  │ PoC Agent    │         │ Docker Agent │                   │
│  │ Python脚本   │         │ Kali工具     │                   │
│  └──────────────┘         └──────────────┘                   │
└──────────────────────────────────────────────────────────────┘

作者：VulnPilot
日期：2025-12-10
"""
import asyncio
import time
import os
import logging
from typing import Literal, Optional
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage, ToolMessage
from langchain_core.runnables import RunnableConfig

from vulnpilot.state import PenetrationTesterState
from vulnpilot.tools import get_all_tools
from vulnpilot.common import log_system_event, log_agent_thought
from vulnpilot.ablation_config import (
    ablation_config_summary,
)
from vulnpilot.langmem_memory import get_memory_store, get_all_memory_tools
from vulnpilot.utils.rate_limiter import get_rate_limiter
from vulnpilot.utils.util import retry_llm_call
from vulnpilot.utils.failure_detector import detect_failure_with_llm


from vulnpilot.agents.advisor import ADVISOR_SYSTEM_PROMPT
from vulnpilot.agents.main_agent import MAIN_AGENT_SYSTEM_PROMPT
from vulnpilot.agents.poc_agent import POC_AGENT_SYSTEM_PROMPT
from vulnpilot.agents.docker_agent import DOCKER_AGENT_SYSTEM_PROMPT
from vulnpilot.agents.auditor_agent import AUDITOR_SYSTEM_PROMPT, auditor_node  # ← 新增
from vulnpilot.agents.intelligence_agent import create_intelligence_agent_node  # ← 情报节点
from vulnpilot.tools.intelligence_tools import (
    searchsploit_cve,
    fetch_exploitdb_poc,
    extract_cve_from_target_info,
    search_github_poc,  # ← GitHub PoC 搜索（免费，需 GITHUB_TOKEN 环境变量）
)  # ← 情报工具
from vulnpilot.prompts_book import (
    TOOL_OUTPUT_SUMMARY_PROMPT,
    MAIN_AGENT_PLANNER_PROMPT,
    build_advisor_context,
    build_main_context,
    get_target_url,
    get_target_info,
)

# 导入 Skills 加载器
from vulnpilot.skills.skill_loader import load_skills_for_context, get_skill_summary


# ==================== 初始化全局速率限制器 ====================
DEEPSEEK_RPS = float(os.getenv("DEEPSEEK_REQUESTS_PER_SECOND", "2.0"))
MINIMAX_RPS = float(os.getenv("MINIMAX_REQUESTS_PER_SECOND", "2.0"))

deepseek_limiter = get_rate_limiter("deepseek_llm", requests_per_second=DEEPSEEK_RPS, burst_size=5)
minimax_limiter = get_rate_limiter("minimax_llm", requests_per_second=MINIMAX_RPS, burst_size=5)


async def build_multi_agent_graph(config: RunnableConfig):
    """
    构建多 Agent 协作图（三层架构）

    Args:
        config: LangGraph 运行时配置

    Returns:
        编译后的 LangGraph 应用
    """
    # ==================== 0. 初始化 LLM ====================
    from vulnpilot.model import create_model
    from vulnpilot.core.singleton import get_config_manager
    from langchain_openai import ChatOpenAI

    agent_config = get_config_manager().config

    # 主 LLM (DeepSeek) - 用于 Main Agent 和执行层
    main_llm = create_model(agent_config)
    log_system_event("[Graph V2] 初始化 main_llm (DeepSeek)")

    # 顾问 LLM (MiniMax)
    advisor_llm = ChatOpenAI(
        base_url=os.getenv("SILICONFLOW_BASE_URL", "https://api.siliconflow.cn/v1"),
        api_key=os.getenv("SILICONFLOW_API_KEY"),
        model=os.getenv("SILICONFLOW_MODEL", "MiniMaxAI/MiniMax-M2"),
        temperature=0.7,
        max_tokens=8192,
        timeout=600,
        max_retries=10
    )
    log_system_event("[Graph V2] 初始化 advisor_llm (MiniMax)")

    # 从 config 中提取 manual_mode
    manual_mode = False
    if config and hasattr(config, "get"):
        configurable = config.get("configurable", {})
        manual_mode = configurable.get("manual_mode", False)

    return await _build_graph_internal(main_llm, advisor_llm, manual_mode=manual_mode)


# ==================== Studio 兼容包装 ====================
def studio_graph():
    """
    LangGraph Studio 兼容的包装函数
    不需要参数，返回一个可以被 Studio 加载的 graph
    """
    import asyncio
    # 使用空配置创建 graph
    return asyncio.run(build_multi_agent_graph({}))


async def _build_graph_internal(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel,
    manual_mode: bool = False,
    graph_name: str = "LangGraph"
):
    """
    构建三层架构图的内部实现

    Args:
        main_llm: 主 LLM
        advisor_llm: 顾问 LLM
        manual_mode: 是否手动模式
        graph_name: 图名称（用于 Langfuse trace name）
    """
    # ==================== 1. 初始化记忆和工具 ====================
    log_system_event("[Ablation] Runtime module switches", ablation_config_summary())
    memory_store = get_memory_store()
    memory_tools = get_all_memory_tools(manual_mode=manual_mode)
    pentest_tools = get_all_tools()
    all_tools = pentest_tools + memory_tools

    # 分离工具：PoC Agent 用 execute_python_poc，Docker Agent 用 execute_command，顺便提取漏洞利用工具
    poc_tool = next((t for t in pentest_tools if t.name == "execute_python_poc"), None)
    docker_tool = next((t for t in pentest_tools if t.name == "execute_command"), None)
    submit_tool = next((t for t in memory_tools if t.name == "submit_flag"), None)
    
    # 提取新的漏洞武器库工具
    ss_search = next((t for t in pentest_tools if t.name == "searchsploit_search"), None)
    ss_read = next((t for t in pentest_tools if t.name == "searchsploit_read"), None)
    msf = next((t for t in pentest_tools if t.name == "msf_exploit"), None)
    # OOB 外带攻击工具（JNDI 注入类漏洞专用：XStream/Log4Shell/FastJson 等）
    oob_get_ip   = next((t for t in pentest_tools if t.name == "get_attack_ip"), None)
    oob_start    = next((t for t in pentest_tools if t.name == "start_jndi_server"), None)
    oob_check    = next((t for t in pentest_tools if t.name == "check_jndi_callback"), None)
    oob_stop     = next((t for t in pentest_tools if t.name == "stop_jndi_server"), None)
    docker_tools_list = [
        t for t in [
            docker_tool, ss_search, ss_read, msf,
            oob_get_ip, oob_start, oob_check, oob_stop  # OOB 工具链
        ] if t is not None
    ]

    log_system_event(
        f"[Graph V2] 初始化三层架构",
        {
            "poc_tool": poc_tool.name if poc_tool else None,
            "docker_tool": docker_tool.name if docker_tool else None,
            "submit_tool": submit_tool.name if submit_tool else None,
            "manual_mode": manual_mode
        }
    )

    # 执行层 Agent 绑定各自的工具
    poc_llm_with_tools = main_llm.bind_tools([poc_tool]) if poc_tool else None
    docker_llm_with_tools = main_llm.bind_tools(docker_tools_list) if docker_tools_list else None

    # 创建 ToolNode 用于执行工具
    base_tool_node = ToolNode(all_tools)

    # ==================== 2. Advisor Agent 节点 ====================
    async def advisor_node(state: PenetrationTesterState):
        """
        顾问 Agent - 提供攻击建议 + 按需加载 Skills
        """
        # 构建系统提示词
        advisor_sys_prompt = ADVISOR_SYSTEM_PROMPT

        # ⭐ 按需加载 Skills
        hint_content = ""
        target_info_msg = ""
        if state.get("current_challenge"):
            challenge = state["current_challenge"]
            hint_content = challenge.get("hint_content", "")
            target_info = challenge.get("target_info", {})
            ip = target_info.get("ip", "unknown")
            ports = target_info.get("port", [])
            target_info_msg = f"- **目标**: {ip}:{','.join(map(str, ports))}"


        # 加载相关 Skills
        # ==================== 提取侦察结果 ====================
        recon_summary = ""
        messages = state.get("messages", [])
        for msg in messages:
            if hasattr(msg, "content"):
                content_str = str(msg.content)
                if "系统自动侦察结果" in content_str or "🔍" in content_str:
                    recon_summary = content_str
                    log_system_event(
                        "[Skills] 找到侦察结果",
                        {"length": len(recon_summary)}
                    )
                    break
        
        # 加载Skills（传入hint和侦察结果）
        skills_content = load_skills_for_context(
            hint=hint_content,
            recon=recon_summary,  # 新增：传入侦察结果
            max_skills=2
        )


        if skills_content:
            advisor_sys_prompt += f"\n\n---\n\n# 漏洞知识库（按需加载）\n\n{skills_content}"
            log_system_event("[Advisor] 已加载漏洞知识库")

        if hint_content:
            advisor_sys_prompt += f"\n## 目标##\n{target_info_msg}\n## 题目提示(**非常重要**): \n\n{hint_content}\n\n"

        advisor_messages = [SystemMessage(content=advisor_sys_prompt)]

        # 构建动态上下文
        context_parts = build_advisor_context(state)

        # ==================== 📓 注入过程笔记（参考结构化过程笔记 context注入）====================
        try:
            from vulnpilot.notebook import format_notebook_for_context
            notebook_section = format_notebook_for_context(state.get("process_notebook"))
            if notebook_section:
                context_parts.append(notebook_section)
                log_system_event("[Advisor] 已注入过程笔记")
        except Exception as e:
            log_system_event(f"[Advisor] 笔记注入失败（不影响主流程）: {str(e)}", level=logging.WARNING)

        if context_parts:
            full_context = "\n".join(context_parts) + "\n\n---\n\n请基于以上信息，提供你的攻击建议。"
            advisor_messages.append(HumanMessage(content=full_context))
        else:
            advisor_messages.append(HumanMessage(content="主攻击手尚未选择题目或开始攻击。请等待进一步信息。"))

        log_agent_thought("[Advisor] 开始分析...")

        try:
            advisor_response: AIMessage = await retry_llm_call(
                advisor_llm.ainvoke,
                advisor_messages,
                max_retries=5,
                base_delay=2.0,
                limiter=minimax_limiter
            )
        except Exception as e:
            log_system_event(
                "[Advisor] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "advisor_suggestion": "",
                "messages": []
            }

        log_agent_thought(
            "[MiniMax] 提供建议",
            {"advice": advisor_response.content}
        )

        return {
            "advisor_suggestion": advisor_response.content,
            "messages": []
        }

    # ==================== 3. Main Agent 节点（规划模式）====================
    async def main_agent_node(state: PenetrationTesterState):
        """
        主 Agent - 规划与决策（不直接执行工具）

        输出格式：
        - [DISPATCH_TASK] ... [/DISPATCH_TASK]：分发任务给执行层
        - [REQUEST_ADVISOR_HELP]：请求顾问帮助
        - [SUBMIT_FLAG:<FLAG真实值>]：提交FLAG，必须填写真实值
          例如：[SUBMIT_FLAG:flag{{abc123-def456}}]
          ⚠️ 禁止写成 [SUBMIT_FLAG:flag{{...}}]，必须从工具返回中复制真实FLAG字符串
        """
        # 构建当前上下文
        current_context = build_main_context(state)

        # 构建系统提示词
        system_prompt = MAIN_AGENT_PLANNER_PROMPT.format(current_context=current_context)

        # ==================== 🔍 注入 Vulhub README 完整情报（核心优化）====================
        # 借鉴 pentest-agent 的 RAG 设计：将完整靶机 README 作为"战场情报"提前投喂给 Agent。
        # 之前只有 hint_content 的前 500 字符（仅简介），导致 Agent 看不到利用步骤和 PoC 命令，
        # 只能靠自身记忆"闭卷"发挥，成功率低。现在完整注入，实现"开卷作战"。
        current_challenge = state.get("current_challenge", {})
        readme_content = current_challenge.get("_readme_content", "")
        cve_id_for_readme = current_challenge.get("_cve_id", "")
        app_name_for_readme = current_challenge.get("_app_name", "")
        is_vulhub = current_challenge.get("_vulhub_mode", False)

        if is_vulhub and readme_content:
            # 限制 README 最大长度（防止超出 LLM 上下文窗口），优先保留完整内容
            max_readme_len = int(os.getenv("MAX_README_LENGTH", "8000"))
            readme_display = readme_content[:max_readme_len]
            if len(readme_content) > max_readme_len:
                readme_display += f"\n\n...（README 过长，已显示前 {max_readme_len} 字符）"

            system_prompt += f"""

---

## 📖 靶场官方漏洞复现说明（🔥 开卷情报 - 最高优先级参考）

> **来源**: Vulhub 官方 README（{app_name_for_readme} / {cve_id_for_readme}）
> **用途**: 这是靶场作者提供的官方复现步骤，务必严格按照此说明中的 URL、命令、请求格式执行！

{readme_display}

---

**⚠️ 情报使用要求**：
1. 上方 README 描述了已知可复现此漏洞的精确步骤，**必须作为你的首要攻击依据**。
2. 严格按照 README 中的 URL 路径、HTTP 方法、请求头、Payload 格式发动第一轮攻击。
3. 如果 README 方法失败，再结合你的通用技能库发散思考，**不要直接放弃**。
"""
            log_system_event(
                "[Main Agent] 已注入完整 Vulhub README 情报",
                {
                    "cve": cve_id_for_readme,
                    "app": app_name_for_readme,
                    "readme_length": len(readme_content),
                    "displayed_length": len(readme_display)
                }
            )

        # ==================== 📓 注入过程笔记 ====================
        try:
            from vulnpilot.notebook import format_notebook_for_context
            notebook_section = format_notebook_for_context(state.get("process_notebook"))
            if notebook_section:
                system_prompt += f"\n\n---\n\n{notebook_section}"
                log_system_event("[Main Agent] 已注入过程笔记")
        except Exception as e:
            log_system_event(f"[Main Agent] 笔记注入失败（不影响主流程）: {str(e)}", level=logging.WARNING)

        # 添加顾问建议
        advisor_suggestion = state.get("advisor_suggestion")
        if advisor_suggestion:
            system_prompt += f"""

---

## 🤝 顾问建议

{advisor_suggestion}

**请参考顾问建议，制定你的攻击计划。**
"""

        # ==================== 📋 注入情报官攻击指导书（Playbook）====================
        # 当情报官已经搜集到 CVE PoC 并提炼为 Playbook 时，Main Agent 开卷作战
        attack_playbooks = state.get("attack_playbooks", [])
        if attack_playbooks:
            playbook_sections = []
            for pb in attack_playbooks:
                cve_id = pb.get("cve_id", "未知")
                sections = [
                    f"### 📌 {cve_id} 攻击指导书（来源: {pb.get('source', 'Intelligence Agent')}）",
                    f"- **目标组件**: {pb.get('target_component', '未知')}",
                    f"- **漏洞类型**: {pb.get('vulnerability_type', '未知')}",
                    f"- **触发接口**: `{pb.get('trigger_endpoint', '未知')}` ({pb.get('http_method', 'POST')})",
                    f"- **必需请求头**: `{pb.get('required_headers', {})}`",
                    f"- **Payload 说明**: {pb.get('payload_description', '参考 execution_steps')}",
                    f"- **成功标志**: {pb.get('success_indicator', '命令执行成功')}",
                    "",
                    "**执行步骤**:",
                ]
                for step in pb.get("execution_steps", []):
                    sections.append(f"  {step}")

                python_template = pb.get("python_template", "")
                if python_template:
                    sections.extend([
                        "",
                        "**Python 代码模板（可直接复用）**:",
                        f"```python\n{python_template}\n```",
                    ])

                playbook_sections.append("\n".join(sections))

            system_prompt += f"""

---

## 🔓 情报官专属攻击操作指导书（🔥 最高优先级）

⚠️ **极度重要**：
1. 下方是情报官通过搜索引擎抓取的针对当前漏洞（CVE）**最精确**的利用方法和 PoC 脚本。
2. 你必须**优先严格**地按照指导书里要求的 URL 路径、请求方法、特定 Payload 等格式去精确攻击！
3. 如果指导书中提供了完整的 Python 利用代码，你必须优先执行该代码以完成漏洞利用。
4. **【核心规则 - 打破僵局】**：如果指导书中的方法被你执行后证明**未授权、报错或彻底失败**，你不可气馁停摆！你必须**立刻打破指导书的束缚**，全面退回到你的通用 Skills 技能库，或者修改和完善上一次报错的脚本去发散思路继续深挖！
5. 每次回答你必须明确下发 [DISPATCH_TASK] 或者 [SUBMIT_FLAG]，如果卡住了，也必须指派新的探测任务！

{"".join(chr(10)*2 + s for s in playbook_sections)}
"""
            log_system_event(
                "[Main Agent] 已注入情报 Playbook",
                {"playbook_count": len(attack_playbooks), "cves": [p.get("cve_id") for p in attack_playbooks]}
            )

        # 初始化消息列表（system_prompt 已包含所有上下文）
        messages = [SystemMessage(content=system_prompt)]

        # 添加历史消息（限制数量）
        history = list(state.get("messages", []))

        max_history = int(os.getenv("MAX_HISTORY_MESSAGES", "50"))
        if len(history) > max_history:
            history = history[-max_history:]

        # ====================================================================
        # ⭐ 核心防御：净化 Main Agent 的消息历史，防原声工具调用幻觉
        # Main Agent 纯规划模式不依赖 bind_tools，但如果有历史 tool_calls
        # (例如 PoC Agent 遗留下的)，API 会自动转换为底层标签 <|DSML|>，致其错乱。
        # 这里将其全部扁平化为纯文本，彻底防范 LLM 的原生函数调用冲动。
        # ====================================================================
        sanitized_history = []
        for msg in history:
            if isinstance(msg, AIMessage) and hasattr(msg, 'tool_calls') and msg.tool_calls:
                content = msg.content or ""
                summary = []
                for tc in msg.tool_calls:
                    summary.append(f"🔧 [执行工具派发] {tc['name']}")
                new_content = (content + "\n\n" + "\n".join(summary)).strip()
                sanitized_history.append(AIMessage(content=new_content))
            elif isinstance(msg, ToolMessage):
                sanitized_history.append(HumanMessage(content=f"📝 [工具执行结果反馈] {msg.name}\n{msg.content}"))
            else:
                sanitized_history.append(msg)

        messages.extend(sanitized_history)

        log_agent_thought("[Main Agent] 开始规划...")

        try:
            ai_message: AIMessage = await retry_llm_call(
                main_llm.ainvoke,  # 不绑定工具，纯规划模式
                messages,
                max_retries=5,
                base_delay=2.0,
                limiter=deepseek_limiter
            )
        except Exception as e:
            log_system_event(
                "[Main Agent] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"规划失败：{str(e)} [REQUEST_ADVISOR_HELP]")],
                "advisor_suggestion": "",
                "request_advisor_help": True
            }

        content = ai_message.content or ""

        # 解析输出
        request_help = "[REQUEST_ADVISOR_HELP]" in content
        dispatch_task = _parse_dispatch_task(content)
        submit_flag, submit_error = _parse_submit_flag(content)

        log_agent_thought(
            "[Main Agent] 规划结果",
            {
                "has_dispatch": dispatch_task is not None,
                "has_submit": submit_flag is not None,
                "request_help": request_help,
                "raw_content_preview": content[:1000] if len(content) > 1000 else content  # 打印出模型实际说了啥
            }
        )

        # 存储分发任务到状态
        result = {
            "messages": [ai_message],
            "advisor_suggestion": "",
            "request_advisor_help": request_help
        }

        if submit_error:
            # 把它当作反馈附加，让大模型知道下一次不能这么干
            result["messages"].append(HumanMessage(content=submit_error))

        if dispatch_task:
            result["pending_task"] = dispatch_task

        is_vulhub_mode = state.get("current_challenge", {}).get("_vulhub_mode", False)
        if submit_flag:
            if is_vulhub_mode:
                log_system_event(
                    "[Vulhub] 忽略 SUBMIT_FLAG 成功路径，改用 ExploitDetector 判定漏洞效果",
                    {"submitted_flag": submit_flag[:80]}
                )
                from vulnpilot.utils.exploitation_detector import detect_exploitation_success
                vulhub_challenge = state.get("current_challenge", {})
                exploit_result = detect_exploitation_success(
                    tool_output=content,
                    llm=main_llm,
                    app_name=vulhub_challenge.get("_app_name", ""),
                    cve_id=vulhub_challenge.get("_cve_id", ""),
                    readme_content=vulhub_challenge.get("_readme_content", ""),
                )
                if exploit_result and exploit_result.success:
                    result["flag"] = f"[Vulhub利用成功] {exploit_result.description} (证据: {exploit_result.raw_match or exploit_result.evidence})"
                    result["is_finished"] = True
                    result["consecutive_failures"] = 0
                    return result
                result["messages"].append(HumanMessage(
                    content=(
                        "Vulhub 模式不接受 SUBMIT_FLAG/flag{...} 作为成功依据。"
                        "请基于真实漏洞效果继续验证，例如 id/whoami 命令回显、/etc/passwd 内容、"
                        "数据库数据、管理员后台内容等；如果无法验证，请调用 finish_testing。"
                    )
                ))
                result["request_advisor_help"] = True
            else:
                result["pending_flag"] = submit_flag

        return result

    # ==================== 4. PoC Agent 节点 ====================
    async def poc_agent_node(state: PenetrationTesterState):
        """
        PoC Agent - 执行 Python 脚本

        处理两种情况：
        1. pending_flag: Main Agent 解析出的 FLAG，需要直接提交
        2. pending_task: 需要执行的 Python PoC 任务
        """
        # 优先处理 pending_flag（Main Agent 解析出的 FLAG）
        pending_flag = state.get("pending_flag")
        if pending_flag:
            if state.get("current_challenge", {}).get("_vulhub_mode"):
                log_system_event(
                    "[Vulhub] PoC Agent 忽略 pending_flag，Vulhub 成功必须由 ExploitDetector 判定",
                    {"pending_flag": pending_flag[:80]}
                )
                return {
                    "messages": [AIMessage(content=(
                        "Vulhub 模式已忽略 FLAG 提交请求。请继续验证真实漏洞效果，"
                        "例如命令执行回显或敏感文件内容。"
                    ))],
                    "pending_flag": None,
                    "pending_task": None,
                }
            if submit_tool:
                log_system_event(f"[PoC Agent] 提交 FLAG: {pending_flag[:20]}...")
                challenge = state.get("current_challenge", {})
                challenge_code = challenge.get("challenge_code", challenge.get("code", "unknown"))

                # 构造工具调用消息
                tool_call_id = f"submit_flag_{challenge_code}"
                ai_message = AIMessage(
                    content="",
                    tool_calls=[{
                        "id": tool_call_id,
                        "name": "submit_flag",
                        "args": {
                            "challenge_code": challenge_code,
                            "flag": pending_flag
                        }
                    }]
                )
                return {
                    "messages": [ai_message],
                    "pending_flag": None,  # 清除已处理的 FLAG
                    "pending_task": None
                }
            else:
                # 手动模式：没有 submit_tool，直接输出 FLAG 并标记完成
                log_system_event(f"[PoC Agent] 手动模式 - 发现 FLAG: {pending_flag}")
                ai_message = AIMessage(
                    content=f"🎉 发现 FLAG: {pending_flag}\n\n（手动模式，请自行提交）"
                )
                return {
                    "messages": [ai_message],
                    "pending_flag": None,
                    "pending_task": None,
                    "flag": pending_flag,
                    "is_finished": True
                }

        pending_task = state.get("pending_task") or {}
        task_description = pending_task.get("task", "")

        if not task_description:
            log_system_event("[PoC Agent] 没有待执行的任务")
            return {"messages": [], "pending_task": None}

        # 构建提示词
        target_url = get_target_url(state)
        hint_content = ""
        if state.get("current_challenge"):
            hint_content = state["current_challenge"].get("hint_content", "")

        prompt = f"""
{POC_AGENT_SYSTEM_PROMPT}

---

## 当前任务

{task_description}

## 目标信息

- **URL**: {target_url}
{"- **提示**: " + hint_content if hint_content else ""}

请编写并执行 Python PoC 代码来完成任务。
"""

        messages = [
            SystemMessage(content=prompt),
            HumanMessage(content="请执行任务。")
        ]

        log_agent_thought(f"[PoC Agent] 执行任务: {task_description[:100]}...")

        try:
            ai_message: AIMessage = await retry_llm_call(
                poc_llm_with_tools.ainvoke,
                messages,
                max_retries=3,
                base_delay=1.0,
                limiter=deepseek_limiter
            )
        except Exception as e:
            log_system_event(
                "[PoC Agent] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"PoC 执行失败：{str(e)}")],
                "pending_task": None
            }

        return {
            "messages": [ai_message],
            "pending_task": None  # 清除已处理的任务
        }

    # ==================== 5. Docker Agent 节点 ====================
    async def docker_agent_node(state: PenetrationTesterState):
        """
        Docker Agent - 执行 Kali 工具
        """
        pending_task = state.get("pending_task") or {}
        task_description = pending_task.get("task", "")

        if not task_description:
            log_system_event("[Docker Agent] 没有待执行的任务")
            return {"messages": [], "pending_task": None}

        # 构建提示词
        target_info = get_target_info(state)
        hint_content = ""
        if state.get("current_challenge"):
            hint_content = state["current_challenge"].get("hint_content", "")

        prompt = f"""
{DOCKER_AGENT_SYSTEM_PROMPT}

---

## 当前任务

{task_description}

## 目标信息

{target_info}
{"- **提示**: " + hint_content if hint_content else ""}

请根据任务性质，自主选择最合适的原生 Tool 进行调用。如果是常规扫描则调用 execute_command；若是需要漏洞库查询或 MSF 打击，请调用对应的原生工具函数。绝不允许把工具名字写进 bash 文本里当做 shell 命令运行！
"""

        messages = [
            SystemMessage(content=prompt),
            HumanMessage(content="请执行任务。")
        ]

        log_agent_thought(f"[Docker Agent] 执行任务: {task_description[:100]}...")

        try:
            ai_message: AIMessage = await retry_llm_call(
                docker_llm_with_tools.ainvoke,
                messages,
                max_retries=3,
                base_delay=1.0,
                limiter=deepseek_limiter
            )
        except Exception as e:
            log_system_event(
                "[Docker Agent] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"Docker 执行失败：{str(e)}")],
                "pending_task": None
            }

        return {
            "messages": [ai_message],
            "pending_task": None
        }

    # ==================== 6. Tool 执行节点 ====================
    async def tool_node(state: PenetrationTesterState):
        """
        工具执行节点 - 执行 PoC Agent 或 Docker Agent 的工具调用
        """
        # ========== 0. 重复检测（防止无限循环） ==========
        import hashlib
        import json
        
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                # 计算当前工具调用的哈希
                tool_call_str = json.dumps(last_message.tool_calls, sort_keys=True)
                current_hash = hashlib.md5(tool_call_str.encode()).hexdigest()
                
                last_hash = state.get("last_tool_call_hash")
                repeated_count = state.get("repeated_tool_calls", 0)
                
                if current_hash == last_hash:
                    # 相同的工具调用
                    repeated_count += 1
                    
                    if repeated_count >= 3:
                        # 连续3次相同调用 → 判定为重复循环
                        log_system_event(
                            "[🔁] 检测到重复循环",
                            {
                                "repeated_count": repeated_count,
                                "tool_call_hash": current_hash[:8],
                                "action": "强制增加失败计数，触发策略切换"
                            }
                        )
                        # 强制设置失败，触发Advisor介入
                        result = await base_tool_node.ainvoke(state)
                        result["consecutive_failures"] = state.get("consecutive_failures", 0) + 3
                        result["repeated_tool_calls"] = 0
                        result["last_tool_call_hash"] = None
                        return result
                else:
                    # 不同的工具调用，重置计数
                    repeated_count = 1
        
        # 执行工具
        result = await base_tool_node.ainvoke(state)

        # ========== 1. 检查 submit_flag 的返回（评测模式） ==========
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    if "答案正确" in msg.content:
                        # 提取 FLAG
                        messages = state.get("messages", [])
                        if messages:
                            last_message = messages[-1]
                            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                                for tool_call in last_message.tool_calls:
                                    if tool_call.get("name") == "submit_flag":
                                        submitted_flag = tool_call.get("args", {}).get("flag")
                                        if submitted_flag:
                                            result["flag"] = submitted_flag
                                            result["is_finished"] = True
                                            result["consecutive_failures"] = 0
                                            log_system_event("[✓] 检测到成功提交FLAG", {"flag": submitted_flag})
                                            return result

        # ========== 2. 自动检测工具返回中的FLAG（手动模式，仅 CTF 模式有效） ==========
        # ⚠️ Vulhub 模式下跳过此步骤！
        # Vulhub 靶机是真实 CVE 漏洞环境，没有 CTF flag 文件。
        # extract_flag_from_text 正则会产生严重误判：
        # - Adminer 靶机：CSP nonce 的 Base64 解码值被误判为 flag
        # - elfinder 靶机：PoC 脚本打印的 "尝试搜索: flag{" 与 JSON 的 "}" 缝合为虚假 flag
        # Vulhub 模式的成功判定完全交给下方的 ExploitDetector（漏洞效果评估器）负责。
        is_vulhub_mode = state.get("current_challenge", {}).get("_vulhub_mode", False)
        from vulnpilot.utils import extract_flag_from_text
        
        if not is_vulhub_mode and "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    # 仅 CTF 模式：尝试从消息内容中提取FLAG
                    found_flags = extract_flag_from_text(str(msg.content))
                    
                    if found_flags:
                        detected_flag = found_flags[0]  # 使用第一个找到的FLAG
                        result["flag"] = detected_flag
                        result["is_finished"] = True
                        result["consecutive_failures"] = 0
                        
                        log_system_event(
                            "[✓] 自动检测到FLAG",
                            {
                                "flag": detected_flag,
                                "total_found": len(found_flags),
                                "all_flags": found_flags
                            }
                        )
                        return result


        # ========== 2.5 Vulhub 模式：漏洞利用成功检测 ==========
        # 仅在 _vulhub_mode=True 时执行，不影响现有 -t 和 -api 流程
        vulhub_challenge = state.get("current_challenge", {})
        if vulhub_challenge.get("_vulhub_mode") and "messages" in result:
            from vulnpilot.utils.exploitation_detector import detect_exploitation_success
            # 收集本轮所有工具输出
            combined_output = " ".join(
                str(msg.content)
                for msg in result["messages"]
                if hasattr(msg, "content") and msg.content
            )
            exploit_result = detect_exploitation_success(
                tool_output=combined_output,
                llm=main_llm,  # 规则层未命中时使用 LLM 判断
                app_name=vulhub_challenge.get("_app_name", ""),
                cve_id=vulhub_challenge.get("_cve_id", ""),
                readme_content=vulhub_challenge.get("_readme_content", ""),
            )
            if exploit_result and exploit_result.success:
                result["flag"] = f"[Vulhub利用成功] {exploit_result.description} (证据: {exploit_result.raw_match or exploit_result.evidence})"
                result["is_finished"] = True
                result["consecutive_failures"] = 0
                log_system_event(
                    "[✓] Vulhub 漏洞利用成功",
                    {
                        "cve": vulhub_challenge.get("_cve_id"),
                        "method": exploit_result.method,
                        "description": exploit_result.description,
                        "evidence": exploit_result.evidence,
                    }
                )
                return result

        # ========== 3. 自动检测关卡转换（多关卡CTF） ==========
        import re
        
        current_level = state.get("current_level", "level1")
        completed_levels = state.get("completed_levels", [])
        level_transitions = state.get("level_transitions", [])
        
        # 扫描工具返回，查找关卡线索
        next_level_found = None
        trigger_info = None
        
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    content = str(msg.content)
                    
                    # 匹配常见关卡模式
                    patterns = [
                        r'level(\d+)\.php',       # level2.php
                        r'stage(\d+)',            # stage2
                        r'step(\d+)',             # step2
                        r'关卡\s*(\d+)',          # 关卡2
                        r'第\s*(\d+)\s*关',       # 第2关
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            # 提取关卡编号
                            level_num = int(matches[0])
                            
                            # 构造关卡标识
                            if 'level' in pattern:
                                next_level = f"level{level_num}"
                            elif 'stage' in pattern:
                                next_level = f"stage{level_num}"
                            elif 'step' in pattern:
                                next_level = f"step{level_num}"
                            else:
                                next_level = f"level{level_num}"
                            
                            # 检查是否是新关卡
                            if next_level != current_level and next_level not in completed_levels:
                                next_level_found = next_level
                                trigger_info = content[:200]
                                break
                    
                    if next_level_found:
                        break
        
        # 如果发现新关卡，更新状态
        if next_level_found:
            # 标记当前关卡为已完成
            if current_level and current_level not in completed_levels:
                if "completed_levels" not in result:
                    result["completed_levels"] = []
                result["completed_levels"].append(current_level)
            
            # 更新到新关卡
            result["current_level"] = next_level_found
            
            # 记录转换历史
            transition = {
                "from": current_level,
                "to": next_level_found,
                "trigger": trigger_info
            }
            if "level_transitions" not in result:
                result["level_transitions"] = []
            result["level_transitions"].append(transition)
            
            log_system_event(
                "[🎯] 检测到关卡转换",
                {
                    "from_level": current_level,
                    "to_level": next_level_found,
                    "completed_count": len(completed_levels) + 1,
                    "trigger_preview": trigger_info
                }
            )

        # ========== 4. 检测失败 ==========
        is_failure = False
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    content = msg.content.lower()
                    failure_keywords = ["error", "failed", "exception", "无法", "错误", "失败"]
                    is_failure = any(kw in content for kw in failure_keywords)

        consecutive_failures = state.get("consecutive_failures", 0)
        if is_failure:
            consecutive_failures += 1
        else:
            consecutive_failures = 0

        result["consecutive_failures"] = consecutive_failures
        
        # ========== 5. 更新重复检测状态 ==========
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                import hashlib
                import json
                tool_call_str = json.dumps(last_message.tool_calls, sort_keys=True)
                current_hash = hashlib.md5(tool_call_str.encode()).hexdigest()
                
                result["last_tool_call_hash"] = current_hash
                result["repeated_tool_calls"] = state.get("repeated_tool_calls", 0)

        # ========== 6. 自动更新过程笔记（参考结构化过程笔记 add_cell_content）==========
        try:
            from vulnpilot.notebook import (
                init_notebook, extract_from_tool_output, merge_notebook
            )
            from langchain_core.messages import ToolMessage as LCToolMessage

            # 获取当前轮次
            all_msgs = state.get("messages", [])
            round_num = len([m for m in all_msgs if hasattr(m, "tool_calls") and m.tool_calls])

            # 获取或初始化笔记
            current_notebook = state.get("process_notebook")
            if not current_notebook:
                current_notebook = init_notebook(state)

            # 从本次工具返回结果中提取信息
            updated_notebook = current_notebook
            for msg in result.get("messages", []):
                if isinstance(msg, LCToolMessage):
                    delta = extract_from_tool_output(
                        tool_name=getattr(msg, "name", "unknown"),
                        tool_output=str(msg.content),
                        round_num=round_num
                    )
                    updated_notebook = merge_notebook(updated_notebook, delta)

            result["process_notebook"] = updated_notebook

        except Exception as e:
            log_system_event(
                f"[📓] 笔记更新失败（不影响主流程）: {str(e)}",
                level=logging.WARNING
            )

        # ========== ⭐ 7. 检测 finish_testing 工具调用 ==========
        # finish_testing 是 Vulhub 模式下的体面退出工具。
        # 当 Agent 调用该工具时，必须将 is_finished 置为 True，
        # 否则 route_after_tools 无法路由到 END，导致系统继续运行。
        pre_messages = state.get("messages", [])
        if pre_messages:
            last_pre_msg = pre_messages[-1]
            if hasattr(last_pre_msg, "tool_calls") and last_pre_msg.tool_calls:
                for tool_call in last_pre_msg.tool_calls:
                    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else getattr(tool_call, "name", "")
                    if tool_name == "finish_testing":
                        log_system_event(
                            "[🏳️] 检测到 finish_testing 调用，标记测试结束",
                            {"action": "is_finished = True, idle_rounds = 0"}
                        )
                        result["is_finished"] = True
                        result["idle_rounds"] = 0  # 重置空转计数
                        return result

        # 正常工具执行后重置空转计数（因为有实质进展）
        result["idle_rounds"] = 0

        return result


    # ==================== 7. 路由函数 ====================
    def route_after_main(state: PenetrationTesterState) -> Literal["poc_agent", "docker_agent", "advisor", "tools", "end"]:
        """
        Main Agent 之后的路由

        修复说明：
        - 新增对 LangChain 原生 tool_calls 的检测（如 finish_testing 工具调用）
        - 增加防死锁的空转计数器，避免 main_agent↔advisor 无限循环浪费超时
        """
        # 检查是否完成
        if state.get("flag") or state.get("is_finished"):
            return "end"

        # ⭐ 修复关键Bug：检测 Main Agent 输出的原生 LangChain 工具调用
        # 场景：Agent 调用 finish_testing 等工具时，必须路由到 tools 节点执行
        # 原来缺少这个检测，导致 tool_calls 被无视，进入 advisor 死循环
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                tool_names = [tc.get("name", "") if isinstance(tc, dict) else getattr(tc, "name", "") for tc in last_message.tool_calls]
                log_system_event(
                    "[Router] Main Agent 发出工具调用，路由到 tools 节点",
                    {"tools": tool_names}
                )
                return "tools"

        # 检查是否请求帮助
        if state.get("request_advisor_help"):
            return "advisor"

        # 检查是否有待分发的任务
        pending_task = state.get("pending_task")
        if pending_task:
            agent = pending_task.get("agent", "poc")
            if agent == "docker":
                log_system_event("[Router] 分发任务到 Docker Agent")
                return "docker_agent"
            else:
                log_system_event("[Router] 分发任务到 PoC Agent")
                return "poc_agent"

        # 检查是否有待提交的 FLAG
        pending_flag = state.get("pending_flag")
        if pending_flag:
            # 直接提交 FLAG（通过 PoC Agent）
            return "poc_agent"

        # ⭐ 防死锁保护：检测 main_agent↔advisor 空转循环
        # 若连续多轮均无任何实质进展（无工具调用、无分发任务、无提交），强制结束
        idle_rounds = state.get("idle_rounds", 0) + 1
        if idle_rounds >= 5:
            log_system_event(
                "[Router] ⚠️ 检测到空转死循环，强制路由到 END",
                {"idle_rounds": idle_rounds, "action": "强制终止，避免 2000s 超时"}
            )
            return "end"

        # 默认返回 advisor
        return "advisor"

    def route_after_execution(state: PenetrationTesterState) -> Literal["tools", "main_agent", "end"]:
        """
        执行层 Agent 之后的路由
        """
        # 检查是否完成
        if state.get("flag") or state.get("is_finished"):
            return "end"

        # 检查是否有工具调用
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                return "tools"

        # 返回 Main Agent 继续规划
        return "main_agent"

    def route_after_tools(state: PenetrationTesterState) -> Literal["main_agent", "advisor", "auditor", "end"]:
        """
        工具执行后的路由
        """
        # 检查是否完成
        if state.get("flag") or state.get("is_finished"):
            return "end"

        # 检查是否超限（双重保险：工具调用次数 + AI 消息次数）
        messages = state.get("messages", [])
        # 统计实际执行过的工具次数（ToolMessage 数量更可靠）
        from langchain_core.messages import ToolMessage as _TM
        tool_exec_count = len([m for m in messages if isinstance(m, _TM)])
        # 统计 AI 发出工具调用的次数（备用计数）
        ai_tool_call_count = len([m for m in messages if hasattr(m, 'tool_calls') and m.tool_calls])
        # 取两者的最大值作为"尝试次数"
        attempts = max(tool_exec_count, ai_tool_call_count)

        from vulnpilot.core.constants import AgentConfig
        max_attempts = AgentConfig.get_max_attempts()

        if attempts > max_attempts:
            log_system_event(
                "[⛔] 已达最大尝试次数，强制结束",
                {"attempts": attempts, "max_attempts": max_attempts}
            )
            return "end"

        # ========== 新增：检查是否需要 Auditor ==========
        consecutive_failures = state.get("consecutive_failures", 0)
        
        # 连续失败3次，且未超过审计重试上限
        audit_history = state.get("audit_history", [])
        max_audit_retries = state.get("max_audit_retries", 2)  # 默认最多审计2次
        
        # 计算最近5次尝试内的审计次数
        recent_audits = [a for a in audit_history if a.get("attempt", 0) >= attempts - 5]
        
        if consecutive_failures >= 3 and len(recent_audits) < max_audit_retries:
            log_system_event(
                "[🚨] 触发 Auditor Agent",
                {
                    "consecutive_failures": consecutive_failures,
                    "audit_count": len(recent_audits),
                    "max_retries": max_audit_retries
                }
            )
            return "auditor"
        
        # ========== 📓 失败时补充写入笔记（参考结构化过程笔记 circle失败上下文更新）==========
        # 对应过程笔记 circle.py 第92-97行：失败时把 circle_feedback 写入 context
        if consecutive_failures >= 1:
            try:
                from vulnpilot.notebook import add_failed_attempt, extract_failed_attempt
                from langchain_core.messages import ToolMessage as LCToolMessage
                
                current_notebook = state.get("process_notebook")
                if current_notebook:
                    # 从最近一条工具消息中提取失败信息
                    recent_tool_msgs = [m for m in messages if isinstance(m, LCToolMessage)]
                    if recent_tool_msgs:
                        last_tool_msg = recent_tool_msgs[-1]
                        failed = extract_failed_attempt(
                            tool_name=getattr(last_tool_msg, "name", "unknown"),
                            tool_output=str(last_tool_msg.content),
                            round_num=attempts,
                        )
                        if failed:
                            # 注意：route_after_tools 是同步函数，无法直接修改state
                            # 失败记录由 tool_node 中的 extract_from_tool_output 负责主要写入
                            # 此处只做日志确认
                            log_system_event(
                                "[📓] 确认失败记录已在笔记中",
                                {"method": failed.get("method"), "reason": failed.get("reason")}
                            )
            except Exception:
                pass  # 不影响路由决策
        
        # 检查是否需要 Advisor（保持原有逻辑）
        from vulnpilot.core.constants import SmartRoutingConfig
        failures_threshold = SmartRoutingConfig.get_failures_threshold()

        if consecutive_failures > 0 and consecutive_failures % failures_threshold == 0:
            return "advisor"

        # 返回 Main Agent
        return "main_agent"

    def route_after_auditor(state: PenetrationTesterState) -> Literal["poc_agent", "docker_agent", "advisor", "main_agent"]:
        """
        Auditor审计后的路由
        
        根据Auditor的判断结果：
        - code_error → 返回执行层Agent（PoC/Docker）重新生成
        - decision_error → 返回Advisor重新规划
        - unknown → 返回Main Agent继续
        """
        error_context = state.get("current_error_context", {})
        next_action = error_context.get("next_action", "continue")
        
        log_system_event(
            "[🔀] Auditor路由决策",
            {
                "error_type": error_context.get("error_type", "unknown"),
                "next_action": next_action,
                "confidence": error_context.get("confidence", 0)
            }
        )
        
        if next_action == "regenerate_code":
            # 判断上一次使用的是哪个执行Agent
            messages = state.get("messages", [])
            for msg in reversed(messages):
                if hasattr(msg, "name"):
                    if msg.name == "poc_agent":
                        log_system_event("[→] 返回 PoC Agent 重新生成代码")
                        return "poc_agent"
                    elif msg.name == "docker_agent":
                        log_system_event("[→] 返回 Docker Agent 重新生成命令")
                        return "docker_agent"
            
            # 默认返回poc_agent
            log_system_event("[→] 默认返回 PoC Agent")
            return "poc_agent"
        
        elif next_action == "consult_advisor":
            # 重置失败计数（避免立即再次触发Auditor）
            log_system_event("[→] 返回 Advisor 重新规划策略")
            return "advisor"
        
        else:  # unknown 或 continue
            log_system_event("[→] 返回 Main Agent 继续")
            return "main_agent"

    # ==================== 8. 构建情报节点 ====================
    # 情报节点使用与 Main Agent 相同的 LLM（DeepSeek，代码理解能力强）
    # 工具顺序：ExploitDB 搜索 → ExploitDB PoC 获取 → GitHub 搜索 → CVE 识别
    intel_tools = [
        searchsploit_cve,        # ExploitDB 搜索
        fetch_exploitdb_poc,     # 获取 ExploitDB PoC 源码
        search_github_poc,       # GitHub 公开 PoC 仓库搜索（兼容 Windows）
        extract_cve_from_target_info,  # 从逻辑描述中提取 CVE 号
    ]
    intelligence_node = create_intelligence_agent_node(main_llm, intel_tools)

    # ==================== 9. 构建 StateGraph ====================
    workflow = StateGraph(PenetrationTesterState)

    # 添加节点
    workflow.add_node("advisor", advisor_node)
    workflow.add_node("intelligence", intelligence_node)  # ← 新增情报节点
    workflow.add_node("main_agent", main_agent_node)
    workflow.add_node("poc_agent", poc_agent_node)
    workflow.add_node("docker_agent", docker_agent_node)
    workflow.add_node("tools", tool_node)
    workflow.add_node("auditor", auditor_node)  # ← 新增Auditor节点

    # 设置入口
    workflow.set_entry_point("advisor")

    # ==================== 定义边 ====================
    # Advisor → 条件路由：Vulhub模式且有CVE时，先经过情报节点；普通CTF直通 main_agent
    def route_after_advisor(state: PenetrationTesterState) -> str:
        """
        Advisor 之后的路由逻辑：
        - Vulhub 模式（_vulhub_mode=True）且 identified_cves 非空 → 情报节点
        - 其他情况（普通 CTF / 无 CVE 信息）→ 直接 main_agent（保持原有行为不变）
        """
        challenge = state.get("current_challenge") or {}
        is_vulhub = challenge.get("_vulhub_mode", False)
        identified_cves = state.get("identified_cves", [])
        intel_status = state.get("intelligence_status", "")

        # 情报节点只触发一次（避免反复搜索 PoC 造成资源浪费）
        if is_vulhub and intel_status not in ("done", "no_cve_found"):
            log_system_event(
                "[→] Vulhub 模式，流转至情报节点搜集 CVE PoC",
                {"identified_cves": identified_cves}
            )
            return "intelligence"
        else:
            return "main_agent"

    workflow.add_conditional_edges(
        "advisor",
        route_after_advisor,
        {
            "intelligence": "intelligence",
            "main_agent": "main_agent",
        }
    )

    # 情报节点完成后固定流转至 main_agent（携带 Playbook 数据）
    workflow.add_edge("intelligence", "main_agent")

    workflow.add_conditional_edges(
        "main_agent",
        route_after_main,
        {
            "tools": "tools",          # ⭐ 新增：main_agent 触发原生工具调用时（如 finish_testing）
            "poc_agent": "poc_agent",
            "docker_agent": "docker_agent",
            "advisor": "advisor",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "poc_agent",
        route_after_execution,
        {
            "tools": "tools",
            "main_agent": "main_agent",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "docker_agent",
        route_after_execution,
        {
            "tools": "tools",
            "main_agent": "main_agent",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "tools",
        route_after_tools,
        {
            "main_agent": "main_agent",
            "advisor": "advisor",
            "auditor": "auditor",  # ← 新增auditor路由
            "end": END
        }
    )

    # ========== 新增：Auditor的条件边 ==========
    workflow.add_conditional_edges(
        "auditor",
        route_after_auditor,
        {
            "poc_agent": "poc_agent",
            "docker_agent": "docker_agent",
            "advisor": "advisor",
            "main_agent": "main_agent"
        }
    )

    # 编译图（传入 name 参数，用于 Langfuse trace name）
    app = workflow.compile(store=memory_store, name=graph_name)

    log_system_event("[Graph V2] 三层架构图构建完成")
    return app


# ==================== 辅助函数 ====================


def _parse_dispatch_task(content: str) -> Optional[dict]:
    """解析任务分发指令"""
    import re

    pattern = r'\[DISPATCH_TASK\]\s*agent:\s*(\w+)\s*task:\s*\|?\s*(.*?)\[/DISPATCH_TASK\]'
    match = re.search(pattern, content, re.DOTALL)

    if match:
        return {
            "agent": match.group(1).strip().lower(),
            "task": match.group(2).strip()
        }

    return None


def _parse_submit_flag(content: str) -> tuple[Optional[str], Optional[str]]:
    """解析 FLAG 提交指令，返回 (flag_value, error_message)"""
    import re  # 局部导入确保模块可用

    pattern = r'\[SUBMIT_FLAG:(.*?)\]'
    match = re.search(pattern, content)

    if match:
        flag_value = match.group(1).strip()

        # ==================== 防御性校验：拒绝占位符 ====================
        # 如果 FLAG 包含省略号或明显是模板占位符，则拒绝
        placeholder_patterns = [
            "...",          # 省略号
            "{...}",        # 花括号省略号
            "<FLAG",        # <FLAG实际值> 格式模板
            "实际值",        # 中文占位符
            "实际FLAG",
            "your_flag",
            "FLAG_HERE",
            "{flag}",       # 未展开的 Python 模板变量
            "{flags",       # 未展开的数组变量，如 {flags[0]}
            "{FLAG}",
        ]

        err_msg = "错误：SUBMIT_FLAG 包含了未展开的模板字面量或占位符，请务必从工具返回的结果中提取真实完整的 FLAG 字符串后再提交！不能瞎猜或填模板。"

        # 拦截整个字符串就是一个 Python {xxx} 变量的字面量（例如 LLM 提交了 "[SUBMIT_FLAG:{flag}]")
        if re.match(r'^\{.*\}$', flag_value.strip()):
            log_system_event(
                "[⚠️] SUBMIT_FLAG 包含了未展开的模板字面量，拒绝接受",
                {"raw_value": flag_value},
                level=logging.WARNING
            )
            return None, err_msg
        for ph in placeholder_patterns:
            if ph in flag_value:
                log_system_event(
                    "[⚠️] SUBMIT_FLAG 包含占位符，拒绝接受",
                    {
                        "raw_value": flag_value,
                        "matched_placeholder": ph,
                        "hint": "LLM应从工具返回结果中提取真实FLAG字符串，而非使用模板"
                    },
                    level=logging.WARNING
                )
                return None, err_msg

        # ==================== 新增：Vulhub 幻觉 Flag 黑名单 ====================
        # 从历史误判日志归纳：大模型在利用失败后捏造的典型 Flag 特征词
        # 案例1: ImageMagick CVE-2022-44268 → 提交了 "flag{test_flag_123}"
        # 案例2: Log4j CVE-2021-44228 → 提交了 "e912fdd5b632267a9088507a2a6bcbc7" (无证据)
        # 案例3: AppWeb CVE-2018-8715 → 提交了 "{matches[0]" (Python 变量引用)
        vulhub_hallucination_patterns = [
            "test_flag",     # flag{test_flag_123}
            "test-flag",
            "demo_flag",
            "demo-flag",
            "example_flag",
            "sample_flag",
            "testflag",
            "fake_flag",
        ]

        vulhub_hallucination_err = (
            "错误：SUBMIT_FLAG 包含了典型的幻觉占位符（如 test_flag、demo 等），"
            "这不是从目标系统中真实读取到的内容！\n"
            "在 Vulhub 渗透测试中，如果漏洞利用失败，请调用 finish_testing 宣告测试结束，"
            "而不是捏造一个 Flag 提交！"
        )

        flag_lower = flag_value.lower()
        for pat_str in vulhub_hallucination_patterns:
            if pat_str in flag_lower:
                log_system_event(
                    "[🚨] SUBMIT_FLAG 包含幻觉占位符，强制拒绝",
                    {
                        "raw_value": flag_value,
                        "matched_pattern": pat_str,
                        "hint": "检测到 Vulhub 幻觉捏造型 Flag，请使用 finish_testing 宣告失败"
                    },
                    level=logging.WARNING
                )
                return None, vulhub_hallucination_err

        # 基本格式验证：至少要包含 flag{ 或 FLAG{ 模式（典型CTF格式）
        # 也接受其他格式如纯数字、字母等，只要不是占位符就行
        if len(flag_value) < 5:
            log_system_event(
                "[⚠️] SUBMIT_FLAG 值过短，拒绝接受",
                {"raw_value": flag_value},
                level=logging.WARNING
            )
            return None, "错误：SUBMIT_FLAG 值过短，请检查是否提取完整"

        return flag_value, None

    return None, None


# ==================== 兼容性包装 ====================

async def build_multi_agent_graph_with_llms(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel,
    manual_mode: bool = False,
    graph_name: str = "LangGraph"
):
    """
    构建三层架构图（支持传入自定义 LLM）

    Args:
        main_llm: 主 LLM
        advisor_llm: 顾问 LLM
        manual_mode: 是否手动模式
        graph_name: 图名称（用于 Langfuse trace name）
    """
    return await _build_graph_internal(main_llm, advisor_llm, manual_mode=manual_mode, graph_name=graph_name)
