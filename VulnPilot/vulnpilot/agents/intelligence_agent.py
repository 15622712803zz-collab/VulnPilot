"""
情报智能体（Intelligence Agent）
====================================

职责：
- 在 Vulhub 靶机渗透前，根据已识别的 CVE 编号从 ExploitDB / searchsploit 检索公开 PoC
- 用 LLM 理解 PoC 代码逻辑，将关键发包格式提炼为结构化的《攻击操作指导书（Playbook）》
- 将 Playbook 写入全局状态，供主攻击手（Main Agent/PoC Agent）直接参考使用

设计规则：
- 本 Agent 只在 Vulhub 模式下有 CVE 目标时触发（通过 graph.py 中的条件边控制）
- 普通 CTF 题目流程中，本 Agent 节点会被直接跳过
- 不直接执行攻击命令，只负责情报搜集和知识提炼
"""
import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from vulnpilot.ablation_config import process_notebook_enabled

logger = logging.getLogger(__name__)

# ==================== Intelligence Agent 系统提示词 ====================
INTELLIGENCE_SYSTEM_PROMPT = """
# 情报分析专家（Intelligence Agent）

你是一名专业的安全情报分析师，专门负责在渗透测试开始前收集已知漏洞的利用情报。

## 你的核心任务

**将粗糙的 PoC 代码或 CVE 描述，提炼成一份精准的《攻击操作指导书（Playbook）》**，让主攻击手拿到后可以"开卷作战"。

## 工作流程

1. **确认目标 CVE**：从状态中获取已识别的 CVE 编号列表
2. **搜索公开 PoC**：调用 `searchsploit_cve` 工具，在 ExploitDB 数据库中搜索该 CVE 的公开 Exploit
3. **阅读 PoC 源码**：调用 `fetch_exploitdb_poc` 工具，获取最相关的 PoC 脚本完整代码并精读
4. **提炼 Playbook**：分析 PoC 代码，提取以下关键信息并生成结构化 Playbook

## Playbook 输出格式（必须严格遵守）

完成分析后，你**必须**以如下 JSON 格式输出最终结果，放在 `[PLAYBOOK_START]` 和 `[PLAYBOOK_END]` 之间：

[PLAYBOOK_START]
{
  "cve_id": "CVE-XXXX-XXXXX",
  "target_component": "漏洞组件名称（如 GitLab ExifTool 解析器）",
  "vulnerability_type": "漏洞类型（RCE / SQLi / SSRF 等）",
  "trigger_endpoint": "触发漏洞的接口路径（如 /uploads/user）",
  "http_method": "HTTP 方法（POST / GET 等）",
  "required_headers": {"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
  "payload_description": "Payload 的详细描述（包括文件类型、字段名称、触发机制）",
  "execution_steps": [
    "步骤1：...",
    "步骤2：...",
    "步骤3：..."
  ],
  "python_template": "Python requests 发包的核心代码片段（可直接复制使用）",
  "success_indicator": "如何判断利用成功（回显特征、状态码、文件落地等）",
  "source": "情报来源（如 ExploitDB #50220）",
  "raw_poc_summary": "原始 PoC 代码的关键段落摘要（不超过 500 字）"
}
[PLAYBOOK_END]

## 核心分析要点

分析 PoC 时，请特别关注以下内容：

1. **HTTP 接口**：攻击时访问的具体 URL 路径是什么？
2. **参数格式**：文件字段叫什么名字（如 `file`、`avatar`）？是否需要 `multipart` 还是普通 JSON？
3. **认证要求**：是否需要先登录获取 Cookie 或 CSRF Token？如果需要，如何获取？
4. **Payload 结构**：恶意内容放在哪里（如图片元数据的哪个字段、JSON 的哪个参数）？
5. **命令执行方式**：如何实现 RCE？（如 ExifTool 的 `qx{...}` 语法、Java 反序列化 Gadget 等）

## 重要规则

- 如果 searchsploit 找不到 PoC，请根据 CVE 的官方描述和你的安全知识构造一份最佳猜测 Playbook
- 始终输出 Playbook，即使信息不完整，也要标注置信度和不确定之处
- python_template 字段尽量给出可以直接运行的 Python 代码片段

现在开始分析！
"""


def create_intelligence_agent_node(llm: Any, tools: list):
    """
    创建情报智能体节点函数

    Args:
        llm: 用于情报分析的 LLM 实例（推荐使用 DeepSeek，理解代码能力强）
        tools: 情报工具列表（searchsploit_cve、fetch_exploitdb_poc 等）

    Returns:
        intelligence_node 节点函数（接受 state，返回 state 更新）
    """
    # 将 LLM 与情报工具绑定
    llm_with_tools = llm.bind_tools(tools)

    from langchain_core.tools import tool as lc_tool
    from langgraph.prebuilt import ToolNode as LGToolNode
    intel_tool_node = LGToolNode(tools)

    async def intelligence_node(state: dict) -> dict:
        """
        情报智能体节点 - 搜集 CVE PoC 并生成攻击 Playbook

        触发条件：state["identified_cves"] 非空（由 main_agent 在侦察后填写）
        输出：state["attack_playbooks"] 追加新的 Playbook，state["intelligence_status"] 更新
        """
        identified_cves = state.get("identified_cves", [])

        # 如果没有识别到 CVE，直接跳过
        if not identified_cves:
            logger.info("[情报智能体] 未发现目标 CVE，跳过情报搜集。")
            return {
                "intelligence_status": "no_cve_found",
                "last_node": "intelligence"
            }

        logger.info(f"[情报智能体] 开始对以下 CVE 进行情报搜集: {identified_cves}")

        # 构造 Intelligence Agent 的工作上下文
        target_url = ""
        if state.get("current_challenge"):
            target_url = state["current_challenge"].get("url", "")

        cve_list_str = "\n".join([f"- {cve}" for cve in identified_cves])
        notebook_context = (
            json.dumps(state.get("process_notebook", {}), ensure_ascii=False, indent=2)[:1000]
            if process_notebook_enabled() and state.get("process_notebook")
            else "N/A"
        )
        user_message = f"""
请对以下目标 CVE 进行情报搜集和 Playbook 生成：

**目标 CVE 列表：**
{cve_list_str}

**靶机目标地址：** {target_url or '（未提供）'}

**过程笔记中的已知信息：**
{notebook_context}

请按照你的工作流程：
1. 先调用 searchsploit_cve 搜索每个 CVE 的公开 PoC
2. 对找到的 PoC 调用 fetch_exploitdb_poc 获取源码
3. 分析后输出结构化的 Playbook

**即使 searchsploit 找不到 PoC，也必须输出一份基于 CVE 知识的最佳猜测 Playbook。**
"""

        messages = [
            SystemMessage(content=INTELLIGENCE_SYSTEM_PROMPT),
            HumanMessage(content=user_message)
        ]

        # 单条工具输出最多保留的字符数（防止 PoC 源码撑爆 Payload 导致断线）
        MAX_TOOL_OUTPUT_CHARS = 4000
        # 整体历史允许的最大字符数（超过时剪裁最早的工具响应）
        MAX_TOTAL_HISTORY_CHARS = 20000

        def _truncate_tool_messages(msgs: list) -> list:
            """对工具返回消息进行截断，防止 PoC 源码等过大文本撑爆上下文"""
            from langchain_core.messages import ToolMessage
            truncated = []
            for m in msgs:
                if isinstance(m, ToolMessage) and isinstance(m.content, str) and len(m.content) > MAX_TOOL_OUTPUT_CHARS:
                    # 截断并标注
                    new_content = m.content[:MAX_TOOL_OUTPUT_CHARS] + f"\n\n...[内容已截断，原始长度 {len(m.content)} 字符，只保留前 {MAX_TOOL_OUTPUT_CHARS} 字符]..."
                    m = ToolMessage(content=new_content, tool_call_id=m.tool_call_id)
                truncated.append(m)
            return truncated

        def _trim_history_if_needed(msgs: list) -> list:
            """若总历史过长，从第 3 条消息（索引 2）开始删除最旧的工具往返对，保留 SystemPrompt 和用户请求"""
            from langchain_core.messages import ToolMessage, AIMessage as AI
            total = sum(len(m.content) if isinstance(m.content, str) else 0 for m in msgs)
            while total > MAX_TOTAL_HISTORY_CHARS and len(msgs) > 2:
                # 找到第一个可删除的 AI 消息（索引 2 之后）
                removed = msgs.pop(2)
                total -= len(removed.content) if isinstance(removed.content, str) else 0
                # 如果它后面紧跟着 ToolMessage，也一并删除
                if len(msgs) > 2 and isinstance(msgs[2], ToolMessage):
                    t = msgs.pop(2)
                    total -= len(t.content) if isinstance(t.content, str) else 0
            return msgs

        # 最多循环 5 轮（搜索 → 读取 → 分析 → 输出）
        MAX_ROUNDS = 5
        for round_idx in range(MAX_ROUNDS):
            # 每轮发送前检查并修剪过长的历史，防止雪球化
            messages = _trim_history_if_needed(messages)
            response = await llm_with_tools.ainvoke(messages)
            messages.append(response)

            # 检查是否调用了工具
            if hasattr(response, "tool_calls") and response.tool_calls:
                logger.info(f"[情报智能体] 第{round_idx+1}轮：调用工具 {[tc['name'] for tc in response.tool_calls]}")
                # 执行工具调用
                tool_result_state = await intel_tool_node.ainvoke({"messages": messages})
                tool_messages = tool_result_state.get("messages", [])

                # ToolNode 单独执行时，返回的是新增的 ToolMessage 列表
                if tool_messages:
                    if hasattr(tool_messages[0], "type") and tool_messages[0].type == "tool":
                        # 截断工具输出后再加入历史
                        messages.extend(_truncate_tool_messages(tool_messages))
                    else:
                        # 兜底：如果返回了整个历史，同样对工具消息截断
                        messages = _truncate_tool_messages(tool_messages)
                logger.info(f"[情报智能体] 第{round_idx+1}轮工具调用完成，当前历史消息数: {len(messages)}")
            else:
                # Agent 不再调用工具，分析完毕
                logger.info(f"[情报智能体] 第{round_idx+1}轮：分析完成，无更多工具调用")
                break

        # 解析最终回复中的 Playbook
        final_content = ""
        for msg in reversed(messages):
            if hasattr(msg, "content") and isinstance(msg.content, str) and msg.content:
                final_content = msg.content
                break

        playbooks = _parse_playbooks(final_content, identified_cves)

        if playbooks:
            logger.info(f"[情报智能体] 成功生成 {len(playbooks)} 个 Playbook: {[p['cve_id'] for p in playbooks]}")
            return {
                "attack_playbooks": playbooks,
                "intelligence_status": "done",
                "last_node": "intelligence"
            }
        else:
            logger.warning("[情报智能体] 未能解析出结构化 Playbook，将原始分析存为文本。")
            # 退化：将整个分析文本作为非结构化 Playbook 存储
            fallback_playbook = {
                "cve_id": identified_cves[0] if identified_cves else "unknown",
                "target_component": "未知",
                "vulnerability_type": "未知",
                "trigger_endpoint": "未知",
                "http_method": "POST",
                "required_headers": {},
                "payload_description": final_content[:2000],
                "execution_steps": ["请参考 payload_description 字段的分析内容"],
                "python_template": "",
                "success_indicator": "命令/请求执行成功",
                "source": "LLM 知识推导",
                "raw_poc_summary": final_content[:500]
            }
            return {
                "attack_playbooks": [fallback_playbook],
                "intelligence_status": "done",
                "last_node": "intelligence"
            }

    return intelligence_node


def _parse_playbooks(content: str, cve_ids: list) -> list:
    """
    从 Intelligence Agent 的回复文本中解析结构化 Playbook

    解析 [PLAYBOOK_START] ... [PLAYBOOK_END] 标记内的 JSON 数据

    Args:
        content: Agent 的完整回复文本
        cve_ids: 预期的 CVE ID 列表（用于验证）

    Returns:
        解析出的 Playbook 列表（可能为空）
    """
    playbooks = []
    import re

    # 提取 [PLAYBOOK_START] ... [PLAYBOOK_END] 之间的内容
    pattern = re.compile(
        r'\[PLAYBOOK_START\](.*?)\[PLAYBOOK_END\]',
        re.DOTALL | re.IGNORECASE
    )
    matches = pattern.findall(content)

    for match in matches:
        raw_json = match.strip()
        # 如果有 markdown 代码块，去掉它
        if raw_json.startswith("```"):
            raw_json = re.sub(r'^```(?:json)?\s*', '', raw_json)
            raw_json = re.sub(r'\s*```$', '', raw_json)
        try:
            playbook = json.loads(raw_json)
            # 基础字段验证
            if "cve_id" not in playbook:
                playbook["cve_id"] = cve_ids[0] if cve_ids else "unknown"
            playbooks.append(playbook)
            logger.info(f"[情报解析] 成功解析 Playbook: {playbook.get('cve_id')}")
        except json.JSONDecodeError as e:
            logger.warning(f"[情报解析] JSON 解析失败: {e}\n原始内容: {raw_json[:200]}")

    return playbooks
