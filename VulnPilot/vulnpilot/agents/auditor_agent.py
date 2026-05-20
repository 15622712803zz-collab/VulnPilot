"""
Auditor Agent - 错误审计专家
================================

职责：
- 分析工具执行失败的原因
- 区分代码错误 vs 决策错误
- 提供针对性的修复建议

触发条件：
- tools node 连续失败3次

输出：
- error_type: "code_error" | "decision_error" | "unknown"
- next_action: "regenerate_code" | "consult_advisor" | "continue"
- reasoning: 详细分析
"""

# ==================== Auditor Agent 系统提示词 ====================
AUDITOR_SYSTEM_PROMPT = '''
# 安全测试错误审计专家

你是一个专门分析CTF安全测试失败原因的审计专家。

## 你的任务

分析最近3次工具执行失败的原因，并给出明确的修复方向。

## 错误分类

### 🔧 代码/命令错误（Code Error）

**特征**：
- Python语法错误（SyntaxError, IndentationError, NameError, TypeError, AttributeError, ImportError）
- 命令不存在（command not found, No such file）
- 权限问题（permission denied, access denied）
- 网络超时（timeout, connection refused, connection timed out）
- 工具使用错误（invalid option, missing argument, unknown flag）
- 格式错误（invalid JSON, malformed request）

**判断标准**：
- 工具输出包含明确的错误信息
- 错误信息指向代码或命令本身的问题
- 修复方法：重新生成正确的代码/命令

**建议动作**：`regenerate_code`

---

### 🎯 决策错误（Decision Error）

**特征**：
- **无进展**：连续N次测试都返回相同响应长度（如都是317字节）
- **忽略提示**：服务器明确提示（如"密码为四位数字"）但Agent继续测试其他方向
- **重复测试**：相同的凭据或payload被反复测试
- **方向错误**：测试了不相关的漏洞类型（如服务器返回明确错误但继续相同攻击）
- **资源浪费**：大量测试都返回404或403，但未切换策略

**判断标准**：
- 工具执行成功（没有语法/命令错误），但结果无价值
- 攻击方向与已知线索不符
- 修复方法：重新规划攻击策略

**建议动作**：`consult_advisor`

---

### ❓ 未知错误（Unknown Error）

**特征**：
- 无法明确分类为代码错误或决策错误
- 可能是环境问题或偶发错误
- 信息不足以做出准确判断

**建议动作**：`continue`（让Main Agent继续尝试）

---

## 输出格式（必须输出JSON）

```json
{
    "error_type": "code_error",
    "confidence": 0.9,
    "next_action": "regenerate_code",
    "reasoning": "检测到Python SyntaxError: invalid syntax。这是明显的代码错误，建议PoC Agent重新生成代码。",
    "key_evidence": [
        "SyntaxError: invalid syntax at line 15",
        "requests.get(url, params={'user': 'admin')"
    ],
    "suggested_fix": "修复代码语法错误：添加缺失的闭合括号"
}
```

## 分析步骤

1. **提取最近3次失败的工具输出**
2. **检查代码/命令错误特征**
   - 扫描错误关键词（SyntaxError, NameError, command not found等）
   - 分析错误堆栈
3. **检查决策错误特征**
   - 比较响应相似度（连续3次相同长度？）
   - 检查是否忽略提示（响应中有"密码为N位数字"等提示？）
   - 检查是否重复测试（相同payload多次出现？）
4. **📓 参考历史失败笔记（重要！）**
   - 查看"历史失败记录"中已经记录的失败方法
   - **如果 `next_action` 是 `consult_advisor`，但笔记中记录的失败方法与当前失败完全相同，说明Advisor建议已经无效，应升级为 `continue` 或标记为 `unknown`**
   - 利用笔记避免推荐已知无效的方法
5. **给出分类和建议**
6. **输出JSON格式结果**

---

## 重要规则

1. **优先识别代码错误**：代码错误更容易修复，且更明确
2. **置信度要诚实**：不确定时标记为 "unknown"，置信度<0.7
3. **提供具体证据**：引用具体的错误信息或响应内容
4. **避免过度审计**：如果连续2次审计都给出相同结论，建议切换到Advisor
5. **📓 参考历史笔记**：避免推荐笔记中已记录的失败方法

---

## 输出要求

**必须严格遵守JSON格式**，不要添加任何Markdown包装，直接输出JSON对象。

示例（正确）：
```
{"error_type": "code_error", "confidence": 0.9, ...}
```

示例（错误）：
```
```json
{"error_type": "code_error", ...}
```
```

---

现在开始你的审计工作。
'''


def create_auditor_prompt(state) -> str:
    """
    构建Auditor的分析上下文
    
    Args:
        state: PenetrationTesterState
        
    Returns:
        格式化的上下文字符串
    """
    from langchain_core.messages import ToolMessage
    
    # 提取最近的工具消息
    messages = state.get("messages", [])
    tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
    
    # 获取最近3次
    recent_failures = tool_messages[-3:] if len(tool_messages) >= 3 else tool_messages
    
    if not recent_failures:
        return "## 最近工具执行结果\n\n【无工具执行记录】\n"
    
    context = "## 最近工具执行结果\n\n"
    context += f"**失败次数**：{state.get('consecutive_failures', 0)} 次\n\n"
    
    for i, msg in enumerate(recent_failures, 1):
        tool_name = getattr(msg, 'name', 'unknown_tool')
        content = msg.content if msg.content else "（空输出）"
        
        # 截取前1000字符（避免过长）
        content_preview = content[:1000]
        if len(content) > 1000:
            content_preview += "\n...(输出过长，已截断)"
        
        context += f"### 失败 {i}（工具：{tool_name}）\n"
        context += f"```\n{content_preview}\n```\n\n"
    
    # 添加额外上下文
    context += "## 额外上下文\n\n"
    
    # 是否有重复测试的迹象
    audit_history = state.get("audit_history", [])
    if audit_history:
        context += f"- **已审计次数**：{len(audit_history)} 次\n"
        last_audit = audit_history[-1] if audit_history else {}
        if last_audit:
            context += f"- **上次审计结论**：{last_audit.get('error_type', 'unknown')} (置信度: {last_audit.get('confidence', 0)})\n"
    
    context += f"- **当前尝试次数**：{len(messages)} 条消息\n"
    
    # ==================== 📓 注入过程笔记（参考结构化过程笔记 Reflection机制）====================
    # 对应过程笔记的 REFLECTION_TASK 中获取 cell_context + error_context
    try:
        from vulnpilot.notebook import format_notebook_for_auditor
        notebook_section = format_notebook_for_auditor(state.get("process_notebook"))
        if notebook_section:
            context += f"\n{notebook_section}\n"
    except Exception:
        pass  # 笔记注入失败不影响审计主流程
    
    return context


async def auditor_node(state) -> dict:
    """
    Auditor Agent 节点
    
    分析工具执行失败的原因，给出修复建议
    
    Args:
        state: PenetrationTesterState
        
    Returns:
        更新后的状态
    """
    from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
    from vulnpilot.common import log_system_event
    import json
    import time
    
    log_system_event(
        "[🔍] Auditor Agent 启动",
        {
            "consecutive_failures": state.get("consecutive_failures", 0),
            "audit_history_count": len(state.get("audit_history", []))
        }
    )
    
    # 构建分析上下文
    context = create_auditor_prompt(state)
    
    # 调用LLM
    from vulnpilot.model import create_model
    from vulnpilot.core.singleton import get_config_manager
    
    agent_config = get_config_manager().config
    auditor_llm = create_model(agent_config)
    
    messages = [
        SystemMessage(content=AUDITOR_SYSTEM_PROMPT),
        HumanMessage(content=context)
    ]
    
    try:
        # 调用LLM
        from vulnpilot.utils.util import retry_llm_call
        response = await retry_llm_call(
            auditor_llm.ainvoke,
            messages,
            max_retries=3
        )
        
        # 解析JSON
        content = response.content.strip()
        
        # 尝试提取JSON（处理可能的Markdown包装）
        if content.startswith("```"):
            # 移除Markdown代码块
            lines = content.split('\n')
            json_lines = []
            in_code_block = False
            for line in lines:
                if line.startswith("```"):
                    in_code_block = not in_code_block
                    continue
                if in_code_block or not line.startswith("```"):
                    json_lines.append(line)
            content = '\n'.join(json_lines).strip()
        
        audit_result = json.loads(content)
        
        # 验证必需字段
        required_fields = ["error_type", "confidence", "next_action", "reasoning"]
        for field in required_fields:
            if field not in audit_result:
                raise ValueError(f"缺少必需字段: {field}")
        
        log_system_event(
            "[✓] Auditor 分析完成",
            {
                "error_type": audit_result["error_type"],
                "confidence": audit_result["confidence"],
                "next_action": audit_result["next_action"]
            }
        )
        
    except Exception as e:
        log_system_event(
            "[❌] Auditor 分析失败",
            {"error": str(e)}
        )
        
        # 使用默认值（继续Main Agent）
        audit_result = {
            "error_type": "unknown",
            "confidence": 0.5,
            "next_action": "continue",
            "reasoning": f"Auditor分析失败：{str(e)}",
            "key_evidence": [],
            "suggested_fix": "继续尝试"
        }
    
    # 更新审计历史
    audit_history = state.get("audit_history", [])
    audit_history.append({
        "attempt": len(state.get("messages", [])),
        "error_type": audit_result["error_type"],
        "audit_decision": audit_result["next_action"],
        "confidence": audit_result["confidence"],
        "reasoning": audit_result["reasoning"],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    
    # 构建AI消息（记录审计结果）
    audit_message = AIMessage(
        content=f"🔍 **Auditor审计结果**\n\n"
                f"- **错误类型**：{audit_result['error_type']}\n"
                f"- **置信度**：{audit_result['confidence']}\n"
                f"- **建议动作**：{audit_result['next_action']}\n"
                f"- **分析理由**：{audit_result['reasoning']}\n",
        name="auditor"
    )
    
    return {
        "audit_history": audit_history,
        "current_error_context": audit_result,
        "messages": [audit_message]
    }
