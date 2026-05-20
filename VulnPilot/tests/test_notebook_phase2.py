"""
阶段2功能测试脚本
运行方式: uv run python tests/test_notebook_phase2.py
"""
import sys
sys.path.insert(0, '.')

print("=" * 60)
print("测试1: 模块导入验证")
print("=" * 60)

from vulnpilot.notebook import (
    init_notebook,
    extract_from_tool_output,
    extract_failed_attempt,
    add_failed_attempt,
    merge_notebook,
    format_notebook_for_context,
    format_notebook_for_auditor,
)
print("✅ notebook.py 所有函数导入成功")

from vulnpilot.agents.auditor_agent import (
    AUDITOR_SYSTEM_PROMPT,
    create_auditor_prompt,
)
print("✅ auditor_agent.py 导入成功")

print()
print("=" * 60)
print("测试2: format_notebook_for_auditor（Auditor专属格式化）")
print("=" * 60)

# 构造一个有失败记录的笔记
state = {
    "current_challenge": {
        "challenge_code": "web-phase2",
        "target_info": {"ip": "10.0.0.1", "port": [80]}
    }
}
nb = init_notebook(state)

# 第1轮：发现端点
delta1 = extract_from_tool_output(
    tool_name="execute_poc",
    tool_output="发现 /api/login 端点，支持POST，状态码: 200",
    round_num=1
)
nb = merge_notebook(nb, delta1)

# 第2轮：SQLi失败
delta2 = extract_from_tool_output(
    tool_name="execute_poc",
    tool_output="SQL注入测试失败，error: blocked by waf, status 403",
    round_num=2
)
nb = merge_notebook(nb, delta2)

# 第3轮：XSS失败
delta3 = extract_from_tool_output(
    tool_name="execute_poc",
    tool_output="XSS测试失败，输出被HTML编码，无法注入，error: filtered",
    round_num=3
)
nb = merge_notebook(nb, delta3)

print("Auditor 专属视图（只含失败记录）：")
print(format_notebook_for_auditor(nb))
print()
print(f"失败记录数量: {len(nb['failed_attempts'])}")

print()
print("=" * 60)
print("测试3: create_auditor_prompt 注入笔记")
print("=" * 60)

# 模拟state（带过程笔记）
from langchain_core.messages import ToolMessage

mock_tool_msg = ToolMessage(
    content="SQLi失败：error: blocked by waf, status 403",
    tool_call_id="test_call_001",
    name="execute_poc"
)

mock_state = {
    "messages": [mock_tool_msg, mock_tool_msg, mock_tool_msg],
    "consecutive_failures": 3,
    "audit_history": [],
    "process_notebook": nb,  # 注入有失败记录的笔记
}

prompt = create_auditor_prompt(mock_state)
print("Auditor 上下文（含注入的笔记）：")
print(prompt)

print()
has_notebook = "历史失败记录" in prompt
print(f"✅ 笔记已注入到Auditor上下文: {has_notebook}")

print()
print("=" * 60)
print("测试4: AUDITOR_SYSTEM_PROMPT 包含笔记利用指引")
print("=" * 60)
has_notebook_guide = "历史失败笔记" in AUDITOR_SYSTEM_PROMPT
has_rule = "参考历史笔记" in AUDITOR_SYSTEM_PROMPT
print(f"✅ 提示词包含笔记分析步骤: {has_notebook_guide}")
print(f"✅ 提示词包含笔记规则: {has_rule}")

print()
print("=" * 60)
print("测试5: extract_failed_attempt 独立测试")
print("=" * 60)
failed = extract_failed_attempt(
    tool_name="execute_poc",
    tool_output="尝试payload: ' OR 1=1-- 失败，WAF拦截，error: blocked by waf",
    round_num=5,
    method_hint="sqli"
)
print(f"提取到的失败记录: {failed}")
assert failed is not None, "应该提取到失败记录"
assert "WAF" in failed["reason"], f"原因应包含WAF，实际: {failed['reason']}"
print("✅ extract_failed_attempt 正常")

print()
print("=" * 60)
print("全部阶段2测试完成！")
print("=" * 60)
