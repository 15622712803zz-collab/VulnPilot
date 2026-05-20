"""
notebook.py 功能测试脚本
运行方式: uv run python tests/test_notebook.py
"""
import sys
sys.path.insert(0, '.')

from vulnpilot.notebook import (
    init_notebook,
    extract_from_tool_output,
    merge_notebook,
    format_notebook_for_context,
)

print("=" * 60)
print("测试1: 初始化笔记")
print("=" * 60)
state = {
    "current_challenge": {
        "challenge_code": "web-test",
        "target_info": {"ip": "127.0.0.1", "port": [8080]}
    }
}
nb = init_notebook(state)
print("初始化成功:", nb["meta"])

print()
print("=" * 60)
print("测试2: 提取工具输出（发现端点）")
print("=" * 60)
delta1 = extract_from_tool_output(
    tool_name="execute_poc",
    tool_output="发现 /api/user 端点，状态码: 200，返回用户信息泄露，邮箱 admin@test.com",
    round_num=1
)
print("提取到资产:", [a["value"] for a in delta1["assets"]])
print("提取到发现:", delta1["key_findings"])
nb = merge_notebook(nb, delta1)

print()
print("=" * 60)
print("测试3: 提取工具输出（失败案例）")
print("=" * 60)
delta2 = extract_from_tool_output(
    tool_name="execute_poc",
    tool_output="SQL注入测试失败，error: blocked by waf, status 403",
    round_num=2
)
print("round_log:", delta2["round_log"])
nb = merge_notebook(nb, delta2)

print()
print("=" * 60)
print("测试4: 格式化输出（Advisor/Main Agent读取格式）")
print("=" * 60)
print(format_notebook_for_context(nb))

print()
print("=" * 60)
print("测试5: 验证笔记状态")
print("=" * 60)
print("资产数量:", len(nb["assets"]))
print("失败记录数量:", len(nb["failed_attempts"]))
print("关键发现数量:", len(nb["key_findings"]))
print("轮次记录数量:", len(nb["round_log"]))
print("总轮次:", nb["meta"]["round_count"])
print()
print("全部测试完成！")
