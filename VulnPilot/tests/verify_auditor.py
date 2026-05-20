"""
Auditor Agent 手动验证脚本
===========================

不依赖pytest，直接运行测试
"""

import sys
import asyncio
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


async def test_basic_functionality():
    """测试基本功能"""
    from vulnpilot.agents.auditor_agent import create_auditor_prompt
    from langchain_core.messages import ToolMessage
    
    print("=" * 70)
    print("Test 1: Context Building")
    print("=" * 70)
    
    state = {
        "messages": [
            ToolMessage(content="SyntaxError: invalid syntax", name="tool1", tool_call_id="call_1"),
            ToolMessage(content="NameError: name 'x' is not defined", name="tool2", tool_call_id="call_2"),
            ToolMessage(content="IndentationError: unexpected indent", name="tool3", tool_call_id="call_3")
        ],
        "consecutive_failures": 3,
        "audit_history": []
    }
    
    context = create_auditor_prompt(state)
    print(context)
    print("\n[OK] Context building succeeded\n")
    
    return True


async def test_import():
    """测试基本导入"""
    print("=" * 70)
    print("Test 2: Module Import")
    print("=" * 70)
    
    try:
        from vulnpilot.agents.auditor_agent import (
            AUDITOR_SYSTEM_PROMPT,
            auditor_node,
            create_auditor_prompt
        )
        print("[OK] auditor_agent.py imported successfully")
        
        from vulnpilot.state import PenetrationTesterState
        print("[OK] state.py imported successfully (with audit fields)")
        
        print("\n[OK] All modules imported successfully\n")
        return True
        
    except Exception as e:
        print(f"[FAIL] Import failed: {e}\n")
        return False


async def test_state_definition():
    """测试状态定义"""
    print("=" * 70)
    print("Test 3: State Definition Verification")
    print("=" * 70)
    
    try:
        from vulnpilot.state import PenetrationTesterState
        
        # 检查是否包含审计字段
        annotations = PenetrationTesterState.__annotations__
        
        required_fields = [
            "audit_history",
            "max_audit_retries",
            "current_error_context"
        ]
        
        for field in required_fields:
            if field in annotations:
                print(f"[OK] Field '{field}' exists")
            else:
                print(f"[FAIL] Field '{field}' missing")
                return False
        
        print("\n[OK] State definition verification passed\n")
        return True
        
    except Exception as e:
        print(f"[FAIL] State verification failed: {e}\n")
        return False


async def test_graph_integration():
    """测试图集成"""
    print("=" * 70)
    print("Test 4: Graph Integration Verification")
    print("=" * 70)
    
    try:
        # 检查graph.py中是否导入了auditor
        with open("vulnpilot/graph.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        checks = [
            ("from vulnpilot.agents.auditor_agent import", "Auditor import"),
            ("workflow.add_node(\"auditor\",", "Auditor node added"),
            ("def route_after_auditor", "route_after_auditor function"),
            ("\"auditor\": \"auditor\"", "auditor routing")
        ]
        
        all_passed = True
        for check_str, desc in checks:
            if check_str in content:
                print(f"[OK] {desc}")
            else:
                print(f"[FAIL] {desc} - not found")
                all_passed = False
        
        if all_passed:
            print("\n[OK] Graph integration verification passed\n")
        else:
            print("\n[FAIL] Graph integration verification failed\n")
        
        return all_passed
        
    except Exception as e:
        print(f"[FAIL] Graph verification failed: {e}\n")
        return False


async def main():
    """主测试函数"""
    print("\n" + "=" * 70)
    print("Auditor Agent Functionality Verification")
    print("=" * 70 + "\n")
    
    results = []
    
    # 测试1：导入
    result1 = await test_import()
    results.append(("Module Import", result1))
    
    # 测试2：状态定义
    result2 = await test_state_definition()
    results.append(("State Definition", result2))
    
    # 测试3：基本功能
    result3 = await test_basic_functionality()
    results.append(("Context Building", result3))
    
    # 测试4：Graph集成
    result4 = await test_graph_integration()
    results.append(("Graph Integration", result4))
    
    # 汇总结果
    print("=" * 70)
    print("Test Results Summary")
    print("=" * 70)
    
    for test_name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {test_name}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    
    print(f"\nTotal: {passed}/{total} passed")
    
    if passed == total:
        print("\nSUCCESS: All verifications passed! Auditor Agent integration successful!")
        return 0
    else:
        print(f"\nWARNING: {total - passed} test(s) failed, please check errors above")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
