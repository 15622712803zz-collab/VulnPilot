"""
FLAG 格式验证工具
==================

用于验证 FLAG 格式是否正确，防止提交不完整的 FLAG。

标准 FLAG 格式：
- 必须以 'flag{' 开头
- 必须以 '}' 结尾
- 中间包含有效内容
"""
import re
from typing import Tuple


def validate_flag_format(flag: str) -> Tuple[bool, str]:
    """
    验证 FLAG 格式是否正确

    Args:
        flag: 待验证的 FLAG 字符串

    Returns:
        (is_valid, error_message) 元组
        - is_valid: 是否有效
        - error_message: 错误信息（如果无效）
    """
    if not flag:
        return False, "FLAG 不能为空"

    # ⭐ 检查是否以 'flag{' 开头（忽略大小写）
    if not flag.lower().startswith("flag{"):
        return False, f"FLAG 必须以 'flag{{' 或 'FLAG{{' 开头（忽略大小写），当前: {flag}..."

    # 检查是否以 '}' 结尾
    if not flag.endswith("}"):
        return False, f"FLAG 必须以 '}}' 结尾，当前: ...{flag[-10:]}"

    # 检查是否包含有效内容
    content = flag[5:-1]  # 去掉 'flag{' 和 '}'
    if not content:
        return False, "FLAG 内容不能为空（flag{} 无效）"

    # 检查是否包含非法字符（可选，根据评测规则调整）
    # 一般 FLAG 内容只包含字母、数字、下划线、连字符
    if not re.match(r'^[a-zA-Z0-9_\-]+$', content):
        # 警告但不阻止（某些评测可能允许特殊字符）
        return True, f"⚠️ 警告：FLAG 内容包含特殊字符，请确认是否正确: {content}"

    return True, ""


def extract_flag_from_text(text: str) -> list:
    """
    从文本中提取所有可能的 FLAG

    Args:
        text: 包含 FLAG 的文本

    Returns:
        提取到的 FLAG 列表（去重，已过滤占位符）
    """
    # 匹配 flag{...} 或 FLAG{...} 格式（忽略大小写）
    pattern = r'[Ff][Ll][Aa][Gg]\{[^}]+\}'
    flags = re.findall(pattern, text)

    # =====================================================================
    # 占位符过滤：排除明显不是真实 FLAG 的模板/注释文字
    # 背景：工具代码注释中常出现"如 flag{...}"等示例描述，
    # 如果不过滤会导致 Agent 误判为找到 FLAG 而提前终止解题。
    # =====================================================================

    # 占位符黑名单正则：匹配明显的模板/示例字符串
    PLACEHOLDER_PATTERNS = [
        r'^flag\{\.+\}$',               # flag{.} / flag{...} / flag{......}
        r'^flag\{[?*！!]+\}$',          # flag{???} / flag{***}
        r'^flag\{your.flag.here\}$',    # flag{your_flag_here}
        r'^flag\{<[^>]*>\}$',           # flag{<value>} / flag{<flag>}
        r'^flag\{insert.flag\}$',       # flag{insert_flag_here}
        r'^flag\{xxx+\}$',              # flag{xxx} / flag{xxxxxxx}
        r'^flag\{example\}$',           # flag{example}
        r'^flag\{placeholder\}$',       # flag{placeholder}
        r'^flag\{flag\}$',              # flag{flag} 错误字面量
        r'^flag\{flags\[\d+\]\}$',      # flag{flags[0]} 错误字面量
    ]

    def is_placeholder(flag: str) -> bool:
        """判断是否为占位符/模板 FLAG"""
        flag_lower = flag.lower()

        # 规则1：花括号内内容过短（少于4字符），几乎不可能是真实 FLAG
        # 例：flag{...} 内容为 "..." 仅3个字符
        content = flag_lower[5:-1]  # 去掉 "flag{" 和 "}"
        if len(content) < 4:
            return True

        # 规则2：内容全由相同字符重复构成（如 "..." "...." "xxx"）
        if len(set(content)) == 1:
            return True

        # 规则3：匹配已知占位符模式
        for pat in PLACEHOLDER_PATTERNS:
            if re.match(pat, flag_lower, re.IGNORECASE):
                return True

        return False

    # 去重并过滤（保持原始大小写）
    unique_flags = []
    seen = set()
    for flag in flags:
        flag_lower = flag.lower()
        if flag_lower not in seen:
            seen.add(flag_lower)
            # 跳过占位符
            if not is_placeholder(flag):
                unique_flags.append(flag)

    return unique_flags


def suggest_flag_fix(incomplete_flag: str) -> str:
    """
    尝试修复不完整的 FLAG

    Args:
        incomplete_flag: 不完整的 FLAG

    Returns:
        修复建议
    """
    suggestions = []

    # ⭐ 忽略大小写检查前缀
    if not incomplete_flag.lower().startswith("flag{"):
        suggestions.append("添加 'flag{' 前缀")

    if not incomplete_flag.endswith("}"):
        suggestions.append("添加 '}' 后缀")

    if suggestions:
        return f"建议修复：{', '.join(suggestions)}"

    return "FLAG 格式看起来正确"


# 示例用法
if __name__ == "__main__":
    test_cases = [
        "flag{hahahahaha_this_is_demo_test_flag}",  # ✓ 正确
        "FLAG{hahahahaha_this_is_demo_test_flag}",  # ✓ 正确（大写）
        "Flag{test_mixed_case}",                     # ✓ 正确（混合大小写）
        "FlaG{another_test}",                        # ✓ 正确（混合大小写）
        "flag{hahahahaha_this_is_demo_test_flag",   # ✗ 缺少 }
        "hahahahaha_this_is_demo_test_flag}",       # ✗ 缺少 flag{
        "flag{}",                                    # ✗ 内容为空
        "flag{test-123_ABC}",                        # ✓ 正确
        "flag{test@#$}",                             # ⚠️ 特殊字符
    ]

    print("=" * 60)
    print("FLAG 格式验证测试")
    print("=" * 60)
    for flag in test_cases:
        is_valid, msg = validate_flag_format(flag)
        status = "✓" if is_valid else "✗"
        print(f"{status} {flag}")
        if msg:
            print(f"  → {msg}")
        if not is_valid:
            print(f"  → {suggest_flag_fix(flag)}")
        print()
