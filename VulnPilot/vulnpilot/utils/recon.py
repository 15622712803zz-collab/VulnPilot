"""
自动信息收集模块
================

在 Agent 开始决策前，自动执行基础信息收集，避免盲猜。

增强功能:
- ⭐ 自动检测和提取 HTML 表单字段
"""
import requests
from typing import Dict, Optional
from vulnpilot.common import log_system_event


def auto_recon_web_target(target_ip: str, target_port: int, timeout: int = 10) -> Dict[str, any]:
    """
    自动对 Web 目标进行基础信息收集

    增强功能:
    - ⭐ 自动检测 HTML 表单并提取字段

    Args:
        target_ip: 目标 IP
        target_port: 目标端口
        timeout: 请求超时时间（秒）

    Returns:
        包含收集到的信息的字典：
        {
            "success": bool,
            "url": str,
            "status_code": int,
            "headers": dict,
            "html_content": str,
            "html_length": int,
            "title": str,
            "forms": list,  # ⭐ 新增：表单信息
            "error": str (如果失败)
        }
    """
    url = f"http://{target_ip}:{target_port}"

    log_system_event(
        f"[自动侦察] 开始收集目标信息: {url}, timeout: {timeout}",
        {}
    )

    result = {
        "success": False,
        "url": url,
        "status_code": None,
        "headers": {},
        "html_content": "",
        "html_length": 0,
        "title": "",
        "forms": [],  # ⭐ 新增
        "error": None
    }

    try:
        # 发送 GET 请求
        response = requests.get(url, timeout=timeout, allow_redirects=True)

        result["success"] = True
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["html_content"] = response.text
        result["html_length"] = len(response.text)

        # 尝试提取 <title>
        import re
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            result["title"] = title_match.group(1).strip()

        # ⭐ 新增：检测并提取表单字段
        if '<form' in response.text.lower():
            try:
                from vulnpilot.tools.web_tools import extract_web_form_fields

                # 提取所有表单（最多 3 个）
                form_count = response.text.lower().count('<form')
                for i in range(min(form_count, 3)):
                    # ⭐ 修复：使用 .invoke() 方法调用 LangChain 工具
                    form_info = extract_web_form_fields.invoke({"html": response.text, "form_index": i})
                    if not form_info.get('error'):
                        result["forms"].append(form_info)

                log_system_event(
                    f"[自动侦察] 🔍 检测到 {len(result['forms'])} 个表单",
                    {"forms": result["forms"]}
                )
            except Exception as e:
                log_system_event(
                    f"[自动侦察] ⚠️ 表单提取失败（非致命错误）",
                    {"error": str(e)}
                )

        log_system_event(
            f"[自动侦察] ✅ 成功获取目标信息",
            {
                "status_code": result["status_code"],
                "content_length": result["html_length"],
                "title": result["title"] if result["title"] else "无标题",
                "server": result["headers"].get("Server", "未知"),
                "content_type": result["headers"].get("Content-Type", "未知"),
                "forms_detected": len(result["forms"]),
                "text": response.text
            }
        )

    except requests.exceptions.Timeout:
        result["error"] = f"请求超时（{timeout}秒）"
        log_system_event(
            f"[自动侦察] ⏱️ 请求超时: {url}",
            {"timeout": timeout}
        )
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"连接失败: {str(e)}"
        log_system_event(
            f"[自动侦察] ❌ 连接失败: {url}",
            {"error": str(e)}
        )
    except Exception as e:
        result["error"] = f"未知错误: {str(e)}"
        log_system_event(
            f"[自动侦察] ⚠️ 未知错误: {url}",
            {"error": str(e)}
        )

    return result


def format_recon_result_for_llm(recon_result: Dict) -> str:
    """
    将侦察结果格式化为适合 LLM 阅读的文本

    增强功能:
    - ⭐ 自动展示提取的表单字段

    Args:
        recon_result: auto_recon_web_target 的返回结果

    Returns:
        格式化的文本
    """
    if not recon_result["success"]:
        return f"""
## 🔍 自动侦察结果

⚠️ **无法访问目标**：{recon_result['url']}
- 错误信息：{recon_result['error']}
- 建议：检查目标是否在线，或尝试其他端口
"""

    # 获取完整 HTML 内容（不截断，让 LLM 看到所有信息）
    html_preview = recon_result["html_content"]

    # 提取关键响应头
    headers = recon_result["headers"]
    key_headers = {
        "Server": headers.get("Server", "未知"),
        "Content-Type": headers.get("Content-Type", "未知"),
        "X-Powered-By": headers.get("X-Powered-By", "无"),
        "Set-Cookie": headers.get("Set-Cookie", "无"),
    }

    # ⭐ 新增：格式化表单信息
    forms_section = ""
    if recon_result.get("forms"):
        forms_section = "\n### ⭐ 检测到的表单\n\n"
        for idx, form in enumerate(recon_result["forms"], 1):
            forms_section += f"**表单 {idx}**:\n"
            forms_section += f"- Action: `{form['action']}` (Method: {form['method']})\n"
            forms_section += f"- 字段数量: {len(form['fields'])} 个\n"

            # 列出所有字段
            if form['fields']:
                forms_section += "- 字段列表:\n"
                for field_name, field_info in form['fields'].items():
                    hidden_tag = " [HIDDEN]" if field_info['hidden'] else ""
                    required_tag = " *" if field_info['required'] else ""
                    value_preview = f" (默认值: '{field_info['value']}')" if field_info['value'] else ""
                    forms_section += f"  - `{field_name}` ({field_info['type']}){hidden_tag}{required_tag}{value_preview}\n"

            forms_section += "\n"

        forms_section += """**⚠️ 重要提示**:
- 所有 [HIDDEN] 字段在提交时都必须包含，即使有默认值
- 多阶段认证时，必须使用 `extract_web_form_fields` 工具提取所有字段
- 示例代码:
  ```python
  # 正确做法
  form_info = extract_web_form_fields(resp1.text)
  data = {k: v['value'] for k, v in form_info['fields'].items()}
  data['password'] = 'test'  # 修改需要的字段
  resp2 = requests.post(url, data=data)
  ```

"""

    return f"""
## 🔍 自动侦察结果

**目标 URL**：{recon_result['url']}
**状态码**：{recon_result['status_code']}
**页面标题**：{recon_result['title'] if recon_result['title'] else "无标题"}

### 响应头信息
```
Server: {key_headers['Server']}
Content-Type: {key_headers['Content-Type']}
X-Powered-By: {key_headers['X-Powered-By']}
Set-Cookie: {key_headers['Set-Cookie']}
```
{forms_section}
### HTML 源码
```html
{html_preview}
```

---
**提示**：以上是自动收集的基础信息，请基于这些信息制定攻击策略，避免盲猜。
"""
