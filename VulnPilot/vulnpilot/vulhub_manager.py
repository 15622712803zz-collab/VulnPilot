"""
Vulhub 靶机生命周期管理模块
==============================

负责：
1. 解析 docker-compose.yml，获取 Web 端口和服务信息
2. 启动/停止 Vulhub 靶机容器（docker compose up/down）
3. 等待靶机服务就绪（HTTP 健康检查）
4. 读取 README.md 获取漏洞描述，注入 Agent 上下文

设计原则：
- 完全独立于现有代码，不影响 -t 和 -api 模式
- 通过 host.docker.internal 解决 Kali 容器访问靶机的网络问题
- 靶机路径格式：app_name/CVE-XXXX-XXXX（相对于 vulhub 仓库根目录）
"""

import os
import subprocess
import time
import socket
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple

import requests
import yaml

from vulnpilot.common import log_system_event


# ==================== 常量配置 ====================

# Kali 容器访问宿主机的特殊域名（Windows Docker Desktop 自动支持）
DOCKER_HOST_NAME = "host.docker.internal"

# 靶机启动等待超时（秒）
STARTUP_TIMEOUT = 120

# 健康检查间隔（秒）
HEALTH_CHECK_INTERVAL = 5

# 健康检查时认为"就绪"的 HTTP 状态码
# 任何有效 HTTP 响应都代表服务已启动（包括 502/503 等错误码，对 Vulhub 靶机很常见）
READY_STATUS_CODES = set(range(100, 600))  # 100-599 全覆盖


# Web 端口优先级（数字越小优先级越高）
WEB_PORT_PRIORITY = {80: 0, 8080: 1, 8888: 2, 8000: 3, 443: 4, 8443: 5, 3000: 6, 9090: 7}


# ==================== 核心类 ====================

class VulhubManager:
    """
    Vulhub 靶机生命周期管理器

    使用示例：
        manager = VulhubManager(vulhub_dir="D:/vulhub")
        info = manager.startup("httpd/CVE-2021-41773")
        # info = {"target_url": "http://host.docker.internal:8080", "port": 8080, ...}
        manager.teardown("httpd/CVE-2021-41773")
    """

    def __init__(self, vulhub_dir: str = "D:/vulhub"):
        """
        初始化 VulhubManager

        Args:
            vulhub_dir: Vulhub 仓库的本地根目录路径
        """
        # 将路径统一为 Path 对象，支持反斜杠和正斜杠
        self.vulhub_dir = Path(vulhub_dir)

        if not self.vulhub_dir.exists():
            raise FileNotFoundError(
                f"Vulhub 仓库目录不存在: {vulhub_dir}\n"
                "请先执行: git clone --depth 1 https://github.com/vulhub/vulhub.git D:/vulhub"
            )

        log_system_event("[Vulhub] VulhubManager 初始化", {"vulhub_dir": str(self.vulhub_dir)})

    def _get_compose_dir(self, vulhub_path: str) -> Path:
        """
        获取 docker-compose.yml 所在的目录

        Args:
            vulhub_path: Vulhub 靶机路径（如 "httpd/CVE-2021-41773"）

        Returns:
            docker-compose.yml 目录的 Path 对象

        Raises:
            FileNotFoundError: 如果路径不存在或缺少 docker-compose.yml
        """
        # 统一路径分隔符
        normalized = vulhub_path.replace("\\", "/")
        compose_dir = self.vulhub_dir / Path(*normalized.split("/"))

        if not compose_dir.exists():
            raise FileNotFoundError(
                f"Vulhub 漏洞目录不存在: {compose_dir}\n"
                f"请确认路径 '{vulhub_path}' 在 {self.vulhub_dir} 下存在"
            )

        compose_file = compose_dir / "docker-compose.yml"
        if not compose_file.exists():
            # 尝试 docker-compose.yaml（部分环境用 .yaml 后缀）
            compose_file = compose_dir / "docker-compose.yaml"
            if not compose_file.exists():
                raise FileNotFoundError(
                    f"docker-compose.yml 不存在: {compose_dir}"
                )

        return compose_dir

    def parse_ports(self, vulhub_path: str) -> List[int]:
        """
        解析 docker-compose.yml，提取所有宿主机端口映射

        Args:
            vulhub_path: Vulhub 靶机路径

        Returns:
            宿主机端口列表（按 Web 端口优先级排序），如 [8080, 3306]
        """
        compose_dir = self._get_compose_dir(vulhub_path)
        compose_file = compose_dir / "docker-compose.yml"
        if not compose_file.exists():
            compose_file = compose_dir / "docker-compose.yaml"

        with open(compose_file, "r", encoding="utf-8") as f:
            compose_data = yaml.safe_load(f)

        # 遍历所有 service 的 ports 字段
        host_ports = []
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            ports = service_config.get("ports", [])
            for port_mapping in ports:
                # 端口映射格式：
                # "8080:80"  → 字符串
                # 8080       → 整数（直接暴露）
                # {"target": 80, "published": 8080}  → 字典
                host_port = _extract_host_port(port_mapping)
                if host_port and host_port not in host_ports:
                    host_ports.append(host_port)

        # 按 Web 端口优先级排序
        host_ports.sort(key=lambda p: WEB_PORT_PRIORITY.get(p, 999))

        log_system_event(
            "[Vulhub] 解析端口映射",
            {"vulhub_path": vulhub_path, "host_ports": host_ports}
        )

        return host_ports

    def get_primary_port(self, vulhub_path: str) -> int:
        """
        获取靶机的主要 Web 访问端口

        Args:
            vulhub_path: Vulhub 靶机路径

        Returns:
            端口号（优先返回 80/8080 等 Web 端口）
        """
        ports = self.parse_ports(vulhub_path)
        if not ports:
            raise ValueError(f"无法从 {vulhub_path} 的 docker-compose.yml 中提取端口")
        # 返回优先级最高的端口（已排序，第一个最优先）
        return ports[0]

    def read_readme(self, vulhub_path: str, max_length: int = 8000) -> str:
        """
        读取 Vulhub 漏洞的 README.md，提供漏洞背景给 Agent

        Args:
            vulhub_path: Vulhub 靶机路径
            max_length: 最大读取字符数（避免上下文过长）

        Returns:
            README 内容字符串，如果不存在则返回空字符串
        """
        compose_dir = self._get_compose_dir(vulhub_path)
        readme_file = compose_dir / "README.md"

        if not readme_file.exists():
            # 尝试中文文件名
            readme_file = compose_dir / "README.zh-cn.md"

        if readme_file.exists():
            try:
                with open(readme_file, "r", encoding="utf-8") as f:
                    content = f.read()
                # 截取前 max_length 字符，避免过长
                if len(content) > max_length:
                    content = content[:max_length] + "\n...(内容已截断)"
                return content
            except Exception as e:
                log_system_event(f"[Vulhub] 读取 README.md 失败: {e}", level=logging.WARNING)

        return ""

    def startup(self, vulhub_path: str) -> Dict:
        """
        启动 Vulhub 靶机，等待就绪，返回目标信息

        Args:
            vulhub_path: Vulhub 靶机路径（如 "httpd/CVE-2021-41773"）

        Returns:
            靶机信息字典 {
                "target_url": str,      # 完整 URL，如 http://host.docker.internal:8080
                "host": str,            # host.docker.internal
                "port": int,            # 主 Web 端口
                "all_ports": List[int], # 所有暴露端口
                "readme": str,          # 漏洞描述
            }
        """
        compose_dir = self._get_compose_dir(vulhub_path)

        log_system_event(
            "[Vulhub] 🚀 启动靶机",
            {"vulhub_path": vulhub_path, "compose_dir": str(compose_dir)}
        )

        # 执行 docker compose up -d
        # 注意：使用 check=False 手动检查，这样可以在失败时记录完整的 Docker 错误信息
        # （check=True + capture_output=True 会导致 stderr 被静默丢失，难以诊断）
        result = subprocess.run(
            ["docker", "compose", "up", "-d"],
            cwd=str(compose_dir),
            capture_output=True,
            text=True,
            check=False,           # 不自动抛异常，手动判断
            timeout=1200           # 最多等 20 分钟（某些大型镜像如 GitLab 首次拉取极慢）
        )

        if result.returncode != 0:
            # 打印完整的 Docker 错误信息（stdout + stderr），便于诊断具体原因
            docker_stdout = result.stdout.strip()
            docker_stderr = result.stderr.strip()
            docker_error_detail = "\n".join(filter(None, [docker_stdout, docker_stderr]))

            log_system_event(
                "❌ 靶机启动失败",
                {
                    "vulhub_path": vulhub_path,
                    "returncode": result.returncode,
                    # 截取最后 1500 字符，避免日志过长，但保留最关键的尾部错误
                    "docker_error": docker_error_detail[-1500:] if docker_error_detail else "（无输出）"
                },
                level=logging.ERROR
            )
            raise RuntimeError(
                f"启动 Vulhub 靶机失败: {vulhub_path}\n"
                f"Docker 错误信息:\n{docker_error_detail[-500:]}"
            )

        log_system_event("[Vulhub] docker compose up -d 执行成功")

        # 获取端口
        all_ports = self.parse_ports(vulhub_path)
        primary_port = all_ports[0] if all_ports else 80

        target_url = f"http://{DOCKER_HOST_NAME}:{primary_port}"

        # 等待靶机就绪
        log_system_event(
            "[Vulhub] ⏳ 等待靶机就绪",
            {"url": target_url, "timeout": STARTUP_TIMEOUT}
        )

        ready = _wait_for_service(target_url, timeout=STARTUP_TIMEOUT, interval=HEALTH_CHECK_INTERVAL)

        if not ready:
            log_system_event(
                "[Vulhub] ⚠️ 靶机可能未完全就绪（超时），尝试继续",
                level=logging.WARNING
            )

        # 读取漏洞描述
        readme = self.read_readme(vulhub_path)

        info = {
            "target_url": target_url,
            "host": DOCKER_HOST_NAME,
            "port": primary_port,
            "all_ports": all_ports,
            "readme": readme,
            "vulhub_path": vulhub_path,
            "compose_dir": str(compose_dir),
        }

        log_system_event(
            "[Vulhub] ✅ 靶机就绪",
            {
                "target_url": target_url,
                "all_ports": all_ports,
                "readme_length": len(readme),
            }
        )

        return info

    def teardown(self, vulhub_path: str):
        """
        停止并销毁 Vulhub 靶机容器（释放资源）

        Args:
            vulhub_path: Vulhub 靶机路径
        """
        compose_dir = self._get_compose_dir(vulhub_path)

        log_system_event("[Vulhub] 🧹 销毁靶机", {"vulhub_path": vulhub_path})

        result = subprocess.run(
            ["docker", "compose", "down", "-v"],
            cwd=str(compose_dir),
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            log_system_event(
                "[Vulhub] ⚠️ docker compose down 失败（容器可能已停止）",
                {"stderr": result.stderr[:500]},
                level=logging.WARNING
            )
        else:
            log_system_event("[Vulhub] ✅ 靶机已销毁")

    def list_available_envs(self, keyword: str = "") -> List[Dict]:
        """
        列出 Vulhub 仓库中可用的漏洞环境

        Args:
            keyword: 过滤关键词（应用名或 CVE 编号，空字符串表示列出全部）

        Returns:
            漏洞环境信息列表 [{"path": "httpd/CVE-2021-41773", "app": "httpd", "cve": "CVE-2021-41773"}, ...]
        """
        results = []

        for app_dir in sorted(self.vulhub_dir.iterdir()):
            if not app_dir.is_dir() or app_dir.name.startswith("."):
                continue

            for cve_dir in sorted(app_dir.iterdir()):
                if not cve_dir.is_dir():
                    continue

                # 检查是否有 docker-compose.yml
                has_compose = (
                    (cve_dir / "docker-compose.yml").exists() or
                    (cve_dir / "docker-compose.yaml").exists()
                )

                if not has_compose:
                    continue

                path = f"{app_dir.name}/{cve_dir.name}"

                # 关键词过滤
                if keyword and keyword.lower() not in path.lower():
                    continue

                results.append({
                    "path": path,
                    "app": app_dir.name,
                    "cve": cve_dir.name,
                })

        return results


# ==================== 辅助函数 ====================

def _extract_host_port(port_mapping) -> Optional[int]:
    """
    从 docker-compose ports 字段的各种格式中提取宿主机端口

    支持格式：
    - "8080:80"   → 8080
    - 8080        → 8080
    - "8080"      → 8080
    - {"target": 80, "published": 8080}  → 8080
    - "0.0.0.0:8080:80"  → 8080
    """
    try:
        if isinstance(port_mapping, dict):
            # 字典格式
            published = port_mapping.get("published", port_mapping.get("target"))
            if published:
                return int(str(published).split("/")[0])

        elif isinstance(port_mapping, int):
            # 纯整数
            return port_mapping

        elif isinstance(port_mapping, str):
            # 字符串格式，去掉协议（tcp/udp）
            port_str = port_mapping.split("/")[0]

            if ":" in port_str:
                # "8080:80" 或 "0.0.0.0:8080:80"
                parts = port_str.split(":")
                host_part = parts[-2]  # 倒数第二个是宿主机端口
                return int(host_part)
            else:
                return int(port_str)

    except (ValueError, TypeError, IndexError):
        pass

    return None


def _wait_for_service(url: str, timeout: int = 120, interval: int = 5) -> bool:
    """
    等待 HTTP 服务就绪（健康检查）

    Args:
        url: 检查的目标 URL
        timeout: 最大等待时间（秒）
        interval: 每次检查的间隔（秒）

    Returns:
        True 表示服务就绪，False 表示超时
    """
    start_time = time.time()
    attempt = 0

    while time.time() - start_time < timeout:
        attempt += 1
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code in READY_STATUS_CODES:
                log_system_event(
                    "[Vulhub] ✅ 靶机健康检查通过",
                    {
                        "url": url,
                        "status_code": response.status_code,
                        "elapsed": f"{time.time() - start_time:.1f}s",
                        "attempt": attempt,
                    }
                )
                return True
        except requests.RequestException:
            pass

        elapsed = time.time() - start_time
        log_system_event(
            f"[Vulhub] ⏳ 等待靶机就绪... ({elapsed:.0f}s/{timeout}s, 第{attempt}次检查)"
        )
        time.sleep(interval)

    return False


def parse_cve_from_path(vulhub_path: str) -> Tuple[str, str]:
    """
    从 Vulhub 路径解析应用名和 CVE 编号

    Args:
        vulhub_path: 如 "httpd/CVE-2021-41773"

    Returns:
        (app_name, cve_id) 如 ("httpd", "CVE-2021-41773")
        如果不是标准 CVE 格式，cve_id 返回原始目录名
    """
    parts = vulhub_path.replace("\\", "/").split("/")
    if len(parts) >= 2:
        app_name = parts[0]
        cve_id = parts[1]
    elif len(parts) == 1:
        app_name = parts[0]
        cve_id = parts[0]
    else:
        app_name = "unknown"
        cve_id = "unknown"

    return app_name, cve_id
