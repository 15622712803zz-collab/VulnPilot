"""VulnPilot 主程序 - 支持多种运行模式

运行模式：
1. 单目标模式 (-t): 直接指定目标 URL 进行渗透测试
   示例: python main.py -t http://192.168.1.100:8080

2. 评测模式 (-api): 通过 API 获取题目，持续运行
   示例: python main.py -api

评测模式架构：
- 持续运行，不自动退出
- 每 10 分钟定时拉取新题目
- 为每道题创建独立的 Agent 实例（异步并发）
- 动态管理解题任务队列（新题自动加入，完成自动清理）
- ⭐ 失败题目自动重试（角色互换 + 历史记录传承）
- ⭐ 任务完成后动态填充槽位
- 实时汇总得分和进度

模块化设计：
- task_manager.py: 任务生命周期管理
- retry_strategy.py: 重试策略（角色互换）
- challenge_solver.py: 单题解题逻辑
- task_launcher.py: 任务启动器
- scheduler.py: 定时任务和监控
- utils/utils.py: 工具函数
"""
import argparse
import asyncio
import os
import logging
from urllib.parse import urlparse
# Langfuse 已禁用，使用 LangSmith 通过环境变量自动追踪

from vulnpilot.core.singleton import get_config_manager
from vulnpilot.task_manager import ChallengeTaskManager
from vulnpilot.retry_strategy import RetryStrategy
from vulnpilot.common import log_system_event


# ==================== 并发控制 ====================
MAX_CONCURRENT_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", "8"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "4"))  # 4 次重试 = 共 5 次机会（首次 + 4 次重试）


def parse_target_url(target: str) -> dict:
    """
    解析目标 URL，构造虚拟 challenge 对象

    支持格式：
    - http://192.168.1.100:8080
    - https://example.com
    - 192.168.1.100:8080 (默认 http)
    - 192.168.1.100 (默认端口 80)

    Returns:
        虚拟 challenge 字典
    """
    # 如果没有协议前缀，添加 http://
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"

    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    # 构造虚拟 challenge
    challenge = {
        "challenge_code": f"manual_{host}_{port}",
        "difficulty": "unknown",
        "points": 0,
        "hint_viewed": False,
        "solved": False,
        "target_info": {
            "ip": host,  # 保持字段名兼容，实际可能是域名
            "port": [port]
        },
        # 标记为手动模式，跳过 API 调用
        "_manual_mode": True,
        "_target_url": target
    }

    return challenge


async def run_single_target(target: str, max_retries: int = 0):
    """
    单目标模式 - 直接对指定目标进行渗透测试

    Args:
        target: 目标 URL (如 http://192.168.1.100:8080)
        max_retries: 最大重试次数 (默认 0，不重试)
    """
    from vulnpilot.challenge_solver import solve_single_challenge

    # ==================== 0. 配置验证 ====================
    try:
        config_manager = get_config_manager()
        config = config_manager.config
    except Exception as e:
        log_system_event(
            f"❌ 配置加载失败: {str(e)}\n"
            "请确保 .env 文件中包含必需的配置项",
            level=logging.ERROR
        )
        raise

    # ==================== 1. 解析目标 ====================
    challenge = parse_target_url(target)

    log_system_event(
        "=" * 80 + "\n" +
        "🎯 VulnPilot 单目标模式启动\n" +
        "=" * 80
    )
    log_system_event(
        f"[目标信息]",
        {
            "URL": challenge["_target_url"],
            "IP": challenge["target_info"]["ip"],
            "端口": challenge["target_info"]["port"],
            "任务ID": challenge["challenge_code"]
        }
    )

    # ==================== 2. LangSmith 自动追踪 ====================
    # LangSmith 通过环境变量 (LANGCHAIN_TRACING_V2=true) 自动启用
    # 无需显式初始化 handler
    challenge_code = challenge["challenge_code"]
    target_url = challenge["_target_url"]

    # ==================== 3. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
        log_system_event("[✓] 重试策略初始化完成")
    except ValueError as e:
        log_system_event(
            f"❌ 重试策略初始化失败（配置错误）: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 4. 初始化任务管理器 ====================
    task_manager = ChallengeTaskManager(max_retries=max_retries)
    concurrent_semaphore = asyncio.Semaphore(1)  # 单目标模式只需要 1 个并发

    # ==================== 5. 获取 LLM 对 ====================
    main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(0)
    log_system_event(f"[✓] LLM 策略: {strategy_desc}")

    # ==================== 6. 开始渗透测试 ====================
    if max_retries > 0:
        log_system_event(f"[重试] 最大重试次数: {max_retries}")

    log_system_event(
        "\n" + "="*80 + "\n" +
        "🚀 开始渗透测试...\n" +
        "- 按 Ctrl+C 可以中断\n" +
        "="*80
    )

    attempt = 0
    result = None
    attempt_history = []

    try:
        while attempt <= max_retries:
            if attempt > 0:
                log_system_event(f"\n[重试] 第 {attempt}/{max_retries} 次重试...")
                # 角色互换
                main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(attempt)
                log_system_event(f"[✓] LLM 策略: {strategy_desc}")

            result = await solve_single_challenge(
                challenge=challenge,
                main_llm=main_llm,
                advisor_llm=advisor_llm,
                config=config,
                task_manager=task_manager,
                concurrent_semaphore=concurrent_semaphore,
                retry_strategy=retry_strategy,
                attempt_history=attempt_history if attempt > 0 else None,
                strategy_description=strategy_desc
            )

            # 成功则退出循环
            if result.get("success"):
                break

            # 记录本次尝试历史
            attempt_history.append({
                "attempt": attempt + 1,
                "summary": result.get("summary", "未知"),
                "attempts_count": result.get("attempts", 0)
            })

            attempt += 1

        # ==================== 7. 输出结果 ====================
        log_system_event("\n" + "="*80)
        if result and result.get("success"):
            log_system_event(
                f"🎉 渗透测试成功！",
                {
                    "FLAG": result.get("flag", "N/A"),
                    "尝试次数": result.get("attempts", 0),
                    "重试次数": attempt
                }
            )
        else:
            log_system_event(
                f"❌ 渗透测试未成功",
                {
                    "尝试次数": result.get("attempts", 0) if result else 0,
                    "重试次数": attempt,
                    "原因": "未找到 FLAG 或达到最大尝试次数"
                }
            )
        log_system_event("="*80)

    except KeyboardInterrupt:
        log_system_event(
            "\n🛑 收到中断信号，正在退出...",
            level=logging.WARNING
        )
    except Exception as e:
        log_system_event(
            f"❌ 渗透测试异常: {str(e)}",
            level=logging.ERROR
        )
        raise


async def run_api_mode():
    """评测模式 - 通过 API 获取题目，持续运行"""
    # 延迟导入，仅在评测模式使用
    from vulnpilot.task_launcher import start_challenge_task
    from vulnpilot.scheduler import (
        check_and_start_pending_challenges,
        periodic_fetch_challenges,
        status_monitor,
        print_final_status
    )

    # ==================== 0. 配置验证 ====================
    try:
        config_manager = get_config_manager()
        config = config_manager.config
    except Exception as e:
        log_system_event(
            f"❌ 配置加载失败: {str(e)}\n"
            "请确保 .env 文件中包含必需的配置项",
            level=logging.ERROR
        )
        raise

    # ==================== 1. 初始化全局变量 ====================
    concurrent_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    task_manager = ChallengeTaskManager(max_retries=MAX_RETRIES)

    log_system_event(
        f"[并发控制] 最大并发任务数: {MAX_CONCURRENT_TASKS}",
        {"可通过环境变量 MAX_CONCURRENT_TASKS 调整"}
    )
    log_system_event(
        f"[重试策略] 最大重试次数: {MAX_RETRIES}（共 {MAX_RETRIES + 1} 次机会）",
        {"可通过环境变量 MAX_RETRIES 调整"}
    )

    log_system_event(
        "=" * 80 + "\n" +
        "🚀 VulnPilot 评测模式启动\n" +
        "=" * 80
    )

    # ==================== 2. LangSmith 自动追踪 ====================
    # LangSmith 通过环境变量 (LANGCHAIN_TRACING_V2=true) 自动启用
    # 无需显式初始化 handler

    # ==================== 3. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
        log_system_event("[✓] 重试策略初始化完成")
    except ValueError as e:
        log_system_event(
            f"❌ 重试策略初始化失败（配置错误）: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 4. 初始化 API 客户端 ====================
    try:
        from vulnpilot.tools.challenge_api_tools import ChallengeAPIClient
        api_client = ChallengeAPIClient()
        log_system_event("[✓] API 客户端初始化完成")
    except Exception as e:
        log_system_event(
            f"❌ API 客户端初始化失败: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 5. 创建任务启动函数（闭包） ====================
    async def start_task_wrapper(challenge, retry_strategy, config):
        """任务启动包装函数"""
        return await start_challenge_task(
            challenge=challenge,
            retry_strategy=retry_strategy,
            config=config,
            task_manager=task_manager,
            concurrent_semaphore=concurrent_semaphore
        )

    # ⭐ 创建空位回填回调函数（立即重试）
    async def refill_slots_callback():
        """
        任务完成后立即触发的空位回填回调

        作用：
        - 失败任务完成后，立即启动重试或新任务
        - 避免等待 10 分钟的定时任务
        - 提高并发槽位利用率
        """
        log_system_event("[立即回填] 任务完成，触发空位回填...")
        await check_and_start_pending_challenges(
            api_client=api_client,
            task_manager=task_manager,
            retry_strategy=retry_strategy,
            config=config,
            start_task_func=start_task_wrapper,
            max_concurrent_tasks=MAX_CONCURRENT_TASKS
        )

    # ⭐ 设置任务完成回调
    task_manager.set_completion_callback(refill_slots_callback)
    log_system_event("[✓] 已设置立即回填机制（任务完成后自动填充空位）")

    # ==================== 6. 首次拉取题目并启动初始任务 ====================
    log_system_event("[*] 首次拉取题目...")
    await check_and_start_pending_challenges(
        api_client=api_client,
        task_manager=task_manager,
        retry_strategy=retry_strategy,
        config=config,
        start_task_func=start_task_wrapper,
        max_concurrent_tasks=MAX_CONCURRENT_TASKS
    )

    # ==================== 7. 启动后台任务 ====================
    # 定时拉取新题目的任务
    fetch_interval = int(os.getenv("FETCH_INTERVAL_SECONDS", "600"))
    fetch_task = asyncio.create_task(
        periodic_fetch_challenges(
            api_client=api_client,
            task_manager=task_manager,
            retry_strategy=retry_strategy,
            config=config,
            start_task_func=start_task_wrapper,
            max_concurrent_tasks=MAX_CONCURRENT_TASKS,
            interval_seconds=fetch_interval
        )
    )

    # 状态监控任务
    monitor_interval = int(os.getenv("MONITOR_INTERVAL_SECONDS", "300"))
    monitor_task = asyncio.create_task(
        status_monitor(
            task_manager=task_manager,
            interval_seconds=monitor_interval
        )
    )

    log_system_event(
        "[✓] 后台任务启动完成",
        {
            "定时拉取间隔": f"{fetch_interval//60} 分钟",
            "状态监控间隔": f"{monitor_interval//60} 分钟"
        }
    )

    # ==================== 8. 持续运行 ====================
    log_system_event(
        "\n" + "="*80 + "\n" +
        "✅ 系统正在运行中...\n" +
        "- 按 Ctrl+C 可以优雅退出\n" +
        "- 系统会自动拉取新题目并创建解题任务\n" +
        "- 失败的题目会自动重试（角色互换）\n" +
        "- 任务完成后会动态填充槽位\n" +
        "="*80
    )

    try:
        # 等待所有后台任务（无限期运行）
        await asyncio.gather(fetch_task, monitor_task)
    except KeyboardInterrupt:
        log_system_event(
            "\n🛑 收到中断信号，正在优雅退出...",
            level=logging.WARNING
        )

        # 取消后台任务
        fetch_task.cancel()
        monitor_task.cancel()

        # 等待后台任务完成取消
        try:
            await asyncio.gather(fetch_task, monitor_task, return_exceptions=True)
        except Exception:
            pass

        # 打印最终状态
        await print_final_status(task_manager)

        log_system_event("👋 程序已退出")


def main():
    """主入口 - 解析命令行参数并选择运行模式"""
    # ==================== 加载环境变量 ====================
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except:
        pass
    
    # ==================== 自动打开 LangSmith Studio ====================
    # 在项目启动时自动打开浏览器查看流程图
    print("\n[DEBUG] 检查 LangSmith 自动打开配置...")
    langsmith_enabled = os.getenv("LANGSMITH_ENABLED", "false").lower() == "true"
    auto_open = os.getenv("LANGSMITH_AUTO_OPEN_BROWSER", "true").lower() == "true"
    print(f"[DEBUG] LANGSMITH_ENABLED={langsmith_enabled}")
    print(f"[DEBUG] AUTO_OPEN={auto_open}")
    
    if langsmith_enabled and auto_open:
        try:
            import webbrowser
            import threading
            from langsmith import Client
            
            api_key = os.getenv("LANGCHAIN_API_KEY") or os.getenv("LANGSMITH_API_KEY")
            project_name = os.getenv("LANGCHAIN_PROJECT") or os.getenv("LANGSMITH_PROJECT", "vulnpilot")
            
            if api_key and api_key != "lsv2_pt_xxx_REPLACE_WITH_YOUR_KEY":
                def open_browser():
                    try:
                        client = Client(api_key=api_key)
                        # 获取项目信息
                        projects = list(client.list_projects(name=project_name))
                        if projects:
                            project = projects[0]
                            tenant_id = project.tenant_id
                            project_id = project.id
                            # 打开 Runs 页面 - 用户可以点击具体 Run 查看流程图
                            runs_url = f"https://smith.langchain.com/o/{tenant_id}/projects/p/{project_id}?tab=runs"
                            print(f"\n✅ [LangSmith] 正在打开 Runs 页面...")
                            print(f"   提示：点击任意 Run 可查看完整执行流程图")
                            print(f"   URL: {runs_url}\n")
                            webbrowser.open(runs_url)
                        else:
                            print(f"\n[LangSmith] 警告：未找到项目 '{project_name}'")
                    except Exception as e:
                        print(f"\n[LangSmith] 无法打开 Studio: {e}")
                
                # 在后台线程打开浏览器，不阻塞主程序
                threading.Thread(target=open_browser, daemon=True).start()
        except Exception as e:
            print(f"\n[LangSmith] Studio 自动打开失败: {e}")
    
    
    parser = argparse.ArgumentParser(
        description="VulnPilot - AI 驱动的自动化渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 单目标模式 - 直接指定目标进行渗透测试
  python main.py -t http://192.168.1.100:8080
  python main.py -t https://example.com
  python main.py -t 192.168.1.100:8080

  # 单目标模式 + 重试
  python main.py -t http://192.168.1.100:8080 -r 3

  # 评测模式 - 通过 API 获取题目
  python main.py -api
  python main.py --api
        """
    )

    # 互斥参数组
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-t", "--target",
        type=str,
        metavar="URL",
        help="单目标模式: 指定目标 URL (如 http://192.168.1.100:8080)"
    )
    mode_group.add_argument(
        "-api", "--api",
        action="store_true",
        help="评测模式: 通过 API 获取题目，持续运行"
    )
    mode_group.add_argument(
        "-vulhub", "--vulhub",
        type=str,
        metavar="PATH",
        help="Vulhub 模式: 指定 Vulhub 漏洞路径 (如 httpd/CVE-2021-41773)"
    )

    # 可选参数
    parser.add_argument(
        "-r", "--retry",
        type=int,
        default=0,
        metavar="N",
        help="单目标模式/Vulhub 模式: 最大重试次数 (默认 0，不重试)"
    )
    parser.add_argument(
        "--vulhub-dir",
        type=str,
        default="D:/vulhub",
        metavar="DIR",
        help="Vulhub 仓库本地路径 (默认 D:/vulhub)"
    )
    parser.add_argument(
        "--disable-process-notebook",
        action="store_true",
        help="消融实验：关闭过程笔记注入和更新。"
    )
    parser.add_argument(
        "--disable-skills",
        action="store_true",
        help="消融实验：关闭 SKILL.md 知识库按需加载。"
    )

    args = parser.parse_args()

    if args.disable_process_notebook:
        os.environ["ENABLE_PROCESS_NOTEBOOK"] = "false"
    else:
        os.environ.setdefault("ENABLE_PROCESS_NOTEBOOK", "true")

    if args.disable_skills:
        os.environ["ENABLE_SKILLS"] = "false"
    else:
        os.environ.setdefault("ENABLE_SKILLS", "true")

    # 根据参数选择运行模式
    if args.target:
        asyncio.run(run_single_target(args.target, max_retries=args.retry))
    elif args.api:
        asyncio.run(run_api_mode())
    elif args.vulhub:
        asyncio.run(run_vulhub_mode(args.vulhub, vulhub_dir=args.vulhub_dir, max_retries=args.retry))



# ==================== Vulhub 模式（新增，不影响现有逻辑）====================

def parse_vulhub_challenge(vulhub_path: str, vulhub_dir: str = "D:/vulhub") -> dict:
    """
    解析 Vulhub 路径，构造虚拟 challenge 对象（类比现有 parse_target_url）

    Args:
        vulhub_path: Vulhub 漏洞路径（如 "httpd/CVE-2021-41773"）
        vulhub_dir: Vulhub 仓库根目录

    Returns:
        虚拟 challenge 字典，包含 Vulhub 专属字段 _vulhub_mode、_cve_id 等
    """
    from vulnpilot.vulhub_manager import VulhubManager, parse_cve_from_path

    manager = VulhubManager(vulhub_dir=vulhub_dir)

    # 解析 CVE 信息
    app_name, cve_id = parse_cve_from_path(vulhub_path)

    # 启动靶机并获取目标 URL
    vulhub_info = manager.startup(vulhub_path)
    target_url = vulhub_info["target_url"]
    port = vulhub_info["port"]
    readme = vulhub_info["readme"]

    # 构造 challenge 对象（兼容现有 solve_single_challenge 接口）
    challenge = {
        "challenge_code": f"vulhub_{app_name}_{cve_id}",
        "difficulty": "medium",
        "points": 0,
        "hint_viewed": False,
        "solved": False,
        "target_info": {
            "ip": vulhub_info["host"],
            "port": [port]
        },
        # --- 现有字段（兼容）---
        "_manual_mode": True,
        "_target_url": target_url,
        # --- Vulhub 专属字段 ---
        "_vulhub_mode": True,
        "_vulhub_path": vulhub_path,
        "_vulhub_dir": vulhub_dir,
        "_cve_id": cve_id,
        "_app_name": app_name,
        "_readme_content": readme,  # 注入漏洞描述给 Agent
        # 将漏洞描述作为 hint，让 Agent 在初始化时就知道漏洞类型
        "hint_content": f"目标漏洞：{app_name} {cve_id}\n{readme[:500]}" if readme else f"目标漏洞：{app_name} {cve_id}",
        "hint_viewed": True,  # 标记为已查看，让 Agent 优先使用此提示
    }

    return challenge, manager


async def run_vulhub_mode(vulhub_path: str, vulhub_dir: str = "D:/vulhub", max_retries: int = 0):
    """
    Vulhub 模式 - 自动启动靶机、攻击、销毁靶机

    Args:
        vulhub_path: Vulhub 漏洞路径（如 "httpd/CVE-2021-41773"）
        vulhub_dir: Vulhub 仓库根目录
        max_retries: 最大重试次数（默认 0，不重试）
    """
    from vulnpilot.challenge_solver import solve_single_challenge

    # ==================== 0. 配置验证 ====================
    try:
        config_manager = get_config_manager()
        config = config_manager.config
    except Exception as e:
        log_system_event(
            f"❌ 配置加载失败: {str(e)}\n请确保 .env 文件中包含必需的配置项",
            level=logging.ERROR
        )
        raise

    log_system_event(
        "=" * 80 + "\n" +
        "🎯 VulnPilot Vulhub 模式启动\n" +
        "=" * 80
    )
    log_system_event(
        "[Vulhub 目标]",
        {
            "路径": vulhub_path,
            "仓库": vulhub_dir,
        }
    )

    # ==================== 1. 启动靶机 ====================
    manager = None
    try:
        challenge, manager = parse_vulhub_challenge(vulhub_path, vulhub_dir)
    except Exception as e:
        log_system_event(f"❌ 靶机启动失败: {e}", level=logging.ERROR)
        raise

    log_system_event(
        "[Vulhub 靶机]",
        {
            "URL": challenge["_target_url"],
            "CVE": challenge["_cve_id"],
            "应用": challenge["_app_name"],
        }
    )

    # ==================== 2. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
    except ValueError as e:
        log_system_event(f"❌ 重试策略初始化失败: {e}", level=logging.ERROR)
        if manager:
            manager.teardown(vulhub_path)
        raise

    task_manager = ChallengeTaskManager(max_retries=max_retries)
    concurrent_semaphore = asyncio.Semaphore(1)

    # ==================== 3. 开始渗透测试 ====================
    attempt = 0
    result = None
    attempt_history = []

    try:
        while attempt <= max_retries:
            if attempt > 0:
                log_system_event(f"\n[重试] 第 {attempt}/{max_retries} 次重试...")

            main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(attempt)
            log_system_event(f"[✓] LLM 策略: {strategy_desc}")

            result = await solve_single_challenge(
                challenge=challenge,
                main_llm=main_llm,
                advisor_llm=advisor_llm,
                config=config,
                task_manager=task_manager,
                concurrent_semaphore=concurrent_semaphore,
                retry_strategy=retry_strategy,
                attempt_history=attempt_history if attempt > 0 else None,
                strategy_description=strategy_desc
            )

            if result.get("success"):
                break

            attempt_history.append({
                "attempt": attempt + 1,
                "summary": result.get("summary", "未知"),
                "attempts_count": result.get("attempts", 0)
            })
            attempt += 1

        # ==================== 4. 输出结果 ====================
        log_system_event("\n" + "=" * 80)
        if result and result.get("success"):
            log_system_event(
                "🎉 Vulhub 渗透测试成功！",
                {
                    "CVE": challenge["_cve_id"],
                    "FLAG/证据": result.get("flag", "（见上方工具输出）"),
                    "尝试次数": result.get("attempts", 0),
                }
            )
        else:
            log_system_event(
                "❌ Vulhub 渗透测试未成功",
                {
                    "CVE": challenge["_cve_id"],
                    "尝试次数": result.get("attempts", 0) if result else 0,
                    "原因": "未成功利用漏洞或达到最大尝试次数"
                }
            )
        log_system_event("=" * 80)

    except KeyboardInterrupt:
        log_system_event("\n🛑 收到中断信号，正在退出...", level=logging.WARNING)
    except Exception as e:
        log_system_event(f"❌ 渗透测试异常: {e}", level=logging.ERROR)
        raise
    finally:
        # ==================== 5. 销毁靶机（无论成功与否）====================
        if manager:
            try:
                manager.teardown(vulhub_path)
            except Exception as e:
                log_system_event(f"⚠️ 靶机销毁失败（请手动执行 docker compose down）: {e}", level=logging.WARNING)


if __name__ == "__main__":
    main()
