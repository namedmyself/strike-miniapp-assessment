# skill 上下文与可信度 —— 详细版（C 节原文存档）

> 迁出时间：2026-09-23。SKILL.md 的 C 节已压缩成索引版，**完整原文在这里，内容未删减**。
> SKILL.md 里每条都写明「细节见本文件 §对应条目」。

## ⚠️ 上下文与可信度（v2.13 新增，必读）

> 这一节是踩坑总结，**优先于后面所有 Phase 的具体步骤**。
> 上下文类问题会连锁失败，可信度类问题会让你在错误前提上排查很久。

### A. `select_appservice_context` 失败时的 fallback 流程

**症状**：`connection_ops(action="select_appservice_context")` 返回
`{"ok": false, "error": "未发现 Runtime context..."}`，同时 `get_basic_page_info` 里
`contextCount: 0`、`selectedAppserviceContextId: null`。
连锁影响：`runtime_eval_appservice` 报 `Uncaught`、`hook_wx_request` 报
`wx.request not found`。

**根因**：CDP 是分层的。在浏览器层发 `Runtime.enable` **拿不到**小程序的
`executionContext`，必须先 `Target.attachToTarget(flatten=true)` 到页面 target，
再在**那个 session 里** enable，才会推送 `Runtime.executionContextCreated`。

**标准处置顺序（v2.13 起工具已内置，通常一步就够）**：

```text
1. connection_ops(action="find_appservice")
   → 一步完成：attach 页面 session + enable Runtime + 选 context
   → 返回 mode 字段：
       "runtime_context" = 正常，selectedContextId 可用
       "frames_bridge"   = 回退到 window.__as 桥
       "failed"          = 两者都失败，按 howToFix 逐条排查

2. 若 mode="runtime_context"：直接 runtime_eval_appservice / hook_* 即可，无需额外操作。

3. 若 mode="frames_bridge"：工具已自动改用 page-frame 桥。
   - 桥把 appservice 的 wx / getCurrentPages / getApp / __wxConfig 绑成**局部变量**再执行表达式，
     所以 `runtime_eval_appservice("wx.getStorageSync('token')")` 这类写法仍然可用。
   - **跨 frame 不能 eval**：`__as.eval(...)` 不可用，只能做属性访问与函数调用。
   - 页面切换后 `window.__as` 可能指向旧 frame。工具每次使用前会校验
     `__as.getCurrentPages` 是否仍在，必要时重找；手工拼表达式时请自行校验。

4. 若 mode="failed"：按返回的 howToFix 走：
   - 确认小程序是在 `02-一键启动.bat` **之后**才打开的（hook 只对之后加载的小程序生效）；
   - `connection_ops(action="list_targets")` 看有没有 `type=page` / `role=appservice`；
   - 有 target 但 context 为空 → `connection_ops(action="find_appservice")` 强制重挂；
   - 仍失败 → 重启小程序（微信会重建 WeChatAppEx 进程树），再重跑 `02-一键启动.bat`。
```

> ❌ **不要**照着「`wx is not defined` → 立刻再调一次 select_appservice_context」死循环。
> 那个调用本身失败时，重复调用不会改变结果，只会原地打转。
> 正确动作是**降级到桥**或**按 howToFix 修环境**。

**手工桥（工具不可用时兜底）**：

```javascript
// 在 page-frame 上下文执行（runtime_ops action="runtime_eval"，不要用 appservice 变体）
(function () {
  if (window.__as && typeof window.__as.getCurrentPages === 'function') return 'cached';
  function find(w, d) {
    if (d > 6) return null;
    try { if (typeof w.wx === 'object' && w.wx && typeof w.__wxConfig === 'object' && w.__wxConfig) return w; } catch (e) {}
    var frames = [];
    try { frames = w.frames || []; } catch (e) {}
    for (var i = 0; i < frames.length; i++) {
      try { var r = find(frames[i], d + 1); if (r) return r; } catch (e) {}
    }
    return null;
  }
  var as = find(window, 0);
  if (!as) return 'NOT_FOUND';
  window.__as = as;
  return 'found';
})()
// 之后：window.__as.wx.* / window.__as.getCurrentPages()
```

> ⚠️ **WMPF appservice 的 JS 引擎怪癖**：在 appservice 上下文里，
> **箭头函数体含 `try` 语句**会抛 `SyntaxError: Unexpected token ')'`
> （同一段函数体改成 `(function(){ ... })()` 就正常）。
> 所有要在 appservice 里求值的脚本，一律用**函数表达式**包裹，不要用箭头函数。
> page-frame 是真正的 webview 引擎，不受影响。

### B. Goji / 原生渲染 vs DOM 渲染

微信 PC 端小程序界面默认是 **Goji（原生渲染）**，page-frame 里**没有 DOM**。

| 现象 | 含义 |
|------|------|
| `list_interactive_elements` 返回 `count: 0` | 不是工具坏了，是原生渲染没有 DOM 节点 |
| `get_document_html` 里 `<div>` / `<button>` 计数为 0 | 同上 |
| `safe_click_and_observe` / `input_text_and_observe`（依赖 CSS selector）不可用 | 同上 |

**替代方案**：走运行时调用，不要走 DOM 选择器。

```text
- 点按钮 / 触发交互 → runtime_eval_appservice 直接调页面方法或 wx API
- 看界面到底渲染成什么样 → capture_screenshot（截图是唯一可靠证据）
- 想确认当前页面/数据 → getCurrentPages() / page.data（经 appservice 或桥）
```

### C. `getCurrentPages()` 有 4–7s 读取延迟

`navigateTo` / `reLaunch` 的回调返回 OK，**不代表**页面栈已更新。
立刻读 `getCurrentPages()` 会拿到旧栈，从而把**成功的导航误判成失败**。

```text
正确做法：
1. route_ops(action="navigate_route", ...)            # 跳转
2. runtime_ops(action="wait_route_stable", timeout=12, settle=2.5)
   → 连续 settle 秒内路由不变才算稳定，返回稳定的 route
   → 总耗时不超过 timeout（硬约束，v2.25 起），回显 timeoutSeconds
3. 或者直接用 capture_screenshot 看界面（比读栈更可信）

❌ 错误做法：navigate 之后立刻 getCurrentPages() 判断成败
```

**读路由的统一入口**（v2.25）：`route_ops(action="wait_route_stable")` 与
`runtime_ops(action="get_basic_page_info")` 内部都走**两级降级链** ——
appservice 的 `getCurrentPages()` → page-frame 的 `__routeNavigator.fetchConfigJson()`。

判读返回值：

| 字段 | 含义 |
|------|------|
| `ok` | **是否真的读到了路由**。读不到时 `ok=false` 并带 `error` / `hint` —— **不再假成功** |
| `route` | 路由字符串（`get_basic_page_info` 里在 `snapshot.route`） |
| `routeSource` | 命中哪一源：`appservice` 或 `routeNavigator`（`get_basic_page_info` 另有顶层 `routeReadOk`） |
| `timeoutSeconds` | 本次生效的超时 —— 用来确认参数**真的传进去了** |
| `failures` | 读路由失败的轮次，每轮带 `attempts` 说明是哪一源挂了 |
| `via` | appservice 侧命中**哪条候选**：`globalThis.getCurrentPages` / `window.__as.getCurrentPages`（桥模式）/ `wx.getCurrentPages` / `globalThis.__wxRoute`（**兜底，值可能滞后**，见下） |

> `ok=false` 几乎总是意味着 **appservice context 已失效**（页面切换后常见）。
> 先 `connection_ops(action="select_appservice_context", force=true)` 重建上下文再重试。

> ⚠️ **参数名是 `timeout` / `settle`，不是 `timeout_seconds` / `settle_seconds`。**
> 传错名字**不会报错**，会被静默忽略并落到默认值（`timeout=12`）——
> 拿返回里的 `timeoutSeconds` 核对一下最稳。

> ⚠️ **appservice 里 `window` 是否存在，取决于走哪条路**（2026-09-22 实测）：
>
> | 模式 | `typeof window` | `window.__as.getCurrentPages()` 可用？ |
> |------|-----------------|--------------------------------------|
> | `runtime_context`（`find_appservice` 默认选中） | **不存在** | ❌ 必然失败 |
> | `frames_bridge` | 存在（桥构造） | ✅ 可用 |
>
> 所以「同一条表达式在两个模式下结果不同」是**正常现象**，不是环境坏了。
> 要写跨模式都能跑的脚本，就**别直接摸 `window`** —— 用 `runtime_eval_appservice`
> 让引擎自己选路，再用 `via` 回显确认实际命中哪条。

> ⚠️ **`globalThis.__wxRoute` 的值会滞后**：实测它还是
> `"pages/other/tzs/success"` 时，真实路由已经走到 `"pages/other/tzs/collect"`。
> 它只作**最后兜底**，`via` 会标出来 —— **看到 `via` 含 `__wxRoute` 就不要信任那个路由值**。

### D. 桥活性探针

任何「桥是不是失效了」的怀疑，**先用探针验证，不要先假设失效**。

```text
runtime_ops(action="probe_bridge")
  → 返回 token（形如 LIVE-12345），并在小程序里弹一个 toast
  → 紧接着 capture_screenshot(file_path="tmp/live-check.png")
  → 截图上能看到这个 toast = 桥驱动的是**可见实例**，桥是活的
```

看不到 toast 才说明桥真的断了，此时再走 A 节的 fallback 流程。

### E. 截图取证

截图是原生渲染下最可靠的证据。**数据在 CDP 响应的双层嵌套里**，别记错层级。

```text
# 推荐：工具已拍平返回结构，并支持直接落盘
capture_screenshot(file_path="tmp/evidence.png")
  → 自动挑 type=page 的小程序 target；内部先 Page.enable 再 captureScreenshot
  → 返回 path / bytes / capturedAt；数据在 data（base64）或直接落盘

# 手工路径（工具不可用时）
connection_ops(action="list_targets")        # 取 type=page 且 url 含 appid 的 targetId
cdp_call_target(targetId, "Page.captureScreenshot", {"format": "png"})
  → 返回里 data 就是 base64 PNG（已从 result.result.data 拍平到 data）
  → 同一个 session 里必须先 Page.enable，否则可能拿到 null
```

### F. 可逆动态验证方法论

授权范围内做增改时，按这个顺序，保证「可恢复、可复核」：

```text
1. 先全量备份
   runtime_eval_appservice("(function(){var i=wx.getStorageInfoSync()||{};var o={};var k=i.keys||[];
     for(var n=0;n<k.length;n++){o[k[n]]=wx.getStorageSync(k[n])}return o})()")
   → 落盘保存（tmp/storage_backup.json），后续还原一律**从备份文件读**。

2. 只做写入 / 修改，不做破坏性动作
   - 不删数据、不提交订单、不领取优惠券、不触发支付
   - 不调用会拉起其它小程序的入口

3. 验证后立即还原，并逐项复核
   - 键集合一致 + 每个键的值 diff 为空
   - 凭据类键要重点复核（写坏会导致后续请求 401）

4. 删除只删自己新增的测试键
```

> ❌ **还原时禁止手写字面量**。token 这类长字符串手抄极易漏字符
> （实测漏一位就从 `...aryc` 变成 `...ary`，直接把登录态写坏）。
> 一律从备份文件读原值写回。

### G. 源码审计：匿名脚本污染与检索

**`Runtime.evaluate` 会把每一次求值也注册成一个 script**，包括工具自己注入的那些表达式。
实测某次会话里 149 个 script 中，绝大多数是这类匿名片段（其中一个的源码就是
`list_interactive_elements` 的查询表达式）。这会直接污染 Phase 4：

- `list_scripts` 里真包被淹没；
- `search_in_sources` 会命中我们自己的表达式，产生**误报**；
- 逐个拉源码还会非常慢。

**正确用法**：

```text
debugger_ops(action="list_scripts")
  → summary.byKind 给出分类计数；businessScripts 直接列出业务包（scriptId+url+length）
debugger_ops(action="list_scripts", named_only=true)
  → 只要带 URL 的

debugger_ops(action="search_in_sources", query="AKID", max_results=20)
  → 默认 scope="miniapp"：跳过匿名脚本、宿主 Node、WASM，并按键(URL+长度)去重
  → 返回统计：searchedScripts / skippedAnonymous / skippedNonMiniapp / skippedDuplicate / skippedStale
  → 要连噪声一起搜传 scope="all"；要连匿名片段一起搜传 include_anonymous=true
```

**实测参考**（对 `wx1234567890abcdef` 主包 1.6 MB）：

```text
search_in_sources(query="userToken")
→ 1.06s，命中 https://usr/app-service.js 第 2760 行
→ searched=9  skippedAnonymous=28  skippedNonMiniapp=9  skippedStale=0
```

**两个曾经会让它「静默返回 0」的坑（v2.16 已修）**：

1. **单个失效 scriptId 会中断整次搜索** —— 脚本 id 会随导航/重解析变动，
   遇到 `No script for id: N` 时旧版直接抛错，搜索一无所获。
   现在会自动摘掉失效项、继续搜其余脚本，并在 `skippedStale` 里报数。
2. **同一份包被重复搜** —— 导航后同一 bundle 会以新 scriptId 再出现，
   旧版会重复拉取几 MB；现在按 `URL+长度` 去重（`skippedDuplicate`）。

**`list_scripts` 返回空 / 只有匿名脚本** → 先看 `summary.byKind`：

```text
{ "business": 3, "wechat_runtime": 10, "anonymous": 28, "wasm": 1, "host_node": 8 }
   ↑ 审计目标      ↑ WeChat 运行时   ↑ 工具自身求值   ↑ 宿主 WASM/Node（都无关）
```

> ✅ **不需要重开小程序**：`Debugger.enable` 在**页面 session** 里会重放已解析脚本
> （v2.15 起工具已在页面 session 里 enable）。实测重启 MCP 服务后立刻就能拿到
> `https://usr/app-service.js`（1.6 MB 的业务主包）。
> 如果 `business` 为 0，才需要重开小程序或改用离线包。

**脚本分类**（`kind` 字段，按优先级排在最前的是审计目标）：

| kind | 含义 | 审计时 |
|------|------|--------|
| `business` | `https://usr/*`、`servicewechat.com/<appid>/*` | ✅ 目标 |
| `wechat_runtime` | `*.cachedata`（WAPAdapter / WAService / WAWebview 等） | 通常忽略 |
| `host_node` | `node:internal/*` —— **宿主 Node 的模块**，跟小程序无关 | ❌ 忽略 |
| `wasm` | `wasm://*` | ❌ 忽略 |
| `anonymous` | 无 URL，`Runtime.evaluate` 的临时片段（含工具自身注入） | ❌ 忽略 |

`list_scripts` 还会直接给出 `businessScripts`（scriptId + url + length），拿来就能搜。

**取整篇源码**用 `full=true`（`length<=0` 等价）。以前固定 `length=2000000`，
**超过 2MB 的包会被静默截断**，后半段的硬编码凭据永远搜不到——这是实打实的漏检。

### H. 导航成败怎么判

`navigateTo` / `reLaunch` 的回调返回 OK **不等于**落到了目标页。
以前只看「命令是否发出」，会产生假成功。现在：

```text
route_ops(action="navigate_route", route="pages/web?url=https://example.com")
  → ok            : 只有**真的落到目标页**才为 true
  → landedOnTarget: 同上（显式字段）
  → final_route   : 实际落点
  → hint          : 没落上时解释原因（守卫弹回 / 被重定向到登录页 / 路由未注册）

route_ops(action="navigate_back", delta=1)
  → ok                    : 以**路由是否真的变化**为准
  → moved                 : 同上
  → pageStackDepthBefore  : 回退前页面栈深度（=1 说明在首层，navigateBack 必然失败）
  → hint                  : 未变化时说明原因

route_ops(action="wait_route_stable", timeout=12, settle=2.5)
  → 等路由稳定后再判定，规避 getCurrentPages() 的 4–7s 读取延迟
```

> 比较目标页时只比 **path**：`getCurrentPages()` 返回的 route 不含 query，
> 而调用方传的 target 常带参数（`pages/web?url=...`）。

### I. 断点：怎么下、怎么撤、卡住了怎么办

**断点是全局状态，用完必须撤。** v2.15 之前只能下不能撤，残留断点会让小程序
在你后续操作时莫名其妙卡住（而且是异步卡，很难联想到是断点）。

```text
# 1. 下断点（按 URL 子串匹配 XHR/fetch）
debugger_ops(action="break_on_xhr", url="/api/order/")
  → 返回 activeCount；断点已登记

# 2. 按源码文本下断点（先搜源码，再在命中行下断）
debugger_ops(action="set_breakpoint_on_text", text="aesEncrypt")
  → 返回 breakpointId；命中的是匿名脚本时会拒绝（无法按 URL 下断）

# 3. 触发后看暂停现场
debugger_ops(action="get_paused_info")
  → isPaused: true 时 paused 里有 callFrames，可看作用域变量
debugger_ops(action="resume_execution")   # 未暂停时会明确报错，属正常
debugger_ops(action="step", kind="over")  # over / into / out

# 4. 撤断点（★ 必做）
debugger_ops(action="list_breakpoints")     # 先看还剩什么
debugger_ops(action="remove_breakpoints")   # 默认清全部；也可用 url / breakpoint_id 精确清
```

**小程序卡住了怎么救**：

```text
1. debugger_ops(action="get_paused_info")   # 确认是不是被断点停住了
2. debugger_ops(action="remove_breakpoints")# 清掉所有断点（会同时把断点整体关掉）
3. debugger_ops(action="resume_execution")  # 恢复执行
4. 仍卡住 → route_ops(action="navigate_route", ...) 重开页面；或直接重开小程序
```

> `remove_breakpoints` 会把断点整体关掉（`active: false`）作为兜底；
> 之后再用 `break_on_xhr` 会自动重新启用，不用手动处理。

### J. GraphQL 接口清单与线索定位

GraphQL 小程序（实测某目标 `wx1234567890abcdef`）的**所有业务接口都打同一个端点**，
`method + path` 完全相同，传统的「按路径聚合接口清单」直接失效：

```text
只按 method+path 聚合 → 只剩 2 条
  POST /tracking/analytics/logging/messages
  GET  /v3/                       ← 这一条里藏着几十个业务 operation

按 operation 拆分 → 6 条
  POST /tracking/analytics/logging/messages          count=18
  GET  /v3/  #TripsSecondaryQuery              count=4
  GET  /v3/  #TripsQuery                       count=3
  GET  /v3/  #ReferralQuery             count=2
  GET  /v3/  #HomepageQuery              count=1
  GET  /v3/  #GetUserProfile                     count=1
```

**工具已自动处理**（v2.19），支持三种形态：

| 形态 | 识别来源 |
|------|---------|
| POST + JSON body | `operationName`、`extensions.persistedQuery.sha256Hash`、`id` |
| **GET + URL query 参数**（某目标走这条） | 同上，但注意 `extensions` 是 **JSON 字符串**不是对象 |
| GET + `?query=query Foo{...}` | 从 GraphQL 文档里正则取 operation 名 |

每条请求记录会带上 `isGraphQL` / `graphqlOperation` / `graphqlOperationId` /
`graphqlQueryPreview`，`get_api_inventory` 直接返回 `businessScripts` 式的拆分结果，
并带 `graphqlRequests` 计数。

**线索定位**：`find_*` 与 `analyze_auth_surface` 的每条线索都带
`api`（`GET /v3/ #GetUserProfile`）、`operation`、`operationId`，
配合 SKILL.md「每条漏洞报告必须包含来源路由」的要求，可以直接写出
「哪个 operation + 哪条路由」。

**仍然要人工核对的**：`matched` 字段返回的是**归一后的小写 token**
（如 `identity`），不是原文子串；组合词（`identityVerification`）能命中，
但别拿它做原文比对。看到可疑命中，先用 `get_request_detail` 看原始报文再下结论。

### K. 结果变少了怎么读（噪声过滤与强弱 token）

v2.22 起分析层默认**摘掉埋点**、并把部分字段降为**弱 token**，
所以「接口清单变短 / 某个风险面变 0」**很可能不是没测到，而是噪声被去掉了**。
先看结果里这几个字段再下结论：

| 字段 | 含义 | 怎么处理 |
|------|------|---------|
| `telemetryExcluded` | 被排除的埋点/遥测请求条数（`kind=telemetry`） | 要分析埋点本身（例如查 PII 上报）→ 传 `includeTelemetry=true` 重跑 |
| `weakOnlyCount` / `weakOnlyNote` | 只命中弱 token（`timestamp`/`nonce`）的请求数 | 这类字段在埋点里遍地都是，**不算签名面**；要确认签名得找 `sign`/`hmac`/`encrypt` |
| `credentialOnlyResponses` | 只命中凭据字段（token/cookie）的响应数 | 凭据**预期存在**，不计 finding；敏感面只看 PII |
| `matched` | 命中的**强** token（归一后小写） | 只用于解释「为什么命中」，别做原文比对 |
| `matchedFields` | 命中的**字段路径**（如 `data.node.user.phone`） | 直接拿去定位字段；比 `matched` 精确 |
| `valueLevelMatch` | 该响应不是结构化 JSON，退回全文匹配 | 值里的偶然字串可能误报，**需人工核对** |

**判断「是不是真的没有」的正确顺序**：

1. 看 `byKind` / `telemetryExcluded` —— 流量是不是被过滤掉了；
2. 看 `get_api_inventory` 里的 operation 数 —— 是不是压根没进业务详情页；
3. 用 `includeTelemetry=true` 再跑一遍做对照 —— 埋点里往往藏着 PII 上报；
4. 最后才下「没有」的结论。

> **典型误判**：看到 `find_sign_related_requests: 0` 就以为目标没有签名机制。
> 实际很可能是所有 `timestamp` 命中都来自埋点、被正确摘掉了 ——
> 这时该去看 `get_api_inventory` 里有没有带 `enc` 参数的接口。
>
> **另一个典型误判**：看到 `find_sensitive_data_exposure: 0` 就以为没有敏感信息。
> 先确认三件事：① 流量里有没有进业务详情页（响应体才有 PII）；
> ② 报出来的 `credentialOnlyResponses` 说明只有凭据、没有 PII；
> ③ 用 `includeTelemetry=true` 再跑一遍 —— 埋点 body 里往往有 `userEmail` / `phone` 这类字段。
>
> **怎么验证 `includeTelemetry` 真的生效**：拿 `find_sign_related_requests` 跑两次，
> 不带参数时 `count=0` + `telemetryExcluded=N`；带 `includeTelemetry=true` 时
> `telemetryExcluded` 消失、多出 `weakOnlyCount=N`。两者对得上就说明过滤开关是通的。

### L. 换了小程序怎么办：重跑 `02`

**换目标后直接重跑一次 `05-一键停止.bat` + `02-一键启动.bat`。**

hook 和 CDP 会话都绑在「打开的那个小程序」上，换目标后旧的全部失效。
重跑一遍比手工清会话 / 重注入可靠，也是日常最省事的做法。

> ⚠️ 只重跑 `02` 可能**什么都没做** —— 它检测到 `9421` / `62000` / `49999`
> 已在监听时会打印「已在运行」并跳过启动。**先 `05` 再 `02`**。

**症状识别**：换目标后如果 `find_appservice` 报 `Session with given id not found`，
或者接口清单看着像上一个 App 的（缓存里还是旧流量），都是同一个原因 → 重跑 05 + 02。

**只想手工切 target**（不重启）：

```
connection_ops(action="list_targets")     :: 取 type=page 且 url 含目标 appid 的那个
connection_ops(action="switch_target", targetId="...")
```

#### L.1 CDP 链路卡死：两级症状与恢复（v2.27 起自动处理第一级）

**第一级：`pendingCalls > 0` —— 求值全部超时**

```
症状：任何 runtime_eval 都返回「求值超时（预算 x.xs）」
      connection_ops(status).cdp.pendingCalls > 0（调用发出后收不到响应）
```

**先看 `pendingCalls` 再下结论** —— 这是最容易误判成「工具坏了」的状态。

```text
1. connection_ops(action="status")   # 看 cdp.pendingCalls
2. connection_ops(action="connect_wmpf")   # ★ v2.27 起会自动重建连接并清掉 pending
```

> **v2.27 之前这里是个死胡同**：`connect_wmpf` 只看 `is_connected()` 标志，
> 链路卡住时它仍为真 → 直接 `reused: true` 返回、什么都不做。
> 现在检测到「已连接 + `pendingCalls > 0`」会**自动重建**，返回里带
> `rebuiltBecause: "pending_calls"` / `droppedPendingCalls`。
> 重建后 **`requestCount` 保留**（进程内记录不受影响），但要重新
> `connection_ops(action="find_appservice")` 选一次 context。
> 也可 `connect_wmpf(force=true)` 无条件重建。

**第二级：CDP 完全无响应 —— 需要重建整条链路**

```
症状：连 Browser.getVersion / Target.getTargets 都不回（不是超时预算问题）
      引擎日志 logs/start-engine.log 里刷
      「miniapp client err: ... Wire format was corrupt」
```

根因是 **Frida 注入态失效**（换过小程序、或小程序在注入后被重开/重载），
`miniapp client` 反复 connected/disconnected。**这不是工具缺陷，重启 MCP 也无效**
（引擎是独立进程，`restart_mcp_server.py` 只重启 MCP）。

> ⚠️ **别拿 `status().cdp.connected` 当健康判据** —— 它只反映**本地连接标志**，
> 链路已经死掉时它**仍然是 `true`**（实测：`connected:true` + `pendingCalls:0` + `lastError:""`，
> 但 `list_targets` / `Browser.getVersion` 全部超时）。这跟 N-2 的病根是同一类
> ——「**只信标志、不看实际响应**」。
> **判链路健康，要用一次真实探活调用**（`connection_ops(action="status")` 里的
> `requestCount` 变化，或直接 `list_targets` 看有没有回）。

```text
1. 05-一键停止.bat          # 先停，否则 02 会因端口已监听而跳过
2. 02-一键启动.bat          # 会弹 UAC，需要人工点「是」
3. 重新打开要测的小程序      # ★ hook 只对注入之后加载的小程序生效
```

**⚠️ 一个高风险的触发场景：导航（`reLaunch` / `switchTab`）之后**

实测（v2.27）：链路健康时（冒烟 **63/63**、`plan_route_crawl` 正常返回 143 条路由），
连续两次 `route_ops(action="navigate_route")` 之后，**所有** CDP 调用立刻开始超时
（`inspect_routes` / `find_appservice` / `list_targets` 全挂），
引擎日志刷 `Wire format was corrupt`（22:34:57 后停止写入），
Frida 日志停在注入时刻、再无新行 —— 即**二级故障**。

- **判定方法（别急着怀疑工具）**：直连 `ws://127.0.0.1:62000` 发一次 `Browser.getVersion`，
  若也超时 → 是引擎/注入态问题，**不是工具缺陷**。
- **为什么值得注意**：`plan_route_crawl` 的设计目标就是驱动批量导航。
  如果导航会让注入态失效，那「一条一条导航 + 增量采集」在 Frida-only 模式下**跑不长**。
- **证据强度（如实标注）**：这是 **n=1 的时间相关性**（导航前后立刻对比，链路从全绿到全挂），
  **不足以断定「导航是根因」** —— 也可能是注入态本就濒临失效、导航只是压垮它的最后一下。
  链路恢复后值得复现：健康 → 导航 1 条 → 立刻探活 → 再导航 1 条 → 再探活。
- **实战应对**：**每批导航后主动探活一次**（`connection_ops(action="status")`），
  一旦超时就**转静态侧**继续，不要连着盲试。

> ⚠️ **别在这里死磕**：此时**静态链路完全不受影响** ——
> `decompile_ops(list_opened_applets)` / `decompile` / `search_source` / `read_source`
> 都不依赖 CDP。先去跑 Phase -1 把源码线索捞出来，等链路重建后再补动态验证。

### M. PII 检测：只按字段名判定

`find_sensitive_data_exposure` 按**字段路径**（key）匹配，不看值：

| 字段 | 含义 |
|------|------|
| `matchedFields` | 命中的字段路径，如 `data.userInfo.real_name` / `data.userInfo.address` |
| `credentialFields` | 凭据类字段（`token`/`cookie`/`authorization`）—— 预期存在，**不计 finding** |
| `preview` | 响应体预览；格式明确的 PII（手机号/邮箱/身份证）**自动打码** |
| `valueLevelMatch` | 响应不是结构化 JSON，退回了全文匹配 —— 值里的偶然字串可能误报，需人工核对 |

> **已知限制：只按 key 判 → 多义字段名会漏。**
> 裸 `mobile` 被排除（某目标的 `"mobile":{"device_type":...}` 是设备信息对象而非手机号），
> 代价是 `"mobile":"00000000000"` 这种**真手机号也不报**。
>
> **规避方法**：看 `preview` —— 手机号会被打成 `173***61`，一眼能看出这个接口回了手机号。

### N. 返回值字段速查（**别猜字段名**）

实测踩过两次：按印象写解析代码 → 拿到 `None` → 误以为「工具没返回数据」。
实际字段名如下，**不确定就直接看原始返回**：

```bat
python scripts\wxmcp.py call decompile_ops --args "{\"action\":\"search_source\",\"pattern\":\"/api/\"}" --pretty
```

| 工具 | 关键字段 |
|------|---------|
| `decompile_ops(search_source)` | `scanned_files` / `hit_count` / `truncated` / `hits[]`（每项含 `path` / `line` / `match` / `context`）|
| `decompile_ops(decompile)` | `reused_existing_output` / `packages[]`（每项含 `files_written` / `status` / `coverage`）|
| `route_ops(plan_route_crawl)` | `totals` / `byPackage` / `perBatch` / `estimatedBatches` / `batches[]` / `collect.baseline` |
| `route_ops(wait_route_stable)` | `ok` / `route` / `routeSource` / `timeoutSeconds` / `failures[]` |

> **`hit_count == 0` 不等于搜不到**：先确认 `scanned_files > 0`（扫描确实跑了），
> 再收窄/放宽 pattern。`is_regex` 默认为假 —— 用 `|` 之类的正则语法时**必须显式传 `is_regex: true`**，
> 否则它按字面量匹配、命中 0 条。

### O. 工具可信度注意事项（实测踩过；**先照做，别重复踩**）

> 下面几条**都不是「工具坏了」**，而是会让**结论出错**的坑。修它们要么成本高、
> 要么收益不明显，所以**不改代码，在这里注明** —— 实战时按「怎么补」那列自行补上即可。

| # | 现象（实测） | 为什么会误导 | 怎么补 |
|---|---|---|---|
| **O-1** | `SKILL_GATE` 只在**MCP 进程的第一次**业务工具调用上拦一次 | 门禁状态是**进程级**的（`SkillGate._loaded` / `_pushed` 是模块级单例的实例字段，无会话维度、无重置时机）。MCP 常驻时**只有第一个会话**会被拦，之后每个新会话都直接放行。实测：MCP 进程 22:31 启动，22:56 的会话首个受门禁调用未被拦，整份日志里 `skill_required` 出现 **0 次** | **不要指望被拦**。每次开工第一条命令永远是 `skill_ops(action='guide')`。另：重启 MCP 后第一次跑 `mcp_smoke_test.py` 会因门禁**假红 1 条**（62/63），第二次才 63/63 —— 该假红已在脚本里修掉（Phase 0 前先读 skill） |
| **O-2** | `get_all_requests` 的结果体量**没有上限** | 实测 `excludeStatic=true` + `limit=120` 返回 **109,510 字符**，直接被上层转存成文件，**该次调用等于白跑** | `excludeStatic=true` 是**必传**；`limit` **压到 50 以内**。要看接口面就**用 `analysis_ops(action='get_api_inventory')`**（已去重、已去噪），不要拉全量再自己过滤 |
| **O-3** | `get_request_detail` **只回 3 个请求头**（`Content-Type` / `token` / `cookie`） | **会把人引向「无鉴权」的错误结论**。实测据「`token` 为空」判某接口无鉴权 —— 那次侥幸成立，换成带 `Authorization` 的站点就会**误判** | 判鉴权**必须交叉验证**：① `scan_sensitive_storage` 看 Storage 里到底有没有 `token` 键；② 同站**另一个已知需要登录**的域做对照，要有 `401/402` vs `200` 的**差异**才算证据。**不要只凭请求头为空就下结论** |
| **O-4** | `analyze_auth_surface` 在「站点本身不用 token 头」时**全量**报 `missing_auth_candidate` | 实测 **84/84 全中**，零区分度 —— 它不是漏报，是**全报**，输出直接不可用 | 把它的输出当**线索**，不当**结论**。真正的信号是**同站点内**「有鉴权 vs 无鉴权」的**返回码差异**，这个基线要自己做。**所有 `find_*` 的输出都要人工过一遍**，报告里不能写「工具报了什么就是什么」 |
| **O-5** | `find_appservice` 的 context probe 报的 `route` 可能与真实路由**不一致** | 实测同一次会话：probe 报 `pages/main/xcztabbar`，而 `get_basic_page_info`（`routeSource: appservice`）与 `runtime_eval_appservice('getCurrentPages()')` **都是** `pages/loading/loading`。probe 取到了**别的 frame / 过期值** | 路由以 `get_basic_page_info` 或 `runtime_eval_appservice` 读 `getCurrentPages()` 为准；**两者不一致时不要采信 probe 的值** |

| **O-6** | `get_recent_console` / `navigate_route` 的**返回体量** | `limit` 只控**条数**、不控字节。改前实测：console `limit=5` 返回 **133,024 字符**、`navigate_route` 返回 **95K~102K**（内联了两张完整路由表 + 每个 hook 的完整返回）→ 每次调用都被上层转存成文件，**`landedOnTarget` / `bouncedToLogin` 这些关键字段反而读不到** | 已加护栏：console 有 `maxBytes`（默认 24000）/`maxTextLength`（默认 2000），返回里的 `returned` / `droppedByBytes` / `truncatedFields` 可直接核对；`navigate_route` 默认**只回路由表摘要**，要完整路由表传 `verbose=true`。**看到结果被转存成文件，先想「是不是我在拉全量」，而不是「工具坏了」** |
| **O-7** | 负向鉴权测试会**清掉目标登录态**（实测踩了两次） | 目标把 `wx.request` 全局包装：**任一业务码 401 → `clearUserState()` 清 12 个 key + 跳登录页**。用 `runtime_eval_appservice` 调 `wx.request` 去做「不带 token 探测」，**走的正是被包装的通道** → 触发副作用 | **负向测试只走 `fetch_from_page`** —— 它用 page-frame 的 `fetch`，**不经过应用包装**，拿不到应用那套 401 处理。代价：这类请求不进 `wx.request` 钩子；确实需要钩子记录时再走 `wx.request`，**并且先快照 storage**。**开工前先翻源码确认目标有没有「业务码 401 → 清态」的包装** |
| **O-8** | 登录态被清之后怎么恢复 | 清态清的是 storage 里的 12 个 key。**只把值写回 storage 是不够的** —— 常驻页面（tabBar）实例里的 `data.isLogin` 还是旧值，会把你弹回登录页 | 三步：① 从早期 hook 记录里取回完整 token（`get_hooked_requests` / `get_request_detail` 的 `responseBodyPreview`，注意 `get_response_body` 在资源回收后必失败）；② 写回 storage；③ **`reLaunch` 重建页面实例**（这步不能省）。服务端账号、档案数据、微信账号都不受影响 |
| **O-9** | 同一个「请求数」，几个工具给几个数 | 实测同一时刻：`status.requestCount` 120、`crawl_routes.collect.requestsAfter` 111、`plan_route_crawl.baseline.requestCount` 67、`get_api_inventory.total` 15。⚠️ 其中 **111 vs 120 只是两次调用之间又采到了请求（时间差），不是口径差** | **真正的口径只有三种**：`baseline.requestCount` = **CDP-only 缓存**条数；`status` 与 `crawl_routes.collect` = **合并后的总记录条数**；`get_api_inventory.total` = **去重后的唯一接口数**（**不是请求数**）。写报告**先说口径再给数**（"去重接口 N 个" vs "采集记录 M 条"），**不要跨工具比绝对值** |

> 这一节的边界：**O-1 ~ O-5 按「不改代码、只注明」结案**（复现成本高或收益低）；
> **O-6 的体量护栏已在 2026-09-23 落地**（本节的字段说明是改后的行为）；
> **O-7 / O-8 是行为约定**（通道怎么选、清态怎么恢复），本来就不需要改代码；
> O-9 是口径说明。若哪天某条真的导致了错误结论，再按「能在实战中复现出实际损害」重新评估。

