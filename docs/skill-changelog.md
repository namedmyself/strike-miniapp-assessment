# SKILL.md 变更历史（v2.13 – v2.30）

> 本文件由 `e0e1-wx/SKILL.md` 迁出（2026-09-23 减脂）。
> 版本历史对 AI 的执行没有帮助，却占掉 SKILL.md 约 300 行 —— 移到这里，SKILL.md 只留一行指针。

## 本版变更

> **当前版本：v2.27**（完整版本历史见文末「更新记录」）

### v2.27

> 主题：**实战中发现的两个真 bug**（都在「本来能用、卡一下」的路径上）+ 把环境抖动的处置写进文档。
> 两个 bug 都是**实测复现**后才改的，改动都很小。

| 类别 | 变更 |
|------|------|
| **修 `tabbar_pages` 带 `.html`（真 bug）** | 实测某目标 `app-config.json` 的 `tabBar.list[].pagePath` 是 `pages/loading/zjcd.html`，而 `config.pages` 里的路由**不带**后缀。直接比较 → **`isTabBar` 恒为 `false`**（于是 `plan_route_crawl(exclude_tabbar=true)` 一个都没排除），且把该值交给 `switchTab` 会报 `page "xxx.html" is not found`。现在 tabBar 一侧统一去 `.html`，比较与返回值都正确 |
| **修 `connect_wmpf` 恢复路径是死胡同（真 bug）** | 链路卡死时（`pendingCalls > 0`）旧实现只看 `is_connected()` 标志 —— 它仍为真，于是 `reused: true` 直接返回、**什么都不做**。实测后果：只能重启整个 MCP 服务，代价是丢掉已采集流量。现在「已连接 + `pendingCalls > 0`」会**自动重建**并报 `rebuiltBecause`；新增 `force=true` 无条件重建。重建用 `fail_pending=True`（否则堆积的 pending 清不掉，等于没修）|
| **文档：CDP 链路卡死的两级症状与恢复** | 新增 C 节 `L.1`：第一级 `pendingCalls>0`（`connect_wmpf` 自动处理）；第二级 CDP 完全无响应（需 `05` + `02` + 重开小程序）。并写明**此时静态链路不受影响，别死磕** |
| **文档：`### N. 返回值字段速查`** | 实测两次因为**猜字段名**拿到 `None` 而误判「工具没返回」。补上 `search_source` / `decompile` / `plan_route_crawl` / `wait_route_stable` 的真实字段名，并说明 `is_regex` 默认为假 |
| **文档：`byPackage` 的正确读法** | `byPackage` 反映「配置里怎么写」，不等于「有没有分包」。实测某目标有 5 个 wxapkg 分包，但 `subPackages[].pages` 全为空 → `{main: 143}` **是正确的**，别当 bug 改 |
| **修 `connect_wmpf` 独立入口完全不可用（真 bug，v2.27 自身引入、当场发现并修掉）** | 上一版把 `local_app.py` 的 `connect_wmpf` 从「转发 `connection_ops`（返回 `json_text` 字符串）」改成「直接 `return await session.connect_wmpf(...)`（返回 **dict**）」，而该工具签名是 `-> str` → FastMCP 输出校验直接拒绝：`1 validation error for connect_wmpfOutput / Input should be a valid string`。**后果：这个独立工具彻底不可用**，而 `connection_ops(action="connect_wmpf")` 是好的（那条路径本来就 `json_text`）—— 又一次「**同一能力两套入口、只有一套能跑**」。现已 `json_text` 包一层 |
| **修冒烟测试吞掉 Phase 0 失败（真 bug）** | `mcp_smoke_test.py` 的 Phase 0 检查**只 print `[FAIL]`，不计入 `passed/total`、也不影响退出码** → 上面那个 bug 让冒烟照样报「61/61 通过」+ 退出码 0，真实回归就这样溜过去了。现已把 Phase 0 结果并入统计与退出码（只读模式总数 61 → **63**）。离线桩验证 `scripts/verify_smoke_phase_count.py` **11/11**，覆盖 `ok:false` / `isError` / 直接抛异常 三类失败 |
| **修 `plan_route_crawl` 所有路径全挂（真 bug，只有真机有流量时才暴露）** | 真机调用报 `'str' object has no attribute 'get'`，**该工具 100% 不可用**（默认 / `routes=[...]` / `routes=[]` 三条路径全挂）。根因：`self.requests` 是 **dict**（按 requestId 索引），却被直接传给了 `build_api_inventory()` —— 它内部 `for req in requests`，迭代 dict 拿到的是**键（字符串）**。现已改为先 `.values()` 再 `normalize_request()`（`path` 是从 `url` 算出来的，不归一化会得到 `GET None`），并按 `get_api_inventory` 的口径只算 `api`+`telemetry`，baseline 增加 `source`/`note` 标明口径。**⚠️ 这个 bug 离线测试全绿** —— 因为 `self.requests` 为空时循环体不执行，**空状态掩盖了它**；测试桩还把 `requests` 写成了 list（真实是 dict），**桩结构错 = 测了个不存在的会话**。已修正桩并新增第 `[10]` 组「真实结构契约」断言 |

**实测验证**

| 项 | 结果 |
|---|---|
| `tabbar_pages`（修复前 → 修复后） | `['pages/loading/loading.html', ...]` → `['pages/loading/loading', ...]`；`isTabBar=True` 的页从 **0 个** → **4 个** |
| `switchTab("pages/loading/zjcd.html")` | 修复前 `page not found`；不带后缀正常（证明去后缀是**修**不是**破坏**）|
| `connect_wmpf` 卡死时 | 修复前 `reused:true` + 什么都不做；修复后 `rebuiltBecause:"pending_calls"` + `droppedPendingCalls` |
| `scripts/verify_nav_inject.js` | **19 passed / 0 failed**（新增 5 条 tabBar 断言）|
| `scripts/verify_cdp_recovery.py` | **23 passed / 0 failed**（新增）|
| `scripts/verify_smoke_phase_count.py` | **11 passed / 0 failed**（新增，离线桩验证冒烟计数）|
| 真机 `connect_wmpf`（独立工具） | 修复前：pydantic `connect_wmpfOutput` 校验失败；修复后：返回合法 JSON，`connected:true` |
| 真机 `connect_wmpf(force=true)`（两套入口） | `reused:false` / `rebuiltBecause:"force"` / `connectionId` **1 → 2 → 3** |
| `mcp_smoke_test.py` 只读模式总数 | **61 → 63**（Phase 0 的两条现在计入）|
| 真机 `plan_route_crawl`（修复前 → 修复后） | `'str' object has no attribute 'get'`（三条路径全挂）→ `ok:true`，`available:143` / `planned:3` / `tabbarPages:4`，`currentRoute:"pages/loading/loading"` |
| 真机 `plan_route_crawl` 输出的路由 | `pages/loading/loading` / `pages/loading/zjcd` / `pages/loading/zcjd` —— **不带 `.html`**（N-1 修复在真机同时确认）|
| 真机冒烟（链路健康时） | **63 / 63 通过，退出码 0** |

### v2.26

> 主题：**补上「批量路由遍历」的规划原语** —— 解决本次实盘里**直接导致流程被中断**的能力缺口。
> 形态是 **dry-run（只规划、不导航）**：先给一份可复核的分批计划，调用方按批执行。

| 类别 | 变更 |
|------|------|
| **新增 `route_ops(action="plan_route_crawl")`** | 把「N 条路由」变成带预计耗时与断点信息的分批计划。返回 `totals` / `byPackage` / `perBatch` / `estimatedBatches` / `batches[]`（每批含 `resumeFrom`）/ `nextStartFrom` / `collect.baseline`。**不执行任何导航** |
| **为什么需要它** | SKILL.md Phase 1.1 一直要求「逐路由导航 + 采集」，但工具没有对应原语 —— 调用方只能自己拼 `setTimeout` 链 + Bash `sleep 70`。实测**连续 4 次相同的 `sleep 70` 触发上层 Agent 的循环调用检测，整个流程被强制中断**。危险的不是「批量导航」，而是**盲等**：不知道要等多久、也不知道进度 |
| **纯读保证** | 规划过程**零 CDP 求值**（除非显式要求 `exclude_tabbar=true` 才去读一次 tabBar 配置）。验证方式是**把 `runtime_eval` 换成会抛异常的桩**再跑一遍 —— 靠「让它没法作弊」而不是靠读代码 |
| **估算口径显式化** | `estimatedSeconds` 是估算，口径写在返回的 `assumption` 里（`settleMs` + 固定导航开销常数）。导航开销无法离线得知，**不允许当成精确预测** |
| **`routes=[]` 的语义** | 显式传空列表 = 「没有路由要规划」，**不会**退回去读配置（早期用真值判断，空列表会静默走 `inspect_routes` 白打一轮 CDP —— 这是单测当场抓出来的 bug）。想读全量路由表就不要传 `routes` |
| **边界情形显式上报** | 计划为空、被 `max_routes` 截断、`settle_ms` 超过 `deadline_seconds`、跳过分包、tabBar 清单为空 —— 全部进 `warnings`，不静默 |
| **参数夹取** | `settle_ms` ∈ [0, 60000]、`deadline_seconds` ∈ [1, 3600]、`max_routes` ∈ [1, 5000]、`start_from` ≥ 0 —— 传怪值不会把工具搞坏 |

**实测（对「电子科大本科招生」，143 路由）**

| 指标 | 值 |
|------|-----|
| `totals.available` / `planned` | **143 / 143**（与既有实盘统计一致） |
| `totals.tabbarPages` | 4 |
| `perBatch` / `estimatedBatches` | 14 / **11** |
| `estimatedSeconds` | 886.6（约 14.8 分钟） |
| 单批示例 | `{index:0, count:14, estimatedSeconds:86.8, resumeFrom:0}` |

验证：`scripts/verify_route_plan.py` **48 passed / 0 failed**（离线，含「零 CDP」契约断言）；
冒烟 `mcp_smoke_test.py` 新增该用例后 **61/61 通过**。

### v2.25

> 主题：**路由读取统一为多源降级链 + 硬时间契约**，附带修掉几处假阴性与误导性返回值。
> 本次修掉两条 P0：`wait_route_stable` 的**假成功**与 `snapshot.route` 的**恒空**；
> 另修一条同类假阴性 —— `analyze_auth_surface` 把**空 token** 误判为「有认证」，会漏报未授权访问。
> ⚠️ **破坏性变更**：`wait_route_stable` 的 `ok` 不再恒为 `true` —— 读不到路由时返回 `ok=false`（此前是 `ok=true, route=""`，会把成功的导航误判成失败）。

| 类别 | 变更 |
|------|------|
| **路由读取统一** | `current_route()` 从「单点读 `window.__as.getCurrentPages` / `globalThis.__wxRoute`」改为 `read_route_detail()` 的**两级降级链**：appservice 的 `getCurrentPages()` → page-frame 的 `__routeNavigator.fetchConfigJson()`。后者内部有 `detectFrame()` 多候选探测，更耐环境差异 |
| **修掉假成功** | 此前读不到路由时 `current_route()` 用 `except Exception: return ""` **静默吞掉异常**，而 `runtime_eval` 的 CDP 超时是 **15s** —— 于是 appservice context 失效时表现为「当前没有路由」。现在失败**显式上报**：`ok=false` + `error` + `attempts` + `hint` |
| **时间契约** | `wait_route_stable` 此前只在每轮迭代开始时检查 deadline，单次读路由最长可挂 15s —— 实测 `timeout=8` **实跑 15.01s**，`timeout` 形同虚设。现在每次读路由的预算被剩余时间硬约束，**总耗时不超过 `timeout_seconds`**，并回显 `timeoutSeconds` |
| **`snapshot.route` 修复** | 快照 expr 读的 `globalThis.__wxRoute` 在 WMPF 里**不存在**，导致 `get_basic_page_info().snapshot.route` 恒为空串（而同一次返回里的 `routeFromAppservice` 明明有值）。现在 page-frame 侧改走 `__routeNavigator`，取不到时再用降级链结果**回填** |
| **新增诊断字段** | `snapshot.routeSource`、顶层 `routeSource` / `routeReadOk`；`wait_route_stable` 新增 `routeSource` / `timeoutSeconds` / `failures` |
| **`via` 语义修正** | appservice 读路由的 `via` 早期**硬编码**为 `'window.__as.getCurrentPages'`，实测在 `runtime_context` 模式下会**误报** —— 该模式里 appservice 的 `window` 根本不存在，真实命中是 `globalThis.getCurrentPages`。现在 `via` 跟随实际来源动态标注：`globalThis.getCurrentPages` / `window.__as.getCurrentPages`（`frames_bridge`）/ `wx.getCurrentPages` / `globalThis.__wxRoute`（兜底，**值可能滞后**，见下） |
| **`__wxRoute` 兜底有滞后** | 实测 appservice 里 `globalThis.__wxRoute = "pages/other/tzs/success"` 时，真实路由已是 `"pages/other/tzs/collect"`。它只作为**最后兜底**（`getCurrentPages` 全失败才走），且 `via` 会标出来 —— **看到 `via` 含 `__wxRoute` 就不要信任这个路由值** |
| **`routeBefore` 不再误导** | 导航注入脚本的 `reLaunchJson` / `navigateToJson` 等在 `success` 回调里同步读 `getCurrentPages()` —— 但该 API 有 **4–7s 读取延迟**，回调触发时页面栈**还没更新**，读到的必然是**跳转前**的路由。此前字段名 `currentRoute` 会让人误以为是跳转后（实测踩过：拿它当落地页判断，结论全错）。现在回调里改回 `routeBefore`，`currentRoute` 保留同值仅作兼容，并补 `note` 明确指向 `wait_route_stable` |
| **`analyze_auth_surface` 空凭据假阴性** | 判据从「请求里**有**认证字段名」改为「认证字段的**值非空**」。实测未登录小程序普遍带 `{"token": ""}` 这类「字段在、值为空」的形态，旧逻辑判成「有认证」→ **跳过** → 漏报未授权访问（与 P0-1 同类的假阴性）。现在递归判定（深度上限 4，避开 `bool`），离线回归 **5/5** |
| **上下文边界写进描述** | `runtime_ops` 的 docstring 明确两种上下文各自有什么：`runtime_eval` = page-frame（有 `window.__routeNavigator` / DOM，**没有** `getCurrentPages` / `wx`，写了会 `ReferenceError`）；`runtime_eval_appservice` = appservice（有 `getCurrentPages` / `wx`，context 不可用时自动走 `window.__as` 桥）。此前只在文档里说，工具描述没说，误用要现场撞墙才知道 |

### v2.24

> 主题：**补上静态侧起点 —— 反编译**。

| 类别 | 变更 |
|------|------|
| **新增 `decompile_ops`** | 不依赖 CDP 的静态工具组：`list_opened_applets` / `decompile` / `list_files` / `search_source` / `read_source`。复用既有解密 / 解包 / 美化能力，在 MCP 进程内用 `asyncio.to_thread` 同步执行，不引入额外常驻进程 |
| **新增 Phase -1** | 反编译作为评估流程的静态起点，置于 Phase 0 之前；「评估流程总览」「快速决策树」「目录」「MCP 工具完整索引」同步更新 |
| **分包覆盖边界显式化** | `decompile` 返回 `coverage` / `subpackages_missing`。分包按需下载，缺失部分静态分析覆盖不到 —— 不显式报告会导致**静默漏测** |
| **修复 JS 美化缩进** | `code_optimizer/formatter.py`：jsbeautifier 会因输入含 tab 就整体改用 tab 缩进（实测哪怕只有 1 个 tab 字符也触发），导致 100% 行带前导 Tab 且顶层多一级缩进。新增 `normalize_indent_tabs()`，用引号状态机只替换字符串字面量之外的 tab（字符串内的真 tab 保留），输出已与独立工具产物逐字符对齐 |
| **静态与动态的分工写明** | 明确 Phase -1 的静态源码与 Phase 4 `list_scripts` 的运行时脚本不是一回事，避免混用 |

### v2.23

> 主题：**冷启动降级与返回值语义**。
> 换小程序后重跑 `02-一键启动.bat` 即可（见 L 节），所以本次**不加自动恢复逻辑**。

| 类别 | 变更 |
|------|------|
| **冷启动必然降级** | `ensure_page_session` / `switch_target` 缺 `ensure_cdp()` → 冷启动首次报「CDP WebSocket 不可用」并退到 frames 桥，第二次才正常。修复后**一次调用**即 `runtime_context` |
| **`get_response_body` 拍平** | `body` 原来只在 `result.body` 里，按顶层取会拿到空 → 提到顶层，补 `bodyLength`，自动解 base64 |
| **`hooked` 提升到顶层** | `hook_*` 顶层 `ok` 只表示「求值成功」，`wx.request not found` 时也是 `ok:true` → 新增 `promote_eval_value()`。⚠️ 提升必须避开信封键（`ok`/`type`/`value`），否则内层 `value` 覆盖外层会把 `call_runtime_crypto_function` 搞坏 |
| **敏感面 `preview` 打码** | docstring 写着「默认脱敏」但 `preview` 直接塞响应体原文（实测含明文手机号）→ 现在格式明确的 PII 会打码 |
| **不做（改文档）** | 不加 `clear_requests`、不加多 App 缓存检测、不给 `select_appservice_context` 加自动重挂、不给 `runtime_eval` 加 session 兜底 —— 都属于「重开小程序」场景，重跑 02 即可 |

### v2.22

> 主题：**分析层误报与漏报**。用一份 49 条请求的真实会话导出做离线回归，
> 把「风险面全在报假阳性」和「snake_case 字段全漏」两个问题一起修掉。

| 类别 | 变更 |
|------|------|
| **埋点噪声** | 新增 `kind=telemetry`。实测一份 49 条请求的会话里 **28 条**是 `POST /tracking/analytics/logging/messages`，但旧代码把它归为 `api`，于是它进了 `get_api_inventory` 和**所有** `find_*`。现在按路径段识别（`tracking`/`telemetry`/`analytics`/`beacon`/`metrics`/`logging`…），**风险面默认排除**，结果里带 `telemetryExcluded` 计数；需要分析埋点本身（例如查 PII 上报）传 `includeTelemetry=true` |
| **签名面假阳性** | `SIGN_RE` 的 `timestamp` / `nonce` 降为**弱 token**。实测签名面 28/49 命中**全部**来自埋点 body 的 `"context":{"timestamp":…}` —— 根本不是签名。现在只有出现 `sign`/`signature`/`hmac`/`encrypt` 这类强 token 才算签名相关；只命中弱 token 的请求计入 `weakOnlyCount` 并附 `weakOnlyNote` 说明 |
| **认证面** | `AUTH_FIELD_RE` 同样把 `timestamp` / `nonce` / `session` 降为弱 token，避免「只要带了时间戳就算有认证」导致 `analyze_auth_surface` 恒为 0 |
| **PII 与凭据分离** | 新增 `PII_FIELD_RE` / `CREDENTIAL_FIELD_RE`。凭据类字段（`token`/`cookie`/`authorization`）**预期存在** —— 实测 49/49 请求都带 `X-Auth-Token`，算成 finding 会让「敏感信息暴露」恒为 100% 命中、零信息量。现在只有 PII 计 finding，凭据单独放进 `credentialFields` / `credentialOnlyResponses` |
| **多义字段** | 剔除裸 `mobile` 与裸 `identity`：实测命中的是 `"mobile":{"device_type":"microsoft"}`（设备信息对象）和 `hasIdentityBadge` / `identityVerificationTypes`（布尔标记 + 验证方式名列表），都不是 PII。但保留 `mobile-?phone` / `identity-?number` 等明确形态，`identityNumber`（身份证号）仍能命中 |
| **敏感面只匹配字段名** | `find_sensitive_data_exposure` 以前拿 `json.dumps(整个响应)` 匹配，**值里的偶然字串也算命中** —— 实测埋点 body 的 `"logging-id": "user-profile.id-card"` 被误报成「身份证字段」（那是埋点**事件名**）。现在递归提取 JSON **字段路径**再匹配，返回 `matchedFields`（如 `data.node.user.phone`），可直接定位字段；响应不是结构化 JSON 时才退回全文匹配，并带 `valueLevelMatch: true` 标注 |
| **🐛 snake_case 全漏** | `FieldTokenMatcher.normalize()` 只拆 camelCase，**漏了 `_`** —— `bank_account` / `phone_number` / `user_email` / `id_card` / `real_name` / `open_id` / `password_hash` 实测 **10/10 MISS**，而对应 camelCase 全部 HIT。现在 `_` 也归一成 `-`，token 复合词用 `-?` 连接（`open-?id` 同时覆盖 `open_id`/`openId`/`openid`）。离线回归 **44/44** |
| 修复 | `ID_FIELD_RE` 同样补 `_?`，`userId` / `user_id` 都能识别 |

**实测（49 条真实请求；离线回归 + 活环境复验）**

| 指标 | 修复前 | 修复后 |
|------|-------:|-------:|
| `kind` 分布 | `api: 49` | `telemetry: 28` / `api: 21` |
| `get_api_inventory` | 6 条（含埋点） | **5 条**（纯业务） |
| `find_sign_related_requests` | **28**（全假） | **0** |
| `find_sensitive_data_exposure` | 1（`hasIdentityBadge` 假阳性） | **0** |
| `find_idor_candidates` | 4 | **4**（真阳性 `userId` base64 未受影响） |

活环境复验：`find_sign_related_requests` 返回 `count: 0` + `telemetryExcluded: 41`
（真实环境里埋点比离线会话更多）。全量自检 **64/64 通过**。

> **结果变少了不等于没测到**：接口清单变短、签名面变 0 通常正是噪声被摘掉的结果。
> 结果里的 `telemetryExcluded` / `weakOnlyCount` 会明确说明排除了多少。

### v2.21

| 类别 | 变更 |
|------|------|
| **IDOR 检测** | `find_idor_candidates` 之前对 GraphQL 小程序**恒为 0** —— 它只看 query/body 的顶层 key，而 ID 藏在 `variables` 这个 JSON 字符串里。现在会解析 `variables` / `input` / `params` / `data`（URL query 与 body 都查），并把疑似 base64 的值**解一层**：`VXNlcjoxNzcx...` → `User:1771...` |
| IDOR 检测 | 返回 `idFields` / `enumerableIds`（field + 解码后明文），并按 api 标签**去重合并**（实测 25 条重复 → 4 个唯一候选）。实测在某目标上直接报出 `GetUserProfile` / `TripsQuery` 的 `userId` 可枚举 ID |
| 诚实 | 结果为 0 时给出三种可能原因（没进业务详情页 / ID 在请求头 / ID 不可枚举） |

> ⚠️ `enumerableIds` 解出的全局 ID（`User:<数字>`）**优先拿来替换相邻 ID 验证越权** ——
> 这是 IDOR 测试里含金量最高的输入。

### v2.20

| 类别 | 变更 |
|------|------|
| 报告 | `generate_security_notes` 不再只输出占位（「认证面：见 analyze_auth_surface」），**真正把各分析结果内嵌成章节**：接口清单 + 认证面 / IDOR / 敏感信息 / 调试后台 / 上传 / 支付 / 签名，每条带 `api` 标签与命中词 |
| 报告 | `generate_api_table_markdown` 增加 **Operation 列** —— 以前 5 个 GraphQL operation 会渲染成 5 行一模一样的 `/v3/`（实测踩过） |
| 诚实 | 分析结果为 0 时会提示「可能是流量不足或只走了 tab 页」，避免把「没测到」当成「没有」 |

### v2.19

| 类别 | 变更 |
|------|------|
| **接口清单** | **GraphQL operation 提取**。GraphQL 小程序所有业务接口都打同一个端点（实测 `/v3/`），只按 `method+path` 聚合会把几十个 operation 压成一行 —— 实测某目标业务面只剩 2 条，清单等于废掉。现在按 `operationName` / `persistedQuery.sha256Hash` 拆分聚合键，实测 2 → 6 条、5 个 operation 全识别 |
| 接口定位 | 所有 `find_*` 与 `analyze_auth_surface` 的线索都带 `api` / `operation` / `operationId`。新增 `api_label()`：`GET /v3/ #GetUserProfile`。以前线索只有 `requestId` + 裸 url，拿到也不知道是哪个接口 |
| 去噪 | 新增 `request_surface()`：风险匹配只看 method / path / query / 请求体 / 请求头。以前拿 `json.dumps(整条记录)` 匹配，`callStack` / `raw` / `responseHeaders` 里的偶然字串全是命中 |
| 正则 | 新增 `FieldTokenMatcher`：**先把 camelCase 归一成 `-` 分隔的 snake_case，再按严格 `\b` 匹配**。三种写法的取舍（全实测踩过）：纯子串 `bank` 命中 `embankment`；只加词边界漏掉 `bankAccount`；camelCase lookahead 在**全大写头名**上又误报 `X-AIRBNB-CLIENT-DEVICE-REGION` 里的 `DEVICE`。归一化离线回归 **24/24** |
| 修复 | `get_request_detail` 超限时曾把 `request` 从对象变成字符串（**破坏调用方契约**，自己的测试脚本当场崩）→ 现在 `request` 永远是对象，按字段预算截断并返回 `truncatedFields` |

> **`matched` 字段的语义变了**：`FieldTokenMatcher.matched_tokens()` 返回的是**归一后的小写 token**
> （如 `identity`），不再是对应原文的子串。用于解释「为什么命中」仍然成立，但别拿它做原文比对。

### v2.18

| 类别 | 变更 |
|------|------|
| **静默失效参数** | 修掉**系统性缺陷**：工具 schema 里声明了 14 个参数，实现里却是 `del xxx` —— **传了不生效、还不报错**。已全部接上：`excludeStatic` / `waitMs` / `captureBeforeAfter` / `forceSelect` / `limit` / `maxLength` |
| 分析信噪比 | `excludeStatic` 真正生效：请求记录带 `kind`（`api`/`static`/`data_uri`/`document`/`websocket`），`get_recent_requests` 默认只返回接口；**分析层（`get_api_inventory` 与所有 `find_*`）固定只看接口**。实测一份会话里 CDP 缓存 29 条请求，绝大多数是字体/图片/`data:` 内联资源，会把真实接口完全淹没 |
| 观察窗口 | `safe_click_and_observe` / `input_text_and_observe` 的 `waitMs` 生效，并返回 `newRequests`（新增请求明细）。此前观察窗口写死 0.3s / 无等待，**「点了但没观察到请求」经常是假阴性** |
| 输出可控 | `maxLength` 生效：`dump_runtime_snapshot`（可见文本）、`get_request_detail`（大响应体按字段截断而非砍坏 JSON）、`inspect_wx_config`、`search_runtime_keywords`、`inspect_vuex_store`、两个 Markdown 生成器 |
| 质量 | `search_runtime_keywords` 以前只返回**匹配位置**（`{"token":[123,456]}`），拿不到上下文；现在每个命中带 60 字片段 + 来源 + `counts` |
| 质量 | `inspect_vx_store` / `patch_vuex_state` / `inspect_wx_config` 改用 appservice 解析（`window.__as` 桥兜底）—— 之前在 page-frame 求值，`globalThis.$store` 永远是 undefined |
| 诚实 | `restore_vuex_state` 返回 `supported: false` + 手工还原指引，不再假装成功 |

> **接口 vs 静态资源**：判断请求是不是接口看 `kind` 字段。
> 如果 `get_api_inventory` 里出现 `.png` / `.woff` / `data:image`，说明过滤没生效。

### v2.17

| 类别 | 变更 |
|------|------|
| **覆盖面** | **修掉「CDP Network 事件一条都收不到」**：`Network.enable` 原来发在浏览器层，和当初 Runtime/Debugger 同一个病根。表现为 `connection_ops(action="status").requestCount` **恒为 0**，`get_all_requests` 里只有 `wx` 来源——webview 的 fetch/XHR、框架自身请求、**响应体**、WebSocket 帧全部丢失。现在在页面 session 里 enable，实测 `requestCount` 0 → 2，且 `get_response_body` 能取到真实响应体 |

> ⚠️ 两类流量是**互补**的，缺一不可：
> `wx.request` 钩子（source=`wx`）看得到业务 API（原生调用，CDP 看不见）；
> CDP Network（source=`cdp`）看得到 webview 的 fetch/XHR、响应体与 WebSocket。
> 如果 `get_all_requests` 里只有一种 source，说明另一条链路没工作。

### v2.16

| 类别 | 变更 |
|------|------|
| **纠错** | v2.15 文档说「新起服务后必须重开小程序才有脚本清单」——**这是错的**。`Debugger.enable` 在**页面 session** 里会重放已解析脚本；v2.15 补的页面 session enable 本身就把这个问题解决了。实测重启 MCP 服务后立刻能拿到 `https://usr/app-service.js`（1.6 MB） |
| 稳定性 | **修掉「单个失效 scriptId 中断整次搜索」**：脚本 id 随导航变动，旧版遇到 `No script for id` 直接抛错、搜索静默返回 0（这正是"搜不到东西"的真凶）。现在自动摘掉失效项继续搜，并报 `skippedStale` |
| 性能 | 同一份包在导航后会被重新解析（换 scriptId），旧版重复拉取；现在按 `URL+长度` 去重，报 `skippedDuplicate` |
| 信噪比 | 脚本按 `kind` 分类（`business`/`wechat_runtime`/`host_node`/`wasm`/`anonymous`），业务包排最前；`list_scripts` 直接给 `businessScripts`；`search_in_sources` 默认 `scope="miniapp"`，跳过宿主 Node / WASM / devtools 噪声 |
| 说明 | `search_in_sources` 返回完整统计（`searchedScripts`/`skippedAnonymous`/`skippedNonMiniapp`/`skippedDuplicate`/`skippedStale`），一眼看出过滤是否按预期生效 |

### v2.15

| 类别 | 变更 |
|------|------|
| 断点 | `debugger_ops` 新增 **`list_breakpoints` / `remove_breakpoints`**——断点终于**可撤销**了。此前只能下断点、撤不掉，残留断点会让小程序莫名卡死。断点类命令也改到**页面 session** 发送（原来发在浏览器层，不会命中） |
| 断点 | 下断点前自动确保断点处于启用态；`get_paused_info` 返回 `isPaused` 与当前断点登记 |
| 加密 | `discover_runtime_crypto_functions` 改为**递归**扫 `globalThis` / `getApp()` / `getApp().globalData` / `__webpack_require__.c` 模块 exports，不再只看顶层 key；返回 `where` 标明来源 |
| 加密 | `call_runtime_crypto_function` 支持**点分路径**（如 `getApp().globalData.crypto.aesEncrypt`、`webpack[12].exports.sign`），并在路径中断时指出断点位置 |
| 重挂 | `rehook_after_route_navigation` 改为**强制重选** context（导航后旧 context 常已销毁），并补上此前漏掉的 `fetch/XHR` 钩子；context 变化时会显式提示旧记录失效 |
| 路由 | 新增 `page_stack_depth` 读取（`navigate_back` 用它判断是否已在首层） |

### v2.14

| 类别 | 变更 |
|------|------|
| 连接 | **不再需要手动 `connect_wmpf`**：任何依赖 CDP 的工具都会按需自动连接一次；失败返回结构化错误 + 指引 |
| 错误 | 所有工具异常统一兜成 `{ok:false, error, hint}`，不再出现 `Error executing tool xxx: <裸异常>` |
| 源码审计 | `list_scripts` 增加 `summary`（`total`/`withUrl`/`anonymous`），带 URL 的排前面；新增 `named_only`；无脚本时给「重开小程序」指引 |
| 源码审计 | `search_in_sources` 默认**跳过匿名脚本**（含工具自身注入），新增 `include_anonymous`；修掉 >2MB 脚本被**静默截断**导致漏匹配的问题 |
| 性能 | `get_script_source` 加源码缓存（条数+字节双上限），重复检索不再重传整包 |
| 可信度 | `navigate_route` 增加 `landedOnTarget`，`ok` 改为「真的落到目标页」；`navigate_back` 增加 `moved` / `pageStackDepthBefore`，首层回退不再假成功 |
| 路径 | 修掉两处**相对路径**（`nav_inject.js`、`export_session` 落点）随启动方式漂移的问题；`start_mcp_server.py` 现在自己写 pid 文件 |

### v2.13

| 类别 | 变更 |
|------|------|
| 上下文 | `connection_ops` 新增 `find_appservice`：attach 页面 session + enable Runtime + 选 context 一步完成；失败时三级降级（重挂 → frames 桥 → howToFix） |
| 可发现性 | 所有 `*_ops` 的 `action` 加 **enum**；传错返回 `validActions` |
| 可信度 | `get_basic_page_info` 带 `capturedAt` / `ageSeconds` / `freshness`；新增 `wait_route_stable` 处理 `getCurrentPages()` 的 4–7s 延迟 |
| 取证 | 新增 `capture_screenshot`（内部先 `Page.enable`，支持落盘）；`cdp_call_target` 返回拍平，截图数据直接在 `data` |
| 分页 | `get_script_source` 支持 `full=true`，返回 `totalLength` / `nextOffset` / `hasMore` |
| 路由 | `route_ops` 新增 `navigate_back`（回退页面栈） |
| 文档 | 新增「上下文与可信度」一节（fallback 流程 / Goji 渲染 / 延迟 / 探针 / 截图 / 可逆验证）+ 目录 |

> 已知环境怪癖：WMPF appservice 引擎下，**箭头函数体含 `try`** 会抛 `SyntaxError`。
> 在 appservice 里执行的脚本一律用 `(function(){ ... })()`。

> **改完工具后先自检**：`python scripts\mcp_smoke_test.py`（只读矩阵，60 项）
> 或 `--include-mutating`（含可变项，64 项）。它会逐项打印 PASS/FAIL，直接指出哪一层断了。
>
> **另跑一次分析层离线回归**：`python scripts\analysis_regression.py`
> —— 它用会话导出验证「结果对不对」（正则误报/漏报、分类、去噪），
> 这是 `mcp_smoke_test.py` 覆盖不到的：活环境流量每次都不同，没法断言「签名面应该是 0 条」。

---


---

## 更新记录

| 版本 | 日期 | 要点 |
|------|------|------|
| v2.32 | 2026-09-23 | **实测反馈入库收尾**（依据 `实际测试结果反馈.md`，5 项发现中 4 项已由测试会话修入 1.4/2.4.B，本次补齐剩余）：**O-10** search_runtime_keywords 的 TLS 噪音陷阱（判应用层加密只认 scan_source，否则结论反向）+ **1.3 节就地警告**；**O-11** inspect_upload_surface 返回组件图标噪音（判上传点改走 search_source / Hook）。+1,239 字节（189,733 B / 3,846 行）。O-10/O-11 分节读取实测通过，门禁回归全绿 |
| v2.31 | 2026-09-23 | **SKILL.md 减脂 + 位置重排**（master 反馈「用起来比以前更弱了」，以 `初始SKILL.md` 148.7K/3245 行为参照）：250,074 → **185,454 字节**、4,385 → **3,790 行**；⚠️ 54→51、表格行 435→207。① 版本史迁出 → 本文件；② C 节 558 行压成**按症状检索的索引**（原文存 `docs/skill-context-detail.md`，内容未删）；③ 修 4 项 skill 文本缺陷：**S-1** 红线加「非自建资源禁发 PUT/PATCH/DELETE」+ 2.4.A/2.4.B/2.8④ 模板改**只读取证**（OPTIONS 读 Allow 头 + 字段缺失空体 + 不存在的 ID）+ 经验法则 8/48/52 加自建资源限定；**S-2** Phase 1.1/2.1 就地交叉引用 O-7；**S-3** 红线第 1 条改措辞对齐门禁 + 补**开工 Checklist**；**S-4/S-5** 补全两处残缺代码；④ O-1..O-9 与 L.1 提升为 H3 使 `skill_ops(read, section=...)` 可寻址；⑤ T-2 sessionId 漂移注记。回归 11/11 全绿 |
| v2.30 | 2026-09-23 | 按另一轮实测（目标 `wx160895c380445180` 档案服务，188 文件 / 111 请求 / 约 40 接口）报出的工具问题落地 **4 处代码修改 + O-6~O-9 文档**。**① 体量护栏（A-1/A-2）**：`get_recent_console` 此前**零体量护栏**（`limit` 只控条数），实测 `limit=40`→80,940 字符、`limit=5`→133,024 字符；现加 `maxBytes`（默 24000）/`maxTextLength`（默 2000）双护栏 + `returned`/`droppedByBytes`/`truncatedFields` 回显。**实现时自己栽了一跤**：单条异常带 50 个长栈帧时，每帧截到 2000 仍有 50×2000=100K，加上「至少留 1 条」的无条件豁免直接击穿上限（返回体仍 103,265 字符）→ 现对「单条就超上限」退化为截断预览，硬约束对任何输入成立。`navigate_route` 原先内联 `before`/`after` **两张完整路由表** + `rehook` 完整返回（实测 95,411/102,079 字符，关键字段反而读不到）→ 现默认只回摘要，完整版要 `verbose=true`。**② 假阳性（B-3）**：`looks_like_hardcoded_secret` **没有任何 CJK 守卫**，135 字中文业务文案因熵 6.21（阈值 3.0）被判 `possible_hardcoded_secret` → 加 `cjk_char_count` 守卫（≥4 个 CJK 即排除；密钥不可能含 4 个中文，不造成漏报）。**③ IDOR 噪声（B-2）**：`id_fields.extend(variable_fields)` **无过滤**把 JSON payload 全部键名塞进 `idFields`（`isList`/`page`/`size`/`type` 全中）→ 实测 10 条候选 `enumerableIds` 全空。注意**不能拿既有的 `ID_FIELD_RE` 去过滤**（它连 `fileId`/`bizId` 都不认，会把驼峰 ID 全漏掉），故新增 `JSON_ID_FIELD_RE`（认 `*_id`/`*Id`/`*ID`/`uid`/`id`，刻意不认裸小写 `*id` 以免 `paid`/`valid`/`android` 误命中），并把完整键名单列为 `jsonPayloadFields`（不丢线索、不冒充 ID）。**④ 文档**：新增 O-6（体量读法）/ O-7（负向测试走 `fetch_from_page`，别走被包装的 `wx.request`）/ O-8（清态恢复三步，含「只写 storage 不够、必须 `reLaunch` 重建实例」）/ O-9（请求数三种口径对照）。`scripts/verify_response_guards.py` **59/59**（新增，每条同时断言新行为与老锚点未被改坏）|
| v2.29 | 2026-09-22 | **修 R-3：补上批量遍历的「执行」原语 `route_ops(action="crawl_routes")`**。v2.26 只补了 `plan_route_crawl`（**只规划不导航**），调用方仍得自己把导航串起来 —— 实测把 N 条导航塞进**单个 `runtime_eval` 的 `for + await` 循环**里**可靠窗口只有约 3 条**：页面切换会销毁当前 executionContext，循环的 async 续体随之丢失，工具以 `TimeoutError` 结束（而导航**其实已经执行**，返回带 `sideEffectMayHaveApplied`）。也就是说 P2-1 想消除的「脆弱模式」只消掉一半 —— 从「`sleep` 盲等」变成了「eval 循环盲等」。**`crawl_routes` 把循环放在 Python 侧**：每条路由 = 一次**有界**导航求值（`_eval_within`）+ 一次有界读路由，**单条超时/失败只记在该条上、绝不中断整批**；返回逐条 `landed` / `finalRoute` / `newRequests` 与 `totals` / `failures` / `nextStartFrom`（断点续跑），`stoppedReason` 区分 `routes_exhausted` / `max_routes` / `deadline`。`ok` 只表示「批次跑完了」，**不代表每条都落到目标页**（登录态缺失、守卫弹回都是**采集结果**）。**顺带实测抓出并修掉我自己写的一个同源 bug**：`deadline_seconds` 被实现里的 `max(5.0, …)` 下限**静默放大**（传 1 秒实际 5 秒）—— 正是本项目反复踩的「参数被顶掉」，现改为只留防负数地板，并加断言「预算原样回显 + 实际耗时受约束」守住。文档侧：新增 C 节 **O 节「工具可信度注意事项」**（O-1 门禁是进程级一次性、O-2 `get_all_requests` 无体量上限、O-3 `get_request_detail` 头不全会误导鉴权结论、O-4 `analyze_auth_surface` 在无 token 站点全量误报、O-5 `find_appservice` 的 probe route 可能取到过期值）—— **这五条一律不改代码，只在 skill 里注明、实战自行补偿**。`scripts/verify_crawl_routes.py` **68/68**（新增）|
| v2.28 | 2026-09-22 | **修 R-1（根因级）：静态规则扫描器没接到 MCP** —— `content_scanner/RegexContentScanner` + `regex_rules/presets.py`（27 条预设）此前**只挂在 GUI 任务池**（`decompiler/worker_matches.py` ← `runner.py`），无头链路 `decompiler/headless.py` 全文无任何引用 → 静态评估拿不到「一次全量」的接口/凭据面，只能自己写脚本扫（实盘中就是这样，产出过一次一次性 Python 扫描器）。现新增 **`decompile_ops(action="scan_source")`** 复用同一套扫描器与预设，返回「每条规则的命中计数 + 有限样本 + `top_files`」，并显式给出 `rules_without_match`（跑过但没命中）与 `skipped_binary_files`。**关键设计：样本有上限，但 `total_match_count` 是真实总数、不被样本数掩盖**（否则就是 P0-1 那种假阴性）。顺带修真 bug 两条：① 预设「私钥块」用 `[\s\S]{20,}?` 跨行捕获整块，而扫描器是**逐行**匹配 → 该规则**永远命不中**（实测整篇 True / 逐行全 False / 扫描器命中 0），已改为锚 `-----BEGIN ... PRIVATE KEY-----` 头部行；② `mcp_smoke_test.py` 在**每次重启 MCP 后的第一次**必假红 1 条（62/63）—— 因为 SKILL_GATE 是**进程级**一次性，第一个受门禁的调用被拦下，第二次才 63/63；现按 README 的正确客户端顺序在 Phase 0 前先读 `skill_ops(guide)`，重启后首次即 63/63。`scripts/verify_scan_source.py` **39/39**（新增）；真机调用 `scan_source` 实测 7s / 330 文件 / 9 条规则命中 / 返回体 16.8 KB；真机冒烟 **63/63** |
| v2.27 | 2026-09-22 | **实战中实测复现的两个真 bug**（都在「本来能用、卡一下」的路径上）：① `tabbar_pages` 带 `.html` 后缀 → `isTabBar` 恒 `false`、`exclude_tabbar` 一个都没排除、`switchTab("xxx.html")` 报 `page not found`（改 `nav_inject.js` 统一去后缀，`isTabBar=True` 的页 0 → 4 个）；② `connect_wmpf` 恢复路径是死胡同 —— 卡死时旧实现只看 `is_connected()` 标志仍为真，于是 `reused:true` 什么都不做，只能重启整个 MCP（现自动检测 `pendingCalls>0` 并重建，新增 `force=true`；重建必须 `fail_pending=True`，否则 pending 清不掉等于没修）。文档侧：新增 C 节 `L.1`（链路卡死两级症状与恢复）、`### N. 返回值字段速查`、`byPackage` 正确读法。**真机实测又抓出 2 个（v2.27 自身引入/掩盖的）**：③ `local_app.py` 的 `connect_wmpf` 返回 dict 而签名是 `-> str` → 输出校验拒绝，**独立工具彻底不可用**（`connection_ops` 那条路径正常，又一处「两套入口只有一套能跑」）；④ `mcp_smoke_test.py` 的 Phase 0 **只打印不计入统计与退出码** → 上面这个 bug 照样报「61/61 通过」，真实回归溜过（只读模式总数 61 → 63）；⑤ 真机又抓出 **`plan_route_crawl` 全路径不可用**：`self.requests` 是 dict 却被直传 `build_api_inventory()`（内部 `for req in requests` 迭代出字符串键）→ `'str' object has no attribute 'get'`，**离线全绿因为空会话掩盖了它、且测试桩把 requests 写成了 list**（已修正桩 + 新增「真实结构契约」断言组）。`verify_cdp_recovery.py` 23/23；`verify_nav_inject.js` 19/19；`verify_smoke_phase_count.py` 11/11；`verify_route_plan.py` 48 → **54/54**；真机冒烟 **63/63** |
| v2.26 | 2026-09-22 | 新增 `route_ops(action="plan_route_crawl")`：**批量路由遍历的 dry-run 规划原语**（只规划、不导航）。输出 `perBatch`/`estimatedBatches`/`batches[].resumeFrom`/`nextStartFrom`/`collect.baseline`，解决「自己拼 setTimeout + `sleep` 盲等被上层循环检测中断」。纯读、零 CDP 求值；估算口径写入 `assumption`；`routes=[]` 与不传 `routes` 语义分离。`verify_route_plan.py` 48/48；冒烟 61/61 |
| v2.25 | 2026-09-22 | **路由读取统一为多源降级链 + 硬时间契约**。修 3 处假阳性/假阴性：`wait_route_stable` 假成功（timeout 形同虚设，实测 timeout=8 跑 15.01s）、`get_basic_page_info().snapshot.route` 恒空、`analyze_auth_surface` 把空 `token` 判成有认证；`via` 语义修正（跟随真实来源）、`routeBefore` 改名纠正误导、`__wxRoute` 兜底滞后警示。⚠️ 破坏性：`wait_route_stable.ok` 不再恒真 |
| v2.24 | 2026-09-22 | 补静态侧起点：新增 `decompile_ops`（`list_opened_applets`/`decompile`/`list_files`/`search_source`/`read_source`）+ 新增 Phase -1；`decompile` 返回 `coverage`/`subpackages_missing` 显式化分包边界；修 JS 美化缩进（jsbeautifier 见 tab 即整体转 tab） |
| v2.23 | 2026-09-22 | 冷启动一次调用即 `runtime_context`（补 `ensure_cdp()`）；`get_response_body` 拍平到顶层；`hook_*` 的 `hooked` 提升到顶层；敏感面 `preview` 对 PII 打码 |
| v2.22 | 2026-09-22 | 分析层误报与漏报（49 条真实会话离线回归）：新增 `kind=telemetry` 埋点分类、签名面 `timestamp`/`nonce` 降弱 token、PII 与凭据分离、剔除多义字段、敏感面改按字段路径匹配、**修 snake_case 全漏**（`_` 归一为 `-`） |
| v2.21 | 2026-09-22 | `find_idor_candidates` 支持 GraphQL：解析 `variables`/`input`/`params`/`data`，疑似 base64 解一层，按 api 去重合并 |
| v2.20 | 2026-09-22 | `generate_security_notes` 真正内嵌各分析章节；`generate_api_table_markdown` 增加 Operation 列；结果为 0 时给出可能原因 |
| v2.19 | 2026-09-22 | GraphQL operation 提取（按 `operationName`/`sha256Hash` 拆聚合键）；新增 `api_label()`；新增 `request_surface()` 去噪；新增 `FieldTokenMatcher`；修 `get_request_detail` 超限破坏调用方契约 |
| v2.18 | 2026-09-22 | 修系统性缺陷：14 个 schema 声明但实现 `del` 掉的**静默失效参数**全部接上（`excludeStatic`/`waitMs`/`captureBeforeAfter`/`forceSelect`/`limit`/`maxLength`）；请求记录带 `kind`；`search_runtime_keywords` 带上下文片段 |
| v2.17 | 2026-09-22 | 修「CDP Network 事件一条都收不到」：`Network.enable` 改在**页面 session** 发送（原来发在浏览器层，同 Runtime/Debugger 的病根） |
| v2.16 | 2026-09-22 | 纠错 v2.15 的「必须重开小程序」说法（实为错误）；修「单个失效 scriptId 中断整次搜索」；脚本按 `URL+长度` 去重；脚本按 `kind` 分类并默认 `scope="miniapp"` |
| v2.15 | 2026-09-22 | 断点**可撤销**：新增 `list_breakpoints`/`remove_breakpoints`，断点类命令改到页面 session；`discover_runtime_crypto_functions` 改递归扫；`call_runtime_crypto_function` 支持点分路径；`rehook_after_route_navigation` 强制重选 context |
| v2.14 | 2026-09-22 | 不再需要手动 `connect_wmpf`（依赖 CDP 的工具按需自动连接）；所有异常统一兜成 `{ok:false, error, hint}`；`list_scripts` 增加 `summary`；修两处相对路径随启动方式漂移 |
| v2.13 | 2026-09-22 | `connection_ops` 新增 `find_appservice`（attach + enable Runtime + 选 context 一步完成）；所有 `*_ops` 的 `action` 加 enum；`get_basic_page_info` 带 `capturedAt`/`freshness`；新增 `wait_route_stable`；新增 `capture_screenshot`；`route_ops` 新增 `navigate_back` |
| v2.12 | 2026-09-17 | 端口基准按 WMP-pentest-automation 更新：9421=debug server、62000=CDP 代理、49999=MCP Server |
| v2.11 | 2026-05-25 | Phase 1.1 重写路由优先级分级 P0/P1/P2/P3，P0 采集完立即进 Phase 2；经验法则 #3 更新 |
| v2.10 | 2026-05-25 | Phase 0 重写：Step 3 改为注入 nav_inject.js；Phase 1.0 改用 fetchConfigJson()；Phase 1.1 导航改用 reLaunchJson；经验法则 #4 更新 |
| v2.9 | 2026-05-25 | Phase 1.1 新增"空流量路由决策树"（空流量→强制刷新→子页→标记跳过，最多重试 2 次）；静态路由标注格式示例；经验法则 #4 更新 TabBar 切换说明；新增经验法则 #7（空流量路由最多重试 2 次即跳过）|
| v2.7 | 2026-05-25 | Phase 2.8 新增 HTTP 响应码行为变化检测（登录 404→OAuth2迁移 / 上传端点存活检测 / 路径遍历CVE探针 + WAF 418指纹 / REST路由参数枚举行为变化）；场景 16-19 新增；最小可行扫描加入 Phase 2.8；经验法则 44-48 新增（HTTP行为检测）|
| v2.6 | 2026-05-24 | 多 appId 语义修正：同一会话多 appId = 同一评估目标（按认证系分类而非按 appId 分桶）；CHECK-2 速查表新增 enc 参数型 + Authen-Sign 型；CHECK-4 新增多 appId 声明项；最小可行扫描路径更新至 2.2.1 + 2.5.1；Phase 2.5.1 ⑤ 重写 + ⑥ 新增 Authen-Sign 分析；场景 15 重写；经验法则 #43 更新 |
| v2.5 | 2026-05-24 | Phase 0 修正步骤顺序（select_appservice_context 移至第 3 步）；Phase 1.0 新增上下文故障恢复指引；Phase 1.4 新增 cachedata 脚本降级方案；Phase 2.1 新增 500 歧义判断；Phase 2.5.1 新增 5 类专项风险检测（JWT-in-URL / 静态 sign / 双斜杠路径 / enc 绑定模式 / 多 appId）；场景 13-15 新增；经验法则 40-43 新增（上下文错误 / cachedata / JWT-in-URL / 多 appId）|
| v2.4 | 2026-05-24 | Phase 2.2.1 新增路径参数 undefined IDOR 检测与枚举测试模板；场景 12 新增 undefined 路径枚举流程；经验法则 #39 新增 |
| v2.3 | 2026-05-23 | 新增评估流程总览表 + 最小可行扫描提示；修复经验法则 #37 工具名拼写（`runtime_eval` → `runtime_ops`）|
| v2.2 | 2026-05-23 | Phase 2.1/2.2 主动测试改造：认证绕过和 IDOR 用 `runtime_eval`+`fetch` 自动发送请求、绕过 `replay_ops` POST 阻断；IDOR 判据从"看静态分析报告"改为"对比数据差异"；Phase 4.7.2 新增 Gateway 配置结构检测（`accessKey\s*[:"]` 精确匹配 + `gateway.*accessKey`）+ 搜索后 4 步验证流程；经验法则 32-33 更新（AK 格式不够 + 二次验证）、新增 36-38（主动测试）|
| v2.1 | 2026-05-23 | Phase 4.7 源码敏感信息检测：11 类凭据扫描 + 11项执行清单 + 报告模板 + 5 条经验法则 + 检测速查表 |
| v2.0 | 2026-05-23 | 路由标注机制 + 全路由遍历测试 + Phase 4 逆向分析 + 密码学攻击检测 + 经验法则 20→30 条 |
| v1.0 | 2026-05-23 | 初版：渗透 Phase 0-5 + 解密多层流水线 + Vuex 检查 + 20 条经验法则 |

> **关于 v2.13–v2.27 的日期**：这 15 版是同一天（2026-09-22）围绕「工具实战缺陷修复」
> 连续迭代的结果，不是 15 天。表格按版本倒序排列，同日期不代表同日发布。
> 补录这段是因为此前的更新记录**停在 v2.12**，而「本版变更」已到 v2.25 —— 属于文档漂移，
> 会让接手的人无法从更新记录判断当前实际版本。
