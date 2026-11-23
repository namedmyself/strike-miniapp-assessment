"""摘要：实现 SKILL.md 所需 MCP 分组工具的异步会话、采集、分析与报告逻辑。"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import math
import re
import time
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from package.config.defaults import DEFAULT_DEVTOOLS_CDP_PORT
from package.mcp_control.cdp_client import JsonDict, LocalCdpClient
from package.mcp_control.crypto_helpers import (
    auto_detect_encoding,
    decode_payload,
    decrypt_payload,
    detect_ecb_pattern,
    identify_crypto_pattern,
    json_text,
)

DEFAULT_WS_URL = f"ws://127.0.0.1:{DEFAULT_DEVTOOLS_CDP_PORT}"
# 全部加词边界：无边界时 `bank` 会命中 `riverbank`、`uid` 会命中 `liquid`、
# `sign` 会命中 `assignment`、`enc` 会命中 `reference` —— 这类假阳性会淹没真实线索。
class FieldTokenMatcher:
    """按「标识符分段」匹配字段名 token。

    字段名匹配试过四种写法，前三种都不行（都是实测踩出来的）：

    | 写法 | 结果 |
    |------|------|
    | 纯子串 `bank` | 误报：`embankment`、`cost` 里的 `cos`、`device` 里的 `dev` |
    | 只加词边界 `\\bbank\\b` | 漏报：`bankAccount`、`identityVerification` |
    | `\\bbank(?=[A-Z_]\\|\\b)` | 全大写头名又误报：`X-AIRBNB-CLIENT-DEVICE-REGION` 里的 `DEVICE` |
    | camelCase → `-`，**漏了 `_`** | **snake_case 全部漏报**：`bank_account`/`phone_number`/`open_id`/`id_card`/`real_name` 实测 10/10 MISS |

    最终方案：**把 camelCase 与 `_` 统一归一成 `-`，token 里的复合词用 `-?` 连接**。
    归一后 `identityVerification` → `identity-verification`（命中）、
    `bank_account` → `bank-account`（命中）、`embankment` → `embankment`（不命中）、
    `CLIENT-DEVICE-REGION` → 同形（`device` 不命中 `dev`）。
    `-?` 让同一条 token 同时覆盖 `open_id` / `openId` / `openid` 三种写法。

    另区分**强 / 弱 token**：`timestamp` / `nonce` 这类字段在埋点里遍地都是，
    单独出现不足以证明「存在签名」或「存在认证」，只有与强 token 同现才算。
    """

    def __init__(self, tokens: str, *, weak: str = "", extras: str = "") -> None:
        """tokens 是 `|` 分隔的英文 token（复合词用 `-?` 连接）；weak 是弱 token；extras 是额外正则（路径片段 / 中文，不参与归一）。"""
        self._tokens = re.compile(rf"\b(?:{tokens})\b") if tokens else None
        self._weak = re.compile(rf"\b(?:{weak})\b") if weak else None
        self._extras = re.compile(extras) if extras else None

    @staticmethod
    def normalize(text: str) -> str:
        """把 camelCase **与 snake_case** 统一拆成 `-` 分隔并转小写。

        分隔符必须用 `-` 而不是 `_`：正则的 `\\b` 把 `_` 当词字符，
        `bank_account` 里的 `bank` 后面跟着 `_` 就不算边界，会匹配失败（实测踩过）；
        `-` 是非词字符，`\\b` 正常成立。

        ⚠️ v2.19 只拆了 camelCase，**漏了 `_`** —— 导致所有 snake_case 字段名全部漏报：
        `bank_account` / `phone_number` / `user_email` / `id_card` / `real_name` /
        `open_id` / `password_hash` 实测 10/10 MISS，而对应 camelCase 全部 HIT。
        这里补上 `.replace("_", "-")`。
        """
        out = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", str(text))
        return out.replace("_", "-").lower()

    def search(self, text: str) -> re.Match[str] | None:
        """返回首个**强** token 命中（弱 token 不单独触发，未命中再试 extras）。"""
        hit = self._tokens.search(self.normalize(text)) if self._tokens else None
        if hit is not None:
            return hit
        return self._extras.search(str(text)) if self._extras else None

    def matched_tokens(self, text: str) -> list[str]:
        """返回命中的**强** token 列表（用于结果里解释「为什么命中」）。"""
        found: set[str] = set()
        if self._tokens:
            found.update(match.group(0) for match in self._tokens.finditer(self.normalize(text)))
        if self._extras:
            found.update(match.group(0) for match in self._extras.finditer(str(text)))
        return sorted(found)

    def weak_matched_tokens(self, text: str) -> list[str]:
        """返回命中的**弱** token 列表（只用于解释，不触发 finding）。"""
        if not self._weak:
            return []
        return sorted({match.group(0) for match in self._weak.finditer(self.normalize(text))})


# PII：真正构成「敏感信息暴露」的字段（含 openid/unionid 这类可关联到具体用户的标识）。
# 刻意排除**裸** `mobile` / `identity` —— 实测某目标的
# `"mobile": {"device_type": "microsoft", ...}` 是「移动设备信息」对象，
# `hasIdentityBadge` / `identityVerificationTypes` 是布尔标记与验证方式名列表，都不是 PII。
# 但 `identityNumber`（身份证号）这类真 PII 要保留，所以只收窄到明确形态、不整词放开。
PII_FIELD_RE = FieldTokenMatcher(
    "phone|telephone|tel|mobile-?phone|mobile-?no|mobile-?number|cell-?phone|"
    "email|id-?card|identity-?card|identity-?no|identity-?number|identity-?id|identity-?code|"
    "real-?name|address|bank|bank-?account|bank-?card|open-?id|union-?id"
)
# 凭据类字段：**预期存在**（每个请求都带 Authorization / Token）。
# 计入「敏感信息暴露」会让报告恒为 100% 命中、零信息量
# （实测 49/49 全部来自请求头 `X-Auth-Token`），所以单独报告、不计 finding。
CREDENTIAL_FIELD_RE = FieldTokenMatcher(
    "token|access-?token|refresh-?token|cookie|authorization|password|passwd|secret|session-?key"
)
SENSITIVE_FIELD_RE = FieldTokenMatcher(
    "phone|telephone|tel|mobile-?phone|mobile-?no|mobile-?number|cell-?phone|"
    "email|id-?card|identity-?card|identity-?no|identity-?number|identity-?id|identity-?code|"
    "real-?name|address|bank|bank-?account|bank-?card|"
    "open-?id|union-?id|session-?key|token|access-?token|refresh-?token|"
    "cookie|authorization|password|passwd|secret"
)
AUTH_FIELD_RE = FieldTokenMatcher(
    "authorization|token|access-?token|refresh-?token|cookie|"
    "session-?key|session-?id|open-?id|union-?id|user-?id|member-?id|uid|sign|signature|enc",
    weak="timestamp|nonce|session",
)
# `_?` 让同一条 token 覆盖 `userId` / `user_id` 两种写法（原来只认 camelCase）。
ID_FIELD_RE = re.compile(r"(^|\.|_|-)(user_?id|uid|member_?id|account_?id|order_?id|coupon_?id|address_?id|invoice_?id|record_?id|book_?id|id)$", re.I)
# 比 `ID_FIELD_RE` 宽一档，**只用于 JSON payload 的键名**（GraphQL variables / 内联 params）。
# 为什么要单独一条：`ID_FIELD_RE` 只认 `^ . _ -` 分隔后的固定词表，所以 `fileId` / `bizId`
# 这类驼峰漏得掉 —— 当初 `collect_idor_signals` 就是因为漏了驼峰 ID 才把「所有 JSON key」
# 无过滤塞进 `idFields`，结果 `isList` / `page` / `size` / `type` 全混了进来（实测 10 条候选
# `enumerableIds` 全空、全是噪声）。这条正则补上驼峰，同时**刻意不认裸小写 `*id`** ——
# 因为 `paid` / `valid` / `android` 都属于这一类；代价是漏掉「全小写 userid」，实测这种命名很少。
JSON_ID_FIELD_RE = re.compile(r"^[Ii]d$|^uid$|_id$|[a-z0-9]Id$|[A-Z]ID$")
# 格式明确的 PII 模式，**只用于给 `preview` 打码**。
#
# 为什么需要它：`find_sensitive_data_exposure` 的 docstring 写着「默认脱敏」，
# 但 `preview` 以前直接把响应体原文塞进结果 —— 实测里面就有
# `"mobile":"00000000000"` 这样的明文手机号，等于把 PII 又抄进了报告。
#
# 注意这里**不做检测**：字段名匹配只看 key，不拿这些模式去报 finding
# （那会引入新的检测维度）。它们仅用于把已经拿到的东西打码。
PII_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("phone", re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}")),
    ("id_card", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
)


PAYMENT_RE = FieldTokenMatcher("pay|payment|payments|order|orders|trade|refund|refunds|wallet|coupon|coupons|checkout|billing", extras="积分|支付|订单|退款|提现|结算")
UPLOAD_RE = FieldTokenMatcher("upload|uploads|uploading|file|files|image|images|avatar|photo|photos|media|attachment|multipart|oss|cos|s3", extras="/oss|/cos|上传|头像|图片|选图")
DEBUG_ADMIN_RE = FieldTokenMatcher("debug|debugger|test|testing|admin|manage|management|internal|staging|mock|sandbox|dev|devtools|grayscale", extras="后台|管理|调试|测试|灰度")
# 签名面：`timestamp` / `nonce` 降为**弱 token** —— 实测签名面 28/49 命中
# 全部来自埋点 body 的 `"context": {"timestamp": ...}`，根本不是签名。
# 只有出现 `sign` / `hmac` / `encrypt` 这类强 token 才算签名相关。
SIGN_RE = FieldTokenMatcher(
    "sign|signature|signed|signing|hmac|encrypt|encrypted|encryption|authen-?sign",
    weak="timestamp|nonce",
    extras="x-signature",
)
# 必须用绝对路径：MCP 服务进程的工作目录取决于启动方式
# （`02-一键启动.bat` 会把它设成 e0e1-wx，手工 `python e0e1-wx\start_mcp_server.py`
# 则是项目根），相对路径会随启动方式时好时坏。
PACKAGE_DIR = Path(__file__).resolve().parents[1]
ROUTE_NAVIGATOR_JS_PATH = PACKAGE_DIR / "applet_routes" / "nav_inject.js"
LOGIN_ROUTE_RE = re.compile(r"login|auth|passport|signin|register|bind", re.I)

# —— 路由读取 ——
#
# 为什么需要专用超时和降级链：实测（2026-09-22）`wait_route_stable(timeout=8)`
# 实跑 **15.01s** 且 `route: ""`。根因是两个独立缺陷叠加：
#   1. `current_route()` 用 `except Exception: return ""` 吞掉异常 —— 而 `runtime_eval`
#      的 CDP 超时是 **15s**（`timeout_ms=15000`）。appservice context 失效时求值挂满
#      15s，然后被伪装成「当前没有路由」，调用方据此把**成功的导航误判为失败**；
#   2. `wait_route_stable` 只在**每轮迭代开始时**检查 deadline，单次 `current_route()`
#      的耗时完全不受 `timeout_seconds` 约束 —— 于是 `timeout` 参数形同虚设。
# 结论：读路由必须有**自己的短超时**，且失败要**显式上报**，不能静默降级成空串。
ROUTE_READ_TIMEOUT_SECONDS = 2.0
ROUTE_POLL_INTERVAL_SECONDS = 0.5

# —— 路由遍历规划（P2-1）的默认参数与估算口径 ——
#
# 背景：SKILL.md Phase 1.1 要求「逐路由导航 + 采集」，但工具没有对应原语，
# 调用方只能自己拼 `setTimeout` 链 + Bash `sleep 70`。实测**连续 4 次相同的
# `sleep 70` 触发了上层 Agent 的循环调用检测，整个流程被强制中断** ——
# 这是「工具能力缺口传导成上层故障」的典型案例。
#
# 本工具提供**规划**（`plan_route_crawl`，dry-run、不导航）与**执行**（`crawl_routes`，真导航）两个原语。
# 规划：把「143 条路由」变成一份可复核的分批计划；
# 执行：按批真正导航并逐条记录落点与新增请求，**循环在 Python 侧**（见 `crawl_routes` 的 docstring）。
DEFAULT_CRAWL_SETTLE_MS = 5000
DEFAULT_CRAWL_DEADLINE_SECONDS = 90.0
DEFAULT_CRAWL_MAX_ROUTES = 200
# 单次导航求值的时间预算。**必须有界**：页面切换瞬间 executionContext 会被销毁，
# 求值可能不返回 —— 无界等待会让整个批次（乃至整条 CDP 链路）卡死。
DEFAULT_CRAWL_NAV_TIMEOUT_SECONDS = 6.0
# 每条路由除 settle 之外的导航开销（`wx.reLaunch` 往返 + 稳定判定）。
# **这是估算口径，不是实测值** —— 输出里会用 `assumption` 字段明确说明，
# 不允许把它当成精确预测。
CRAWL_NAVIGATION_OVERHEAD_SECONDS = 1.2

# appservice 侧：多候选 `getCurrentPages` + `__wxRoute` 兜底。
# 用 `function(){}` 而非箭头函数 —— WMPF 的 JS 引擎里箭头函数体含 `try`
# 会抛 `SyntaxError: Unexpected token ')'`。
#
# 注意 `gname`：实测 appservice 里 **`window` 并不存在**（`typeof window === 'undefined'`），
# 所以真正命中的通常是 `globalThis.getCurrentPages`。早期版本把 `via` 硬编码成
# `window.__as.getCurrentPages`，会误导排查（2026-09-22 现场对照实测发现），
# 现改为跟随 `g` 的真实来源。
APPSERVICE_ROUTE_EXPR = (
    "(function(){"
    "var out={route:'',via:''};"
    "var g=null,gname='globalThis';"
    "try{if(typeof window!=='undefined'&&window.__as){g=window.__as;gname='window.__as';}}catch(e){}"
    "if(!g){try{g=globalThis;gname='globalThis';}catch(e){}}"
    "var cands=[];"
    "try{if(g&&typeof g.getCurrentPages==='function')"
    "cands.push([gname+'.getCurrentPages',function(){return g.getCurrentPages();}]);}catch(e){}"
    "try{if(typeof getCurrentPages==='function')"
    "cands.push(['getCurrentPages',function(){return getCurrentPages();}]);}catch(e){}"
    "try{if(typeof wx!=='undefined'&&wx&&typeof wx.getCurrentPages==='function')"
    "cands.push(['wx.getCurrentPages',function(){return wx.getCurrentPages();}]);}catch(e){}"
    "for(var i=0;i<cands.length;i++){"
    "try{var p=cands[i][1]()||[];"
    "if(p.length){var pg=p[p.length-1];var r=String((pg&&(pg.route||pg.__route__))||'');"
    "if(r){out.route=r;out.via=cands[i][0];return out;}}}catch(e){}}"
    "try{if(g&&g.__wxRoute){out.route=String(g.__wxRoute);out.via=gname+'.__wxRoute';return out;}}catch(e){}"
    "return out;})()"
)

# page-frame 侧：`__routeNavigator.fetchConfigJson()` 内部有 `detectFrame()`
# 多候选探测（按 wx / __wxConfig / getCurrentPages 打分），比单点取全局更耐环境差异。
NAVIGATOR_ROUTE_EXPR = (
    "(function(){"
    "try{"
    "if(typeof window==='undefined'||!window.__routeNavigator)"
    "return {route:'',via:'',error:'__routeNavigator 未注入'};"
    "if(typeof window.__routeNavigator.fetchConfigJson!=='function')"
    "return {route:'',via:'',error:'fetchConfigJson 不可用'};"
    "var d=JSON.parse(window.__routeNavigator.fetchConfigJson());"
    "return {route:String((d&&d.currentRoute)||''),via:'__routeNavigator.fetchConfigJson'};"
    "}catch(e){return {route:'',via:'',error:String(e)};}})()"
)

# page-frame 快照里的 route 字段。
# 为什么不用 `globalThis.__wxRoute`：实测该全局在 WMPF 里**不存在**，
# 这正是 `dump_runtime_snapshot().snapshot.route` 恒为空串的原因。
PAGE_ROUTE_EXPR = (
    "(function(){"
    "try{"
    "if(typeof window!=='undefined'&&window.__routeNavigator"
    "&&typeof window.__routeNavigator.fetchConfigJson==='function'){"
    "var d=JSON.parse(window.__routeNavigator.fetchConfigJson());"
    "if(d&&d.currentRoute)return String(d.currentRoute);"
    "}"
    "}catch(e){}"
    "try{return String((typeof globalThis!=='undefined'&&globalThis.__wxRoute)||'');}catch(e){}"
    "return '';"
    "})()"
)

SENSITIVE_STORAGE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("oss_cos_s3_credentials", re.compile(r"accessKeyId|secretAccessKey|securityToken|bucket|oss|cos|s3", re.I)),
    ("database_middleware", re.compile(r"mysql|redis|jdbc|mongodb|mongo|postgres|pgsql|sqlserver|rabbitmq|kafka", re.I)),
    ("third_party_service", re.compile(r"appSecret|apiKey|privateKey|clientSecret|client_id|appId.*secret|secret.*appId", re.I)),
    ("payment_credentials", re.compile(r"mchId|mchKey|paySecret|wxPayKey|payKey|paymentSecret", re.I)),
    ("sms_push_credentials", re.compile(r"smsKey|smsSecret|pushSecret|twilioKey|jpush|umeng|aliyunSms", re.I)),
    ("jwt_session", re.compile(r"refreshToken|sessionKey|session_key|jwt|bearer|idToken|accessToken|privateKey|token", re.I)),
    ("hardcoded_password", re.compile(r"password|passwd|pwd", re.I)),
    ("internal_config", re.compile(r"serverUrl|baseUrl|internalHost|adminPassword|intranet|internal|localhost|127\.0\.0\.1|10\.|172\.16|192\.168", re.I)),
)

# —— 结构性敏感值检测 ——
#
# 为什么需要：上面 `SENSITIVE_STORAGE_RULES` 是**纯字面量正则**，只能匹配明文关键词。
# 实测（2026-09-22，某高校招生小程序）踩到两类系统性漏报：
#   1. **JWT 永远是 base64 形态**，编码后既不含 `jwt` 也不含 `token` 字面量
#      —— `jwt_session` 那条规则对真实 JWT **结构性无效**；
#   2. **硬编码密钥**（实测 `jjmData: "Adf123098SSddfdg"`）键名与值都不含
#      `password`/`secret`/`key`，字面量规则无从下手。
# 结果是工具返回 `findings: []`、`count: 0`，而 14 年有效期的 HS256 JWT 和
# 疑似硬编码密钥就躺在它自己返回的 `raw` 字段里 —— 这种假阴性比漏报更危险，
# 因为报告会写「未发现敏感信息」。
# 这里补三条**与字面量无关**的通道：JWT 结构 / base64 递归 / 高熵启发式。

# JWT：`header.payload.signature`，三段均为 base64url。
# 首段固定以 `eyJ` 开头（`{"` 的 base64）；signature 允许为空（`alg=none` 畸形令牌也要抓）。
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"(eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*)"
    r"(?![A-Za-z0-9_\-])"
)

# base64 / base64url 形态：长度足够且字符集干净。
BASE64_LIKE_RE = re.compile(r"^[A-Za-z0-9+/\-_]{20,}={0,2}$")

# 高熵启发式的阈值。
#
# 阈值定在 3.0 而不是直觉上的 3.5：实测真实样本 `Adf123098SSddfdg`
# （16 字符、11 个不同字符）熵只有 **3.25** —— 定 3.5 会把它漏掉，
# 而它正是本次要抓的那个硬编码密钥。降阈值带来的误报由下面几条形状规则兜住。
SECRET_MIN_LEN = 12
SECRET_MAX_LEN = 200
SECRET_MIN_ENTROPY = 3.0

# 排除项：URL / 文件路径 / wxfile / data URI / 常见静态资源名。
# 这些天然含 `:` `/` `.` 等符号、熵也不低（实测
# `wxfile://store/1a0c8ee50cd_1c2.png` 熵就有 3.8+），不排除会把每个图标
# 都报成「疑似密钥」，反而淹没真实线索。
_STORAGE_PATHISH_RE = re.compile(
    r"(://|^data:|^wxfile:|^https?:|^blob:|^wx[a-z0-9]{16}:|"
    r"\.(png|jpe?g|gif|webp|svg|bmp|ico|woff2?|ttf|otf|eot|mp4|mp3|css|js|json|wxml|wxss)$)",
    re.I,
)
# 纯数字不参与熵判定（多为 id / 时间戳）
_STORAGE_PURE_NUM_RE = re.compile(r"^\d+$")
# 纯十六进制且长度是常见摘要长度 → 更可能是 hash / etag，不算密钥
_STORAGE_PURE_HEX_RE = re.compile(r"^[0-9a-f]+$", re.I)
_DIGEST_LENGTHS = frozenset({32, 40, 64, 128})
# 纯字母（无数字无符号）不算密钥 —— 排除 `HelloWorldFoo` 这类驼峰标识符
_STORAGE_PURE_ALPHA_RE = re.compile(r"^[A-Za-z]+$")
# 全小写的 snake_case / kebab-case 标识符不算密钥。
#
# 为什么必须有这条：实测字典数据的键名 `search_show_type` / `oa_notify_read`
# 熵高达 3.5（**比真密钥 `Adf123098SSddfdg` 的 3.25 还高**），
# 仅靠熵阈值根本无法区分。但它们的形状是「全小写 + 下划线分隔」的标识符，
# 而真密钥 `Adf123098SSddfdg` 含大写字母 —— 用形状区分才有效。
_STORAGE_SNAKE_IDENT_RE = re.compile(r"^[a-z][a-z0-9]*([_-][a-z0-9]+)+$")

# CJK 守卫：中文业务文案的熵误报。
# 中文以「字」为单位、常用字重复率低 → 香农熵天然很高（实测 135 字中文文案 **6.21**，
# 而真密钥阈值只要 **3.0**），所以不先判 CJK 就会把中文文案判成 `possible_hardcoded_secret`。
# 密钥/口令里不可能出现 4 个以上 CJK 字符，所以这条守卫**不会导致漏报**。
# 范围含中日韩统一表意文字 + 扩展 A + 中文标点/全角区（覆盖「，。：（）」这类全角标点）。
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3000-\u303f\uff00-\uffef]")
CJK_SECRET_MAX_CHARS = 4


def shannon_entropy(text: str) -> float:
    """计算字符串的香农熵（bit/字符），用于识别随机生成的密钥。"""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def charset_class_count(text: str) -> int:
    """统计字符集类别数（小写/大写/数字/符号），用于过滤低多样性字符串。"""
    classes = 0
    if re.search(r"[a-z]", text):
        classes += 1
    if re.search(r"[A-Z]", text):
        classes += 1
    if re.search(r"\d", text):
        classes += 1
    if re.search(r"[^A-Za-z0-9]", text):
        classes += 1
    return classes


def cjk_char_count(text: str) -> int:
    """统计 CJK 字符数（含中文标点与全角字符）。"""
    return len(_CJK_RE.findall(str(text or "")))


def looks_like_hardcoded_secret(text: Any) -> bool:
    """高熵启发式：判断裸字符串是否像硬编码密钥/口令。

    实测锚点（全部来自 2026-09-22 那次真实评估）：

    | 样本 | 期望 | 靠哪条规则 |
    |------|------|-----------|
    | `Adf123098SSddfdg`（`jjmData`） | **命中** | 熵 3.25、含大写+数字、非 snake_case |
    | `omEG45HbNADHJY5j0NTwTfSb5cek`（openId） | 形状上像，但由调用方按 PII 路径抑制 | 见 `classify_sensitive_storage_source` |
    | `wxfile://store/1a0c8ee50cd_1c2.png` | 不命中 | 路径形态 |
    | `1ebb927375304fd1bb67163d5eaa356e` | 不命中 | 32 位纯 hex（摘要长度） |
    | `1790077453712602847` | 不命中 | 纯数字 |
    | `search_show_type`（字典键名） | 不命中 | **snake_case 标识符**（熵 3.5，比真密钥还高，只能靠形状排除） |
    | `2023-01-09 00:00:00` | 不命中 | 熵 2.21 < 3.0 |
    | **135 字中文业务文案**（`businessProcessInfo`） | **不命中** | **CJK 守卫**（实测熵 6.21，中文文案熵天然偏高） |
    """
    value = str(text or "").strip()
    if not (SECRET_MIN_LEN <= len(value) <= SECRET_MAX_LEN):
        return False
    # CJK 守卫必须放在熵判定**之前**：中文的熵一定过阈值，先判熵必然误报。
    if cjk_char_count(value) >= CJK_SECRET_MAX_CHARS:
        return False
    if _STORAGE_PATHISH_RE.search(value):
        return False
    if _STORAGE_PURE_NUM_RE.match(value):
        return False
    if _STORAGE_PURE_HEX_RE.match(value) and len(value) in _DIGEST_LENGTHS:
        return False
    if _STORAGE_PURE_ALPHA_RE.match(value):
        return False
    if _STORAGE_SNAKE_IDENT_RE.match(value):
        return False
    if charset_class_count(value) < 2:
        return False
    return shannon_entropy(value) >= SECRET_MIN_ENTROPY


def decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """只读解码 JWT 的 header/payload，返回可复核的结论；解析失败返回 None。

    **不校验签名**。目的是把「一串看不出所以然的 base64」变成
    「HS256 / exp=2040-07-10 / username=omEG...」这样能直接写进报告的证据。
    """
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None

    def _decode(segment: str) -> Any:
        if not segment:
            return None
        try:
            raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            return json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001 - 解不开就当它不是 JWT
            return None

    header = _decode(parts[0])
    payload = _decode(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None

    claims: dict[str, Any] = {
        "alg": header.get("alg"),
        "typ": header.get("typ"),
        "hasSignature": bool(parts[2]),
        "claimKeys": sorted(str(k) for k in payload),
    }
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp > 0:
        exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
        claims["exp"] = exp_dt.isoformat()
        claims["expiresInDays"] = int((exp_dt - datetime.datetime.now(datetime.timezone.utc)).days)
    # payload 里的用户标识（各系统叫法不一，都收一下）
    for field in ("username", "userName", "sub", "openId", "openid", "unionId", "userId"):
        if payload.get(field) not in (None, ""):
            claims[field] = payload[field]
    return claims


def try_base64_decode(text: Any) -> str | None:
    """尝试把 base64/base64url 字符串解一层，返回可打印文本；失败返回 None。"""
    value = str(text or "").strip()
    if not BASE64_LIKE_RE.match(value):
        return None
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(value + "=" * (-len(value) % 4))
            decoded = raw.decode("utf-8")
        except Exception:  # noqa: BLE001
            continue
        # 只接受「看起来是文本」的结果，避免二进制垃圾污染扫描
        printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
        if decoded and printable / len(decoded) > 0.9:
            return decoded
    return None


def mask_jwt_claims(claims: dict[str, Any] | None) -> dict[str, Any] | None:
    """把 JWT claims 里的用户标识打码后再放进 finding。

    踩过的坑：`valuePreview` 已经脱敏了，但 `jwtClaims.username` 把 openId
    **原样**带了出来 —— 等于脱敏白做，明文又抄进了报告。
    实测断言 `完整 openId 未出现在 findings` 就是为了钉住这一点。
    """
    if not claims:
        return claims
    masked = dict(claims)
    for field in ("username", "userName", "sub", "openId", "openid", "unionId", "userId"):
        value = masked.get(field)
        if isinstance(value, str) and value:
            masked[field] = f"{value[:4]}***{value[-2:]}" if len(value) > 6 else "***"
    return masked


def iter_string_leaves(
    value: Any,
    prefix: str = "",
    *,
    max_leaves: int = 1500,
) -> list[tuple[str, str]]:
    """递归取出容器里的所有字符串叶子，返回 (路径, 值) 列表。

    高熵启发式只应作用于**叶子字符串**，不能对整个 JSON 文本算熵
    （那样任何 dict 的熵都够高，会全量误报）。

    `max_leaves` 是必需的护栏：实测 storage 里 `dictList` 单键就有 19 万字符、
    `lqxxDict` 12 万字符，全量遍历既慢又只会产出噪音。
    """
    leaves: list[tuple[str, str]] = []
    if isinstance(value, str):
        leaves.append((prefix or "$", value))
    elif isinstance(value, dict):
        for key, item in value.items():
            leaves.extend(iter_string_leaves(item, f"{prefix}.{key}" if prefix else str(key), max_leaves=max_leaves))
            if len(leaves) >= max_leaves:
                break
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            leaves.extend(iter_string_leaves(item, f"{prefix}[{index}]", max_leaves=max_leaves))
            if len(leaves) >= max_leaves:
                break
    return leaves[:max_leaves]


UPLOAD_SURFACE_RE = re.compile(r"upload|chooseImage|chooseMedia|avatar|file|media|photo|image|上传|头像|选择图片|图片|文件", re.I)

# WMPF appservice 的 JS 引擎对「箭头函数体里含 try 语句」会抛
# `SyntaxError: Unexpected token ')'`（实测：同一段函数体，箭头形式失败、函数表达式成功）。
# 因此所有要在 appservice 里求值的脚本，一律用函数表达式 `(function(){ ... })()` 包裹。
# page-frame 是真正的 webview 引擎，不受影响。
APPSERVICE_SCRIPT_PREFIX = "(function(){"
APPSERVICE_SCRIPT_SUFFIX = "})()"

# —— 各组 *_ops 的合法 action ——
# 单一事实来源：既用于 MCP inputSchema 的 enum，也用于「未知 action」错误信息，
# 避免合法值只存在于中文散文描述里、调用方只能盲试。
CONNECTION_ACTIONS: tuple[str, ...] = (
    "status",
    "connect_wmpf",
    "select_appservice_context",
    "find_appservice",
    "list_targets",
    "switch_target",
    "cdp_call",
    "cdp_call_target",
)
NETWORK_ACTIONS: tuple[str, ...] = (
    "network_enable",
    "install_early_hooks",
    "hook_wx_request",
    "hook_upload_apis",
    "hook_fetch_and_xhr",
    "fetch_from_page",
    "upload_formdata_from_page",
    "get_all_requests",
    "get_recent_requests",
    "get_request_detail",
    "get_response_body",
    "get_recent_console",
    "get_hooked_requests",
    "search_runtime_keywords",
    "trace_request_callstack",
    "inspect_wx_config",
)
RUNTIME_ACTIONS: tuple[str, ...] = (
    "runtime_eval",
    "runtime_eval_appservice",
    "probe_bridge",
    "wait_route_stable",
    "dump_runtime_snapshot",
    "get_basic_page_info",
    "scan_sensitive_storage",
    "inspect_upload_surface",
    "get_document_html",
    "query_selector_text",
    "inspect_window_keys",
    "search_global_string",
    "inspect_vuex_store",
    "patch_vuex_state",
    "restore_vuex_state",
    "list_interactive_elements",
    "safe_click_and_observe",
    "input_text_and_observe",
)
DEBUGGER_ACTIONS: tuple[str, ...] = (
    "list_scripts",
    "get_script_source",
    "save_script_source",
    "search_in_sources",
    "evaluate_script",
    "break_on_xhr",
    "set_breakpoint_on_text",
    "list_breakpoints",
    "remove_breakpoints",
    "get_paused_info",
    "resume_execution",
    "step",
    "get_websocket_messages",
)
ROUTE_ACTIONS: tuple[str, ...] = (
    "inspect_routes",
    "enable_redirect_guard",
    "disable_redirect_guard",
    "navigate_route",
    "navigate_route_with_guard",
    "navigate_back",
    "back",
    "go_back",
    "wait_route_stable",
    "plan_route_crawl",
    "crawl_routes",
)
ANALYSIS_ACTIONS: tuple[str, ...] = (
    "get_api_inventory",
    "analyze_auth_surface",
    "find_idor_candidates",
    "find_sensitive_data_exposure",
    "find_upload_surfaces",
    "find_payment_and_order_surfaces",
    "find_debug_admin_surfaces",
    "find_sign_related_requests",
    "build_replay_plan",
    "compare_two_requests",
    "passive_param_fuzz_suggestions",
    "generate_security_notes",
    "generate_api_table_markdown",
    "export_session",
)
DECRYPT_ACTIONS: tuple[str, ...] = (
    "auto_detect_encoding",
    "decode_payload",
    "decode_base64",
    "decrypt_payload",
    "run_decrypt_pipeline",
    "detect_ecb_pattern",
    "discover_runtime_crypto_functions",
    "call_runtime_crypto_function",
)
REVERSE_ACTIONS: tuple[str, ...] = ("identify_crypto_pattern", "match_reverse_cases", "detect_reverse_strategy")
REPLAY_ACTIONS: tuple[str, ...] = ("start_auto_replay", "get_replay_job")
PENTEST_ACTIONS: tuple[str, ...] = ("start_pentest_scan", "get_pentest_job", "list_pentest_jobs")


def now_iso() -> str:
    """返回当前本地时间 ISO 字符串。"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def safe_json_loads(value: Any) -> Any:
    """尽量把字符串解析为 JSON，失败时返回原值。"""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def compact_text(value: Any, limit: int = 2000) -> str:
    """把任意值压缩成限定长度的预览文本。"""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def parse_url_query(url: str) -> dict[str, Any]:
    """解析 URL 查询参数为普通字典。"""
    return {key: values[-1] if values else "" for key, values in parse_qs(urlparse(str(url or "")).query).items()}


def classify_script_url(url: str) -> str:
    """给脚本 URL 分类，用于把源码审计的噪声挡在外面。

    实测一份小程序会话里会同时出现：
      * `https://usr/app-service.js`            业务主包（审计目标）
      * `node:internal/fs/promises`             **宿主 Node 的模块**（跟小程序无关）
      * `wasm://wasm/xxx.wasm`                  WASM 模块
      * `...-V0FQQ0FkYXB0ZXJBcHBJbmRleC5qcw==.cachedata`  WeChat 运行时（WAPAdapter/WAService/WAWebview）
      * `''`                                     Runtime.evaluate 的临时片段
    """
    text = str(url or "").strip()
    if not text:
        return "anonymous"
    lowered = text.lower()
    if lowered.startswith("node:") or "node:internal" in lowered:
        return "host_node"
    if lowered.startswith("wasm:") or lowered.endswith(".wasm"):
        return "wasm"
    if lowered.startswith("devtools://"):
        return "devtools"
    if ".cachedata" in lowered:
        return "wechat_runtime"
    if lowered.startswith("https://usr/") or lowered.startswith("http://usr/"):
        return "business"
    if "servicewechat.com" in lowered:
        return "business"
    return "other"


# 永远不会是小程序业务代码的来源，源码审计默认跳过
NON_MINIAPP_SCRIPT_KINDS = {"host_node", "wasm", "devtools"}

# 静态资源扩展名：这些不是接口，分析时应当排除
STATIC_URL_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".css", ".js", ".mjs", ".map", ".json", ".txt", ".xml",
    ".mp4", ".webm", ".mp3", ".wav", ".aac",
)


# 埋点 / 遥测路径段：它们也是「接口」，但对风险面分析是纯噪声。
# 实测一份 49 条请求的会话里 **28 条**是 `POST /tracking/analytics/logging/messages`，
# 它把接口清单和签名面全部污染（签名面 28 条命中全是它 body 里的 `context.timestamp`）。
# 不能一刀切删掉 —— 埋点本身也可能上报 PII，所以单独归类、可显式包含。
TELEMETRY_SEGMENTS = frozenset(
    {
        "tracking", "tracker", "telemetry", "analytics", "beacon", "metrics",
        "logging", "logreport", "log-report", "statistics", "stat",
    }
)


def is_telemetry_request(url: str) -> bool:
    """判断是否属于埋点 / 遥测请求（路径段命中 TELEMETRY_SEGMENTS）。"""
    segments = [seg for seg in urlparse(str(url or "")).path.lower().split("/") if seg]
    return any(seg in TELEMETRY_SEGMENTS for seg in segments)


def classify_request_url(url: str) -> str:
    """给请求 URL 分类，用于把接口分析从静态资源噪声里摘出来。

    实测一份真实会话里，CDP 缓存 29 条请求中绝大多数是字体 / 图片 / SVG，
    甚至还有被当成请求记录的 `data:` 内联资源（`image/*;base64,...`）。
    这些进入 `get_api_inventory` 与各 `find_*` 会直接淹没真实接口。

    `telemetry` 是 v2.22 新增的一类：埋点流量占比可以极高（实测 28/49），
    但它不是「静态资源」，所以旧代码把它当 `api` 放进了所有分析面。
    """
    text = str(url or "").strip()
    if not text:
        return "unknown"
    lowered = text.lower()
    if lowered.startswith("data:"):
        return "data_uri"
    if lowered.startswith("blob:"):
        return "blob"
    if lowered.startswith("ws:") or lowered.startswith("wss:"):
        return "websocket"
    parsed = urlparse(text)
    path = parsed.path.lower()
    if path.endswith(".html") or path.endswith(".htm"):
        return "document"
    if path.endswith(STATIC_URL_EXTS) or "/static/" in path or "/assets/" in path or "/fonts/" in path:
        return "static"
    if is_telemetry_request(text):
        return "telemetry"
    return "api"


def is_static_request(url: str) -> bool:
    """判断是否属于「与接口分析无关」的请求。"""
    return classify_request_url(url) in {"data_uri", "blob", "static", "document"}


def truncate_text(text: str, limit: int) -> tuple[str, bool]:
    """按字符数截断文本，返回 (结果, 是否被截断)。

    工具 schema 里的 `maxLength` 以前全被 `del` 丢弃，调用方无法控制输出体积；
    大响应/大源码动辄几 MB，直接把上下文撑爆。
    """
    size = int(limit or 0)
    if size <= 0 or len(text) <= size:
        return text, False
    return text[:size] + "\n...<truncated>", True


GRAPHQL_OPERATION_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)")


def extract_graphql_operation(body: Any) -> JsonDict | None:
    """从请求体 / 查询参数里提取 GraphQL operation 标识。

    GraphQL 小程序的**所有**业务接口都打同一个端点（实测是 `/v3/`），
    只按 `method + path` 聚合会把几十个 operation 压成一行，接口清单直接失效。
    这里提取 `operationName` 与 `persistedQuery.sha256Hash`，让清单能按 operation 区分。

    支持三种形态：
      * POST + JSON body：`{"operationName":..., "extensions":{"persistedQuery":{...}}}`
      * POST + `{"id": "<hash>"}`（部分客户端用 id 传持久化查询）
      * GET + `?query=query Foo{...}`（GraphQL over GET，query 本身就是文档）
    """
    payload = safe_json_loads(body)
    if isinstance(payload, str):
        text = payload.strip()
        if not text or not any(token in text for token in ("{", "query", "mutation", "subscription")):
            return None
        match = GRAPHQL_OPERATION_RE.search(text)
        if not match:
            return None
        return {"isGraphQL": True, "graphqlOperation": match.group(1), "graphqlQueryPreview": compact_text(text, 300)}
    if not isinstance(payload, dict):
        return None
    operation_name = str(payload.get("operationName") or "").strip()
    operation_id = str(payload.get("id") or "").strip()
    # extensions 可能是对象（POST body），也可能是 **JSON 字符串**（URL query 参数）
    extensions = safe_json_loads(payload.get("extensions"))
    if isinstance(extensions, dict):
        persisted = safe_json_loads(extensions.get("persistedQuery"))
        if isinstance(persisted, dict):
            operation_id = operation_id or str(persisted.get("sha256Hash") or "").strip()
    query_text = str(payload.get("query") or "")
    if not operation_name and query_text:
        match = GRAPHQL_OPERATION_RE.search(query_text)
        if match:
            operation_name = match.group(1)
    if not operation_name and not operation_id:
        return None
    result: JsonDict = {"isGraphQL": True}
    if operation_name:
        result["graphqlOperation"] = operation_name
    if operation_id:
        result["graphqlOperationId"] = operation_id
    if query_text:
        result["graphqlQueryPreview"] = compact_text(query_text, 300)
    return result


def unknown_action_error(group: str, action: str, valid: tuple[str, ...]) -> JsonDict:
    """构造统一的「未知 action」错误，并把合法值一并回传，避免调用方盲试。"""
    return {
        "ok": False,
        "error": f"未知 {group} action: {action}",
        "validActions": list(valid),
        "hint": f"{group} 的合法 action 见 validActions（inputSchema 里也有 enum）。",
    }


def route_from_eval(result: Any) -> str:
    """从一次求值结果里取出路由字符串。

    兼容两种返回形态：`{route: "..."}` 对象（本项目各路由 expr 的约定），
    以及裸字符串（老 expr 直接 `return String(...)` 的情况）。
    """
    if not isinstance(result, dict):
        return ""
    value = result.get("value")
    if isinstance(value, dict):
        return str(value.get("route") or "").strip()
    if isinstance(value, str):
        return value.strip()
    return ""


def _shrink_console_event(event: Any, max_text_length: int, counter: list[int], depth: int = 0) -> Any:
    """按上限截断 console 事件里的超长字符串。

    **返回新结构，不改动缓存里的原对象**（否则一旦截断就永久丢掉了原始内容，
    后续想调大 `maxBytes` 再取也取不回来）。

    `counter` 用单元素列表累计「截断了几处」—— Python 的 int 不可变，只能这样回传。
    递归深度限制 8 层：CDP 事件的嵌套通常只有 2~3 层，够用且不会因异常结构爆栈。
    """
    if depth > 8:
        return "<depth-limited>"
    if isinstance(event, str):
        if len(event) > max_text_length:
            counter[0] += 1
            return event[:max_text_length] + f"…（已截断，原长 {len(event)}）"
        return event
    if isinstance(event, dict):
        return {
            key: _shrink_console_event(value, max_text_length, counter, depth + 1)
            for key, value in event.items()
        }
    if isinstance(event, (list, tuple)):
        return [_shrink_console_event(item, max_text_length, counter, depth + 1) for item in event]
    return event


def _slim_route_table(table: Any) -> JsonDict:
    """把 `inspect_routes()` 的完整返回压成摘要，**只保留判断导航成败所需的字段**。

    为什么需要它：`navigate_route` 原先把 `before`/`after` 两张**完整路由表**内联进返回
    （各含 `pages[]` 全部条目），实测返回体 **95,411 / 102,079 字符** → 被上层转存成文件，
    于是 `landedOnTarget` / `bouncedToLogin` 这些**关键字段反而读不到**。
    摘要保留了目标页/守卫/计数，丢掉的只有 `pages[]` 明细（要明细本来可以单独调
    `route_ops(action="inspect_routes")`）。需要完整版时传 `verbose=true`。
    """
    if not isinstance(table, dict):
        return {"ok": False, "available": False}
    pages = table.get("pages") if isinstance(table.get("pages"), list) else []
    return {
        "ok": bool(table.get("ok")),
        "currentRoute": table.get("current_route"),
        "guardEnabled": table.get("guard_enabled"),
        "blockedRedirects": table.get("blocked_redirects_count"),
        "routeCount": len(pages),
        "tabbarCount": len(table.get("tabbar_pages") or []),
    }


def _slim_rehook(rehook: Any) -> JsonDict:
    """把 `rehook_after_route_navigation()` 的返回压成摘要（每个 hook 只留是否成功）。"""
    if not isinstance(rehook, dict):
        return {"ok": False}
    hooks = rehook.get("hooks") if isinstance(rehook.get("hooks"), dict) else {}
    slim: JsonDict = {
        "ok": bool(rehook.get("ok")),
        "hooks": {
            name: (bool(value.get("ok")) if isinstance(value, dict) else bool(value))
            for name, value in hooks.items()
        },
    }
    for key in ("skipped", "reason", "mode", "previousContextId", "selectedContextId"):
        if rehook.get(key) is not None:
            slim[key] = rehook.get(key)
    return slim


class IgnoreOptionalCdpError:
    """忽略兼容性 CDP 命令失败，避免可选 domain 影响主流程。"""

    def __enter__(self) -> None:
        """进入忽略异常上下文。"""
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        """退出时吞掉异常。"""
        return True


class McpRuntimeSession:
    """保存一个 MCP HTTP 服务进程内的 CDP 连接、采集缓存和分析状态。"""

    def __init__(self) -> None:
        """初始化 CDP 客户端、请求/脚本缓存和后台任务状态。"""
        self.cdp = LocalCdpClient(disconnect_grace_seconds=1.8)
        self.requests: dict[str, JsonDict] = {}
        self.request_order: deque[str] = deque(maxlen=1500)
        self.scripts: dict[str, JsonDict] = {}
        self.contexts: dict[int, JsonDict] = {}
        self.console_events: deque[JsonDict] = deque(maxlen=500)
        self.websocket_events: deque[JsonDict] = deque(maxlen=500)
        self.selected_appservice_context_id: int | None = None
        self.selected_target_id: str | None = None
        self.jobs: dict[str, JsonDict] = {}
        # 监听器只需注册一次；domain 的 enable 则要按「连接代数」重发
        self._listeners_registered = False
        self._domain_connection_id = -1
        # 脚本源码缓存（search_in_sources 反复拉同一批脚本，不缓存会非常慢）
        self._script_source_cache: dict[str, str] = {}
        self._script_source_bytes = 0
        self._script_source_max_entries = 40
        self._script_source_max_bytes = 8 * 1024 * 1024
        self._script_source_max_total = 48 * 1024 * 1024
        # 断点登记表：以前只能下断点、不能撤，违反「可逆」原则，也没法做清理
        self.xhr_breakpoints: set[str] = set()
        self.script_breakpoints: dict[str, JsonDict] = {}
        self.breakpoints_active = True
        # —— 页面 session / 桥接状态（用于 appservice 上下文自动发现）——
        # CDP 是分层的：在浏览器层发 Runtime.enable 拿不到小程序的 executionContext，
        # 必须先 attach 到页面 target 并在该 session 里 enable，才能收到 context 事件。
        self.page_session_id: str | None = None
        self.page_target_id: str | None = None
        self.context_sessions: dict[int, str] = {}
        self.appservice_bridge_frame: str = ""
        self.last_route_seen: str = ""
        self.last_route_changed_at: float = 0.0
        self.last_snapshot_at: float = 0.0

    async def connection_ops(self, action: str, **kwargs: Any) -> str:
        """执行连接类 MCP 操作并返回 JSON 文本。"""
        action = str(action or "status")
        if action == "status":
            return json_text(await self.status())
        if action == "connect_wmpf":
            return json_text(
                await self.connect_wmpf(
                    str(kwargs.get("ws_url") or kwargs.get("wsUrl") or DEFAULT_WS_URL),
                    force=bool(kwargs.get("force", False)),
                )
            )
        if action == "select_appservice_context":
            return json_text(await self.select_appservice_context(force=bool(kwargs.get("force", False))))
        if action == "find_appservice":
            return json_text(await self.find_appservice())
        if action == "list_targets":
            cdp_state = await self.ensure_cdp()
            if not cdp_state.get("ok"):
                return json_text(cdp_state)
            return json_text(await self.list_targets())
        if action == "switch_target":
            cdp_state = await self.ensure_cdp()
            if not cdp_state.get("ok"):
                return json_text(cdp_state)
            return json_text(await self.switch_target(str(kwargs.get("target_id") or kwargs.get("targetId") or "")))
        if action == "cdp_call":
            return json_text(await self.cdp_call(str(kwargs.get("method") or ""), kwargs.get("params") or {}, kwargs.get("sessionId") or kwargs.get("session_id")))
        if action == "cdp_call_target":
            return json_text(await self.cdp_call_target(str(kwargs.get("target_id") or kwargs.get("targetId") or ""), str(kwargs.get("method") or ""), kwargs.get("params") or {}))
        return json_text(unknown_action_error("connection_ops", action, CONNECTION_ACTIONS))

    async def network_ops(self, action: str, **kwargs: Any) -> str:
        """执行网络采集、Hook 和接口资产类 MCP 操作。"""
        action = str(action or "")
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return json_text(cdp_state)
        if action == "network_enable":
            await self.ensure_network_enabled()
            return json_text({"ok": True, "message": "Network domain 已启用"})
        if action == "hook_wx_request":
            return json_text(await self.hook_wx_request())
        if action == "hook_upload_apis":
            return json_text(await self.hook_upload_apis())
        if action == "install_early_hooks":
            return json_text(await self.install_early_hooks())
        if action == "hook_fetch_and_xhr":
            return json_text(await self.hook_fetch_and_xhr())
        if action == "fetch_from_page":
            return json_text(
                await self.fetch_from_page(
                    str(kwargs.get("url") or ""),
                    method=str(kwargs.get("method") or "GET"),
                    headers=kwargs.get("headers"),
                    body=kwargs.get("body"),
                    await_promise=bool(kwargs.get("await_promise", True)),
                )
            )
        if action == "upload_formdata_from_page":
            return json_text(
                await self.upload_formdata_from_page(
                    str(kwargs.get("url") or ""),
                    method=str(kwargs.get("method") or "POST"),
                    headers=kwargs.get("headers"),
                    fields=kwargs.get("fields"),
                    files=kwargs.get("files"),
                    await_promise=bool(kwargs.get("await_promise", True)),
                )
            )
        if action == "get_all_requests":
            return json_text(
                await self.get_all_requests(
                    limit=int(kwargs.get("limit") or 200),
                    keyword=kwargs.get("keyword"),
                    domain=kwargs.get("domain"),
                    path_prefix=kwargs.get("pathPrefix") or kwargs.get("path_prefix"),
                    exclude_static=bool(kwargs.get("excludeStatic", False)),
                    exclude_telemetry=bool(kwargs.get("excludeTelemetry", False)),
                )
            )
        if action == "get_request_detail":
            return json_text(
                await self.get_request_detail(
                    str(kwargs.get("request_id") or kwargs.get("requestId") or kwargs.get("id") or ""),
                    max_length=int(kwargs.get("maxLength") or kwargs.get("max_length") or 20_000),
                )
            )
        if action == "get_recent_requests":
            return json_text(
                await self.get_recent_requests(
                    int(kwargs.get("limit") or 50),
                    domain=kwargs.get("domain"),
                    path_prefix=kwargs.get("pathPrefix") or kwargs.get("path_prefix"),
                    keyword=kwargs.get("keyword"),
                    compact=bool(kwargs.get("compact", True)),
                    exclude_static=bool(kwargs.get("excludeStatic", True)),
                )
            )
        if action == "get_response_body":
            return json_text(await self.get_response_body(str(kwargs.get("request_id") or kwargs.get("requestId") or "")))
        if action == "get_recent_console":
            return json_text(
                await self.get_recent_console(
                    int(kwargs.get("limit") or 50),
                    max_bytes=int(kwargs.get("maxBytes") or kwargs.get("max_bytes") or 24_000),
                    max_text_length=int(
                        kwargs.get("maxTextLength") or kwargs.get("max_text_length") or 2_000
                    ),
                )
            )
        if action == "get_hooked_requests":
            return json_text({"ok": True, "requests": (await self.get_hooked_requests())[-max(1, int(kwargs.get("limit") or 50)): ]})
        if action == "search_runtime_keywords":
            keywords = kwargs.get("keywords") or kwargs.get("query") or kwargs.get("keyword") or []
            if isinstance(keywords, str):
                keywords = [keywords]
            return json_text(
                await self.search_runtime_keywords(
                    list(keywords), max_length=int(kwargs.get("maxLength") or kwargs.get("max_length") or 20_000)
                )
            )
        if action == "trace_request_callstack":
            return json_text(
                await self.trace_request_callstack(
                    str(kwargs.get("request_id") or kwargs.get("requestId") or ""),
                    limit=int(kwargs.get("limit") or 50),
                )
            )
        if action == "inspect_wx_config":
            return json_text(await self.inspect_wx_config(int(kwargs.get("maxLength") or kwargs.get("max_length") or 20_000)))
        return json_text(unknown_action_error("network_ops", action, NETWORK_ACTIONS))

    async def runtime_ops(self, action: str, **kwargs: Any) -> str:
        """执行运行时求值、快照和状态检查类 MCP 操作。"""
        action = str(action or "")
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return json_text(cdp_state)
        if action == "runtime_eval":
            return json_text(await self.runtime_eval(str(kwargs.get("expression") or ""), await_promise=bool(kwargs.get("await_promise", True)), context_id=kwargs.get("context_id") or kwargs.get("contextId")))
        if action == "runtime_eval_appservice":
            return json_text(await self.runtime_eval_appservice(str(kwargs.get("expression") or "")))
        if action == "probe_bridge":
            return json_text(await self.probe_bridge())
        if action == "wait_route_stable":
            return json_text(await self.wait_route_stable(timeout_seconds=float(kwargs.get("timeout") or 12), settle_seconds=float(kwargs.get("settle") or 2.5)))
        if action == "dump_runtime_snapshot":
            return json_text(await self.dump_runtime_snapshot(int(kwargs.get("maxLength") or kwargs.get("max_length") or 20_000)))
        if action == "scan_sensitive_storage":
            return json_text(
                await self.scan_sensitive_storage(
                    include_raw=bool(kwargs.get("includeRaw", False)),
                    max_raw_chars=int(kwargs.get("maxRawChars") or kwargs.get("max_raw_chars") or 4000),
                )
            )
        if action == "inspect_upload_surface":
            return json_text(await self.inspect_upload_surface())
        if action == "get_basic_page_info":
            return json_text(await self.get_basic_page_info())
        if action == "get_document_html":
            return json_text(await self.get_document_html(int(kwargs.get("maxLength") or kwargs.get("max_length") or 20_000)))
        if action == "query_selector_text":
            return json_text(await self.query_selector_text(str(kwargs.get("selector") or ""), int(kwargs.get("maxLength") or kwargs.get("max_length") or 10_000)))
        if action == "inspect_window_keys":
            return json_text(await self.inspect_window_keys(kwargs.get("pattern"), int(kwargs.get("limit") or 200)))
        if action == "search_global_string":
            return json_text(await self.search_global_string(str(kwargs.get("keyword") or ""), int(kwargs.get("maxLength") or kwargs.get("max_length") or 20_000)))
        if action == "inspect_vuex_store":
            return json_text(
                await self.inspect_vuex_store(
                    force_select=bool(kwargs.get("forceSelect", False)),
                    max_length=int(kwargs.get("maxLength") or kwargs.get("max_length") or 20_000),
                )
            )
        if action == "patch_vuex_state":
            return json_text(
                await self.patch_vuex_state(
                    str(kwargs.get("path") or ""),
                    kwargs.get("value"),
                    bool(kwargs.get("dryRun", True)),
                    bool(kwargs.get("requireConfirm", False)),
                    force_select=bool(kwargs.get("forceSelect", False)),
                )
            )
        if action == "restore_vuex_state":
            return json_text(
                await self.restore_vuex_state(
                    bool(kwargs.get("dryRun", True)),
                    bool(kwargs.get("requireConfirm", False)),
                    force_select=bool(kwargs.get("forceSelect", False)),
                )
            )
        if action == "list_interactive_elements":
            return json_text(await self.list_interactive_elements())
        if action == "safe_click_and_observe":
            return json_text(
                await self.safe_click_and_observe(
                    str(kwargs.get("selector") or ""),
                    bool(kwargs.get("requireConfirm", False)),
                    wait_ms=int(kwargs.get("waitMs") if kwargs.get("waitMs") is not None else 300),
                    capture_before_after=bool(kwargs.get("captureBeforeAfter", True)),
                )
            )
        if action == "input_text_and_observe":
            return json_text(
                await self.input_text_and_observe(
                    str(kwargs.get("selector") or ""),
                    str(kwargs.get("text") or ""),
                    wait_ms=int(kwargs.get("waitMs") if kwargs.get("waitMs") is not None else 800),
                )
            )
        return json_text(unknown_action_error("runtime_ops", action, RUNTIME_ACTIONS))

    async def route_ops(self, action: str, **kwargs: Any) -> str:
        """执行小程序路由、守卫和跳转类 MCP 操作。"""
        action = str(action or "")
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return json_text(cdp_state)
        if action == "inspect_routes":
            return json_text(await self.inspect_routes())
        if action == "enable_redirect_guard":
            return json_text(await self.set_redirect_guard(True))
        if action == "disable_redirect_guard":
            return json_text(await self.set_redirect_guard(False))
        if action in {"navigate_route", "navigate_route_with_guard"}:
            wait_arg = kwargs.get("wait_ms")
            return json_text(
                await self.navigate_route(
                    str(kwargs.get("route") or ""),
                    is_tabbar=bool(kwargs.get("is_tabbar", False)),
                    guard=action == "navigate_route_with_guard",
                    wait_ms=int(wait_arg if wait_arg is not None else 1200),
                    verbose=bool(kwargs.get("verbose", False)),
                )
            )
        if action in {"navigate_back", "back", "go_back"}:
            return json_text(
                await self.navigate_back(
                    delta=int(kwargs.get("delta") or 1),
                    wait_ms=int(kwargs.get("wait_ms") if kwargs.get("wait_ms") is not None else 1200),
                )
            )
        if action == "wait_route_stable":
            return json_text(
                await self.wait_route_stable(
                    timeout_seconds=float(kwargs.get("timeout") or 12),
                    settle_seconds=float(kwargs.get("settle") or 2.5),
                )
            )
        if action == "plan_route_crawl":
            raw_routes = kwargs.get("routes")
            return json_text(
                await self.plan_route_crawl(
                    routes=(
                        [str(item) for item in raw_routes]
                        if isinstance(raw_routes, (list, tuple))
                        else None
                    ),
                    settle_ms=int(kwargs.get("settle_ms") or DEFAULT_CRAWL_SETTLE_MS),
                    deadline_seconds=float(
                        kwargs.get("deadline_seconds") or DEFAULT_CRAWL_DEADLINE_SECONDS
                    ),
                    max_routes=int(kwargs.get("max_routes") or DEFAULT_CRAWL_MAX_ROUTES),
                    start_from=int(kwargs.get("start_from") or 0),
                    exclude_tabbar=bool(kwargs.get("exclude_tabbar", False)),
                    include_subpackages=bool(kwargs.get("include_subpackages", True)),
                )
            )
        if action == "crawl_routes":
            raw_routes = kwargs.get("routes")
            rehook_arg = kwargs.get("rehook")
            nav_timeout_arg = kwargs.get("navigation_timeout_seconds")
            return json_text(
                await self.crawl_routes(
                    routes=(
                        [str(item) for item in raw_routes]
                        if isinstance(raw_routes, (list, tuple))
                        else None
                    ),
                    start_from=int(kwargs.get("start_from") or 0),
                    max_routes=int(kwargs.get("max_routes") or DEFAULT_CRAWL_MAX_ROUTES),
                    settle_ms=int(kwargs.get("settle_ms") or DEFAULT_CRAWL_SETTLE_MS),
                    deadline_seconds=float(
                        kwargs.get("deadline_seconds") or DEFAULT_CRAWL_DEADLINE_SECONDS
                    ),
                    # `or` 会吞掉显式 False，`bool(None)` 又会顶掉默认 True —— 两条都要防。
                    rehook=True if rehook_arg is None else bool(rehook_arg),
                    navigation_timeout_seconds=float(
                        nav_timeout_arg or DEFAULT_CRAWL_NAV_TIMEOUT_SECONDS
                    ),
                )
            )
        return json_text(
            {
                "ok": False,
                "error": f"未知 route_ops action: {action}",
                "validActions": [
                    "inspect_routes",
                    "enable_redirect_guard",
                    "disable_redirect_guard",
                    "navigate_route",
                    "navigate_route_with_guard",
                    "navigate_back",
                    "wait_route_stable",
                    "plan_route_crawl",
                    "crawl_routes",
                ],
            }
        )

    async def ensure_route_navigator(self) -> JsonDict:
        """注入共享路由导航脚本到当前页面/window Runtime。"""
        if not ROUTE_NAVIGATOR_JS_PATH.is_file():
            return {
                "ok": False,
                "stage": "load_nav_inject",
                "error": f"路由导航脚本不存在：{ROUTE_NAVIGATOR_JS_PATH}",
                "hint": "确认安装完整（该文件随包分发）；若你移动过 e0e1-wx\\package 目录请还原。",
            }
        script = await asyncio.to_thread(ROUTE_NAVIGATOR_JS_PATH.read_text, encoding="utf-8")
        injected = await self.runtime_eval(script)
        if not injected.get("ok"):
            return {"ok": False, "stage": "inject", "error": injected}
        probe = await self.runtime_eval("(()=>({ok:!!(window.__routeNavigator), type:typeof window.__routeNavigator}))()")
        value = probe.get("value") if isinstance(probe, dict) else None
        if isinstance(value, dict) and value.get("ok"):
            return {"ok": True, "navigator": value}
        return {"ok": False, "stage": "probe", "error": probe}

    async def inspect_routes(self) -> JsonDict:
        """读取小程序路由配置、当前路由和防跳转守卫状态。"""
        ready = await self.ensure_route_navigator()
        if not ready.get("ok"):
            return ready
        result = await self.runtime_eval("window.__routeNavigator.fetchConfigJson()", await_promise=True)
        if not result.get("ok"):
            return {"ok": False, "stage": "fetch", "error": result}
        payload = safe_json_loads(result.get("value"))
        if not isinstance(payload, dict):
            return {"ok": False, "stage": "parse", "raw": result.get("value")}
        return {
            "ok": True,
            "pages": payload.get("pages") or [],
            "tabbar_pages": payload.get("tabBarPages") or [],
            "current_route": str(payload.get("currentRoute") or ""),
            "guard_enabled": bool(payload.get("guardEnabled")),
            "blocked_redirects_count": int(payload.get("blockedRedirectsCount") or 0),
        }

    async def plan_route_crawl(
        self,
        *,
        routes: list[str] | None = None,
        settle_ms: int = DEFAULT_CRAWL_SETTLE_MS,
        deadline_seconds: float = DEFAULT_CRAWL_DEADLINE_SECONDS,
        max_routes: int = DEFAULT_CRAWL_MAX_ROUTES,
        start_from: int = 0,
        exclude_tabbar: bool = False,
        include_subpackages: bool = True,
    ) -> JsonDict:
        """规划一次「逐路由导航 + 增量采集」，**不执行任何导航**（dry-run）。

        为什么只做规划：SKILL.md Phase 1.1 要求逐路由遍历，但调用方自己拼
        `setTimeout` 链 + Bash `sleep` 会被上层的循环调用检测强制中断（实测连续
        4 次 `sleep 70` 就触发）。真正危险的不是「批量导航」，而是**盲等** ——
        调用方不知道要等多久、也不知道进度。

        所以这里先把「N 条路由」变成一份**可复核、可分批、带断点**的计划：
        每条路由的预计耗时、每批装得下几条、`resumeFrom` 从哪续跑。

        ⚠️ 本方法**只读**：不调用任何 `navigate*` / `switchTab` / `reLaunch`。
        路由清单来自 `inspect_routes()`（读 `__wxConfig`，不触发导航）。

        `estimatedSeconds` 是**估算**，口径写在返回的 `assumption` 里 ——
        导航开销无法离线得知，不要把估算当精确值。
        """
        settle_ms = max(0, min(int(settle_ms), 60_000))
        deadline_seconds = max(1.0, min(float(deadline_seconds), 3_600.0))
        max_routes = max(1, min(int(max_routes), 5_000))
        start_from = max(0, int(start_from))

        warnings: list[str] = []
        # 注意用 `is not None` 而不是真值判断：显式传 `routes=[]` 的语义是
        # 「调用方说没有路由要规划」，不该被当成「没传」从而去打一次 CDP 读配置
        # （实测踩过：空列表会静默走 inspect_routes，白打一轮网络）。
        route_source = "caller" if routes is not None else "appservice"
        tabbar_pages: list[str] = []
        current_route = ""

        if routes is not None:
            entries = [
                {"route": self.normalize_miniapp_route(str(item)), "source": "caller", "isTabBar": False}
                for item in routes
            ]
            # 只有真要排除 tabBar 时才去读配置（避免为一次纯规划多打一轮 CDP）。
            if exclude_tabbar:
                probe = await self.inspect_routes()
                if probe.get("ok"):
                    tabbar_pages = [str(x) for x in (probe.get("tabbar_pages") or [])]
                    current_route = str(probe.get("current_route") or "")
                    for entry in entries:
                        entry["isTabBar"] = entry["route"] in tabbar_pages
                else:
                    warnings.append(
                        "exclude_tabbar=true 但读取 tabBar 配置失败，本次**未排除任何 tabBar 页**；"
                        f"原因：{probe.get('error') or probe.get('stage') or '未知'}"
                    )
        else:
            probe = await self.inspect_routes()
            if not probe.get("ok"):
                return {
                    "ok": False,
                    "stage": "read_route_config",
                    "dryRun": True,
                    "error": probe.get("error") or probe,
                    "hint": (
                        "读不到路由清单。可改用 routes=[...] 显式传入；"
                        "或先 connection_ops(action=\"connect_wmpf\") 恢复 CDP 连接。"
                    ),
                }
            tabbar_pages = [str(x) for x in (probe.get("tabbar_pages") or [])]
            current_route = str(probe.get("current_route") or "")
            entries = []
            for item in probe.get("pages") or []:
                if isinstance(item, dict):
                    entries.append(
                        {
                            "route": self.normalize_miniapp_route(str(item.get("route") or "")),
                            "source": str(item.get("source") or "main"),
                            "isTabBar": bool(item.get("isTabBar")),
                        }
                    )
                else:
                    entries.append(
                        {
                            "route": self.normalize_miniapp_route(str(item)),
                            "source": "main",
                            "isTabBar": False,
                        }
                    )

        available = len(entries)

        # —— 过滤：无效 / 重复 / tabBar / 分包 ——
        planned: list[JsonDict] = []
        seen: set[str] = set()
        skipped_invalid = 0
        skipped_duplicate = 0
        skipped_tabbar = 0
        skipped_subpackage = 0
        for entry in entries:
            route = entry["route"]
            if not route:
                skipped_invalid += 1
                continue
            if route in seen:
                skipped_duplicate += 1
                continue
            seen.add(route)
            if exclude_tabbar and entry["isTabBar"]:
                skipped_tabbar += 1
                continue
            if not include_subpackages and entry["source"] not in {"main", "caller"}:
                skipped_subpackage += 1
                continue
            planned.append(entry)

        # —— 断点续跑：跳过前 start_from 条 ——
        skipped_by_start_from = min(start_from, len(planned))
        planned = planned[skipped_by_start_from:]

        # —— 上限：避免生成一份几千条的计划 ——
        truncated_by_max_routes = max(0, len(planned) - max_routes)
        planned = planned[:max_routes]

        per_route_seconds = settle_ms / 1000.0 + CRAWL_NAVIGATION_OVERHEAD_SECONDS
        per_batch = max(1, int(deadline_seconds // per_route_seconds)) if per_route_seconds else 1

        batches: list[JsonDict] = []
        for index, offset in enumerate(range(0, len(planned), per_batch)):
            chunk = planned[offset : offset + per_batch]
            batches.append(
                {
                    "index": index,
                    "count": len(chunk),
                    "estimatedSeconds": round(len(chunk) * per_route_seconds, 1),
                    "deadlineSeconds": deadline_seconds,
                    # 供调用方按批执行时原样回传，实现断点续跑。
                    "resumeFrom": skipped_by_start_from + offset,
                    "routes": [item["route"] for item in chunk],
                }
            )

        by_package: dict[str, int] = {}
        for item in planned:
            key = str(item["source"] or "main")
            by_package[key] = by_package.get(key, 0) + 1

        # baseline 的口径与 analysis_ops(action="get_api_inventory") 对齐（同样只算
        # api + telemetry，即 exclude_static=True、exclude_telemetry=True），
        # 这样「本轮 inventory − baseline」的差集才有意义。
        #
        # ⚠️ 两个坑都踩过（v2.27 实测）：
        # 1) `self.requests` 是 **dict**（按 requestId 索引），不是 list。直接传给
        #    `build_api_inventory()` 会让它 `for req in requests` 迭代到**键（字符串）**，
        #    抛 `'str' object has no attribute 'get'` —— 本方法**所有路径**都因此失败。
        #    必须先取 `.values()` 并过一遍 `normalize_request()`（`path` 是从 `url` 算出来的，
        #    原始记录里没有 `path` 字段，不归一化会得到 `GET None`）。
        # 2) **不能**图省事改用 `get_all_requests()` 来对齐口径：它会调
        #    `get_hooked_requests()` → `runtime_eval()`，而本方法对「显式传 routes」
        #    的路径承诺**零 CDP 求值**（离线断言守着这条）。所以只读进程内缓存。
        #
        # 这个 bug 只在**有真实流量**时暴露：`self.requests` 为空时循环体根本不执行，
        # 于是离线单测（空会话）全绿、真机一跑就炸。空状态会**掩盖**这类 bug。
        cached = [self.normalize_request(value) for value in self.requests.values()]
        cached = [record for record in cached if record.get("kind") in {"api", "telemetry"}]
        inventory = self.build_api_inventory(cached)
        baseline = {
            "requestCount": len(cached),
            "apiCount": int(inventory.get("total") or 0),
            "currentRoute": current_route,
            "source": "in_process_cache",
            "note": (
                "只统计进程内 CDP 缓存里的接口类请求（api + telemetry），"
                "**不含** hook 采集的记录 —— 本方法不做 CDP 求值。"
                "要与 get_api_inventory 严格对齐口径，请直接调用后者。"
            ),
        }

        if not planned:
            warnings.append(
                "计划为空 —— 检查 routes 参数是否为空、或 start_from 是否已超过总数"
                f"（过滤后总数 {len(seen)}，start_from={start_from}）。"
            )
        if truncated_by_max_routes:
            warnings.append(
                f"因 max_routes={max_routes} 截断，还有 {truncated_by_max_routes} 条未进计划；"
                f"下一批请用 start_from={skipped_by_start_from + len(planned)} 续跑。"
            )
        if per_route_seconds > deadline_seconds:
            warnings.append(
                f"单条路由估算耗时 {per_route_seconds:.1f}s 已超过 deadline_seconds={deadline_seconds}，"
                "每批只能装 1 条；建议调大 deadline_seconds 或调小 settle_ms。"
            )
        if exclude_tabbar and not tabbar_pages:
            warnings.append("exclude_tabbar=true 但 tabBar 清单为空，可能该小程序没有 tabBar 或配置未读到。")
        if skipped_subpackage:
            warnings.append(
                f"因 include_subpackages=false 跳过 {skipped_subpackage} 条分包路由；"
                "分包路由往往是业务主体，跳过前请确认这是有意为之。"
            )

        return {
            "ok": True,
            "dryRun": True,
            "plannedAt": now_iso(),
            "routeSource": route_source,
            "totals": {
                "available": available,
                "planned": len(planned),
                "skippedInvalid": skipped_invalid,
                "skippedDuplicate": skipped_duplicate,
                "skippedTabbar": skipped_tabbar,
                "skippedSubpackage": skipped_subpackage,
                "skippedByStartFrom": skipped_by_start_from,
                "truncatedByMaxRoutes": truncated_by_max_routes,
                "tabbarPages": len(tabbar_pages),
            },
            "byPackage": by_package,
            "settleMs": settle_ms,
            "deadlineSeconds": deadline_seconds,
            "assumption": (
                f"每条路由耗时 ≈ settleMs({settle_ms}ms) + 导航开销({CRAWL_NAVIGATION_OVERHEAD_SECONDS}s)，"
                "导航开销为估算常数、非实测值；实际会随页面复杂度与网络抖动浮动。"
            ),
            "estimatedSeconds": round(len(planned) * per_route_seconds, 1),
            "estimatedBatches": len(batches),
            "perBatch": per_batch,
            "nextStartFrom": skipped_by_start_from + len(planned),
            "batches": batches,
            "collect": {
                "baseline": baseline,
                "perRoute": [
                    "导航后用 route_ops(action=\"wait_route_stable\") 确认真的落到目标页（别只看 ok:true）",
                    "新增请求数 = network_ops(action=\"get_recent_requests\") 的记录数增量",
                    "新出现的 API = get_api_inventory 与上一轮的差集（这才是「增量新接口」）",
                ],
                "note": (
                    "本工具**只规划、不导航**。执行请用 **`crawl_routes`**（传 batches[].routes 或 start_from），"
                    "它会真正导航、逐条记录落点与新增请求，并用 nextStartFrom 支持续跑 —— "
                    "不要用固定 sleep 盲等，也不要在单个 runtime_eval 里自己拼导航循环。"
                ),
            },
            "warnings": warnings,
        }

    async def crawl_routes(
        self,
        *,
        routes: list[str] | None = None,
        start_from: int = 0,
        max_routes: int = DEFAULT_CRAWL_MAX_ROUTES,
        settle_ms: int = DEFAULT_CRAWL_SETTLE_MS,
        deadline_seconds: float = DEFAULT_CRAWL_DEADLINE_SECONDS,
        rehook: bool = True,
        navigation_timeout_seconds: float = DEFAULT_CRAWL_NAV_TIMEOUT_SECONDS,
    ) -> JsonDict:
        """**按批真正导航**并逐条记录落点与新增请求 —— 批量遍历的**执行**原语。

        为什么必须有它（而不是让调用方自己拼循环）：
        实测把 N 条导航塞进**单个 `runtime_eval` 的 `for + await` 循环**里，**可靠窗口只有约 3 条**
        —— 页面切换会销毁当前 executionContext，循环的 async 续体随之丢失，工具以 `TimeoutError`
        结束（而导航**其实已经执行**了，返回里还会带 `sideEffectMayHaveApplied: true`）。
        所以「一条条导航 + 增量采集」在调用方侧只有两条路：写成 N 次工具调用，或写成一段脆弱的循环
        —— 两者都不可取。

        **本方法把循环放在 Python 侧**：每条路由 = 一次**有界**导航求值 + 一次**有界**读路由。
        任何一条超时/失败都**只记在该条上，绝不中断整批** —— 这正是 `_eval_within`
        （结构化失败、不向上抛）存在的意义。

        与 `plan_route_crawl` 的分工：那个**只规划不导航**（dry-run），这个**真导航**。
        典型用法：`plan_route_crawl` 拿 `batches[].resumeFrom`
        → 按批把 `routes=[...]` 或 `start_from=N` 传给本方法 → 用返回的 `nextStartFrom` 续跑。

        `ok` 只表示**批次跑完了**（没有致命错误），**不代表每条都落到目标页**：
        登录态缺失、被守卫弹回都会让 `landed=false`，那是**采集结果**而不是工具故障。
        逐条看 `routes[].landed`，汇总看 `totals`。
        """
        started = time.time()
        settle = min(max(int(settle_ms or 0), 0), 30_000) / 1000.0
        nav_budget = max(0.5, float(navigation_timeout_seconds or DEFAULT_CRAWL_NAV_TIMEOUT_SECONDS))
        max_count = max(1, int(max_routes or DEFAULT_CRAWL_MAX_ROUTES))
        # ⚠️ 不要给预算加「下限」把一个合法的小值顶掉：`max(5.0, 调用方传的值)` 会让
        # `deadline_seconds=1` 变成 5 —— 这就是本项目反复踩的「参数被静默覆盖」。
        # 只加一个防止除零/负数的地板，调用方传什么就用什么。
        budget = max(0.1, float(deadline_seconds or DEFAULT_CRAWL_DEADLINE_SECONDS))
        deadline = started + budget

        plan = await self.inspect_routes()
        plan_ok = bool(plan.get("ok"))
        warnings: list[str] = []
        if not plan_ok and not routes:
            return {
                **plan,
                "ok": False,
                "crawled": False,
                "hint": "读路由表失败，且未显式传 routes —— 无法确定要遍历什么。",
            }
        tabbar_pages: set[str] = set()
        if plan_ok:
            tabbar_pages = {
                self.normalize_miniapp_route(str(item)).split("?", 1)[0]
                for item in (plan.get("tabbar_pages") or [])
            }
        else:
            warnings.append("读路由表失败 → tabbar 判定不可用，本批全部按 reLaunch 处理。")

        ordered: list[str] = []
        seen: set[str] = set()
        if routes:
            for item in routes:
                target = self.normalize_miniapp_route(str(item))
                if target and target not in seen:
                    seen.add(target)
                    ordered.append(target)
            route_source = "caller"
        else:
            for page in plan.get("pages") or []:
                target = self.normalize_miniapp_route(str(page.get("route") or ""))
                if target and target not in seen:
                    seen.add(target)
                    ordered.append(target)
            route_source = "config"

        total = len(ordered)
        begin = min(max(int(start_from or 0), 0), total)
        end = min(begin + max_count, total)
        truncated_by_max_routes = end < total

        requests_before = len(self.requests)
        entries: list[JsonDict] = []
        failures: list[JsonDict] = []
        rehook_failures = 0
        attempted = 0
        landed_count = 0
        stop_reason = "routes_exhausted"

        for index in range(begin, end):
            if time.time() >= deadline:
                stop_reason = "deadline"
                break
            target = ordered[index]
            path = target.split("?", 1)[0]
            is_tabbar = path in tabbar_pages
            method = "switchTabJson" if is_tabbar else "reLaunchJson"
            before_requests = len(self.requests)

            nav = await self._eval_within(
                f"window.__routeNavigator.{method}({json.dumps(target, ensure_ascii=False)})",
                timeout_seconds=nav_budget,
                session_id=None,
            )
            if settle:
                await asyncio.sleep(settle)

            detail = await self.read_route_detail()
            after_requests = len(self.requests)
            final_route = str(detail.get("route") or "")
            landed = bool(final_route) and final_route.split("?", 1)[0] == path

            entry: JsonDict = {
                "index": index,
                "route": target,
                "action": "switchTab" if is_tabbar else "reLaunch",
                "navigationOk": bool(nav.get("ok")),
                "landed": landed,
                "finalRoute": final_route,
                "routeSource": str(detail.get("source") or ""),
                "newRequests": after_requests - before_requests,
            }
            if not nav.get("ok"):
                entry["error"] = str(nav.get("error") or nav.get("exception") or "导航求值失败")
                if nav.get("timedOut"):
                    entry["timedOut"] = True
                    entry["note"] = (
                        "导航求值超时 —— 页面切换瞬间 executionContext 会被销毁，属已知现象。"
                        "**本条不要重试**（导航通常已经执行）。"
                    )
                failures.append({"index": index, "route": target, "error": entry["error"]})
            elif not landed:
                entry["note"] = (
                    f"未落到目标（实际 {final_route or '(空)'}）—— 常见原因：登录态缺失被重定向到登录页、"
                    "被防跳转守卫弹回、或该路由不在 pages 注册表里。"
                )
                failures.append({"index": index, "route": target, "finalRoute": final_route})

            attempted += 1
            if landed:
                landed_count += 1
            entries.append(entry)

            if rehook and nav.get("ok"):
                try:
                    rehook_result = await self.rehook_after_route_navigation()
                    if not rehook_result.get("ok"):
                        rehook_failures += 1
                except Exception:  # noqa: BLE001 - 重挂失败不该中断采集
                    rehook_failures += 1
        else:
            stop_reason = "max_routes" if truncated_by_max_routes else "routes_exhausted"

        next_start = begin + attempted
        payload: JsonDict = {
            "ok": True,
            "dryRun": False,
            "routeSource": route_source,
            "startFrom": begin,
            "nextStartFrom": next_start,
            "stoppedReason": stop_reason,
            "totals": {
                "available": total,
                "planned": end - begin,
                "attempted": attempted,
                "landed": landed_count,
                "notLanded": attempted - landed_count,
                "remaining": max(total - next_start, 0),
            },
            "settleMs": int(settle * 1000),
            "deadlineSeconds": budget,
            "elapsedSeconds": round(time.time() - started, 2),
            "collect": {
                "requestsBefore": requests_before,
                "requestsAfter": len(self.requests),
                "newRequests": len(self.requests) - requests_before,
            },
            "tabbarPages": sorted(tabbar_pages),
            "rehookFailures": rehook_failures,
            "routes": entries,
            "failures": failures,
            "hint": (
                "① 本方法**只负责导航与记录增量**，不做风险判定 —— "
                "`collect.newRequests` 与 `analysis_ops(get_api_inventory)` 的差集才是「本轮新接口」；"
                "② `landed=false` 是**采集结果**（登录态缺失 / 守卫弹回），不是工具故障；"
                f"③ 续跑：把 nextStartFrom={next_start} 原样回传；"
                "④ 一批跑不完是正常的（deadline 保护），分批推进即可、不要加大 settle 硬等。"
            ),
        }
        if stop_reason == "deadline":
            payload["hint"] += " ⑤ 本次因**到达时间预算**提前收工 —— 这不是错误。"
        if rehook_failures:
            warnings.append(
                f"有 {rehook_failures} 条路由在导航后**重挂 Hook 失败** —— "
                "这些条目的流量可能没被采到，建议对它们单独重跑一次。"
            )
        if warnings:
            payload["warnings"] = warnings
        return payload

    async def set_redirect_guard(self, enabled: bool) -> JsonDict:
        """开启或关闭小程序路由防跳转守卫。"""
        ready = await self.ensure_route_navigator()
        if not ready.get("ok"):
            return ready
        method = "enableRedirectGuardJson" if enabled else "disableRedirectGuardJson"
        result = await self.runtime_eval(f"window.__routeNavigator.{method}()", await_promise=True)
        payload = safe_json_loads(result.get("value")) if result.get("ok") else result
        return {"ok": bool(result.get("ok")), "enabled": bool(enabled), "result": payload}

    async def navigate_route(
        self,
        route: str,
        *,
        is_tabbar: bool = False,
        guard: bool = False,
        wait_ms: int = 1200,
        verbose: bool = False,
    ) -> JsonDict:
        """执行路由跳转，可选防跳转守卫，并返回最终路由观测。

        **返回体量受控**（默认）：`before` / `after` 只回摘要
        （currentRoute / guardEnabled / blockedRedirects / routeCount / tabbarCount），
        `rehook` 里每个 hook 只回是否成功 —— 原先内联两张**完整**路由表 + 完整 hook 返回，
        实测 95,411 / 102,079 字符，会把返回撑成转存文件、**反而读不到
        `landedOnTarget` / `bouncedToLogin` 这些关键字段**。
        需要完整路由表就传 `verbose=true`（返回体显著变大），
        或单独调 `route_ops(action="inspect_routes")`。
        """
        target = self.normalize_miniapp_route(route)
        if not target:
            return {"ok": False, "error": "route 不能为空"}
        before = await self.inspect_routes()
        if not before.get("ok"):
            return before
        if guard:
            guard_result = await self.set_redirect_guard(True)
            if not guard_result.get("ok"):
                return guard_result
            before = await self.inspect_routes()
        method = "switchTabJson" if is_tabbar else "reLaunchJson"
        jump = await self.runtime_eval(
            f"window.__routeNavigator.{method}({json.dumps(target, ensure_ascii=False)})",
            await_promise=True,
        )
        jump_value = safe_json_loads(jump.get("value")) if jump.get("ok") else jump
        delay = min(max(int(wait_ms or 0), 0), 10_000) / 1000
        if delay:
            await asyncio.sleep(delay)
        after = await self.inspect_routes()
        before_blocked = int(before.get("blocked_redirects_count") or 0)
        after_blocked = int(after.get("blocked_redirects_count") or 0) if after.get("ok") else before_blocked
        final_route = str(after.get("current_route") or "") if after.get("ok") else ""
        guard_enabled = bool(after.get("guard_enabled")) if after.get("ok") else bool(guard)
        rehook = await self.rehook_after_route_navigation() if after.get("ok") else {"ok": False, "skipped": True, "reason": "route inspect failed"}
        upload_indicators = await self.inspect_upload_surface() if after.get("ok") else {"ok": False, "skipped": True, "reason": "route inspect failed"}
        # 只比较 path：getCurrentPages() 返回的 route 不含 query，
        # 而调用方传进来的 target 常常带参数（如 `pages/web?url=...`）。
        target_path = self.normalize_miniapp_route(target).split("?", 1)[0]
        final_path = self.normalize_miniapp_route(final_route).split("?", 1)[0]
        landed_on_target = bool(target_path) and final_path == target_path
        payload: JsonDict = {
            "ok": bool(jump.get("ok")) and bool(after.get("ok")) and landed_on_target,
            "action": method,
            "target_route": target,
            "final_route": final_route,
            "landedOnTarget": landed_on_target,
            "is_tabbar": bool(is_tabbar),
            "guard_requested": bool(guard),
            "before": _slim_route_table(before),
            "jump": jump_value,
            "after": _slim_route_table(after),
            "blocked_redirects_delta": after_blocked - before_blocked,
            "rehook": _slim_rehook(rehook),
            "uploadIndicators": upload_indicators,
            "bouncedToLogin": self.detect_route_bounce(
                target,
                final_route,
                guard_enabled=guard_enabled,
                before_blocked=before_blocked,
                after_blocked=after_blocked,
            ),
        }
        if verbose:
            # 只有显式要完整版时才回大对象 —— 默认路径必须保持小返回体。
            payload["beforeFull"] = before
            payload["afterFull"] = after
            payload["rehookFull"] = rehook
            payload["verboseNote"] = (
                "已按 verbose=true 回传 before/after 的**完整路由表**与 rehook 明细，"
                "返回体会显著变大，注意别把上下文挤爆。"
            )
        if not landed_on_target:
            payload["hint"] = (
                f"最终路由是 {final_route or '(空)'}，不是目标 {target}。"
                "常见原因：页面被守卫弹回、登录态缺失被重定向到登录页、"
                "或 target 不在 pages 注册表里（可先 route_ops(action='inspect_routes') 核对）。"
            )
        return payload

    def detect_route_bounce(
        self,
        target_route: str,
        final_route: str,
        *,
        guard_enabled: bool,
        before_blocked: int,
        after_blocked: int,
    ) -> bool:
        """判断目标页是否在跳转后弹回登录或其他非目标页。"""
        target = self.normalize_miniapp_route(target_route)
        final = self.normalize_miniapp_route(final_route)
        if not final:
            return False
        if LOGIN_ROUTE_RE.search(final):
            return True
        if target and final != target:
            guard_blocked = bool(guard_enabled) and int(after_blocked) > int(before_blocked)
            return not guard_blocked
        return False

    @staticmethod
    def normalize_miniapp_route(route: str) -> str:
        """标准化小程序路由，去掉前导斜杠和空白。"""
        return str(route or "").strip().lstrip("/")

    async def page_stack_depth(self) -> int | None:
        """读取当前页面栈深度；读不到返回 None。"""
        expr = (
            "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "try{var p=(typeof g.getCurrentPages==='function')?g.getCurrentPages():[];"
            "return p.length;}catch(e){return -1;}})()"
        )
        try:
            if self.selected_appservice_context_id is not None:
                result = await self.runtime_eval(expr, context_id=self.selected_appservice_context_id)
            else:
                result = await self.runtime_eval(expr, session_id=None)
        except Exception:
            return None
        value = result.get("value") if isinstance(result, dict) else None
        return int(value) if isinstance(value, int) and value >= 0 else None

    async def navigate_back(self, *, delta: int = 1, wait_ms: int = 1200) -> JsonDict:
        """回退页面栈（wx.navigateBack）；此前只能自己拼原语。

        `ok` 以**路由是否真的变化**为准，而不是「API 被调用了」——
        `wx.navigateBack` 在页面栈首层会静默失败，只报 called 会造成假成功。
        """
        before = await self.current_route()
        depth_before = await self.page_stack_depth()
        steps = max(1, int(delta or 1))
        expr = (
            "(function(){const g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            f"try{{if(g.wx&&typeof g.wx.navigateBack==='function'){{g.wx.navigateBack({{delta:{steps}}});"
            f"return {{ok:true,api:'wx.navigateBack',delta:{steps}}};}}"
            "if(g.history&&typeof g.history.back==='function'){g.history.back();return {ok:true,api:'history.back',delta:1};}"
            "return {ok:false,error:'当前环境没有可用的回退 API'};}catch(e){return {ok:false,error:String(e)}}})()"
        )
        result = await self.eval_appservice_script(expr)
        value = result.get("value") if isinstance(result, dict) else None
        delay = min(max(int(wait_ms or 0), 0), 10_000) / 1000
        if delay:
            await asyncio.sleep(delay)
        stability = await self.wait_route_stable(timeout_seconds=10, settle_seconds=2.0)
        after = str(stability.get("route") or "")
        moved = bool(before and after and before != after)
        payload: JsonDict = {
            "ok": moved,
            "beforeRoute": before,
            "afterRoute": after,
            "moved": moved,
            "pageStackDepthBefore": depth_before,
            "jump": value,
            "stability": stability,
            "raw": result,
        }
        if not moved:
            reasons: list[str] = []
            if depth_before is not None and depth_before <= 1:
                reasons.append(f"当前页面栈只有 {depth_before} 页，已在首层，wx.navigateBack 会失败")
            if not before:
                reasons.append("回退前就没读到路由，可能 appservice 上下文不可用")
            payload["hint"] = (
                "路由未发生变化，因此 ok=false。"
                + ("原因：" + "；".join(reasons) + "。" if reasons else "")
                + "若确实需要回退，请先用 route_ops(action='navigate_route') 进入子页面。"
            )
        return payload

    async def debugger_ops(self, action: str, **kwargs: Any) -> str:
        """执行源码、断点、调用栈和 WebSocket 类 MCP 操作。"""
        action = str(action or "")
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return json_text(cdp_state)
        if action == "list_scripts":
            return json_text(
                await self.list_scripts(
                    str(kwargs.get("url_filter") or kwargs.get("urlFilter") or ""),
                    named_only=bool(kwargs.get("named_only", False)),
                    limit=int(kwargs.get("limit") or 300),
                )
            )
        if action == "get_script_source":
            raw_length = kwargs.get("length")
            return json_text(
                await self.get_script_source(
                    script_id=kwargs.get("script_id") or kwargs.get("scriptId"),
                    url=kwargs.get("url"),
                    offset=kwargs.get("offset"),
                    length=int(raw_length) if raw_length is not None else 2000,
                    start_line=kwargs.get("start_line") or kwargs.get("startLine"),
                    end_line=kwargs.get("end_line") or kwargs.get("endLine"),
                    full=bool(kwargs.get("full", False)),
                )
            )
        if action == "save_script_source":
            return json_text(await self.save_script_source(str(kwargs.get("file_path") or kwargs.get("filePath") or ""), script_id=kwargs.get("script_id") or kwargs.get("scriptId"), url=kwargs.get("url")))
        if action == "search_in_sources":
            return json_text(
                await self.search_in_sources(
                    str(kwargs.get("query") or ""),
                    case_sensitive=bool(kwargs.get("case_sensitive", False)),
                    is_regex=bool(kwargs.get("is_regex", False)),
                    max_results=int(kwargs.get("max_results") or 50),
                    url_filter=kwargs.get("url_filter") or kwargs.get("urlFilter"),
                    include_anonymous=bool(kwargs.get("include_anonymous", False)),
                    scope=str(kwargs.get("scope") or "miniapp"),
                )
            )
        if action == "evaluate_script":
            return json_text(await self.runtime_eval(str(kwargs.get("expression") or ""), await_promise=bool(kwargs.get("await_promise", True)), context_id=kwargs.get("context_id") or kwargs.get("contextId")))
        if action == "break_on_xhr":
            return json_text(await self.break_on_xhr(str(kwargs.get("url") or kwargs.get("pattern") or "")))
        if action == "set_breakpoint_on_text":
            return json_text(await self.set_breakpoint_on_text(str(kwargs.get("text") or kwargs.get("query") or "")))
        if action == "list_breakpoints":
            return json_text(await self.list_breakpoints())
        if action == "remove_breakpoints":
            return json_text(
                await self.remove_breakpoints(
                    url=str(kwargs.get("url") or ""),
                    breakpoint_id=str(kwargs.get("breakpoint_id") or kwargs.get("breakpointId") or ""),
                    all_breakpoints=bool(kwargs.get("all", kwargs.get("removeAll", True))),
                )
            )
        if action == "get_paused_info":
            return json_text(await self.get_paused_info())
        if action == "resume_execution":
            return json_text(await self.resume_execution())
        if action == "step":
            return json_text(await self.step(str(kwargs.get("kind") or kwargs.get("type") or "over")))
        if action == "get_websocket_messages":
            return json_text(await self.get_websocket_messages())
        return json_text(unknown_action_error("debugger_ops", action, DEBUGGER_ACTIONS))

    @staticmethod
    def annotate_analysis(payload: str, *, telemetry_skipped: int = 0) -> str:
        """把「已排除 N 条埋点」的信息注入 JSON 结果。

        否则调用方看到接口清单变短 / 签名面变 0，会误判成「没测到」。
        """
        if not telemetry_skipped:
            return payload
        try:
            data = json.loads(payload)
        except (TypeError, ValueError):
            return payload
        if not isinstance(data, dict):
            return payload
        data["telemetryExcluded"] = int(telemetry_skipped)
        data["telemetryHint"] = (
            f"已从风险面排除 {telemetry_skipped} 条埋点/遥测请求（kind=telemetry）。"
            f"它们会污染接口清单与签名面；如需包含请传 includeTelemetry=true。"
        )
        return json.dumps(data, ensure_ascii=False, indent=2)

    async def analysis_ops(self, action: str, **kwargs: Any) -> str:
        """执行接口资产、风险线索、重放计划和报告导出类 MCP 操作。"""
        action = str(action or "")
        # 分析层只看接口类请求：字体 / 图片 / data: 内联资源会淹没真实接口。
        # 默认再摘掉埋点/遥测 —— 实测一份 49 条请求的会话里 28 条是埋点，
        # 它把接口清单和签名面全部污染。要看埋点（例如查 PII 上报）传 includeTelemetry。
        include_telemetry = bool(kwargs.get("includeTelemetry") or kwargs.get("include_telemetry"))
        fetched = await self.get_all_requests(
            limit=int(kwargs.get("limit") or 500),
            exclude_static=True,
            exclude_telemetry=not include_telemetry,
        )
        requests = fetched.get("requests", [])
        telemetry_skipped = int(fetched.get("telemetrySkipped") or 0)

        payload: str
        if action == "get_api_inventory":
            payload = json_text(self.build_api_inventory(requests))
        elif action == "analyze_auth_surface":
            payload = json_text(self.analyze_auth_surface(requests))
        elif action == "find_idor_candidates":
            payload = json_text(self.find_idor_candidates(requests))
        elif action == "find_sensitive_data_exposure":
            payload = json_text(self.find_sensitive_data_exposure(requests))
        elif action == "find_payment_and_order_surfaces":
            payload = json_text(self.find_by_regex(requests, PAYMENT_RE, "payment_order"))
        elif action == "find_upload_surfaces":
            payload = json_text(self.find_by_regex(requests, UPLOAD_RE, "upload"))
        elif action == "find_debug_admin_surfaces":
            payload = json_text(self.find_by_regex(requests, DEBUG_ADMIN_RE, "debug_admin"))
        elif action == "find_sign_related_requests":
            payload = json_text(self.find_by_regex(requests, SIGN_RE, "sign_related"))
        elif action == "build_replay_plan":
            payload = json_text(await self.build_replay_plan(str(kwargs.get("request_id") or kwargs.get("requestId") or "")))
        elif action == "compare_two_requests":
            payload = json_text(await self.compare_two_requests(str(kwargs.get("request_id_a") or kwargs.get("requestIdA") or ""), str(kwargs.get("request_id_b") or kwargs.get("requestIdB") or "")))
        elif action == "passive_param_fuzz_suggestions":
            payload = json_text(self.passive_param_fuzz_suggestions(requests))
        elif action == "generate_security_notes":
            payload = json_text(self.generate_security_notes(requests, max_length=int(kwargs.get("maxLength") or 80_000)))
        elif action == "generate_api_table_markdown":
            # 这个是纯 Markdown，不能注 JSON 字段，直接在末尾追加说明
            table = self.generate_api_table_markdown(requests, max_length=int(kwargs.get("maxLength") or 80_000))
            if telemetry_skipped:
                table += (
                    f"\n\n> 已排除 {telemetry_skipped} 条埋点/遥测请求（kind=telemetry）。"
                    f"如需包含请传 includeTelemetry=true。\n"
                )
            return table
        elif action == "export_session":
            payload = json_text(await self.export_session(requests))
        else:
            return json_text(unknown_action_error("analysis_ops", action, ANALYSIS_ACTIONS))
        return self.annotate_analysis(payload, telemetry_skipped=telemetry_skipped)

    async def decrypt_ops(self, action: str, **kwargs: Any) -> str:
        """执行编码识别、解码、解密和运行时加密函数发现。"""
        action = str(action or "")
        value = str(kwargs.get("value") or "")
        if action == "auto_detect_encoding":
            return json_text(auto_detect_encoding(value))
        if action in {"decode_payload", "decode_base64"}:
            encoding = "base64" if action == "decode_base64" else str(kwargs.get("input_encoding") or kwargs.get("encoding") or "auto")
            return json_text(decode_payload(value, encoding))
        if action == "decrypt_payload":
            return json_text(decrypt_payload(value, algorithm=str(kwargs.get("algorithm") or "aes"), key=str(kwargs.get("key") or ""), mode=str(kwargs.get("mode") or "cbc"), iv=str(kwargs.get("iv") or ""), input_encoding=str(kwargs.get("input_encoding") or "base64"), key_encoding=str(kwargs.get("key_encoding") or "utf-8"), iv_encoding=str(kwargs.get("iv_encoding") or "utf-8")))
        if action == "run_decrypt_pipeline":
            return json_text(await self.run_decrypt_pipeline(value, kwargs.get("steps") or []))
        if action == "detect_ecb_pattern":
            return json_text(detect_ecb_pattern(value, str(kwargs.get("input_encoding") or "base64")))
        if action == "discover_runtime_crypto_functions":
            return json_text(await self.discover_runtime_crypto_functions())
        if action == "call_runtime_crypto_function":
            return json_text(await self.call_runtime_crypto_function(str(kwargs.get("function_name") or kwargs.get("functionName") or ""), kwargs.get("args") or []))
        return json_text(unknown_action_error("decrypt_ops", action, DECRYPT_ACTIONS))

    async def reverse_ops(self, action: str, **kwargs: Any) -> str:
        """执行逆向案例匹配、加密模式识别和策略建议。"""
        action = str(action or "detect_reverse_strategy")
        text = str(kwargs.get("text") or kwargs.get("source") or "")
        if action == "identify_crypto_pattern":
            return json_text(identify_crypto_pattern(text))
        if action == "match_reverse_cases":
            return json_text(self.match_reverse_cases(text))
        if action == "detect_reverse_strategy":
            return json_text(self.detect_reverse_strategy(text))
        return json_text(unknown_action_error("reverse_ops", action, REVERSE_ACTIONS))

    async def replay_ops(self, action: str, **kwargs: Any) -> str:
        """执行安全重放任务管理；默认只生成计划，不自动发送写请求。"""
        action = str(action or "")
        if action == "start_auto_replay":
            request_id = str(kwargs.get("request_id") or kwargs.get("requestId") or "")
            plan = await self.build_replay_plan(request_id)
            job_id = f"replay-{int(time.time() * 1000)}"
            self.jobs[job_id] = {"id": job_id, "type": "replay", "status": "planned", "plan": plan, "createdAt": now_iso()}
            return json_text(self.jobs[job_id])
        if action == "get_replay_job":
            return json_text(self.jobs.get(str(kwargs.get("job_id") or kwargs.get("jobId") or ""), {"ok": False, "error": "job not found"}))
        return json_text(unknown_action_error("replay_ops", action, REPLAY_ACTIONS))

    async def pentest_ops(self, action: str, **kwargs: Any) -> str:
        """执行主动扫描任务管理；当前仅记录授权扫描计划并保持任务隔离。"""
        action = str(action or "")
        if action == "start_pentest_scan":
            job_id = f"pentest-{int(time.time() * 1000)}"
            self.jobs[job_id] = {"id": job_id, "type": "pentest", "status": "queued", "scope": kwargs.get("scope") or "current-session", "createdAt": now_iso(), "note": "主动验证请在授权环境按生成计划逐项执行"}
            return json_text(self.jobs[job_id])
        if action == "get_pentest_job":
            return json_text(self.jobs.get(str(kwargs.get("job_id") or kwargs.get("jobId") or ""), {"ok": False, "error": "job not found"}))
        if action == "list_pentest_jobs":
            return json_text([job for job in self.jobs.values() if job.get("type") == "pentest"])
        return json_text(unknown_action_error("pentest_ops", action, PENTEST_ACTIONS))

    async def status(self) -> JsonDict:
        """汇总 MCP、CDP、缓存、target session 和上下文状态。

        不做自动连接（它本身是探针），但会在未连接时给出明确指引，
        避免调用方误判成「工具坏了」。
        """
        cdp_status = self.cdp.status()
        result: JsonDict = {
            "ok": True,
            "cdp": cdp_status,
            "selectedAppserviceContextId": self.selected_appservice_context_id,
            "selectedTargetId": self.page_target_id,
            "pageSessionId": self.page_session_id,
            "appserviceMode": "runtime_context" if self.selected_appservice_context_id is not None else ("frames_bridge" if self.appservice_bridge_frame else None),
            "requestCount": len(self.requests),
            "scriptCount": len(self.scripts),
            "contextCount": len(self.contexts),
        }
        if not cdp_status.get("connected"):
            result["hint"] = (
                "CDP 尚未连接（这不代表工具坏了）。任何依赖 CDP 的工具现在会自动连接一次；"
                "若持续失败，请确认 62000 在监听、`02-一键启动.bat` 已跑完、且小程序是在启动之后打开的。"
            )
        return result

    async def connect_wmpf(self, ws_url: str | None = None, *, force: bool = False) -> JsonDict:
        """连接本机 WMPF/CDP，并注册 Network/Runtime/Debugger 事件。

        **链路卡死时自动重建**：若已连接但存在未响应的堆积调用（`pendingCalls > 0`），
        说明这条 CDP 连接已经收不到回应了 —— 此时旧实现会因 `is_connected()` 仍为真而
        `reused: true` 直接返回、什么都不做，**恢复路径变成死胡同**（实测踩过：
        只能重启整个 MCP 服务，代价是丢掉已采集的流量）。

        现在这种情形会**自动重建连接**并在返回里说明原因；也可以传 `force=True` 无条件重建。
        重建会丢弃那些本就不会返回的调用 —— 它们早已失效，丢掉不损失有效结果。
        """
        stale_pending = len(self.cdp.pending)
        wedged = self.cdp.is_connected() and stale_pending > 0
        rebuild = bool(force) or wedged
        result = await self.cdp.connect(ws_url or DEFAULT_WS_URL, force=rebuild)
        await self._enable_domains(force=True)
        payload: JsonDict = {"ok": True, **result, "status": await self.status()}
        if wedged and not force:
            payload["rebuiltBecause"] = "pending_calls"
            payload["droppedPendingCalls"] = stale_pending
            payload["note"] = (
                f"原连接有 {stale_pending} 个未响应的 CDP 调用，判定为链路卡死，已自动重建连接。"
                "这些调用本来也不会返回，重建不会损失有效结果；"
                "**进程内已采集的请求记录不受影响**（`requestCount` 保留），"
                "但 appservice context / page session 需要重新选一次（`connection_ops(action=\"find_appservice\")`）。"
            )
        elif force:
            payload["rebuiltBecause"] = "force"
            payload["droppedPendingCalls"] = stale_pending
        return payload

    async def ensure_cdp(self) -> JsonDict:
        """确保 CDP 已连接并已启用必要 domain；未连接时自动连一次。

        这样调用方不必先记得调 `connect_wmpf`——直接调任何工具都能用。
        失败时返回结构化错误 + 指引，而不是让异常冒到 MCP 层变成不透明报错。
        """
        if self.cdp.is_connected():
            await self._enable_domains(force=False)
            return {"ok": True, "reused": True, "connectionId": self.cdp.connection_id}
        try:
            result = await self.cdp.connect(DEFAULT_WS_URL)
        except Exception as exc:
            return {
                "ok": False,
                "stage": "connect_wmpf",
                "wsUrl": DEFAULT_WS_URL,
                "error": str(exc),
                "hint": (
                    "CDP 未连接且自动连接失败。检查："
                    "① `02-一键启动.bat` 是否跑完；"
                    "② 62000 是否在监听（`03-检测依赖.bat` 的「运行中端口」）；"
                    "③ 小程序是否是在启动之后才打开的。"
                ),
            }
        await self._enable_domains(force=True)
        return {"ok": True, **result}

    def _register_listeners(self) -> None:
        """注册 CDP 事件监听（整个进程只注册一次，重复注册会让事件被处理多次）。"""
        if self._listeners_registered:
            return
        for method in ("Network.requestWillBeSent", "Network.requestWillBeSentExtraInfo", "Network.responseReceived", "Network.responseReceivedExtraInfo", "Network.loadingFinished", "Network.loadingFailed", "Network.webSocketCreated", "Network.webSocketFrameSent", "Network.webSocketFrameReceived", "Network.webSocketClosed"):
            self.cdp.on(method, self._on_network_event)
        self.cdp.on("Runtime.executionContextCreated", self._on_execution_context_created)
        self.cdp.on("Runtime.executionContextDestroyed", self._on_execution_context_destroyed)
        self.cdp.on("Runtime.consoleAPICalled", self._on_console_event)
        self.cdp.on("Runtime.exceptionThrown", self._on_console_event)
        self.cdp.on("Debugger.scriptParsed", self._on_script_parsed)
        self.cdp.on("Debugger.paused", self._on_console_event)
        self._listeners_registered = True

    async def _enable_domains(self, *, force: bool = False) -> None:
        """按当前连接启用 Runtime / Network / Debugger。

        注意顺序：先在浏览器层 enable（page-frame 求值依赖它），
        再 attach 页面 target 并在**那个 session 里** enable —— 只有后者才会推送
        小程序的 `Runtime.executionContextCreated`，这是 appservice 上下文能被发现的前提。

        断线重连会拿到新的连接代数，此时必须重发 enable，否则事件静默停推。
        """
        self._register_listeners()
        generation = self.cdp.connection_id
        if not force and generation == self._domain_connection_id:
            return
        self._domain_connection_id = generation
        # 换连接后旧的 context id 全部失效
        self.contexts.clear()
        self.context_sessions.clear()
        self.page_session_id = None
        self.selected_appservice_context_id = None
        with IgnoreOptionalCdpError():
            await self.cdp.send("Runtime.enable", timeout_ms=5000)
        with IgnoreOptionalCdpError():
            await self.cdp.send("Debugger.enable", timeout_ms=5000)
        with IgnoreOptionalCdpError():
            await self.cdp.send("Network.enable", timeout_ms=5000)
        with IgnoreOptionalCdpError():
            await self.ensure_page_session()
        # Debugger 与 Network 都必须**按 session** 生效：
        # 在浏览器层 enable 只会「成功但收不到任何事件」——实测表现为
        # requestCount 恒为 0（只看到 wx.request 钩子的流量，漏掉 webview 的 fetch/XHR、
        # 框架自身请求、响应体与 WebSocket 帧）。断点同理，发在浏览器层不会命中。
        if self.page_session_id:
            with IgnoreOptionalCdpError():
                await self.cdp.send("Debugger.enable", timeout_ms=5000, session_id=self.page_session_id)
            with IgnoreOptionalCdpError():
                await self.cdp.send("Network.enable", timeout_ms=5000, session_id=self.page_session_id)

    def debugger_session_id(self) -> str | None:
        """返回 Debugger 命令该用的 session（页面 session，拿不到时退回 None）。"""
        return self.page_session_id

    async def ensure_runtime_enabled(self) -> None:
        """确保 Runtime domain 已启用（含页面 session attach）。"""
        await self._enable_domains(force=False)

    async def list_targets_raw(self) -> list[JsonDict]:
        """读取 CDP Target.getTargets 的原始 targetInfos。"""
        response = await self.cdp.send("Target.getTargets", timeout_ms=8000)
        infos = response.get("result", {}).get("targetInfos", [])
        return [item for item in infos if isinstance(item, dict)] if isinstance(infos, list) else []

    @staticmethod
    def score_target(target: JsonDict) -> int:
        """给 target 打分，用于判断哪个更像「当前小程序的页面/逻辑层」。"""
        kind = str(target.get("type") or "").lower()
        url = str(target.get("url") or "")
        title = str(target.get("title") or "")
        score = 0
        if kind == "page":
            score += 10
        elif kind == "webview":
            score += 6
        elif kind == "worker":
            score += 2
        if re.search(r"appservice|app-service|logic", url, re.I):
            score += 30
        if re.search(r"wx[0-9a-f]{16}", url, re.I) or re.search(r"wx[0-9a-f]{16}", title, re.I):
            score += 8
        if re.search(r"miniapp|__APP__|pages/|\.html|\.js", url, re.I):
            score += 3
        if str(target.get("attached") or "").lower() == "true":
            score -= 2
        return score

    @staticmethod
    def classify_target(target: JsonDict) -> str:
        """给 target 一个可读角色标签，补足 worker 类型 url/title 为空的问题。"""
        kind = str(target.get("type") or "").lower()
        url = str(target.get("url") or "")
        if re.search(r"appservice|app-service|logic", url, re.I):
            return "appservice"
        if kind == "page":
            return "page"
        if kind == "webview":
            return "webview"
        if kind == "worker":
            return "worker"
        if kind == "service_worker":
            return "service_worker"
        return kind or "unknown"

    async def ensure_page_session(self, *, force: bool = False) -> JsonDict:
        """确保已 attach 到当前小程序的页面 target，并拿到 flatten sessionId。"""
        if self.page_session_id and not force:
            return {"ok": True, "sessionId": self.page_session_id, "targetId": self.page_target_id, "reused": True}

        # 必须先把 CDP 连上 —— 否则冷启动第一次调用会直接报
        # 「CDP WebSocket 不可用」并降级到 frames 桥（实测：`find_appservice` 少这一步，
        # 冷启动首次必然降级，第二次才正常）。`ensure_cdp` 幂等，已连接时开销可忽略。
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return {"ok": False, "stage": "ensure_cdp", "error": cdp_state.get("error") or "CDP 未连接"}

        try:
            targets = await self.list_targets_raw()
        except Exception as exc:
            return {"ok": False, "stage": "getTargets", "error": str(exc)}

        if not targets:
            return {"ok": False, "stage": "getTargets", "error": "Target.getTargets 未返回任何 target，请确认小程序已打开"}

        ranked = sorted(targets, key=self.score_target, reverse=True)
        chosen = ranked[0]
        if self.score_target(chosen) <= 0:
            return {
                "ok": False,
                "stage": "pick",
                "error": "没有找到像小程序的 target（type=page / url 含 appservice）",
                "targets": targets,
            }

        target_id = str(chosen.get("targetId") or "")
        try:
            attached = await self.cdp.send("Target.attachToTarget", {"targetId": target_id, "flatten": True}, timeout_ms=10000)
        except Exception as exc:
            return {"ok": False, "stage": "attachToTarget", "targetId": target_id, "error": str(exc)}

        session_id = str(attached.get("result", {}).get("sessionId") or "")
        if not session_id:
            return {"ok": False, "stage": "attachToTarget", "targetId": target_id, "error": "attachToTarget 未返回 sessionId", "raw": attached}

        self.page_session_id = session_id
        self.page_target_id = target_id
        # 在页面 session 里 enable Runtime —— 这是能收到 executionContextCreated 的关键
        with IgnoreOptionalCdpError():
            await self.cdp.send("Runtime.enable", timeout_ms=5000, session_id=session_id)
        await asyncio.sleep(0.4)
        return {
            "ok": True,
            "sessionId": session_id,
            "targetId": target_id,
            "targetUrl": chosen.get("url"),
            "role": self.classify_target(chosen),
            "reused": False,
            "contextCount": len(self.contexts),
        }

    async def wait_for_contexts(self, timeout_seconds: float = 2.0) -> int:
        """等待 executionContextCreated 事件落地，返回当前 context 数量。"""
        deadline = time.time() + max(0.0, float(timeout_seconds))
        while time.time() < deadline:
            if self.contexts:
                return len(self.contexts)
            await asyncio.sleep(0.1)
        return len(self.contexts)

    async def ensure_appservice_bridge(self) -> JsonDict:
        """在 page-frame 里定位 appservice frame 并缓存为 window.__as。

        这是 `select_appservice_context` 失败时的兜底路径：
        小程序界面是原生渲染，page-frame 没有 DOM；但 page-frame 的
        `window.frames` 里能找到同时有 `wx` 与 `__wxConfig` 的那一帧。
        跨 frame **不能调用 `__as.eval`**，只能做属性访问。
        """
        finder = r"""
(()=>{
  const cached = window.__as;
  if (cached && typeof cached.getCurrentPages === 'function' && cached.__wxConfig) {
    return {ok:true, cached:true, appId:String(cached.__wxConfig&&cached.__wxConfig.appId||'')};
  }
  function find(w, depth){
    if (depth > 6) return null;
    try { if (typeof w.wx === 'object' && w.wx && typeof w.__wxConfig === 'object' && w.__wxConfig) return w; } catch(e){}
    let frames = [];
    try { frames = w.frames || []; } catch(e){ frames = []; }
    for (let i = 0; i < frames.length; i++){
      try { const r = find(frames[i], depth + 1); if (r) return r; } catch(e){}
    }
    return null;
  }
  const as = find(window, 0);
  if (!as) return {ok:false, error:'未找到同时具备 wx 与 __wxConfig 的 frame'};
  window.__as = as;
  return {ok:true, cached:false, appId:String(as.__wxConfig&&as.__wxConfig.appId||''), route:String(as.__wxRoute||'')};
})()
"""
        result = await self.runtime_eval(finder, await_promise=True, session_id=None)
        value = result.get("value") if isinstance(result, dict) else None
        if isinstance(value, dict) and value.get("ok"):
            self.appservice_bridge_frame = str(value.get("appId") or "bridge")
            return {"ok": True, "mode": "frames_bridge", **value}
        return {"ok": False, "mode": "frames_bridge", "error": (value or {}).get("error") or result.get("exception") or "桥注入失败", "raw": result}

    @staticmethod
    def bridge_wrap(expression: str) -> str:
        """把一段引用 wx / getCurrentPages 的表达式改写成走 window.__as 桥。

        跨 frame 不能 eval，所以这里只做「把 appservice 的全局对象绑成局部变量」，
        表达式本身的逻辑不变。
        """
        return (
            "(()=>{"
            "const __AS=(typeof window!=='undefined')?window.__as:null;"
            "if(!__AS)return {__bridge:false,error:'window.__as 不可用，请先 select_appservice_context'};"
            "const wx=__AS.wx, getCurrentPages=__AS.getCurrentPages, getApp=__AS.getApp, "
            "__wxConfig=__AS.__wxConfig, __wxRoute=__AS.__wxRoute;"
            f"return ({expression});"
            "})()"
        )

    async def ensure_network_enabled(self) -> None:
        """确保 Network domain 已启用（CDP 未连接时会自动连接）。"""
        info = await self.ensure_cdp()
        if not info.get("ok"):
            raise RuntimeError(str(info.get("error") or "CDP 不可用"))

    async def ensure_debugger_enabled(self) -> None:
        """确保 Debugger domain 已启用（CDP 未连接时会自动连接）。"""
        await self.ensure_runtime_enabled()

    async def list_targets(self) -> JsonDict:
        """列出 CDP Target 信息，并补足可读的角色/名称元数据。

        原始 `Target.getTargets` 里大量 worker 的 `url` / `title` 为空，
        无法判断哪个是当前小程序的 appservice。这里补 `name` / `role` / `score` /
        `isAppservice`，并给出 `recommendedTargetId`，避免逐个探测导致超时。
        """
        targets = await self.list_targets_raw()
        enriched: list[JsonDict] = []
        for item in targets:
            role = self.classify_target(item)
            url = str(item.get("url") or "")
            title = str(item.get("title") or "")
            name = str(item.get("name") or title or url or "").strip()
            if not name:
                name = f"{role}-{str(item.get('targetId') or '')[:8]}"
            enriched.append(
                {
                    **item,
                    "name": name,
                    "role": role,
                    "score": self.score_target(item),
                    "isAppservice": role == "appservice",
                    "hasMetadata": bool(url or title),
                }
            )
        enriched.sort(key=lambda entry: int(entry.get("score") or 0), reverse=True)
        blank = sum(1 for entry in enriched if not entry.get("hasMetadata"))
        result: JsonDict = {
            "ok": True,
            "count": len(enriched),
            "targets": enriched,
            "recommendedTargetId": enriched[0].get("targetId") if enriched else None,
            "pageSessionId": self.page_session_id,
        }
        if blank:
            result["note"] = (
                f"其中 {blank} 个 target 的 url/title 为空（多为 worker），"
                "请优先用 role / isAppservice / score 判断，或直接调用 "
                'connection_ops(action="find_appservice")。'
            )
        return result

    async def find_appservice(self) -> JsonDict:
        """一步到位：定位当前小程序的 appservice（target + Runtime context）。"""
        session = await self.ensure_page_session(force=True)
        await self.wait_for_contexts(1.5)
        context = await self.select_appservice_context()
        targets = await self.list_targets_raw()
        return {
            "ok": bool(session.get("ok")) or bool(context.get("ok")),
            "targetId": self.page_target_id,
            "sessionId": self.page_session_id,
            "selectedContextId": self.selected_appservice_context_id,
            "mode": context.get("mode"),
            "session": session,
            "context": context,
            "targetCount": len(targets),
        }

    async def switch_target(self, target_id: str) -> JsonDict:
        """attach 到指定 target 并把它设为当前页面 session。"""
        if not target_id:
            return {"ok": False, "error": "target_id 不能为空"}
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return {"ok": False, "targetId": target_id, "stage": "ensure_cdp", "error": cdp_state.get("error") or "CDP 未连接"}
        try:
            attached = await self.cdp.send("Target.attachToTarget", {"targetId": target_id, "flatten": True}, timeout_ms=10000)
        except Exception as exc:
            return {"ok": False, "targetId": target_id, "error": str(exc)}
        session_id = str(attached.get("result", {}).get("sessionId") or "")
        if not session_id:
            return {"ok": False, "targetId": target_id, "error": "attachToTarget 未返回 sessionId", "raw": attached}
        self.selected_target_id = target_id
        self.page_target_id = target_id
        self.page_session_id = session_id
        self.contexts.clear()
        self.context_sessions.clear()
        with IgnoreOptionalCdpError():
            await self.cdp.send("Runtime.enable", timeout_ms=5000, session_id=session_id)
        await asyncio.sleep(0.4)
        return {"ok": True, "selectedTargetId": target_id, "sessionId": session_id, "contextCount": len(self.contexts)}

    async def select_appservice_context(self, *, force: bool = False) -> JsonDict:
        """自动选择 appservice 的 Runtime context；失败时回退到 frames 桥。

        分三级：
          1) attach 页面 target 并在该 session 里 enable Runtime，等
             `executionContextCreated`，逐个探测打分；
          2) 拿不到 context 时强制重新 attach 再试一次；
          3) 仍然失败，退回 `window.frames` 遍历 + `window.__as` 桥（page-frame 侧驱动）。
        """
        diagnostics: JsonDict = {"stages": []}
        if force:
            self.page_session_id = None
            self.contexts.clear()
            self.context_sessions.clear()

        await self.ensure_runtime_enabled()
        session_info = await self.ensure_page_session(force=force)
        diagnostics["stages"].append({"name": "ensure_page_session", "result": session_info})

        if not session_info.get("ok"):
            diagnostics["hint"] = "页面 target attach 失败：可能小程序未打开，或 CDP 代理未连上 62000。"
        else:
            await self.wait_for_contexts(1.5)

        if not self.contexts and session_info.get("ok"):
            # 兜底再 attach 一次：Runtime.enable 可能早于页面脚本注入，事件会漏
            retry = await self.ensure_page_session(force=True)
            diagnostics["stages"].append({"name": "ensure_page_session_retry", "result": retry})
            await self.wait_for_contexts(1.5)

        probes: list[JsonDict] = []
        probe_expr = (
            "(()=>({hasWx:typeof wx!=='undefined',hasRequire:typeof require!=='undefined',"
            "hasPages:typeof getCurrentPages!=='undefined',"
            "appId:(typeof __wxConfig!=='undefined'&&__wxConfig&&__wxConfig.appId)||'',"
            "route:(typeof __wxRoute!=='undefined'&&__wxRoute)||''}))()"
        )
        for context_id in list(self.contexts.keys()):
            probe = await self.runtime_eval(probe_expr, context_id=context_id)
            value = probe.get("value") if isinstance(probe, dict) else None
            score = 0
            if isinstance(value, dict):
                score = (4 if value.get("hasWx") else 0) + (3 if value.get("hasRequire") else 0) + (3 if value.get("hasPages") else 0)
            probes.append({"contextId": context_id, "score": score, "sessionId": self.context_sessions.get(context_id), "probe": value})
        diagnostics["stages"].append({"name": "probe_contexts", "contextCount": len(self.contexts), "probes": probes})

        if probes:
            probes.sort(key=lambda item: int(item.get("score") or 0), reverse=True)
            best = probes[0]
            if int(best.get("score") or 0) > 0:
                self.selected_appservice_context_id = int(best["contextId"])
                return {
                    "ok": True,
                    "mode": "runtime_context",
                    "selectedContextId": self.selected_appservice_context_id,
                    "selectedSessionId": best.get("sessionId"),
                    "probes": probes,
                    "diagnostics": diagnostics,
                }

        # 第三级：frames 桥兜底
        bridge = await self.ensure_appservice_bridge()
        diagnostics["stages"].append({"name": "ensure_appservice_bridge", "result": bridge})
        if bridge.get("ok"):
            self.selected_appservice_context_id = None
            return {
                "ok": True,
                "mode": "frames_bridge",
                "selectedContextId": None,
                "bridge": bridge,
                "probes": probes,
                "diagnostics": diagnostics,
                "note": (
                    "已回退到 page-frame 桥（window.__as）。此后 runtime_eval_appservice / hook_* "
                    "会自动走该桥；跨 frame 不能 eval，只支持属性访问与函数调用。"
                ),
            }

        return {
            "ok": False,
            "error": "未发现 Runtime context，且 frames 桥也未能建立",
            "mode": "failed",
            "probes": probes,
            "diagnostics": diagnostics,
            "howToFix": [
                "1) 确认小程序是在 02-一键启动.bat 之后才打开的（hook 只对之后加载的小程序生效）",
                "2) 用 connection_ops(action=\"list_targets\") 看是否有 type=page / role=appservice 的 target",
                "3) 若 target 存在但 context 为空，调用 connection_ops(action=\"find_appservice\") 强制重挂",
                "4) 仍失败时按 SKILL.md 的「select_appservice_context 失败时的 fallback 流程」走 window.__as 桥",
            ],
        }

    async def runtime_eval(self, expression: str, *, await_promise: bool = True, context_id: Any = None, session_id: Any = None) -> JsonDict:
        """执行 Runtime.evaluate 并清理 CDP 结果结构。

        给了 `context_id` 就带上，并从 context 反查它所属的 flatten session。
        不带 session 的 appservice 求值会落到浏览器层，表现为 `Uncaught`。
        """
        await self.ensure_cdp()
        params: JsonDict = {"expression": expression, "returnByValue": True, "awaitPromise": bool(await_promise)}
        target_session = str(session_id) if session_id else None
        if context_id not in {None, ""}:
            try:
                resolved_id: int | None = int(context_id)
            except (TypeError, ValueError):
                resolved_id = None
            if resolved_id is not None:
                params["contextId"] = resolved_id
                target_session = target_session or self.context_sessions.get(resolved_id)
        response = await self.cdp.send("Runtime.evaluate", params, timeout_ms=15000, session_id=target_session)
        result_root = response.get("result", {})
        result = result_root.get("result", {})
        if result_root.get("exceptionDetails"):
            return {"ok": False, "exception": result_root.get("exceptionDetails"), "sessionId": target_session, "raw": response}
        return {"ok": True, "type": result.get("type"), "value": result.get("value"), "description": result.get("description"), "sessionId": target_session}

    async def runtime_eval_appservice(self, expression: str) -> JsonDict:
        """在 appservice 里求值；有 Runtime context 就用 context，否则自动走 frames 桥。"""
        if self.selected_appservice_context_id is not None:
            result = await self.runtime_eval(expression, context_id=self.selected_appservice_context_id)
            if result.get("ok"):
                return {**result, "mode": "runtime_context"}
            # context 已失效（页面切换后常见）→ 重新发现，再退回桥
            reselected = await self.select_appservice_context(force=True)
            if reselected.get("ok") and self.selected_appservice_context_id is not None:
                return {**await self.runtime_eval(expression, context_id=self.selected_appservice_context_id), "mode": "runtime_context"}
        bridge = await self.ensure_appservice_bridge()
        if not bridge.get("ok"):
            return {"ok": False, "stage": "bridge", "error": bridge}
        result = await self.runtime_eval(self.bridge_wrap(expression), session_id=None)
        value = result.get("value") if isinstance(result, dict) else None
        if isinstance(value, dict) and value.get("__bridge") is False:
            return {"ok": False, "stage": "bridge", "error": value.get("error") or "window.__as 不可用", "raw": result}
        return {**result, "mode": "frames_bridge"}

    async def eval_appservice_script(self, script: str) -> JsonDict:
        """执行一段「自带全局解析」的 appservice 脚本。

        脚本内部用 `const g=(window.__as||globalThis)` 自行解析全局对象，
        因此无论走 Runtime context 还是走 frames 桥都能命中真正的 appservice。

        返回值里的对象字段会被**提升到顶层** —— 见 `promote_eval_value`。
        """
        if self.selected_appservice_context_id is None:
            selected = await self.select_appservice_context()
            if not selected.get("ok"):
                return {"ok": False, "stage": "select_appservice_context", "error": selected}
        if self.selected_appservice_context_id is not None:
            return self.promote_eval_value(await self.runtime_eval(script, context_id=self.selected_appservice_context_id))
        # 桥模式：脚本自己在 page-frame 里取 window.__as
        return self.promote_eval_value(await self.runtime_eval(script, session_id=None))

    # `runtime_eval` 返回信封自带的键。提升时**必须避开**它们，
    # 否则内层的 `value` / `type` 会覆盖外层 —— 实测把
    # `call_runtime_crypto_function` 直接搞坏（它依赖 `value` 是对象，
    # 覆盖后变成字符串，报「求值未返回对象」）。
    EVAL_ENVELOPE_KEYS = frozenset({"ok", "type", "value", "description", "sessionId", "raw", "exception"})

    @classmethod
    def promote_eval_value(cls, result: JsonDict) -> JsonDict:
        """把求值结果里的对象字段提升到顶层（只提升不与信封键冲突的）。

        `hook_*` 脚本返回 `{hooked:true|false, error?}`，但原来只藏在 `value` 里，
        而顶层 `ok` 只表示「**求值**成功」—— `wx.request not found` 时 `ok` 仍是 true，
        调用方据此会误以为钩子装上了（实测踩过：`ok:true` 但 `hooked:false`）。
        提升后 `hooked` / `count` / `error` 可直接读。
        """
        if not isinstance(result, dict) or not result.get("ok"):
            return result
        value = result.get("value")
        if not isinstance(value, dict):
            return result
        promoted = {key: item for key, item in value.items() if key not in cls.EVAL_ENVELOPE_KEYS}
        return {**result, **promoted} if promoted else result

    @staticmethod
    def appservice_global_js() -> str:
        """返回脚本里用于解析 appservice 全局对象的片段。"""
        return "const g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"

    async def hook_wx_request(self) -> JsonDict:
        """在 appservice 中注入非破坏性 wx.request Hook。"""
        script = r"""
(function(){const g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;if(g.__MCP_WX_REQUEST_HOOKED__)return {hooked:true,reused:true,count:(g.__MCP_WX_REQUESTS__||[]).length};
g.__MCP_WX_REQUESTS__=[];const wxObj=g.wx;if(!wxObj||typeof wxObj.request!=='function')return {hooked:false,error:'wx.request not found'};
const raw=wxObj.request;wxObj.request=function(opts){const id='wx-'+Date.now()+'-'+Math.random().toString(16).slice(2);const rec={id,source:'wx',url:opts&&opts.url||'',method:(opts&&opts.method||'GET').toUpperCase(),requestHeaders:opts&&opts.header||{},requestBodyPreview:opts&&opts.data,callStack:(new Error()).stack,timestamp:new Date().toISOString()};g.__MCP_WX_REQUESTS__.push(rec);const next=Object.assign({},opts||{});const ok=next.success,fail=next.fail,done=next.complete;next.success=function(res){rec.statusCode=res&&res.statusCode;rec.responseHeaders=res&&res.header||{};rec.responseBodyPreview=res&&res.data;rec.finishedAt=new Date().toISOString();if(typeof ok==='function')return ok.apply(this,arguments)};next.fail=function(err){rec.error=String(err&&err.errMsg||err);rec.finishedAt=new Date().toISOString();if(typeof fail==='function')return fail.apply(this,arguments)};next.complete=function(res){rec.completed=true;if(typeof done==='function')return done.apply(this,arguments)};return raw.call(this,next)};g.__MCP_WX_REQUEST_HOOKED__=true;return {hooked:true,reused:false};})()
"""
        return await self.eval_appservice_script(script)

    async def hook_upload_apis(self) -> JsonDict:
        """在 appservice 中尽早注入 wx.uploadFile/chooseImage/chooseMedia Hook。"""
        script = r"""
(function(){const g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;if(g.__MCP_UPLOAD_HOOKED__)return {hooked:true,reused:true,count:(g.__MCP_UPLOAD_REQUESTS__||[]).length};
g.__MCP_UPLOAD_REQUESTS__=g.__MCP_UPLOAD_REQUESTS__||[];const wxObj=g.wx;if(!wxObj)return {hooked:false,error:'wx not found'};
const mk=(kind)=>kind+'-'+Date.now()+'-'+Math.random().toString(16).slice(2);
function copy(obj){try{return Object.assign({},obj||{})}catch(e){return {}}}
const hooks={};
if(typeof wxObj.uploadFile==='function'){const raw=wxObj.uploadFile;wxObj.uploadFile=function(opts){const id=mk('upload');const rec={id,source:'upload',api:'wx.uploadFile',url:opts&&opts.url||'',method:'POST',filePath:opts&&opts.filePath,name:opts&&opts.name,requestHeaders:opts&&opts.header||{},requestBodyPreview:opts&&opts.formData,callStack:(new Error()).stack,timestamp:new Date().toISOString()};g.__MCP_UPLOAD_REQUESTS__.push(rec);const next=Object.assign({},opts||{});const ok=next.success,fail=next.fail,done=next.complete;next.success=function(res){rec.statusCode=res&&res.statusCode;rec.responseHeaders=res&&res.header||{};rec.responseBodyPreview=res&&res.data;rec.finishedAt=new Date().toISOString();if(typeof ok==='function')return ok.apply(this,arguments)};next.fail=function(err){rec.error=String(err&&err.errMsg||err);rec.finishedAt=new Date().toISOString();if(typeof fail==='function')return fail.apply(this,arguments)};next.complete=function(res){rec.completed=true;if(typeof done==='function')return done.apply(this,arguments)};return raw.call(this,next)};hooks.uploadFile=true}
if(typeof wxObj.chooseImage==='function'){const raw=wxObj.chooseImage;wxObj.chooseImage=function(opts){const id=mk('chooseImage');const rec={id,source:'chooseImage',api:'wx.chooseImage',method:'LOCAL',options:copy(opts),callStack:(new Error()).stack,timestamp:new Date().toISOString()};g.__MCP_UPLOAD_REQUESTS__.push(rec);const next=Object.assign({},opts||{});const ok=next.success,fail=next.fail,done=next.complete;next.success=function(res){rec.tempFilePaths=res&&res.tempFilePaths;rec.tempFiles=res&&res.tempFiles;rec.finishedAt=new Date().toISOString();if(typeof ok==='function')return ok.apply(this,arguments)};next.fail=function(err){rec.error=String(err&&err.errMsg||err);rec.finishedAt=new Date().toISOString();if(typeof fail==='function')return fail.apply(this,arguments)};next.complete=function(res){rec.completed=true;if(typeof done==='function')return done.apply(this,arguments)};return raw.call(this,next)};hooks.chooseImage=true}
if(typeof wxObj.chooseMedia==='function'){const raw=wxObj.chooseMedia;wxObj.chooseMedia=function(opts){const id=mk('chooseMedia');const rec={id,source:'chooseMedia',api:'wx.chooseMedia',method:'LOCAL',options:copy(opts),callStack:(new Error()).stack,timestamp:new Date().toISOString()};g.__MCP_UPLOAD_REQUESTS__.push(rec);const next=Object.assign({},opts||{});const ok=next.success,fail=next.fail,done=next.complete;next.success=function(res){rec.tempFiles=res&&res.tempFiles;rec.type=res&&res.type;rec.finishedAt=new Date().toISOString();if(typeof ok==='function')return ok.apply(this,arguments)};next.fail=function(err){rec.error=String(err&&err.errMsg||err);rec.finishedAt=new Date().toISOString();if(typeof fail==='function')return fail.apply(this,arguments)};next.complete=function(res){rec.completed=true;if(typeof done==='function')return done.apply(this,arguments)};return raw.call(this,next)};hooks.chooseMedia=true}
g.__MCP_UPLOAD_HOOKED__=true;return {hooked:Object.keys(hooks).length>0,reused:false,hooks,count:g.__MCP_UPLOAD_REQUESTS__.length};})()
"""
        return await self.eval_appservice_script(script)

    async def install_early_hooks(self) -> JsonDict:
        """Phase 0 一次性安装最早期 Hook，必须早于任何路由导航。"""
        result: JsonDict = {"ok": True, "phase": "early_hooks", "steps": {}}
        try:
            result["steps"]["select_appservice_context"] = await self.select_appservice_context()
        except Exception as exc:  # pragma: no cover - 防止局部能力缺失影响 page-frame hook
            result["steps"]["select_appservice_context"] = {"ok": False, "error": str(exc)}
        for name, func in [
            ("hook_wx_request", self.hook_wx_request),
            ("hook_upload_apis", self.hook_upload_apis),
            ("hook_fetch_and_xhr", self.hook_fetch_and_xhr),
        ]:
            try:
                result["steps"][name] = await func()
            except Exception as exc:  # pragma: no cover - Runtime 现场异常需返回给 Agent
                result["steps"][name] = {"ok": False, "error": str(exc)}
        result["ok"] = any(bool(step.get("ok")) for step in result["steps"].values() if isinstance(step, dict))
        return result

    async def rehook_after_route_navigation(self) -> JsonDict:
        """路由跳转后重新选择 appservice context，并重注入会随 context 失效的 Hook。

        两处修正：
          1. 必须 `force=True` 重选 —— 导航后旧的 executionContext 往往已销毁，
             沿用缓存 id 会得到「看似成功但注入到了已死的上下文」；
          2. 之前漏了 `hook_fetch_and_xhr`，H5/内嵌页的 fetch/XHR 流量在跳转后就断了。
        """
        output: JsonDict = {"ok": True, "hooks": {}}
        before_context = self.selected_appservice_context_id
        selected = await self.select_appservice_context(force=True)
        output["select_appservice_context"] = selected
        output["previousContextId"] = before_context
        output["selectedContextId"] = selected.get("selectedContextId")
        output["mode"] = selected.get("mode")
        if not selected.get("ok"):
            output["ok"] = False
            output["hint"] = (
                "导航后重新定位 appservice 失败。此时 Hook 已随旧上下文失效，"
                "继续抓流量会拿到空数据。请按 connection_ops(action='find_appservice') 的 howToFix 处理。"
            )
            return output
        for name, func in (
            ("wx", self.hook_wx_request),
            ("upload", self.hook_upload_apis),
            ("fetch_xhr", self.hook_fetch_and_xhr),
        ):
            try:
                output["hooks"][name] = await func()
            except Exception as exc:  # noqa: BLE001 - 单个 Hook 失败不该拖垮其余
                output["hooks"][name] = {"ok": False, "error": str(exc)}
        output["ok"] = any(bool(hook.get("ok")) for hook in output["hooks"].values() if isinstance(hook, dict))
        if before_context != self.selected_appservice_context_id:
            output["note"] = (
                f"context 从 {before_context} 变为 {self.selected_appservice_context_id}，"
                "旧上下文里已捕获的 Hook 记录会随之失效（历史记录已并入 get_all_requests 的 CDP 部分）。"
            )
        return output

    async def hook_fetch_and_xhr(self) -> JsonDict:
        """注入非破坏性 fetch/XHR Hook，记录请求、响应和调用栈。"""
        script = r"""
(function(){const g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;if(g.__MCP_FETCH_XHR_HOOKED__)return {hooked:true,reused:true,count:(g.__MCP_FETCH_XHR_REQUESTS__||[]).length};g.__MCP_FETCH_XHR_REQUESTS__=[];
if(typeof g.fetch==='function'){const rawFetch=g.fetch;g.fetch=async function(input,init){const id='fetch-'+Date.now()+'-'+Math.random().toString(16).slice(2);const url=typeof input==='string'?input:(input&&input.url)||'';const rec={id,source:'fetch',url,method:(init&&init.method||'GET').toUpperCase(),requestHeaders:init&&init.headers||{},requestBodyPreview:init&&init.body,callStack:(new Error()).stack,timestamp:new Date().toISOString()};g.__MCP_FETCH_XHR_REQUESTS__.push(rec);try{const resp=await rawFetch.apply(this,arguments);rec.statusCode=resp.status;rec.responseHeaders=Object.fromEntries(resp.headers.entries());const clone=resp.clone();clone.text().then(t=>{rec.responseBodyPreview=t.slice(0,2000);rec.finishedAt=new Date().toISOString();}).catch(e=>{rec.error=String(e)});return resp}catch(e){rec.error=String(e);rec.finishedAt=new Date().toISOString();throw e}}}
if(typeof g.XMLHttpRequest!=='undefined'){const XHR=g.XMLHttpRequest;const open=XHR.prototype.open,send=XHR.prototype.send,set=XHR.prototype.setRequestHeader;XHR.prototype.open=function(method,url){this.__mcp={id:'xhr-'+Date.now()+'-'+Math.random().toString(16).slice(2),source:'xhr',method:String(method||'GET').toUpperCase(),url:String(url||''),requestHeaders:{},callStack:(new Error()).stack,timestamp:new Date().toISOString()};return open.apply(this,arguments)};XHR.prototype.setRequestHeader=function(k,v){if(this.__mcp)this.__mcp.requestHeaders[k]=v;return set.apply(this,arguments)};XHR.prototype.send=function(body){const rec=this.__mcp||{id:'xhr-'+Date.now(),source:'xhr'};rec.requestBodyPreview=body;g.__MCP_FETCH_XHR_REQUESTS__.push(rec);this.addEventListener('loadend',function(){rec.statusCode=this.status;rec.responseBodyPreview=String(this.responseText||'').slice(0,2000);rec.finishedAt=new Date().toISOString();});return send.apply(this,arguments)}}
g.__MCP_FETCH_XHR_HOOKED__=true;return {hooked:true};})()
"""
        return await self.runtime_eval(script)

    async def fetch_from_page(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Any = None,
        body: Any = None,
        await_promise: bool = True,
    ) -> JsonDict:
        """在 page-frame 上下文使用 fetch 发送请求，绕过 wx.request 合法域名白名单限制。"""
        target = str(url or "").strip()
        if not target:
            return {"ok": False, "error": "url 不能为空"}
        method_name = str(method or "GET").upper()
        header_obj = headers if isinstance(headers, dict) else {}
        init: JsonDict = {"method": method_name, "headers": header_obj}
        if body is not None:
            init["body"] = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
        expr = f"""
(async()=>{{
  const url={json.dumps(target, ensure_ascii=False)};
  const init={json.dumps(init, ensure_ascii=False)};
  try {{
    const resp=await fetch(url, init);
    const text=await resp.clone().text();
    let jsonBody=null;
    try {{ jsonBody=JSON.parse(text); }} catch(_e) {{}}
    return {{ok:true,url,method:init.method||'GET',status:resp.status,statusText:resp.statusText,headers:Object.fromEntries(resp.headers.entries()),text:text.slice(0,10000),json:jsonBody}};
  }} catch(e) {{
    return {{ok:false,url,method:init.method||'GET',error:String(e&&e.message||e)}};
  }}
}})()
"""
        result = await self.runtime_eval(expr, await_promise=await_promise, context_id=None)
        value = result.get("value")
        if isinstance(value, dict):
            return {"ok": bool(result.get("ok")) and bool(value.get("ok")), "url": target, "method": method_name, "result": value}
        return {"ok": bool(result.get("ok")), "url": target, "method": method_name, "result": value, "raw": result}

    async def upload_formdata_from_page(
        self,
        url: str,
        *,
        headers: Any = None,
        fields: Any = None,
        files: Any = None,
        method: str = "POST",
        await_promise: bool = True,
    ) -> JsonDict:
        """在 page-frame 上下文构建 FormData 并发送 multipart 上传，避免退回 appservice wx.uploadFile。"""
        target = str(url or "").strip()
        if not target:
            return {"ok": False, "error": "url 不能为空"}
        method_name = str(method or "POST").upper()
        header_obj = headers if isinstance(headers, dict) else {}
        field_obj = fields if isinstance(fields, dict) else {}
        file_items = files if isinstance(files, list) else []
        normalized_files: list[JsonDict] = []
        for index, item in enumerate(file_items):
            if not isinstance(item, dict):
                continue
            normalized_files.append(
                {
                    "fieldName": str(item.get("fieldName") or item.get("name") or "file"),
                    "filename": str(item.get("filename") or item.get("fileName") or f"upload-{index + 1}.bin"),
                    "mimeType": str(item.get("mimeType") or item.get("contentType") or "application/octet-stream"),
                    "content": item.get("content") if isinstance(item.get("content"), str) else json.dumps(item.get("content"), ensure_ascii=False, default=str),
                    "encoding": str(item.get("encoding") or "utf-8").lower(),
                }
            )
        expr = f"""
(async()=>{{
  const url={json.dumps(target, ensure_ascii=False)};
  const method={json.dumps(method_name, ensure_ascii=False)};
  const headers={json.dumps(header_obj, ensure_ascii=False)};
  const fields={json.dumps(field_obj, ensure_ascii=False)};
  const files={json.dumps(normalized_files, ensure_ascii=False)};
  const fd=new FormData();
  const appendField=(key,value)=>{{
    if(Array.isArray(value)){{ for(const item of value) appendField(key,item); return; }}
    if(value===null||typeof value==='undefined'){{ fd.append(key,''); return; }}
    if(typeof value==='object'){{ fd.append(key,JSON.stringify(value)); return; }}
    fd.append(key,String(value));
  }};
  const decodeBytes=(spec)=>{{
    const text=String(spec&&spec.content||'');
    const encoding=String(spec&&spec.encoding||'utf-8').toLowerCase();
    if(encoding==='base64'||encoding==='base64url'){{
      const normalized=encoding==='base64url'?text.replace(/-/g,'+').replace(/_/g,'/'):text;
      const padded=normalized + '='.repeat((4 - normalized.length % 4) % 4);
      const binary=atob(padded);
      return Uint8Array.from(binary, ch => ch.charCodeAt(0));
    }}
    if(encoding==='hex'){{
      const clean=text.replace(/[^0-9a-f]/gi,'');
      const size=Math.floor(clean.length/2);
      const out=new Uint8Array(size);
      for(let i=0;i<size;i++) out[i]=parseInt(clean.slice(i*2,i*2+2),16);
      return out;
    }}
    return new TextEncoder().encode(text);
  }};
  Object.entries(fields||{{}}).forEach(([key,value])=>appendField(key,value));
  for(const spec of files||[]){{
    const blob=new Blob([decodeBytes(spec)],{{type:String(spec&&spec.mimeType||'application/octet-stream')}});
    fd.append(String(spec&&spec.fieldName||'file'), blob, String(spec&&spec.filename||'upload.bin'));
  }}
  try {{
    const resp=await fetch(url, {{method, headers, body:fd}});
    const text=await resp.clone().text();
    let jsonBody=null;
    try {{ jsonBody=JSON.parse(text); }} catch(_e) {{}}
    return {{
      ok:true,
      url,
      method,
      status:resp.status,
      statusText:resp.statusText,
      headers:Object.fromEntries(resp.headers.entries()),
      text:text.slice(0,10000),
      json:jsonBody,
      fieldsCount:Object.keys(fields||{{}}).length,
      filesCount:(files||[]).length
    }};
  }} catch(e) {{
    return {{
      ok:false,
      url,
      method,
      error:String(e&&e.message||e),
      fieldsCount:Object.keys(fields||{{}}).length,
      filesCount:(files||[]).length
    }};
  }}
}})()
"""
        result = await self.runtime_eval(expr, await_promise=await_promise, context_id=None)
        value = result.get("value")
        if isinstance(value, dict):
            return {
                "ok": bool(result.get("ok")) and bool(value.get("ok")),
                "url": target,
                "method": method_name,
                "result": value,
                "fields": field_obj,
                "files": [{"fieldName": item["fieldName"], "filename": item["filename"], "mimeType": item["mimeType"], "encoding": item["encoding"]} for item in normalized_files],
            }
        return {
            "ok": bool(result.get("ok")),
            "url": target,
            "method": method_name,
            "result": value,
            "fields": field_obj,
            "files": [{"fieldName": item["fieldName"], "filename": item["filename"], "mimeType": item["mimeType"], "encoding": item["encoding"]} for item in normalized_files],
            "raw": result,
        }

    async def get_hooked_requests(self) -> list[JsonDict]:
        """从运行时读取 Hook 捕获的 wx/fetch/xhr/upload/choose 记录。"""
        records: list[JsonDict] = []
        context_ids = [self.selected_appservice_context_id, None] if self.selected_appservice_context_id is not None else [None]
        seen: set[str] = set()
        for context_id in context_ids:
            with IgnoreOptionalCdpError():
                result = await self.runtime_eval(
                    "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
                    "return [].concat(g.__MCP_WX_REQUESTS__||[],g.__MCP_FETCH_XHR_REQUESTS__||[],g.__MCP_UPLOAD_REQUESTS__||[]);})()",
                    context_id=context_id,
                )
                value = result.get("value")
                if isinstance(value, list):
                    for item in value:
                        if not isinstance(item, dict):
                            continue
                        rid = str(item.get("id") or json.dumps(item, ensure_ascii=False, default=str))
                        if rid in seen:
                            continue
                        seen.add(rid)
                        records.append(item)
        return records

    async def get_all_requests(
        self,
        *,
        limit: int = 200,
        keyword: Any = None,
        domain: Any = None,
        path_prefix: Any = None,
        exclude_static: bool = False,
        exclude_telemetry: bool = False,
    ) -> JsonDict:
        """合并 CDP 缓存和 Hook 记录，返回统一请求列表。

        每条记录带 `kind`（`api` / `telemetry` / `static` / `data_uri` /
        `document` / `websocket`）。
        `exclude_static=True` 时只保留接口类请求（`api` + `telemetry`）——
        接口资产盘点与各 `find_*` 都应当用它，否则字体 / 图片 / SVG 会淹没真实接口。
        `exclude_telemetry=True` 再摘掉埋点（风险面分析默认用它，见 v2.22）。
        """
        hooked = await self.get_hooked_requests()
        merged: dict[str, JsonDict] = {key: self.normalize_request(value) for key, value in self.requests.items()}
        for item in hooked:
            rid = str(item.get("id") or f"hook-{len(merged)}")
            merged[rid] = self.normalize_request({**item, "requestId": rid})
        items = list(merged.values())
        kw = str(keyword or "").lower()
        dm = str(domain or "").lower()
        pp = str(path_prefix or "")
        if kw:
            items = [r for r in items if kw in json.dumps(r, ensure_ascii=False).lower()]
        if dm:
            items = [r for r in items if dm in str(urlparse(str(r.get("url") or "")).netloc).lower()]
        if pp:
            items = [r for r in items if str(urlparse(str(r.get("url") or "")).path).startswith(pp)]
        by_kind: dict[str, int] = {}
        for record in items:
            kind = str(record.get("kind") or classify_request_url(str(record.get("url") or "")))
            by_kind[kind] = by_kind.get(kind, 0) + 1
        total_before = len(items)
        if exclude_static:
            items = [r for r in items if r.get("kind") in {"api", "telemetry"}]
        telemetry_skipped = 0
        if exclude_telemetry:
            before = len(items)
            items = [r for r in items if r.get("kind") != "telemetry"]
            telemetry_skipped = before - len(items)
        items.sort(key=lambda r: str(r.get("timestamp") or ""), reverse=True)
        result: JsonDict = {
            "ok": True,
            "total": len(items),
            "totalBeforeFilter": total_before,
            "excludeStatic": bool(exclude_static),
            "excludeTelemetry": bool(exclude_telemetry),
            "telemetrySkipped": telemetry_skipped,
            "byKind": by_kind,
            "requests": items[: max(1, int(limit))],
        }
        if exclude_static and by_kind:
            dropped = total_before - len(items) - telemetry_skipped
            if dropped:
                result["filterNote"] = (
                    f"已按 excludeStatic 过滤掉 {dropped} 条非接口请求"
                    f"（static/data_uri/document/websocket）。要看全部请传 excludeStatic=false。"
                )
        if telemetry_skipped:
            result["telemetryNote"] = (
                f"已过滤 {telemetry_skipped} 条埋点/遥测请求（kind=telemetry）——"
                f"它们占比可以很高（实测 28/49）且会污染风险面。"
                f"如需包含请传 excludeTelemetry=false。"
            )
        return result

    async def get_request_detail(self, request_id: str, max_length: int = 20_000) -> JsonDict:
        """读取指定请求详情，必要时尝试通过 CDP 获取响应体。

        `max_length` 控制返回体积（以前该参数被丢弃，大响应体会直接撑爆上下文）。
        查找时**不做静态过滤**，否则按 id 查静态资源会查不到。
        """
        all_requests = await self.get_all_requests(limit=2000, exclude_static=False)
        for req in all_requests.get("requests", []):
            if str(req.get("id")) == request_id or str(req.get("requestId")) == request_id:
                detail = dict(req)
                if req.get("source") == "cdp":
                    with IgnoreOptionalCdpError():
                        body = await self.cdp.send("Network.getResponseBody", {"requestId": request_id}, timeout_ms=5000)
                        detail["responseBodyRaw"] = body.get("result", {})
                limit = max(500, int(max_length))
                text = json.dumps(detail, ensure_ascii=False, default=str)
                truncated_fields: list[str] = []
                if len(text) > limit:
                    # 关键：`request` **始终是对象**。把大字段按预算压缩，
                    # 而不是把整个 detail 序列化成字符串返回（那会直接破坏调用方契约）。
                    per_field = max(500, limit // 6)
                    big_fields = ("responseBodyRaw", "responseBodyPreview", "requestBodyPreview", "callStack", "raw")
                    for field in big_fields:
                        if field not in detail:
                            continue
                        serialized = json.dumps(detail[field], ensure_ascii=False, default=str)
                        if len(serialized) > per_field:
                            detail[field] = compact_text(serialized, per_field)
                            truncated_fields.append(field)
                    text = json.dumps(detail, ensure_ascii=False, default=str)
                    # 仍然超限就按体积从大到小继续砍，只砍大字段，结构保持完整
                    for field in sorted(
                        big_fields,
                        key=lambda name: -len(json.dumps(detail.get(name), ensure_ascii=False, default=str)),
                    ):
                        if len(text) <= limit or field not in detail:
                            continue
                        detail[field] = f"<omitted: 超过 maxLength={limit}，原长度 {len(json.dumps(detail[field], ensure_ascii=False, default=str))}>"
                        if field not in truncated_fields:
                            truncated_fields.append(field)
                        text = json.dumps(detail, ensure_ascii=False, default=str)
                return {
                    "ok": True,
                    "request": detail,
                    "truncated": bool(truncated_fields),
                    "truncatedFields": truncated_fields,
                    "serializedLength": len(text),
                    "maxLength": limit,
                    **({"hint": "部分大字段已截断/省略；调大 maxLength 可看全。"} if truncated_fields else {}),
                }
        return {"ok": False, "error": f"未找到请求：{request_id}"}

    def normalize_request(self, raw: JsonDict) -> JsonDict:
        """把 CDP 或 Hook 原始记录归一为统一结构。"""
        url = str(raw.get("url") or raw.get("request", {}).get("url") or "")
        parsed = urlparse(url)
        body = raw.get("requestBodyPreview", raw.get("postData", raw.get("request", {}).get("postData")))
        headers = raw.get("requestHeaders", raw.get("request", {}).get("headers", {})) or {}
        response_headers = raw.get("responseHeaders", raw.get("response", {}).get("headers", {})) or {}
        body_preview = safe_json_loads(body)
        url_query = parse_url_query(url)
        # 三种形态都试：POST body / URL query 参数（GET 形态，实测某目标走这条）/ query= 参数
        graphql = (
            extract_graphql_operation(body_preview)
            or extract_graphql_operation(url_query)
            or extract_graphql_operation(url_query.get("query"))
        )
        record = {"id": str(raw.get("requestId") or raw.get("id") or ""), "requestId": str(raw.get("requestId") or raw.get("id") or ""), "source": str(raw.get("source") or "cdp"), "kind": classify_request_url(url), "method": str(raw.get("method") or raw.get("request", {}).get("method") or "GET"), "url": url, "path": parsed.path, "query": parse_url_query(url), "requestHeaders": headers, "requestBodyPreview": body_preview, "statusCode": raw.get("statusCode", raw.get("response", {}).get("status")), "responseHeaders": response_headers, "responseBodyPreview": safe_json_loads(raw.get("responseBodyPreview", "")), "timestamp": raw.get("timestamp") or now_iso(), "callStack": raw.get("callStack") or raw.get("initiator"), "raw": raw}
        if graphql:
            record.update(graphql)
        return record

    def _on_network_event(self, event: JsonDict) -> None:
        """处理 CDP Network 事件并更新请求缓存。"""
        method = str(event.get("method") or "")
        params = event.get("params") if isinstance(event.get("params"), dict) else {}
        request_id = str(params.get("requestId") or "")
        if method.startswith("Network.webSocket"):
            self.websocket_events.append(event)
            return
        if not request_id:
            return
        record = self.requests.setdefault(request_id, {"requestId": request_id, "source": "cdp"})
        if request_id not in self.request_order:
            self.request_order.append(request_id)
        if method == "Network.requestWillBeSent":
            req = params.get("request") or {}
            record.update({"url": req.get("url"), "method": req.get("method"), "request": req, "initiator": params.get("initiator"), "timestamp": params.get("timestamp") or now_iso()})
        elif method == "Network.requestWillBeSentExtraInfo":
            record["requestHeaders"] = params.get("headers") or record.get("requestHeaders", {})
        elif method == "Network.responseReceived":
            record["response"] = params.get("response") or {}
            record["statusCode"] = record["response"].get("status")
        elif method == "Network.responseReceivedExtraInfo":
            record["responseHeaders"] = params.get("headers") or record.get("responseHeaders", {})
        elif method == "Network.loadingFinished":
            record["loadingFinished"] = True
        elif method == "Network.loadingFailed":
            record["loadingFailed"] = params.get("errorText") or True

    def _on_script_parsed(self, event: JsonDict) -> None:
        """缓存 Debugger.scriptParsed 事件中的脚本元信息。"""
        params = event.get("params") if isinstance(event.get("params"), dict) else {}
        script_id = str(params.get("scriptId") or "")
        if script_id:
            self.scripts[script_id] = dict(params)

    def _on_execution_context_created(self, event: JsonDict) -> None:
        """缓存 Runtime execution context 信息，并记录它属于哪个 flatten session。"""
        params = event.get("params") if isinstance(event.get("params"), dict) else {}
        ctx = params.get("context") if isinstance(params.get("context"), dict) else {}
        context_id = ctx.get("id")
        if isinstance(context_id, int):
            session_id = str(event.get("sessionId") or "")
            self.contexts[context_id] = dict(ctx)
            if session_id:
                self.context_sessions[context_id] = session_id
            else:
                self.context_sessions.pop(context_id, None)

    def _on_execution_context_destroyed(self, event: JsonDict) -> None:
        """清理已销毁的 Runtime execution context。"""
        params = event.get("params") if isinstance(event.get("params"), dict) else {}
        context_id = params.get("executionContextId")
        if isinstance(context_id, int):
            self.contexts.pop(context_id, None)
            self.context_sessions.pop(context_id, None)

    def _on_console_event(self, event: JsonDict) -> None:
        """缓存控制台、异常和暂停事件。"""
        self.console_events.append(event)

    async def _eval_within(self, expression: str, *, timeout_seconds: float, context_id: Any = None, session_id: Any = None) -> JsonDict:
        """在给定时间预算内求值；超时/异常都返回**结构化失败**，不向上抛。

        为什么不直接用 `runtime_eval`：它的 CDP 超时是 15s。读路由这种高频轻量
        操作等不起，而且超时会一路冒泡到调用方被 `except` 吞掉、伪装成「没有路由」。
        """
        budget = max(0.2, float(timeout_seconds))
        try:
            result = await asyncio.wait_for(
                self.runtime_eval(expression, context_id=context_id, session_id=session_id),
                timeout=budget,
            )
        except (asyncio.TimeoutError, TimeoutError):
            return {"ok": False, "error": f"求值超时（预算 {budget:.1f}s）", "timedOut": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc).strip() or repr(exc), "errorType": exc.__class__.__name__}
        if not isinstance(result, dict):
            return {"ok": False, "error": f"求值返回了非字典：{type(result).__name__}"}
        return result

    async def read_route_detail(self, *, timeout_seconds: float = ROUTE_READ_TIMEOUT_SECONDS) -> JsonDict:
        """多源读取当前路由，返回带诊断信息的结构化结果。

        降级链（前一源拿不到才走下一源）：
          1. **appservice** 的 `getCurrentPages()` —— 最权威，但有 4-7s 读取延迟；
          2. **page-frame** 的 `__routeNavigator.fetchConfigJson()` —— 内部有
             `detectFrame()` 多候选探测，比单点取全局更耐环境差异。

        与 `current_route()` 的区别：本方法**不把失败伪装成空串**。
        `ok=False` 明确表示「没读到」，并给出 `attempts` 便于定位是哪一源挂了。
        """
        budget = max(0.2, float(timeout_seconds or ROUTE_READ_TIMEOUT_SECONDS))
        deadline = time.time() + budget
        attempts: list[JsonDict] = []

        # 源 1：appservice
        if self.selected_appservice_context_id is not None:
            left = deadline - time.time()
            if left > 0:
                result = await self._eval_within(
                    APPSERVICE_ROUTE_EXPR,
                    timeout_seconds=left,
                    context_id=self.selected_appservice_context_id,
                )
                attempts.append({
                    "source": "appservice",
                    "contextId": self.selected_appservice_context_id,
                    "ok": bool(result.get("ok")),
                    "error": result.get("error"),
                })
                route = route_from_eval(result)
                if route:
                    return {"ok": True, "route": route, "source": "appservice", "attempts": attempts}
        else:
            attempts.append({"source": "appservice", "ok": False, "error": "未选中 appservice context"})

        # 源 2：page-frame 的 __routeNavigator
        left = deadline - time.time()
        if left > 0:
            result = await self._eval_within(NAVIGATOR_ROUTE_EXPR, timeout_seconds=left, session_id=None)
            attempts.append({"source": "routeNavigator", "ok": bool(result.get("ok")), "error": result.get("error")})
            route = route_from_eval(result)
            if route:
                return {"ok": True, "route": route, "source": "routeNavigator", "attempts": attempts}

        return {
            "ok": False,
            "route": "",
            "source": "",
            "error": "所有路由来源都未取到值",
            "attempts": attempts,
            "hint": (
                "appservice context 可能已失效（页面切换后常见）。"
                "先调 connection_ops(action='select_appservice_context', force=true) 重建上下文再试。"
            ),
        }

    async def current_route(self) -> str:
        """读取当前小程序路由；读不到时返回空串。

        内部走 `read_route_detail()` 的降级链（appservice → `__routeNavigator`），
        并带 `ROUTE_READ_TIMEOUT_SECONDS` 硬超时。为了兼容既有调用点仍返回裸字符串；
        **需要区分「路由为空」和「读取失败」时请直接用 `read_route_detail()`**。
        """
        detail = await self.read_route_detail()
        return str(detail.get("route") or "")

    async def wait_route_stable(self, *, timeout_seconds: float = 12.0, settle_seconds: float = 2.5) -> JsonDict:
        """等待路由稳定：连续 `settle_seconds` 内路由不再变化才算稳定。

        `getCurrentPages()` 有 4-7s 的读取延迟，`navigateTo` 回调返回 OK
        不代表页面栈已更新。直接立刻读栈会把**成功的导航误判成失败**。

        时间契约：总耗时**不超过 `timeout_seconds`**（外加一次读路由的短预算）。
        此前只在每轮迭代开始时检查 deadline，单次读路由最长可挂 15s，
        导致 `timeout=8` 实跑 15.01s。现在每次读路由的预算都被剩余时间硬约束。

        `ok` 以**是否真的读到路由**为准 —— 读不到时返回 `ok=false` + `error`，
        而不是像以前那样给一个 `ok=true, route=""` 的假成功。
        """
        started = time.time()
        timeout = max(0.5, float(timeout_seconds))
        deadline = started + timeout
        settle = max(0.2, float(settle_seconds))
        samples: list[JsonDict] = []
        failures: list[JsonDict] = []
        current = ""
        current_source = ""
        stable_since: float | None = None

        while True:
            left = deadline - time.time()
            if left <= 0:
                break
            detail = await self.read_route_detail(timeout_seconds=min(ROUTE_READ_TIMEOUT_SECONDS, left))
            route = str(detail.get("route") or "")
            samples.append({"atSeconds": round(time.time() - started, 2), "route": route})
            if route:
                if route != current:
                    current = route
                    current_source = str(detail.get("source") or "")
                    stable_since = time.time()
                elif stable_since is not None and (time.time() - stable_since) >= settle:
                    break
            else:
                failures.append({
                    "atSeconds": round(time.time() - started, 2),
                    "error": detail.get("error"),
                    "attempts": detail.get("attempts"),
                })
            left = deadline - time.time()
            if left <= 0:
                break
            await asyncio.sleep(min(ROUTE_POLL_INTERVAL_SECONDS, left))

        elapsed = round(time.time() - started, 2)
        payload: JsonDict = {
            "ok": bool(current),
            "route": current,
            "routeSource": current_source,
            "stable": bool(current),
            "elapsedSeconds": elapsed,
            "timeoutSeconds": round(timeout, 2),
            "samples": samples[-20:],
        }
        if current:
            payload["note"] = (
                "getCurrentPages() 存在 4-7s 读取延迟；"
                "判断导航是否成功请用本结果的 route，不要立刻读栈。"
            )
        else:
            payload["error"] = f"在 {round(timeout, 2)}s 内未能读到路由（失败 {len(failures)} 次）"
            payload["failures"] = failures[-5:]
            payload["hint"] = (
                "appservice context 可能已失效。先调 connection_ops(action='select_appservice_context', force=true) "
                "重建上下文，再用 route_ops(action='wait_route_stable') 重试。"
            )
        return payload

    async def pick_screenshot_target(self) -> str:
        """挑选适合截图的 target（优先 type=page 且 url 含小程序 appid）。"""
        try:
            targets = await self.list_targets_raw()
        except Exception:
            return ""
        best_id = ""
        best_score = -1
        for item in targets:
            if str(item.get("type") or "").lower() != "page":
                continue
            url = str(item.get("url") or "")
            score = 10 + (5 if re.search(r"wx[0-9a-f]{16}", url, re.I) else 0)
            if score > best_score:
                best_score = score
                best_id = str(item.get("targetId") or "")
        return best_id

    async def capture_screenshot(self, *, target_id: str = "", image_format: str = "png", quality: Any = None, file_path: str = "") -> JsonDict:
        """截图取证；给 `file_path` 就直接落盘，避免大段 base64 卡在响应里。

        截图数据在 CDP 响应的**双层嵌套**里（`result.result.data`），
        这里已经拍平到 `data` 字段。
        """
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return cdp_state
        resolved_target = str(target_id or "")
        if not resolved_target:
            resolved_target = await self.pick_screenshot_target() or str(self.page_target_id or "")
        if not resolved_target:
            return {
                "ok": False,
                "error": "未找到可截图的页面 target",
                "hint": "先调用 connection_ops(action='find_appservice')，再用 list_targets 里 type=page 的 targetId。",
            }
        params: JsonDict = {"format": str(image_format or "png").lower()}
        if quality is not None:
            params["quality"] = int(quality)
        # 必须在**同一个** session 里先 Page.enable 再 captureScreenshot：
        # 每次重新 attach 会拿到新 session，直接截图会返回 null。
        try:
            attached = await self.cdp.send("Target.attachToTarget", {"targetId": resolved_target, "flatten": True}, timeout_ms=10000)
        except Exception as exc:
            return {"ok": False, "stage": "attachToTarget", "targetId": resolved_target, "error": str(exc)}
        session_id = str(attached.get("result", {}).get("sessionId") or "")
        if not session_id:
            return {"ok": False, "stage": "attachToTarget", "error": "attachToTarget 未返回 sessionId", "raw": attached}
        try:
            with IgnoreOptionalCdpError():
                await self.cdp.send("Page.enable", {}, session_id=session_id, timeout_ms=8000)
            envelope = await self.cdp.send("Page.captureScreenshot", params, session_id=session_id, timeout_ms=20000)
        except Exception as exc:
            return {"ok": False, "stage": "captureScreenshot", "targetId": resolved_target, "sessionId": session_id, "error": str(exc)}
        result = envelope.get("result") if isinstance(envelope, dict) else None
        if not isinstance(result, dict):
            return {"ok": False, "stage": "captureScreenshot", "targetId": resolved_target, "error": "CDP 未返回截图对象", "raw": envelope}
        data = result.get("data")
        if not isinstance(data, str) or not data:
            return {"ok": False, "error": "CDP 未返回截图数据", "raw": result}
        payload: JsonDict = {
            "ok": True,
            "targetId": resolved_target,
            "sessionId": session_id,
            "format": params["format"],
            "base64Length": len(data),
            "capturedAt": now_iso(),
        }
        if file_path:
            import base64

            path = Path(file_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(path.write_bytes, base64.b64decode(data))
            payload.update({"path": str(path), "bytes": path.stat().st_size})
        else:
            payload["data"] = data
            payload["note"] = "data 是 base64；数据量大时建议传 file_path 直接落盘。"
        return payload

    async def probe_bridge(self) -> JsonDict:
        """桥活性探针：发一个 toast，配合截图判断当前桥驱动的是否是可见实例。"""
        token = f"LIVE-{int(time.time()) % 100000}"
        token_literal = json.dumps(token)
        script = (
            "(function(){const g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "try{if(g.wx&&g.wx.showToast)g.wx.showToast({title:" + token_literal + ",icon:'none',duration:6000});"
            "return {ok:true,token:" + token_literal + ",hasWx:!!g.wx,mode:(g===globalThis?'page_frame':'frames_bridge')};"
            "}catch(e){return {ok:false,error:String(e)}}})()"
        )
        result = await self.eval_appservice_script(script)
        value = result.get("value") if isinstance(result, dict) else None
        return {
            "ok": bool(result.get("ok")) and bool(isinstance(value, dict) and value.get("ok")),
            "token": token,
            "probe": value,
            "raw": result,
            "howToVerify": (
                "紧接着调用 cdp_call_target(targetId, 'Page.captureScreenshot', {'format':'png'}) 截图；"
                "能看到这个 toast 就说明当前桥驱动的是可见实例（截图数据在 result.result.data）。"
            ),
        }

    async def dump_runtime_snapshot(self, max_length: int = 20_000) -> JsonDict:
        """采集当前页面 URL、storage、路由和可见文本摘要，并标注数据新鲜度。

        `max_length` 控制可见文本的截断长度（以前该参数被丢弃、写死 1500 字符）。
        """
        text_limit = max(200, min(int(max_length or 20_000), 200_000))
        # route 部分用拼接而非 f-string 插入：`PAGE_ROUTE_EXPR` 里满是花括号，
        # 塞进 f-string 需要 `{{{...}}}` 三层转义，极易写错。
        expr = (
            "(()=>({href:location.href,title:document.title,route:("
            + PAGE_ROUTE_EXPR
            + "),storage:Object.keys(localStorage||{}).slice(0,50).reduce((a,k)=>(a[k]=String(localStorage.getItem(k)).slice(0,200),a),{}),"
            + "visibleText:(document.body&&document.body.innerText||'').slice(0,"
            + str(text_limit)
            + "),wxConfig:typeof __wxConfig!=='undefined'?{appId:__wxConfig.appId,pages:(__wxConfig.pages||[]).slice(0,20)}:null}))()"
        )
        result = await self.runtime_eval(expr)
        captured_at = time.time()
        self.last_snapshot_at = captured_at
        route_detail = await self.read_route_detail()
        appservice_route = str(route_detail.get("route") or "")
        if appservice_route and appservice_route != self.last_route_seen:
            self.last_route_seen = appservice_route
            self.last_route_changed_at = captured_at
        snapshot = result.get("value") if isinstance(result, dict) else result
        # P0-5：page-frame 侧读 route 只能靠 `__routeNavigator`；若它也没注入，
        # 就用 appservice 已读到的值**回填** —— 否则 `snapshot.route` 恒为空串，
        # 调用方据此得出「当前没有路由」的错误结论，而同一次返回里的
        # `routeFromAppservice` 明明是有值的。
        if isinstance(snapshot, dict):
            page_route = str(snapshot.get("route") or "").strip()
            if page_route:
                snapshot["routeSource"] = "page_frame"
            elif appservice_route:
                snapshot["route"] = appservice_route
                snapshot["routeSource"] = "appservice"
            else:
                snapshot["routeSource"] = ""
        age_seconds = round(max(0.0, time.time() - captured_at), 2)
        route_age = round(max(0.0, captured_at - self.last_route_changed_at), 2) if self.last_route_changed_at else None
        return {
            "ok": bool(result.get("ok")),
            "snapshot": snapshot,
            "capturedAt": now_iso(),
            "capturedAtEpoch": round(captured_at, 3),
            "ageSeconds": age_seconds,
            "routeFromAppservice": appservice_route,
            "routeSource": str(route_detail.get("source") or ""),
            "routeReadOk": bool(route_detail.get("ok")),
            "routeChangedSecondsAgo": route_age,
            "freshness": {
                "visibleText": "本次实时读取，但渲染层可能滞后于导航（Goji/原生渲染下尤其明显）",
                "route": "降级链读取：appservice 的 getCurrentPages() → page-frame 的 __routeNavigator；前者有 4-7s 读取延迟",
                "advice": "若 visibleText 与预期不符，先截图（Page.captureScreenshot）或调用 runtime_ops(action='wait_route_stable') 再判断。",
            },
            "contexts": list(self.contexts.values()),
            "status": await self.status(),
        }

    async def scan_sensitive_storage(self, *, include_raw: bool = False, max_raw_chars: int = 4000) -> JsonDict:
        """扫描 wx/local/session Storage 中的凭据、密码、内部配置和令牌线索。

        `include_raw=False`（默认）时**不回传原始 storage 转储**。

        为什么必须默认关掉：实测某目标 `raw` 字段让返回体涨到 **783 KB**
        （storage 里有 19 万字符的 `dictList`），直接超出工具结果上限、被转存到
        文件后不可读 —— 本阶段等于白跑。而且 `findings` 里的 `valuePreview`
        明明做了脱敏，`raw` 却把 JWT 和硬编码密钥**原样**吐出来，脱敏形同虚设。
        需要原始值时显式传 `includeRaw=true`，并用 `maxRawChars` 限制体积。
        """
        expr = r"""
(function(){var out={wxStorage:{},localStorage:{},sessionStorage:{},errors:[]};
try{if(typeof wx!=='undefined'&&wx.getStorageInfoSync&&wx.getStorageSync){var info=wx.getStorageInfoSync()||{};var keys=info.keys||[];for(var i=0;i<keys.length;i++){var wk=keys[i];try{out.wxStorage[wk]=wx.getStorageSync(wk)}catch(e){out.errors.push('wx:'+wk+':'+String(e))}}}}catch(e){out.errors.push('wxStorage:'+String(e))}
try{if(typeof localStorage!=='undefined'){for(var i=0;i<localStorage.length;i++){var lk=localStorage.key(i);out.localStorage[lk]=localStorage.getItem(lk)}}}catch(e){out.errors.push('localStorage:'+String(e))}
try{if(typeof sessionStorage!=='undefined'){for(var i=0;i<sessionStorage.length;i++){var sk=sessionStorage.key(i);out.sessionStorage[sk]=sessionStorage.getItem(sk)}}}catch(e){out.errors.push('sessionStorage:'+String(e))}
return out;})()
"""
        contexts = [("appservice", self.selected_appservice_context_id)] if self.selected_appservice_context_id is not None else []
        contexts.append(("page_frame", None))
        raw_results: list[JsonDict] = []
        value: JsonDict = {"wxStorage": {}, "localStorage": {}, "sessionStorage": {}, "errors": []}
        for context_name, context_id in contexts:
            runtime = await self.runtime_eval(expr, context_id=context_id)
            raw_results.append({"context": context_name, "contextId": context_id, "result": runtime})
            current = runtime.get("value")
            if not isinstance(current, dict):
                continue
            for source_name in ["wxStorage", "localStorage", "sessionStorage"]:
                source_value = current.get(source_name) or {}
                if isinstance(source_value, dict):
                    value[source_name].update(source_value)
            if isinstance(current.get("errors"), list):
                value["errors"].extend(current.get("errors") or [])
        findings: list[JsonDict] = []
        for source in ["wxStorage", "localStorage", "sessionStorage"]:
            data = value.get(source) or {}
            if not isinstance(data, dict):
                continue
            findings.extend(self.classify_sensitive_storage_source(source, data))
        by_category: dict[str, int] = {}
        for item in findings:
            category = str(item.get("category") or "unknown")
            by_category[category] = by_category.get(category, 0) + 1
        result: JsonDict = {
            "ok": any(bool(item.get("result", {}).get("ok")) for item in raw_results),
            "findings": findings,
            "count": len(findings),
            "byCategory": by_category,
            "sources": {name: len(value.get(name) or {}) for name in ["wxStorage", "localStorage", "sessionStorage"]},
            "errors": value.get("errors") or [],
        }
        if include_raw:
            # 体积护栏：`raw` 是唯一能把返回体撑到 700KB+ 的字段。
            # 上下限写法与 `dump_runtime_snapshot` 的 max_length 保持一致。
            text = json.dumps(raw_results, ensure_ascii=False, default=str)
            limit = max(200, min(int(max_raw_chars or 4000), 200_000))
            if len(text) > limit:
                result["raw"] = text[:limit]
                result["rawTruncated"] = True
                result["rawNote"] = (
                    f"raw 已截断到 {limit} 字符（原长 {len(text)}）。"
                    "完整转储体积过大且含明文密钥，建议只依赖 findings。"
                )
            else:
                result["raw"] = raw_results
                result["rawTruncated"] = False
        else:
            result["rawOmitted"] = True
            result["rawHint"] = "原始 storage 转储默认不回传（体积可到 700KB+ 且含明文密钥）；需要时传 includeRaw=true。"
        return result

    def classify_sensitive_storage_source(self, source: str, data: dict[str, Any]) -> list[JsonDict]:
        """对单个 storage 源执行敏感 key/value 分类。

        四条检测通道并行，按 (key, category) 去重：

        1. **字面量规则**（`SENSITIVE_STORAGE_RULES`）—— 原有行为，匹配明文关键词；
        2. **JWT 结构** —— base64 形态的令牌，字面量规则抓不到；
        3. **PII 字段名** —— 复用 `PII_FIELD_RE`（`openId` / `unionId` / 手机号…），
           此前它只作用于请求流量，storage 侧完全没接入；
        4. **高熵 + base64 递归** —— 键名值名都无关键词的硬编码密钥。

        通道 2/3/4 是 2026-09-22 补的：此前某目标返回 `findings: []`，而
        14 年有效期的 HS256 JWT 与疑似硬编码密钥就在 `raw` 里。
        """
        findings: list[JsonDict] = []
        seen: set[tuple[str, str]] = set()

        def _add(key: str, category: str, reason: list[str], value: Any, **extra: Any) -> None:
            signature = (key, category)
            if signature in seen:
                return
            seen.add(signature)
            findings.append(
                {
                    "source": source,
                    "key": key,
                    "category": category,
                    "reason": reason,
                    "valuePreview": self.mask_sensitive_value(value),
                    **extra,
                }
            )

        for key, value in data.items():
            key_text = str(key)
            text = f"{key_text}\n{compact_text(value, 1000)}"

            # 通道 1：字面量规则（原有行为，保持不变）
            for category, pattern in SENSITIVE_STORAGE_RULES:
                matched = sorted({m.group(0) for m in pattern.finditer(text)})[:8]
                if matched:
                    _add(key_text, category, matched, value)

            # 通道 2：JWT 结构识别（含 base64 解码后的 payload）
            for token in dict.fromkeys(JWT_RE.findall(text)):
                claims = decode_jwt_claims(token)
                if claims is None:
                    continue
                reason = [f"alg={claims.get('alg')}"]
                if claims.get("hasSignature"):
                    reason.append("hasSignature")
                if claims.get("exp"):
                    reason.append(f"exp={claims['exp']}")
                _add(key_text, "jwt_token", reason, token, jwtClaims=mask_jwt_claims(claims))

            # 通道 3：PII 字段名（顶层 key 与嵌套叶子路径都看）
            # 必须连路径一起看 —— 实测 `openId` 是嵌在 `wxUserInfo` 对象里的，
            # 只看顶层 key（`wxUserInfo`）会漏掉。
            pii_hits = PII_FIELD_RE.matched_tokens(key_text)
            if pii_hits:
                _add(key_text, "pii_in_storage", pii_hits, value)

            # 通道 4：高熵 + base64 递归（只作用于字符串叶子）
            for path, leaf in iter_string_leaves(value, prefix=key_text):
                if not pii_hits:
                    path_pii = PII_FIELD_RE.matched_tokens(path)
                    if path_pii:
                        _add(key_text, "pii_in_storage", path_pii, leaf, path=path)
                # PII 路径上的值按定义就是用户标识，不是密钥。
                # 实测 `openId` 值 `omEG45HbNADHJY5j0NTwTfSb5cek`（熵 4.35）
                # 会被熵规则误报成「疑似硬编码密钥」—— 这里是必须的抑制，
                # 否则每次扫描都会多出一条噪音，把真密钥淹没。
                if PII_FIELD_RE.matched_tokens(path):
                    continue
                # JWT 本体（熵 5.5+）必然也满足高熵条件，但它已由通道 2
                # 以 `jwt_token` 上报过 —— 不跳过就会对同一个值重复报两条，
                # 稀释 finding 的信噪比。
                if JWT_RE.search(leaf):
                    continue
                if looks_like_hardcoded_secret(leaf):
                    _add(
                        key_text,
                        "possible_hardcoded_secret",
                        [f"entropy={shannon_entropy(leaf):.2f}", f"len={len(leaf)}"],
                        leaf,
                        path=path,
                    )
                    continue  # 已判定为疑似密钥，不必再尝试 base64 解码
                decoded = try_base64_decode(leaf)
                if not decoded:
                    continue
                # 解码后可能露出明文关键词，或露出另一个 JWT
                for category, pattern in SENSITIVE_STORAGE_RULES:
                    matched = sorted({m.group(0) for m in pattern.finditer(decoded)})[:8]
                    if matched:
                        _add(
                            key_text,
                            f"base64_encoded_{category}",
                            [f"decoded={m}" for m in matched],
                            leaf,
                            path=path,
                        )
                for token in dict.fromkeys(JWT_RE.findall(decoded)):
                    claims = decode_jwt_claims(token)
                    if claims is not None:
                        _add(
                            key_text,
                            "base64_encoded_jwt_token",
                            [f"alg={claims.get('alg')}", f"exp={claims.get('exp')}"],
                            leaf,
                            path=path,
                            jwtClaims=mask_jwt_claims(claims),
                        )

        return findings

    @staticmethod
    def mask_sensitive_value(value: Any) -> str:
        """默认脱敏 storage 值，仅保留少量前后缀便于复核。"""
        text = compact_text(value, 300)
        if not text:
            return ""
        if len(text) <= 6:
            return "***"
        return f"{text[:4]}***{text[-2:]}"

    async def inspect_upload_surface(self) -> JsonDict:
        """检查当前路由 DOM、页面方法和 data 中的上传/选图/头像相关指示。"""
        dom_expr = r"""
(()=>{const re=/upload|chooseImage|chooseMedia|avatar|file|media|photo|image|上传|头像|选择图片|图片|文件/i;
const nodes=Array.from(document.querySelectorAll('button,a,input,textarea,label,[role=button],image,img,view,text')).slice(0,800);
return nodes.map((e,i)=>{const attrs={id:e.id||'',className:String(e.className||''),type:e.getAttribute&&e.getAttribute('type')||'',name:e.getAttribute&&e.getAttribute('name')||'',placeholder:e.getAttribute&&e.getAttribute('placeholder')||'',src:e.getAttribute&&e.getAttribute('src')||'',ariaLabel:e.getAttribute&&e.getAttribute('aria-label')||''};const text=String(e.innerText||e.textContent||e.value||'').slice(0,160);const joined=JSON.stringify(attrs)+' '+text;if(!re.test(joined))return null;return {type:'element',index:i,tag:e.tagName,text,attrs,selector:e.id?'#'+e.id:(e.className?e.tagName.toLowerCase()+'.'+String(e.className).split(/\s+/).filter(Boolean).join('.'):e.tagName.toLowerCase())}}).filter(Boolean).slice(0,100);})()
"""
        app_expr = r"""
(function(){var re=/upload|chooseImage|chooseMedia|avatar|file|media|photo|image|上传|头像|选择图片|图片|文件/i;
var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;
var pages=typeof g.getCurrentPages==='function'?g.getCurrentPages():[];var page=pages[pages.length-1]||{};var methods=[];
var pkeys=Object.keys(page);for(var i=0;i<pkeys.length;i++){var pk=pkeys[i];try{if(typeof page[pk]==='function'&&re.test(pk))methods.push(pk)}catch(e){}}
var dataHits=[];var seen=[];
function walk(obj,path,depth){if(!obj||depth>3||typeof obj!=='object')return;if(seen.indexOf(obj)>=0)return;seen.push(obj);
var ks=Object.keys(obj).slice(0,300);for(var j=0;j<ks.length;j++){var k=ks[j];var v;try{v=obj[k]}catch(e){continue}
var p=path?path+'.'+k:k;var s=String(k)+' '+(typeof v==='string'?v:'');if(re.test(s))dataHits.push({path:p,value:typeof v==='string'?v.slice(0,160):Object.prototype.toString.call(v)});if(v&&typeof v==='object')walk(v,p,depth+1)}}
walk(page.data||{},'',0);
return {route:page.route||g.__wxRoute||'',methods:methods.slice(0,100),dataKeys:dataHits.slice(0,100),hasWxUpload:!!(g.wx&&g.wx.uploadFile),hasChooseImage:!!(g.wx&&g.wx.chooseImage),hasChooseMedia:!!(g.wx&&g.wx.chooseMedia)};})()
"""
        dom = await self.runtime_eval(dom_expr)
        app = await self.eval_appservice_script(app_expr)
        indicators: list[JsonDict] = []
        dom_value = dom.get("value") if isinstance(dom, dict) else None
        app_value = app.get("value") if isinstance(app, dict) else None
        if isinstance(dom_value, list):
            indicators.extend([item for item in dom_value if isinstance(item, dict)])
        if isinstance(app_value, dict):
            indicators.extend({"type": "method", "name": name} for name in app_value.get("methods") or [])
            indicators.extend({"type": "data", **item} for item in app_value.get("dataKeys") or [] if isinstance(item, dict))
        return {"ok": bool(dom.get("ok")) or bool(app.get("ok")), "indicators": indicators, "dom": dom_value, "appservice": app_value, "raw": {"dom": dom, "appservice": app}}

    async def list_scripts(self, url_filter: str = "", *, named_only: bool = False, limit: int = 300) -> JsonDict:
        """列出已加载脚本，支持 URL 过滤。

        ⚠️ `Runtime.evaluate` 会把**每一次求值**也注册成一个匿名 script，
        所以这里会混进大量工具自己注入的一行表达式（实测 149 个里绝大多数是这种）。
        带 URL 的才是小程序真正的包内脚本；`named_only=True` 只返回这些。
        """
        await self.ensure_debugger_enabled()
        all_scripts = list(self.scripts.values())
        for item in all_scripts:
            item["kind"] = classify_script_url(str(item.get("url") or ""))
        named = [s for s in all_scripts if str(s.get("url") or "").strip()]
        anonymous = [s for s in all_scripts if not str(s.get("url") or "").strip()]
        scripts = named if named_only else named + anonymous
        if url_filter:
            scripts = [s for s in scripts if url_filter in str(s.get("url") or "")]
        # 业务包排最前，然后其它带 URL 的，最后匿名
        order = {"business": 0, "other": 1, "wechat_runtime": 2, "wasm": 3, "host_node": 4, "devtools": 5, "anonymous": 6}
        scripts.sort(key=lambda item: (order.get(str(item.get("kind")), 9), int(item.get("scriptId") or 0)))
        by_kind: dict[str, int] = {}
        for item in all_scripts:
            kind = str(item.get("kind") or "unknown")
            by_kind[kind] = by_kind.get(kind, 0) + 1
        result: JsonDict = {
            "ok": True,
            "count": len(scripts),
            "summary": {
                "total": len(all_scripts),
                "withUrl": len(named),
                "anonymous": len(anonymous),
                "byKind": by_kind,
                "note": (
                    "kind 说明：business=小程序业务包（审计目标）；"
                    "wechat_runtime=WeChat 运行时 cachedata；"
                    "host_node/wasm=宿主 Node 与 WASM（与小程序无关，审计请忽略）；"
                    "anonymous=Runtime.evaluate 的临时片段（含工具自身注入）。"
                ),
            },
            "scripts": scripts[: max(1, int(limit))],
            "truncated": len(scripts) > max(1, int(limit)),
        }
        business = [s for s in named if str(s.get("kind")) == "business"]
        if business:
            result["businessScripts"] = [
                {"scriptId": s.get("scriptId"), "url": s.get("url"), "length": s.get("length")} for s in business[:20]
            ]
        if not named:
            # CDP 只推送「启用 Debugger 之后才解析」的脚本；已加载的不会补发。
            # 新起的 MCP 服务天然是空清单，必须提示重开小程序，否则会被误判成工具坏了。
            result["hint"] = (
                "没有拿到任何带 URL 的脚本。`Debugger.scriptParsed` 只对「启用 Debugger 之后才解析」"
                "的脚本生效，已经加载过的不补发。请**关掉再重新打开小程序**（或换一个小程序）"
                "后重新 list_scripts；也可以直接用离线包里的 app-service.js 做反编译检索。"
            )
            result["howToFix"] = [
                "1) 关掉小程序再重新打开（微信会重新解析全部脚本）",
                "2) 重新调用 debugger_ops(action='list_scripts')",
                "3) 仍然为空时，改用离线包 app-service.js：debugger_ops(action='save_script_source') 或直接读包内文件",
            ]
        return result

    def _cache_script_source(self, script_id: str, source: str) -> None:
        """缓存脚本源码。

        `search_in_sources` 会反复拉同一批脚本；不缓存的话每次检索都要重新传一遍
        几 MB 的源码。脚本源码在解析后基本不变，缓存是安全的。
        用「条数 + 总字节」双重上限，避免大包把内存吃满。
        """
        if not source or len(source) > self._script_source_max_bytes:
            return
        existing = self._script_source_cache.get(script_id)
        if existing is not None:
            self._script_source_bytes -= len(existing)
        self._script_source_cache[script_id] = source
        self._script_source_bytes += len(source)
        while (
            len(self._script_source_cache) > self._script_source_max_entries
            or self._script_source_bytes > self._script_source_max_total
        ) and len(self._script_source_cache) > 1:
            oldest_key = next(iter(self._script_source_cache))
            self._script_source_bytes -= len(self._script_source_cache.pop(oldest_key))

    async def get_script_source(self, *, script_id: Any = None, url: Any = None, offset: Any = None, length: int = 2000, start_line: Any = None, end_line: Any = None, full: bool = False) -> JsonDict:
        """读取脚本源码片段，支持 URL 或 scriptId，并返回分页所需的元信息。

        `full=true` 或 `length<=0` 时一次性返回整篇（配合 `save_script_source` 更省事）；
        否则返回 `totalLength` / `returnedLength` / `nextOffset` / `hasMore`，
        不用再靠猜来分页。
        """
        await self.ensure_debugger_enabled()
        sid = str(script_id or "")
        if not sid and url:
            for key, script in self.scripts.items():
                if str(url) in str(script.get("url") or ""):
                    sid = key
                    break
        if not sid:
            available = [
                {"scriptId": key, "url": str(value.get("url") or ""), "hasUrl": bool(value.get("url"))}
                for key, value in list(self.scripts.items())[:40]
            ]
            return {
                "ok": False,
                "error": "缺少 script_id，或 url 未匹配到任何已加载脚本",
                "hint": (
                    "Debugger.scriptParsed 只对「启用 Debugger 之后才加载」的脚本生效，"
                    "已经加载过的脚本不会补发。可用 scriptId 直接指定，或重启小程序后再试；"
                    "离线包里的 app-service.js 也可以直接反编译检索。"
                ),
                "loadedScriptCount": len(self.scripts),
                "availableScripts": available,
            }
        source = self._script_source_cache.get(sid)
        if source is None:
            try:
                response = await self.cdp.send("Debugger.getScriptSource", {"scriptId": sid}, timeout_ms=20000)
            except Exception as exc:
                message = str(exc)
                stale = "No script for id" in message or "Could not find script" in message
                if stale:
                    # 脚本已失效（导航 / 重新解析后 id 会变），从清单里摘掉，避免后续反复失败
                    self.scripts.pop(sid, None)
                return {
                    "ok": False,
                    "scriptId": sid,
                    "stale": stale,
                    "error": message,
                    "hint": (
                        "该 scriptId 已失效（页面导航或脚本重新解析后 id 会变）。已从清单移除；"
                        "重新 debugger_ops(action='list_scripts') 拿最新 id 即可。"
                        if stale
                        else "取源码失败，稍后重试或重新 list_scripts。"
                    ),
                }
            source = response.get("result", {}).get("scriptSource", "")
            self._cache_script_source(sid, source)
        total_length = len(source)
        script_url = str(self.scripts.get(sid, {}).get("url") or "")
        meta: JsonDict = {"scriptId": sid, "url": script_url, "totalLength": total_length}

        if start_line is not None or end_line is not None:
            lines = source.splitlines()
            start = max(0, int(start_line or 1) - 1)
            end = min(len(lines), int(end_line or len(lines)))
            snippet = "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(lines[start:end], start))
            meta.update({"mode": "line_range", "startLine": start + 1, "endLine": end, "totalLines": len(lines)})
        else:
            start = max(0, int(offset or 0))
            if full or int(length or 0) <= 0:
                snippet = source[start:]
                meta["mode"] = "full"
            else:
                snippet = source[start : start + max(1, int(length))]
                meta["mode"] = "offset"
            returned = len(snippet)
            next_offset = start + returned
            meta.update(
                {
                    "offset": start,
                    "returnedLength": returned,
                    "nextOffset": next_offset,
                    "hasMore": next_offset < total_length,
                }
            )
        meta["source"] = snippet

        if ".cachedata" in script_url.lower():
            meta["warning"] = (
                "该脚本是 .cachedata 二进制缓存，调试器 search_in_sources 对它无效。"
                "请改用离线包里的 app-service.js（反编译后检索），或用 "
                'debugger_ops(action="save_script_source") 先落盘再搜。'
            )
        return {"ok": True, **meta}

    async def save_script_source(self, file_path: str, *, script_id: Any = None, url: Any = None) -> JsonDict:
        """把脚本源码保存到用户指定文件，统一使用 utf-8。"""
        if not file_path:
            return {"ok": False, "error": "file_path 不能为空"}
        result = await self.get_script_source(script_id=script_id, url=url, offset=0, full=True)
        if not result.get("ok"):
            return result
        path = Path(file_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(path.write_text, str(result.get("source") or ""), encoding="utf-8")
        return {"ok": True, "path": str(path), "bytes": path.stat().st_size}

    async def search_in_sources(self, query: str, *, case_sensitive: bool = False, is_regex: bool = False, max_results: int = 50, url_filter: Any = None, include_anonymous: bool = False, scope: str = "miniapp") -> JsonDict:
        """在已加载脚本中搜索字符串或正则。

        默认只搜「可能是小程序代码」的脚本，跳过三类噪声：
          * 匿名脚本（`Runtime.evaluate` 的临时片段，含工具自身注入）；
          * 宿主 Node 模块（`node:internal/*`）与 WASM —— 与小程序的业务代码无关；
          * 同一份包的重复副本（导航后重新解析会换 scriptId）。
        要连噪声一起搜时传 `scope="all"` / `include_anonymous=true`。
        """
        await self.ensure_debugger_enabled()
        matches: list[JsonDict] = []
        flags = 0 if case_sensitive else re.I
        pattern = re.compile(query, flags) if is_regex else None
        searched = 0
        skipped_anonymous = 0
        skipped_stale = 0
        skipped_duplicate = 0
        skipped_non_miniapp = 0
        cachedata_scripts: list[JsonDict] = []
        seen_content: set[str] = set()
        search_all = str(scope or "").lower() == "all"
        for sid, script in list(self.scripts.items()):
            script_url = str(script.get("url") or "")
            if not script_url.strip() and not include_anonymous:
                skipped_anonymous += 1
                continue
            if not search_all:
                kind = str(script.get("kind") or classify_script_url(script_url))
                if kind in NON_MINIAPP_SCRIPT_KINDS:
                    skipped_non_miniapp += 1
                    continue
            if url_filter and str(url_filter) not in script_url:
                continue
            # 同一份包在导航/重载后会以新的 scriptId 再出现一次，按 URL+长度去重，
            # 否则同一份几 MB 的 bundle 会被重复搜好几遍。
            fingerprint = f"{script_url}::{script.get('length')}"
            if script_url:
                if fingerprint in seen_content:
                    skipped_duplicate += 1
                    continue
                seen_content.add(fingerprint)
            if ".cachedata" in script_url.lower():
                cachedata_scripts.append({"scriptId": sid, "url": script_url})
            searched += 1
            # 用 full=True 取整篇：以前固定 length=2_000_000，超过 2MB 的包会被**静默截断**，
            # 后半段的敏感信息永远搜不到。
            source_result = await self.get_script_source(script_id=sid, offset=0, full=True)
            if not source_result.get("ok"):
                # 单个脚本失效不能中断整次搜索 —— 脚本 id 会随导航频繁变动
                skipped_stale += 1
                continue
            source = str(source_result.get("source") or "")
            for line_no, line in enumerate(source.splitlines(), 1):
                hit = bool(pattern.search(line)) if pattern else ((query in line) if case_sensitive else (query.lower() in line.lower()))
                if hit:
                    matches.append({"scriptId": sid, "url": script.get("url"), "line": line_no, "text": compact_text(line, 300)})
                    if len(matches) >= max_results:
                        return {
                            "ok": True,
                            "matches": matches,
                            "truncated": True,
                            "searchedScripts": searched,
                            "skippedAnonymous": skipped_anonymous,
                            "skippedStale": skipped_stale,
                            "skippedDuplicate": skipped_duplicate,
                            "skippedNonMiniapp": skipped_non_miniapp,
                            "scope": "all" if search_all else "miniapp",
                        }
        result: JsonDict = {
            "ok": True,
            "matches": matches,
            "truncated": False,
            "searchedScripts": searched,
            "skippedAnonymous": skipped_anonymous,
            "skippedStale": skipped_stale,
            "skippedDuplicate": skipped_duplicate,
            "skippedNonMiniapp": skipped_non_miniapp,
            "scope": "all" if search_all else "miniapp",
        }
        if skipped_non_miniapp:
            result["scopeNote"] = (
                f"已跳过 {skipped_non_miniapp} 个非小程序脚本（宿主 Node / WASM / devtools）。"
                "需要连它们一起搜请传 scope='all'。"
            )
        if skipped_stale:
            result["staleNote"] = (
                f"有 {skipped_stale} 个 scriptId 已失效被跳过（导航/重解析后会换 id）。"
                "已自动从清单移除，不影响本次结果；如需完整覆盖请重新 list_scripts 再搜。"
            )
        if skipped_anonymous and not include_anonymous:
            result["anonymousNote"] = (
                f"已跳过 {skipped_anonymous} 个匿名脚本（Runtime.evaluate 产生的临时片段，"
                "含工具自身注入）。需要一起搜请传 include_anonymous=true。"
            )
        if not matches:
            if cachedata_scripts:
                # C-8：.cachedata 是二进制缓存，静态文本检索对它无效，必须明确提示改路子
                result["hint"] = (
                    f"本次检索的脚本里有 {len(cachedata_scripts)} 个是 .cachedata 二进制缓存，"
                    "静态文本搜索对它无效（返回 0 不代表没有）。请改用："
                    "① 离线包里的 app-service.js 反编译后检索；"
                    "② runtime_ops(action='search_runtime_keywords') 做运行时搜索；"
                    "③ 遍历 globalThis 函数名 / wx.getStorageSync 密钥。"
                )
                result["cachedataScripts"] = cachedata_scripts
            elif searched == 0:
                result["hint"] = (
                    "没有可检索的脚本。Debugger.scriptParsed 只对「启用 Debugger 之后才加载」的脚本生效，"
                    "已加载过的不会补发；请重启小程序后再试，或用 debugger_ops(action='list_scripts') 确认。"
                )
            else:
                result["hint"] = "已检索全部已加载脚本，未命中。压缩/混淆代码可能因分词跳过匹配，建议换关键词或走运行时搜索二次验证。"
        return result

    async def ensure_breakpoints_armed(self) -> None:
        """确保断点处于「启用」状态。

        `remove_breakpoints` 会把断点整体关掉（`Debugger.setBreakpointsActive(false)`）作为兜底，
        那之后新下的断点不会命中。所以每次下断点前先确保重新启用。
        """
        if self.breakpoints_active:
            return
        session_id = self.debugger_session_id()
        with IgnoreOptionalCdpError():
            await self.cdp.send("Debugger.setBreakpointsActive", {"active": True}, timeout_ms=5000, session_id=session_id)
        self.breakpoints_active = True

    async def break_on_xhr(self, url: str) -> JsonDict:
        """按 URL 子串设置 XHR/fetch 断点，并登记以便之后撤销。"""
        await self.ensure_debugger_enabled()
        if not url:
            return {"ok": False, "error": "url 不能为空（XHR 断点按 URL 子串匹配）"}
        await self.ensure_breakpoints_armed()
        session_id = self.debugger_session_id()
        try:
            result = await self.cdp.send("DOMDebugger.setXHRBreakpoint", {"url": url}, timeout_ms=5000, session_id=session_id)
        except Exception as exc:
            return {
                "ok": False,
                "stage": "setXHRBreakpoint",
                "url": url,
                "sessionId": session_id,
                "error": str(exc),
                "hint": "断点必须下在页面 session 里。若报 session 相关错误，先 connection_ops(action='find_appservice')。",
            }
        self.xhr_breakpoints.add(url)
        return {
            "ok": True,
            "url": url,
            "sessionId": session_id,
            "activeCount": len(self.xhr_breakpoints),
            "note": "已登记；用 debugger_ops(action='remove_breakpoints') 撤销（此前的版本只能下不能撤）。",
            "raw": result,
        }

    async def set_breakpoint_on_text(self, text: str) -> JsonDict:
        """通过源码文本搜索后在首个命中行设置断点，并登记 breakpointId。"""
        found = await self.search_in_sources(text, max_results=1)
        matches = found.get("matches") or []
        if not matches:
            return {
                "ok": False,
                "error": "未找到文本，未设置断点",
                "searchedScripts": found.get("searchedScripts"),
                "skippedAnonymous": found.get("skippedAnonymous"),
                "hint": "确认脚本清单里有带 URL 的真脚本（list_scripts named_only=true）；新起服务后需重开小程序。",
            }
        first = matches[0]
        target_url = str(first.get("url") or "")
        if not target_url:
            return {"ok": False, "error": "命中的是匿名脚本（无 URL），无法按 URL 下断点", "match": first}
        await self.ensure_breakpoints_armed()
        session_id = self.debugger_session_id()
        try:
            result = await self.cdp.send(
                "Debugger.setBreakpointByUrl",
                {"url": target_url, "lineNumber": max(0, int(first.get("line") or 1) - 1)},
                timeout_ms=5000,
                session_id=session_id,
            )
        except Exception as exc:
            return {"ok": False, "stage": "setBreakpointByUrl", "url": target_url, "sessionId": session_id, "error": str(exc)}
        breakpoint_id = str((result.get("result") or {}).get("breakpointId") or "")
        if breakpoint_id:
            self.script_breakpoints[breakpoint_id] = {"breakpointId": breakpoint_id, "url": target_url, "line": first.get("line")}
        return {
            "ok": True,
            "breakpointId": breakpoint_id,
            "sessionId": session_id,
            "match": first,
            "note": "已登记；用 debugger_ops(action='remove_breakpoints') 撤销。",
            "raw": result,
        }

    async def list_breakpoints(self) -> JsonDict:
        """列出当前登记的断点。"""
        return {
            "ok": True,
            "active": self.breakpoints_active,
            "xhrBreakpoints": sorted(self.xhr_breakpoints),
            "scriptBreakpoints": list(self.script_breakpoints.values()),
            "hint": "断点是全局状态，用完请 remove_breakpoints 清掉，否则会影响后续复测。",
        }

    async def remove_breakpoints(self, *, url: str = "", breakpoint_id: str = "", all_breakpoints: bool = True) -> JsonDict:
        """撤销 XHR / 脚本断点，让断点操作可逆。

        以前只能下断点、不能撤，页面上会残留断点，后续复测时小程序莫名其妙卡住。
        `all_breakpoints=true`（默认）清掉所有已登记的；也可以用 url / breakpoint_id 精确清一个。
        """
        await self.ensure_debugger_enabled()
        session_id = self.debugger_session_id()
        removed: list[JsonDict] = []
        failed: list[JsonDict] = []

        xhr_targets = sorted(self.xhr_breakpoints) if all_breakpoints else ([url] if url else [])
        for target in xhr_targets:
            try:
                await self.cdp.send("DOMDebugger.removeXHRBreakpoint", {"url": target}, timeout_ms=5000, session_id=session_id)
                self.xhr_breakpoints.discard(target)
                removed.append({"type": "xhr", "url": target})
            except Exception as exc:
                failed.append({"type": "xhr", "url": target, "error": str(exc)})

        if breakpoint_id:
            script_targets = [breakpoint_id]
        elif all_breakpoints:
            script_targets = list(self.script_breakpoints.keys())
        else:
            script_targets = []
        for bp_id in script_targets:
            try:
                await self.cdp.send("Debugger.removeBreakpoint", {"breakpointId": bp_id}, timeout_ms=5000, session_id=session_id)
                self.script_breakpoints.pop(bp_id, None)
                removed.append({"type": "script", "breakpointId": bp_id})
            except Exception as exc:
                failed.append({"type": "script", "breakpointId": bp_id, "error": str(exc)})

        # 兜底：把断点整体关掉再打开，确保没有漏网的
        if all_breakpoints:
            with IgnoreOptionalCdpError():
                await self.cdp.send("Debugger.setBreakpointsActive", {"active": False}, timeout_ms=5000, session_id=session_id)
            self.breakpoints_active = False

        return {
            "ok": not failed,
            "sessionId": session_id,
            "removed": removed,
            "failed": failed,
            "remaining": {"xhr": sorted(self.xhr_breakpoints), "script": list(self.script_breakpoints.keys())},
            "breakpointsActive": self.breakpoints_active,
        }

    async def get_paused_info(self) -> JsonDict:
        """返回最近一次暂停事件和控制台事件。"""
        paused = [e for e in self.console_events if e.get("method") == "Debugger.paused"]
        latest = paused[-1] if paused else None
        result: JsonDict = {
            "ok": True,
            "paused": latest,
            "isPaused": latest is not None,
            "recentConsole": list(self.console_events)[-20:],
            "breakpoints": {"xhr": sorted(self.xhr_breakpoints), "script": list(self.script_breakpoints.keys()), "active": self.breakpoints_active},
        }
        if latest is None:
            result["hint"] = (
                "没有观察到暂停事件。断点只在「命令下发之后」命中的代码上生效；"
                "若刚下完断点还没有流量经过，属正常。卡住小程序时用 remove_breakpoints 清断点。"
            )
        return result

    async def resume_execution(self) -> JsonDict:
        """恢复 JavaScript 执行。"""
        await self.ensure_debugger_enabled()
        session_id = self.debugger_session_id()
        try:
            result = await self.cdp.send("Debugger.resume", timeout_ms=5000, session_id=session_id)
        except Exception as exc:
            return {
                "ok": False,
                "stage": "Debugger.resume",
                "sessionId": session_id,
                "error": str(exc),
                "hint": "只有在暂停状态下才能 resume；若小程序没卡住，报错属正常。",
            }
        return {"ok": True, "sessionId": session_id, "raw": result}

    async def step(self, kind: str) -> JsonDict:
        """执行 Debugger 单步控制。"""
        await self.ensure_debugger_enabled()
        mapping = {"over": "Debugger.stepOver", "into": "Debugger.stepInto", "out": "Debugger.stepOut"}
        method = mapping.get(kind, "Debugger.stepOver")
        session_id = self.debugger_session_id()
        try:
            result = await self.cdp.send(method, timeout_ms=5000, session_id=session_id)
        except Exception as exc:
            return {"ok": False, "stage": method, "sessionId": session_id, "error": str(exc), "hint": "单步只在暂停状态下有效。"}
        return {"ok": True, "method": method, "sessionId": session_id, "raw": result}

    async def get_websocket_messages(self) -> JsonDict:
        """返回已缓存 WebSocket 事件。"""
        return {"ok": True, "events": list(self.websocket_events)}

    async def search_runtime_keywords(self, keywords: list[str], max_length: int = 20_000) -> JsonDict:
        """在运行时对象、storage、页面文本和请求缓存中搜索关键词。

        以前只返回**匹配位置**（`{"token": [123, 456]}`）—— 拿不到上下文，基本没法用。
        现在每个命中都带 60 字上下文片段与来源，并按 `max_length` 控制总体积。
        """
        expr = (
            "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "var out={keys:[],storage:{},text:'',route:''};"
            "try{out.keys=Object.keys(g).slice(0,3000);}catch(e){}"
            "try{if(g.wx&&g.wx.getStorageInfoSync&&g.wx.getStorageSync){var info=g.wx.getStorageInfoSync()||{};"
            "var ks=info.keys||[];for(var i=0;i<ks.length;i++){try{out.storage[ks[i]]=g.wx.getStorageSync(ks[i]);}catch(e){}}}}catch(e){}"
            "try{if(typeof localStorage!=='undefined'){for(var j=0;j<localStorage.length;j++){var lk=localStorage.key(j);out.storage['local:'+lk]=localStorage.getItem(lk);}}}catch(e){}"
            "try{out.text=String((document.body&&document.body.innerText)||'').slice(0,5000);}catch(e){}"
            "try{out.route=String(g.__wxRoute||'');}catch(e){}"
            "return out;})()"
        )
        runtime = await self.eval_appservice_script(expr)
        sources: list[tuple[str, str]] = []
        value = runtime.get("value")
        if isinstance(value, dict):
            sources.append(("runtime.keys", json.dumps(value.get("keys"), ensure_ascii=False)))
            sources.append(("runtime.storage", json.dumps(value.get("storage"), ensure_ascii=False, default=str)))
            sources.append(("runtime.pageText", str(value.get("text") or "")))
        requests = (await self.get_all_requests(limit=500)).get("requests", [])
        sources.append(("observedRequests", json.dumps(requests, ensure_ascii=False, default=str)))

        results: dict[str, list[JsonDict]] = {}
        for keyword in keywords:
            pattern = re.compile(re.escape(str(keyword)), re.I)
            found: list[JsonDict] = []
            for source_name, haystack in sources:
                for match in pattern.finditer(haystack):
                    start = max(0, match.start() - 60)
                    end = min(len(haystack), match.end() + 60)
                    found.append(
                        {
                            "source": source_name,
                            "offset": match.start(),
                            "snippet": haystack[start:end].replace("\n", " "),
                        }
                    )
                    if len(found) >= 20:
                        break
                if len(found) >= 20:
                    break
            results[str(keyword)] = found

        text = json.dumps({"hits": results}, ensure_ascii=False, default=str)
        snippet, truncated = truncate_text(text, max_length)
        return {
            "ok": True,
            "hits": results,
            "counts": {key: len(items) for key, items in results.items()},
            "mode": runtime.get("mode"),
            "truncated": truncated,
            "maxLength": int(max_length),
            "raw": snippet if truncated else None,
        }

    async def inspect_wx_config(self, max_length: int = 20_000) -> JsonDict:
        """读取小程序 __wxConfig / accountInfo 摘要。

        `__wxConfig` 展开后可以很大，所以按 `max_length` 截断（以前这个参数被丢弃，
        返回体积完全不可控）。同时改用 appservice 解析，page-frame 里没有 __wxConfig。
        """
        expr = (
            "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "var cfg=null;try{if(typeof g.__wxConfig!=='undefined'&&g.__wxConfig){var c=g.__wxConfig;"
            "cfg={appId:c.appId,envVersion:c.envVersion,version:c.version,"
            "pageCount:(c.pages||[]).length,subPackageCount:(c.subPackages||c.subpackages||[]).length,"
            "tabBar:(c.tabBar&&c.tabBar.list||[]).map(function(i){return i.pagePath;})};}}catch(e){cfg={error:String(e)};}"
            "var acc=null;try{if(g.wx&&typeof g.wx.getAccountInfoSync==='function'){var a=g.wx.getAccountInfoSync();"
            "acc={miniProgram:a&&a.miniProgram,plugin:a&&a.plugin};}}catch(e){acc={error:String(e)};}"
            "return {wxConfig:cfg,account:acc,route:g.__wxRoute||''};})()"
        )
        result = await self.eval_appservice_script(expr)
        value = result.get("value")
        text = json.dumps(value, ensure_ascii=False, default=str)
        snippet, truncated = truncate_text(text, max_length)
        return {
            "ok": bool(result.get("ok")),
            "mode": result.get("mode"),
            "truncated": truncated,
            "maxLength": int(max_length),
            "value": safe_json_loads(snippet) if not truncated else snippet,
        }

    async def trace_request_callstack(self, request_id: str, limit: int = 50) -> JsonDict:
        """返回指定请求的调用栈或 initiator 信息。

        `limit` 以前被工具层直接丢弃；现在用它裁剪调用栈行数（调用栈动辄几十行）。
        """
        detail = await self.get_request_detail(request_id)
        req = detail.get("request") if detail.get("ok") else {}
        raw_stack = req.get("callStack") if isinstance(req, dict) else None
        frames: Any = raw_stack
        truncated = False
        if isinstance(raw_stack, str) and raw_stack.strip():
            lines = [line for line in raw_stack.splitlines() if line.strip()]
            if len(lines) > max(1, int(limit)):
                frames = "\n".join(lines[: max(1, int(limit))])
                truncated = True
        return {
            "ok": bool(detail.get("ok")),
            "requestId": request_id,
            "callStack": frames,
            "truncated": truncated,
            "limit": int(limit),
        }

    async def inspect_vuex_store(self, *, force_select: bool = False, max_length: int = 20_000) -> JsonDict:
        """查找 Vuex-like store，并保存只读摘要。

        改用 appservice 解析（`window.__as` 桥兜底）—— 之前直接在 page-frame 求值，
        `globalThis.$store` 基本永远是 undefined。`max_length` 控制 state 快照体积。
        """
        if force_select:
            await self.select_appservice_context(force=True)
        expr = (
            "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "var cands=[g.$store,g.store,g.__store__,g.__VUE_STORE__];var out=[];"
            "for(var i=0;i<cands.length;i++){var s=cands[i];if(!s)continue;"
            "try{out.push({index:i,keys:Object.keys(s),state:s.state,"
            "mutations:Object.keys(s._mutations||{}),actions:Object.keys(s._actions||{}),"
            "getters:Object.keys(s.getters||{})});}catch(e){out.push({index:i,error:String(e)});}}"
            "return out;})()"
        )
        result = await self.eval_appservice_script(expr)
        stores = result.get("value") if isinstance(result, dict) else None
        if not isinstance(stores, list):
            return {"ok": False, "error": "求值未返回数组", "mode": result.get("mode"), "raw": result}
        snapshot_text = json.dumps(stores[0].get("state") if stores else None, ensure_ascii=False, default=str)
        snapshot_snippet, snapshot_truncated = truncate_text(snapshot_text, max_length)
        payload: JsonDict = {
            "ok": True,
            "count": len(stores),
            "stores": stores,
            "mode": result.get("mode"),
            "snapshot": safe_json_loads(snapshot_snippet) if not snapshot_truncated else snapshot_snippet,
            "snapshotTruncated": snapshot_truncated,
            "maxLength": int(max_length),
        }
        if not stores:
            payload["hint"] = (
                "没找到 Vuex-like store。小程序可能没用 Vuex，或 store 挂在闭包里。"
                "可先用 runtime_eval_appservice 遍历 globalThis 找疑似 store。"
            )
        return payload

    async def patch_vuex_state(self, path: str, value: Any, dry_run: bool, require_confirm: bool, *, force_select: bool = False) -> JsonDict:
        """按安全开关修改 Vuex state；默认 dryRun 不修改。"""
        if dry_run or not require_confirm:
            return {"ok": True, "dryRun": True, "message": "未修改 state；需要 dryRun=false 且 requireConfirm=true", "path": path, "value": value}
        if not path:
            return {"ok": False, "error": "path 不能为空"}
        if force_select:
            await self.select_appservice_context(force=True)
        expr = (
            "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "var s=(g.$store||g.store||g.__store__||{}).state;if(!s)return {ok:false,error:'no state'};"
            "var parts=" + json.dumps(path.split("."), ensure_ascii=False) + ";var o=s;"
            "for(var i=0;i<parts.length-1;i++){o=o[parts[i]];if(o==null)return {ok:false,error:'路径中断于 '+parts.slice(0,i+1).join('.')};}"
            "o[parts[parts.length-1]]=" + json.dumps(value, ensure_ascii=False) + ";"
            "return {ok:true,path:parts.join('.'),value:o[parts[parts.length-1]]};})()"
        )
        result = await self.eval_appservice_script(expr)
        payload_value = result.get("value") if isinstance(result, dict) else None
        return {
            "ok": bool(isinstance(payload_value, dict) and payload_value.get("ok")),
            "dryRun": False,
            "path": path,
            "result": payload_value,
            "mode": result.get("mode"),
            "warning": "已实际修改 state；请用 restore_vuex_state 或重开页面还原。",
        }

    async def restore_vuex_state(self, dry_run: bool, require_confirm: bool, *, force_select: bool = False) -> JsonDict:
        """恢复 Vuex state 快照占位；默认不修改。"""
        if force_select:
            await self.select_appservice_context(force=True)
        return {
            "ok": True,
            "dryRun": dry_run or not require_confirm,
            "supported": False,
            "message": "当前版本不支持自动还原：inspect_vuex_store 保存的快照需人工复核后写回。",
            "hint": (
                "要还原请用 runtime_ops(action='patch_vuex_state') 逐路径写回快照值，"
                "或直接重开页面（页面重建会重置 store）。"
            ),
        }

    async def list_interactive_elements(self) -> JsonDict:
        """列出当前页面可交互元素摘要。

        返回归一化成 `{ok, count, elements}`：以前直接把 `runtime_eval` 的裸信封
        （`{ok, type, value}`）透传出去，调用方拿不到 count，也分不清「0 个元素」
        和「求值失败」。
        """
        expr = "(()=>Array.from(document.querySelectorAll('button,a,input,textarea,[role=button]')).slice(0,200).map((e,i)=>({i,tag:e.tagName,text:(e.innerText||e.value||e.ariaLabel||'').slice(0,120),selector:e.id?'#'+e.id:e.className?e.tagName.toLowerCase()+'.'+String(e.className).split(/\\s+/).join('.') : e.tagName.toLowerCase()})))()"
        result = await self.runtime_eval(expr)
        elements = result.get("value") if isinstance(result, dict) else None
        if not isinstance(elements, list):
            exception = result.get("exception") if isinstance(result, dict) else None
            detail = ""
            if isinstance(exception, dict):
                detail = str((exception.get("exception") or {}).get("description") or exception.get("text") or "")
            return {
                "ok": False,
                "count": 0,
                "elements": [],
                "error": detail or "求值未返回数组",
                "raw": result,
            }
        payload: JsonDict = {"ok": True, "count": len(elements), "elements": elements}
        if elements:
            payload["renderer"] = "dom"
        else:
            payload["renderer"] = "native_or_empty"
            payload["hint"] = (
                "未发现任何 DOM 元素。Goji / 原生渲染的小程序界面没有 DOM，"
                "这**不是工具故障**；请改用 runtime_eval_appservice 直接调用页面方法或 wx API。"
            )
        return payload

    async def safe_click_and_observe(self, selector: str, require_confirm: bool, wait_ms: int = 300, capture_before_after: bool = True) -> JsonDict:
        """安全点击元素并观察请求变化；高风险文本需要确认。

        `wait_ms` 以前被工具层丢弃、观察窗口写死 0.3s —— 很多接口 300ms 内根本没发出去，
        所以「点了但没观察到新请求」经常是假阴性。
        """
        if not selector:
            return {"ok": False, "error": "selector 不能为空"}
        before_ids: set[str] = set()
        if capture_before_after:
            before_ids = {str(r.get("id")) for r in (await self.get_all_requests(limit=2000)).get("requests", [])}
        expr = f"(()=>{{const e=document.querySelector({json.dumps(selector)});if(!e)return {{clicked:false,error:'not found'}};const t=e.innerText||e.value||'';if(/支付|提交订单|删除|注销|退款|提现|确认支付/.test(t)&&{str(bool(require_confirm)).lower()}!==true)return {{clicked:false,blocked:true,text:t}};e.click();return {{clicked:true,text:t}};}})()"
        clicked = await self.runtime_eval(expr)
        delay = min(max(int(wait_ms or 0), 0), 60_000) / 1000
        if delay:
            await asyncio.sleep(delay)
        after = await self.get_all_requests(limit=2000)
        click_value = clicked.get("value") if isinstance(clicked, dict) else None
        after_records = after.get("requests", [])
        new_requests = [r for r in after_records if str(r.get("id")) not in before_ids] if capture_before_after else []
        payload: JsonDict = {
            "ok": bool(isinstance(click_value, dict) and click_value.get("clicked")),
            "click": click_value,
            "waitMs": int(wait_ms),
            "newRequestCount": len(new_requests),
            "newRequests": [
                {"id": r.get("id"), "source": r.get("source"), "kind": r.get("kind"), "method": r.get("method"), "path": r.get("path")}
                for r in new_requests[:20]
            ],
        }
        if isinstance(click_value, dict) and click_value.get("blocked"):
            payload["hint"] = "命中高风险文案白名单，未执行点击。确需点击请传 requireConfirm=true。"
        elif not payload["ok"]:
            payload["hint"] = (
                "未点到元素。若 selector 正确仍失败，多半是 Goji/原生渲染没有 DOM；"
                "请改用 runtime_eval_appservice 调用页面方法。"
            )
        return payload

    async def input_text_and_observe(self, selector: str, text: str, wait_ms: int = 800) -> JsonDict:
        """向输入框写入文本并触发 input/change 事件，随后观察新增请求。

        `wait_ms` 以前被工具层丢弃（写死无等待），输入类联动请求经常来不及产生。
        """
        before_ids = {str(r.get("id")) for r in (await self.get_all_requests(limit=2000)).get("requests", [])}
        expr = f"(()=>{{const e=document.querySelector({json.dumps(selector)});if(!e)return {{ok:false,error:'not found'}};e.value={json.dumps(text)};e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));return {{ok:true}};}})()"
        result = await self.runtime_eval(expr)
        value = result.get("value") if isinstance(result, dict) else None
        delay = min(max(int(wait_ms or 0), 0), 60_000) / 1000
        if delay:
            await asyncio.sleep(delay)
        after_records = (await self.get_all_requests(limit=2000)).get("requests", [])
        new_requests = [r for r in after_records if str(r.get("id")) not in before_ids]
        payload: JsonDict = {
            "ok": bool(isinstance(value, dict) and value.get("ok")),
            "result": value,
            "waitMs": int(wait_ms),
            "newRequestCount": len(new_requests),
            "newRequests": [
                {"id": r.get("id"), "source": r.get("source"), "kind": r.get("kind"), "method": r.get("method"), "path": r.get("path")}
                for r in new_requests[:20]
            ],
        }
        if not payload["ok"]:
            payload["hint"] = "未找到输入框。Goji/原生渲染没有 DOM，请改用 runtime_eval_appservice。"
        return payload

    def build_api_inventory(self, requests: list[JsonDict]) -> JsonDict:
        """按 method+path 聚合接口清单；GraphQL 再按 operation 细分。

        GraphQL 小程序所有业务接口都打同一个端点，只按 method+path 会聚成一行
        （实测整个业务面只剩 `POST /v3/`），接口清单等于废掉。
        这里把 `operationName` / `persistedQuery hash` 并入聚合键。
        """
        groups: dict[str, JsonDict] = {}
        graphql_count = 0
        for req in requests:
            operation = str(req.get("graphqlOperation") or "")
            operation_id = str(req.get("graphqlOperationId") or "")
            base = f"{req.get('method')} {req.get('path')}"
            if req.get("isGraphQL"):
                graphql_count += 1
                suffix = operation or (f"#{operation_id[:12]}" if operation_id else "#<unknown-op>")
                key = f"{base} {suffix}"
            else:
                key = base
            group = groups.setdefault(
                key,
                {
                    "key": key,
                    "method": req.get("method"),
                    "path": req.get("path"),
                    "isGraphQL": bool(req.get("isGraphQL")),
                    "operation": operation or None,
                    "operationId": operation_id or None,
                    "count": 0,
                    "statusCodes": set(),
                    "examples": [],
                },
            )
            group["count"] += 1
            if req.get("statusCode") is not None:
                group["statusCodes"].add(req.get("statusCode"))
            if len(group["examples"]) < 3:
                group["examples"].append(req.get("id"))
        apis = [{**g, "statusCodes": sorted(g["statusCodes"])} for g in groups.values()]
        apis.sort(key=lambda item: int(item.get("count") or 0), reverse=True)
        return {
            "ok": True,
            "total": len(apis),
            "graphqlRequests": graphql_count,
            "apis": apis,
            **(
                {"note": "GraphQL 请求已按 operationName 拆分，不再聚成同一个端点。"}
                if graphql_count
                else {}
            ),
        }

    @classmethod
    def _contains_effective_auth(cls, node: Any, depth: int = 0) -> bool:
        """递归判断结构里是否存在【非空】的认证字段值。

        只看字段名是不够的 —— 实测 `{"token": ""}` 这种「字段在、值为空」的形态
        非常常见（小程序未登录时就是这样）。若只匹配字段名，它会被判成「有认证」
        从而**跳过**，直接漏报未授权访问（P2-7②，与 P0-1 同类的假阴性）。
        """
        if depth > 4 or node is None:
            return False
        if isinstance(node, dict):
            for key, value in node.items():
                if AUTH_FIELD_RE.search(str(key)) and not isinstance(value, bool):
                    if isinstance(value, (str, int, float)) and str(value).strip():
                        return True
                if cls._contains_effective_auth(value, depth + 1):
                    return True
            return False
        if isinstance(node, (list, tuple)):
            return any(cls._contains_effective_auth(item, depth + 1) for item in node)
        if isinstance(node, str):
            # 纯字符串形态无法区分键与值，退化为整体匹配（保持原行为）
            return bool(AUTH_FIELD_RE.search(node))
        return False

    def analyze_auth_surface(self, requests: list[JsonDict]) -> JsonDict:
        """分析请求中认证字段位置和缺失认证线索。

        判据是「是否携带了**非空**凭据」—— 空串（`token: ""`）等同于没有凭据。
        """
        findings = []
        for req in requests:
            has_auth = (
                self._contains_effective_auth(req.get("requestHeaders"))
                or self._contains_effective_auth(req.get("query"))
                or self._contains_effective_auth(req.get("requestBodyPreview"))
            )
            if not has_auth and req.get("statusCode") in {200, 201, 204, None}:
                findings.append(
                    {
                        "type": "missing_auth_candidate",
                        "requestId": req.get("id"),
                        "url": req.get("url"),
                        **self.finding_context(req),
                    }
                )
        return {
            "ok": True,
            "count": len(findings),
            "findings": findings,
            "note": "仅为线索，需在授权环境使用无/伪造凭据对比验证",
        }

    @staticmethod
    def api_label(req: JsonDict) -> str:
        """给请求生成可读标签：`METHOD path [#operation]`。

        GraphQL 请求的 path 全是同一个端点（实测 `/v3/`），
        不带 operation 的话所有线索都长一个样，根本分不清是哪个接口。
        """
        base = f"{req.get('method')} {req.get('path')}"
        operation = str(req.get("graphqlOperation") or "")
        if operation:
            return f"{base} #{operation}"
        operation_id = str(req.get("graphqlOperationId") or "")
        if operation_id:
            return f"{base} #{operation_id[:12]}"
        return base

    @classmethod
    def finding_context(cls, req: JsonDict) -> JsonDict:
        """线索里统一附带的接口定位信息。"""
        return {
            "api": cls.api_label(req),
            "operation": req.get("graphqlOperation"),
            "operationId": req.get("graphqlOperationId"),
        }

    @staticmethod
    def collect_idor_signals(req: JsonDict) -> tuple[list[str], list[str], list[JsonDict]]:
        """收集一个请求里的 ID 类字段名与可枚举 ID 值。

        关键缺口：GraphQL 的 ID 藏在 `variables`（URL query 里是 **JSON 字符串**，
        POST body 里是对象）—— 以前只看顶层 key，`userId` 这种直接漏掉，
        导致 `find_idor_candidates` 对 GraphQL 小程序恒为 0。
        另外把疑似 base64 的值解一层：`VXNlcjoxNzcx...` 解开是 `User:1771...`，
        这种全局可枚举 ID 正是越权测试最想找的。
        """
        names: list[str] = []
        encoded_values: list[JsonDict] = []
        json_candidates: list[Any] = [req.get("requestBodyPreview")]

        query = req.get("query") if isinstance(req.get("query"), dict) else {}
        for key, value in query.items():
            names.append(str(key))
            if str(key).lower() in {"variables", "input", "params", "data"}:
                json_candidates.append(value)

        body = req.get("requestBodyPreview")
        if isinstance(body, dict):
            for key, value in body.items():
                names.append(str(key))
                if str(key).lower() in {"variables", "input", "params", "data"}:
                    json_candidates.append(value)

        fields: set[str] = set()
        for candidate in json_candidates:
            payload = safe_json_loads(candidate)
            if not isinstance(payload, dict):
                continue
            for key, value in payload.items():
                fields.add(str(key))
                text = str(value)
                if not re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", text):
                    continue
                try:
                    decoded = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace")
                except Exception:
                    continue
                if re.search(r"\d{6,}", decoded) or ":" in decoded:
                    encoded_values.append(
                        {"field": str(key), "value": compact_text(text, 44), "decoded": compact_text(decoded, 90)}
                    )
        return names, sorted(fields), encoded_values

    def find_idor_candidates(self, requests: list[JsonDict]) -> JsonDict:
        """识别路径、查询、body 与 GraphQL variables 中含 ID 字段的越权候选接口。"""
        candidates = []
        for req in requests:
            names, variable_fields, encoded_values = self.collect_idor_signals(req)
            path_ids = re.findall(r"/(\d+|undefined)(?=/|$)", str(req.get("path") or ""))
            id_fields = [name for name in names if ID_FIELD_RE.search(name)]
            # JSON payload 的键名**必须过滤后再进 idFields**。此前是无过滤 extend，
            # 于是 `isList` / `page` / `size` / `type` 全被当成 ID 字段 → 候选虚增、全是噪声。
            # 完整键名仍保留在 `jsonPayloadFields` 里（不丢线索），只是不再冒充 ID。
            json_id_fields = [name for name in variable_fields if JSON_ID_FIELD_RE.search(name)]
            id_fields.extend(json_id_fields)
            if path_ids or id_fields or encoded_values:
                candidates.append(
                    {
                        "requestId": req.get("id"),
                        "method": req.get("method"),
                        "url": req.get("url"),
                        "pathIds": path_ids,
                        "fields": sorted(set(names)),
                        "idFields": sorted(set(id_fields)),
                        "jsonPayloadFields": sorted(set(variable_fields)),
                        "enumerableIds": encoded_values,
                        **self.finding_context(req),
                    }
                )
        candidates.sort(key=lambda item: -len(item.get("enumerableIds") or []))
        # 同一个接口会出现多次（分页/重复请求），按 api 标签去重合并，
        # 否则 Agent 看到 25 条几乎一样的候选反而漏掉真正的差异。
        merged: dict[str, JsonDict] = {}
        for item in candidates:
            label = str(item.get("api") or item.get("url") or "")
            existing = merged.get(label)
            if existing is None:
                merged[label] = item
                continue
            existing["idFields"] = sorted(set((existing.get("idFields") or [])) | set(item.get("idFields") or []))
            existing["fields"] = sorted(set((existing.get("fields") or [])) | set(item.get("fields") or []))
            existing["jsonPayloadFields"] = sorted(
                set((existing.get("jsonPayloadFields") or [])) | set(item.get("jsonPayloadFields") or [])
            )
            existing["pathIds"] = sorted(set((existing.get("pathIds") or [])) | set(item.get("pathIds") or []))
            existing["examples"] = sorted(
                {str(e) for e in (existing.get("examples") or [])} | {str(item.get("requestId"))}
            )[:5]
            known_ids = {(e.get("field"), e.get("decoded")) for e in (existing.get("enumerableIds") or [])}
            for encoded in item.get("enumerableIds") or []:
                if (encoded.get("field"), encoded.get("decoded")) not in known_ids:
                    existing.setdefault("enumerableIds", []).append(encoded)
        result: JsonDict = {
            "ok": True,
            "count": len(merged),
            "candidates": list(merged.values()),
            "note": (
                "enumerableIds 是解出来的可枚举 ID（如 User:<数字>），**优先按它排序判断越权价值**。"
                "读法：`idFields` 是**过滤后**的疑似 ID 字段名（可信度较高）；"
                "`jsonPayloadFields` 是 JSON payload 里的**全部**键名（含 page/size/isList 这类非 ID 参数，"
                "只作线索、别当 ID 用）。**`enumerableIds` 为空的候选基本没有可验证价值**，"
                "先看非空的那些。"
            ),
        }
        if not candidates:
            result["hint"] = (
                "没有发现带 ID 字段的接口。可能原因：① 只走了 tab 页，没进业务详情页；"
                "② 接口把 ID 放在请求头里（本工具不扫请求头，需人工核对）；"
                "③ ID 是随机不可枚举的。"
            )
        return result

    @classmethod
    def iter_json_field_paths(cls, value: Any, prefix: str = "", depth: int = 0) -> list[str]:
        """递归收集 JSON 里的**字段路径**（只取 key，不取 value）。

        为什么要只取 key：实测埋点 body 里有 `"logging-id": "user-profile.id-card"` ——
        值里带 `id-card`，但那是个**埋点事件名**，不是身份证字段。
        把整个 JSON 当文本匹配会把这类值噪声全算成 finding。
        返回的是点分路径（`data.node.profileInfo.phone`），便于直接定位到字段。
        """
        if depth > 8:
            return []
        paths: list[str] = []
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                paths.append(path)
                paths.extend(cls.iter_json_field_paths(child, path, depth + 1))
        elif isinstance(value, list):
            for item in value[:20]:
                paths.extend(cls.iter_json_field_paths(item, prefix, depth + 1))
        elif isinstance(value, str) and value[:1] in "{[":
            try:
                paths.extend(cls.iter_json_field_paths(json.loads(value), prefix, depth + 1))
            except (TypeError, ValueError):
                pass
        return paths

    @staticmethod
    def mask_pii_text(text: str) -> str:
        """把文本里**格式明确**的 PII 打码。

        `find_sensitive_data_exposure` 的 docstring 写着「默认脱敏」，
        但以前 `preview` 直接把响应体原文塞进结果 —— 实测里面就有
        `"mobile":"00000000000"` 这样的明文手机号，等于把 PII 又抄进了报告。
        """
        for _label, pattern in PII_VALUE_PATTERNS:
            text = pattern.sub(lambda m: m.group(0)[:3] + "***" + m.group(0)[-2:], text)
        return text

    def find_sensitive_data_exposure(self, requests: list[JsonDict]) -> JsonDict:
        """在响应里查找 **PII 字段名**并默认脱敏。

        凭据类字段（token / cookie / authorization …）**预期存在** ——
        实测每个请求都带 `X-Auth-Token`，把它们算成 finding 会让
        「敏感信息暴露」恒为 100% 命中、零信息量。所以这里只对 PII 计 finding，
        凭据单独放进 `credentialFields` 供参考。

        **匹配对象是字段路径而不是整段 JSON 文本**：
        以前 `json.dumps(整个响应)` 去匹配，值里的偶然字串也算命中 ——
        实测埋点 body 的 `"logging-id": "user-profile.id-card"` 就是这样被误报成
        「身份证字段」的。现在只匹配 key；响应不是结构化 JSON 时才退回全文匹配。

        ⚠️ 已知限制（按字段名判定带来的）：裸 `mobile` 被排除（某目标的
        `"mobile":{"device_type":...}` 是设备信息对象而非手机号），代价是
        `"mobile":"00000000000"` 这种真手机号也不会报出来。响应体里的手机号/邮箱/
        身份证仍会被 `preview` 打码，人工看 preview 能发现。
        """
        findings = []
        credential_only = 0
        for req in requests:
            preview = req.get("responseBodyPreview")
            field_paths = self.iter_json_field_paths(preview)
            if field_paths:
                text = "\n".join(field_paths)
                matched_paths = [p for p in field_paths if PII_FIELD_RE.search(p)][:10]
                value_level = False
            else:
                # 响应不是结构化 JSON（HTML / 纯文本）—— 退回全文匹配，但如实标注
                text = json.dumps(preview, ensure_ascii=False)
                matched_paths = []
                value_level = True
            pii = PII_FIELD_RE.matched_tokens(text)
            credentials = CREDENTIAL_FIELD_RE.matched_tokens(text)
            if not pii:
                if credentials:
                    credential_only += 1
                continue
            raw_preview = json.dumps(preview, ensure_ascii=False)
            findings.append(
                {
                    "requestId": req.get("id"),
                    "url": req.get("url"),
                    "matched": pii[:20],
                    "matchedFields": matched_paths,
                    "credentialFields": credentials[:10],
                    **({"valueLevelMatch": True} if value_level else {}),
                    # 打码后再放进结果，否则等于把 PII 抄进报告
                    "preview": self.mask_pii_text(compact_text(raw_preview, 500)),
                    **self.finding_context(req),
                }
            )
        return {
            "ok": True,
            "count": len(findings),
            "findings": findings,
            "credentialOnlyResponses": credential_only,
            "note": (
                "只统计 PII（手机号/邮箱/身份证/姓名/地址/银行卡/openid），且只匹配**字段名**。"
                "凭据类字段（token/cookie/authorization）预期存在，不计入 finding。"
                "`mobile`、`identity` 这类多义字段已排除"
                "（实测命中 `\"mobile\":{\"device_type\":...}` 与 `hasIdentityBadge`，都不是 PII）。"
                "响应不是结构化 JSON 时会退回全文匹配，此时会带 `valueLevelMatch: true`，"
                "值里的偶然字串可能造成误报，需人工核对。"
                "`preview` 已对格式明确的 PII 打码。"
            ),
        }
    @staticmethod
    def request_surface(req: JsonDict) -> str:
        """构造用于风险匹配的「接口面」文本。

        以前直接 `json.dumps(req)` 拿整条记录去匹配，会把 `callStack` / `raw` /
        `responseHeaders` 里的偶然字串也算命中 —— 实测 `find_debug_admin_surfaces`
        因此报了 33 条、`find_upload_surfaces` 报了 24 条噪声，真实线索被淹没。
        这里只保留表达接口语义的部分：method / path / query / 请求体 / 请求头。
        """
        return "\n".join(
            [
                str(req.get("method") or ""),
                str(req.get("path") or ""),
                json.dumps(req.get("query") or {}, ensure_ascii=False, default=str),
                json.dumps(req.get("requestBodyPreview"), ensure_ascii=False, default=str),
                json.dumps(req.get("requestHeaders") or {}, ensure_ascii=False, default=str),
            ]
        )

    def find_by_regex(self, requests: list[JsonDict], pattern: re.Pattern, finding_type: str) -> JsonDict:
        """按正则在接口面（path / query / 请求体 / 请求头）中筛选风险面。

        `matched` 只报**强** token；命中弱 token（如 `timestamp` / `nonce`）
        不构成 finding，但会作为 `weakMatched` 附在结果里，
        方便判断「为什么这条看起来像但没报」。
        """
        hits = []
        weak_only = 0
        for req in requests:
            text = self.request_surface(req)
            weak = pattern.weak_matched_tokens(text)[:6] if hasattr(pattern, "weak_matched_tokens") else []
            if pattern.search(text):
                hits.append(
                    {
                        "type": finding_type,
                        "requestId": req.get("id"),
                        "method": req.get("method"),
                        "url": req.get("url"),
                        "statusCode": req.get("statusCode"),
                        # 命中了哪些词 —— 以前不带这个，拿到 finding 也不知道为什么命中
                        "matched": pattern.matched_tokens(text)[:12],
                        **({"weakMatched": weak} if weak else {}),
                        **self.finding_context(req),
                    }
                )
            elif weak:
                weak_only += 1
        result: JsonDict = {"ok": True, "count": len(hits), "findings": hits}
        if weak_only:
            result["weakOnlyCount"] = weak_only
            result["weakOnlyNote"] = (
                f"{weak_only} 条只命中弱 token（timestamp/nonce 之类），未计入 finding ——"
                f"这类字段在埋点里遍地都是，单独出现不足以证明存在签名。"
            )
        return result

    async def build_replay_plan(self, request_id: str) -> JsonDict:
        """根据请求生成 Burp/手工重放计划，不自动发送请求。"""
        detail = await self.get_request_detail(request_id)
        if not detail.get("ok"):
            return detail
        req = detail["request"]
        return {"ok": True, "requestId": request_id, "manualOnly": True, "method": req.get("method"), "url": req.get("url"), "headers": req.get("requestHeaders"), "body": req.get("requestBodyPreview"), "checks": ["删除/替换 Authorization 后对比响应", "修改 ID 字段为本人相邻资源 ID", "timestamp/nonce/sign 保持原值测试重放窗口", "写操作必须人工确认且只在授权测试数据上执行"]}

    async def compare_two_requests(self, a: str, b: str) -> JsonDict:
        """对比两个请求的 URL、认证字段、Body 和状态差异。"""
        da = await self.get_request_detail(a)
        db = await self.get_request_detail(b)
        if not da.get("ok") or not db.get("ok"):
            return {"ok": False, "a": da, "b": db}
        ra, rb = da["request"], db["request"]
        return {"ok": True, "diff": {"urlChanged": ra.get("url") != rb.get("url"), "methodChanged": ra.get("method") != rb.get("method"), "statusChanged": ra.get("statusCode") != rb.get("statusCode"), "queryA": ra.get("query"), "queryB": rb.get("query"), "authA": self.extract_auth_fields(ra), "authB": self.extract_auth_fields(rb)}}

    def extract_auth_fields(self, req: JsonDict) -> JsonDict:
        """提取请求中的认证相关字段。"""
        out: JsonDict = {}
        for source_name in ["requestHeaders", "query"]:
            data = req.get(source_name) or {}
            if isinstance(data, dict):
                out[source_name] = {k: "***" if len(str(v)) > 8 else v for k, v in data.items() if AUTH_FIELD_RE.search(str(k))}
        return out

    def passive_param_fuzz_suggestions(self, requests: list[JsonDict]) -> JsonDict:
        """基于已捕获参数生成被动 fuzz 建议，不发送请求。"""
        suggestions = []
        for req in requests:
            params = list((req.get("query") or {}).keys())
            body = req.get("requestBodyPreview")
            if isinstance(body, dict):
                params.extend(body.keys())
            interesting = [p for p in params if ID_FIELD_RE.search(str(p)) or AUTH_FIELD_RE.search(str(p))]
            if interesting:
                suggestions.append({"requestId": req.get("id"), "url": req.get("url"), "parameters": interesting, "tests": ["空值", "本人相邻 ID", "超长字符串", "类型切换 number/string"]})
        return {"ok": True, "suggestions": suggestions}

    def generate_security_notes(self, requests: list[JsonDict], max_length: int = 80_000) -> JsonDict:
        """生成 Markdown 报告素材；`max_length` 控制返回体积。

        以前只输出占位（「认证面：见 analyze_auth_surface」），不写实际结论，
        调用方还得自己把各分析结果拼一遍。现在直接把各分析结果内嵌成章节。
        """
        inventory = self.build_api_inventory(requests)
        lines: list[str] = [
            "# 小程序安全评估笔记",
            "",
            f"生成时间：{now_iso()}",
            "",
            f"接口数量：{len(inventory.get('apis', []))}（GraphQL 请求 {inventory.get('graphqlRequests', 0)} 条）",
            "",
            "## 接口清单",
            "",
            self.generate_api_table_markdown(requests, max_length=max(4_000, max_length // 4)),
        ]
        sections = [
            ("认证面", self.analyze_auth_surface(requests)),
            ("IDOR 候选", self.find_idor_candidates(requests)),
            ("敏感信息暴露", self.find_sensitive_data_exposure(requests)),
            ("调试 / 后台面", self.find_by_regex(requests, DEBUG_ADMIN_RE, "debug_admin")),
            ("上传面", self.find_by_regex(requests, UPLOAD_RE, "upload")),
            ("支付 / 订单面", self.find_by_regex(requests, PAYMENT_RE, "payment_order")),
            ("签名相关", self.find_by_regex(requests, SIGN_RE, "sign_related")),
        ]
        for title, result in sections:
            findings = result.get("findings") or result.get("candidates") or []
            lines += ["", f"## {title}（{len(findings)} 条）", ""]
            if not findings:
                lines.append("_无。注意：可能是确实没有，也可能流量不足或只走了 tab 页。_")
                continue
            for item in findings[:40]:
                label = str(item.get("api") or item.get("url") or "")
                matched = item.get("matched") or item.get("fields") or item.get("pathIds") or []
                suffix = f"　matched/fields={matched}" if matched else ""
                lines.append(f"- `{label}`{suffix}")
        markdown, truncated = truncate_text("\n".join(lines), max_length)
        return {"ok": True, "markdown": markdown, "truncated": truncated, "maxLength": int(max_length)}

    def generate_api_table_markdown(self, requests: list[JsonDict], max_length: int = 80_000) -> str:
        """生成接口清单 Markdown 表格；`max_length` 控制返回体积。

        GraphQL 请求的 path 全是同一个端点，表格里必须带 operation，
        否则 5 个 operation 会渲染成 5 行一模一样的 `/v3/`（实测踩过）。
        """
        inventory = self.build_api_inventory(requests).get("apis", [])
        lines = ["| Method | Path | Operation | Count | Status |", "|---|---|---|---:|---|"]
        for api in inventory:
            operation = str(api.get("operation") or ("#" + str(api.get("operationId"))[:12] if api.get("isGraphQL") else ""))
            lines.append(
                f"| {api.get('method')} | `{api.get('path')}` | {operation or '—'} | {api.get('count')} | {','.join(map(str, api.get('statusCodes', [])))} |"
            )
        markdown, _truncated = truncate_text("\n".join(lines), max_length)
        return markdown

    async def export_session(self, requests: list[JsonDict]) -> JsonDict:
        """导出当前 MCP 采集会话到 e0e1-wx/output/reports，文件写入放入线程执行。

        目录锚定在包目录上而不是工作目录：否则导出的落点会随启动方式变化
        （`02-一键启动.bat` 与手工启动的 CWD 不同），文件会「找不到」。
        """
        report_dir = PACKAGE_DIR.parent / "output" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / f"mcp-session-{int(time.time())}.json"
        payload = {"createdAt": now_iso(), "status": await self.status(), "requests": requests, "scripts": list(self.scripts.values())}
        await asyncio.to_thread(path.write_text, json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return {"ok": True, "path": str(path), "requestCount": len(requests)}

    async def run_decrypt_pipeline(self, value: str, steps: list[Any]) -> JsonDict:
        """按步骤执行多层解码/解密流水线。"""
        current = value
        outputs = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            action = str(step.get("action") or "decode_payload")
            if action.startswith("decode"):
                result = decode_payload(current, str(step.get("encoding") or step.get("input_encoding") or "auto"))
                current = result.get("text") or result.get("hex_preview") or current
            elif action.startswith("decrypt"):
                result = decrypt_payload(current, algorithm=str(step.get("algorithm") or "aes"), key=str(step.get("key") or ""), mode=str(step.get("mode") or "cbc"), iv=str(step.get("iv") or ""), input_encoding=str(step.get("input_encoding") or "base64"), key_encoding=str(step.get("key_encoding") or "utf-8"))
                current = result.get("text") or current
            else:
                result = {"error": f"未知步骤：{action}"}
            outputs.append({"step": step, "result": result})
        return {"ok": True, "final": current, "steps": outputs}

    async def discover_runtime_crypto_functions(self, *, limit: int = 200) -> JsonDict:
        """枚举运行时中疑似加密/签名函数。

        以前只扫 `globalThis` 的 key —— 但业务加密函数基本都藏在 webpack 模块里，
        所以经常返回空数组，让人误以为「没有加密」。这里同时扫：
          * `globalThis`
          * `getApp()` 及其 `globalData`
          * `__webpack_require__.c` 的模块 exports（浅层递归）
        并用函数表达式包裹（appservice 引擎对「箭头函数 + try」会语法报错）。
        """
        expr = (
            "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "var re=/encrypt|decrypt|sign|signature|crypto|md5|sha1|sha256|aes|des|rsa|hmac|base64|token/i;"
            "var out=[];var seen=[];var LIMIT=" + str(max(1, int(limit))) + ";"
            "function push(where,name,kind){if(out.length>=LIMIT)return;if(!re.test(String(name)))return;"
            "out.push({where:where,name:String(name),kind:kind});}"
            "function walk(obj,where,depth){if(out.length>=LIMIT)return;"
            "var t=typeof obj;if(!obj||(t!=='object'&&t!=='function'))return;"
            "if(seen.indexOf(obj)>=0)return;seen.push(obj);"
            "var ks=[];try{ks=Object.keys(obj)}catch(e){ks=[]}"
            "for(var i=0;i<ks.length&&i<600;i++){var k=ks[i];var v;try{v=obj[k]}catch(e){continue}"
            "push(where,k,typeof v);"
            "if(v&&(typeof v==='object'||typeof v==='function')&&depth<2)walk(v,where+'.'+k,depth+1);}}"
            "walk(g,'globalThis',0);"
            "try{if(typeof g.getApp==='function'){var app=g.getApp();walk(app,'getApp()',0);"
            "if(app&&app.globalData)walk(app.globalData,'getApp().globalData',0);}}catch(e){}"
            "try{var wr=g.__webpack_require__;if(wr&&wr.c){for(var mid in wr.c){if(out.length>=LIMIT)break;"
            "try{var m=wr.c[mid];if(m&&m.exports)walk(m.exports,'webpack['+mid+'].exports',0);}catch(e){}}}}catch(e){}"
            "return out;})()"
        )
        result = await self.eval_appservice_script(expr)
        candidates = result.get("value") if isinstance(result, dict) else None
        if not isinstance(candidates, list):
            return {"ok": False, "error": "扫描未返回数组", "mode": result.get("mode"), "raw": result}
        deduped: list[JsonDict] = []
        seen_keys: set[str] = set()
        for item in candidates:
            if not isinstance(item, dict):
                continue
            key = f"{item.get('where')}::{item.get('name')}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped.append(item)
        payload: JsonDict = {
            "ok": True,
            "count": len(deduped),
            "mode": result.get("mode"),
            "candidates": deduped,
            "nextStep": (
                "用 decrypt_ops(action='call_runtime_crypto_function', function_name='<where 去掉 globalThis. 前缀后的路径>', args=[...]) "
                "直接调用验证；where 里的 webpack[x].exports 说明它来自打包模块。"
            ),
        }
        if not deduped:
            payload["hint"] = (
                "没有扫到疑似加密函数。这不等于目标没加密——常见原因是："
                "① 加密逻辑在闭包里没有挂到任何可枚举对象上；"
                "② 小程序还没走到触发加密的页面；"
                "③ 需要先 hook_wx_request 抓到密文参数再回溯源码（见 SKILL.md 场景 6）。"
            )
        return payload

    async def call_runtime_crypto_function(self, function_name: str, args: list[Any]) -> JsonDict:
        """调用指定运行时函数并返回结果，支持点分路径。

        以前只支持 `globalThis` 上的顶层名字；现在可以传
        `getApp().globalData.crypto.aesEncrypt` 或 `webpack[12].exports.sign` 这类路径。
        """
        if not function_name:
            return {"ok": False, "error": "function_name 不能为空"}
        path_parts = [part for part in re.split(r"\.|\[\s*'?|'\s*\]|\s*\]", function_name) if part not in {"", "()"}]
        # `getApp()` 里的 () 去掉，保留 getApp 作为函数调用
        path_parts = [part.replace("()", "") for part in path_parts]
        if not path_parts:
            return {"ok": False, "error": "无法解析 function_name 路径"}
        args_literal = json.dumps(args or [], ensure_ascii=False)
        path_literal = json.dumps(path_parts, ensure_ascii=False)
        expr = (
            "(function(){var g=(typeof window!=='undefined'&&window.__as)?window.__as:globalThis;"
            "var path=" + path_literal + ";var cur=g;var label=[];"
            "for(var i=0;i<path.length;i++){var seg=path[i];label.push(seg);"
            "if(cur==null)return {ok:false,error:'路径中断于 '+label.join('.')};"
            "if(seg==='getApp'&&typeof cur.getApp==='function'){cur=cur.getApp();continue;}"
            "cur=cur[seg];}"
            "if(typeof cur!=='function')return {ok:false,error:'不是函数: '+path.join('.'),type:typeof cur};"
            "try{var out=cur.apply(null," + args_literal + ");return {ok:true,value:out,type:typeof out};}"
            "catch(e){return {ok:false,error:String(e&&e.message||e)}}})()"
        )
        result = await self.eval_appservice_script(expr)
        value = result.get("value") if isinstance(result, dict) else None
        if isinstance(value, dict):
            return {"ok": bool(value.get("ok")), "functionName": function_name, "path": path_parts, "result": value, "mode": result.get("mode")}
        return {"ok": False, "functionName": function_name, "error": "求值未返回对象", "raw": result}

    def match_reverse_cases(self, text: str) -> JsonDict:
        """把源码特征映射到当前项目 SKILL.md 的逆向场景。"""
        pattern = identify_crypto_pattern(text).get("patterns", {})
        cases = []
        if pattern.get("webpack"):
            cases.append("场景 7：Webpack 打包逆向")
        if pattern.get("jsvmp"):
            cases.append("场景 8：JSVMP 虚拟机保护")
        if pattern.get("aes") or pattern.get("rsa") or pattern.get("md5"):
            cases.append("场景 2/6/10：加密参数与动态密钥追踪")
        return {"ok": True, "cases": cases, "patterns": pattern}

    def detect_reverse_strategy(self, text: str) -> JsonDict:
        """根据代码保护特征给出逆向优先策略。"""
        matched = self.match_reverse_cases(text)
        patterns = matched.get("patterns", {})
        if patterns.get("jsvmp"):
            strategy = "优先 hook_wx_request 截取最终签名；若失败再做入口/出口断点追踪"
        elif patterns.get("webpack"):
            strategy = "先枚举 __webpack_require__.c 模块缓存，再按 encrypt/sign/request 关键词定位模块"
        else:
            strategy = "先 search_in_sources 搜索 encrypt/decrypt/sign，再用 break_on_xhr 获取调用栈"
        return {"ok": True, "strategy": strategy, "matched": matched}

    async def cdp_call(self, method: str, params: JsonDict | None = None, session_id: str | None = None) -> JsonDict:
        """调用任意 CDP 方法，支持 flatten sessionId。"""
        if not method:
            return {"ok": False, "error": "method 不能为空"}
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return cdp_state
        result = await self.cdp.send(method, params or {}, session_id=session_id, timeout_ms=15000)
        return {"ok": True, "method": method, "sessionId": session_id, "result": result}

    async def cdp_call_target(self, target_id: str, method: str, params: JsonDict | None = None) -> JsonDict:
        """attach 到指定 targetId 后在子 session 中调用 CDP 方法。

        返回结构做了扁平化：CDP 的响应是 `{"result": {"result": {...}}}` 双层嵌套，
        截图数据在**第二层**的 `data`。这里额外给出 `value`（第二层整体）与 `data`，
        不用再记 `result.result.data` 这个坑。
        """
        if not target_id or not method:
            return {"ok": False, "error": "target_id 和 method 均不能为空"}
        cdp_state = await self.ensure_cdp()
        if not cdp_state.get("ok"):
            return cdp_state
        try:
            attached = await self.cdp.send("Target.attachToTarget", {"targetId": target_id, "flatten": True}, timeout_ms=10000)
        except Exception as exc:
            return {"ok": False, "stage": "attachToTarget", "targetId": target_id, "method": method, "error": str(exc)}
        session_id = attached.get("result", {}).get("sessionId")
        if not session_id:
            return {"ok": False, "stage": "attachToTarget", "error": "attachToTarget 未返回 sessionId", "raw": attached}
        try:
            result = await self.cdp.send(method, params or {}, session_id=session_id, timeout_ms=15000)
        except Exception as exc:
            return {
                "ok": False,
                "stage": "call",
                "targetId": target_id,
                "sessionId": session_id,
                "method": method,
                "error": str(exc),
                "hint": "页面切换过程中偶发；请稍等 1-2s 重试，或先 runtime_ops(action='wait_route_stable')。",
            }

        try:
            serialized = json.loads(json.dumps(result, ensure_ascii=False, default=str))
        except (TypeError, ValueError) as exc:
            return {"ok": False, "stage": "serialize", "method": method, "error": f"CDP 返回无法序列化：{exc}"}
        if not isinstance(serialized, dict):
            return {"ok": False, "stage": "shape", "method": method, "error": "CDP 返回不是对象", "raw": serialized}

        envelope = serialized.get("result")
        value = envelope.get("result") if isinstance(envelope, dict) else None
        payload: JsonDict = {
            "ok": True,
            "targetId": target_id,
            "sessionId": session_id,
            "method": method,
            "value": value,
            "result": serialized,
        }
        if isinstance(value, dict) and "data" in value:
            payload["data"] = value.get("data")
            if isinstance(value.get("data"), str) and len(value["data"]) > 200:
                payload["dataLength"] = len(value["data"])
                payload["note"] = "data 是 base64 编码的大字段（如截图 PNG）；已同时给出 value 与 data，不必再记 result.result.data。"
        return payload

    async def get_recent_requests(self, limit: int = 50, *, domain: str | None = None, path_prefix: str | None = None, keyword: str | None = None, compact: bool = True, exclude_static: bool = True) -> JsonDict:
        """返回最近 CDP/Hook 请求，兼容 wmpf-mcp-bridge 的 get_recent_requests。

        `exclude_static` 默认 True：这是工具 schema 一直声明但**从未生效**的参数
        （旧代码里直接 `del excludeStatic`），导致结果被字体 / 图片塞满。
        """
        data = await self.get_all_requests(
            limit=limit, keyword=keyword, domain=domain, path_prefix=path_prefix, exclude_static=exclude_static
        )
        if not compact:
            return data
        compact_items = [
            {"id": item.get("id"), "source": item.get("source"), "kind": item.get("kind"), "method": item.get("method"), "url": item.get("url"), "statusCode": item.get("statusCode")}
            for item in data.get("requests", [])
        ]
        result: JsonDict = {
            "ok": True,
            "compact": True,
            "requests": compact_items,
            "total": data.get("total", len(compact_items)),
            "excludeStatic": bool(exclude_static),
            "byKind": data.get("byKind"),
        }
        if data.get("filterNote"):
            result["filterNote"] = data["filterNote"]
        return result

    async def get_response_body(self, request_id: str) -> JsonDict:
        """读取 CDP Network.getResponseBody 响应体。

        返回**拍平**：`body` 提到顶层（原来只在 `result.body` 里，
        调用方按顶层 `body` 取会拿到空 —— 实测踩过，和 v2.14 修 `cdp_call_target`
        双层嵌套是同一类问题）。`result` 仍保留以兼容旧调用方。
        """
        if not request_id:
            return {"ok": False, "error": "request_id 不能为空"}
        try:
            result = await self.cdp.send("Network.getResponseBody", {"requestId": request_id}, timeout_ms=8000)
            payload = result.get("result", result)
            body = payload.get("body") if isinstance(payload, dict) else None
            base64_encoded = bool(payload.get("base64Encoded")) if isinstance(payload, dict) else False
            if base64_encoded and isinstance(body, str):
                try:
                    body = base64.b64decode(body).decode("utf-8", errors="replace")
                    base64_encoded = False
                except Exception:
                    pass
            return {
                "ok": True,
                "requestId": request_id,
                "body": body,
                "bodyLength": len(body) if isinstance(body, str) else None,
                "base64Encoded": base64_encoded,
                "result": payload,
            }
        except Exception as exc:
            return {"ok": False, "requestId": request_id, "error": str(exc)}

    async def get_recent_console(
        self,
        limit: int = 50,
        *,
        max_bytes: int = 24_000,
        max_text_length: int = 2_000,
    ) -> JsonDict:
        """返回最近 console、exception 和 paused 事件。**带硬体量上限。**

        ⚠️ 为什么必须加护栏：`limit` 只控制**条数**，不控制**字节数**。
        实测 `limit=40` 返回 80,940 字符、`limit=5` 返回 133,024 字符 ——
        后者更大**不是**「非单调」，而是两次调用之间 console 缓存内容变了
        （`[-5:]` 永远是 `[-40:]` 的子集）。单条巨长的异常/日志就能撑爆返回体，
        表现是每次调用都被上层转存成文件、**等于白调**。

        两层护栏：
          * `max_text_length` —— 单条事件里的字符串按此截断（默认 2000 字符/处）；
          * `max_bytes` —— 从**最新**往旧累计，超出即丢弃更早的事件
            （默认 24,000 字符，上限 400,000）。**至少保证返回 1 条**，
            不会出现「全被丢掉但 droppedByBytes>0」那种让人摸不着头脑的结果。

        要看更早的事件就调大 `max_bytes`；要找特定报错优先用
        `search_runtime_keywords` 定向，而不是把它整段拉回来。
        """
        events = list(self.console_events)[-max(1, int(limit)):]
        size_cap = max(1_024, min(int(max_bytes or 24_000), 400_000))
        text_cap = max(64, min(int(max_text_length or 2_000), 200_000))

        counter = [0]
        kept: list[Any] = []
        used = 0
        for raw in reversed(events):  # 从最新往旧装，先保住最新的
            shrunk = _shrink_console_event(raw, text_cap, counter)
            size = len(json.dumps(shrunk, ensure_ascii=False, default=str))
            if size > size_cap:
                # ⚠️ 单条事件自己就超上限时，**不能**靠「至少留 1 条」把它整条塞进去 ——
                # 实测一条带 50 个长栈帧的异常：每帧被 maxTextLength 截到 2000 后
                # 仍然 50×2000 = 100K，直接击穿上限（第一次实现就栽在这）。
                # 退化成截断预览，保证「返回体不超过上限」这条硬约束对任何输入都成立。
                preview = json.dumps(shrunk, ensure_ascii=False, default=str)
                shrunk = {
                    "_truncated": True,
                    "preview": preview[: max(200, size_cap - 300)],
                    "originalBytes": size,
                }
                size = len(json.dumps(shrunk, ensure_ascii=False))
                counter[0] += 1
            if kept and used + size > size_cap:
                break
            kept.append(shrunk)
            used += size
        kept.reverse()

        dropped = len(events) - len(kept)
        payload: JsonDict = {
            "ok": True,
            "events": kept,
            "returned": len(kept),
            "available": len(events),
            "droppedByBytes": dropped,
            "truncatedFields": counter[0],
            "maxBytes": size_cap,
            "maxTextLength": text_cap,
        }
        if dropped or counter[0]:
            payload["note"] = (
                f"为控制返回体量：超长字符串已按 maxTextLength 截断（{counter[0]} 处），"
                f"超出 maxBytes 的**更早**事件已被丢弃（{dropped} 条）。"
                "需要它们请调大 maxBytes，或先用 search_runtime_keywords 定向查找。"
            )
        return payload

    async def get_basic_page_info(self) -> JsonDict:
        """返回兼容旧版的基础页面快照。"""
        return await self.dump_runtime_snapshot()

    async def get_document_html(self, max_length: int = 20_000) -> JsonDict:
        """读取 document.documentElement.outerHTML 前缀。"""
        limit = max(1, int(max_length))
        expr = f"(()=>String(document.documentElement&&document.documentElement.outerHTML||'').slice(0,{limit}))()"
        result = await self.runtime_eval(expr)
        return {"ok": bool(result.get("ok")), "html": result.get("value"), "maxLength": limit}

    async def query_selector_text(self, selector: str, max_length: int = 10_000) -> JsonDict:
        """读取 document.querySelector(selector) 的文本和 HTML 摘要。"""
        if not selector:
            return {"ok": False, "error": "selector 不能为空"}
        limit = max(1, int(max_length))
        expr = f"(()=>{{const el=document.querySelector({json.dumps(selector)});if(!el)return {{ok:false,selector:{json.dumps(selector)},error:'Element not found'}};const cut=v=>String(v??'').slice(0,{limit});return {{ok:true,selector:{json.dumps(selector)},innerText:cut(el.innerText),textContent:cut(el.textContent),outerHTML:cut(el.outerHTML)}};}})()"
        result = await self.runtime_eval(expr)
        return result.get("value") if isinstance(result.get("value"), dict) else result

    async def inspect_window_keys(self, pattern: str | None = None, limit: int = 200) -> JsonDict:
        """列出 globalThis/window key，可按关键词过滤。"""
        expr = f"(()=>{{const pat={json.dumps(pattern or '')}.toLowerCase();const keys=Object.keys(globalThis).sort();const f=pat?keys.filter(k=>k.toLowerCase().includes(pat)):keys;return {{ok:true,pattern:pat,count:f.length,keys:f.slice(0,{max(1,int(limit))})}};}})()"
        result = await self.runtime_eval(expr)
        return result.get("value") if isinstance(result.get("value"), dict) else result

    async def search_global_string(self, keyword: str, max_length: int = 20_000) -> JsonDict:
        """搜索 document、storage、window keys 和请求缓存中的单个关键词。"""
        hits = await self.search_runtime_keywords([keyword])
        text = json.dumps(hits, ensure_ascii=False)
        return {"ok": True, "keyword": keyword, "result": safe_json_loads(text[: max(1, int(max_length))])}
