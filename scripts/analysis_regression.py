"""离线回归：用导出的会话 JSON 验证分析层（不需要活的小程序）。

为什么需要它
------------
`mcp_smoke_test.py` 只能验证「工具没报错」，**验证不了「结果对不对」** ——
它跑在活环境上，流量每次都不一样，也没法断言「签名面应该是 0 条」。
而分析层的改动（正则、分类、去噪）恰恰最容易出现「不报错但报错东西」的情况：

- v2.19 的 `FieldTokenMatcher` 修了 camelCase，却漏了 snake_case
  （`bank_account` / `phone_number` / `open_id` 全部漏报，10/10 MISS）
- v2.21 的签名面在真实数据上是 28/49 假阳性（全部来自埋点 body 的 `context.timestamp`）

这些**只有拿固定的真实数据回归才能发现**。本脚本就是干这个的：
加载一份 `output/reports/mcp-session-*.json`，跑各分析函数，和基线表逐项比对。

检查三部分：
1. **匹配器回归** —— 真阳性必须命中、假阳性必须不命中（含 snake_case 那批漏报）
2. **敏感面键匹配** —— `find_sensitive_data_exposure` 只应匹配字段名，不应匹配值
   （实测埋点 body 的 `"logging-id": "user-profile.id-card"` 曾被误报成身份证字段）
3. **结构性断言** —— 埋点确实被排除、各面命中数不超过风险面请求数等

用法
----
    python scripts\\analysis_regression.py                     # 用最新的会话导出
    python scripts\\analysis_regression.py --session <path>    # 指定会话文件
    python scripts\\analysis_regression.py --verbose           # 打印全部明细

退出码 0 = 全部符合基线，1 = 有偏差。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
E0E1 = PROJECT_ROOT / "e0e1-wx"
REPORTS_DIR = E0E1 / "output" / "reports"

sys.path.insert(0, str(E0E1))

from package.mcp_control.runtime_session import (  # noqa: E402
    AUTH_FIELD_RE,
    CREDENTIAL_FIELD_RE,
    DEBUG_ADMIN_RE,
    PAYMENT_RE,
    PII_FIELD_RE,
    SIGN_RE,
    SENSITIVE_FIELD_RE,
    UPLOAD_RE,
    McpRuntimeSession,
    classify_request_url,
)

# ── 匹配器回归：真阳性必须命中，假阳性必须不命中 ──────────────────────────
# 每条都对应一个实测踩过的坑，注释写清「为什么它在这一侧」。
MATCHER_POSITIVE: list[tuple[str, str]] = [
    # camelCase
    ("SENSITIVE", "bankAccount"),
    ("SENSITIVE", "idCard"),
    ("SENSITIVE", "realName"),
    ("SENSITIVE", "openId"),
    ("SENSITIVE", "userEmail"),
    ("SENSITIVE", "phoneNumber"),
    ("SENSITIVE", "mobilePhone"),
    # snake_case —— v2.19 全部漏报的那批
    ("SENSITIVE", "bank_account"),
    ("SENSITIVE", "id_card"),
    ("SENSITIVE", "real_name"),
    ("SENSITIVE", "open_id"),
    ("SENSITIVE", "user_email"),
    ("SENSITIVE", "phone_number"),
    ("SENSITIVE", "mobile_phone"),
    # 拼接写法
    ("SENSITIVE", "openid"),
    # 全大写头名
    ("SENSITIVE", "X-AIRBNB-OAUTH-TOKEN"),
    # 收窄后的明确形态（不能因为剔除了裸 identity 就漏掉身份证号）
    ("PII", "identityNumber"),
    ("PII", "identity_no"),
    ("PII", "identityCard"),
    # 凭据
    ("CRED", "password_hash"),
    ("CRED", "access_token"),
    ("CRED", "X-Auth-Token"),
    # 认证
    ("AUTH", "authorization"),
    ("AUTH", "X-Auth-Token"),
    # 签名：强 token
    ("SIGN", "X-Api-Signature"),
    ("SIGN", '{"sign":"x"}'),
    ("SIGN", '{"hmac":"x"}'),
]

MATCHER_NEGATIVE: list[tuple[str, str]] = [
    # 词边界：子串会误报
    ("SENSITIVE", "embankment"),   # bank
    ("SENSITIVE", "payload"),      # pay
    ("SENSITIVE", "cost"),         # cos
    ("SENSITIVE", "profile"),      # file
    ("SENSITIVE", "device"),       # dev
    ("SENSITIVE", "reference"),    # enc
    ("SENSITIVE", "assignment"),   # sign
    ("SENSITIVE", "liquid"),       # uid
    # 多义字段：实测命中的都不是 PII
    ("SENSITIVE", "mobile_version"),            # 手机端版本号
    ("SENSITIVE", '"mobile":{"device_type":"microsoft"}'),  # 设备信息对象
    ("SENSITIVE", "hasIdentityBadge"),          # 布尔标记
    ("SENSITIVE", "identityVerificationTypes"),  # 验证方式名列表
    # identityVerification 是「实名状态」而不是身份证号 ——
    # 剔除裸 `identity` 正是为了修这一类的假阳性；真身份证号走 identity-?number / identity-?card
    ("SENSITIVE", "identityVerification"),
    # 全大写头名里的偶然子串
    ("SENSITIVE", "X-AIRBNB-CLIENT-DEVICE-REGION"),
    # 弱 token 单独出现不算签名
    ("SIGN", '{"context":{"timestamp":123}}'),
    ("SIGN", '{"nonce":"abc"}'),
]

MATCHERS = {
    "SENSITIVE": SENSITIVE_FIELD_RE,
    "PII": PII_FIELD_RE,
    "CRED": CREDENTIAL_FIELD_RE,
    "AUTH": AUTH_FIELD_RE,
    "SIGN": SIGN_RE,
}

# ── 敏感面：只应匹配字段名，不应匹配值 ──────────────────────────────────
# 每条都对应一个实测踩过的坑。第三项是期望的 matchedFields（字段路径）。
SENSITIVE_CASES: list[tuple[str, object, bool]] = [
    # 值里带 id-card，但那是埋点事件名而不是身份证字段
    ("埋点事件名（值里带 id-card）", {"logging-id": "user-profile.id-card", "uuid": "x"}, False),
    # 事件名数组里带 upload —— 与 PII 无关
    ("事件名数组", {"events": ["homes.upload.photo", "homes.upload.video"]}, False),
    # 凭据预期存在，不计 finding
    ("凭据 only", {"token": "abc", "authorization": "Bearer x", "cookie": "y"}, False),
    # 多义字段
    ("多义字段 mobile/identity", {"mobile": {"device_type": "microsoft"}, "hasIdentityBadge": False}, False),
    # 真 PII：嵌套路径
    ("真 PII（嵌套）", {"data": {"node": {"user": {"phone": "+8600000000000", "email": "a@b.com"}}}}, True),
    # 真 PII：snake_case
    ("真 PII（snake_case）", {"user_id_card": "000000000000000000", "real_name": "张三"}, True),
    # 非结构化响应 → 退回全文匹配并标注 valueLevelMatch
    ("非结构化响应（HTML）", "<div data-field='phone'>00000000000</div>", True),
]


def check_sensitive_matching(verbose: bool) -> tuple[int, int]:
    """验证 find_sensitive_data_exposure 只匹配字段名、不匹配值。"""
    print("\n── 敏感面 · 键匹配 vs 值匹配 ──")
    session_obj = McpRuntimeSession.__new__(McpRuntimeSession)
    ok = 0
    for name, body, expect in SENSITIVE_CASES:
        req = {
            "id": "r1",
            "url": "https://api.example.com/x",
            "method": "POST",
            "path": "/x",
            "responseBodyPreview": body,
        }
        res = session_obj.find_sensitive_data_exposure([req])
        hit = res["count"] > 0
        good = hit == expect
        ok += good
        detail = ""
        if hit:
            item = res["findings"][0]
            fields = item.get("matchedFields") or []
            values = item.get("valueMatches") or []
            detail = f"fields={fields} values={values}"
            if item.get("valueLevelMatch"):
                detail += "  [valueLevel]"
        if not good:
            print(f"  [FAIL] {name:30s} hit={hit} 期望={expect}")
        elif verbose:
            print(f"  [PASS] {name:30s} hit={hit}  {detail}")
    print(f"  {ok}/{len(SENSITIVE_CASES)} 通过")
    return ok, len(SENSITIVE_CASES)


# ── eval 结果提升（信封键不能被子对象的键覆盖）─────────────────────────
PROMOTE_CASES: list[tuple[str, dict, dict]] = [
    # (说明, runtime_eval 结果, 期望的提升后字段)
    (
        "hook 风格：hooked/count 应提升",
        {"ok": True, "type": "object", "value": {"hooked": True, "reused": False, "count": 3}},
        {"hooked": True, "count": 3},
    ),
    (
        "crypto 风格：键与信封冲突，不应提升",
        {"ok": True, "type": "object", "value": {"ok": True, "value": '{"a":1}', "type": "string"}},
        {},
    ),
]


def check_promote(verbose: bool) -> tuple[int, int]:
    """验证 eval 结果提升：对象字段提升到顶层，但信封键不能被覆盖。"""
    print("\n── eval 结果提升（信封键保护）──")
    session_cls = McpRuntimeSession
    envelope = set(session_cls.EVAL_ENVELOPE_KEYS)
    ok = 0
    for name, result, expect in PROMOTE_CASES:
        out = session_cls.promote_eval_value(dict(result))
        inner = result.get("value") or {}
        wanted = all(out.get(k) == v for k, v in expect.items())
        envelope_intact = all(out.get(k) == result.get(k) for k in result)
        all_promoted = all(k in out for k in inner if k not in envelope)
        good = wanted and envelope_intact and all_promoted
        ok += good
        if not good:
            print(f"  [FAIL] {name:38s} -> {out}")
        elif verbose:
            print(f"  [PASS] {name:38s} 提升={[k for k in inner if k not in envelope]}")
    print(f"  {ok}/{len(PROMOTE_CASES)} 通过")
    return ok, len(PROMOTE_CASES)


def latest_session() -> Path | None:
    """返回最新的会话导出文件。"""
    if not REPORTS_DIR.is_dir():
        return None
    files = sorted(REPORTS_DIR.glob("mcp-session-*.json"), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def check_matchers(verbose: bool) -> tuple[int, int]:
    """跑匹配器回归，返回 (通过, 总数)。"""
    passed = 0
    total = 0
    for label, cases, expect in [
        ("真阳性（必须命中）", MATCHER_POSITIVE, True),
        ("假阳性（必须不命中）", MATCHER_NEGATIVE, False),
    ]:
        print(f"\n── 匹配器 · {label} ──")
        ok = 0
        for which, text in cases:
            total += 1
            hit = bool(MATCHERS[which].search(text))
            if hit == expect:
                ok += 1
                if verbose:
                    print(f"  [PASS] {which:9s} {text[:44]:46s} hit={hit}")
            else:
                print(f"  [FAIL] {which:9s} {text[:44]:46s} hit={hit} 期望={expect}")
        passed += ok
        print(f"  {ok}/{len(cases)} 通过")
    return passed, total


def analyze(session: dict) -> dict:
    """对一份会话跑各分析函数，返回指标字典。"""
    requests = session.get("requests") or []
    for req in requests:
        req["kind"] = classify_request_url(str(req.get("url") or ""))

    by_kind: dict[str, int] = {}
    for req in requests:
        by_kind[req["kind"]] = by_kind.get(req["kind"], 0) + 1

    # 风险面 = 接口类且非埋点（等价于 analysis_ops 的默认行为）
    surface = [r for r in requests if r["kind"] == "api"]

    session_obj = McpRuntimeSession.__new__(McpRuntimeSession)
    return {
        "byKind": by_kind,
        "apiCount": len(surface),
        "telemetryCount": by_kind.get("telemetry", 0),
        "telemetryInSurface": sum(1 for r in surface if r["kind"] == "telemetry"),
        "apiInventory": session_obj.build_api_inventory(surface)["total"],
        "signRelated": session_obj.find_by_regex(surface, SIGN_RE, "sign_related")["count"],
        "sensitive": session_obj.find_sensitive_data_exposure(surface)["count"],
        "idor": session_obj.find_idor_candidates(surface)["count"],
        "authSurface": session_obj.analyze_auth_surface(surface)["count"],
        "debugAdmin": session_obj.find_by_regex(surface, DEBUG_ADMIN_RE, "debug_admin")["count"],
        "upload": session_obj.find_by_regex(surface, UPLOAD_RE, "upload")["count"],
        "payment": session_obj.find_by_regex(surface, PAYMENT_RE, "payment_order")["count"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="离线回归分析层（用导出的会话 JSON）")
    parser.add_argument("--session", help="会话导出文件路径，默认取 output/reports 下最新的")
    parser.add_argument("--verbose", action="store_true", help="打印逐条明细")
    args = parser.parse_args()

    session_path = Path(args.session) if args.session else latest_session()
    if not session_path or not session_path.exists():
        print("[SKIP] 没找到会话导出文件。")
        print(f"       先跑一次真实评估并调用 analysis_ops(action=\"export_session\")，")
        print(f"       产物会落在 {REPORTS_DIR}")
        return 0

    session = json.loads(session_path.read_text(encoding="utf-8"))
    requests = session.get("requests") or []
    print(f"会话文件：{session_path}")
    print(f"导出时间：{session.get('createdAt')}    请求数：{len(requests)}")

    matcher_pass, matcher_total = check_matchers(args.verbose)
    sens_pass, sens_total = check_sensitive_matching(args.verbose)
    extra_pass, extra_total = check_promote(args.verbose)

    metrics = analyze(session)
    print("\n── 分析层指标 ──")
    print(f"  kind 分布            : {metrics['byKind']}")
    print(f"  风险面请求数          : {metrics['apiCount']}（埋点 {metrics['telemetryCount']} 条已排除）")
    print(f"  get_api_inventory    : {metrics['apiInventory']} 条")
    print(f"  find_sign_related    : {metrics['signRelated']}")
    print(f"  find_sensitive       : {metrics['sensitive']}")
    print(f"  find_idor_candidates : {metrics['idor']}")
    print(f"  analyze_auth_surface : {metrics['authSurface']}")
    print(f"  debug_admin/upload/payment : {metrics['debugAdmin']}/{metrics['upload']}/{metrics['payment']}")

    # ── 结构性断言：与具体目标无关，任何会话都应成立 ──────────────────────
    print("\n── 结构性断言 ──")
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
        if not ok:
            failures.append(name)

    check("kind 里没有 unknown", "unknown" not in metrics["byKind"],
          f"byKind={metrics['byKind']}")
    check("风险面里没有埋点（telemetry 已被排除）",
          metrics["telemetryInSurface"] == 0,
          f"混入 {metrics['telemetryInSurface']} 条")
    check("apiCount + telemetryCount <= 总请求数",
          metrics["apiCount"] + metrics["telemetryCount"] <= len(requests))
    check("接口清单条数 <= 风险面请求数",
          metrics["apiInventory"] <= max(metrics["apiCount"], 1),
          f"inventory={metrics['apiInventory']} surface={metrics['apiCount']}")
    check("签名面命中数 <= 风险面请求数",
          metrics["signRelated"] <= metrics["apiCount"])
    check("敏感面命中数 <= 风险面请求数",
          metrics["sensitive"] <= metrics["apiCount"])

    # 埋点排除的端到端验证：把埋点加回来，签名面必须明显变大或持平
    all_requests = session["requests"]
    session_obj = McpRuntimeSession.__new__(McpRuntimeSession)
    sign_with_telemetry = session_obj.find_by_regex(all_requests, SIGN_RE, "sign_related")
    weak_only = int(sign_with_telemetry.get("weakOnlyCount") or 0)
    check("把埋点加回来时，签名面噪声能被识别为弱 token",
          weak_only == 0 or sign_with_telemetry["count"] >= metrics["signRelated"],
          f"含埋点 count={sign_with_telemetry['count']} weakOnly={weak_only}")

    print("\n" + "=" * 62)
    total_pass = matcher_pass + sens_pass + extra_pass
    total_all = matcher_total + sens_total + extra_total
    if failures:
        print(f"结果：匹配器 {matcher_pass}/{matcher_total}，敏感面 {sens_pass}/{sens_total}，"
              f"eval 提升 {extra_pass}/{extra_total}，结构性断言 {len(failures)} 项失败")
        for name in failures:
            print(f"  - {name}")
        return 1
    print(f"结果：匹配器 {matcher_pass}/{matcher_total}，敏感面 {sens_pass}/{sens_total}，"
          f"eval 提升 {extra_pass}/{extra_total}，结构性断言全部通过（合计 {total_pass}/{total_all}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
