"""验证 scan_sensitive_storage 的分类逻辑（P0-1 回归护栏）。

用**本次评估（2026-09-22 某高校招生小程序）的真实 storage 数据**做断言，
不编造样本 —— 因为这些样本恰恰是旧实现全部漏报的那批。

旧实现的失败现象：
    "findings": [], "count": 0
而 14 年有效期的 HS256 JWT、疑似硬编码密钥 `jjmData`、明文 openId
就躺在它自己返回的 `raw` 字段里。

用法：
    "D:/Python 12.4/python.exe" scripts/verify_storage_classifier.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "e0e1-wx"))

from package.mcp_control.runtime_session import (  # noqa: E402
    McpRuntimeSession,
    decode_jwt_claims,
    looks_like_hardcoded_secret,
    shannon_entropy,
    try_base64_decode,
)

# —— 真实样本（取自本次评估的 wxStorage 扫描结果）——

# 真实 JWT：HS256，exp=2225533478 → 2040-07-10，payload.username 就是 openId
REAL_JWT = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJleHAiOjIyMjU1MzM0NzgsInVzZXJuYW1lIjoib21FRzQ1SGJOQURISlk1ajBOVHdUZlNiNWNlayJ9."
    "LP5u0d63JYqDQE4WwuvsEXW_7uXfRVVN476Ub0OEsHg"
)
REAL_OPENID = "omEG45HbNADHJY5j0NTwTfSb5cek"

REAL_STORAGE = {
    # —— 应当命中 ——
    "wxUserInfo": {"openId": REAL_OPENID, "as": REAL_JWT},
    "jjmData": "Adf123098SSddfdg",
    "openId": REAL_OPENID,
    # —— 不应命中（噪音样本，旧实现和新实现都不能报）——
    "dqnf": "2026",
    "__DC_STAT_UUID": "1790077453712602847",
    "mrsf": "四川",
    "role": "s",
    "state": 0,
    "loading": True,
    "index_nav1": "wxfile://store/1a0c8ee50cd_1c2.png",
    "logo": "wxfile://store/1a0c8ee47e5_ca2.png",
    "sysCfg": {
        "id": "1ebb927375304fd1bb67163d5eaa356e",  # 32 位 hex，应被摘要长度排除
        "xxmc": "uestc",
        "kpnf": "2022",
        "kpjs": "01,02",
    },
    "sfList": [{"sf": "北京"}, {"sf": "天津"}],
    "tabBarList": [{"iconPath": "/static/tab1.png", "text": "首页"}],
}

EXPECTED_HITS = {
    ("wxUserInfo", "jwt_token"),
    ("wxUserInfo", "pii_in_storage"),  # 嵌套路径 wxUserInfo.openId
    ("jjmData", "possible_hardcoded_secret"),
    ("openId", "pii_in_storage"),
}
# 这些 key 不应产生任何 finding
EXPECTED_CLEAN = {
    "dqnf",
    "__DC_STAT_UUID",
    "mrsf",
    "role",
    "state",
    "loading",
    "index_nav1",
    "logo",
    "sysCfg",
    "sfList",
    "tabBarList",
}

_passed = 0
_failed = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {label}")
    else:
        _failed += 1
        print(f"  [FAIL] {label}" + (f"  <- {detail}" if detail else ""))


async def main() -> int:
    print("=== 1. 单元级：辅助函数 ===")
    claims = decode_jwt_claims(REAL_JWT)
    print(f"  decode_jwt_claims -> {json.dumps(claims, ensure_ascii=False)}")
    check("JWT 可解析", claims is not None)
    if claims:
        check("alg=HS256", claims.get("alg") == "HS256", str(claims.get("alg")))
        check("exp 解码为 2040-07-10", str(claims.get("exp", "")).startswith("2040-07-10"), str(claims.get("exp")))
        check("expiresInDays > 5000（超长有效期）", (claims.get("expiresInDays") or 0) > 5000, str(claims.get("expiresInDays")))
        check("payload.username 被提取", claims.get("username") == REAL_OPENID, str(claims.get("username")))
        check("hasSignature=True", claims.get("hasSignature") is True)

    check("jjmData 判定为疑似密钥", looks_like_hardcoded_secret("Adf123098SSddfdg"))
    check("熵计算可用", 3.0 < shannon_entropy("Adf123098SSddfdg") < 4.5, f"{shannon_entropy('Adf123098SSddfdg'):.3f}")

    print("\n  —— 噪音必须被排除 ——")
    for noise in (
        "wxfile://store/1a0c8ee50cd_1c2.png",
        "/static/tab1.png",
        "1790077453712602847",
        "2026",
        "四川",
        "uestc",
        "1ebb927375304fd1bb67163d5eaa356e",
        "01,02",
        # 关键样本：字典键名，熵 3.5 —— 比真密钥的 3.25 还高。
        # 仅靠熵阈值无法区分，必须由 snake_case 形状规则排除。
        "search_show_type",
        "oa_notify_read",
        "2023-01-09 00:00:00",
        "HelloWorldFoo",
    ):
        check(f"不判定为密钥: {noise!r}", not looks_like_hardcoded_secret(noise))

    print("\n  —— base64 递归 ——")
    import base64 as _b64

    encoded = _b64.b64encode(b'{"password":"S3cr3tP@ssw0rd!"}').decode()
    decoded = try_base64_decode(encoded)
    check("base64 可解码", decoded is not None and "password" in (decoded or ""), repr(decoded))
    check("非 base64 文本返回 None", try_base64_decode("hello world this is plain") is None)
    check("wxfile 路径不当作 base64", try_base64_decode("wxfile://store/1a0c8ee50cd_1c2.png") is None)

    print("\n=== 2. 集成级：真实 storage 数据分类 ===")
    session = McpRuntimeSession()
    findings = session.classify_sensitive_storage_source("wxStorage", REAL_STORAGE)
    print(f"  产出 {len(findings)} 条 finding：")
    for item in findings:
        extra = ""
        if item.get("jwtClaims"):
            extra = f"  claims={json.dumps(item['jwtClaims'], ensure_ascii=False)}"
        elif item.get("path"):
            extra = f"  path={item['path']}"
        print(f"    - [{item['category']}] key={item['key']!r} reason={item['reason']}{extra}")

    actual = {(item["key"], item["category"]) for item in findings}
    print()
    for expected in sorted(EXPECTED_HITS):
        check(f"命中 {expected}", expected in actual, f"实际命中集={sorted(actual)}")

    dirty = {item["key"] for item in findings} & EXPECTED_CLEAN
    check("噪音 key 无 finding", not dirty, f"误报={sorted(dirty)}")

    # openId 是用户标识，不是密钥。熵规则必须被 PII 路径抑制掉，
    # 否则每次扫描都会多一条噪音，把真密钥淹没。
    secret_keys = {item["key"] for item in findings if item["category"] == "possible_hardcoded_secret"}
    check("openId 未被误报为疑似密钥", "openId" not in secret_keys, f"误报={sorted(secret_keys)}")
    check("wxUserInfo 未被误报为疑似密钥（其 openId 叶子应被抑制）", "wxUserInfo" not in secret_keys, f"误报={sorted(secret_keys)}")
    check("jjmData 是唯一的疑似密钥命中", secret_keys == {"jjmData"}, f"实际={sorted(secret_keys)}")

    print("\n=== 3. 脱敏检查：findings 里不得出现完整密钥 ===")
    blob = json.dumps(findings, ensure_ascii=False)
    check("完整 JWT 未出现在 findings", REAL_JWT not in blob)
    check("完整 openId 未出现在 findings", REAL_OPENID not in blob)
    check("jjmData 明文未出现在 findings", "Adf123098SSddfdg" not in blob)

    print("\n=== 4. 回归：旧的字面量规则仍然生效 ===")
    legacy = session.classify_sensitive_storage_source(
        "wxStorage",
        {"cfg": {"accessKeyId": "AKIDxxx", "mchId": "1900000109", "password": "p@ss"}},
    )
    legacy_cats = {item["category"] for item in legacy}
    print(f"  {sorted(legacy_cats)}")
    check("oss_cos_s3_credentials 仍命中", "oss_cos_s3_credentials" in legacy_cats)
    check("payment_credentials 仍命中", "payment_credentials" in legacy_cats)
    check("hardcoded_password 仍命中", "hardcoded_password" in legacy_cats)

    print("\n=== 5. scan_sensitive_storage 的返回体护栏（P2-4 本工具部分）===")

    class StubSession(McpRuntimeSession):
        """把 runtime_eval 换成固定返回，避免依赖真机。"""

        def __init__(self, payload: dict) -> None:
            super().__init__()
            self._payload = payload
            self.selected_appservice_context_id = 4

        async def runtime_eval(self, *args: object, **kwargs: object) -> dict:
            return {"ok": True, "value": self._payload}

    stub_payload = {
        "wxStorage": REAL_STORAGE,
        "localStorage": {},
        "sessionStorage": {},
        "errors": [],
    }

    # 默认：不回传 raw
    session = StubSession(stub_payload)
    res = await session.scan_sensitive_storage()
    size = len(json.dumps(res, ensure_ascii=False))
    print(f"  默认返回体 {size} 字符；count={res['count']}；byCategory={res['byCategory']}")
    check("默认不含 raw 字段", "raw" not in res)
    check("rawOmitted=True 且带 rawHint", res.get("rawOmitted") is True and bool(res.get("rawHint")))
    check("count=4", res.get("count") == 4, str(res.get("count")))
    check("byCategory 已聚合", res.get("byCategory", {}).get("jwt_token") == 1, str(res.get("byCategory")))
    check("返回体 < 8000 字符（旧实现是 783,047）", size < 8000, str(size))

    # 显式要 raw：应被截断
    session2 = StubSession(stub_payload)
    res2 = await session2.scan_sensitive_storage(include_raw=True, max_raw_chars=200)
    check("includeRaw=true 时才回传 raw", "raw" in res2)
    check("超限时 rawTruncated=True", res2.get("rawTruncated") is True)
    check("截断后长度受控", len(res2["raw"]) <= 200, str(len(res2.get("raw", ""))))

    print(f"\n=== 结果：{_passed} passed, {_failed} failed ===")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
