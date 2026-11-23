#!/usr/bin/env python3
"""离线验证：`decompile_ops(action="scan_source")` 的接线与扫描语义（R-1）。

只读、不连 CDP，用临时夹具跑，不碰真实产物。

为什么必须有这个脚本 —— 本项目最贵的一课（v2.27 的 N-3/N-5）是：
**实现层对了，包装层没接上**（`local_app.py` 的签名/分发），离线单测结构上就看不到那一层；
**以及空数据会掩盖 bug**。所以这里同时断言两件事：

1. **签名层真的暴露了** `scan_source` 与新增参数（FastMCP 用函数签名生成 inputSchema，
   实现层支持但签名没声明 → 调用直接被拒收，这是本项目最高频的 bug 源）；
2. **计数不被样本上限掩盖** —— 这是本功能最容易埋雷的地方：
   为了控制返回体量只回有限样本，但如果顺手把「计数」也算成了样本数，
   Agent 就会拿到**偏小的命中数**，从而误判「没什么东西」，与 P0-1 的假阴性同性质。
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "e0e1-wx"))

from package.decompiler import headless  # noqa: E402
from package.decompiler.headless import DECOMPILE_ACTIONS, scan_output  # noqa: E402
from package.mcp_control.local_app import create_mcp_app  # noqa: E402
from package.regex_rules.presets import DEFAULT_REGEX_RULES  # noqa: E402

PASSED = 0
FAILED = 0

PHONES = [f"1380{i:07d}" for i in range(1000000, 1000030)]  # 30 个互不相同的手机号
PHONE_IN_A = "00000000000"


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  [PASS] {label}")
    else:
        FAILED += 1
        print(f"  [FAIL] {label}")
    if detail:
        print(f"         {detail}")


def build_fixture(root: Path) -> None:
    """造一棵最小产物树：2 个该扫的文本 + 1 个二进制 + 1 个图片。"""
    (root / "a.js").write_text(
        "\n".join(
            [
                f"var phone = '{PHONE_IN_A}';",
                "var mail = 'ops@example.com';",
                "var ak = 'LTAI5tQx9rFk2mNpQwErTyUi';",
                "var api = 'https://chaxun.example.edu.cn/api/front/mini/getXxjj';",
                "var page = '/pages/student/index/lqcx/lqcx';",
                "-----BEGIN RSA PRIVATE KEY-----",
                "MIIEowIBAAKCAQEA1234567890abcdefghijklmnop",
                "-----END RSA PRIVATE KEY-----",
            ]
        ),
        encoding="utf-8",
    )
    (root / "b.json").write_text(
        "\n".join(f'"p{i}": "{value}",' for i, value in enumerate(PHONES)),
        encoding="utf-8",
    )
    # 含 NUL → 应被 looks_binary 判为二进制并整份跳过
    (root / "bin.js").write_bytes(b"var x = 00000000005;\x00\x00\x01\x02\x03binary")
    # 非扫描扩展名 → 应在 discover_files 阶段就被排除
    (root / "pic.png").write_text("00000000006", encoding="utf-8")


async def test_schema() -> None:
    """签名层：action 与新增参数必须真的在 inputSchema 里。"""
    print("\n[1] 签名层（FastMCP inputSchema）")
    mcp = create_mcp_app()
    tools = await mcp.list_tools()
    by_name = {tool.name: tool for tool in tools}
    tool = by_name.get("decompile_ops")
    if tool is None:
        check("找到 decompile_ops", False)
        return

    schema = tool.inputSchema or {}
    props = schema.get("properties") or {}
    enum = (props.get("action") or {}).get("enum") or []
    check("decompile_ops 暴露 scan_source", "scan_source" in enum, f"enum={enum}")
    check("DECOMPILE_ACTIONS 含 scan_source", "scan_source" in DECOMPILE_ACTIONS)
    for key in ("rules", "max_samples_per_rule", "output_dir", "appid"):
        check(f"inputSchema 含 {key}", key in props)
    for key in ("list_opened_applets", "decompile", "list_files", "read_source", "search_source"):
        check(f"回归：既有 action 未丢失 {key}", key in enum)


def test_default_rules(root: Path) -> dict:
    print("\n[2] 默认规则集与基本计数")
    result = scan_output(str(root))
    check("返回 ok", bool(result.get("ok")), f"error={result.get('error')}")
    check(
        "默认规则数 = 预设条数",
        result.get("rule_count") == len(DEFAULT_REGEX_RULES),
        f"rule_count={result.get('rule_count')} 预设={len(DEFAULT_REGEX_RULES)}",
    )
    check(
        "二进制文件被跳过（scanned_files=2，只算真正参与匹配的文本）",
        result.get("scanned_files") == 2,
        f"scanned_files={result.get('scanned_files')}",
    )
    check(
        "二进制跳过数被单独上报（skipped_binary_files=1）",
        result.get("skipped_binary_files") == 1,
        f"skipped_binary_files={result.get('skipped_binary_files')}",
    )

    by_rule = {item["name"]: item for item in result.get("rules", [])}
    check("命中「手机号」规则", "手机号" in by_rule)
    phone = by_rule.get("手机号", {})
    check(
        "手机号计数 = 31（1 in a.js + 30 in b.json）",
        phone.get("match_count") == 31,
        f"match_count={phone.get('match_count')}",
    )
    check("命中「邮箱」规则", "邮箱" in by_rule)
    check("命中「云厂商 AK」规则", "云厂商 AK" in by_rule)
    check("命中「私钥块」规则", "私钥块" in by_rule)
    check("命中「URL 接口」或「路径接口」", bool({"URL 接口", "路径接口"} & set(by_rule)))

    # R-8 回归护栏：`RegexContentScanner` 是**逐行**匹配的，
    # 任何含跨行构造（[\s\S] / (?s) / \n）的预设规则在这条链路上**永远命不中**。
    # 「私钥块」曾经就是这种死规则（实测整篇 True / 逐行 False / 扫描器命中 0），已改成锚头部行。
    cross = [
        rule["name"]
        for rule in DEFAULT_REGEX_RULES
        if "[\\s\\S]" in rule["pattern"] or "(?s)" in rule["pattern"] or "\\n" in rule["pattern"]
    ]
    check(
        "预设中不存在跨行死规则",
        not cross,
        f"含跨行构造的规则={cross}（逐行扫描下必然 0 命中）",
    )
    return by_rule


def test_sample_cap(root: Path) -> None:
    """核心断言：样本有上限，但**计数不受样本上限影响**。"""
    print("\n[3] 样本上限 vs 计数完整性（防假阴性）")
    result = scan_output(str(root), max_samples_per_rule=5)
    by_rule = {item["name"]: item for item in result.get("rules", [])}
    phone = by_rule.get("手机号", {})
    check(
        "样本被截到 cap=5",
        len(phone.get("samples") or []) == 5,
        f"len(samples)={len(phone.get('samples') or [])}",
    )
    check("samples_truncated=True", phone.get("samples_truncated") is True)
    check(
        "★ 计数仍为 31（未被样本上限掩盖）",
        phone.get("match_count") == 31,
        f"match_count={phone.get('match_count')}",
    )

    print("\n[4] 假阴性护栏：跑过但没命中的规则必须显式列出")
    empty = result.get("rules_without_match") or []
    check("rules_without_match 非空", bool(empty), f"共 {len(empty)} 条")
    check("含确定不存在的规则（Stripe Key）", "Stripe Key" in empty)
    matched_names = {item["name"] for item in result.get("rules", [])}
    check(
        "命中 + 未命中 = 全部规则（无静默丢弃）",
        len(matched_names) + len(empty) == len(DEFAULT_REGEX_RULES),
        f"命中 {len(matched_names)} + 未命中 {len(empty)} = {len(matched_names) + len(empty)}",
    )


def test_top_files(root: Path) -> None:
    print("\n[5] top_files 与样本路径")
    result = scan_output(str(root))
    top = result.get("top_files") or []
    check("top_files 非空", bool(top), f"{top}")
    if top:
        counts = [item["match_count"] for item in top]
        check("top_files 按命中数降序", counts == sorted(counts, reverse=True), f"{counts}")
        check(
            "path 是相对路径（不含绝对前缀）",
            all(not str(item["path"]).replace("\\", "/").startswith("/") for item in top),
            f"示例={top[0]['path']}",
        )
    by_rule = {item["name"]: item for item in result.get("rules", [])}
    sample = (by_rule.get("手机号", {}).get("samples") or [{}])[0]
    check("样本带 path/line/match", all(key in sample for key in ("path", "line", "match")))
    check("样本行号 > 0", int(sample.get("line") or 0) > 0, f"line={sample.get('line')}")


def test_overrides(root: Path) -> None:
    print("\n[6] 自定义 rules 与回落语义")
    custom = scan_output(str(root), rules=[{"name": "只匹配手机号", "pattern": r"1[3-9]\d{9}"}])
    names = [item["name"] for item in custom.get("rules", [])]
    check("自定义规则生效且只跑这一条", names == ["只匹配手机号"], f"{names}")
    check("自定义规则 rule_count=1", custom.get("rule_count") == 1)

    fallback = scan_output(str(root), rules=[])
    check(
        "rules=[] 回落默认预设（不是「没有规则」）",
        fallback.get("rule_count") == len(DEFAULT_REGEX_RULES),
        f"rule_count={fallback.get('rule_count')}",
    )

    bad = scan_output(str(root), rules=[{"name": "坏正则", "pattern": "([unclosed"}])
    check("全部正则无效时 ok=False 且带 error", bad.get("ok") is False and bool(bad.get("error")))


def test_guards(root: Path) -> None:
    print("\n[7] 目录护栏与大文件护栏")
    missing = scan_output(str(root / "not-exist"))
    check("目录不存在 → ok=False", missing.get("ok") is False and bool(missing.get("error")))

    original = headless.SEARCH_MAX_FILE_BYTES
    try:
        headless.SEARCH_MAX_FILE_BYTES = 64
        small = scan_output(str(root))
        check(
            "超大文件被跳过并计数",
            (small.get("skipped_large_files") or 0) >= 1,
            f"skipped_large_files={small.get('skipped_large_files')}",
        )
    finally:
        headless.SEARCH_MAX_FILE_BYTES = original


async def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="verify_scan_source_"))
    try:
        build_fixture(temp_root)
        await test_schema()
        test_default_rules(temp_root)
        test_sample_cap(temp_root)
        test_top_files(temp_root)
        test_overrides(temp_root)
        test_guards(temp_root)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    print()
    print("=" * 78)
    print(f"结果：{PASSED} passed / {FAILED} failed")
    print("=" * 78)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
