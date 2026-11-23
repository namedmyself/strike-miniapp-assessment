#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""提交前脱敏自检：扫描即将 git add 的文件，发现疑似凭据/PII/本机路径就报警。

用法：
  python tools/sanitize_check.py           # 扫描当前目录（排除 .git / output / .venv）
  python tools/sanitize_check.py <dir>     # 扫描指定目录
退出码 1 = 发现问题，0 = 干净。
"""
import sys, os, re
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
SKIP_DIRS = {".git", ".venv", "output", "logs", "__pycache__", ".runtime", "node_modules"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".pyc", ".woff", ".woff2", ".ttf"}

# 运行时拼接，避免检测模式字面量出现在脚本自身而误报
_BS = chr(92)
_WIN_USERS = "C:" + _BS + "Users" + _BS
_POSIX_USERS = "/" + "Users" + "/"
PATTERNS = [
    ("本机绝对路径", re.compile(re.escape(_WIN_USERS) + r'|' + re.escape(_POSIX_USERS) + r'[A-Za-z0-9_.-]+/')),
    ("疑似手机号",   re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)')),
    ("疑似身份证",   re.compile(r'(?<!\d)\d{17}[\dXx](?!\d)')),
    ("token赋值",    re.compile(r'(?i)(x-access-token|x-token|authorization\s*:\s*bearer)\s*[:=]\s*["\']?[A-Za-z0-9._+/=-]{20,}')),
    ("MCP token",    re.compile(re.escape("eeeeeeeecode") + r'-[0-9a-z-]+')),
    ("疑似密钥",     re.compile(r'(?i)(appsecret|aeskey|secret_key|password)\s*[:=]\s*["\'][^"\']{8,}["\']')),
    ("真实目标域名", re.compile(r'(?i)(' + r'|'.join(re.escape(d) for d in
        ["tengmed" + "." + "cn", "jjzntc" + "." + "com", "everjiankang" + "." + "cn",
         "bychy" + "." + "com", "houde-food" + "." + "com"]) + r')')),
]

def iter_files():
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            p = Path(dp) / f
            if p.suffix.lower() in SKIP_EXT: continue
            if p.name.startswith(".") and p.name not in {".gitignore", ".env.example"}: continue
            yield p

def main():
    findings = []
    for p in iter_files():
        try: text = p.read_text(encoding="utf-8", errors="replace")
        except Exception: continue
        for lineno, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            # 明显占位符/测试样例豁免
            if any(tag in line or tag in low for tag in
                   ["<本机用户名>", "testuser", "000000000000000000", "0000000000",
                    "占位", "placeholder", "example", "replace_me", "change_me"]):
                continue
            for label, pat in PATTERNS:
                m = pat.search(line)
                if m:
                    snippet = line.strip()[:100]
                    findings.append((str(p.relative_to(ROOT)), lineno, label, snippet))
    if not findings:
        print("[PASS] 未发现疑似敏感信息，可以提交。")
        return 0
    print(f"[WARN] 发现 {len(findings)} 处疑似敏感信息：\n")
    for f, ln, label, snip in findings[:60]:
        print(f"  {f}:{ln}  [{label}]  {snip}")
    if len(findings) > 60:
        print(f"  ... 还有 {len(findings)-60} 处")
    print("\n提交前请确认：这些是否为占位/示例；真实值必须删除或替换。")
    return 1

if __name__ == "__main__":
    sys.exit(main())
