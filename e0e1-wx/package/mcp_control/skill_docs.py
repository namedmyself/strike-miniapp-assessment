"""把项目内的 SKILL.md 通过 MCP 暴露给 AI 客户端。

**为什么需要它**：通过 MCP 连过来的 AI 客户端（Codex / Claude 等）不一定具备
WMP 目录的文件读权限，而 SKILL.md（skill: `miniapp-security-core`）是整套评估
流程的唯一权威来源。本模块提供「取开篇 / 取索引 / 读章节 / 检索」四个能力，
让 AI 不依赖文件系统也能拿到 skill 内容，从而做到「收到请求 → 先读 skill → 再调工具」。

设计约束：
  * SKILL.md 有 20 万字符量级，**绝不能整份返回** —— 所以按章节切分，单次带上限。
  * `guide` 只返回「开工前必须知道」的开篇几块（红线 / 授权 / 流程总览 / 决策树），
    这是让 AI 快速进入正确流程的最小集合。
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from typing import Any

SKILL_FILE_NAME = "SKILL.md"

SKILL_ACTIONS = ("guide", "index", "read", "search")

# guide 动作返回的章节（按标题子串匹配，命中即收）
GUIDE_TITLES = ("红线", "授权声明", "评估流程总览", "快速决策树")

# 单次返回的字符上限，避免把上下文打爆
MAX_SECTION_CHARS = 24000
MAX_SEARCH_HITS = 60
SECTION_PATTERN = re.compile(r"^(#{2,3})\s+(.*?)\s*$")


def skill_path() -> Path:
    """定位 e0e1-wx/SKILL.md（本文件位于 package/mcp_control/ 下）。"""
    return Path(__file__).resolve().parents[2] / SKILL_FILE_NAME


def load_skill_lines() -> list[str]:
    """读取 SKILL.md 的全部行（去 BOM，保留行尾外的内容）。"""
    path = skill_path()
    if not path.is_file():
        raise FileNotFoundError(f"没有找到 SKILL.md：{path}")
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    return raw.split("\n")


def split_sections(lines: list[str]) -> list[dict]:
    """按 `##` / `###` 标题切分。

    关键规则：一个章节的正文一直延伸到**下一个同级或更高级标题之前**，
    也就是 `## Phase 1` 要把它下面的所有 `### 1.x` 子章节一并包含进来 ——
    否则 `read(section='Phase 1')` 只会拿到标题那一行（实测踩过：只有 21 字符）。
    """
    marks: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        matched = SECTION_PATTERN.match(line)
        if matched:
            marks.append((index, len(matched.group(1)), matched.group(2).strip()))
    if not marks:
        return []

    sections: list[dict] = []
    for position, (index, level, title) in enumerate(marks):
        end = len(lines) - 1
        for next_index, next_level, _next_title in marks[position + 1 :]:
            if next_level <= level:
                end = next_index - 1
                break
        body = "\n".join(lines[index : end + 1])
        sections.append(
            {
                "level": level,
                "title": title,
                "start_line": index + 1,
                "end_line": end + 1,
                "lines": end - index + 1,
                "chars": len(body),
            }
        )
    return sections


def _section_text(section: dict, lines: list[str]) -> str:
    body = "\n".join(lines[section["start_line"] - 1 : section["end_line"]])
    if len(body) > MAX_SECTION_CHARS:
        body = body[:MAX_SECTION_CHARS] + "\n...（本节过长已截断，可用 read 动作按章节继续取）"
    return body


def get_guide() -> dict:
    """返回开工前必读的开篇章节（红线 / 授权 / 流程总览 / 决策树）。"""
    path = skill_path()
    lines = load_skill_lines()
    sections = split_sections(lines)
    picked = [
        section
        for section in sections
        if any(key in section["title"] for key in GUIDE_TITLES)
    ]
    body_parts = []
    for section in picked:
        body_parts.append(f"<!-- 第 {section['start_line']}-{section['end_line']} 行 -->")
        body_parts.append(_section_text(section, lines))
    return {
        "ok": True,
        "skill": "miniapp-security-core",
        "skill_path": str(path),
        "total_lines": len(lines),
        "sections_returned": [section["title"] for section in picked],
        "next": (
            "这是评估流程的开篇。完整流程含 Phase -1（反编译）→ Phase 0 环境 → "
            "Phase 1 侦察 → Phase 2 渗透线索 → Phase 3 解密 → Phase 4 逆向 → Phase 5 State → Phase 6 报告。"
            "用 skill_ops(action='index') 看完整章节目录，"
            "skill_ops(action='read', section='Phase 1') 取具体章节。"
        ),
        "content": "\n\n".join(body_parts),
    }


def get_index() -> dict:
    """返回 SKILL.md 的章节索引（标题 + 行号范围 + 体量）。"""
    path = skill_path()
    lines = load_skill_lines()
    sections = split_sections(lines)
    return {
        "ok": True,
        "skill": "miniapp-security-core",
        "skill_path": str(path),
        "total_lines": len(lines),
        "section_count": len(sections),
        "sections": [
            {
                "title": section["title"],
                "level": section["level"],
                "start_line": section["start_line"],
                "end_line": section["end_line"],
                "chars": section["chars"],
            }
            for section in sections
        ],
        "hint": "用 skill_ops(action='read', section='<标题片段>') 取章节全文。",
    }


def read_section(section: str) -> dict:
    """按标题片段（或行号）取某一章节全文。"""
    key = str(section or "").strip()
    if not key:
        return {
            "ok": False,
            "error": "read 需要 section 参数。",
            "hint": "例如 section='Phase 1' / '2.2' / '经验法则' / '红线'。",
        }

    path = skill_path()
    lines = load_skill_lines()
    sections = split_sections(lines)

    if key.isdigit():
        target_line = int(key)
        candidates = [
            section_item
            for section_item in sections
            if section_item["start_line"] <= target_line <= section_item["end_line"]
        ]
        # 取最靠后的候选 = 包含该行的**最具体**章节（子章节总在父章节之后）
        matched = candidates[-1] if candidates else None
    else:
        lowered = key.casefold()
        # 匹配优先级：精确 > 标题开头 > 包含。
        # 实测踩过：只按「包含」匹配时，key='2.2' 会先命中 'v2.24'（因为 2.2 是它的子串）。
        exact = [item for item in sections if item["title"].casefold() == lowered]
        startswith = [item for item in sections if item["title"].casefold().startswith(lowered)]
        contains = [item for item in sections if lowered in item["title"].casefold()]
        matched = (exact or startswith or contains or [None])[0]

    if matched is None:
        titles = [item["title"] for item in sections][:40]
        return {
            "ok": False,
            "error": f"没有找到章节：{key}",
            "available_titles": titles,
            "hint": "标题支持片段匹配，例如 'Phase 1' / '2.2' / '经验法则'。",
        }

    body = _section_text(matched, lines)
    return {
        "ok": True,
        "skill": "miniapp-security-core",
        "title": matched["title"],
        "start_line": matched["start_line"],
        "end_line": matched["end_line"],
        "chars": matched["chars"],
        "truncated": matched["chars"] > MAX_SECTION_CHARS,
        "content": body,
    }


def search_skill(pattern: str, *, is_regex: bool = False, context_lines: int = 1) -> dict:
    """在 SKILL.md 里检索关键词或正则，返回行号与上下文。"""
    key = str(pattern or "").strip()
    if not key:
        return {"ok": False, "error": "search 需要 pattern 参数。"}

    path = skill_path()
    lines = load_skill_lines()
    ctx = max(int(context_lines or 0), 0)

    if is_regex:
        try:
            matcher = re.compile(key, re.IGNORECASE)
        except re.error as exc:
            return {"ok": False, "error": f"正则无效：{exc}", "pattern": pattern}
        check = lambda text: matcher.search(text) is not None  # noqa: E731
    else:
        lowered = key.casefold()
        check = lambda text: lowered in text.casefold()  # noqa: E731

    hits: list[dict] = []
    truncated = False
    for index, line in enumerate(lines):
        if not check(line):
            continue
        start = max(index - ctx, 0)
        stop = min(index + ctx + 1, len(lines))
        hits.append(
            {
                "line": index + 1,
                "match": line.strip()[:300],
                "context": "\n".join(
                    f"{start + offset + 1}: {text}"
                    for offset, text in enumerate(lines[start:stop])
                ),
            }
        )
        if len(hits) >= MAX_SEARCH_HITS:
            truncated = True
            break

    return {
        "ok": True,
        "skill": "miniapp-security-core",
        "pattern": pattern,
        "is_regex": bool(is_regex),
        "hit_count": len(hits),
        "truncated": truncated,
        "hits": hits,
        "hint": "定位到章节后用 skill_ops(action='read', section='<章节标题>') 取全文。",
    }


def run(action: str, *, section: str = "", pattern: str = "", is_regex: bool = False) -> dict:
    """按 action 分发。"""
    if action == "guide":
        result = get_guide()
        SKILL_GATE.mark_loaded()
        return result
    if action == "index":
        SKILL_GATE.mark_loaded()
        return get_index()
    if action == "read":
        result = read_section(section)
        if result.get("ok"):
            SKILL_GATE.mark_loaded()
        return result
    if action == "search":
        result = search_skill(pattern, is_regex=is_regex)
        if result.get("ok"):
            SKILL_GATE.mark_loaded()
        return result
    return {
        "ok": False,
        "error": f"未知 action: {action}",
        "valid_actions": list(SKILL_ACTIONS),
    }


class SkillGate:
    """首调门禁：AI 没读 skill 就调业务工具时，拦下**首次**调用并把 skill 开篇一并塞回去。

    **为什么需要它**：MCP 的 `instructions` 只是「建议」，AI 不一定会遵守；
    `skill_ops` 提供了入口，但 AI 也可能不主动调。而「工具的返回内容」是模型必然消费的 ——
    所以用一次拦截把 skill 推给 AI，**完全不依赖客户端做任何 skill 配置**，
    也无需用户预先安装 skill。

    设计取舍：
      * **只拦一次**。若 AI 拿到拦截响应后仍不配合，第二次放行 ——
        否则会把工具彻底卡死，那比不读 skill 更糟。
      * `EXEMPT_TOOLS` 里的工具不受管：读 skill 的入口本身，以及无副作用的 `status`。
      * 状态是**进程级**的：WMP 的 MCP 固定监听 127.0.0.1 且带固定 token，
        实质是单人本机使用，进程级标志足够；多客户端并发不是这个部署形态的诉求。
    """

    EXEMPT_TOOLS = frozenset({"skill_ops", "status"})

    def __init__(self) -> None:
        self._loaded = False
        self._pushed = False
        self._lock = threading.Lock()

    @property
    def loaded(self) -> bool:
        """skill 是否已被读取。"""
        return self._loaded

    def mark_loaded(self) -> None:
        """标记 skill 已读。"""
        with self._lock:
            self._loaded = True

    def check(self, tool_name: str) -> dict | None:
        """返回 None = 放行；返回 dict = 拦截响应（已含 skill 开篇内容）。"""
        name = str(tool_name or "")
        if name in self.EXEMPT_TOOLS:
            return None
        with self._lock:
            if self._loaded or self._pushed:
                return None
            self._pushed = True

        guide = get_guide()
        return {
            "ok": False,
            "type": "skill_required",
            "tool": name,
            "error": (
                f"调用 `{name}` 之前必须先读取本项目的评估流程"
                "（skill: miniapp-security-core）。开篇内容已附在下方，请按它确定当前该走哪个 Phase，"
                "再继续编排工具。"
            ),
            "skill": "miniapp-security-core",
            "guide": guide.get("content", ""),
            "sections_included": guide.get("sections_returned", []),
            "next": [
                "读上面的流程，确认当前处于哪个 Phase；",
                "要完整章节目录：skill_ops(action='index')（共 "
                f"{guide.get('total_lines')} 行）；",
                "取具体章节：skill_ops(action='read', section='Phase 1')；",
                f"完成后重新调用 `{name}` —— 本次拦截只发生一次。",
            ],
        }

    def reset(self) -> None:
        """重置门禁状态（自检/测试用）。"""
        with self._lock:
            self._loaded = False
            self._pushed = False


# 全局门禁实例：所有 MCP 工具调用共用
SKILL_GATE = SkillGate()
