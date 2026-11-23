"""发现并格式化反编译输出中的可读源码文件。"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


FormatFunction = Callable[[str], tuple[str | None, str]]
MAX_FORMAT_FILE_BYTES = 32 * 1024 * 1024
CACHE_DIR_NAME = ".e0e1_cache"
QUOTE_CHARS = ('"', "'", "`")


def normalize_indent_tabs(text: str) -> str:
    """规范化输入，消除 jsbeautifier 对缩进的错误推断。

    jsbeautifier 会根据输入内容推断缩进字符：只要文本里出现 tab，它就会改用
    tab 作为缩进字符（实测哪怕只有 1 个 tab 也会触发），此时 indent_char=" "
    完全失效，整个文件会变成 tab 缩进。微信打包产物恰好用 tab 缩进，会踩到这个行为。

    字符串里真正需要保留的 tab 不能动，因此这里用引号状态机区分：
    引号内的原样保留（含反斜杠转义），引号外的 tab 才替换为空格。

    此外，jsbeautifier 还会把「文件第一行的前导空白」当作整体缩进沿用到输出，
    使顶层语句也带上一级缩进。所以最后去掉文件开头的空白 —— 只影响开头一处，
    不触碰任何其他行，因此不会破坏模板字符串里的缩进。
    """
    out: list[str] = []
    quote = ""
    i = 0
    total = len(text)
    while i < total:
        ch = text[i]
        if quote:
            if ch == "\\" and i + 1 < total:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in QUOTE_CHARS:
            quote = ch
            out.append(ch)
            i += 1
            continue
        out.append(" " if ch == "\t" else ch)
        i += 1
    return "".join(out).lstrip(" \t\r\n")


@dataclass
class FormatFileResult:
    """单个文件格式化结果。"""

    path: str
    status: str
    changed: bool = False
    message: str = ""

    def to_dict(self) -> dict:
        """转换为可跨进程传输的普通字典。"""
        return asdict(self)


class CodeFormatter:
    """反编译输出文件格式化器。"""

    def __init__(self, max_file_bytes: int = MAX_FORMAT_FILE_BYTES) -> None:
        """初始化支持的格式化器和单文件大小上限。"""
        self.max_file_bytes = max_file_bytes
        self.formatters: dict[str, FormatFunction] = {}
        self.register_formatters()

    def register_formatters(self) -> None:
        """注册各种文件类型的格式化器。"""
        self.formatters = {
            ".js": self.format_js,
            ".json": self.format_json,
            ".html": self.format_html,
            ".wxml": self.format_html,
            ".wxss": self.format_css,
            ".css": self.format_css,
        }

    def get_formatter(self, file_ext: str) -> FormatFunction | None:
        """根据文件扩展名获取对应的格式化函数。"""
        return self.formatters.get(str(file_ext or "").lower())

    def is_supported_file(self, path: Path) -> bool:
        """判断文件是否属于可格式化类型。"""
        return self.get_formatter(path.suffix) is not None

    def discover_files(self, directory: Path) -> list[Path]:
        """扫描目录下所有可格式化文件。"""
        if not directory.exists() or not directory.is_dir():
            return []
        files: list[Path] = []
        for path in directory.rglob("*"):
            try:
                if CACHE_DIR_NAME in path.parts:
                    continue
                if path.is_file() and self.is_supported_file(path):
                    files.append(path)
            except OSError:
                continue
        files.sort(key=lambda item: str(item).lower())
        return files

    def format_file(self, file_path: Path) -> dict:
        """格式化单个文件并返回统计结果。"""
        path = Path(file_path)
        formatter = self.get_formatter(path.suffix)
        if formatter is None:
            return FormatFileResult(str(path), "skipped", message="不支持的文件类型").to_dict()

        try:
            file_size = path.stat().st_size
            if file_size > self.max_file_bytes:
                return FormatFileResult(str(path), "skipped", message="文件过大，已跳过").to_dict()

            content = path.read_text(encoding="utf-8", errors="ignore")
            formatted_content, message = formatter(content)
            if formatted_content is None:
                return FormatFileResult(str(path), "skipped", message=message).to_dict()
            if formatted_content == content:
                return FormatFileResult(str(path), "skipped", message=message or "内容无需调整").to_dict()

            path.write_text(formatted_content, encoding="utf-8")
            return FormatFileResult(str(path), "success", changed=True, message=message).to_dict()
        except Exception as exc:
            return FormatFileResult(str(path), "error", message=str(exc)).to_dict()

    def format_js(self, content: str) -> tuple[str | None, str]:
        """格式化 JavaScript 代码。"""
        try:
            import jsbeautifier
        except ImportError:
            return None, "缺少 jsbeautifier，已跳过 JS 格式化"

        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.indent_char = " "
            opts.max_preserve_newlines = 2
            opts.preserve_newlines = True
            opts.keep_array_indentation = False
            opts.break_chained_methods = False
            # 注：indent_scripts 不是 jsbeautifier(Python) 的 Options 属性，设置它不生效
            # （实测 normal / keep / separate 三种取值输出完全一致）。真正决定缩进字符的
            # 是输入文本里有没有 tab —— 统一交给 normalize_indent_tabs() 处理。
            opts.brace_style = "collapse"
            opts.space_before_conditional = True
            opts.unescape_strings = True
            opts.jslint_happy = False
            opts.end_with_newline = True
            opts.wrap_line_length = 0
            opts.indent_inner_html = False
            opts.comma_first = False
            opts.e4x = False
            opts.indent_empty_lines = False
            return jsbeautifier.beautify(normalize_indent_tabs(content), opts), ""
        except Exception as exc:
            return None, f"JS 格式化失败：{exc}"

    def format_json(self, content: str) -> tuple[str | None, str]:
        """格式化 JSON 代码。"""
        try:
            parsed = json.loads(content)
            return json.dumps(parsed, indent=4, ensure_ascii=False) + "\n", ""
        except Exception as exc:
            return None, f"JSON 解析失败，已跳过：{exc}"

    def format_html(self, content: str) -> tuple[str | None, str]:
        """格式化 HTML/WXML 代码。"""
        try:
            script_pattern = re.compile(r"(<script[^>]*>)(.*?)(</script>)", re.DOTALL | re.IGNORECASE)

            def replace_script(match: re.Match) -> str:
                """格式化内联 script 内容。"""
                script_tag_open = match.group(1)
                script_content = match.group(2)
                script_tag_close = match.group(3)
                formatted_js, _message = self.format_js(script_content)
                return f"{script_tag_open}\n{formatted_js or script_content}\n{script_tag_close}"

            content = script_pattern.sub(replace_script, content)
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(content, "html.parser")
                return soup.prettify(), ""
            except ImportError:
                return re.sub(r">\s+<", ">\n<", content).strip() + "\n", "缺少 BeautifulSoup，已使用基础格式化"
        except Exception as exc:
            return None, f"HTML/WXML 格式化失败：{exc}"

    def format_css(self, content: str) -> tuple[str | None, str]:
        """格式化 CSS/WXSS 代码。"""
        try:
            formatted = re.sub(r"\s+", " ", content)
            formatted = re.sub(r"\s*{\s*", " {\n    ", formatted)
            formatted = re.sub(r"\s*}\s*", "\n}\n", formatted)
            formatted = re.sub(r";\s*", ";\n    ", formatted)
            formatted = re.sub(r";\n\s*\}", ";\n}", formatted)
            return formatted.strip() + "\n", ""
        except Exception as exc:
            return None, f"CSS/WXSS 格式化失败：{exc}"
