"""创建 package 内置的 Streamable HTTP MCP 应用，并注册分组工具。

设计要点：
  * 所有 `*_ops` 的 `action` 都带 **enum**（inputSchema 里可自省），
    合法值不再只写在中文散文描述里。
  * 描述里同时给出 action 清单与典型用法，便于 Agent 一次调对。
"""

from __future__ import annotations

import asyncio
import functools
from pathlib import Path
from typing import Any, Callable, Literal

from mcp.server.fastmcp import FastMCP

from package.decompiler.headless import (
    DECOMPILE_ACTIONS,
    MANIFEST_NAME,
    DEFAULT_READ_MAX_LINES,
    DEFAULT_SCAN_SAMPLES_PER_RULE,
    DEFAULT_SEARCH_MAX_RESULTS,
    decompile_applet,
    default_output_root,
    list_opened_applets,
    list_output_files,
    read_source,
    scan_output,
    search_in_output,
)
from package.mcp_control import skill_docs
from package.mcp_control.crypto_helpers import json_text
from package.mcp_control.runtime_session import (
    ANALYSIS_ACTIONS,
    CONNECTION_ACTIONS,
    DEBUGGER_ACTIONS,
    DECRYPT_ACTIONS,
    NETWORK_ACTIONS,
    PENTEST_ACTIONS,
    REPLAY_ACTIONS,
    REVERSE_ACTIONS,
    ROUTE_ACTIONS,
    RUNTIME_ACTIONS,
    McpRuntimeSession,
)

# action 的 enum 直接由 runtime_session 的常量生成，避免 schema 与实现漂移。
ConnectionAction = Literal.__getitem__(CONNECTION_ACTIONS)
NetworkAction = Literal.__getitem__(NETWORK_ACTIONS)
RuntimeAction = Literal.__getitem__(RUNTIME_ACTIONS)
DebuggerAction = Literal.__getitem__(DEBUGGER_ACTIONS)
AnalysisAction = Literal.__getitem__(ANALYSIS_ACTIONS)
DecryptAction = Literal.__getitem__(DECRYPT_ACTIONS)
ReverseAction = Literal.__getitem__(REVERSE_ACTIONS)
ReplayAction = Literal.__getitem__(REPLAY_ACTIONS)
PentestAction = Literal.__getitem__(PENTEST_ACTIONS)
RouteAction = Literal.__getitem__(ROUTE_ACTIONS)
DecompileAction = Literal.__getitem__(DECOMPILE_ACTIONS)
SkillAction = Literal.__getitem__(skill_docs.SKILL_ACTIONS)


def _actions_text(actions: tuple[str, ...]) -> str:
    """把 action 元组渲染成描述里的可读清单。"""
    return "/".join(actions)


def safe_tool(func: Callable[..., Any], tool_name: str = "") -> Callable[..., Any]:
    """统一包装工具：异常兜底 + 未读 skill 时的首次拦截。

    **skill 门禁**：AI 没读评估流程就直接调业务工具时，拦下**首次**调用，
    并把 SKILL.md 的开篇（红线 / 授权 / 流程总览 / 决策树）一并塞进返回内容。
    这样 skill 是「被工具返回推给 AI」的，**不依赖客户端做任何 skill 配置** ——
    既不需要客户端预先安装，也不指望 AI 自觉去读文件。

    异常兜底：未包裹时 FastMCP 会返回 `Error executing tool xxx: <原始异常>`——
    Agent 拿不到 `ok:false`、也拿不到该怎么修，只能看到一句「工具坏了」。
    `functools.wraps` 保留了签名与注解，所以 inputSchema 的生成不受影响。
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        gate_response = skill_docs.SKILL_GATE.check(tool_name or func.__name__)
        if gate_response is not None:
            return json_text(gate_response)
        try:
            return await func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - 这里就是要兜住一切
            # `str(exc)` 对某些异常是空串（实测超时类异常就是），于是返回
            # `error:""` —— 而 hint 却写着「真实原因见 error 字段」，等于零信息。
            # 退化为 repr / 类名，保证 error 永远非空。
            detail = str(exc).strip() or repr(exc).strip() or exc.__class__.__name__
            # 超时类异常尤其危险：副作用往往已经发生（例如导航其实成功了），
            # 调用方若按「失败」重试就会重复执行。显式标注出来。
            timed_out = isinstance(exc, (asyncio.TimeoutError, TimeoutError))
            return json_text(
                {
                    "ok": False,
                    "tool": func.__name__,
                    "error": detail,
                    "errorType": exc.__class__.__name__,
                    **({"timedOut": True, "sideEffectMayHaveApplied": True} if timed_out else {}),
                    "hint": (
                        "已把异常兜成结构化错误，真实原因见 error 字段，请以它为准。"
                        "若是 WebSocket / CDP 相关：确认 `02-一键启动.bat` 已跑完、62000 在监听；"
                        "若是文件路径相关：注意服务进程的工作目录可能与你手工启动时不同；"
                        "若发生在页面切换瞬间：target 会短暂不可用，等 1-2s 重试即可。"
                    ),
                }
            )

    return wrapper


def create_mcp_app(runtime: McpRuntimeSession | None = None) -> FastMCP:
    """创建 MCP 应用实例，并把当前 SKILL.md 需要的分组工具注册进去。"""
    session = runtime or McpRuntimeSession()
    mcp = FastMCP(
        name="wxcdp",
        instructions=(
            "⚠️ 开工约定（务必遵守）：收到「测试 / 评估 / 分析 / 渗透某个小程序」这类请求时，"
            "**第一步必须先调用 skill_ops(action='guide') 读取评估流程**"
            "（skill: miniapp-security-core），再按它编排工具 —— "
            "不要跳过 skill 直接凭直觉调工具。"
            f"skill_ops 的 action: {_actions_text(skill_docs.SKILL_ACTIONS)}"
            "（guide=必读开篇 / index=完整章节目录 / read=取某章节 / search=在 skill 内检索）。"
            " ｜ 两条链路："
            "① 静态，不依赖 CDP —— decompile_ops(action='list_opened_applets') 定 appid → "
            "decompile 产出可读源码树 → search_source / read_source 定向看源码；"
            "② 动态 —— connection_ops / network_ops / runtime_ops / debugger_ops / analysis_ops / "
            "decrypt_ops / reverse_ops / replay_ops / pentest_ops / route_ops，"
            "连接 appservice 前建议先调用 connection_ops(action='find_appservice')。"
            "每个 *_ops 的 action 都有 enum，可直接自省。"
        ),
        streamable_http_path="/mcp",
        stateless_http=False,
    )

    def tool(**kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """注册工具，并统一套上结构化异常兜底 + skill 门禁（需要工具名）。"""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            name = str(kwargs.get("name") or func.__name__)
            return mcp.tool(**kwargs)(safe_tool(func, name))

        return decorator

    def resolve_output_dir(output_dir: str | None, appid: str | None = None) -> str:
        """推断反编译产物目录：显式传入优先，否则按 appid，再退回最近一次产物。

        这样 Agent 不必把 output_dir 一路传下来，少一处出错的地方。
        """
        if output_dir:
            return str(Path(str(output_dir)).expanduser())
        root = default_output_root()
        target = str(appid or "").strip()
        if target:
            candidate = root / target
            if candidate.is_dir():
                return str(candidate)
        try:
            candidates = [
                child
                for child in root.iterdir()
                if child.is_dir() and (child / MANIFEST_NAME).is_file()
            ]
        except OSError:
            candidates = []
        if candidates:
            latest = max(candidates, key=lambda item: item.stat().st_mtime)
            return str(latest)
        return str(root)

    @tool(
        name="skill_ops",
        description=(
            "读取本项目的评估流程 skill（`miniapp-security-core`，源文件 e0e1-wx/SKILL.md）。"
            "**收到「测试 / 评估 / 分析某小程序」这类请求时，第一步先调 action='guide'**，"
            "拿到红线、授权声明、评估流程总览与快速决策树，再按流程编排其它工具。"
            f"action: {_actions_text(skill_docs.SKILL_ACTIONS)}。"
            "guide=必读开篇；index=完整章节目录（标题 + 行号范围）；"
            "read=取某章节全文（section 支持标题片段，如 'Phase 1' / '2.2' / '经验法则' / '红线'）；"
            "search=在 skill 内按关键词或正则检索。"
            "注意：skill 有 20 万字符量级，**不要试图一次读完**，按需取章节即可。"
        ),
    )
    async def skill_ops(
        action: SkillAction = "guide",
        section: str = "",
        pattern: str = "",
        is_regex: bool = False,
    ) -> str:
        """读取评估流程 skill（读文件放线程里跑，避免阻塞事件循环）。"""
        return json_text(
            await asyncio.to_thread(
                skill_docs.run,
                action,
                section=section,
                pattern=pattern,
                is_regex=is_regex,
            )
        )

    @tool(
        name="decompile_ops",
        description=(
            "小程序静态源码（反编译）工具组 —— 不依赖 CDP 连接，可独立使用，"
            "是整个评估流程的静态侧起点。"
            f"action: {_actions_text(DECOMPILE_ACTIONS)}。"
            "list_opened_applets=列出本机有包缓存的小程序 + 当前微信小程序窗口（先跑它定 appid）；"
            "decompile=解密+解包+美化，产出可读源码树（幂等：源包没变就复用旧产物）；"
            "list_files=产物文件清单（按大小倒序）；"
            "search_source=内容检索，返回文件/行号/上下文（定位代码的主路径，大文件别整读）；"
            "read_source=按行区间读单个文件（默认上限 400 行）；"
            "scan_source=**按内置预设规则全量扫描产物**（27 条：PII / 云 AK / 私钥 / Token / "
            "Webhook / URL 接口 / 路径接口 / 加密调用 …），返回**每条规则的命中计数 + 有限样本 + "
            "top_files**。与 search_source 互补：那是指向已知假设的定向检索，这是「先摸清包里有什么」"
            "的全量清单，**静态评估第一步就该跑它**，不要自己写脚本扫。"
            "路径约定：产物所有相对路径都以 decompile 返回的 output_dir 为基准，"
            "形如 '__APP__/app-service.js'；未传 output_dir 时会按 appid 或最近一次产物自动推断。"
            "重要：分包按需下载，decompile 返回的 coverage / subpackages_missing 会显式报告"
            "缺失分包 —— 不要把主包当成全量，否则会静默漏测。"
        ),
    )
    async def decompile_ops(
        action: DecompileAction = "list_opened_applets",
        appid: str | None = None,
        version: str | None = None,
        packages_root: str | None = None,
        output_dir: str | None = None,
        output_root: str | None = None,
        path: str | None = None,
        pattern: str | None = None,
        start_line: int = 1,
        end_line: int | None = None,
        max_lines: int = DEFAULT_READ_MAX_LINES,
        is_regex: bool = False,
        case_sensitive: bool = False,
        context_lines: int = 2,
        max_results: int = DEFAULT_SEARCH_MAX_RESULTS,
        max_samples_per_rule: int = DEFAULT_SCAN_SAMPLES_PER_RULE,
        rules: list[dict[str, Any]] | None = None,
        extensions: list[str] | None = None,
        do_format: bool = True,
        force: bool = False,
    ) -> str:
        """执行静态反编译类操作（放到线程里跑，避免阻塞事件循环）。"""
        if action == "list_opened_applets":
            return json_text(
                await asyncio.to_thread(list_opened_applets, packages_root, limit=50)
            )

        if action == "decompile":
            if not appid:
                return json_text(
                    {
                        "ok": False,
                        "error": "decompile 需要 appid。",
                        "hint": "先调 action='list_opened_applets' 拿 appid。",
                    }
                )
            return json_text(
                await asyncio.to_thread(
                    decompile_applet,
                    appid,
                    packages_root=packages_root,
                    version=version,
                    output_root=output_root,
                    do_format=do_format,
                    force=force,
                )
            )

        if action == "list_files":
            target = resolve_output_dir(output_dir, appid)
            return json_text(
                await asyncio.to_thread(list_output_files, target, extensions=extensions)
            )

        if action == "search_source":
            if not pattern:
                return json_text(
                    {
                        "ok": False,
                        "error": "search_source 需要 pattern。",
                        "hint": "接口类可试 '/api/|/sys/|request\\('，凭据类可试 'token|secret|sign'。",
                    }
                )
            target = resolve_output_dir(output_dir, appid)
            return json_text(
                await asyncio.to_thread(
                    search_in_output,
                    target,
                    pattern,
                    is_regex=is_regex,
                    case_sensitive=case_sensitive,
                    context_lines=context_lines,
                    max_results=max_results,
                    extensions=extensions,
                )
            )

        if action == "scan_source":
            target = resolve_output_dir(output_dir, appid)
            return json_text(
                await asyncio.to_thread(
                    scan_output,
                    target,
                    rules=rules,
                    max_samples_per_rule=max_samples_per_rule,
                    extensions=extensions,
                )
            )

        if action == "read_source":
            if not path:
                return json_text({"ok": False, "error": "read_source 需要 path。"})
            target = resolve_output_dir(output_dir, appid)
            return json_text(
                await asyncio.to_thread(
                    read_source,
                    path,
                    base_dir=target,
                    start_line=start_line,
                    end_line=end_line,
                    max_lines=max_lines,
                )
            )

        return json_text(
            {
                "ok": False,
                "error": f"未知 action: {action}",
                "valid_actions": list(DECOMPILE_ACTIONS),
            }
        )

    @tool(
        name="connection_ops",
        description=(
            "CDP 连接与 target/上下文管理。"
            f"action: {_actions_text(CONNECTION_ACTIONS)}。"
            "status=状态；connect_wmpf=连 62000；list_targets=列 target（已补 role/isAppservice/score）；"
            "find_appservice=一步定位 appservice（attach 页面 session + 选 context）；"
            "select_appservice_context=只选 context（失败会自动回退 frames 桥）；"
            "switch_target=真正 attach 指定 target；cdp_call/cdp_call_target=透传任意 CDP 方法。"
        ),
    )
    async def connection_ops(
        action: ConnectionAction = "status",
        ws_url: str | None = None,
        wsUrl: str | None = None,
        target_id: str | None = None,
        targetId: str | None = None,
        method: str | None = None,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        sessionId: str | None = None,
        force: bool = False,
    ) -> str:
        """执行连接管理类操作。"""
        return await session.connection_ops(
            action,
            ws_url=ws_url,
            wsUrl=wsUrl,
            target_id=target_id,
            targetId=targetId,
            method=method,
            params=params,
            session_id=session_id,
            sessionId=sessionId,
            force=force,
        )

    @tool(
        name="network_ops",
        description=(
            "网络采集与 Hook。"
            f"action: {_actions_text(NETWORK_ACTIONS)}。"
            "install_early_hooks=导航前一次性装好所有 Hook（推荐先跑）；"
            "hook_wx_request/hook_upload_apis/hook_fetch_and_xhr=单独注入；"
            "fetch_from_page/upload_formdata_from_page=用 page-frame 的 fetch 绕过合法域名白名单。"
            "get_all_requests/get_recent_requests 务必显式传 excludeStatic=true，"
            "否则字体/图片/SVG 等静态资源会淹没结果（实测可涨到 1.7MB 导致返回体溢出）。"
        ),
    )
    async def network_ops(
        action: NetworkAction,
        request_id: str | None = None,
        requestId: str | None = None,
        id: str | None = None,
        limit: int | None = None,
        keyword: str | None = None,
        query: str | None = None,
        keywords: list[str] | None = None,
        domain: str | None = None,
        path_prefix: str | None = None,
        pathPrefix: str | None = None,
        url: str | None = None,
        method: str | None = None,
        headers: dict[str, Any] | None = None,
        body: Any | None = None,
        fields: dict[str, Any] | None = None,
        files: list[dict[str, Any]] | None = None,
        await_promise: bool = True,
        exclude_static: bool | None = None,
        excludeStatic: bool | None = None,
        exclude_telemetry: bool | None = None,
        excludeTelemetry: bool | None = None,
        compact: bool | None = None,
        max_length: int | None = None,
        maxLength: int | None = None,
    ) -> str:
        """执行网络采集类操作。

        `excludeStatic` / `excludeTelemetry` / `compact` / `maxLength` 以前只写在
        独立工具（`get_all_requests` / `get_recent_requests` / `get_request_detail`）
        的签名里，`network_ops` 没有暴露 —— 于是「按 SKILL.md 走 network_ops」的
        调用方既传不进 `excludeStatic`（静态资源不排除，返回体可涨到 1.7MB+ 直接
        溢出），又会因 inputSchema 的 `additionalProperties:false` 而**直接报参数
        校验错**。实现层一直支持这几个 key（`runtime_session.network_ops` 直接读），
        这里补齐即可。

        注意：值为 `None` 的键**不能透传** —— 实现层用的是
        `bool(kwargs.get("compact", True))` 这种「键不存在才取默认值」的写法，
        显式传 None 会被 `bool(None) -> False` 顶掉默认值，反而改变既有行为。
        """
        extra = {
            "excludeStatic": excludeStatic if excludeStatic is not None else exclude_static,
            "excludeTelemetry": excludeTelemetry if excludeTelemetry is not None else exclude_telemetry,
            "compact": compact,
            "maxLength": maxLength if maxLength is not None else max_length,
        }
        return await session.network_ops(
            action,
            request_id=request_id,
            requestId=requestId,
            id=id,
            limit=limit,
            keyword=keyword,
            query=query,
            keywords=keywords,
            domain=domain,
            path_prefix=path_prefix,
            pathPrefix=pathPrefix,
            url=url,
            method=method,
            headers=headers,
            body=body,
            fields=fields,
            files=files,
            await_promise=await_promise,
            **{key: value for key, value in extra.items() if value is not None},
        )

    @tool(
        name="runtime_ops",
        description=(
            "运行时求值、快照、storage 扫描、上传面检测、路由稳定等待、桥探针与 Vuex 检查。"
            f"action: {_actions_text(RUNTIME_ACTIONS)}。"
            "runtime_eval=在 page-frame 求值（有 window.__routeNavigator / DOM，"
            "但没有 getCurrentPages / wx —— 写了会 ReferenceError）；"
            "runtime_eval_appservice=在 appservice 求值（有 getCurrentPages / wx；"
            "context 不可用时自动走 window.__as 桥）；"
            "wait_route_stable=等路由稳定（getCurrentPages 有 4-7s 延迟，别立刻读栈）；"
            "probe_bridge=发 toast 做活性探针，配合 capture_screenshot 验证。"
        ),
    )
    async def runtime_ops(
        action: RuntimeAction,
        expression: str | None = None,
        await_promise: bool = True,
        context_id: int | None = None,
        contextId: int | None = None,
        selector: str | None = None,
        text: str | None = None,
        path: str | None = None,
        value: Any | None = None,
        dryRun: bool = True,
        requireConfirm: bool = False,
        timeout: float | None = None,
        settle: float | None = None,
        include_raw: bool | None = None,
        includeRaw: bool = False,
        max_raw_chars: int | None = None,
        maxRawChars: int | None = None,
    ) -> str:
        """执行运行时类操作。"""
        return await session.runtime_ops(
            action,
            expression=expression,
            await_promise=await_promise,
            context_id=context_id,
            contextId=contextId,
            selector=selector,
            text=text,
            path=path,
            value=value,
            dryRun=dryRun,
            requireConfirm=requireConfirm,
            timeout=timeout,
            settle=settle,
            includeRaw=include_raw if include_raw is not None else includeRaw,
            maxRawChars=maxRawChars if maxRawChars is not None else max_raw_chars,
        )

    @tool(
        name="debugger_ops",
        description=(
            "源码分析、断点、执行控制与 WebSocket 消息。"
            f"action: {_actions_text(DEBUGGER_ACTIONS)}。"
            "list_scripts=列出已加载脚本（带 summary，named_only 只看带 URL 的真脚本）；"
            "get_script_source=取源码（full=true 整篇返回，并给出 totalLength/nextOffset/hasMore）；"
            "save_script_source=整篇落盘；search_in_sources=检索已加载脚本"
            "（默认跳过匿名脚本，对 .cachedata 无效）；"
            "break_on_xhr/set_breakpoint_on_text=下断点（**必须配对调用 remove_breakpoints**，"
            "否则断点会残留并卡住后续复测）；list_breakpoints/remove_breakpoints=查看与撤销断点。"
        ),
    )
    async def debugger_ops(
        action: DebuggerAction,
        query: str | None = None,
        text: str | None = None,
        expression: str | None = None,
        url: str | None = None,
        pattern: str | None = None,
        script_id: str | None = None,
        scriptId: str | None = None,
        file_path: str | None = None,
        filePath: str | None = None,
        offset: int | None = None,
        length: int | None = None,
        full: bool = False,
        start_line: int | None = None,
        startLine: int | None = None,
        end_line: int | None = None,
        endLine: int | None = None,
        case_sensitive: bool = False,
        is_regex: bool = False,
        max_results: int | None = None,
        url_filter: str | None = None,
        urlFilter: str | None = None,
        named_only: bool = False,
        include_anonymous: bool = False,
        scope: Literal["miniapp", "all"] = "miniapp",
        limit: int | None = None,
        breakpoint_id: str | None = None,
        breakpointId: str | None = None,
        removeAll: bool = True,
        await_promise: bool = True,
        context_id: int | None = None,
        contextId: int | None = None,
        kind: str | None = None,
        type: str | None = None,
    ) -> str:
        """执行调试器类操作。"""
        return await session.debugger_ops(action, query=query, text=text, expression=expression, url=url, pattern=pattern, script_id=script_id, scriptId=scriptId, file_path=file_path, filePath=filePath, offset=offset, length=length, full=full, start_line=start_line, startLine=startLine, end_line=end_line, endLine=endLine, case_sensitive=case_sensitive, is_regex=is_regex, max_results=max_results, url_filter=url_filter, urlFilter=urlFilter, named_only=named_only, include_anonymous=include_anonymous, scope=scope, limit=limit, breakpoint_id=breakpoint_id, breakpointId=breakpointId, removeAll=removeAll, await_promise=await_promise, context_id=context_id, contextId=contextId, kind=kind, type=type)

    @tool(
        name="analysis_ops",
        description=(
            "接口资产、认证/IDOR/敏感信息/上传/支付风险线索、重放计划和报告导出。"
            f"action: {_actions_text(ANALYSIS_ACTIONS)}。"
            "默认排除埋点/遥测（kind=telemetry）—— 它们占比可以很高（实测 28/49）且会污染"
            "接口清单与签名面；需要分析埋点本身（例如查 PII 上报）时传 includeTelemetry=true。"
        ),
    )
    async def analysis_ops(
        action: AnalysisAction,
        request_id: str | None = None,
        requestId: str | None = None,
        request_id_a: str | None = None,
        requestIdA: str | None = None,
        request_id_b: str | None = None,
        requestIdB: str | None = None,
        limit: int | None = None,
        include_telemetry: bool | None = None,
        includeTelemetry: bool | None = None,
        max_length: int | None = None,
        maxLength: int | None = None,
    ) -> str:
        """执行分析类操作。"""
        return await session.analysis_ops(action, request_id=request_id, requestId=requestId, request_id_a=request_id_a, requestIdA=requestIdA, request_id_b=request_id_b, requestIdB=requestIdB, limit=limit, include_telemetry=include_telemetry, includeTelemetry=includeTelemetry, max_length=max_length, maxLength=maxLength)

    @tool(
        name="decrypt_ops",
        description=(
            "编码识别、解码、解密、多层流水线和运行时加密函数调用。"
            f"action: {_actions_text(DECRYPT_ACTIONS)}。"
        ),
    )
    async def decrypt_ops(
        action: DecryptAction,
        value: str | None = None,
        algorithm: str | None = None,
        key: str | None = None,
        mode: str | None = None,
        iv: str | None = None,
        input_encoding: str | None = None,
        key_encoding: str | None = None,
        iv_encoding: str | None = None,
        encoding: str | None = None,
        steps: list[Any] | None = None,
        function_name: str | None = None,
        functionName: str | None = None,
        args: list[Any] | None = None,
    ) -> str:
        """执行解密类操作。"""
        return await session.decrypt_ops(action, value=value, algorithm=algorithm, key=key, mode=mode, iv=iv, input_encoding=input_encoding, key_encoding=key_encoding, iv_encoding=iv_encoding, encoding=encoding, steps=steps, function_name=function_name, functionName=functionName, args=args)

    @tool(
        name="reverse_ops",
        description=(
            "逆向案例匹配、加密模式识别和逆向策略建议。"
            f"action: {_actions_text(REVERSE_ACTIONS)}。"
        ),
    )
    async def reverse_ops(action: ReverseAction = "detect_reverse_strategy", text: str | None = None, source: str | None = None) -> str:
        """执行逆向辅助类操作。"""
        return await session.reverse_ops(action, text=text, source=source)

    @tool(
        name="replay_ops",
        description=(
            "自动重放任务管理；默认只生成计划，不自动发送写请求。"
            f"action: {_actions_text(REPLAY_ACTIONS)}。"
        ),
    )
    async def replay_ops(
        action: ReplayAction,
        request_id: str | None = None,
        requestId: str | None = None,
        job_id: str | None = None,
        jobId: str | None = None,
    ) -> str:
        """执行重放计划类操作。"""
        return await session.replay_ops(action, request_id=request_id, requestId=requestId, job_id=job_id, jobId=jobId)

    @tool(
        name="pentest_ops",
        description=(
            "主动扫描任务管理，任务隔离并可查询。"
            f"action: {_actions_text(PENTEST_ACTIONS)}。"
        ),
    )
    async def pentest_ops(action: PentestAction, scope: str | None = None, job_id: str | None = None, jobId: str | None = None) -> str:
        """执行主动扫描任务类操作。"""
        return await session.pentest_ops(action, scope=scope, job_id=job_id, jobId=jobId)

    @tool(
        name="route_ops",
        description=(
            "小程序路由操作。"
            f"action: {_actions_text(ROUTE_ACTIONS)}。"
            "inspect_routes=读路由表与守卫状态；navigate_route/navigate_route_with_guard=跳转；"
            "⚠️ 跳转类工具默认只回**路由表摘要**（`before`/`after` 含 currentRoute/guardEnabled/"
            "routeCount 等），完整路由表与 hook 明细要传 `verbose=true` —— "
            "早先内联完整路由表时返回体达 95K~102K 字符，关键字段 `landedOnTarget` 反而读不到。"
            "navigate_back=回退页面栈（不用自己拼 wx.navigateBack）；"
            "wait_route_stable=等路由稳定后再判断成败；"
            "plan_route_crawl=**只规划不导航**：把 N 条路由拆成带预计耗时与 resumeFrom 的分批计划；"
            "**crawl_routes=真正执行导航**（批量遍历的执行原语）：按批导航并逐条记录落点与新增请求，"
            "支持 start_from / max_routes / deadline_seconds 分段与 nextStartFrom 续跑，"
            "单条失败只记在该条上、不中断整批。"
            "**两者配对用**：先 plan_route_crawl 拿分批计划，再把 batches[].routes 交给 crawl_routes 执行 —— "
            "不要在单个 runtime_eval 里自己拼导航循环（实测可靠窗口只有约 3 条，会以超时结束且导航已执行）。"
        ),
    )
    async def route_ops(
        action: RouteAction,
        route: str | None = None,
        is_tabbar: bool = False,
        isTabbar: bool | None = None,
        wait_ms: int | None = None,
        waitMs: int | None = None,
        delta: int | None = None,
        timeout: float | None = None,
        settle: float | None = None,
        routes: list[str] | None = None,
        settle_ms: int | None = None,
        settleMs: int | None = None,
        deadline_seconds: float | None = None,
        deadlineSeconds: float | None = None,
        max_routes: int | None = None,
        maxRoutes: int | None = None,
        start_from: int | None = None,
        startFrom: int | None = None,
        verbose: bool | None = None,
        rehook: bool | None = None,
        navigation_timeout_seconds: float | None = None,
        navigationTimeoutSeconds: float | None = None,
        exclude_tabbar: bool | None = None,
        excludeTabbar: bool | None = None,
        include_subpackages: bool | None = None,
        includeSubpackages: bool | None = None,
    ) -> str:
        """执行小程序路由和防跳转守卫类操作。"""
        extra: dict[str, Any] = {
            "routes": routes,
            "settle_ms": settle_ms if settle_ms is not None else settleMs,
            "deadline_seconds": (
                deadline_seconds if deadline_seconds is not None else deadlineSeconds
            ),
            "max_routes": max_routes if max_routes is not None else maxRoutes,
            "start_from": start_from if start_from is not None else startFrom,
            "verbose": verbose,
            "rehook": rehook,
            "navigation_timeout_seconds": (
                navigation_timeout_seconds
                if navigation_timeout_seconds is not None
                else navigationTimeoutSeconds
            ),
            "exclude_tabbar": exclude_tabbar if exclude_tabbar is not None else excludeTabbar,
            "include_subpackages": (
                include_subpackages if include_subpackages is not None else includeSubpackages
            ),
        }
        return await session.route_ops(
            action,
            route=route,
            is_tabbar=bool(is_tabbar if isTabbar is None else isTabbar),
            wait_ms=wait_ms if wait_ms is not None else waitMs,
            delta=delta,
            timeout=timeout,
            settle=settle,
            # 值为 None 的键不能透传：实现层用 `kwargs.get(x) or 默认值` 取默认，
            # 显式传 None 会顶掉默认值（与 network_ops 同一坑，见该处注释）。
            **{key: value for key, value in extra.items() if value is not None},
        )

    # —— 以下为单动作快捷工具（兼容旧调用方）——

    @tool(name="status", description="返回 MCP 桥与 CDP 连接状态，含 pageSessionId / appserviceMode。")
    async def status() -> str:
        """返回 MCP 与 CDP 的连接状态。"""
        return await session.connection_ops("status")

    @tool(
        name="connect_wmpf",
        description=(
            "连接本机 WMPFDebugger 的 CDP WebSocket（默认 ws://127.0.0.1:62000）。"
            "**链路卡死时（status().cdp.pendingCalls > 0）会自动重建连接** —— "
            "这种状态下旧连接已收不到回应，只有重建才恢复得了；"
            "force=true 可无条件重建。重建后需重新 find_appservice 选 context。"
        ),
    )
    async def connect_wmpf(
        wsUrl: str | None = None,
        ws_url: str | None = None,
        force: bool = False,
    ) -> str:
        """连接本机 CDP WebSocket。"""
        # 必须 json_text 包一层：本文件的工具签名统一是 `-> str`，FastMCP 会据此生成
        # outputSchema 并做输出校验；直接返回 dict 会被 pydantic 挡下，报
        # `1 validation error for connect_wmpfOutput / Input should be a valid string`。
        # 实测踩过：`connect_wmpf` 曾因此**完全不可用**（而 `connection_ops(action="connect_wmpf")`
        # 是好的，因为那条路径本来就 return json_text）—— 典型的「两套入口只有一套能跑」。
        return json_text(await session.connect_wmpf(wsUrl or ws_url, force=bool(force)))

    @tool(
        name="select_appservice_context",
        description=(
            "自动定位并选中 appservice 的 Runtime context。"
            "失败时自动回退到 window.frames 桥（mode=frames_bridge），并返回 howToFix。"
            "force=true 会强制重新 attach 页面 session。"
        ),
    )
    async def select_appservice_context(force: bool = False) -> str:
        """自动选中 appservice 的 Runtime context。"""
        return await session.connection_ops("select_appservice_context", force=force)

    @tool(
        name="find_appservice",
        description=(
            "一步到位定位 appservice：attach 页面 target + 选 Runtime context + 返回诊断。"
            "连接类问题优先调这个，而不是自己拼 list_targets/switch_target。"
        ),
    )
    async def find_appservice() -> str:
        """一步定位 appservice target 与 Runtime context。"""
        return await session.connection_ops("find_appservice")

    @tool(name="list_targets", description="列出 CDP target，并补 name/role/score/isAppservice 与 recommendedTargetId。")
    async def list_targets() -> str:
        """列出带元数据的 CDP target。"""
        return await session.connection_ops("list_targets")

    @tool(name="switch_target", description="attach 到指定 targetId 并把它设为当前页面 session（会重建 Runtime context 缓存）。")
    async def switch_target(target_id: str | None = None, targetId: str | None = None) -> str:
        """切换到指定 target。"""
        return await session.connection_ops("switch_target", target_id=target_id, targetId=targetId)

    @tool(
        name="cdp_call",
        description="调用任意 CDP 方法（浏览器层）。可选 flatten sessionId。",
    )
    async def cdp_call(method: str, params: dict[str, Any] | None = None, sessionId: str | None = None, session_id: str | None = None) -> str:
        """调用任意 CDP 方法。"""
        return json_text(await session.cdp_call(method, params or {}, sessionId or session_id))

    @tool(
        name="cdp_call_target",
        description=(
            "attach 到 targetId（flatten）后在该 session 调用 CDP 方法。"
            "返回已拍平：value=方法返回值，data=其中的 data 字段"
            "（截图就是 result.result.data，这里直接给 data）。"
        ),
    )
    async def cdp_call_target(targetId: str | None = None, target_id: str | None = None, method: str = "", params: dict[str, Any] | None = None) -> str:
        """在指定 target 的子 session 中调用 CDP 方法。"""
        return json_text(await session.cdp_call_target(targetId or target_id or "", method, params or {}))

    @tool(
        name="capture_screenshot",
        description=(
            "截图取证。不传 targetId 时自动挑 type=page 的小程序 target。"
            "传 file_path 直接落盘（推荐，避免大段 base64）；不传则返回 base64 的 data。"
        ),
    )
    async def capture_screenshot(
        targetId: str | None = None,
        target_id: str | None = None,
        format: str = "png",
        quality: int | None = None,
        file_path: str | None = None,
        filePath: str | None = None,
    ) -> str:
        """对小程序页面截图。"""
        return json_text(
            await session.capture_screenshot(
                target_id=targetId or target_id or "",
                image_format=format,
                quality=quality,
                file_path=file_path or filePath or "",
            )
        )

    @tool(name="runtime_eval", description="在当前 Runtime 求值 JavaScript（默认 awaitPromise=true）。")
    async def runtime_eval(expression: str, returnByValue: bool = True, awaitPromise: bool = True) -> str:
        """在当前 Runtime 求值 JavaScript。"""
        del returnByValue
        return await session.runtime_ops("runtime_eval", expression=expression, await_promise=awaitPromise)

    @tool(
        name="runtime_eval_appservice",
        description=(
            "在 appservice 中求值 JavaScript。context 不可用时自动改走 window.__as 桥"
            "（跨 frame 不能 eval，但 wx/getCurrentPages 等全局会被绑成局部变量）。"
        ),
    )
    async def runtime_eval_appservice(expression: str, forceSelect: bool = False) -> str:
        """在 appservice 中求值 JavaScript。"""
        if forceSelect:
            await session.select_appservice_context(force=True)
        return await session.runtime_ops("runtime_eval_appservice", expression=expression)

    @tool(name="wait_route_stable", description="等待路由稳定（连续 settle 秒不变）再返回 route；用于避免把成功导航误判为失败。")
    async def wait_route_stable(timeout: float = 12, settle: float = 2.5) -> str:
        """等待路由稳定。"""
        return await session.runtime_ops("wait_route_stable", timeout=timeout, settle=settle)

    @tool(name="probe_bridge", description="桥活性探针：发一个 toast 并返回 token，配合 capture_screenshot 判断桥是否驱动可见实例。")
    async def probe_bridge() -> str:
        """执行桥活性探针。"""
        return await session.runtime_ops("probe_bridge")

    @tool(name="dump_runtime_snapshot", description="采集页面 URL/storage/路由/可见文本快照，并标注 capturedAt 与数据新鲜度。")
    async def dump_runtime_snapshot(maxLength: int = 20_000) -> str:
        """采集运行时快照。maxLength 控制可见文本截断长度。"""
        return await session.runtime_ops("dump_runtime_snapshot", maxLength=maxLength)

    @tool(
        name="scan_sensitive_storage",
        description=(
            "扫描 wx/local/session Storage 中的 OSS/COS/S3、DB、API、支付、短信、JWT、口令与内部配置线索。"
            "检测通道含字面量关键词、JWT 结构识别（解码出 alg/exp）、PII 字段名、高熵硬编码密钥与 base64 递归解码。"
            "原始 storage 转储默认不回传（体积可到 700KB+ 且含明文密钥），需要时传 includeRaw=true。"
        ),
    )
    async def scan_sensitive_storage(includeRaw: bool = False, maxRawChars: int = 4000) -> str:
        """扫描敏感 Storage。"""
        return await session.runtime_ops("scan_sensitive_storage", includeRaw=includeRaw, maxRawChars=maxRawChars)

    @tool(name="inspect_upload_surface", description="检查当前路由的上传/选图/头像/文件相关指示。")
    async def inspect_upload_surface() -> str:
        """检查当前页上传面。"""
        return await session.runtime_ops("inspect_upload_surface")

    @tool(
        name="get_basic_page_info",
        description=(
            "页面信息快照。注意：visibleText 是渲染层文本，导航后可能滞后；"
            "route 来自 getCurrentPages()，有 4-7s 读取延迟。返回里带 capturedAt/ageSeconds/freshness。"
        ),
    )
    async def get_basic_page_info() -> str:
        """返回页面信息快照。"""
        return json_text(await session.get_basic_page_info())

    @tool(name="get_document_html", description="返回 document.documentElement.outerHTML 前缀（仅 DOM 渲染环境有内容）。")
    async def get_document_html(maxLength: int = 20_000) -> str:
        """返回 document HTML 前缀。"""
        return json_text(await session.get_document_html(maxLength))

    @tool(name="query_selector_text", description="返回 document.querySelector(selector) 的文本与 HTML 摘要（仅 DOM 渲染环境可用）。")
    async def query_selector_text(selector: str, maxLength: int = 10_000) -> str:
        """返回匹配元素的文本与 HTML。"""
        return json_text(await session.query_selector_text(selector, maxLength))

    @tool(
        name="list_interactive_elements",
        description=(
            "列出可点击/可输入元素及风险提示。"
            "注意：**仅适用于 DOM 渲染（webview renderer）**。Goji/原生渲染的小程序界面没有 DOM，"
            "本工具会返回 count=0，此时请改用 runtime_eval_appservice 直接调用页面方法。"
        ),
    )
    async def list_interactive_elements() -> str:
        """列出可交互元素。"""
        return await session.runtime_ops("list_interactive_elements")

    @tool(
        name="safe_click_and_observe",
        description=(
            "点击一个元素并观察被动变化（依赖 CSS selector，仅 DOM 渲染环境可用；"
            "Goji/原生渲染请改用 runtime_eval_appservice）。危险文案需要 requireConfirm=true。"
        ),
    )
    async def safe_click_and_observe(selector: str, waitMs: int = 1500, captureBeforeAfter: bool = True, requireConfirm: bool = False) -> str:
        """点击元素并观察变化。waitMs 是点击后的观察窗口（默认 1.5s）。"""
        return await session.runtime_ops(
            "safe_click_and_observe", selector=selector, requireConfirm=requireConfirm, waitMs=waitMs, captureBeforeAfter=captureBeforeAfter
        )

    @tool(
        name="input_text_and_observe",
        description="向一个输入框写入文本并观察被动变化（依赖 CSS selector，仅 DOM 渲染环境可用）。",
    )
    async def input_text_and_observe(selector: str, text: str, waitMs: int = 800) -> str:
        """写入文本并观察变化。waitMs 是写入后的观察窗口。"""
        return await session.runtime_ops("input_text_and_observe", selector=selector, text=text, waitMs=waitMs)

    @tool(name="network_enable", description="启用 CDP Network domain。")
    async def network_enable() -> str:
        """启用 CDP Network domain。"""
        return await session.network_ops("network_enable")

    @tool(name="get_recent_requests", description="返回最近的 CDP Network 请求，支持过滤与紧凑输出。")
    async def get_recent_requests(limit: int = 50, domain: str | None = None, pathPrefix: str | None = None, keyword: str | None = None, excludeStatic: bool = True, compact: bool = True) -> str:
        """返回最近请求。excludeStatic 默认 true，过滤字体/图片/SVG/data: 内联资源。"""
        return json_text(
            await session.get_recent_requests(
                limit, domain=domain, path_prefix=pathPrefix, keyword=keyword, compact=compact, exclude_static=excludeStatic
            )
        )

    @tool(name="get_response_body", description="返回 CDP Network.getResponseBody。")
    async def get_response_body(requestId: str | None = None, request_id: str | None = None) -> str:
        """返回响应体。"""
        return json_text(await session.get_response_body(requestId or request_id or ""))

    @tool(
        name="get_recent_console",
        description=(
            "返回最近的 console 与异常事件。**带硬体量上限**："
            "`maxTextLength`（默认 2000，截断单条事件里的长字符串）与 "
            "`maxBytes`（默认 24000，从最新往旧累计，超出即丢弃更早的事件）。"
            "⚠️ `limit` 只控制**条数**、不控制体量 —— 单条巨长异常就能撑爆返回体"
            "（实测 limit=40 → 80,940 字符、limit=5 → 133,024 字符）。"
            "返回里的 `returned` / `droppedByBytes` / `truncatedFields` 说明实际给了多少、丢了多少。"
        ),
    )
    async def get_recent_console(
        limit: int = 50,
        max_bytes: int | None = None,
        maxBytes: int | None = None,
        max_text_length: int | None = None,
        maxTextLength: int | None = None,
    ) -> str:
        """返回最近控制台事件（带体量护栏）。"""
        return json_text(
            await session.get_recent_console(
                limit,
                max_bytes=max_bytes if max_bytes is not None else maxBytes,
                max_text_length=max_text_length if max_text_length is not None else maxTextLength,
            )
        )

    @tool(name="inspect_window_keys", description="列出 window/globalThis 的 key，可按关键词过滤。")
    async def inspect_window_keys(pattern: str | None = None, limit: int = 200) -> str:
        """列出全局 key。"""
        return json_text(await session.inspect_window_keys(pattern, limit))

    @tool(name="search_global_string", description="在 document、脚本、window key 中搜索一个关键词。")
    async def search_global_string(keyword: str, maxLength: int = 20_000) -> str:
        """全局搜索关键词。"""
        return json_text(await session.search_global_string(keyword, maxLength))

    @tool(name="hook_wx_request", description="注入非破坏性的 wx.request Hook。")
    async def hook_wx_request() -> str:
        """注入 wx.request Hook。"""
        return await session.network_ops("hook_wx_request")

    @tool(name="hook_upload_apis", description="在 appservice 中尽早注入 wx.uploadFile/chooseImage/chooseMedia Hook。")
    async def hook_upload_apis() -> str:
        """注入上传与选图 Hook。"""
        return await session.network_ops("hook_upload_apis")

    @tool(name="install_early_hooks", description="Phase-0 最早安装所有 Hook：appservice 选择、wx.request、上传 API、fetch/XHR。")
    async def install_early_hooks() -> str:
        """Phase 0 最早安装所有 Hook。"""
        return await session.network_ops("install_early_hooks")

    @tool(name="hook_fetch_and_xhr", description="注入非破坏性的 fetch/XHR Hook，并捕获响应。")
    async def hook_fetch_and_xhr() -> str:
        """注入 fetch/XHR Hook。"""
        return await session.network_ops("hook_fetch_and_xhr")

    @tool(name="fetch_from_page", description="在 page-frame 发 fetch 请求，可绕过 wx.request 的合法域名白名单。")
    async def fetch_from_page(url: str, method: str = "GET", headers: dict[str, Any] | None = None, body: Any | None = None) -> str:
        """在 page-frame 上下文执行 fetch。"""
        return await session.network_ops("fetch_from_page", url=url, method=method, headers=headers, body=body)

    @tool(name="upload_formdata_from_page", description="首选上传方式：用 page-frame fetch + FormData 发 multipart，而不是 appservice 的 wx.uploadFile。")
    async def upload_formdata_from_page(
        url: str,
        headers: dict[str, Any] | None = None,
        fields: dict[str, Any] | None = None,
        files: list[dict[str, Any]] | None = None,
        method: str = "POST",
    ) -> str:
        """在 page-frame 上下文构建 FormData 并发起 multipart 上传。"""
        return await session.network_ops("upload_formdata_from_page", url=url, method=method, headers=headers, fields=fields, files=files)

    @tool(name="get_hooked_requests", description="返回 fetch/XHR/wx.request Hook 记录。")
    async def get_hooked_requests(limit: int = 50) -> str:
        """返回 Hook 记录。"""
        return json_text({"ok": True, "requests": (await session.get_hooked_requests())[-max(1, int(limit)): ]})

    @tool(
        name="get_all_requests",
        description=(
            "返回归一化后的 CDP + wx.request + fetch/XHR 请求。每条带 kind（api/telemetry/static/data_uri/document）。"
            "excludeStatic=true 只看接口类请求。"
        ),
    )
    async def get_all_requests(limit: int = 50, keyword: str | None = None, domain: str | None = None, pathPrefix: str | None = None, excludeStatic: bool = False) -> str:
        """返回全部请求。"""
        return await session.network_ops("get_all_requests", limit=limit, keyword=keyword, domain=domain, pathPrefix=pathPrefix, excludeStatic=excludeStatic)

    @tool(name="get_request_detail", description="返回单条归一化请求，并尽量附上 CDP 响应体。")
    async def get_request_detail(requestId: str | None = None, request_id: str | None = None, maxLength: int = 20_000) -> str:
        """返回单条请求详情。maxLength 控制返回体积（响应体过大时会截断并提示）。"""
        return await session.network_ops("get_request_detail", requestId=requestId, request_id=request_id, maxLength=maxLength)

    @tool(name="get_api_inventory", description="基于已观测请求生成去重后的接口资产清单。")
    async def get_api_inventory(limit: int = 300) -> str:
        """生成接口资产清单。"""
        return await session.analysis_ops("get_api_inventory", limit=limit)

    @tool(name="analyze_auth_surface", description="分析认证字段与重放线索。")
    async def analyze_auth_surface() -> str:
        """分析认证面。"""
        return await session.analysis_ops("analyze_auth_surface")

    @tool(name="find_idor_candidates", description="找出手动 IDOR 测试候选；不发送任何请求。")
    async def find_idor_candidates() -> str:
        """查找 IDOR 候选。"""
        return await session.analysis_ops("find_idor_candidates")

    @tool(name="find_sensitive_data_exposure", description="在已观测请求/响应中查找敏感字段，默认脱敏。")
    async def find_sensitive_data_exposure() -> str:
        """查找敏感数据暴露。"""
        return await session.analysis_ops("find_sensitive_data_exposure")

    @tool(name="find_upload_surfaces", description="查找上传/文件相关接口与手动检查点。")
    async def find_upload_surfaces() -> str:
        """查找上传面。"""
        return await session.analysis_ops("find_upload_surfaces")

    @tool(name="find_payment_and_order_surfaces", description="查找支付/订单/优惠券/钱包相关面；不做变更也不重放。")
    async def find_payment_and_order_surfaces() -> str:
        """查找支付与订单面。"""
        return await session.analysis_ops("find_payment_and_order_surfaces")

    @tool(name="find_debug_admin_surfaces", description="查找 debug/test/admin/internal/dev/staging/mock 等指示。")
    async def find_debug_admin_surfaces() -> str:
        """查找调试与后台面。"""
        return await session.analysis_ops("find_debug_admin_surfaces")

    @tool(name="build_replay_plan", description="生成手动重放测试计划；永不发送请求。")
    async def build_replay_plan(requestId: str | None = None, request_id: str | None = None) -> str:
        """生成重放计划。"""
        return await session.analysis_ops("build_replay_plan", requestId=requestId, request_id=request_id)

    @tool(name="compare_two_requests", description="比较两条已观测请求的认证/请求体/响应差异。")
    async def compare_two_requests(requestIdA: str | None = None, request_id_a: str | None = None, requestIdB: str | None = None, request_id_b: str | None = None) -> str:
        """比较两条请求。"""
        return await session.analysis_ops("compare_two_requests", requestIdA=requestIdA, request_id_a=request_id_a, requestIdB=requestIdB, request_id_b=request_id_b)

    @tool(name="passive_param_fuzz_suggestions", description="只生成被动 fuzz 建议；不发送请求。")
    async def passive_param_fuzz_suggestions(requestId: str | None = None, request_id: str | None = None) -> str:
        """生成被动 fuzz 建议。"""
        return await session.analysis_ops("passive_param_fuzz_suggestions", requestId=requestId, request_id=request_id)

    @tool(name="inspect_wx_config", description="检查 __wxConfig、__wxAppCode__、__wxRoute、__wxAppData__ 摘要。")
    async def inspect_wx_config(maxLength: int = 20_000) -> str:
        """检查小程序运行时配置。maxLength 控制返回体积。"""
        return await session.network_ops("inspect_wx_config", maxLength=maxLength)

    @tool(name="search_runtime_keywords", description="在运行时、storage、脚本与已观测请求中搜索关键词。")
    async def search_runtime_keywords(keywords: list[str] | None = None, maxLength: int = 20_000) -> str:
        """搜索运行时关键词。每个命中带 60 字上下文片段与来源；maxLength 控制总体积。"""
        return await session.network_ops("search_runtime_keywords", keywords=keywords or [], maxLength=maxLength)

    @tool(name="trace_request_callstack", description="返回 wx/fetch/XHR Hook 捕获的调用栈。")
    async def trace_request_callstack(requestId: str | None = None, request_id: str | None = None, limit: int = 50) -> str:
        """返回请求调用栈。limit 限制返回的栈帧行数。"""
        return await session.network_ops("trace_request_callstack", requestId=requestId, request_id=request_id, limit=limit)

    @tool(name="inspect_vuex_store", description="检查 appservice 里的 Vuex-like store，并保存原始 state 快照。")
    async def inspect_vuex_store(maxLength: int = 20_000, forceSelect: bool = False) -> str:
        """检查 Vuex store。forceSelect=true 会先强制重选 appservice 上下文；maxLength 控制 state 快照体积。"""
        return await session.runtime_ops("inspect_vuex_store", forceSelect=forceSelect, maxLength=maxLength)

    @tool(name="patch_vuex_state", description="修改 Vuex-like state。默认 dryRun，需要 requireConfirm=true 才真正写入。")
    async def patch_vuex_state(path: str = "", value: Any | None = None, dryRun: bool = True, requireConfirm: bool = False, forceSelect: bool = False) -> str:
        """修改 Vuex state。默认 dryRun；真正写入需 dryRun=false 且 requireConfirm=true。"""
        return await session.runtime_ops("patch_vuex_state", path=path, value=value, dryRun=dryRun, requireConfirm=requireConfirm, forceSelect=forceSelect)

    @tool(name="restore_vuex_state", description="用 inspect_vuex_store 保存的快照还原 Vuex-like state。默认 dryRun。")
    async def restore_vuex_state(dryRun: bool = True, requireConfirm: bool = False, forceSelect: bool = False) -> str:
        """还原 Vuex state。注意：当前不支持自动还原，会返回 supported=false 与手工还原指引。"""
        return await session.runtime_ops("restore_vuex_state", dryRun=dryRun, requireConfirm=requireConfirm, forceSelect=forceSelect)

    @tool(name="find_sign_related_requests", description="查找包含 sign/signature/timestamp/nonce 字段的请求。")
    async def find_sign_related_requests() -> str:
        """查找签名相关请求。"""
        return await session.analysis_ops("find_sign_related_requests")

    @tool(name="export_session", description="把当前评估会话导出为 JSON 到 output/reports。")
    async def export_session() -> str:
        """导出评估会话。"""
        return await session.analysis_ops("export_session")

    @tool(name="generate_security_notes", description="基于已观测证据生成 Markdown 安全评估笔记。")
    async def generate_security_notes(maxLength: int = 80_000) -> str:
        """生成安全评估笔记。maxLength 控制 Markdown 长度。"""
        return await session.analysis_ops("generate_security_notes", maxLength=maxLength)

    @tool(name="generate_api_table_markdown", description="生成 Markdown 接口表。")
    async def generate_api_table_markdown(maxLength: int = 80_000) -> str:
        """生成接口表 Markdown。maxLength 控制输出长度。"""
        return await session.analysis_ops("generate_api_table_markdown", maxLength=maxLength)

    return mcp
