"""轻量 WMPF/CDP WebSocket 客户端：负责发请求、收事件、断线重连。"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import websockets


JsonDict = dict[str, Any]
EventCallback = Callable[[JsonDict], None]


@dataclass(slots=True)
class PendingCdpCall:
    """一个已发出但还没收到响应的 CDP 调用。"""

    future: asyncio.Future
    method: str
    created_at: float = field(default_factory=time.time)


class LocalCdpClient:
    """MCP 进程内唯一的 CDP 连接，统一管理请求、事件与重连。"""

    def __init__(self, *, max_events: int = 1000, disconnect_grace_seconds: float = 1.2) -> None:
        """初始化事件缓存、pending Future 表与重连参数。"""
        self.max_events = int(max_events)
        self.disconnect_grace_seconds = max(0.0, float(disconnect_grace_seconds))
        self.ws_url = "ws://127.0.0.1:62000"
        self.websocket: Any | None = None
        self.connected = False
        self.transient_disconnected = False
        # 连接代数：每次成功建连 +1。会话层用它判断「是否需要重新注册事件 / 重发 enable」，
        # 否则断线重连后 Runtime/Network/Debugger 的事件会静默停止推送。
        self.connection_id = 0
        self.next_id = 1
        self.pending: dict[int, PendingCdpCall] = {}
        self.events: deque[JsonDict] = deque(maxlen=self.max_events)
        self.listeners: dict[str, list[EventCallback]] = {}
        self.receive_task: asyncio.Task | None = None
        self.reconnect_task: asyncio.Task | None = None
        self.last_error = ""
        self.lock = asyncio.Lock()

    def assert_local_ws_url(self, ws_url: str) -> None:
        """只允许连接本机 CDP 端点，避免误连远端。"""
        parsed = urlparse(ws_url)
        if parsed.scheme not in {"ws", "wss"}:
            raise ValueError("CDP WebSocket URL 必须是 ws:// 或 wss:// 开头")
        if parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("CDP WebSocket 只允许连接 127.0.0.1 或 localhost")

    def is_connected(self) -> bool:
        """当前 WebSocket 是否处于已连接状态。"""
        return bool(self.connected and self.websocket is not None)

    async def connect(
        self,
        ws_url: str | None = None,
        *,
        timeout_ms: int = 10_000,
        force: bool = False,
    ) -> JsonDict:
        """建立 CDP WebSocket 连接并启动接收循环。

        `force=True` 会**丢弃现有连接重建**（`_close_locked(fail_pending=True)`
        会让所有堆积的 pending 调用立刻失败，从而清掉 `pendingCalls`）。

        为什么需要 `force`：链路卡死时（CDP 调用发出后收不到响应，`pendingCalls`
        持续堆积）**仅凭 `is_connected()` 判断不出问题** —— 那个标志仍是 True，
        于是旧实现会 `reused: true` 直接返回、什么都不做，恢复路径变成死胡同。
        实测踩过：只能重启整个 MCP 服务，代价是丢掉已采集的流量。
        """
        target = str(ws_url or self.ws_url or "ws://127.0.0.1:62000")
        self.assert_local_ws_url(target)
        async with self.lock:
            if not force and self.is_connected() and self.ws_url == target:
                return {"connected": True, "wsUrl": self.ws_url, "reused": True, "transient": False}
            # force 重建时必须 fail_pending=True：已关闭的连接永远不可能再回应这些调用，
            # 留着它们只会让 pendingCalls 一直不为 0（那正是「链路卡死」的表征）。
            await self._close_locked(fail_pending=force)
            self.ws_url = target
            timeout = max(0.1, float(timeout_ms) / 1000.0)
            self.websocket = await asyncio.wait_for(websockets.connect(target, max_size=None), timeout=timeout)
            self.connected = True
            self.transient_disconnected = False
            self.last_error = ""
            self.connection_id += 1
            self.receive_task = asyncio.create_task(self._receive_loop(), name="mcp-cdp-receive")
            return {"connected": True, "wsUrl": self.ws_url, "reused": False, "transient": False, "connectionId": self.connection_id}

    async def close(self) -> None:
        """主动关闭连接，并让所有 pending 调用立刻失败。"""
        async with self.lock:
            await self._close_locked(fail_pending=True)

    async def _close_locked(self, *, fail_pending: bool) -> None:
        """在持锁状态下关闭连接与接收任务。"""
        task = self.receive_task
        self.receive_task = None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        ws = self.websocket
        self.websocket = None
        self.connected = False
        if ws is not None:
            with contextlib.suppress(Exception):
                await ws.close()
        if fail_pending:
            self._fail_all_pending(RuntimeError("CDP connection closed"))

    async def send(
        self,
        method: str,
        params: JsonDict | None = None,
        *,
        timeout_ms: int = 10_000,
        session_id: str | None = None,
    ) -> JsonDict:
        """发送一条 CDP 命令并等待响应。

        `session_id` 是 flatten 模式下的子会话 id：appservice 的求值必须带上它，
        否则命令会落到浏览器层，表现为 `Uncaught` / 找不到对象。
        """
        await self.wait_until_ready(timeout_ms=timeout_ms)
        if not self.websocket:
            raise RuntimeError("CDP WebSocket 尚未连接，请先调用 connection_ops(action='connect_wmpf')")
        request_id = self.next_id
        self.next_id += 1
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.pending[request_id] = PendingCdpCall(future=future, method=method)
        payload: JsonDict = {"id": request_id, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        try:
            await self.websocket.send(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
            return await asyncio.wait_for(future, timeout=max(0.1, float(timeout_ms) / 1000.0))
        except Exception:
            self.pending.pop(request_id, None)
            raise

    async def wait_until_ready(self, *, timeout_ms: int = 10_000) -> None:
        """等待连接就绪；短暂断线时在宽限期内轮询重连结果。"""
        if self.is_connected():
            return
        if self.transient_disconnected:
            deadline = time.monotonic() + max(0.1, float(timeout_ms) / 1000.0)
            while time.monotonic() < deadline:
                if self.is_connected():
                    return
                await asyncio.sleep(0.05)
        raise RuntimeError(f"CDP WebSocket 不可用：{self.last_error or self.ws_url}")

    def on(self, method: str, callback: EventCallback) -> None:
        """注册一个 CDP 事件回调。"""
        self.listeners.setdefault(method, []).append(callback)

    def off(self, method: str, callback: EventCallback) -> None:
        """注销一个 CDP 事件回调。"""
        callbacks = self.listeners.get(method, [])
        if callback in callbacks:
            callbacks.remove(callback)

    async def _receive_loop(self) -> None:
        """持续读取 WebSocket 消息；异常退出时触发重连。"""
        try:
            async for message in self.websocket:
                await self._handle_message(message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            if self.receive_task is asyncio.current_task():
                self.connected = False
                self.transient_disconnected = True
                self.receive_task = None
                self._schedule_reconnect()

    async def _handle_message(self, message: str | bytes) -> None:
        """把一条消息分派给 pending 调用或事件监听器。"""
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        msg_id = data.get("id")
        if isinstance(msg_id, int) and msg_id in self.pending:
            pending = self.pending.pop(msg_id)
            if not pending.future.done():
                if data.get("error"):
                    pending.future.set_exception(RuntimeError(json.dumps(data.get("error"), ensure_ascii=False)))
                else:
                    pending.future.set_result(data)
        method = data.get("method")
        if isinstance(method, str):
            event = dict(data)
            event["timestamp"] = time.time()
            self.events.append(event)
            for callback in list(self.listeners.get(method, [])):
                with contextlib.suppress(Exception):
                    callback(event)

    def _schedule_reconnect(self) -> None:
        """安排一次后台重连（同一时刻只保留一个）。"""
        if self.reconnect_task is not None and not self.reconnect_task.done():
            return
        self.reconnect_task = asyncio.create_task(self._reconnect_loop(), name="mcp-cdp-reconnect")

    async def _reconnect_loop(self) -> None:
        """在宽限期内尝试重连，超时后让所有 pending 调用失败。"""
        deadline = time.monotonic() + self.disconnect_grace_seconds
        while time.monotonic() <= deadline:
            try:
                async with self.lock:
                    if self.is_connected():
                        self.transient_disconnected = False
                        return
                    self.websocket = await websockets.connect(self.ws_url, max_size=None)
                    self.connected = True
                    self.transient_disconnected = False
                    self.last_error = ""
                    self.connection_id += 1
                    self.receive_task = asyncio.create_task(self._receive_loop(), name="mcp-cdp-receive")
                    return
            except Exception as exc:
                self.last_error = str(exc)
                await asyncio.sleep(0.15)
        self.transient_disconnected = False
        self._fail_all_pending(RuntimeError(f"CDP 重连失败：{self.last_error}"))

    def _fail_all_pending(self, exc: Exception) -> None:
        """让所有等待中的调用抛出同一个异常。"""
        for pending in list(self.pending.values()):
            if not pending.future.done():
                pending.future.set_exception(exc)
        self.pending.clear()

    def status(self) -> JsonDict:
        """返回连接、重连与缓存状态快照。"""
        return {
            "connected": self.is_connected(),
            "wsUrl": self.ws_url,
            "connectionId": self.connection_id,
            "transientDisconnected": self.transient_disconnected,
            "pendingCalls": len(self.pending),
            "cachedEvents": len(self.events),
            "lastError": self.last_error,
        }
