# WMPF 偏移提取 — 技术参考（Windows）

macOS 见 [reference-macos.md](reference-macos.md)。

## 依赖

```bash
pip install pefile capstone
```

## 布局判定（先做这一步）

| 锚点字符串 | legacy | modern |
|------------|--------|--------|
| `devtools_message_filter_applet_webview.cc` | 无 | 有 |
| `CastToJson` | 无 | 有 |
| `devtools_message_filter.cc` | 无 | 有 |
| ` request.url=` | 无 | 有 |
| `create webview devtools failed.` | 无 | 有 |

5 个全中 → modern。`sync_latest_wmpf_offsets.py` 会自动判定，不用手工选。

## 一键同步脚本（`sync_latest_wmpf_offsets.py`）

把「找 DLL → 判布局 → 提取 → 写两处配置」串成一条命令。

**1. 定位已安装的 WMPF 运行时**

依次探测下列基目录，取其中名字全为数字、且存在 `extracted/runtime/flue.dll` 的子目录：

| 来源 | 说明 |
|------|------|
| `$WMPF_ROOT` | 直接覆盖 |
| `%APPDATA%` | 首选 |
| `%LOCALAPPDATA%\..\Roaming` | 兜底（注意是 Local 的**兄弟**目录） |
| `%USERPROFILE%\AppData\Roaming`、`Path.home()/AppData/Roaming` | 兜底 |
| `$XWECHAT_HOME` | 兜底 |

> `APPDATA` 在部分 shell / 服务环境里**不存在**，所以必须有后面几级兜底 ——
> 这正是内置 `WMPFDebugger` 原先报 `error in find wmpf version` 的原因
> （它当时只用 `process.env.APPDATA` 一个来源）。

默认取版本号最大的一个；`--all` 处理全部；`--version N` 指定；`--dll` 直接给文件。

**2. 提取**：调用 `extract_wmpf_offsets_modern.py`（自动判 modern / legacy，带内部一致性断言）。

**3. 写入两处**（内容必须一致，`03-检测依赖.bat` 会校验）：

1. `WMPFDebugger/frida/config/addresses.<版本>.json`
2. `e0e1-wx/tools/config/win/addresses.<版本>.json`

已存在时默认跳过，`--force` 覆盖。退出码 `0` 成功 / `1` 有失败项。

## modern 布局算法（`extract_wmpf_offsets_modern.py`）

上游 WMPFDebugger `frida/autodetect/win32.js` 的离线静态移植，同一套算法：

1. **函数表**：解析 `.pdata`（每项 12 字节 `BeginRVA, EndRVA, UnwindRVA`），同 `BeginRVA` 取最宽的 `EndRVA`。
2. **字符串锚点**：非 `.text`/`.pdata` 节里扫 ASCII。`exact` 类 range = `[rva, rva]`；
   `containing` 类向前回溯到 NUL，range = `[串首, rva+len-1]`（MSVC 字符串池会把短串并进长串后缀）。
3. **xref → 所属函数**：扫可执行节 `48 8D` / `4C 8D`，要求 `(byte[+2] & 0xC7) == 0x05`（RIP 相对），
   `target = insn_rva + 7 + s32[+3]`；落在 range 内则记录包含该指令的 `.pdata` 函数入口。
4. **定位四个函数**（交集且必须唯一）：
   - `OnLoadStart` = `xref(loadFile) ∩ xref(loadName)`
   - `DevToolsWebSocketServer::Start` = `xref(startUrl) ∩ xref(startFailure)`
   - `SendToClientFilter` = `xref(filterName) ∩ xref(filterFile)`
   - `CastToJson` = `xref(castName) ∩ xref(castFile)`
5. **寄存器回溯数据流**：从目标指令往前找最后一条写该寄存器的指令，只认 `mov/movabs/lea/add/sub`，
   遇 `call` 且寄存器易失即放弃；结果要么是「第 N 个参数」，要么是 `load(base, disp)` 链。**失败即 fail closed。**
6. **取 guard**：函数内找 `cmp [reg+disp], 1101` 与 `cmp [reg+disp], 1`，base 表达式相同且可回溯到 `arg0`
   → 得 `rootOffsets`（链）、`sceneOffset`、`modeOffset`。
7. **交叉断言**（不通过就报错，不要绕过）：`serverChain` 长 2、两处 guard 链长 3、
   `serverChain[0] == loadGuard.rootOffsets[0]`、`loadGuard.rootOffsets[1:] == startGuard.rootOffsets[1:]`、
   `sceneOffset` 与 `modeOffset` 一致。
8. **websocket URL 偏移**：在 `Start` 里找 `cmp byte [X+disp], 0`（SSO marker 测试），
   `stringOffset = disp - 23`；要求 `*(arg0+rootOffsets[0])` 上确实存在 `stringOffset` 与 `stringOffset+8` 两个访问。
9. **CastToJson ABI 校验**：其前缀必须读 `arg1+0` 与 `arg1+8`；且 `SendToClientFilter` 必须直接 `call` 到它。

输出映射：

```
LoadStartHookOffset      = OnLoadStart.begin
CDPFilterHookOffset      = SendToClientFilter.begin
CastToJsonHookOffset     = CastToJson.begin
LaunchConfigOffsets      = serverChain + [startGuard.rootOffsets[0]]
RemoteDebugConfigOffsets = startGuard.rootOffsets[1:]
SceneOffset              = startGuard.sceneOffset
RemoteDebugModeOffset    = startGuard.modeOffset
WebSocketURLStringOffset = 第 8 步结果
```

modern 邻近版本参考（函数地址逐版本漂移，结构字段稳定期内完全相同）：

| 版本 | LoadStart | CDPFilter | CastToJson | LaunchConfig | RemoteDebug | Scene | WS | Mode |
|------|-----------|-----------|------------|--------------|-------------|-------|----|------|
| 25707 | `0x2d45bd0` | `0x381c6f0` | `0x9ec7d70` | `[64,1568,8]` | `[1504,16]` | 456 | 616 | 724 |
| 25715 | `0x2D456B0` | `0x381C1D0` | `0x9EC7870` | `[64,1568,8]` | `[1504,16]` | 456 | 616 | 724 |

## .pdata 解析

x64 Windows DLL 的 `RUNTIME_FUNCTION` 表（`.pdata`）每项 12 字节：`BeginRVA, EndRVA, UnwindRVA`。

用 `BeginRVA <= addr < EndRVA` 判定函数边界，比扫描 `0xCC` 填充可靠得多。

## CDPFilterHookOffset 算法

1. 在文件内搜 ASCII `SendToClientFilter`，得 `str_rva`
2. 在可执行节扫描 `48/4C 8D`（`lea reg, [rip+disp]`），`insn+7+disp == str_rva` 得 `xref_rva`
3. 用 `.pdata` 找包含 `xref_rva` 的函数 `[func_start, func_end)`
4. 从 `func_start` 起扫描，第一条操作码为 `0xE8` 的 `call rel32` → `target_rva = insn+5+rel32`
5. `CDPFilterHookOffset = hex(target_rva)`

25047 实例：xref `0x368CF4A` → 父函数 `0x368CD00` → 首 call `0x3859AE0`。

## LoadStartHookOffset 算法

1. 遍历 `.pdata` 函数（建议过滤 `size < 0x8000`）
2. 对函数体扫描 `lea [rip+disp]`，读取目标字符串
3. 选中同时满足：
   - 含 `applet_index_container.cc`
   - 含 `AppletIndexContainer::OnLoadStart(bool`
4. `LoadStartHookOffset = func_start`

25047 实例：`0x29EF320`（含 Chromium perf 日志序言，入口处 `rcx`/ `edx` 仍正确）。

## SceneOffsets 算法

1. 在 OnLoadStart 函数反汇编中找 `mov rax,[rsi+40h]` 与后续 `call`
2. 典型模式：
   ```asm
   mov rax, [rsi+40h]
   mov rcx, [rax+5D0h]    ; → SceneOffsets[1]，版本间可能变
   ...
   call sub_352C550
   ```
3. 进入 callee，找链：
   ```asm
   mov rax, [rcx+8]
   mov rcx, [rax+590h]
   mov rcx, [rcx+10h]
   cmp dword ptr [rcx+1C8h], 44Dh
   ```
4. 映射为 `[64, 1488, 8, 1424, 16, 456]`（`0x44D = 1101` 为 hook 目标 scene）

## hook.js 指针链对照

```javascript
a1.add(sceneOffsets[0]).readPointer()   // +64
  .add(sceneOffsets[1]).readPointer()   // +1488
  .add(sceneOffsets[2]).readPointer()   // +8
  .add(sceneOffsets[3]).readPointer()   // +1424
  .add(sceneOffsets[4]).readPointer()   // +16
  .add(sceneOffsets[5])                 // +456 field offset
```

## 邻近版本 SceneOffsets 趋势

| 版本 | SceneOffsets |
|------|----------------|
| 19841 | [64, 1408, 8, 1344, 16, 456] |
| 19977 / 20005 | [64, 1480, 8, 1416, 16, 456] |
| 25047 | [64, 1488, 8, 1424, 16, 456] |

仅作校验参考，**必须以目标 DLL 反汇编为准**。

## IDA MCP 工具链

配置 `~/.cursor/mcp.json`：

```json
"idalib-mcp": {
  "command": "C:\\Python\\Python312\\python.exe",
  "args": ["-m", "ida_pro_mcp.idalib_supervisor", "--stdio"]
}
```

常用调用顺序：`idb_open` → `find_regex` / `xrefs_to` → `decompile` → `disasm`

GUI 模式（IDA 内已开 flue.dll）：`idb_open(..., mode="prefer_gui")` + IDA 菜单 **Edit → Plugins → MCP**
