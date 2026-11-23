---
name: wmpf-offset-adaptation
description: >-
  Extract / sync Frida hook offsets for WMPFDebugger / X Debugger after a WeChat
  (WMPF) update. Windows: `sync_latest_wmpf_offsets.py` scans the installed
  RadiumWMPF runtimes, extracts flue.dll offsets (modern or legacy layout) and
  writes addresses.{ver}.json into WMPFDebugger/frida/config and
  e0e1-wx/tools/config/win. macOS: WeChatAppEx Framework via
  extract_macos_offsets.py (+ resign-wechatappex.sh). Use for version 404,
  偏移适配/同步, 微信更新后偏移失效, WMPF / macOS WeChat adaptation,
  SIP/codesign inject issues, 布局判定 (modern vs legacy).
---

# WMPF / macOS 偏移适配

按平台分流。**不要**把 Windows `addresses.{int}.json` 和 macOS `macos/addresses.{x.y.z.w}.json` 混用；字段集合与指针链长度都不同。

| 平台 | 模块 | 配置路径 | 版本号形态 |
|------|------|----------|------------|
| **Windows** | `flue.dll`（WMPF ≥ 13331） | `nebula-tauri/frida/config/addresses.{version}.json` | 整数，如 `25047` |
| **macOS** | `WeChatAppEx Framework`（ARM64） | `nebula-tauri/frida/config/macos/addresses.{version}.json` | 字符串，如 `4.1.11.80` |

Hook 脚本：Windows → `frida/hook.js`；macOS → `frida/hook-macos.js`（源自 WMPFDebugger-arm）。

---

# A. Windows（flue.dll）

为 `addresses.{version}.json` 生成偏移。ImageBase 通常为 `0x180000000`；写入值为 **RVA**。

## A.0 一键同步（本项目的推荐入口）

微信更新后，在项目根目录执行 `04-自动更新.bat`（或直接跑脚本）：

```bash
python 偏移提取工具/sync_latest_wmpf_offsets.py
python 偏移提取工具/sync_latest_wmpf_offsets.py --force    # 覆盖已存在配置
python 偏移提取工具/sync_latest_wmpf_offsets.py -v         # 打印检测中间量
python 偏移提取工具/sync_latest_wmpf_offsets.py --all      # 为所有已安装版本各生成一份
```

它会自动：扫描本机 `RadiumWMPF\<版本>\extracted\runtime\flue.dll` → 取最新版本 →
**判定 modern / legacy 布局并提取偏移** → 同时写入两处配置目录：

1. `WMPFDebugger/frida/config/addresses.<版本>.json`
2. `e0e1-wx/tools/config/win/addresses.<版本>.json`

微信**不用关闭**（只读打开 flue.dll）。两处内容必须一致，`03-检测依赖.bat` 会校验这一点。

## A.0.1 先判定布局：modern 还是 legacy（**关键**）

flue.dll 有两套结构，JSON 字段不同，**写错会让 hook 崩溃**：

| 布局 | 判定特征（字符串锚点，全中即 modern） | JSON 结构 |
|------|----------------------------------------|-----------|
| **legacy**（约 ≤ 25xxx 早期） | — | `LoadStartHookOffset` + `CDPFilterHookOffset` + `SceneOffsets`(6) |
| **modern**（25xxx 中后期起，如 25707 / 25715） | `devtools_message_filter_applet_webview.cc`、`CastToJson`、`devtools_message_filter.cc`、` request.url=`、`create webview devtools failed.` | 再加 `CastToJsonHookOffset` + `MiniAppConfigStructOffsets` |

判定由 `sync_latest_wmpf_offsets.py` 自动完成（内部调用
`extract_wmpf_offsets_modern.py`，即上游 WMPFDebugger `frida/autodetect/win32.js`
的离线静态移植：同一套字符串锚点 + 寄存器回溯数据流 + 内部一致性断言）。

> **踩坑**：对 modern 版本用只认 legacy 的 `extract_wmpf_offsets.py`，会输出一个
> **格式合法但内容错误**的 `SceneOffsets`，hook 会走 legacy 分支并崩溃。
> 所以本项目已把 sync 脚本的默认引擎换成 modern 检测器。

modern 输出示例（25707 实测）：

```json
{
    "Version": 25707,
    "LoadStartHookOffset": "0x2d45bd0",
    "CDPFilterHookOffset": "0x381c6f0",
    "CastToJsonHookOffset": "0x9ec7d70",
    "MiniAppConfigStructOffsets": {
        "LaunchConfigOffsets": [64, 1568, 8],
        "RemoteDebugConfigOffsets": [1504, 16],
        "SceneOffset": 456,
        "WebSocketURLStringOffset": 616,
        "RemoteDebugModeOffset": 724
    }
}
```

结构稳定期内 `MiniAppConfigStructOffsets` 跨版本相同（25707 与 25715 完全一致），
可用来交叉验证结果是否合理。

## 快速流程（手动分步）

1. **定位 flue.dll**
   ```
   %APPDATA%\Tencent\xwechat\xplugin\Plugins\RadiumWMPF\{version}\extracted\runtime\flue.dll
   ```
2. **优先跑自动化脚本**（无需 IDA）：
   ```bash
   # modern 布局（自动判定，推荐）
   python extract_wmpf_offsets_modern.py --version 25707 -v
   python extract_wmpf_offsets_modern.py --version 25707 --write --config-dir path/to/frida/config

   # legacy 布局（老版本）
   python extract_wmpf_offsets.py --version 25047 --dll "C:\...\flue.dll"
   python extract_wmpf_offsets.py --version 25047 --write --config-dir path/to/frida/config
   ```
3. **验证**：重启调试器 → 等 `script loaded` → 再开小程序 → DevTools 连 `ws://127.0.0.1:62000`

## 输出格式

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x........",
    "CDPFilterHookOffset": "0x........",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

## 三项偏移含义

| 字段 | hook.js 行为 | 定位要点 |
|------|-------------|----------|
| `CDPFilterHookOffset` | `patchCDPFilter` 挂在过滤器子函数 | 搜 `SendToClientFilter` → 引用它的 `.pdata` 函数 → **该函数第一条 `E8` call** 的目标 |
| `LoadStartHookOffset` | `patchOnLoadStart` 挂在 `AppletIndexContainer::OnLoadStart` 入口（`rcx`=this，`dl`=bool） | 搜同时引用 `applet_index_container.cc` 与 `AppletIndexContainer::OnLoadStart(bool` 的 `.pdata` 函数入口 |
| `SceneOffsets` | `hookOnLoadScene` **六段**指针链后改 scene 为 1101 | 从 OnLoadStart 尾部 `call` 跟入子函数，找 `cmp dword ptr [reg+0x1C8], 0x44D`（1101）反推链 |

```
p1  = read(this + [0])
p2  = read(p1 + [1])
p3  = read(p2 + [2])
p4  = read(p3 + [3])
p5  = read(p4 + [4])
scene_addr = p5 + [5]   // 末项是字段偏移，不再 readPointer
```

## 方法选择

| 方法 | 何时用 |
|------|--------|
| **脚本 + .pdata**（推荐） | 默认；不依赖 IDA GUI |
| **IDA + idalib-mcp** | 脚本失败或需人工确认 |
| **手工** | 对照上游 `ADAPTATION.md` |

## Windows 常见陷阱

1. 勿 hook 通用 `OnLoadStart` 日志桩（`music_player_window.cc` 等）——要 `applet_index_container.cc`。
2. 勿把字符串 helper 当成 CDP —— CDP 是 SendToClientFilter **父函数首个 `E8`**。
3. `SceneOffsets` 不能照搬旧版本（邻近版本仅作趋势参考）。
4. plain `OnLoadStart` 有 5+ xref，多数非 applet。

## Windows 参考（25047）

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x29EF320",
    "CDPFilterHookOffset": "0x3859AE0",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

## Windows 失败排查

| 现象 | 处理 |
|------|------|
| `version config not found: <N>` | 缺该版本配置；跑 `04-自动更新.bat`（sync 脚本会按布局生成） |
| `error in find wmpf version` | 版本探测找不到 `RadiumWMPF\<版本>\...\flue.dll`。已修：探测改为多基目录（APPDATA / LOCALAPPDATA 兄弟目录 / USERPROFILE / os.homedir()），并支持 `--wmpf-version <n>` 强制指定 |
| 一加载小程序就崩 / `ReferenceError` | **布局判错**：modern 版本喂了 legacy JSON。用 sync 脚本重新生成 |
| 注入无 `script loaded` | 偏移错误；重跑脚本或 IDA 复核 |
| `unable to intercept` | CET/地址错；核对 `.pdata` 入口 |
| scene 不生效 | legacy：重算六段 `SceneOffsets`；modern：重算 `MiniAppConfigStructOffsets` |
| 两处配置不一致 | 跑 `04-自动更新.bat --force`（`03-检测依赖.bat` 会校验一致性） |
| 小程序没回连调试端口 | 检查 `ws://localhost:9421` 是否被占用、modern 布局的 `WebSocketURLStringOffset` 是否正确 |

细节见 [reference.md](reference.md)。

---

# B. macOS（WeChatAppEx Framework）

为 `macos/addresses.{WeChatBundleVersion}.json` 生成 **五项**（比 Windows 多 `SceneHookOffset`、`ResourceCachePolicyHookOffset`）。值为相对 Framework 模块基址的偏移（RVA）；IDA imagebase 常为 `0`，此时函数入口即偏移。

方法对齐 `WMPFDebugger-arm` / `nebula-tauri/MACOS_ADAPTATION.md`。**不能**复用其他 macOS 版本地址，也不能从 Windows flue.dll 平移。

## 快速流程

1. **优先跑脚本（prepare）**
   ```bash
   python scripts/extract_macos_offsets.py
   # → 探测 WeChatBundleVersion、lipo ARM64 thin、写出 draft JSON
   ```
2. **提取五项偏移**
   - 有 idalib：
     ```bash
     python scripts/extract_macos_offsets.py --idalib \
       --binary ./.ida-work-macos/WeChatAppEx_Framework_arm64_<ver> \
       --write --config-dir path/to/frida/config/macos
     ```
     **必须**人工复核 `SceneOffsets` 与 `CDPFilterHookOffset`（见下方定位规则 / `reference-macos.md`）。
   - 无 idalib：IDA GUI 打开 thin 二进制，按下面规则手填。
3. **注入前 resign**（与偏移无关，但现代 macOS 必做）
   ```bash
   # 恢复模式: csrutil disable → 重启
   ./scripts/macos/resign-wechatappex.sh
   ```
4. **验证**：开微信小程序 →「启动调试」见四条 `attached at` → DevTools `ws://127.0.0.1:62000`

## 输出格式

```json
{
  "Version": "4.1.11.80",
  "ModuleName": "WeChatAppEx Framework",
  "CDPFilterHookOffset": "0x........",
  "SceneHookOffset": "0x........",
  "SceneOffsets": [8, 1440, 16, 456],
  "LoadStartHookOffset": "0x........",
  "ResourceCachePolicyHookOffset": "0x........"
}
```

`SceneOffsets` 在 macOS 上通常是 **四级**（与 Windows 六级不同），语义对应 `hook-macos.js`。

## 四组偏移定位（实测流程）

### 1. LoadStartHookOffset

1. Strings 搜 `[perf] AppletIndexContainer::OnLoadStart` 或同时锚定 `applet_index_container.cc`。
2. 进引用该串的函数，取 **函数入口**。
3. Hook 行为：把 ARM64 `X1` 置为允许调试（`ptr(1)` 或 `(x1 & ~0xFF) | 1`）。

### 2. SceneHookOffset + SceneOffsets

1. 仍在 OnLoadStart 伪代码中，找接近尾部的形态：
   ```c
   if ((_DWORD)a2)
       return unk_XXXXXXXX(...);   // ← 这个 unk_ 入口 = SceneHookOffset
   ```
   即「最后一个在 `(_DWORD)a2` 条件下调用的函数」，**不是**随便挑一个尾部 `BL`。
2. 进入 SceneHook 伪代码，找与 **1101 (`0x44D`)** 比较的指针链，逐级记下成员偏移写入 `SceneOffsets`。
3. 典型形态（版本会变，以伪代码为准）：
   ```
   v = *(a1 + [0]);           // e.g. +8
   v = *(v + [1]);            // e.g. +1440（版本间常变）
   v = *(v + [2]);            // e.g. +16
   if (*(DWORD*)(v + [3]) == 1101)  // e.g. +456 → 改写为 1101
   ```
4. **勿照搬旧版第二级偏移**；只更新函数地址沿用旧链是常见翻车点。

### 3. CDPFilterHookOffset

1. Strings 搜 `SendToClientFilter`，进引用所在 **父函数**。
2. **不要** hook 带该字符串的日志/包装函数本身。
3. 在父函数里找过滤器调用与状态判断，形态类似：
   ```c
   v107 = (_DWORD *)filter_func(...);   // ← filter_func 入口 = CDPFilterHookOffset
   if (v107[2] != 6) ...
   ```
4. Hook 在返回后把 `retval+8` 的状态 `6` 改成 `0`。
5. 陷阱：自动脚本若命中短日志桩（如 `0x11a6ae4`）一律作废；以「返回指针且 `[2]`/`+8` 与 6 比较」的 callee 为准。

### 4. ResourceCachePolicyHookOffset

1. Strings 搜 `WAPCAdapterAppIndex.js`。
2. 取 **第一处有效 xref** 所在函数入口。
3. Hook 将该函数返回值改成 `0`（保底，利于 Sources）。

## macOS 地址换算

```
配置偏移 = IDA 函数入口 - IDA imagebase
运行地址 = Frida Module.findModuleByName("WeChatAppEx Framework").base + 配置偏移
```

禁止填写：字符串 EA、xref 指令 EA、ASLR 运行时绝对地址。

## macOS 分析注意（idalib / IDA）

- 优先 **ARM64 thin** 副本；fat 文件分析慢且易选错 slice。
- Cursor 可用 `idalib-mcp`（stdio）；GUI 已打开同一 IDB 时 headless 会锁库。
- 全库 `Strings()` 枚举在巨型 Framework 上极慢 → 按目标字节串定点搜 + ADRP/ADD xref，或 Hex-Rays 定点反编译。
- 激活 idalib（示例）：
  ```bash
  python "/Applications/IDA Professional 9.2.app/Contents/MacOS/idalib/python/py-activate-idalib.py" \
    -d "/Applications/IDA Professional 9.2.app/Contents/MacOS"
  ```

## macOS 进程与注入（运行侧）

- 打开小程序后才有 `WeChatAppEx`；Frida 名可能是 `WeChatAppEx` / `微信`。
- PID：argv0 必须是 `.../WeChatAppEx.app/Contents/MacOS/WeChatAppEx`（避免 shell cmdline 误匹配）。
- **根因（现代 macOS）**：Apple 签名 + Hardened Runtime → Frida 注入触发 `SIGKILL (Code Signature Invalid)`。
  - 仅 `csrutil enable --without debug` **不够**（lldb 能挂、Frida 仍会被杀）。
  - 正确流程：
    1. 恢复模式 `csrutil disable` 并重启
    2. `scripts/macos/resign-wechatappex.sh`（去掉 runtime，加 `disable-library-validation`）
    3. 开微信小程序 → 启动调试
  - 微信更新后需重新 resign。
- 详见 `nebula-tauri/MACOS_ADAPTATION.md` §0 与 `reference-macos.md`。

## macOS 参考（4.1.11.80 实测）

```json
{
  "Version": "4.1.11.80",
  "ModuleName": "WeChatAppEx Framework",
  "CDPFilterHookOffset": "0x8436B98",
  "SceneHookOffset": "0x8444BD0",
  "SceneOffsets": [8, 1440, 16, 456],
  "LoadStartHookOffset": "0x4F744C4",
  "ResourceCachePolicyHookOffset": "0x4FDC63C"
}
```

邻近配置仅作结构参考：`addresses.4.1.0.240.json`、`addresses.4.1.5.17.json`。

## macOS 失败排查

| 现象 | 处理 |
|------|------|
| 配置 404 / 未加载 macos json | 文件名必须等于 `WeChatBundleVersion`；路径在 `frida/config/macos/` |
| attach：`current user account` | SIP 过严；完整流程是 `csrutil disable` + resign（仅 `--without debug` 往往不够） |
| attach 后立刻 `SIGKILL` / Code Signature Invalid | 未 resign 或仍带 Hardened Runtime；重跑 `resign-wechatappex.sh` |
| 无 WeChatAppEx / 找不到 PID | 先开微信再开任意小程序 |
| `attached` 后立刻崩（非 codesign） | 偏移当 VA 写了、或 CDP/Scene 挂错函数 |
| scene 不生效 | 重算四级 `SceneOffsets`，确认比较常量 1101 |
| CDP 无连接 | 确认挂的是 `v[2]!=6` 那个 filter callee，不是字符串父函数 |
| 微信更新后注入又挂 | Apple 签名恢复 → 重新 resign |

## 提交前核对

- 四个函数入口均在 Framework 可执行段内。
- `Version` 与 `WeChatBundleVersion` 完全一致。
- `SceneOffsets` 为十进制；链长与 `hook-macos.js` 一致。
- 日志四条 `attached at`，小程序打开后 62000 有 CDP。
- 已 `csrutil disable` 且 WeChatAppEx 已 ad-hoc resign（无 runtime）。

---

# 附加资源

- Windows 脚本细节：[reference.md](reference.md)
- macOS 脚本/算法：[reference-macos.md](reference-macos.md)
- 脚本（本目录为扁平结构）：
  - `sync_latest_wmpf_offsets.py` — **一键同步到两处配置目录**（推荐入口）
  - `extract_wmpf_offsets_modern.py` — modern 布局离线检测（sync 的默认引擎）
  - `extract_wmpf_offsets.py` — legacy 布局
  - `extract_macos_offsets.py`、`macos/resign-wechatappex.sh` — macOS
- 项目 macOS 说明：`nebula-tauri/MACOS_ADAPTATION.md`
- 上游 macOS 参考：`WMPFDebugger-arm` 的 `ADAPTATION.md` / `frida/hook.js`
