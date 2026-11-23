# macOS WeChatAppEx Framework 偏移 — 技术参考

目标模块：`WeChatAppEx Framework`（ARM64）。写入值为 **相对 imagebase 的偏移**（不是 VA、不是 ASLR 运行时地址）。

## 依赖

| 步骤 | 依赖 |
|------|------|
| prepare（默认） | macOS 本机 `/usr/bin/lipo`、`plutil`；无需 Python 第三方库 |
| idalib 半自动 | IDA Pro + Hex-Rays + idalib Python |
| 注入运行 | `csrutil disable` + `scripts/macos/resign-wechatappex.sh` |

激活 idalib（路径按本机 IDA 版本改）：

```bash
python "/Applications/IDA Professional 9.2.app/Contents/MacOS/idalib/python/py-activate-idalib.py" \
  -d "/Applications/IDA Professional 9.2.app/Contents/MacOS"
```

## 脚本用法

```bash
# 1) 探测版本 + lipo ARM64 + 写出 draft JSON
python scripts/extract_macos_offsets.py
python scripts/extract_macos_offsets.py --prepare-only --work ./.ida-work-macos

# 2) 有 idalib 时半自动提取（务必人工复核 SceneOffsets / CDP）
python scripts/extract_macos_offsets.py --idalib \
  --binary ./.ida-work-macos/WeChatAppEx_Framework_arm64_4.1.11.80 \
  --write --config-dir path/to/nebula-tauri/frida/config/macos
```

产出文件名：`addresses.<WeChatBundleVersion>.json`。

## 五项偏移定位

### LoadStartHookOffset

1. 搜 `[perf] AppletIndexContainer::OnLoadStart` 或 `applet_index_container.cc`
2. 取引用所在函数 **入口**
3. Hook：把 `X1` 置为允许调试

### SceneHookOffset + SceneOffsets

1. 在 OnLoadStart 伪代码尾部找：
   ```c
   if ((_DWORD)a2)
       return unk_XXXXXXXX(...);  // ← SceneHookOffset
   ```
2. 进入 SceneHook，找与 **1101 (`0x44D`)** 比较的四级指针链 → `SceneOffsets`（十进制）
3. 典型（4.1.11.80）：`[8, 1440, 16, 456]` — **第二级常变，禁止照搬旧版**

### CDPFilterHookOffset

1. 搜 `SendToClientFilter` → 进 **父函数**
2. 找 `filter_func(...); if (v[2] != 6)` 的 **callee 入口**
3. 不要 hook 带字符串的日志桩

### ResourceCachePolicyHookOffset

1. 搜 `WAPCAdapterAppIndex.js`
2. 第一处有效 xref 所在函数入口
3. Hook 返回值改为 `0`

## 地址换算

```
配置偏移 = IDA 函数入口 - IDA imagebase
运行地址 = Module.findModuleByName("WeChatAppEx Framework").base + 配置偏移
```

## hook-macos.js 指针链对照

```javascript
a1.add(sceneOffsets[0]).readPointer()   // e.g. +8
  .add(sceneOffsets[1]).readPointer()   // e.g. +1440
  .add(sceneOffsets[2]).readPointer()   // e.g. +16
  .add(sceneOffsets[3])                 // e.g. +456 field → write 1101
```

四级链（与 Windows 六级不同）。

## 邻近版本参考（仅结构）

| 版本 | LoadStart | SceneHook | SceneOffsets | CDP | Resource |
|------|-----------|-----------|--------------|-----|----------|
| 4.1.0.240 | 见 examples | | 四级 | | |
| 4.1.5.17 | 见 examples | | 四级 | | |
| 4.1.11.80 | `0x4F744C4` | `0x8444BD0` | `[8,1440,16,456]` | `0x8436B98` | `0x4FDC63C` |

## 注入前提（与偏移无关，但适配必做）

现代 macOS 上 Apple 签名 + Hardened Runtime 会在 Frida 注入时 `SIGKILL (Code Signature Invalid)`。

1. 恢复模式：`csrutil disable` → 重启  
2. `scripts/macos/resign-wechatappex.sh`（去掉 runtime，加 `disable-library-validation`）  
3. 开微信小程序 → 启动调试  

仅 `csrutil enable --without debug` **不够**（lldb 能挂、Frida 仍会被杀）。微信更新后需重新 resign。

## IDA / idalib 注意

- 优先 ARM64 thin；fat 慢且易选错 slice
- 巨型 Framework 上全库 `Strings()` 很慢 → 定点字节串 + xref
- GUI 已打开同一 IDB 时 headless idalib 会锁库
