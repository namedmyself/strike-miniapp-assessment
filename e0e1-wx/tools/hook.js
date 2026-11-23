const VERBOSE = false;
const PLATFORM = Process.platform;  // 'darwin' | 'windows'
const ARCH = Process.arch;          // 'arm64' | 'x64' | 'x86_64' | ...

// 小程序回连的调试地址。必须与 e0e1-wx 的 miniapp_debug_port 一致（默认 9421）。
// modern 布局下这个地址是配置字段，需要由 hook 写入；legacy 布局下由 WMPF 自身默认值决定。
const DEBUG_WS_URL = "ws://localhost:9421";

// ── Module Resolution ──

const getMainModule = (version) => {
    if (PLATFORM === "darwin") {
        return Process.findModuleByName("WeChatAppEx Framework");
    }
    // Windows: flue.dll for newer versions
    if (version >= 13331) {
        return Process.findModuleByName("flue.dll");
    }
    return Process.findModuleByName("WeChatAppEx.exe");
};

// ── Scene Values ──

const SCENE_WHITELIST = [
    1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074,
    1145, 1168, 1178, 1256, 1260, 1302, 1308,
];

// ── Layout helpers ──
//
// flue.dll 有两套结构，配置字段不同：
//   legacy —— SceneOffsets: [6 个数字]，末项是字段偏移
//   modern —— MiniAppConfigStructOffsets: { LaunchConfigOffsets, RemoteDebugConfigOffsets,
//              SceneOffset, WebSocketURLStringOffset, RemoteDebugModeOffset }
//             （25xxx 中后期起，例如 25707 / 25715）
// 两者的指针链语义是等价的：launch = a1 -> L[0] -> L[1] -> L[2]，
// remoteDebug = launch -> R[0] -> R[1]，scene = remoteDebug + SceneOffset。

const isModernConfig = (config) => !!config.MiniAppConfigStructOffsets;

const resolveStructOffsets = (config) =>
    isModernConfig(config) ? config.MiniAppConfigStructOffsets : config.SceneOffsets;

const resolvePointerChain = (a1, config) => {
    const offsets = resolveStructOffsets(config);
    let launchPtr;
    let remoteDebugPtr;

    if (isModernConfig(config)) {
        const launch = offsets.LaunchConfigOffsets;
        const remote = offsets.RemoteDebugConfigOffsets;
        launchPtr = a1
            .add(launch[0]).readPointer()
            .add(launch[1]).readPointer()
            .add(launch[2]).readPointer();
        remoteDebugPtr = launchPtr
            .add(remote[0]).readPointer()
            .add(remote[1]).readPointer();
    } else {
        launchPtr = a1
            .add(offsets[0]).readPointer()
            .add(offsets[1]).readPointer()
            .add(offsets[2]).readPointer();
        remoteDebugPtr = launchPtr
            .add(offsets[3]).readPointer()
            .add(offsets[4]).readPointer();
    }

    return { launchPtr, remoteDebugPtr, offsets };
};

// ── CDP Filter Patch (shared logic, platform-specific pointer access) ──

const patchCDPFilter = (base, config) => {
    // xref: SendToClientFilter / devtools_message_filter_applet_webview.cc

    // modern: 用 CastToJson 包装替换整个过滤器（与上游 hook.js 的 modern 分支一致）。
    // legacy 的「attach 后把 +8 状态从 6 改成 0」在 modern 布局上语义已变，不能复用。
    if (PLATFORM === "windows" && config.CastToJsonHookOffset) {
        const castToJsonFunc = new NativeFunction(
            base.add(config.CastToJsonHookOffset),
            "pointer",
            ["pointer", "pointer"],
        );
        const callback = new NativeCallback(function (thiz, jsonOut, cborInput) {
            castToJsonFunc(jsonOut, cborInput);
            return jsonOut;
        }, "pointer", ["pointer", "pointer", "pointer"]);
        Interceptor.replace(base.add(config.CDPFilterHookOffset), callback);
        return;
    }

    Interceptor.attach(base.add(config.CDPFilterHookOffset), {
        onEnter(args) {
            if (PLATFORM === "windows") {
                this.inputValue = args[0];
            }
        },
        onLeave(retval) {
            let target;
            if (PLATFORM === "darwin") {
                // macOS: retval points directly to the struct
                if (!retval || retval.isNull()) return;
                target = retval.add(8);
            } else {
                // Windows: dereference args[0] to get the struct pointer
                const ptr = this.inputValue.readPointer();
                if (ptr.isNull() || ptr.add(8).isNull()) return;
                target = ptr.add(8);
            }
            VERBOSE && console.log(`[patch] CDP filter v8[2]: ${target.readU32()}`);
            if (target.readU32() === 6) {
                target.writeU32(0x0);
            }
        },
    });
};

// ── Resource Cache Policy Patch (darwin only) ──

const patchResourceCachePolicy = (base, offset) => {
    // xref: WAPCAdapterAppIndex.js
    Interceptor.attach(base.add(offset), {
        onLeave(retval) {
            VERBOSE && console.log(`[patch] cache policy retval: ${retval.toInt32()} -> 0`);
            retval.replace(0x0);
        },
    });
};

// ── OnLoadStart: Darwin ──

const darwinPatchLoadStart = (base, offset) => {
    // xref: AppletIndexContainer::OnLoadStart (first match)
    // Force debug mode by setting second param to true
    Interceptor.attach(base.add(offset), {
        onEnter() {
            console.log("[hook] AppletIndexContainer::OnLoadStart onEnter");
            if (ARCH === "arm64") {
                this.context.x1 = (this.context.x1 & ~0xff) | 0x1;
            } else {
                // x64 / x86_64: System V ABI, second param = RSI
                this.context.rsi = (this.context.rsi & ~0xff) | 0x1;
            }
        },
        onLeave() {},
    });
};

const darwinPatchLoadStart2 = (base, offset, structOffset) => {
    // xref: AppletIndexContainer::OnLoadStart (last function)
    // Hijack scene value via struct pointer chain
    Interceptor.attach(base.add(offset), {
        onEnter(args) {
            try {
                const v4 = args[0].add(8).readPointer();
                if (!v4 || v4.isNull()) return;
                const q1 = v4.add(structOffset).readPointer();
                if (!q1 || q1.isNull()) return;
                const q2 = q1.add(16).readPointer();
                if (!q2 || q2.isNull()) return;
                const scenePtr = q2.add(488);
                const scene = scenePtr.readInt();
                console.log(`[hook] scene: ${scene}`);
                if (SCENE_WHITELIST.includes(scene)) {
                    console.log("[hook] hook scene -> 1101");
                    scenePtr.writeInt(1101);
                }
            } catch (e) {
                console.error(`[hook] onLoadStart2 error: ${e}`);
            }
        },
        onLeave() {},
    });
};

// ── OnLoadStart: Windows ──

const winHandleOnLoadStart = (a1, config) => {
    let launchPtr;
    let remoteDebugPtr;
    let scenePtr;
    let offsets;

    try {
        ({ launchPtr, remoteDebugPtr, offsets } = resolvePointerChain(a1, config));
        scenePtr = isModernConfig(config)
            ? remoteDebugPtr.add(offsets.SceneOffset)
            : remoteDebugPtr.add(offsets[5]);
    } catch (e) {
        send(`[hook] scene pointer chain failed: ${e}`);
        return;
    }

    const scene = scenePtr.readInt();
    send(`[hook] scene: ${scene}`);
    if (!SCENE_WHITELIST.includes(scene)) {
        return;
    }
    send("[hook] hook scene -> 1101");
    scenePtr.writeInt(1101);

    if (!isModernConfig(config)) {
        // legacy：scene 是唯一需要改的字段，到此为止
        return;
    }

    // modern：还要把回连地址与远程调试开关一起改掉
    try {
        const websocketUrl =
            typeof config.DebugWebSocketUrl === "string" && config.DebugWebSocketUrl
                ? config.DebugWebSocketUrl
                : DEBUG_WS_URL;
        const urlPtr = launchPtr.add(offsets.WebSocketURLStringOffset);
        // std::string 短字符串优化：marker 为负表示已走长表示（堆指针 + 长度）
        const marker = urlPtr.add(23).readS8();
        if (marker < 0) {
            urlPtr.readPointer().writeUtf8String(websocketUrl);
            urlPtr.add(8).writeU64(websocketUrl.length);
        } else {
            urlPtr.writeUtf8String(websocketUrl);
            urlPtr.add(23).writeU8(websocketUrl.length);
        }
        send(`[hook] websocket url -> ${websocketUrl}`);

        const modePtr = remoteDebugPtr.add(offsets.RemoteDebugModeOffset);
        send(`[hook] remote debug mode: ${modePtr.readInt()} -> 1`);
        modePtr.writeInt(1);
    } catch (e) {
        send(`[hook] modern struct patch failed: ${e}`);
    }
};

const winPatchLoadStart = (base, config) => {
    // xref: AppletIndexContainer::OnLoadStart
    // Windows combines debug flag + scene hijack in one hook
    Interceptor.attach(base.add(config.LoadStartHookOffset), {
        onEnter() {
            // Microsoft x64 ABI: second param = RDX, force debug mode
            if ((this.context.rdx & 0xff) !== 1) {
                this.context.rdx = (this.context.rdx & ~0xff) | 0x1;
            }
            winHandleOnLoadStart(this.context.rcx, config);
        },
        onLeave() {},
    });
};

// ── Config Parsing ──

const parseConfig = () => {
    const rawConfig = `@@CONFIG@@`;
    if (rawConfig.includes("@@")) {
        // Fallback test config
        if (PLATFORM === "darwin") {
            return {
                Version: 17078,
                Arch: {
                    arm64: {
                        LoadStartHookOffset: "0x4F0620C",
                        LoadStartHookOffset2: "0x81CEC08",
                        CDPFilterHookOffset: "0x81BFC04",
                        ResourceCachePolicyHookOffset: "0x4F699E8",
                        StructOffset: 1376,
                    },
                },
            };
        }
        return {
            Version: 18955,
            LoadStartHookOffset: "0x25B52C0",
            CDPFilterHookOffset: "0x30248B0",
            SceneOffsets: [1408, 1344, 488],
        };
    }
    return JSON.parse(rawConfig);
};

const resolveArchConfig = (config) => {
    // Windows configs have offsets at top level — return directly
    if (config && config.LoadStartHookOffset) {
        return config;
    }
    // Mac configs nest under Arch.{arm64|x64}
    const table = config?.Arch || config?.arch;
    if (!table) return null;

    const candidates = [ARCH];
    if (ARCH === "x86_64") candidates.push("x64");
    if (ARCH === "amd64") candidates.push("x64");

    for (const key of candidates) {
        const picked = table[key];
        if (picked && picked.LoadStartHookOffset) {
            return { ...picked, Version: config.Version, __arch: key };
        }
    }
    return null;
};

// ── Main ──

const main = () => {
    const rawConfig = parseConfig();
    const config = resolveArchConfig(rawConfig);

    if (!config) {
        console.error(`[frida] no config for platform=${PLATFORM} arch=${ARCH}`);
        return;
    }

    const mainModule = getMainModule(config.Version);
    if (!mainModule) {
        const expected = PLATFORM === "darwin" ? "WeChatAppEx Framework" : "flue.dll / WeChatAppEx.exe";
        console.error(`[frida] module not found: ${expected}`);
        return;
    }

    const layout = PLATFORM === "windows"
        ? (isModernConfig(config) ? "modern" : "legacy")
        : "darwin";
    console.log(`[frida] version=${config.Version} platform=${PLATFORM} arch=${config.__arch || ARCH} layout=${layout}`);
    console.log(`[frida] module base: ${mainModule.base}`);

    const base = mainModule.base;

    // CDP filter patch — both platforms
    patchCDPFilter(base, config);

    if (PLATFORM === "darwin") {
        darwinPatchLoadStart(base, config.LoadStartHookOffset);
        darwinPatchLoadStart2(base, config.LoadStartHookOffset2, config.StructOffset);
        if (config.ResourceCachePolicyHookOffset) {
            patchResourceCachePolicy(base, config.ResourceCachePolicyHookOffset);
        }
    } else {
        winPatchLoadStart(base, config);
    }
};

main();
