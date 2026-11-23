import { promises } from "node:fs";
import { EventEmitter } from "node:events";
import os from "node:os";
import path from "node:path";
import * as frida from "frida";
import WebSocket, { WebSocketServer } from "ws";

import { parse_cli_options, CliOptions } from "./cli";
import { create_logger, Logger } from "./logger";

const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");

class DebugMessageEmitter extends EventEmitter {}

const debugMessageEmitter = new DebugMessageEmitter();

const bufferToHexString = (buffer: ArrayBuffer) => {
    return Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
};

const debug_server = (options: CliOptions, logger: Logger) => {
    const wss = new WebSocketServer({ port: options.debugPort });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    let messageCounter = 0;

    const onMessage = (message: ArrayBuffer) => {
        logger.main_debug(
            `[miniapp] client received raw message (hex): ${bufferToHexString(message)}`,
        );
        let unwrappedData: any = null;
        try {
            const decodedData =
                messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(
                    message,
                );
            unwrappedData = codex.unwrapDebugMessageData(decodedData);
            logger.main_debug(`[miniapp] [DEBUG] decoded data:`);
            logger.main_debug(unwrappedData);
        } catch (e) {
            logger.error(`[miniapp] miniapp client err: ${e}`);
        }

        if (unwrappedData === null) {
            return;
        }

        if (unwrappedData.category === "chromeDevtoolsResult") {
            // need to proxy to CDP client
            debugMessageEmitter.emit("cdpmessage", unwrappedData.data.payload);
        }
    };

    wss.on("connection", (ws: WebSocket) => {
        logger.info("[miniapp] miniapp client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            logger.error("[miniapp] miniapp client err:", err);
        });
        ws.on("close", () => {
            logger.info("[miniapp] miniapp client disconnected");
        });
    });

    debugMessageEmitter.on("proxymessage", (message: string) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // encode CDP and send to miniapp
                    // wrapDebugMessageData(data, category, compressAlgo)
                    const rawPayload = {
                        jscontext_id: "",
                        op_id: Math.round(100 * Math.random()),
                        payload: message.toString(),
                    };
                    logger.main_debug(rawPayload);
                    const wrappedData = codex.wrapDebugMessageData(
                        rawPayload,
                        "chromeDevtools",
                        0,
                    );
                    const outData = {
                        seq: ++messageCounter,
                        category: "chromeDevtools",
                        data: wrappedData.buffer,
                        compressAlgo: 0,
                        originalSize: wrappedData.originalSize,
                    };
                    const encodedData =
                        messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode(
                            outData,
                        ).finish();
                    client.send(encodedData, { binary: true });
                }
            });
    });
};

const proxy_server = (options: CliOptions, logger: Logger) => {
    const wss = new WebSocketServer({ port: options.cdpPort });
    logger.info(
        `[server] proxy server running on ws://localhost:${options.cdpPort}`,
    );
    logger.info(
        `[server] link: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${options.cdpPort}`,
    );

    const onMessage = (message: string) => {
        debugMessageEmitter.emit("proxymessage", message);
    };

    wss.on("connection", (ws: WebSocket) => {
        logger.info("[cdp] CDP client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            logger.error("[cdp] CDP client err:", err);
        });
        ws.on("close", () => {
            logger.info("[cdp] CDP client disconnected");
        });
    });

    debugMessageEmitter.on("cdpmessage", (message: string) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // send CDP message to devtools
                    client.send(message);
                }
            });
    });
};

// Detect the local WMPF runtime version by scanning the RadiumWMPF plugin
// directory, mirroring project_doctor.py's detect_latest_wmpf():
//   %APPDATA%/Tencent/xwechat/xplugin/Plugins/RadiumWMPF/<version>/extracted/runtime/flue.dll
// The newest valid runtime wins. Never guesses from process paths — new WeChat
// builds run WeChatAppEx.exe from a version-less directory
// (...\Plugins\RadiumWMPF\WeChatAppEx.exe), so path-derived versions are
// unreliable.
// RadiumWMPF 根目录候选。APPDATA 并非总是存在（部分 shell / 服务环境会剥掉它），
// 所以同时用 LOCALAPPDATA 的兄弟目录、USERPROFILE、os.homedir() 兜底；
// WMPF_ROOT 可直接覆盖。
const radium_root_candidates = (): string[] => {
    if (process.env.WMPF_ROOT) {
        return [process.env.WMPF_ROOT];
    }
    const bases: string[] = [];
    const push = (value: string | undefined) => {
        if (value) {
            bases.push(value);
        }
    };
    push(process.env.APPDATA);
    if (process.env.LOCALAPPDATA) {
        // LOCALAPPDATA 是 ...\AppData\Local，Roaming 是它的兄弟目录
        push(path.join(process.env.LOCALAPPDATA, "..", "Roaming"));
    }
    if (process.env.USERPROFILE) {
        push(path.join(process.env.USERPROFILE, "AppData", "Roaming"));
    }
    try {
        push(path.join(os.homedir(), "AppData", "Roaming"));
    } catch {
        // homedir 不可用时忽略
    }
    const subpath = path.join(
        "Tencent",
        "xwechat",
        "xplugin",
        "Plugins",
        "RadiumWMPF",
    );
    return Array.from(new Set(bases.map((base) => path.join(base, subpath))));
};

const detect_wmpf_version_from_disk = async (): Promise<number | null> => {
    const candidates: number[] = [];
    for (const radiumRoot of radium_root_candidates()) {
        let versions: (number | null)[];
        try {
            const entries = await promises.readdir(radiumRoot, {
                withFileTypes: true,
            });
            versions = await Promise.all(
                entries
                    .filter(
                        (entry) => entry.isDirectory() && /^\d+$/.test(entry.name),
                    )
                    .map(async (entry) => {
                        const flue = path.join(
                            radiumRoot,
                            entry.name,
                            "extracted",
                            "runtime",
                            "flue.dll",
                        );
                        try {
                            await promises.access(flue);
                            return Number(entry.name);
                        } catch {
                            return null;
                        }
                    }),
            );
        } catch {
            // 该基目录不存在或不可读，试下一个
            continue;
        }
        for (const version of versions) {
            if (version !== null) {
                candidates.push(version);
            }
        }
    }
    if (candidates.length === 0) {
        return null;
    }
    return Math.max(...candidates);
};

// Legacy fallback: derive the version from the WMPF process path
// (...\RadiumWMPF\<version>\...). Only used when disk detection fails and the
// path actually contains a version-like number segment.
const detect_wmpf_version_from_path = (
    processPath: string | undefined,
): number | null => {
    if (!processPath) {
        return null;
    }
    const segments = processPath.split(/[\\/]/);
    // scan from the deepest segment upwards for a pure-number directory name
    for (let i = segments.length - 1; i >= 0; i--) {
        if (/^\d+$/.test(segments[i]) && segments[i].length >= 4) {
            return Number(segments[i]);
        }
    }
    return null;
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const frida_server = async (options: CliOptions, logger: Logger) => {
    // 主循环：注入 → 等目标脱离 → 自动重注入。
    // WMPF 进程树崩溃/重启后旧 hook 全部失效（hook 只存在于进程内存中），
    // 静默失效会让用户以为一切正常，实际小程序再也不会连调试端口。
    for (;;) {
        try {
            await inject_once(options, logger);
            logger.info(
                "[frida] target detached, waiting for a new WMPF process tree to re-inject...",
            );
        } catch (err: any) {
            logger.error("[frida]", err.message);
            logger.info(
                "[frida] injection failed, retrying in 10s (Ctrl+C to quit)",
            );
        }
        await sleep(10000);
        // WMPF 重启需要时间，先等它把进程树拉起来再尝试 attach
    }
};

const inject_once = async (options: CliOptions, logger: Logger) => {
    const localDevice = await frida.getLocalDevice();

    // 轮询等待 WeChatAppEx 进程出现（最多 60 秒）
    // 用户可以先启动 WMPFDebugger，再打开小程序
    const pollInterval = 2000;
    const pollTimeout = 60000;
    const pollStart = Date.now();

    let wmpfProcesses: frida.Process[] = [];
    while (wmpfProcesses.length === 0) {
        const allProcesses = await localDevice.enumerateProcesses({
            scope: frida.Scope.Metadata,
        });
        wmpfProcesses = allProcesses.filter(
            (process) => process.name === "WeChatAppEx.exe",
        );
        if (wmpfProcesses.length === 0) {
            if (Date.now() - pollStart >= pollTimeout) {
                throw new Error("[frida] WeChatAppEx.exe process not found (timeout after 60s)");
            }
            logger.info("[frida] waiting for WeChatAppEx.exe to appear...");
            await sleep(pollInterval);
        }
    }
    logger.info(`[frida] found ${wmpfProcesses.length} WeChatAppEx.exe processes`);

    // 重新枚举全部进程（包含 WeChatAppEx 的父进程信息）
    const allProcesses = await localDevice.enumerateProcesses({
        scope: frida.Scope.Metadata,
    });
    const wmpfPids = wmpfProcesses.map((p) =>
        p.parameters.ppid ? p.parameters.ppid : 0,
    );

    // find the parent process
    const wmpfPid = wmpfPids
        .sort(
            (a, b) =>
                wmpfPids.filter((v) => v === a).length -
                wmpfPids.filter((v) => v === b).length,
        )
        .pop();
    if (wmpfPid === undefined) {
        throw new Error("[frida] WeChatAppEx.exe process not found");
        return;
    }
    const wmpfProcess = allProcesses.filter(
        (process) => process.pid === wmpfPid,
    )[0];
    // 如果 PPID 查找失败（如 PPID 全为 0），直接用第一个 WeChatAppEx 进程
    const resolvedProcess = wmpfProcess || wmpfProcesses[0];
    if (!resolvedProcess) {
        throw new Error("[frida] WeChatAppEx.exe process not found");
    }
    const wmpfProcessPath = resolvedProcess.parameters.path as string | undefined;

    // WMPF version detection:
    //   1. primary — scan %APPDATA% RadiumWMPF runtime dirs for flue.dll
    //      (same logic as project_doctor.py's detect_latest_wmpf)
    //   2. fallback — version-like directory segment in the WMPF process path
    const detectedVersion =
        options.wmpfVersion > 0
            ? options.wmpfVersion
            : await detect_wmpf_version_from_disk();
    const wmpfVersion =
        detectedVersion ?? detect_wmpf_version_from_path(wmpfProcessPath);
    if (wmpfVersion === null) {
        throw new Error(
            "[frida] error in find wmpf version: no RadiumWMPF\\<version>\\extracted\\runtime\\flue.dll found under\n" +
                radium_root_candidates()
                    .map((root) => `    - ${root}`)
                    .join("\n") +
                `\n    process path: ${wmpfProcessPath ?? "(unknown)"}\n` +
                "    hint: 用 --wmpf-version <n> 手动指定版本，或先执行 01-sync-offsets.bat",
        );
    }
    logger.info(`[frida] Detected WMPF version: ${wmpfVersion}`);

    // attach to process
    const session = await localDevice.attach(Number(wmpfPid));

    // find hook script
    const projectRoot = path.join(
        path.dirname(
            (require.main && require.main.filename) ||
                (process.mainModule && process.mainModule.filename) ||
                process.cwd(),
        ),
        "..",
    );
    let scriptContent: string | null = null;
    try {
        scriptContent = (
            await promises.readFile(path.join(projectRoot, "frida/hook.js"))
        ).toString();
    } catch (e) {
        throw new Error("[frida] hook script not found");
        return;
    }

    let configContent: string | null = null;
    try {
        configContent = (
            await promises.readFile(
                path.join(
                    projectRoot,
                    "frida/config",
                    `addresses.${wmpfVersion}.json`,
                ),
            )
        ).toString();
        configContent = JSON.stringify(JSON.parse(configContent));
    } catch (e) {
        throw new Error(`[frida] version config not found: ${wmpfVersion}`);
    }

    if (scriptContent === null || configContent === null) {
        throw new Error("[frida] unable to find hook script");
        return;
    }

    // load script
    const script = await session.createScript(
        scriptContent.replace("@@CONFIG@@", configContent),
    );
    script.message.connect((message: frida.Message) => {
        if (message.type === "error") {
            logger.error("[frida client]", message);
            return;
        }

        logger.frida_debug("[frida client]", message.payload);
    });
    await script.load();
    logger.info(
        `[frida] script loaded, WMPF version: ${wmpfVersion}, pid: ${wmpfPid}`,
    );
    logger.info(`[frida] you can now open any miniapps`);

    // 阻塞等待目标脱离：WMPF 进程树崩溃/重启时 Frida 会发出 detached 事件，
    // 此时返回让外层循环对新进程树重新注入。
    await new Promise<void>((resolve) => {
        session.detached.connect((reason: string, crash) => {
            logger.info(
                `[frida] session detached from pid ${wmpfPid} (reason: ${reason}${
                    crash ? ", target crashed" : ""
                })`,
            );
            resolve();
        });
    });
};

const main = async () => {
    const options = parse_cli_options();
    const logger = create_logger(options);
    // 仅做 Frida 注入 —— debug/proxy server 由 e0e1-wx 接管（自带 CDP 会话管理）
    logger.info("[server] Frida-only mode (debug/proxy servers delegated to e0e1-wx)");
    // frida_server 内部循环注入并监听脱离，永不返回
    await frida_server(options, logger);
};

(async () => {
    await main();
})();
