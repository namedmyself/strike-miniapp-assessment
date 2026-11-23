#!/usr/bin/env node
/**
 * 离线验证 nav_inject.js 的 runWxMethod 返回值语义（P1-3）。
 *
 * 背景：`success` 回调里**同步**求值 `currentRoute(frame)`，而工具自己的文档就承认
 * `getCurrentPages()` 有 4-7s 读取延迟 —— 所以这里拿到的必然是**跳转前**的路由。
 * 修复后新增 `routeBefore` 字段并加 `note` 说明，同时保留 `currentRoute` 保证向后兼容。
 *
 * 本脚本用 vm 在最小 mock 环境里跑**真实脚本**（不复制逻辑），验证：
 *   1. success 分支返回 routeBefore；
 *   2. routeBefore === currentRoute（向后兼容）；
 *   3. routeBefore 是【跳转前】的路由，而不是跳转后的；
 *   4. 返回带 note，且 note 点明语义并指向 wait_route_stable；
 *   5. fail 分支语义不变（仍返回 currentRoute，且不出现 routeBefore）；
 *   6. 重复注入幂等（不覆盖已有 __routeNavigator）。
 *
 * 用法：node scripts/verify_nav_inject.js
 */

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SCRIPT_PATH = path.resolve(
  __dirname,
  "..",
  "e0e1-wx",
  "package",
  "applet_routes",
  "nav_inject.js"
);

let passed = 0;
let failed = 0;

function check(name, condition, detail) {
  if (condition) {
    passed += 1;
    console.log(`  [PASS] ${name}`);
  } else {
    failed += 1;
    console.log(`  [FAIL] ${name}${detail ? " -> " + detail : ""}`);
  }
}

function has(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function buildSandbox(wxConfig) {
  // 模拟真实时序：success 触发时页面栈【还没更新】—— 这正是 4-7s 延迟的体现。
  const state = { route: "pages/before/route" };

  const appFrame = {
    __wxConfig: wxConfig || { appId: "wxtestappid" },
    getCurrentPages: function () {
      return [{ route: state.route }];
    },
    wx: {
      reLaunch: function (opts) {
        setTimeout(function () {
          if (opts && typeof opts.success === "function") {
            // 关键：回调触发时 getCurrentPages() 仍是旧栈
            opts.success({});
          }
          // 页面栈真正更新发生在回调之后（模拟延迟）
          setTimeout(function () {
            state.route = "pages/after/route";
          }, 5);
        }, 0);
      },
      navigateBack: function (opts) {
        if (opts && typeof opts.fail === "function") {
          opts.fail({ errMsg: "navigateBack:fail mock" });
        }
      },
    },
    frames: [],
  };

  const win = { frames: [appFrame], parent: undefined };
  win.window = win;

  const sandbox = {
    window: win,
    console: console,
    Promise: Promise,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    Error: Error,
    TypeError: TypeError,
    JSON: JSON,
    Object: Object,
    Array: Array,
    String: String,
    Number: Number,
    Boolean: Boolean,
    Date: Date,
    Math: Math,
    RegExp: RegExp,
  };
  sandbox.globalThis = sandbox;
  return { sandbox, state };
}

function finish() {
  console.log("\n==============================================================");
  console.log(`=== 结果：${passed} passed / ${failed} failed ===`);
  console.log("==============================================================");
  process.exit(failed === 0 ? 0 : 1);
}

async function main() {
  console.log("=== nav_inject.js runWxMethod 返回值语义（P1-3）===\n");

  if (!fs.existsSync(SCRIPT_PATH)) {
    console.log(`找不到脚本：${SCRIPT_PATH}`);
    process.exit(1);
  }

  const code = fs.readFileSync(SCRIPT_PATH, "utf8");
  const { sandbox } = buildSandbox();
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: "nav_inject.js" });

  const nav = sandbox.window.__routeNavigator;
  check("注入后暴露 window.__routeNavigator", !!nav, "window.__routeNavigator 未定义");
  if (!nav) {
    finish();
  }

  // ---------- [1] success 分支 ----------
  console.log("\n[1] success 分支（reLaunchJson）");
  const raw = await nav.reLaunchJson("pages/after/route");
  let result;
  try {
    result = JSON.parse(raw);
  } catch (err) {
    check("返回体是合法 JSON", false, String(err));
    finish();
  }
  check("ok === true", result.ok === true, `实际 ${JSON.stringify(result.ok)}`);
  check("返回含 routeBefore 字段", has(result, "routeBefore"), JSON.stringify(result));
  check("返回仍含 currentRoute（向后兼容）", has(result, "currentRoute"));
  check(
    "routeBefore 是【跳转前】的路由",
    result.routeBefore === "pages/before/route",
    `实际 ${JSON.stringify(result.routeBefore)}`
  );
  check(
    "routeBefore === currentRoute（两字段同值）",
    result.routeBefore === result.currentRoute,
    `${JSON.stringify(result.routeBefore)} vs ${JSON.stringify(result.currentRoute)}`
  );
  check(
    "routeBefore 不是跳转后的路由（没把旧值当新值卖）",
    result.routeBefore !== "pages/after/route"
  );
  check(
    "返回带 note 说明",
    typeof result.note === "string" && result.note.length > 0,
    JSON.stringify(result.note)
  );
  check(
    "note 点明「跳转前」",
    typeof result.note === "string" && result.note.indexOf("跳转前") >= 0,
    JSON.stringify(result.note)
  );
  check(
    "note 指向 wait_route_stable",
    typeof result.note === "string" && result.note.indexOf("wait_route_stable") >= 0
  );

  // ---------- [2] fail 分支 ----------
  console.log("\n[2] fail 分支（navigateBackJson，语义应保持不变）");
  const failResult = JSON.parse(await nav.navigateBackJson("pages/x", 1));
  check("ok === false", failResult.ok === false, `实际 ${JSON.stringify(failResult.ok)}`);
  check("fail 分支仍返回 currentRoute", has(failResult, "currentRoute"));
  check("fail 分支不出现 routeBefore（语义未变）", !has(failResult, "routeBefore"));

  // ---------- [4] tabBar pagePath 带 .html（实战发现）----------
  console.log("\n[4] tabBar pagePath 带 .html 后缀");
  console.log("    实测：某小程序 __wxConfig.tabBar.list[].pagePath 是 'pages/loading/zjcd.html'，");
  console.log("    而 config.pages 里的路由不带后缀 → isTabBar 恒为 false、switchTab 报 page not found。");

  const cfgSandbox = buildSandbox({
    appId: "wxtestappid",
    pages: ["pages/loading/loading", "pages/loading/zjcd", "pages/main/xcztabbar"],
    tabBar: {
      list: [
        { pagePath: "pages/loading/loading.html" },
        { pagePath: "/pages/loading/zjcd.html" },
      ],
    },
  });
  vm.createContext(cfgSandbox.sandbox);
  vm.runInContext(code, cfgSandbox.sandbox, { filename: "nav_inject.js" });
  const navCfg = cfgSandbox.sandbox.window.__routeNavigator;

  const cfg = JSON.parse(await navCfg.fetchConfigJson());
  const tb = cfg.tabBarPages || [];
  const byRoute = {};
  (cfg.pages || []).forEach(function (p) {
    byRoute[p.route] = p;
  });

  check(
    "tabBarPages 已去掉 .html",
    tb.length === 2 && tb.every(function (r) { return r.indexOf(".html") < 0; }),
    JSON.stringify(tb)
  );
  check(
    "前导斜杠也被去掉（'/pages/...' → 'pages/...'）",
    tb.indexOf("pages/loading/zjcd") >= 0,
    JSON.stringify(tb)
  );
  check(
    "isTabBar 对 tabBar 页为 true（修复前恒为 false）",
    byRoute["pages/loading/loading"] && byRoute["pages/loading/loading"].isTabBar === true,
    JSON.stringify(byRoute["pages/loading/loading"])
  );
  check(
    "isTabBar 对非 tabBar 页为 false",
    byRoute["pages/main/xcztabbar"] && byRoute["pages/main/xcztabbar"].isTabBar === false,
    JSON.stringify(byRoute["pages/main/xcztabbar"])
  );
  check(
    "tabBarPages 的值与 pages[].route 形态一致（可直接用于 switchTab）",
    tb.every(function (r) { return Object.prototype.hasOwnProperty.call(byRoute, r); }),
    JSON.stringify(tb)
  );

  // ---------- [5] 幂等 ----------
  console.log("\n[5] 重复注入幂等");
  const before = sandbox.window.__routeNavigator;
  vm.runInContext(code, sandbox, { filename: "nav_inject.js" });
  check("重复注入后对象引用不变", sandbox.window.__routeNavigator === before);

  finish();
}

main().catch(function (err) {
  console.error("测试自身异常：", err);
  process.exit(1);
});
