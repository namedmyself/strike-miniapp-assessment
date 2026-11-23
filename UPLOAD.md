# GitHub 上传指引

仓库已在 `open-source-repo/` 完全准备好：342 个文件、脱敏自检全绿、本地 commit 已完成。
你只需提供 **GitHub 账号信息** 并执行 3 条命令。

---

## 你需要提供的东西（缺一不可）

1. **GitHub 账号**（能创建 public 仓库）
2. **认证方式二选一**：
   - 装了 GitHub CLI（`gh`）并已 `gh auth login`；或
   - 一个 **Personal Access Token（PAT）**：GitHub → Settings → Developer settings → Personal access tokens → Tokens(classic)，勾选 `repo` 权限
3. **仓库名**（默认建议 `strike-miniapp-assessment`）

> 我无法替你登录 GitHub，所以这一步必须你来（账号密码/token 不该经过我）。

---

## 方式 A：用 GitHub CLI（推荐）

```bash
cd open-source-repo
gh repo create strike-miniapp-assessment --public --source=. --remote=origin --push
```

一条命令完成：建仓库 + 关联 + 推送。

## 方式 B：用 HTTPS + PAT

```bash
cd open-source-repo
# 1. 在 GitHub 网页上先新建一个空仓库 strike-miniapp-assessment（不要初始化 README）
# 2. 推送（把 <TOKEN> 换成你的 PAT）：
git remote add origin https://<TOKEN>@github.com/<你的用户名>/strike-miniapp-assessment.git
git branch -M main
git push -u origin main
```

推送成功后，删掉 remote 里的 token（避免泄露）：
```bash
git remote set-url origin https://github.com/<你的用户名>/strike-miniapp-assessment.git
```

---

## 推送前最后确认（已替你做过）

- ✅ 脱敏自检通过：`python tools/sanitize_check.py`（无 token / PII / 本机路径）
- ✅ `.gitignore` 排除：`.venv / node_modules / .runtime / output / logs / token.txt / *.pid`
- ✅ 无真实抓包数据、无真实姓名手机、无目标域名
- ✅ LICENSE = GPL-2.0
- ✅ 本地 commit 已完成，工作区干净

---

## 公开后的注意事项

- 首次运行工具的 `02-一键启动.bat` 会下载 node 运行时/frida（这些不在仓库里，README 已说明）。
- 若后续要更新，改完源码后跑一遍 `python tools/sanitize_check.py`，全绿再 commit/push。
- 仓库是 GPL-2.0，允许他人使用修改，但需保留署名与同协议开源。
