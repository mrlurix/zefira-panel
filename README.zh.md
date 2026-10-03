# Zefira

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-live-brightgreen)](https://mrlurix.github.io/zefira-panel/)
[![Pentest](https://img.shields.io/badge/pentest-129%2F129-success)](https://github.com/mrlurix/zefira-panel/blob/main/attack_test.py)

> 🌐 **语言:** [English](README.md) · [فارسی](README.fa.md) · **中文** · [Русский](README.ru.md)

> 📚 **文档: [mrlurix.github.io/zefira-panel](https://mrlurix.github.io/zefira-panel/)** —— 安装指南、用户手册、API 参考、常见问题。

用于管理和销售 VPN 账号的简洁面板。最初是我给自己服务器用的私有工具，后来整理成可公开发布的形态。

支持 VLESS、VLESS-REALITY、VMess、Trojan、Shadowsocks、Hysteria2、WireGuard、OpenVPN、L2TP/IPsec、Cisco AnyConnect 和 SOCKS5。一个用户可以同时拥有多个协议，并且只拿到**一条**订阅链接。

基于 FastAPI + SQLite 构建。不需要 Docker，只要有 Python。

### 截图

![登录](screenshots/screenshot-login.png)
![管理面板](screenshots/screenshot-dashboard.png)
![用户面板](screenshots/screenshot-user-dashboard.png)
![外观设置](screenshots/screenshot-appearance.png)

### 在服务器上安装

一行命令：

```bash
curl -fsSL https://raw.githubusercontent.com/mrlurix/zefira-panel/main/install.sh | sudo bash
```

更想先读一遍？那就下载、查看，然后运行**那一份**：

```bash
d="$(mktemp -d)"                       # 只有你自己能读的私有目录
curl -fsSL -o "$d/install.sh" \
  https://raw.githubusercontent.com/mrlurix/zefira-panel/v1.15.16/install.sh
less "$d/install.sh"
sudo bash "$d/install.sh"
rm -rf "$d"
```

> 两种都可以。单行版本会把当时上游提供的任何代码直接管进 root shell，所以如果你在意**以 root 身份运行的是哪份代码**，就用第二种：它落在 `mktemp` 刚刚为你创建的目录里（固定的 `/tmp/zefira-inst` 可能已被本地其他用户预先创建，而 `mkdir -p` 会在一个自己并不拥有的目录上静默成功），并且 `v1.15.16` 这个 tag 固定了安装脚本本身。
>
> 随后安装脚本会按它自带的发布 tag 克隆面板源码。如果你想更严格地固定到具体提交：
>
> ```bash
> ZEFIRA_EXPECTED_SHA=<40 位提交哈希> sudo bash install.sh
> ```
>
> 除非克隆结果正是该提交，否则会被拒绝。`ZEFIRA_INSTALL_REF=main` 恢复较早的「跟踪分支」行为。安装脚本还会拒绝把 `/opt/zefira` 自身当作源码：那棵树对服务账号可写，信任它等于把一个服务立足点交给 root。

脚本会安装 Python 依赖、创建一个 systemd 服务，并把首次登录凭据保存在 `instance/first-run-credentials.txt`（权限 600）——用 `sudo cat` 读取，首次登录后请删除。适用于 Ubuntu / Debian / Alma / Rocky（需要 Python 3.10+）。

启用 nginx 选项时面板只绑定 `127.0.0.1`，防火墙只开放 80/443；不启用时面板会在所选端口上以明文 HTTP 应答，所以在真正使用前请在前面放好 TLS。

之后要卸载：`sudo bash install.sh --uninstall`

### 手动安装

```bash
git clone https://github.com/mrlurix/zefira-panel.git
cd zefira-panel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header --no-proxy-headers
```

绑定 `127.0.0.1` 并在前面放一个带 TLS 的反向代理。`--host 0.0.0.0` 会把管理员登录以明文暴露出去（没有 Secure cookie，没有 HSTS）。

首次运行会把管理员用户名/密码写入 `instance/first-run-credentials.txt`（权限 600），并且只打印路径。如果你在启动前设置了 `ZEFIRA_ADMIN_PASSWORD`，则改用该值。

> **只运行一个 worker。** 速率限制器、restore/update 锁、节点监控循环和设置缓存都存在于进程内存中——`--workers N` 会成倍放大限流额度，并可能让 restore 相互交错。要扩容请加机器，而不是加 worker。

默认登录地址：`http://YOUR_SERVER_IP:8000`

### 你会得到什么

- 支持流量上限、到期时间和备注的用户。如果希望计时器只在首次连接后开始，支持 start-on-first-use。每行的铅笔按钮可编辑备注、流量、到期时间和设备数限制。
- 每个用户可多种协议，全部汇总到一个订阅。支持标准 base64 订阅和 Clash YAML（`?format=clash`）。链接备注显示纯用户名。
- **订阅内容只承载分享链接，不含其他任何东西。** `WireGuard`、`OpenVPN`、`L2TP/IPsec` 和 `Cisco AnyConnect` 属于文件类协议——`.conf`/`.ovpn` 不是 URI，任何链接导入器都读不了它们——它们以文件形式交付：面板卡片、每个用户的 **Download config** 按钮，或 ZIP。因此只由文件类协议组成的套餐没有可列出的链接，订阅会返回 `422` 并说明原因，而不是返回一段客户端无法解析的文本。在 v1.15.8 之前，这些文件会以 `### OpenVPN ###` 标题内联到订阅里；客户端只会跳过那一行以 `#` 开头的标记，然后把其余约 90 行当作节点接收。
- 浏览器面板：在浏览器中打开订阅链接会显示用量、链接、二维码和应用列表；VPN 客户端始终拿到原始字节。
- 入站：为每个协议定义额外的端口/主机，每个用户都会得到全部对应的链接。可以把入站固定到服务器节点——离线节点会自动从链接中排除。
- 服务器节点：登记远程服务器，每 5 分钟健康检查、延迟和在线率；支持按需检查、启用/禁用、安全删除。
- 反审查：在面板内生成 REALITY 密钥，链接使用 `xtls-rprx-vision` 并自动轮换 SNI。
- BackPack 隧道节点：为你的伊朗/境外服务器创建隧道，下载已填好 token 的配置指南，并检查伊朗一侧是否可达。
- 每个订阅都有二维码，配置可下载 ZIP。
- AI 助手气泡：仅面板内的助手（优先 Groq，也支持 OpenAI/Anthropic/Gemini/Ollama），面向新手。
- 面板内一键从 GitHub 更新，并可预览变更日志。
- API token（`zfp_…` bearer）供 Telegram 机器人和看板使用——无需 CSRF 头。scope：`full` 或最小权限的 `bot`（仅列出/创建用户）。
- 完整个性化：主题色、品牌名称、面板留言。
- 敏感操作有强密码校验、完整审计日志、系统统计、可选的 Telegram 通知。
- JSON 备份/恢复（两者都需确认密码），可选加密备份。还能导入/导出全部设置。
- 以无特权 `zefira` 系统用户运行（绝不 root）；订阅上强制执行流量配额。

完整指南见文档站点（顶部链接）。

### 你可能想改的设置

大部分设置就在面板里：**Settings -> Server / Hosts Settings**（域名、端口、DNS、REALITY 设置）和 **Settings -> Remote Access**（公开 URL、可信代理）。

如果你更习惯环境变量文件，把 `.env.example` 复制为 `.env`。环境变量只作为首次启动时的默认值。

### 安全

我尽量把它收得很紧：密码用 scrypt，JWT 放在 HttpOnly cookie 里，登录有速率限制（按来源 IP，在任何哈希之前检查），CSRF 校验，严格 CSP，参数化查询，用户数据不走 innerHTML，以及审计日志。

**哪些是加密的：** Telegram/AI 凭据、REALITY 与 WireGuard 主机密钥、隧道 token 和加密备份（AES/Fernet，密钥在 `instance/secret.key`）。**哪些不是：** 数据库里每位客户的 VPN 凭据（`secret_data`）——它们是 `instance/zefira.db` 和未加密备份中的明文 JSON，这是有意为之，好让面板无需一次解密往返就能重建链接。请把数据库和未加密备份当作客户凭据对待：将 `instance/` 保持为 `700`，使用加密备份或全盘加密，并阅读 [SECURITY.md](SECURITY.md)。

### 运行测试

这些测试套件从外部打击运行中的面板。先启动面板，然后逐个运行（套件之间重启面板）。也可以一次跑完：`python run_all_tests.py admin YOURPASS`。各套件之间互不依赖顺序，结束时都会把面板恢复到出厂默认设置。

**在线套件（9 个）**——需要正在运行的面板：

```bash
python security_test.py      http://127.0.0.1:8000 admin YOURPASS  # 滥用/防御
python functional_test.py    http://127.0.0.1:8000 admin YOURPASS  # 端到端流程
python feature_test.py       http://127.0.0.1:8000 admin YOURPASS  # 功能覆盖
python attack_test.py        http://127.0.0.1:8000 admin YOURPASS  # 实弹攻击探测
python attack_quota_test.py  http://127.0.0.1:8000 admin YOURPASS  # 配额/模式边界
python attack_paths_test.py  http://127.0.0.1:8000 admin YOURPASS  # 运维路径
python frontend_bugs_test.py http://127.0.0.1:8000 admin YOURPASS  # 前端回归
python panel_sections_test.py http://127.0.0.1:8000 admin YOURPASS  # 面板各分区
python security_audit_test.py http://127.0.0.1:8000 admin YOURPASS  # 安全审计
```

`feature_test.py` 走遍 11 个面板分区里的全部 77 条 API 路由，并断言每项能力**确实可用**（订阅里有真实链接、二维码可解码、配置压缩包可用、机器人 scope 矩阵、备份/恢复往返等），而不只是「能访问」。`attack_test.py` 会自己发起攻击流量：请求头伪造、存储型 XSS、路径穿越、超大/深层嵌套请求体、Unicode/编码技巧、时间侧信道、登录洪水、限流器逐出尝试，以及完整的鉴权矩阵。

**无需服务器（9 个 Python 套件）**——它们执行真实代码而不是只读代码，因为下面每一个缺陷都通过了源码级审查：

```bash
python installer_test.py          # 安装脚本的保证，做成静态守卫
python dashboard_link_test.py     # 猜测域名安装下的客户面板链接
python proxy_trust_test.py        # 代理信任与客户端 IP 的一致性
python link_encoding_test.py      # 分享链接备注的编码
python update_guard_test.py       # 更新器的运行时侵入守卫
python migration_guard_test.py    # 架构迁移步骤，各自独立事务
python env_symlink_guard_test.py  # 安装脚本经由符号链接写 .env
python bump_assets_guard_test.py  # 文档资源版本更新的输入
python i18n_test.py               # 面板模板与 JS 对照所有语言
python docs_coverage_test.py      # 每个端点、分区和设置都有文档
```

**无需服务器（2 个 Node 脚本）**——面向文档站点的四种语言：

```bash
node i18n_dict_check.js           # 加载并检查文档字典
node i18n_render_check.js         # 用敌意输入喂给文档渲染器
```

`i18n_dict_check.js` 之所以存在，是因为文档有四种语言且必须保持同步，而此前没有任何东西在检查这一点。它加载 `docs/assets/i18n.js`，读出浏览器实际会拿到的对象，并在以下情况失败：某个键在任一语言中缺失或为空、某个值把两条内容粘在了一起、出现乱码、`data-i18n` 属性名拼错以至于 `applyI18n` 读不到、以及页面引用了任何语言都不存在的键。对于**与英文完全相同**的值它会报告但不算失败，因为有时这是对的：`GitHub Security Advisories` 是 GitHub 自己的功能名，把它翻译成协议列表反而更糟。

修改 `docs/` 下任何内容之后，请运行 `python docs/build_index.py`。它会重建搜索索引、给每个标题一个稳定锚点，并且**自己**通过 `docs/bump_assets.py` 提升资源缓存版本号。最后这一点不是装饰：这个计数器散落在十四个位置，只在十二个页面上提升它，会让 `docs.js` 和 `support-ai.js` 继续读取**上一版**的 `search-index.json` 和 `site-knowledge.json`——HTML 是新的，搜索结果是旧的，支持机器人则依据上周的知识库作答。

各套件的检查数量刻意**不**写在这里：每加一个检查它就会变，而一个已经过时的数字比没有数字更糟，因为它看起来像是可以拿来对比的东西。请直接从运行结果中读取——每个套件都会打印 `N/N checks passed`。

### 依赖

`requirements.txt` 保存人工维护的**直接**依赖锁定（你有意要升级的东西）。`requirements.lock` 是完全解析并**用哈希锁定**的集合，`install.sh` 和面板内更新器实际安装的就是它：

```bash
pip install --require-hashes --no-deps -r requirements.lock
```

顶层的精确锁定从来锁不住传递依赖图——光是 `uvicorn[standard]` 就会拖进十几个版本区间——所以同一份 `requirements.txt` 的两次安装可能执行不同的代码。编辑 `requirements.txt` 后请重新生成锁文件，然后验证它：

```bash
python tools_lock.py
python verify_lock_hashes.py
```

> **务必运行验证器。** 锁文件在一台机器上生成、在另一台机器上安装，而只覆盖生成机器平台的哈希会让安装在服务器上直接中断——或者更糟，留下一个其实什么都没验证的锁文件。早期版本的 `tools_lock.py` 只记录它能在本地下载到的构件，这导致 31 个包中有 11 个在 Linux 上根本无法安装。`verify_lock_hashes.py` 会把每条记录的哈希与 PyPI 逐一核对。

### API

这是一个普通的 REST API，全部位于 `/api/*` 之下。完整表格请看面板内的 Docs 页面，或者使用面板时直接打开浏览器开发者工具。

### 许可证

MIT —— 见 [LICENSE](LICENSE)。随意使用，只要保留声明。

### 赞助

如果 Zefira 对你有帮助，可以考虑支持它：钱包地址见[赞助页面](https://mrlurix.github.io/zefira-panel/donate.html)。

```text
TRX BEP-20:    0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
ETH BEP-20:    0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
USDC BEP-20:   0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
```

---

如果喜欢它，请点个 star。Issue 和 PR 都很欢迎。

[English](README.md) · [فارسی](README.fa.md) · **中文** · [Русский](README.ru.md)