# 开发环境记录

> 记录日期：2026-11-16
> 本文件记录阶段 0 实际使用的工具链版本与路径。后续阶段不得擅自降级这些组件；如需变更，先记录原因与兼容性影响。

## 1. 工具链版本

| 组件 | 实际版本 | 路径/说明 |
| --- | --- | --- |
| Windows | Windows 11 Pro 10.0.26200，x64 | — |
| Node.js | v22.14.0 | `D:\Program\nvm` / `D:\Program\nodejs` |
| npm | 10.9.2 | 随 Node.js |
| WebView2 Runtime | 157.0.4341.46 | `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\157.0.4341.46` |
| Visual Studio Build Tools | Visual Studio 生成工具 2026，18.12.12405.243 | `D:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools` |
| MSVC 工具集 | 14.52.37025 | `...\VC\Tools\MSVC\14.52.37025` |
| cl.exe | 14.52.37025（Hostx64/x64） | `...\VC\Tools\MSVC\14.52.37025\bin\Hostx64\x64\cl.exe` |
| Windows SDK | 10.0.26100.0、10.0.19041.0 | `C:\Program Files (x86)\Windows Kits\10` |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) | `C:\Users\ZJ\.cargo\bin\rustc.exe` |
| Cargo | 1.100.0 (3acc79c0c 2026-11-05) | `C:\Users\ZJ\.cargo\bin\cargo.exe` |
| rustup | 1.29.3 (edbc831ce 2026-11-02) | `C:\Users\ZJ\.rustup` |
| 默认工具链 | `stable-x86_64-pc-windows-msvc` | 仅安装该目标 |
| rustfmt | 1.11.0-stable | `cargo fmt` |
| clippy | 0.1.100 | `cargo clippy` |

## 2. 项目依赖版本

| 依赖 | 版本 |
| --- | --- |
| Tauri Rust crate | 2.12.5 |
| tauri-build | 2.7.4 |
| tauri-runtime | 2.12.2 |
| wry | 0.57.2 |
| @tauri-apps/api | 2.12.4 |
| @tauri-apps/cli | 2.12.4 |
| Vue | 3.5.45 |
| Vite | 8.3.8 |
| Less | 4.9.1 |
| Vitest | 4.1.12 |
| rusqlite | 0.41.1（bundled SQLite 3.54.1） |
| windows-sys（直接依赖） | 0.61.2 |
| authenticode | 0.6.0（features: object, std） |
| object | 0.39.1（pe/read_core/unaligned，no default features） |
| msi | 0.11.1 |
| cms | 0.2.3 |
| x509-cert | 0.2.5 |
| sha2 | 0.10.9 |

Tauri 2.12 要求 Rust 1.90+；`Cargo.toml` 已声明 `rust-version = "1.90"`。Rust crate 与 npm 包必须保持同主/次版本。

## 3. 终端 PATH

- 用户 PATH（HKCU）已包含 `C:\Users\ZJ\.cargo\bin`。
- 使用 `Start-Process -UseNewEnvironment` 启动全新 `cmd.exe` 验证，`where cargo` 与 `where rustc` 均解析到 `C:\Users\ZJ\.cargo\bin`。
- 机器级 PATH 未包含 Cargo，不需要修改。
- 当前 Claude Code 会话的父进程 PATH 是安装 Rust 前的旧快照，因此本会话内执行 cargo 命令时临时把 `C:\Users\ZJ\.cargo\bin` 加入 PATH；这不影响新开终端。

## 4. 应用数据目录权限与生命周期

### 4.1 目录

| 路径 | 用途 |
| --- | --- |
| `%LOCALAPPDATA%\upsweep` | 应用数据库（`upsweep.db`） |
| `%LOCALAPPDATA%\zengjin.upsweep` | WebView2 用户数据目录（由 Tauri/WebView2 管理） |

### 4.2 权限检查

`icacls` 实际结果：

```text
C:\Users\ZJ\AppData\Local\upsweep
  DESKTOP-ARTI90V\CodexSandboxUsers:(I)(OI)(CI)(RX)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(F)
  DESKTOP-ARTI90V\ZJ:(I)(OI)(CI)(F)
```

- 所有者：`DESKTOP-ARTI90V\ZJ`。
- 当前用户具有完全控制；SYSTEM 与 Administrators 具有完全控制。
- `CodexSandboxUsers` 仅有继承的只读/执行权限，不能写入或删除。
- 未发现 `Everyone`、`Users` 或匿名用户的写权限。
- 数据库文件 `upsweep.db` 的 ACL 与目录一致，所有者 `ZJ`。

> `CodexSandboxUsers` 是当前执行环境注入的沙箱组；普通用户机器上通常只有当前用户、SYSTEM 和 Administrators。应用不依赖该组。

### 4.3 生命周期

- 数据库在应用启动的 Tauri `setup` 阶段打开时创建；目录不存在则创建。
- 数据库连接在应用运行期间保持，退出时由 Rust 释放；无后台常驻进程。
- 数据用于后续设置/历史持久化，退出后保留，不自动删除或轮转。
- 当前未实现卸载清理；Tauri 安装包的卸载是否移除 `%LOCALAPPDATA%\upsweep` 需在阶段 8 验证。按 Windows 惯例，用户数据不应在升级时被删除。
- 阶段 0 自检在事务内删除测试键；运行时检查 `app_meta` 为 0 行，无测试残留。

## 5. 复核命令

```powershell
rustc --version
cargo --version
rustup show
where.exe cargo
where.exe rustc

& "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" `
  -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  -property installationPath

icacls "$env:LOCALAPPDATA\upsweep"
```
