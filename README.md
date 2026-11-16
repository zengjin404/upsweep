# 过河拆包（UpSweep）

Windows 软件升级残留清理器。用于发现软件自动更新后遗留的旧安装包、升级包与孤立目录，并在充分展示证据、用户确认后执行清理。

> **当前状态：阶段 0（项目初始化与技术验证）已完成。**
> 桌面窗口、前后端通信、SQLite 基本读写、Windows API 调用与 Rust 测试均已实际运行通过。阶段 0 不包含任何文件扫描或删除功能。

## 技术栈

| 模块 | 技术 |
| --- | --- |
| 桌面框架 | Tauri 2（Rust crate 2.12.5） |
| 前端框架 | Vue 3（JavaScript，Composition API） |
| 构建工具 | Vite 8 |
| 样式 | Less |
| 后端 | Rust |
| 本地数据库 | SQLite（rusqlite 0.41，bundled） |
| 系统接口 | Windows API（windows-sys 0.61，独立封装） |

## 环境要求

| 组件 | 要求 | 本机检测结果 |
| --- | --- | --- |
| Windows | Windows 10/11 | Windows 11 Pro 10.0.26200，x64 |
| Node.js | 22.12+ | v22.14.0 |
| npm | 随 Node 提供 | 10.9.2 |
| WebView2 Runtime | 建议最新版 | 157.0.4341.46 |
| Visual Studio Build Tools | 含 MSVC x64/x86 生成工具 | Visual Studio 生成工具 2026 18.12.12405.243 |
| MSVC | 14.5x | 14.52.37025 |
| Windows SDK | 10.0.19041.0 或更高 | 10.0.26100.0、10.0.19041.0 |
| Rust | **1.90+**，`x86_64-pc-windows-msvc` | 1.100.0 |
| rustfmt / clippy | 随 Rust 默认 profile 安装 | rustfmt 1.11.0 / clippy 0.1.100 |

Tauri 2.12 要求 Rust 1.90+；项目 `Cargo.toml` 已声明 `rust-version = "1.90"`。

## 安装开发依赖（图形化优先）

以下步骤供其他机器复现环境使用。本机已完成安装。系统级依赖优先使用官方图形化安装程序；只有官方确实不提供图形化安装器时，才使用其官方控制台安装器，并会明确说明。

### 1. Visual Studio Build Tools（必需）

官方下载页：[Visual Studio 下载页](https://visualstudio.microsoft.com/downloads/) → 「用于 Visual Studio 的工具」→ **Build Tools for Visual Studio 2026** → 下载并运行安装程序。

图形化安装步骤：

1. 启动安装程序，点击「继续」。
2. 在「工作负荷」页勾选 **使用 C++ 的桌面开发**（Desktop development with C++）。
3. 在右侧「安装详细信息」中确认必需组件：
   - **MSVC v143/v14x - VS C++ x64/x86 生成工具**（必需）
   - **Windows 11 SDK** 或 **Windows 10 SDK（10.0.19041.0 或更高）**（必需；已安装时可取消重复版本）
4. 可选组件：
   - 「C++ 的 CMake 工具」：当前项目不依赖 CMake，可不选。
   - 「Git for Windows」：本机已有 Git，可不选。
5. 不需要安装的附带组件：
   - 完整 Visual Studio IDE、.NET 桌面开发、ASP.NET、Azure、Python、Node.js、UWP、C++/CLI、vcpkg。
6. 在安装程序左下角「安装位置」标签中可自定义安装路径；本机路径为 `D:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools`。
7. 点击「安装」，完成后重启终端。

验收：Visual Studio Installer 显示 Build Tools 已安装；`C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe` 可查找到包含 `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` 的实例。

### 2. Rust（必需）

官方页面：[rustup.rs](https://rustup.rs/) → 下载 Windows x86_64 的 `rustup-init.exe`（官方地址 `https://win.rustup.rs/x86_64`）。

**说明：Rust 官方没有图形化安装向导。** `rustup-init.exe` 打开的是控制台交互菜单（1 默认安装 / 2 自定义 / 3 取消），这属于官方控制台安装器，不是图形化向导。

- 选择 `1` 使用默认安装，默认工具链为 `stable-x86_64-pc-windows-msvc`，默认 profile 包含 rustc、cargo、rustfmt、clippy。
- 选择 `2` 可自定义 host triple、默认工具链、profile 和 PATH。
- 默认安装目录为 `%USERPROFILE%\.cargo` 与 `%USERPROFILE%\.rustup`；如需自定义路径，需在运行安装器前设置 `CARGO_HOME`、`RUSTUP_HOME` 环境变量（没有图形化路径选择器）。
- 安装完成后重新打开终端，确认：

```powershell
rustc --version
cargo --version
rustup show
```

`rustup show` 的默认工具链应为 `stable-x86_64-pc-windows-msvc`。

### 3. Node.js（通常已具备）

官方下载页：[nodejs.org](https://nodejs.org/) → LTS 版 Windows Installer (.msi)。这是图形化安装向导，可自定义安装路径；安装过程中的「自动安装必要工具」选项可以取消，本项目不需要额外全局工具。

### 4. WebView2 Runtime（通常已具备）

官方页面：[Microsoft Edge WebView2](https://developer.microsoft.com/microsoft-edge/webview2/) → Evergreen Bootstrapper（图形化）或 Standalone Installer。Windows 11 通常已预装。

### 5. Windows SDK（通常随 Build Tools 安装）

官方页面：[Windows SDK 下载](https://developer.microsoft.com/windows/downloads/windows-sdk/) → `winsdksetup.exe`（图形化安装程序），或在 Visual Studio Installer 的 C++ 工作负载中勾选对应 SDK。

## 快速开始

```bash
npm ci
npm run tauri dev
```

`npm run dev` 只启动浏览器中的 Vite 页面，Tauri 命令不可用；需要验证桌面功能时使用 `npm run tauri dev`。

生产构建：

```bash
npm run tauri build
```

## 常用命令

| 命令 | 说明 |
| --- | --- |
| `npm run dev` | 启动 Vite 开发服务器（浏览器） |
| `npm run build` | 构建前端到 `dist/` |
| `npm test` | 运行前端 Vitest 测试 |
| `npm run test:rust` | 运行 Rust 单元与集成测试 |
| `npm run tauri dev` | 启动桌面应用开发模式 |
| `npm run tauri build` | 构建桌面应用与安装包 |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --check` | 检查 Rust 格式 |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` | Rust 静态检查 |

## 目录结构

```text
upsweep/
├── src/                          # Vue 前端
│   ├── components/common/        # 通用组件
│   ├── views/                    # 页面（阶段 0：技术验证页）
│   ├── services/                 # Tauri 命令调用封装
│   ├── styles/                   # Less 变量与全局样式
│   ├── utils/                    # 前端纯函数与测试
│   ├── assets/                   # 预留：静态资源
│   ├── components/{scanner,results,cleaner,settings}/  # 预留
│   ├── composables/ stores/ router/                     # 预留
│   ├── App.vue
│   └── main.js
├── src-tauri/
│   ├── src/
│   │   ├── commands/             # Tauri 命令入口（system / diagnostics）
│   │   ├── config/               # 常量与路径解析
│   │   ├── database/             # SQLite 连接、迁移、自检
│   │   ├── models/               # 前后端数据契约与错误类型
│   │   ├── utils/                # Windows API 安全封装
│   │   ├── {scanner,discovery,metadata,signature,software,
│   │   │    analyzer,planner,cleaner,directory,protection,rules,history}/  # 预留
│   │   ├── lib.rs
│   │   └── main.rs
│   ├── tests/                    # Rust 集成测试
│   ├── capabilities/
│   ├── icons/                    # 当前为脚手架占位图标
│   └── tauri.conf.json
├── rules/                        # 外部识别规则（阶段 3 实现）
├── docs/
├── tests/fixtures/               # 测试夹具（阶段 1 起使用）
├── DEVELOPMENT.md                # 项目开发手册
└── README.md
```

标记为「预留」的目录目前只有 `.gitkeep`，用于保持手册规定的模块边界；不会提前放入空实现。

## 阶段 0 验证结果

| 验证项 | 结果 |
| --- | --- |
| `npm ci` / `npm install` | 通过，87 个包，0 vulnerabilities |
| `npm run build` | 通过，Vite 8.3.8，21 个模块 |
| `npm test` | 通过，1 个文件 / 3 个用例 |
| `cargo check` | 通过，无警告 |
| `cargo test` | 通过，7 个单元测试 + 2 个集成测试，共 9 个 |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | 通过 |
| `npm run tauri dev` | 桌面窗口正常启动，标题 `过河拆包 - 升级残留清理器` |
| 前后端通信 | 3 个命令均通过真实 `invoke` 返回正确数据，控制台 0 错误 |
| SQLite | SQLite 3.54.1，schema v1，写入/读回/删除通过，数据库 12 KB |
| Windows API | 3 项探测全部通过（`GetWindowsDirectoryW`、`GetSystemDirectoryW`、`GetFileAttributesW`） |
| Release 构建 | `tauri build --no-bundle` 通过，产物 `upsweep.exe` 约 6.0 MB，启动后保持运行 |

实际运行结果示例：

```text
产品名称：过河拆包
包名：upsweep
版本：0.1.0
应用标识：zengjin.upsweep
应用数据目录：C:\Users\<用户>\AppData\Local\upsweep

SQLite：3.54.1 / v1 / 往返读写通过
Windows：C:\Windows、C:\Windows\system32、kernel32.dll 属性读取通过
```

## 安全边界

- 阶段 0 不扫描、不修改、不删除任何用户软件目录。
- Windows API 探测仅读取系统目录和 `kernel32.dll` 的属性。
- SQLite 自检只操作应用自己的数据目录，并在同一事务内删除测试键。
- 后续清理功能必须遵循 [DEVELOPMENT.md](DEVELOPMENT.md) 的安全要求，默认使用回收站，默认仅勾选推荐项。

## 文档

- [阶段 0 实施记录](docs/PHASE-0.md)
- [架构说明](docs/ARCHITECTURE.md)
- [测试说明](docs/TESTING.md)
- [开发手册](DEVELOPMENT.md)

## 许可证

尚未确定，待项目发布前补充。当前仓库不附带任何开源许可证授权。
