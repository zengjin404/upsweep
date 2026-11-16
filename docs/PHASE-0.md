# 阶段 0 实施记录：项目初始化与技术验证

> 记录日期：2026-11-16
> 状态：**已完成**。桌面窗口、前后端通信、SQLite 基本读写、Windows API 调用、Rust 测试、格式与静态检查均已实际运行验证。阶段 0 不包含文件扫描或删除功能。

## 一、环境检测结果

初次检测时，本机缺少 Rust 与 MSVC；随后按用户要求由用户手动安装。当前环境已通过 Tauri CLI 自检。

### 1.1 当前环境

| 组件 | 检测结果 |
| --- | --- |
| 操作系统 | Windows 11 Pro 10.0.26200，x64 |
| Node.js / npm | v22.14.0 / 10.9.2 |
| WebView2 Runtime | 157.0.4341.46，存在 `msedgewebview2.exe` |
| Visual Studio Build Tools | Visual Studio 生成工具 2026，18.12.12405.243 |
| Build Tools 安装路径 | `D:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools` |
| MSVC | 14.52.37025（`VC\Tools\MSVC\14.52.37025`） |
| Windows SDK | 10.0.26100.0、10.0.19041.0 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| Cargo | 1.100.0 (3acc79c0c 2026-11-05) |
| rustup | 1.29.3 (edbc831ce 2026-11-02) |
| 默认工具链 | `stable-x86_64-pc-windows-msvc` |
| rustfmt / clippy | rustfmt 1.11.0-stable / clippy 0.1.100 |
| Rust 目标 | `x86_64-pc-windows-msvc` |

`npm run tauri info` 当前输出：

```text
[✔] Environment
    ✔ WebView2: 157.0.4341.46
    ✔ MSVC: Visual Studio 生成工具 2026
    ✔ rustc: 1.100.0
    ✔ cargo: 1.100.0
    ✔ rustup: 1.29.3
    ✔ Rust toolchain: stable-x86_64-pc-windows-msvc (default)
```

> 说明：当前会话的父进程 PATH 尚未包含 `%USERPROFILE%\.cargo\bin`，验证命令通过临时把该目录加入 PATH 后执行。重新打开终端或 IDE 后，rustup 写入的用户 PATH 应生效。

### 1.2 初次检测的缺失项与处理

| 组件 | 初次检测 | 处理 |
| --- | --- | --- |
| Rust / Cargo / rustup | 未找到 | 用户通过 Rust 官方 `rustup-init.exe` 控制台安装器安装（官方无图形化向导） |
| MSVC C++ 编译器 | 未找到；VS 2019 目录为空 | 用户通过 Visual Studio Build Tools 2026 图形化安装器安装，自定义路径，仅安装 C++ 生成工具工作负载 |
| Visual Studio 完整 IDE | 未安装 | 保持不安装，符合“不安装完整 IDE”的要求 |

### 1.3 其他环境信息

| 项 | 结果 | 影响 |
| --- | --- | --- |
| 当前终端权限 | 普通用户（非管理员） | 应用以普通用户权限运行，符合安全要求 |
| LongPathsEnabled | 注册表值不存在（默认关闭） | 后续扫描长路径时需处理或评估启用 |
| C 盘剩余空间 | 约 25 GB | 足够构建 |
| D 盘剩余空间 | 约 23 GB | 项目与 `src-tauri/target` 所在盘 |
| npm registry | `https://registry.npmjs.org/` | 可用 |
| crates.io | index/static 均可用 | 依赖下载正常 |
| Visual Studio Installer | `C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe` | 可查询到 Build Tools 实例 |

## 二、完成内容

1. 使用 `create-tauri-app@latest`（4.8.0）生成 Tauri 2 + Vue 3 + Vite 项目，JavaScript 模板（无 TypeScript），标识符 `zengjin.upsweep`。
2. 将脚手架迁移到项目根目录，保留 `DEVELOPMENT.md`，迁移前确认无文件冲突。
3. 产品命名：
   - `package.json` / Cargo 包名：`upsweep`
   - `productName`：`过河拆包`
   - `mainBinaryName`：`upsweep`（编译产物为 `upsweep.exe`）
   - 窗口标题：`过河拆包 - 升级残留清理器`
4. 建立手册规定的基础目录；预留模块目录使用 `.gitkeep` 占位，未提前编写空实现。
5. 移除脚手架自带的 `tauri-plugin-opener` 依赖与权限，避免无关能力。
6. 实现 3 个 Tauri 命令：
   - `get_app_info`：产品名、crate 名、版本、标识符、数据目录、构建模式。
   - `run_database_check`：SQLite 事务自检。
   - `probe_windows_api`：Windows 系统目录与文件属性只读探测。
7. SQLite：
   - `rusqlite 0.41`（`bundled`），SQLite 随应用静态编译。
   - 数据库路径：`%LOCALAPPDATA%\upsweep\upsweep.db`。
   - 结构版本 v1，表 `app_meta(key, value, updated_at)`。
   - 自检在事务中 UPSERT → 读回 → DELETE，不遗留测试数据。
   - 初始化失败不阻止应用启动，错误通过命令返回前端。
8. Windows API：
   - `windows-sys 0.61`，仅 `cfg(windows)` 编译。
   - 只读调用 `GetWindowsDirectoryW`、`GetSystemDirectoryW`、`GetFileAttributesW`。
   - `unsafe` 集中在 `utils/windows_api.rs`，命令层不直接调用 FFI。
   - 单项探测失败不中断其余检查。
9. 前端：
   - Vue 3 Composition API + `<script setup>` + Less。
   - 技术验证页展示真实调用结果；未运行状态显示“尚未运行”，不使用模拟数据。
   - 前端通过 `src/services/diagnostics.js` 集中调用命令。
10. 测试环境：
    - Rust 单元测试（数据库、Windows API）+ 集成测试。
    - 前端 Vitest + 纯函数测试。
    - 文档记录测试命令与夹具安全规则。

## 三、修改文件

### 新增

```text
CHANGELOG.md
docs/ARCHITECTURE.md
docs/PHASE-0.md
docs/TESTING.md
rules/README.md
tests/fixtures/README.md
vitest.config.js
src/components/common/StatusCard.vue
src/views/Home.vue
src/services/diagnostics.js
src/styles/variables.less
src/styles/global.less
src/utils/format.js
src/utils/format.test.js
src-tauri/src/commands/mod.rs
src-tauri/src/commands/system.rs
src-tauri/src/commands/diagnostics.rs
src-tauri/src/config/mod.rs
src-tauri/src/database/mod.rs
src-tauri/src/models/mod.rs
src-tauri/src/models/error.rs
src-tauri/src/models/reports.rs
src-tauri/src/utils/mod.rs
src-tauri/src/utils/windows_api.rs
src-tauri/tests/database_roundtrip.rs
src-tauri/tests/windows_api.rs
```

### 修改（脚手架生成后改写）

```text
README.md
index.html
package.json
src/App.vue
src/main.js
src-tauri/Cargo.toml
src-tauri/tauri.conf.json
src-tauri/capabilities/default.json
src-tauri/src/lib.rs
```

### 生成/保留

```text
package-lock.json
src-tauri/Cargo.lock（Rust 依赖锁定）
node_modules/（本地依赖，已忽略）
dist/（前端构建产物，已忽略）
src-tauri/target/（Rust 构建产物，已忽略）
src-tauri/src/main.rs（脚手架内容，未改动）
src-tauri/build.rs（脚手架内容，未改动）
src-tauri/icons/*（脚手架占位图标）
.vscode/extensions.json
.gitignore
src-tauri/.gitignore
```

### 预留目录（仅 `.gitkeep`）

```text
src/assets/
src/components/{scanner,results,cleaner,settings}/
src/composables/
src/stores/
src/router/
src-tauri/src/{scanner,discovery,metadata,signature,software,analyzer,planner,cleaner,directory,protection,rules,history}/
tests/{scanner,analyzer,planner,cleaner}/
```

## 四、技术实现说明

### 4.1 前后端契约

命令统一返回 `Result<T, AppError>`。`AppError` 包含稳定的 `code` 与可读 `message`；前端展示 `message`，不暴露调用栈。模型使用 `serde(rename_all = "camelCase")`，前端直接使用 `productName`、`databaseSizeBytes` 等字段。

### 4.2 数据目录选择

Tauri 的 `app_local_data_dir()` 会追加 bundle identifier（`%LOCALAPPDATA%\zengjin.upsweep`）。开发手册约定 `%LOCALAPPDATA%\upsweep`，因此使用 `PathResolver::local_data_dir()` 加固定目录名 `upsweep`。WebView2 自身的数据目录仍由 Tauri 放在 `%LOCALAPPDATA%\zengjin.upsweep`，与应用数据库分离。

### 4.3 SQLite 结构版本

使用 SQLite 原生 `PRAGMA user_version` 管理结构版本，当前为 v1。迁移在打开连接后执行；版本高于程序支持版本时返回明确错误，不静默降级。后续设置、扫描记录、清理记录表通过递增 `SCHEMA_VERSION` 添加。

### 4.4 Windows API 封装

`query_system_path` 统一处理 Win32 路径 API 的行为：返回值为不含终止符的字符数，缓冲区不足时返回所需大小。文件属性接口返回 `INVALID_FILE_ATTRIBUTES` 时转换为错误，不把失败当作“不存在”或“安全”。当前只做只读查询，不包含删除、移动、回收站或提权调用。

### 4.5 Tauri 版本对齐

首次构建时 `Cargo.toml` 声明 `rust-version = "1.85"`。Cargo 的 MSRV 感知解析据此选择了 Tauri crate 2.11.6（MSRV 1.77.2），而 npm 端 `@tauri-apps/api` 为 2.12.4，`tauri dev` 因此拒绝启动：

```text
Error Found version mismatched Tauri packages...
tauri (v2.11.6) : @tauri-apps/api (v2.12.4)
```

Tauri 2.12 的 MSRV 为 1.90。将 `rust-version` 调整为 `1.90` 后执行：

```bash
cargo update --manifest-path src-tauri/Cargo.toml -p tauri --precise 2.12.5
```

最终解析为：

```text
tauri 2.12.5
tauri-runtime 2.12.2
tauri-runtime-wry 2.12.3
tauri-build 2.7.4
wry 0.57.2
@tauri-apps/api 2.12.4
@tauri-apps/cli 2.12.4
```

Tauri 要求 Rust crate 与 npm 包同主/次版本；2.12 与 2.12 匹配。

### 4.6 测试环境限制

Vite 8.3.8 + Vitest 4.1.12 下，从 `"vitest"` 显式导入 `describe/it/expect` 会在 worker 中抛出 `TypeError: Cannot read properties of undefined (reading 'config')`；使用 `globals: true` 注入的全局 API 正常。Vitest 5.1.0 同样复现。已在 `vitest.config.js` 启用 `globals`，并在 [TESTING.md](TESTING.md) 记录。

## 五、测试与验证结果

### 5.1 构建与测试

| 项目 | 命令 | 结果 |
| --- | --- | --- |
| 依赖安装 | `npm ci` | 通过；87 个包，0 vulnerabilities |
| 前端生产构建 | `npm run build` | 通过；Vite 8.3.8，21 个模块，JS 约 71.00 kB、CSS 4.71 kB |
| 前端单元测试 | `npm test` | 通过；1 个文件，3 个用例 |
| Rust 编译 | `cargo check --manifest-path src-tauri/Cargo.toml` | 通过，无警告 |
| Rust 测试 | `cargo test --manifest-path src-tauri/Cargo.toml` | 通过；7 个单元 + 2 个集成，共 9 个 |
| 格式检查 | `cargo fmt --check` | 通过 |
| 静态检查 | `cargo clippy --all-targets -- -D warnings` | 通过 |
| Release 构建 | `npm run tauri build -- --no-bundle` | 见 5.3 |

### 5.2 桌面运行时验证

使用 `npm run tauri dev` 启动真实窗口，并通过 WebView2 远程调试协议执行页面按钮点击与命令调用（调试端口只通过临时 `--config` 启用，不写入项目配置）。

| 验证项 | 实际结果 |
| --- | --- |
| 窗口标题 | `过河拆包 - 升级残留清理器` |
| 页面标题 | `过河拆包 - 升级残留清理器` |
| 产品名 | `过河拆包` |
| 包名（crate） | `upsweep` |
| 版本 | `0.1.0` |
| 标识符 | `zengjin.upsweep` |
| 数据目录 | `C:\Users\<用户>\AppData\Local\upsweep` |
| 构建模式 | `debug` |
| SQLite 引擎 | 3.54.1 |
| SQLite schema | v1 |
| 事务自检 | 写入 / 读回 / 删除通过 |
| 自检后残留 | `app_meta` 行数为 0（无测试键遗留） |
| 数据库文件 | 12,288 字节（12 KB） |
| 自检耗时 | 47–71 ms |
| Windows 目录 | `C:\Windows` |
| System32 目录 | `C:\Windows\system32` |
| 属性探测文件 | `C:\Windows\System32\kernel32.dll`，属性 `0x00000020` |
| Windows API 检查 | 3/3 通过 |
| 页面控制台错误 | 0 |

数据库文件已实际生成：

```text
C:\Users\<用户>\AppData\Local\upsweep\upsweep.db
文件头：SQLite format 3
```

### 5.3 Release 构建

命令：

```bash
npm run tauri build -- --no-bundle
```

结果：**通过**。

- Cargo release profile（`codegen-units = 1`、`lto = true`、`strip = true`）编译耗时约 6 分 47 秒。
- 产物：`src-tauri/target/release/upsweep.exe`，大小 6,014,464 字节（约 5.7 MiB）。
- 文件版本与产品版本均为 `0.1.0`。
- 单独启动 release 二进制并观察 6 秒，进程保持运行，未发生启动崩溃。
- 未执行 NSIS/MSI 安装包打包。

### 5.4 未验证项

| 项目 | 状态 |
| --- | --- |
| NSIS / MSI 安装包打包 | 未执行（使用 `--no-bundle`，仅验证 release 二进制） |
| Windows 10 实机 | 未执行 |
| 普通用户权限下的完整安装/卸载流程 | 未执行（阶段 8） |
| 长路径场景 | 未执行；LongPathsEnabled 未启用 |

## 六、未完成事项

- 正式应用图标（当前为脚手架占位）。
- CSP 安全策略（当前 `csp: null`，发布前必须配置）。
- NSIS/MSI 安装包构建与安装/卸载验证。
- Git 仓库初始化与提交（当前目录不是 Git 仓库）。
- 许可证选择。
- 阶段 1 的扫描、候选识别、进度与取消（按计划不提前实现）。

## 七、风险与问题

1. **LongPathsEnabled 关闭**：后续扫描可能遇到 260 字符路径限制；阶段 1 前需评估启用或采用 `\\?\` 路径处理。
2. **npm 依赖变更问题**：npm 10.9.2 在已有依赖树上修改 Vitest 版本时触发 arborist 错误 `Cannot read properties of null (reading 'edgesOut')`；本次通过 `--legacy-peer-deps` 完成变更，`npm ci` 可正常从锁文件安装。后续增删依赖若复现，需记录并谨慎处理。
3. **Vitest 显式导入限制**：当前使用 `globals: true` 规避；升级 Vite/Vitest 后应复核。
4. **图标与 CSP 未完成**：不影响技术验证，但属于发布前必须处理项。
5. **安装包未验证**：`bundle.targets = "all"` 的 NSIS/MSI 流程尚未实际执行。
6. **Tauri 版本锁定**：Rust crate 2.12.5 与 npm API 2.12.4 属于同一 minor；升级任一端时必须同步另一端，避免再次出现启动时版本不匹配。

## 八、下一阶段建议（未开始）

阶段 1 应先建立 `tests/fixtures/` 下的模拟软件目录，再实现：

- 扫描根目录获取（Windows 环境变量/系统 API）。
- 目录递归扫描与候选目录识别。
- 文件名、扩展名特征与基本属性收集。
- 扫描进度、取消令牌、权限错误记录。
- 单元测试与模拟目录测试。

阶段 1 仍然不执行任何删除操作。进入阶段 1 前需得到用户确认。
