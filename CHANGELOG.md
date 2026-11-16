# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的结构，版本号遵循语义化版本。

## [Unreleased]

### Added

- 阶段 0：Tauri 2 + Vue 3 + Vite + Less 项目骨架（JavaScript，无 TypeScript）。
- 产品命名：`过河拆包` / `upsweep` / 可执行文件 `upsweep.exe`。
- 基础目录结构与后续模块预留目录。
- Tauri 命令：`get_app_info`、`run_database_check`、`probe_windows_api`。
- SQLite 连接、`app_meta` 表、`user_version` 迁移与事务自检。
- Windows API 只读封装：`GetWindowsDirectoryW`、`GetSystemDirectoryW`、`GetFileAttributesW`。
- 技术验证页（真实调用结果，不显示模拟数据）。
- Rust 单元/集成测试与 Vitest 前端测试。
- 文档：README、阶段 0 实施记录、架构说明、测试说明。
- 阶段 1：扫描引擎与元数据采集（2026-11-16）。
  - 预设/自定义/排除目录；安全迭代遍历；进度、取消、结构化日志。
  - 多维度候选发现（目录、文件名、版本号、扩展名），只记录证据。
  - PE 版本资源、Authenticode 状态/发布者、MSI/MSP 元数据。
  - Windows 卸载注册表只读采集（HKLM 64/32 视图、HKCU）。
  - 路径边界、受保护目录、reparse point 防护。
  - 扫描集成测试、性能测试与独立夹具。

### Verification

- `npm ci`：通过，0 vulnerabilities。
- `npm run build`：通过，21 个模块。
- `npm test`：3/3 通过。
- `cargo check`：通过，无警告。
- `cargo test`：9/9 通过（7 个单元 + 2 个集成）。
- `cargo fmt --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `npm run tauri dev`：桌面窗口正常启动；3 个 IPC 命令均返回真实数据；控制台 0 错误。
- SQLite 3.54.1 / schema v1 / 事务往返读写通过。
- Windows API 3 项只读探测全部通过。
- Tauri crate 2.12.5 与前端 API 2.12.4 版本对齐。
- `npm run tauri build -- --no-bundle`：release 二进制 `upsweep.exe` 构建成功（约 6.0 MB），启动后保持运行。
- 阶段 1：59 个常规 Rust 测试通过；Clippy/fmt 通过；真实 Tauri IPC 扫描与已安装软件读取通过；release 构建通过（`upsweep.exe` 6,855,168 字节）。
- 阶段 1 性能基线（debug，合成目录）：201 个目录、1,250 个文件、250 个候选，约 322–641 ms（1,949–3,877 文件/秒）。
- 阶段 1 真实目录只读扫描：EdgeUpdate 16 目录 / 109 文件 / 14 候选，PE 14/14，签名 14/14 有效，0 issue，约 1.03 s，取消响应 6–22 ms。

### Known issues

- 应用图标为脚手架占位；CSP 尚未配置。
- Vitest 显式导入 API 在 Vite 8.3.8 下异常，当前使用 `globals: true`。
- LongPathsEnabled 未启用。
- NSIS/MSI 安装包打包尚未验证（release 二进制已构建并启动验证）。
- 阶段 1 尚未实现扫描 UI；Authenticode 按 SignerIdentifier 匹配叶证书（SubjectKeyIdentifier 暂不支持），MSI 发布者优先使用 Manufacturer；WinVerifyTrust 不进行网络吊销检查。
