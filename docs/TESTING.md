# 测试说明

## 1. 测试分层

| 层级 | 位置 | 命令 | 当前状态 |
| --- | --- | --- | --- |
| Rust 单元测试 | `src-tauri/src/**/mod.rs` 内的 `#[cfg(test)]` | `npm run test:rust` | 通过：7 个 |
| Rust 集成测试 | `src-tauri/tests/` | `npm run test:rust` | 通过：2 个 |
| 前端单元测试 | `src/**/*.test.js` | `npm test` | 通过：3 个 |
| 桌面运行时验证 | 技术验证页 | `npm run tauri dev` | 通过：3 个命令、0 控制台错误 |

## 2. Rust 测试

```bash
npm run test:rust
# 等价于：
cargo test --manifest-path src-tauri/Cargo.toml
```

阶段 0 覆盖：

- `database/mod.rs`
  - 内存数据库迁移到 v1。
  - 事务自检写入/读回/删除成功，且不遗留测试键。
  - 文件数据库创建、关闭、重新打开后结构版本保持。
- `utils/windows_api.rs`
  - `GetWindowsDirectoryW` 返回绝对路径且具有目录属性。
  - `GetSystemDirectoryW` 返回目录。
  - 不存在的路径返回错误。
  - 三项探测全部通过。
- `src-tauri/tests/database_roundtrip.rs`
  - 从库 crate 公开 API 验证自检。
- `src-tauri/tests/windows_api.rs`
  - 从库 crate 公开 API 验证 Windows 探测。

实际结果（2026-11-16）：

```text
running 7 tests ... test result: ok. 7 passed; 0 failed
running 1 test  ... test result: ok. 1 passed; 0 failed
running 1 test  ... test result: ok. 1 passed; 0 failed
```

格式与静态检查：

```bash
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

两项均通过。测试中允许使用 `expect` 表达测试前置条件；生产代码不得用 `unwrap()` 处理常规文件访问异常。

## 3. 前端测试

```bash
npm test        # 单次
npm run test:watch
```

阶段 0 覆盖 `src/utils/format.js::formatBytes` 的正常值、边界值（0/1024/10 KB）和非法输入，3 个用例全部通过。

### 已知环境限制

当前 Vite 8.3.8 + Vitest 4.1.12 组合下，从 `"vitest"` 显式导入 `describe/it/expect` 会在 worker 中抛出：

```text
TypeError: Cannot read properties of undefined (reading 'config')
```

使用 `vitest.config.js` 的 `globals: true` 注入全局 API 后测试正常。Vitest 5.1.0 在同一环境复现同样问题。升级依赖后应复核该限制；若上游修复，可改回显式导入并移除 `globals`。

## 4. 桌面运行时验证

阶段 0 使用 `npm run tauri dev` 启动真实桌面窗口，并通过 WebView2 调试协议（`additionalBrowserArgs` 临时启用 `--remote-debugging-port`）执行页面点击，验证：

- 窗口标题：`过河拆包 - 升级残留清理器`。
- 页面标题：`过河拆包 - 升级残留清理器`。
- `get_app_info`：产品名 `过河拆包`、包名 `upsweep`、版本 `0.1.0`、标识符 `zengjin.upsweep`、数据目录 `%LOCALAPPDATA%\upsweep`。
- `run_database_check`：SQLite 3.54.1、schema v1、写入/读回/删除通过、数据库 12288 字节。
- `probe_windows_api`：`GetWindowsDirectoryW`、`GetSystemDirectoryW`、`GetFileAttributesW` 全部通过。
- 页面控制台错误：0。

临时调试配置只用于本地验证，不写入项目的 `tauri.conf.json`。生产构建不启用远程调试端口。

## 5. 测试夹具安全规则

- 所有扫描/清理测试必须在 `tests/fixtures/` 或临时目录中进行。
- 不得扫描、修改或删除用户真实软件目录、系统目录、注册表卸载项。
- 不得使用真实系统文件做破坏性测试。
- 测试文件应为专门生成的无害文件；安装包形态的夹具可以是占位内容，但不得实际执行。
- 涉及文件移动/回收站的测试必须在阶段 6 前建立独立临时目录，并在测试后清理。

`tests/fixtures/` 目前只有说明文件，阶段 1 开始按 [DEVELOPMENT.md 第 12.1 节](../DEVELOPMENT.md) 建立模拟软件目录。

## 6. 后续必须覆盖的测试

按开发手册第 12.2–12.4 节执行：

- 识别测试：`installer.exe`、`setup.exe`、`PixPin_2.0.0.3.exe`、无安装包命名但位于 `updater/`、正常组件误报、PE 元数据有无、签名有无、MSI/MSP、占用状态、待安装版本、多版本、版本未知。
- 目录递归测试：空目录、多级空目录、父目录有内容/未知子目录/未选中候选/主安装目录/系统保护目录、Junction/Symbolic Link、移动失败、删除失败、确认前后内容变化。
- 清理执行测试：回收站成功、永久删除默认关闭、占用、权限不足、文件不存在/被替换/大小或时间变化、部分成功、中途取消、回收站异常、记录保存。

保护性测试必须证明程序不会越界删除。
