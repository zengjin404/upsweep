# UpSweep 架构说明

> 本文件描述当前已落地的结构与后续阶段的模块边界。阶段 0 只实现诊断链路；扫描、分析、计划与清理模块尚未实现。

## 1. 分层

```text
Vue 3 前端（src/）
    │  invoke（仅调用仓内命令，不直接访问文件系统）
    ▼
Tauri Commands（src-tauri/src/commands/）
    │  参数接收、结果返回；不直接操作文件
    ▼
业务模块（当前：database / config / utils）
    │
    ├── SQLite（database/）
    ├── Windows API 封装（utils/windows_api.rs）
    └── 后续：scanner / discovery / metadata / signature / software /
              analyzer / planner / directory / cleaner / protection / rules / history
    ▼
Windows 文件系统 / Windows API / SQLite
```

约束：

- 前端不决定文件是否安全，不提交任意删除路径。
- 文件系统与 Windows API 调用必须位于 Rust 模块，命令层只做编排。
- `unsafe` FFI 只出现在 `utils/windows_api.rs` 等明确的平台封装中，并为每处调用写明安全前提。
- 数据库结构变更通过 `PRAGMA user_version` 递增迁移，不静默兼容未知高版本。

## 2. 当前模块

| 模块 | 文件 | 职责 |
| --- | --- | --- |
| 命令入口 | `commands/system.rs`、`commands/diagnostics.rs` | `get_app_info`、`run_database_check`、`probe_windows_api` |
| 配置/路径 | `config/mod.rs` | 产品常量、`%LOCALAPPDATA%\upsweep` 路径解析 |
| 数据库 | `database/mod.rs` | 连接、结构迁移、事务自检、Tauri 状态封装 |
| 模型 | `models/` | 序列化报告、`AppError` |
| Windows API | `utils/windows_api.rs` | 系统目录与文件属性只读封装 |
| 前端调用 | `src/services/diagnostics.js` | 集中封装 `invoke` |
| 前端页面 | `src/views/Home.vue`、`components/common/StatusCard.vue` | 阶段 0 技术验证页 |

## 3. 预留模块与阶段对应

| 目录 | 阶段 | 职责 | 当前状态 |
| --- | --- | --- | --- |
| `scanner/` | 1 | 扫描计划、遍历、候选调度、进度、取消、会话管理 | 已实现 |
| `scanner/discovery.rs` | 1 | 目录/文件名/版本号/扩展名多特征候选发现 | 已实现 |
| `metadata/` | 1 | PE Version Information、MSI/MSP 元数据 | 已实现 |
| `signature/` | 1 | WinVerifyTrust 状态 + Authenticode 发布者 | 已实现 |
| `software/` | 1 | 卸载注册表只读采集 | 已实现 |
| `protection/` | 1 | 路径规范化、组件边界、受保护路径、reparse point | 已实现 |
| `analyzer/` | 3 | 规则约束的风险分类与理由 | 预留 |
| `planner/` | 5 | 清理计划生成与预览 | 预留 |
| `directory/` | 5 | 孤立目录分析与自底向上计划 | 预留 |
| `cleaner/` | 6 | 执行前复核、回收站操作、部分失败处理 | 预留 |
| `rules/` | 3 | 外部 JSON 规则加载、校验、版本 | 预留；根目录 `rules/` 见其 README |
| `history/` | 7 | 扫描/清理历史 | 预留 |

预留目录中的 `.gitkeep` 只用于保留目录，不代表已经实现。不得把空实现接入命令注册表。

### 阶段 1 扫描数据流

```text
Vue（阶段 4 才接入）
  → start_scan(ScanRequest)
  → scanner::plan::prepare
      → 预设/自定义根解析
      → 受保护路径 + 排除目录
      → MetadataOptions / maxDepth / 并发度
  → 后台线程 scanner::engine::run
      → 迭代遍历（canonicalize + visited + reparse 检查）
      → scanner::discovery 候选证据
      → 有界队列 → 元数据 worker（PE / 签名 / MSI）
      → scan-progress / scan-candidate 事件
  → scan-finished(ScanReport)
  → ScanManager 保留最近报告；cancel_scan 设置原子取消令牌
```

## 4. 阶段 0 数据流

### 4.1 应用启动

```text
main.rs → lib.rs::run()
  → Tauri Builder.setup()
      → config::app_data_dir()：%LOCALAPPDATA%\upsweep
      → DatabaseState::initialize(%LOCALAPPDATA%\upsweep\upsweep.db)
          → create_dir_all → Connection::open → PRAGMA foreign_keys / busy_timeout
          → user_version 迁移到 v1（app_meta）
      → app.manage(DatabaseState)
  → 注册 3 个命令
```

数据库初始化失败时 `DatabaseState::failed` 保存错误信息，窗口仍可启动；自检命令返回 `DB_UNAVAILABLE`，不会 panic。

### 4.2 前端调用

```text
Home.vue
  → services/diagnostics.js::invoke(...)
  → commands::*
  → database 或 utils::windows_api
  → 返回 camelCase 结构
  → 页面展示；失败时展示 AppError.message
```

所有检查按钮在未运行时显示“尚未运行”，不会预填假数据。

## 5. 安全不变量（后续阶段必须保持）

1. 默认回收站，默认永久删除关闭。
2. 扫描阶段只读，不修改文件系统。
3. 清理执行前重新校验路径、存在性、大小、修改时间、保护范围、占用状态。
4. 前端只提交候选 ID/选择状态，不提交删除路径。
5. 目录清理必须独立分析，禁止 `remove_dir_all` 式递归删除。
6. 路径边界按组件比较，不使用字符串前缀；不跟随 Junction/Symbolic Link。
7. 未知状态一律保留，不因扫描异常把文件当作安全项。
8. 不以文件名、目录名、文件年龄、签名状态中的任何单一证据触发推荐清理。

## 6. 待定事项

- CSP：当前为 `null`，发布前配置最小策略。
- 应用图标：当前为脚手架占位。
- 数据库业务表：阶段 7 实现设置/历史，阶段 2–6 只存任务级摘要。
- 规则文件格式：阶段 3 按 [DEVELOPMENT.md 第 9.2 节](../DEVELOPMENT.md) 定义并校验。
