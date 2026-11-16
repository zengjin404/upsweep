# 阶段 1 实施记录：扫描引擎与元数据采集

> 记录日期：2026-11-16
> 状态：**已完成**。扫描、候选发现、PE/MSI 元数据、Authenticode 状态、已安装软件读取、进度/取消/异常处理与测试均已落地。
> 阶段 1 **不包含**风险分类、清理计划、文件移动、删除或回收站操作。

## 一、完成内容

1. **扫描根目录**
   - 预设目录：`%LOCALAPPDATA%`、`%APPDATA%`、`%PROGRAMDATA%`、`%PROGRAMFILES%`、`%PROGRAMFILES(X86)%`。
   - 自定义目录：前端传入路径，后端绝对化、规范化并校验。
   - 排除目录：默认受保护路径 + 用户自定义排除。
   - 预设目录不存在时记录结构化日志；自定义目录无效时记录问题并继续，不静默忽略。

2. **安全目录遍历**
   - 迭代式遍历，避免递归栈溢出。
   - 每个目录先规范化，再按路径组件边界检查受保护路径/排除路径。
   - 不跟随 symlink、junction、mount point 或其他 reparse point。
   - 维护已访问目录集合，重解析点循环不会导致无限扫描。
   - 目录项按名称排序，最终候选按路径排序，结果可重复。
   - long path 通过 `\\?\` 规范化路径处理。

3. **多维度候选发现**
   - 目录名称特征（`updater`、`update`、`package`、`cache` 等）。
   - 文件名特征（`installer`、`setup`、`update`、`patch` 等）。
   - 文件名版本号特征（至少两段点分隔数字）。
   - 扩展名仅限 `.exe`、`.msi`、`.msp`，且扩展名本身不足以构成候选。
   - 记录匹配证据与可读理由，不做风险分类。

4. **PE 版本资源**
   - `GetFileVersionInfoSizeW` / `GetFileVersionInfoW` / `VerQueryValueW`。
   - 读取 ProductName、ProductVersion、FileDescription、CompanyName、FileVersion、OriginalFilename、InternalName、语言/代码页。
   - 版本资源缺失不是扫描失败；读取失败记录 `peVersion` 元数据问题。

5. **Authenticode**
   - `WinVerifyTrust` 判定 Valid / NotSigned / Invalid / UntrustedRoot / Expired / Revoked / Unknown。
   - 仅使用本地缓存与证书，不访问网络（`WTD_CACHE_ONLY_URL_RETRIEVAL` + `WTD_REVOCATION_CHECK_NONE`）。这是**本地信任验证**，不是在线吊销检查；不得把“Valid”表述为已在线吊销验证。
   - 通过 Google `authenticode` 解析 PE PKCS#7 结构，并按 CMS SignerIdentifier（issuer + serial）匹配**叶证书**；不再取证书集合中的第一个证书。
   - 分别输出签名是否存在、签名结构是否有效、WinVerifyTrust 信任结果、证书链状态、发布者 Subject/CN/Organization 与诊断原因。匹配不到叶证书时发布者为空，不猜测。
   - 证书链状态由 WinVerifyTrust 错误码映射（Valid / UntrustedRoot / Expired / Revoked / Invalid / NotChecked / Unknown），没有另外构建独立证书链；这是本地信任验证结果的一部分。
   - SubjectKeyIdentifier 签名者暂不匹配，返回无发布者/Unknown。
   - 同时支持 PE32 与 PE32+（先尝试 PE32+，再回退 PE32），覆盖 32 位安装程序。
   - 解析失败只影响发布者字段，不改变 WinVerifyTrust 的信任判定。

6. **MSI / MSP 元数据**
   - 使用纯 Rust `msi` 解析库读取，不调用安装服务、不执行安装包。
   - 读取 PackageType、ProductName、ProductVersion、Manufacturer、ProductCode、UpgradeCode、PackageCode、Summary 标题/主题/作者、Patch 表代码。
   - 损坏文件返回 `present = false` 与错误信息，不中断扫描。

7. **已安装软件**
   - 只读读取 HKLM 64 位视图、HKLM 32 位视图、HKCU 的 Uninstall 项。
   - 读取 DisplayName、DisplayVersion、Publisher、InstallLocation、UninstallString、InstallDate、SystemComponent、ReleaseType、ParentKeyName。
   - 识别 MSI ProductCode 与 `msiexec` 卸载命令。
   - 只调用 RegOpenKeyExW / RegEnumKeyExW / RegQueryValueExW / RegCloseKey，不写注册表。

8. **扫描会话与进度**
   - `start_scan` 立即返回 session ID，扫描在独立线程执行。
   - 事件：`scan-progress`、`scan-candidate`、`scan-finished`、`scan-error`。
   - `cancel_scan` 通过原子取消令牌停止遍历与元数据 worker。
   - 有界元数据 worker（最多 4 个），单个候选失败不影响其他候选。
   - 结构化日志、问题列表、截断计数、统计汇总写入报告。

## 二、模块架构与职责

```text
commands/scan.rs
  ├── start_scan / cancel_scan / get_scan_report / is_scan_active
  ├── TauriScanObserver：把进度与候选转为事件
  └── get_installed_software：spawn_blocking 只读注册表
        │
        ▼
scanner/plan.rs        路径解析、扫描根/排除/受保护校验、会话计划
scanner/engine.rs      遍历、进度、取消、有界元数据 worker、报告组装
scanner/discovery.rs   目录/文件名/版本号多维度候选发现
scanner/manager.rs     会话取消令牌与最近报告（最多保留 10 份）
        │
        ├── protection/      路径规范化、组件边界、受保护路径、reparse point
        ├── metadata/        PE 版本资源、MSI/MSP、元数据调度
        ├── signature/       WinVerifyTrust + Authenticode 解析
        └── software/        卸载注册表只读采集
```

### 扫描数据流

```text
ScanRequest
  → plan::prepare：解析预设/自定义根、排除、保护边界
  → engine::run：遍历目录（单线程、确定性）
      → 发现候选（仅记录证据）
      → 候选进入有界队列
          → 元数据 worker（≤4）读取 PE/签名/MSI
          → 结果进入候选集合，发送 scan-candidate 事件
  → 取消/完成：关闭队列、join workers、排序结果
  → ScanReport + scan-finished 事件
```

## 三、数据结构

| 结构 | 关键字段 | 说明 |
| --- | --- | --- |
| `ScanRequest` | `includeDefaultRoots`, `customRoots`, `excludedPaths`, `maxDepth`, `includeMetadata`, `includeSignature`, `includeMsi` | 前端输入；后端重新校验路径 |
| `ScanSessionInfo` | `sessionId`, `startedAtMs`, `roots`, `exclusions` | `start_scan` 返回值 |
| `ScanProgress` | `phase`, 目录/文件/候选/元数据计数、跳过计数、`currentPath`、`cancelled` | 增量进度事件 |
| `ScanReport` | `status`, `startedAtMs`, `finishedAtMs`, `durationMs`, `roots`, `exclusions`, `config`, `totals`, `candidates`, `directorySummaries`, `issues`, `log`, `truncation` | 完整扫描结果 |
| `ScanCandidate` | `id`, `file`, `directoryContext`, `discovery`, `peMetadata`, `signature`, `msiMetadata`, `metadataIssues` | 候选证据，不含风险等级/推荐状态 |
| `FileInfo` | `path`, `fileName`, `extension`, `size`, 创建/修改/访问时间、属性标志、`identity` | 只读文件属性 |
| `FileIdentity` | `volumeSerial`, `fileId`, `size`, 创建/修改时间、`readError` | 文件身份快照，供后续清理前复核；不是候选 ID |
| `DiscoveryEvidence` | 目录/文件名匹配、版本号、扩展名、`reasons` | 可解释的候选理由 |
| `PeMetadata` | ProductName/Version、FileDescription、CompanyName、FileVersion、OriginalFilename、InternalName、语言/代码页、`readError` | 缺失允许 |
| `SignatureInfo` | `signaturePresent`, `structureValid`, `signerCertificateFound`, `trustStatus`, `chainStatus`, `signerSubject/Issuer`, `publisherCommonName/Organization`, `isSelfSigned`, `errorCode`, `diagnostic` | 区分签名存在、结构、信任、证书链与发布者 |
| `MsiMetadata` | PackageType、ProductName/Version、Manufacturer、ProductCode、UpgradeCode、PackageCode、Summary、PatchCodes、`readError` | MSI/MSP |
| `InstalledSoftware` | DisplayName/Version、Publisher、InstallLocation、UninstallString、InstallDate、hive/view、ProductCode、`isMsi`、SystemComponent、ReleaseType、ParentKeyName | 只读注册表 |
| `ScanIssue` | `kind`, `code`, `message`, `path`, `recoverable` | 结构化错误/跳过记录 |
| `ScanLogEvent` | `timestampMs`, `level`, `event`, `message`, `path` | 结构化日志 |
| `DirectorySummary` | 路径、提示、文件/子目录/候选数、跳过的重解析点 | 后续目录分析基础 |

候选 ID 使用规范化 Windows 路径身份的 SHA-256 截断值（前 16 字节、32 位十六进制），跨运行稳定；路径身份由 `PathKey` 组件键表示，大小写使用 Windows `LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE)`，最终候选按路径排序保证可重复。

候选 ID 只代表“路径身份”，**不是文件身份**。同一文件经硬链接暴露为两个路径时会有两个不同候选 ID，但 `FileIdentity` 的卷序列号与文件 ID 相同。`FileIdentity` 为后续清理阶段预留“文件是否被替换”的复核能力。

## 四、安全边界

1. **路径规范化与组件边界**
   - 所有路径先绝对化，目录再 `canonicalize`。
   - 受保护/排除判定使用 `PathKey` 组件键 + 组件边界，不用字符串前缀；`C:\Program Files Backup` 不属于 `C:\Program Files`。
   - 大小写语义统一使用 Windows `LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE)`；路径规范化、边界比较、排除/受保护判断、visited 集合与候选 ID 共用同一规则。
   - `PathKey` 支持盘符路径、UNC、`\\?\`/`\\?\UNC\`、`\\.\`、长路径、中文/日文/特殊字符；测试覆盖大小写变体。

2. **受保护目录**
   - `C:\Windows` 及其 `System32`、`WinSxS`、`Installer`、`SoftwareDistribution`、`SystemApps`、`System32\DriverStore`。
   - `C:\ProgramData\Microsoft`、`C:\ProgramData\Package Cache`。
   - `Program Files\WindowsApps`、`Program Files (x86)\WindowsApps`。
   - `$Recycle.Bin`、`System Volume Information`、`Recovery`、`Windows.old`、`Config.Msi`。
   - 受保护目录不能作为扫描根；遍历中遇到时跳过并记录日志。

3. **重解析点**
   - 使用 `GetFileAttributesW` 的 `FILE_ATTRIBUTE_REPARSE_POINT` 与 `symlink_metadata` 双重判定。
   - 不进入 symlink/junction/mount point；不读取链接目标。
   - 已访问目录集合防止循环。

4. **只读保证**
   - 扫描、元数据、签名、MSI、注册表模块不包含写入、删除、移动、回收站或提权调用。
   - MSI 通过纯 Rust 解析，不调用安装服务。
   - 签名验证使用 `WTD_UI_NONE` + `WTD_CACHE_ONLY_URL_RETRIEVAL`，不弹窗、不联网。

5. **候选不等于可清理**
   - 文件名、目录名、扩展名、大小、时间均只作为发现证据。
   - 本阶段没有风险等级、推荐清理、清理计划或删除入口；这些在后续阶段单独实现。

## 五、测试与执行结果

### 5.1 测试统计

| 测试集 | 数量 | 结果 |
| --- | --- | --- |
| Rust 单元测试（`src-tauri/src`） | 39 | 通过 |
| 数据库集成测试 | 1 | 通过 |
| 扫描引擎集成测试（`tests/scanner.rs`） | 18 | 通过 |
| Windows API 集成测试 | 1 | 通过 |
| 合计（常规） | **59** | **全部通过** |
| 性能测试（`tests/performance.rs`，默认 ignored） | 1 | 单独运行通过 |
| 真实目录测试（`tests/real_scan.rs`，默认 ignored） | 1 | 单独运行通过 |

### 5.2 扫描测试用例

| 用例 | 验证点 | 结果 |
| --- | --- | --- |
| `scans_update_directory_and_reads_pe_metadata` | updater 目录、普通 EXE 排除、PE 版本、无签名、目录摘要 | 通过 |
| `scans_msi_and_msp_metadata` | MSI ProductName/Version、MSP PackageType=Patch | 通过 |
| `ordinary_directory_does_not_produce_candidates` | 普通目录不因扩展名产生候选 | 通过 |
| `exclusion_skips_candidate_directory` | 排除目录生效、跳过计数 | 通过 |
| `corrupt_exe_is_reported_without_crashing_scan` | 损坏 EXE 仍记录候选与元数据问题，扫描完成 | 通过 |
| `progress_reports_start_finalize_and_counts` | Preparing→Finalizing、文件/候选计数 | 通过 |
| `cancellation_returns_a_report_and_releases_threads` | 取消返回报告、线程退出 | 通过 |
| `cancellation_during_metadata_finishes_without_deadlock` | 元数据 worker 取消无死锁 | 通过 |
| `junction_is_not_followed` | Junction 不跟随、跳过计数/日志 | 通过 |
| `symlink_is_not_followed_if_creation_is_allowed` | Symbolic Link 不跟随 | 通过 |
| `long_path_can_be_scanned` | 超过 260 字符路径可扫描 | 通过 |
| `inaccessible_directory_is_recorded_and_scan_continues` | 独占目录句柄导致访问失败，记录问题并继续其他目录 | 通过 |
| `junction_loop_is_not_followed` | 指向自身的 junction 不导致循环 | 通过 |
| `scan_results_are_repeatable` | 两次扫描的候选 ID/路径一致 | 通过 |
| `preset_roots_resolve_without_scanning` | 预设根解析、存在性校验（不扫描） | 通过 |
| `candidate_ids_are_stable_across_root_casing` | 大小写不同扫描根的候选 ID 一致 | 通过 |
| `unicode_path_is_candidate_and_id_is_stable` | 中文/空格路径候选、重复扫描 ID 一致 | 通过 |
| `candidate_id_is_not_file_identity_for_hardlinks` | 硬链接的两个路径 ID 不同、卷/文件 ID 相同 | 通过 |

### 5.3 其他测试

- `metadata::msi`：安装包/补丁包/损坏文件 3 个用例通过。
- `metadata::pe_version`：版本资源、无版本资源 2 个用例通过。
- `signature`：未签名、自签名（解析发布者但不信任）、损坏 PE 3 个用例通过。
- `software`：ProductCode 识别、真实注册表只读冒烟通过。
- `protection`：路径边界、大小写语义、中文/日文/特殊字符、UNC/verbatim、长路径、盘符根、受保护根、重解析点、词法规范化。
- `utils::windows_api`：文件身份稳定、大小写路径解析到同一卷/文件 ID。
- `signature`：未签名、自签名、篡改签名、损坏 PE、受信任系统二进制；叶证书按 SignerIdentifier 匹配。
- `scanner::discovery`：目录/文件名/版本号/普通 EXE 7 个用例通过。

### 5.4 Tauri 应用内验证

通过 WebView2 调试协议在真实桌面应用中调用：

```text
start_scan(customRoots=[tests/fixtures/software-b])
  → status = completed
  → directories=3, files=3, candidates=2
  → PixPin_2.0.0.3.exe: PE ProductName=UpSweep Fixture, trustStatus=notSigned, signaturePresent=false
  → PixPin_2.0.0.3.msi: MSI ProductName=PixPin, ProductVersion=2.0.0.3
  → directorySummaries=2, issues=0
  → candidate.id 长度 32（SHA-256 前 16 字节）
  → FileIdentity: volumeSerial/fileId 均存在，readError=null
  → PE signaturePresent=false, structureValid=false, trustStatus=notSigned
  → MSI signaturePresent=false, structureValid=null, trustStatus=notSigned
  → logEvents: custom_root_added, scan_plan_ready, scan_started, scan_finished
get_installed_software()
  → items=282, scannedKeys=330, issues=0
consoleErrors = 0
```

调试端口仅通过临时 `--config` 启用，未写入项目配置。

### 5.5 Release 构建

`npm run tauri build -- --no-bundle` 通过：

```text
Finished `release` profile [optimized] target(s) in 5m 11s
产物：src-tauri/target/release/upsweep.exe
大小：6,855,168 字节（约 6.5 MiB）
启动观察 5 秒：进程保持运行
```

### 5.6 性能数据

合成目录：50 个 `updater` 目录 × 5 个候选 EXE + 100 个普通目录 × 10 个文件。

```text
status=Completed
directories=201
files=1250
candidates=250
metadata=250
signatures=250
elapsed_ms=322–641（路径键 + 文件身份读取后，受缓存/负载影响）
files_per_sec=1,949–3,877
```

环境：Windows 11、debug 构建、元数据 worker 上限 4、版本资源 PE 夹具。该数据仅用于阶段 1 基线，不代表 release 或真实大型目录性能；冷缓存首轮明显更慢。加入 Windows 路径键与文件身份读取后，本机多次测量为约 322–641 ms（1,949–3,877 文件/秒），仍为纯读扫描；差异来自文件缓存与系统负载。

### 5.7 真实软件目录只读扫描

测试目录：`C:\Program Files (x86)\Microsoft\EdgeUpdate`（只读，未修改任何文件）。

```text
REAL_SCAN root=C:\Program Files (x86)\Microsoft\EdgeUpdate
dirs=16 files=109 candidates=14
PE 元数据成功=14/14
MSI/MSP 元数据成功=0/0（该目录没有 MSI/MSP）
签名读取=14，有效=14，未签名=0
issues=0
elapsed_ms=1029
workingset before=14.4 MB, after=20.2 MB, peak=204.2 MB
```

取消响应：同一目录第二次只读扫描，启动后 5 ms 取消，`status=Cancelled`，从取消调用到线程 join 返回约 **6–22 ms**，已保留 2 个完成候选。高峰工作集包含测试进程的峰值，不代表扫描单独占用；实际扫描增量约 6 MB 工作集。

## 六、已知限制

1. **尚未实现扫描 UI**：阶段 1 只提供后端命令与事件；页面交互属于阶段 4。
2. **遍历为单线程**：元数据 worker 并发，目录枚举本身串行；大型 `Program Files` 扫描可能耗时较长，需依赖取消。
3. **候选发现偏保守**：没有更新目录提示、没有安装/更新文件名特征、没有版本号的随机命名 EXE 不会被列为候选；这是安全取舍。
4. **签名者匹配**：按 CMS SignerIdentifier 的 issuer + serial 匹配叶证书；SubjectKeyIdentifier 签名者暂不匹配，返回无发布者/Unknown，不猜测。发布者字段仅来自匹配到的叶证书。
5. **MSI 发布者**：MSI 签名证书结构未解析；发布者优先使用 MSI Manufacturer 字段。
6. **受信任签名测试依赖系统文件**：有效签名测试读取 `C:\Windows\System32\kernel32.dll`（只读），不修改系统信任存储；自签名/篡改签名使用独立夹具。
7. **无网络吊销检查**：`WTD_CACHE_ONLY_URL_RETRIEVAL` 只使用本地缓存；离线或缓存缺失时可能返回 Unknown，不能据此断言签名有效或无效。
8. **TOCTOU**：文件在属性检查与元数据读取之间可能被替换；阶段 1 只读，后续清理阶段必须在执行前重新校验 `FileIdentity`（卷/文件 ID、大小、时间）。
9. **路径身份不是文件身份**：同一文件经硬链接/不同路径会有不同候选 ID；候选 ID 只用于路径级选择，清理前必须用 `FileIdentity` 复核。
10. **注册表只读测试**：没有写入注册表夹具；测试只验证解析/容错与真实只读读取，不验证特定软件条目。
11. **默认扫描范围较大**：包含 Program Files/AppData，首次全量扫描可能很慢；后续阶段可提供范围预设与排除管理。
12. **日志/问题上限**：各 5,000 条，超出后设置截断标志；候选列表不截断。

## 七、修改文件

### 新增

```text
src-tauri/src/scanner/{mod.rs,plan.rs,engine.rs,discovery.rs,manager.rs}
src-tauri/src/metadata/{mod.rs,pe_version.rs,msi.rs}
src-tauri/src/signature/mod.rs
src-tauri/src/software/mod.rs
src-tauri/src/protection/mod.rs
src-tauri/src/models/scan.rs
src-tauri/src/commands/scan.rs
src-tauri/src/utils/time.rs
src-tauri/tests/scanner.rs
src-tauri/tests/performance.rs
src-tauri/tests/real_scan.rs
src-tauri/examples/make-fixture-msi.rs
tests/fixtures/metadata/{plain.exe,versioned.exe,signed-self.exe,signed-tampered.exe,corrupt.exe}
tests/fixtures/metadata/src/{plain.c,versioned.rc}
tests/fixtures/software-a/...
tests/fixtures/software-b/...
tests/fixtures/software-c/...
tests/fixtures/software-d/...
tests/fixtures/software-e/...
tests/fixtures/paths/中文 空格/安装程序_2.0.0.1.exe
tests/fixtures/protected/Windows/installer.exe
tests/fixtures/normal/app.exe
docs/PHASE-1.md
```

### 修改

```text
src-tauri/Cargo.toml（authenticode/object/msi/cms/x509-cert/sha2、windows-sys 新特性）
src-tauri/Cargo.lock
src-tauri/src/lib.rs（模块注册、ScanManager、命令注册）
src-tauri/src/commands/mod.rs
src-tauri/src/models/mod.rs
src-tauri/src/utils/mod.rs
src-tauri/src/utils/windows_api.rs（文件身份、PE32 签名路径等）
README.md
CHANGELOG.md
docs/{ARCHITECTURE,TESTING,ENVIRONMENT}.md
tests/fixtures/README.md
```

## 八、下一阶段

阶段 1 完成，等待验收。**未开始**阶段 2/3/4；不包含风险判断、清理计划、文件修改或删除。
