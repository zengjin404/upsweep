# 阶段 2 实施记录：风险判断引擎

> 记录日期：2026-11-16
> 状态：**已完成，等待验收**。基于阶段 1 扫描报告进行可解释风险分类；不实现清理计划、文件移动、删除、回收站或目录清理。

## 一、开始前核查

### 1.1 PathKey 与 Windows 路径比较语义

- 现有 `PathKey` 使用 Windows `LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE)` 生成组件键。
- 新增测试 `path_key_agrees_with_compare_string_ordinal`，与 `CompareStringOrdinal(..., bIgnoreCase=TRUE)` 对照：
  - 大小写不同路径；
  - 中文、日文、`ÄÖÜ`、`Ω` 等非 ASCII；
  - `ß` 与 `SS`、土耳其 `İ` 与 `i` 等特殊字符；
  - 组件边界相似路径。
  - 测试覆盖的字符集上，两种 Windows 原生语义一致。
- 仍存在一个实际差异：**NTFS 目录级大小写敏感**。启用该标志的目录不能用大小写不敏感键折叠。已处理：
  - `GetFileInformationByHandleEx(FileCaseSensitiveInfo)` 检测目录标志；
  - 扫描器遇到启用目录级大小写敏感的目录时**保守跳过**并记录 `case_sensitive_directory_skipped`；
  - `ScanTotals.skippedCaseSensitive` 计数；
  - 新增测试启用该标志并确认目录被跳过。
- 因此扫描范围内继续统一使用 `PathKey`：路径比较、排除/受保护判断、visited 集合和候选 ID 使用同一语义。

### 1.2 更新器目录风险

- 不把 `updater`、`update`、`cache`、`packages` 目录名直接当作残留证据。
- 新增硬保护：
  - 已安装软件中名称/发布者含 `update`/`updater`/`maintenance service` 的更新器安装目录；
  - 已知活动更新器路径：`\EdgeUpdate\`、`\GoogleUpdate\`、`\Microsoft\EdgeUpdate`；
  - 文件名/PE 元数据表明是 updater / update service 组件的文件。
- 真实 EdgeUpdate 扫描的 14 个候选全部被判为 `NotRecommended`，包括 `CopilotUpdate.exe`、`MicrosoftEdgeUpdate*.exe` 和下载缓存中的旧 Edge 安装包。目录名本身没有触发推荐。

## 二、模块与数据结构

```text
analyzer/matching.rs   候选与已安装软件匹配、名称规范化、版本比较
analyzer/rules.rs      硬保护、安装包特征、更新器识别、风险分类、理由
analyzer/mod.rs        RiskReport 汇总、全局限制说明
models/risk.rs         风险等级、证据、理由、评估与报告
commands/analyze.rs    analyze_scan 命令（spawn_blocking）
```

| 结构 | 说明 |
| --- | --- |
| `RiskLevel` | `Recommended` / `NeedsConfirmation` / `NotRecommended` |
| `RiskAssessment` | 候选 ID/路径、风险等级、默认勾选、可选择、置信度、软件匹配、证据、理由、警告 |
| `RiskEvidence` | 安装包特征、强/弱证据、受保护、活动更新器、安装目录、版本关系、签名、元数据、占用状态 |
| `SoftwareMatch` | 匹配到的已安装软件、置信度、匹配原因 |
| `RiskSummary` | 总数、推荐/确认/不建议数量、推荐项总大小 |
| `RiskReport` | 扫描 session、软件数量、汇总、逐项评估、全局限制 |

## 三、风险等级判定

### 3.1 推荐清理（默认勾选）

必须同时满足：

1. 不在受保护路径、活动更新器目录或软件安装目录内；
2. **不在 updater/update/cache/download/packages 等更新目录内**（更新状态不明，最多需要确认）；
3. 文件占用检测为 `NotDetected`（仅表示本次未检测到共享冲突，不是“绝对未使用”的证明）；
4. 存在强安装包信号（MSI/MSP、文件名或 PE 原始文件名/内部名/描述包含 installer/setup/update/upgrade/patch/package）；
5. 与已安装软件达到 **High** 置信度匹配：
   - MSI ProductCode 一致；或
   - 产品名称完全匹配 + 发布者/签名发布者/安装路径至少一项一致；
6. 候选版本低于已安装版本（辅助证据，不是唯一依据）；
7. 无元数据冲突、无无效/不受信任签名、无未知占用状态、不是补丁/回滚/修复包、不是未登记更新器上下文。

输出 `defaultSelected=true`、`selectable=true`。

### 3.2 需要确认（默认不勾选）

包括：

- 位于软件安装目录的更新子目录（无法确认活动更新器是否仍在使用）；
- 位于 updater/update/cache/download/packages 等更新目录（无法证明不属于活动更新流程）；
- PE 元数据表明文件属于 Update Service / Maintenance Service，而不是独立安装包；
- MSP/补丁、rollback/backup/restore/repair 命名或元数据；
- 未登记的更新器目录特征（路径组件以 updater/edgeupdate/googleupdate 结尾）；
- 软件归属未匹配、低置信度或存在歧义；
- 产品名称/发布者冲突（包括 MSI ProductCode 相同但元数据冲突）；
- 签名无效、不受信任、过期、吊销或未知；
- 文件占用状态无法确认（含权限不足；普通非保护目录 → 需要确认；受保护目录由硬规则判为不建议）；
- 候选版本等于/高于已安装版本，或版本无法比较；
- 元数据缺失、损坏，或位于更新目录但无法确认是否为安装包；
- 软件已卸载且无法确认残留归属。

输出 `defaultSelected=false`、`selectable=true`。

### 3.3 不建议清理（普通流程不可选择）

包括：

- 受保护路径（Windows、System32、WinSxS、Installer、SoftwareDistribution、DriverStore、ProgramData\Microsoft、Package Cache、WindowsApps、回收站、系统卷信息等）；
- 文件被占用（共享冲突）；
- 活动更新器安装/缓存目录（含 EdgeUpdate、GoogleUpdate、已安装更新器目录）；
- updater/update service 组件自身；
- 软件主安装目录或非更新子目录中的文件；
- 未发现安装包特征且不在更新目录中的普通 EXE/组件；
- 元数据缺失且没有更新目录背景的普通文件。

输出 `defaultSelected=false`、`selectable=false`。

### 3.4 各等级主要误判风险

- **推荐清理**：静态扫描无法证明更新已完成，可能把回滚包/待安装包误判为旧包。缓解：要求 High 归属、旧版本、强安装包/更新目录证据、未占用、不在安装目录/活动更新器，且仍不直接删除。
- **需要确认**：可能把本可安全清理的项目降级，造成漏判；这是有意的安全取舍。
- **不建议清理**：活动更新器路径/更新器组件/安装目录/占用检测可能偏保守，导致部分真实残留被保留；不会造成误删。

## 四、软件关联与冲突处理

- 关联证据：MSI ProductCode、产品名称、发布者、签名发布者、安装目录路径、版本。
- 仅发布者相同不足以关联软件。
- 不同发布者 + 相同产品名称 → 冲突，最多需要确认。
- 相同发布者 + 不同产品 → 不关联，最多需要确认。
- MSI ProductCode 相同但产品名称/发布者冲突 → 仍降级为需要确认，不因 ProductCode 直接推荐。
- 多个软件同等匹配 → 歧义，置信度 Low，需要确认。
- 产品名称只部分匹配（如 Edge / Edge Update）→ 最多 Medium，不满足推荐条件。
- 版本比较只接受数字段；无法解析或缺失 → Unknown → 需要确认。

## 五、文件占用判断

- `NotDetected` 仅表示本次独占打开没有遇到共享冲突，不等于“文件绝对未被使用”。
- `InUse`：共享冲突，判定为可能正在使用，不建议清理。
- `Unknown`：权限不足、文件不存在、其他打开错误；阻止推荐。普通非保护目录归入需要确认；若同时命中受保护/活动更新器/安装目录等更高优先级硬规则，最终等级由硬规则决定（例如 `C:\System Volume Information` 的 Unknown 最终是不建议清理，因为受保护路径规则先执行）。
- 只有 `NotDetected` 才允许继续考虑推荐；它不是正面用途证据，只是没有发现冲突。
- 该方法是启发式，不列出占用进程，也不能证明文件未被使用；已在全局警告中说明。

## 六、测试与结果

### 6.1 测试统计

计数说明：安全复核前分析器测试为 **16 项**；第一次安全复核新增 **9 项**（上一份报告列出的第 10 个名称 `older_installer_in_update_directory_needs_confirmation...` 是原 `older_installer_outside_install_directory_is_recommended` 的改名/改判，不是新增测试）；本次最终核对新增 **1 项**（Update Service 下载目录测试），当前 **26 项**，累计新增 10 项。

| 测试集 | 数量 | 结果 |
| --- | --- | --- |
| Rust 单元测试 | 45 | 通过 |
| 分析器集成测试（`tests/analyzer.rs`） | 26 | 通过 |
| 扫描引擎集成测试 | 19 | 通过 |
| 数据库 + Windows API 集成测试 | 2 | 通过 |
| 常规测试合计 | **92** | **全部通过** |
| 性能/真实目录测试（默认 ignored） | 2 | 单独运行通过 |

分析器覆盖：

- 更新目录（updater/cache/download）内的旧版本安装包 → 需要确认，不自动推荐；
- 普通下载目录中的 EXE、PE 描述为 “Update Service”、版本低于已安装版本 → 需要确认；`update_service_like` 阻止推荐，但不把所有包含 update 的文件硬保护；
- 非更新目录的独立旧安装包 → 在 High 归属、强安装包信号、未占用、版本较低时推荐；
- 新版本/同版本 → 需要确认；
- 有效签名旧安装包 → 推荐；有效签名但无法归属 → 需要确认；
- 无签名旧安装包 → 在强证据下推荐，并输出无签名警告；
- 无效签名 → 需要确认；
- MSP/补丁、rollback/repair 命名 → 需要确认；
- 未登记的更新器路径 → 需要确认；路径关键词相似但非更新器 → 不误保护（可推荐）；
- 更新器自身文件 → 不建议；
- EdgeUpdate 活动安装/缓存目录 → 不建议；
- 软件安装目录主文件 → 不建议；安装目录更新子目录 → 需要确认；
- 文件被占用 → 不建议；占用 Unknown（含权限不足）→ 需要确认；权限不足不得当作 NotDetected；
- 普通 EXE → 不建议；
- 软件已卸载残留 → 需要确认；
- 不同发布者同产品名 → 需要确认（冲突）；
- 相同发布者不同产品 → 需要确认（未关联）；
- 缺失/损坏元数据 → 需要确认；
- MSI ProductCode 匹配旧安装包 → 推荐；ProductCode 相同但产品/发布者冲突 → 需要确认；
- 多个已安装软件同等匹配 → 需要确认（低置信度）；
- 受保护路径 → 不建议；
- 默认勾选/可选择状态符合等级定义。

### 6.2 真实 EdgeUpdate 分析

真实目录：`C:\Program Files (x86)\Microsoft\EdgeUpdate`。

```text
扫描：16 目录 / 109 文件 / 14 候选
PE 元数据：14/14
签名：14/14 本地验证有效
风险：推荐 0，需要确认 0，不建议 14
```

被硬保护的文件包括 `CopilotUpdate.exe`、`MicrosoftEdgeUpdate*.exe`、`MicrosoftEdge_X64_*.exe`、`MicrosoftEdgeUpdateSetup_X86_*.exe` 等。它们均位于已知活动更新器目录，目录名没有单独触发推荐。

夹具 `software-b` 的 PixPin 安装包/MSI 因本机没有对应已安装软件记录，被判为需要确认（未匹配到软件归属）。

### 6.3 构建与命令

- `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings` 通过。
- `npm test` 3/3、`npm run build` 通过。
- 新增 Tauri 命令 `analyze_scan(sessionId)`，对已完成扫描报告执行分析。
- `analyze_scan` 在真实应用内通过 IPC 调用验证。
- Release 构建：`tauri build --no-bundle` 通过（2m39s），`upsweep.exe` 6,944,256 字节，启动后保持运行。

## 七、误判风险与已知限制

1. **静态判断无法知道更新是否完成**：因此 updater/update/cache/download/packages 目录内一律最多“需要确认”，不会因版本较低自动推荐。
2. **活动更新器识别依赖已知路径、已安装记录和 updater 文件特征**：未登记更新器路径按 unregistered updater context 降级为需要确认；不保证覆盖所有第三方更新器。
3. **文件占用为启发式**：`NotDetected` 只是没有检测到共享冲突，不是未被使用的证明；Unknown 会阻止推荐。
4. **版本比较只处理数字段**：渠道/构建元数据不参与比较；版本较低只是辅助证据，且更新目录内不作为推荐条件。
5. **发布者匹配为规范化文本匹配**：名称不规范、空发布者、同名不同厂商会产生冲突/需要确认。
6. **MSI 签名结构未解析**：MSI 发布者使用 Manufacturer；签名状态由 WinVerifyTrust 提供。
7. **签名有效不等于可清理**：有效签名只用于归属证据，不作为清理条件；无签名也不单独阻止或触发推荐。
8. **NTFS 目录级大小写敏感目录被保守跳过**：避免大小写不敏感键折叠，但会漏扫这些目录。
9. **安装目录登记可能缺失/带引号/不存在**：路径匹配失败时只能依据产品/发布者，推荐条件更严格。
10. **不包含目录级孤立目录分析**：本阶段只判断文件；目录计划属于阶段 5。
11. **无在线吊销检查**：WinVerifyTrust 仅本地缓存验证。
12. **风险等级不是删除授权**：推荐项仍需后端复核和用户确认；本阶段没有清理入口。

## 八、下一阶段

阶段 2 完成，等待验收。未进入阶段 3/4，未实现清理计划、文件移动、删除、回收站或目录清理。
