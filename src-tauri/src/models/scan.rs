//! 扫描引擎的前后端数据结构。
//!
//! 阶段 1 只描述“发现了什么、证据是什么、读取成功还是失败”，
//! 不包含风险等级、推荐清理或删除计划；这些属于后续阶段。

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// 前端发起的扫描请求。路径由后端解析和校验，前端不能直接指定删除目标。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    #[serde(default = "default_true")]
    pub include_default_roots: bool,
    #[serde(default)]
    pub custom_roots: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default = "default_true")]
    pub include_metadata: bool,
    #[serde(default = "default_true")]
    pub include_signature: bool,
    #[serde(default = "default_true")]
    pub include_msi: bool,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            include_default_roots: true,
            custom_roots: Vec::new(),
            excluded_paths: Vec::new(),
            max_depth: None,
            include_metadata: true,
            include_signature: true,
            include_msi: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanStatus {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanPhase {
    Preparing,
    Enumerating,
    ReadingMetadata,
    Finalizing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanRootSource {
    LocalAppData,
    RoamingAppData,
    ProgramData,
    ProgramFiles,
    ProgramFilesX86,
    Custom,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRootInfo {
    pub path: String,
    pub source: ScanRootSource,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanExclusionInfo {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSessionInfo {
    pub session_id: String,
    pub started_at_ms: u64,
    pub roots: Vec<ScanRootInfo>,
    pub exclusions: Vec<ScanExclusionInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub session_id: String,
    pub phase: ScanPhase,
    pub scanned_directories: u64,
    pub scanned_files: u64,
    pub candidates_found: u64,
    pub metadata_read: u64,
    pub signatures_read: u64,
    pub skipped_reparse_points: u64,
    pub skipped_protected: u64,
    pub skipped_excluded: u64,
    pub errors: u64,
    pub current_path: Option<String>,
    pub elapsed_ms: u64,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLogEvent {
    pub timestamp_ms: u64,
    pub level: LogLevel,
    pub event: String,
    pub message: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanIssueKind {
    DirectoryAccess,
    FileAccess,
    Metadata,
    Registry,
    PathValidation,
    ReparsePointSkipped,
    ProtectedPathSkipped,
    ExcludedPathSkipped,
    MaxDepthReached,
    LoopDetected,
    Cancelled,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanIssue {
    pub kind: ScanIssueKind,
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub recoverable: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTotals {
    pub directories: u64,
    pub files: u64,
    pub candidates: u64,
    pub metadata_read: u64,
    pub signatures_read: u64,
    pub skipped_reparse_points: u64,
    pub skipped_protected: u64,
    pub skipped_excluded: u64,
    pub skipped_max_depth: u64,
    pub skipped_case_sensitive: u64,
    pub errors: u64,
    pub warnings: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTruncation {
    pub issues_truncated: bool,
    pub log_truncated: bool,
    pub dropped_issues: u64,
    pub dropped_log_events: u64,
}

/// 文件身份快照，供后续清理阶段在确认后复核文件是否被替换。
///
/// 这不是权限凭据，也不参与候选 ID；候选 ID 只代表规范化路径身份。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileIdentity {
    pub volume_serial: Option<u32>,
    pub file_id: Option<u64>,
    pub size: u64,
    pub created_at_ms: Option<u64>,
    pub modified_at_ms: Option<u64>,
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub path: String,
    pub file_name: String,
    pub extension: Option<String>,
    pub size: u64,
    pub created_at_ms: Option<u64>,
    pub modified_at_ms: Option<u64>,
    pub accessed_at_ms: Option<u64>,
    pub attributes: u32,
    pub is_reparse_point: bool,
    pub is_read_only: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub is_archive: bool,
    pub identity: FileIdentity,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryContext {
    pub scan_root: String,
    pub relative_directory: String,
    pub directory_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryEvidence {
    pub matched_directory_hints: Vec<String>,
    pub matched_filename_hints: Vec<String>,
    pub has_version_token: bool,
    pub supported_extension: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeMetadata {
    pub present: bool,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub file_description: Option<String>,
    pub company_name: Option<String>,
    pub file_version: Option<String>,
    pub original_filename: Option<String>,
    pub internal_name: Option<String>,
    pub language: Option<String>,
    pub codepage: Option<String>,
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SignatureStatus {
    Valid,
    NotSigned,
    Invalid,
    UntrustedRoot,
    Expired,
    Revoked,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChainStatus {
    Valid,
    UntrustedRoot,
    Expired,
    Revoked,
    Invalid,
    NotChecked,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    /// PE 是否存在 Authenticode 证书表；MSI 未解析时为 None。
    pub signature_present: Option<bool>,
    /// 证书表能否解析为有效的 PKCS#7/Authenticode 结构；MSI 为 None。
    pub structure_valid: Option<bool>,
    /// 是否通过 SignerIdentifier 正确匹配到签名者叶证书。
    pub signer_certificate_found: bool,
    /// WinVerifyTrust 的信任判定。
    pub trust_status: SignatureStatus,
    /// 证书链状态；NotChecked 表示未执行签名验证。
    pub chain_status: ChainStatus,
    pub signer_subject: Option<String>,
    pub signer_issuer: Option<String>,
    pub publisher_common_name: Option<String>,
    pub publisher_organization: Option<String>,
    pub is_self_signed: Option<bool>,
    pub error_code: Option<i32>,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MsiPackageType {
    Installer,
    Patch,
    Transform,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MsiMetadata {
    pub present: bool,
    pub package_type: MsiPackageType,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub manufacturer: Option<String>,
    pub product_code: Option<String>,
    pub upgrade_code: Option<String>,
    pub package_code: Option<String>,
    pub summary_title: Option<String>,
    pub summary_subject: Option<String>,
    pub summary_author: Option<String>,
    pub patch_codes: Vec<String>,
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataIssue {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCandidate {
    pub id: String,
    pub file: FileInfo,
    pub directory_context: DirectoryContext,
    pub discovery: DiscoveryEvidence,
    pub pe_metadata: Option<PeMetadata>,
    pub signature: Option<SignatureInfo>,
    pub msi_metadata: Option<MsiMetadata>,
    pub metadata_issues: Vec<MetadataIssue>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectorySummary {
    pub path: String,
    pub relative_path: String,
    pub directory_hints: Vec<String>,
    pub file_count: u64,
    pub subdirectory_count: u64,
    pub candidate_count: u64,
    pub skipped_reparse_points: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReportConfig {
    pub include_metadata: bool,
    pub include_signature: bool,
    pub include_msi: bool,
    pub max_depth: Option<u32>,
    pub concurrency: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub session_id: String,
    pub status: ScanStatus,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub duration_ms: u64,
    pub roots: Vec<ScanRootInfo>,
    pub exclusions: Vec<ScanExclusionInfo>,
    pub config: ScanReportConfig,
    pub totals: ScanTotals,
    pub candidates: Vec<ScanCandidate>,
    pub directory_summaries: Vec<DirectorySummary>,
    pub issues: Vec<ScanIssue>,
    pub log: Vec<ScanLogEvent>,
    pub truncation: ScanTruncation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledSoftware {
    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub uninstall_string: Option<String>,
    pub install_date: Option<String>,
    pub registry_hive: String,
    pub registry_view: String,
    pub key_name: String,
    pub product_code: Option<String>,
    pub is_msi: bool,
    pub system_component: bool,
    pub release_type: Option<String>,
    pub parent_key_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledSoftwareReport {
    pub items: Vec<InstalledSoftware>,
    pub issues: Vec<ScanIssue>,
    pub scanned_keys: u64,
}
