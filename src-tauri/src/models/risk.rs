//! 阶段 2 风险判断数据结构。
//!
//! 风险判断只读取扫描报告、已安装软件信息和文件占用状态；不包含清理计划、
//! 文件移动、删除或回收站操作。

use serde::Serialize;

use super::SignatureStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RiskLevel {
    Recommended,
    NeedsConfirmation,
    NotRecommended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IdentityConfidence {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VersionRelation {
    CandidateOlder,
    Equal,
    CandidateNewer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileUsageStatus {
    NotDetected,
    InUse,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskReason {
    pub code: String,
    /// protection / ownership / version / signature / usage / directory / metadata
    pub category: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftwareMatch {
    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub product_code: Option<String>,
    pub registry_hive: String,
    pub registry_view: String,
    pub confidence: IdentityConfidence,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskEvidence {
    pub installer_like: bool,
    pub installer_signal_strong: bool,
    pub strong_update_directory: bool,
    pub unregistered_updater_context: bool,
    pub update_service_like: bool,
    pub patch_like: bool,
    pub rollback_or_repair: bool,
    pub updater_component: bool,
    pub protected_path: bool,
    pub active_updater: bool,
    pub in_install_location: bool,
    pub update_like_directory: bool,
    pub publisher_match: Option<bool>,
    pub product_match: Option<bool>,
    pub path_match: bool,
    pub product_code_match: bool,
    pub candidate_version: Option<String>,
    pub installed_version: Option<String>,
    pub version_relation: VersionRelation,
    pub signature_present: Option<bool>,
    pub signature_trust: Option<SignatureStatus>,
    pub signature_bad: bool,
    pub metadata_complete: bool,
    pub metadata_conflict: bool,
    pub file_usage: FileUsageStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    pub candidate_id: String,
    pub path: String,
    pub file_name: String,
    pub risk_level: RiskLevel,
    pub default_selected: bool,
    pub selectable: bool,
    pub confidence: IdentityConfidence,
    pub matched_software: Option<SoftwareMatch>,
    pub evidence: RiskEvidence,
    pub reasons: Vec<RiskReason>,
    pub warnings: Vec<RiskReason>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskSummary {
    pub total: u64,
    pub recommended: u64,
    pub needs_confirmation: u64,
    pub not_recommended: u64,
    pub recommended_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskReport {
    pub session_id: String,
    pub generated_at_ms: u64,
    pub software_count: u64,
    pub summary: RiskSummary,
    pub assessments: Vec<RiskAssessment>,
    pub global_warnings: Vec<RiskReason>,
}
