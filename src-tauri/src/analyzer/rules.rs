//! 规则约束的风险判断。
//!
//! 风险等级不是黑盒总分：所有推荐/确认/不建议都由可解释条件组合决定。
//! 任何单一证据（文件名、目录名、扩展名、大小、时间、签名状态）都不能单独
//! 触发“推荐清理”。

use std::path::{Path, PathBuf};

use crate::models::{
    FileUsageStatus, IdentityConfidence, InstalledSoftware, RiskAssessment, RiskEvidence,
    RiskLevel, RiskReason, ScanCandidate, SignatureStatus, SoftwareMatch, VersionRelation,
};
use crate::protection::{self, ProtectedPaths};
use crate::utils::windows_api::{self, FileUsageInfo};

use super::matching::{self, SoftwareCandidateMatch};

pub struct AssessmentContext<'a> {
    pub protected: &'a ProtectedPaths,
    pub software: &'a [InstalledSoftware],
    pub updater_locations: &'a [PathBuf],
}

pub fn assess(candidate: &ScanCandidate, context: &AssessmentContext<'_>) -> RiskAssessment {
    let identity = matching::candidate_identity(candidate);
    let mut reasons = Vec::new();
    let mut warnings = Vec::new();
    let path = Path::new(&candidate.file.path);

    let protected_match = context.protected.match_protected(path);
    let protected_path = protected_match.is_some();
    if let Some((protected_path_value, reason)) = protected_match {
        push_reason(
            &mut reasons,
            "PROTECTED_PATH",
            "protection",
            format!(
                "位于受保护目录 {}（{}），不允许普通清理流程选择",
                protected_path_value.display(),
                reason
            ),
        );
    }

    let usage = match windows_api::file_usage(path) {
        FileUsageInfo::NotInUse => FileUsageStatus::NotDetected,
        FileUsageInfo::InUse => FileUsageStatus::InUse,
        FileUsageInfo::Unknown(error) => {
            warnings.push(warning(
                "FILE_USAGE_UNKNOWN",
                "usage",
                format!("无法确认文件占用状态：{error}"),
            ));
            FileUsageStatus::Unknown
        }
    };
    if usage == FileUsageStatus::InUse {
        push_reason(
            &mut reasons,
            "FILE_IN_USE",
            "usage",
            "文件当前可能正在被其他进程使用，不允许清理".to_string(),
        );
    }

    let update_like_directory = is_update_like_directory(candidate);
    let installer_like = is_installer_like(candidate);
    let installer_signal_strong = has_strong_installer_signal(candidate);
    let strong_update_directory = has_strong_update_hint(candidate);
    let unregistered_updater_context = has_unregistered_updater_context(path);
    let update_service_like = has_update_service_metadata(candidate);
    let patch_like = is_patch_like(candidate);
    let rollback_or_repair = is_rollback_or_repair(candidate);
    let updater_component = is_updater_component(candidate);
    if installer_like {
        push_reason(
            &mut reasons,
            "INSTALLER_LIKE",
            "ownership",
            "存在安装包/升级包特征（扩展名、文件名、PE/MSI 元数据或更新目录）".to_string(),
        );
    } else {
        push_reason(
            &mut reasons,
            "NOT_INSTALLER_LIKE",
            "ownership",
            "未发现安装包/升级包特征，可能是普通程序或组件".to_string(),
        );
    }
    if update_like_directory {
        push_reason(
            &mut reasons,
            "UPDATE_LIKE_DIRECTORY",
            "directory",
            "所在目录具有更新/缓存/安装包特征".to_string(),
        );
    }

    let match_outcome = matching::find_software_match(candidate, context.software);
    let matched = match_outcome.matched.as_ref();
    let version_relation = matched
        .map(|value| {
            matching::compare_versions(
                identity.version.as_deref(),
                value.software.display_version.as_deref(),
            )
        })
        .unwrap_or(VersionRelation::Unknown);
    let known_updater_path = is_known_updater_path(path);
    let active_updater = known_updater_path
        || context
            .updater_locations
            .iter()
            .any(|location| protection::path_starts_with(path, location).unwrap_or(false));
    let install_location_owner = context
        .software
        .iter()
        .find(|item| path_under_install_location(path, item));

    let in_install_location = install_location_owner.is_some();
    let metadata_conflict = match_outcome
        .matched
        .as_ref()
        .is_some_and(|value| value.conflict)
        || !match_outcome.conflicts.is_empty();
    let metadata_complete = identity.metadata_complete;

    if let Some(value) = matched {
        push_reason(
            &mut reasons,
            "SOFTWARE_MATCH",
            "ownership",
            format!(
                "匹配到已安装软件“{}”（版本 {}，发布者 {}）",
                value.software.display_name,
                value.software.display_version.as_deref().unwrap_or("未知"),
                value.software.publisher.as_deref().unwrap_or("未知")
            ),
        );
        for reason in &value.reasons {
            push_reason(
                &mut reasons,
                "SOFTWARE_MATCH_DETAIL",
                "ownership",
                reason.clone(),
            );
        }
    } else {
        push_reason(
            &mut reasons,
            "NO_SOFTWARE_MATCH",
            "ownership",
            "未找到足以确认软件归属的已安装软件记录".to_string(),
        );
    }
    for conflict in &match_outcome.conflicts {
        warnings.push(warning("METADATA_CONFLICT", "metadata", conflict.clone()));
    }
    if !metadata_complete {
        warnings.push(warning(
            "METADATA_MISSING",
            "metadata",
            " PE/MSI 元数据缺失或无法读取，无法可靠确认软件归属".to_string(),
        ));
    }
    if updater_component {
        push_reason(
            &mut reasons,
            "UPDATER_COMPONENT",
            "directory",
            "文件本身具有更新器/更新服务组件特征，应视为活动更新组件".to_string(),
        );
    }
    if unregistered_updater_context {
        push_reason(
            &mut reasons,
            "UNREGISTERED_UPDATER_CONTEXT",
            "protection",
            "路径包含更新器目录特征，但未登记为已知/已安装更新器；更新状态未知".to_string(),
        );
    }
    if update_service_like {
        push_reason(
            &mut reasons,
            "UPDATE_SERVICE_METADATA",
            "directory",
            "PE 元数据表明文件属于 Update Service，而不是独立安装包".to_string(),
        );
    }
    if patch_like {
        push_reason(
            &mut reasons,
            "PATCH_PACKAGE",
            "version",
            "文件是 MSP 或 MSI Patch，可能是补丁/累积更新或回滚资源".to_string(),
        );
    }
    if rollback_or_repair {
        push_reason(
            &mut reasons,
            "ROLLBACK_OR_REPAIR",
            "version",
            "文件名/元数据表明可能是回滚、修复或恢复包".to_string(),
        );
    }
    if active_updater {
        push_reason(
            &mut reasons,
            if known_updater_path {
                "KNOWN_ACTIVE_UPDATER_PATH"
            } else {
                "ACTIVE_UPDATER_DIRECTORY"
            },
            "protection",
            "文件位于已知/已安装活动更新器的安装或缓存目录，属于更新维护数据".to_string(),
        );
    }
    if in_install_location {
        push_reason(
            &mut reasons,
            "IN_INSTALL_LOCATION",
            "directory",
            "文件位于已安装软件的安装目录范围内，默认高度谨慎".to_string(),
        );
    }
    if metadata_conflict {
        warnings.push(warning(
            "SOFTWARE_IDENTITY_CONFLICT",
            "metadata",
            "产品名称/发布者存在冲突，软件归属不能确认".to_string(),
        ));
    }
    if identity.signature_bad {
        warnings.push(warning(
            "SIGNATURE_BAD",
            "signature",
            "数字签名无效、不受信任或无法验证；不能作为可清理依据".to_string(),
        ));
    }
    if let Some(signature) = &candidate.signature {
        if signature.trust_status == SignatureStatus::NotSigned {
            warnings.push(warning(
                "SIGNATURE_ABSENT",
                "signature",
                "文件没有数字签名；无签名不等于可以清理".to_string(),
            ));
        } else if signature.trust_status == SignatureStatus::Valid {
            push_reason(
                &mut reasons,
                "SIGNATURE_VALID",
                "signature",
                "数字签名本地验证有效；签名有效不等于文件可清理".to_string(),
            );
        }
    }

    let evidence = RiskEvidence {
        installer_like,
        installer_signal_strong,
        strong_update_directory,
        unregistered_updater_context,
        update_service_like,
        patch_like,
        rollback_or_repair,
        updater_component,
        protected_path,
        active_updater,
        in_install_location,
        update_like_directory,
        publisher_match: matched.and_then(|value| value.publisher_match),
        product_match: matched.and_then(|value| value.product_match),
        path_match: matched.is_some_and(|value| value.path_match),
        product_code_match: matched.is_some_and(|value| value.product_code_match),
        candidate_version: identity.version.clone(),
        installed_version: matched.and_then(|value| value.software.display_version.clone()),
        version_relation,
        signature_present: candidate
            .signature
            .as_ref()
            .and_then(|value| value.signature_present),
        signature_trust: candidate.signature.as_ref().map(|value| value.trust_status),
        signature_bad: identity.signature_bad,
        metadata_complete,
        metadata_conflict,
        file_usage: usage,
    };

    let confidence = if match_outcome.ambiguous {
        IdentityConfidence::Low
    } else {
        matched
            .map(|value| value.confidence)
            .unwrap_or(IdentityConfidence::Unknown)
    };

    let risk_level = decide_risk(&mut reasons, &mut warnings, &evidence, matched, confidence);

    if risk_level == RiskLevel::Recommended {
        push_reason(
            &mut reasons,
            "RECOMMENDED",
            "risk",
            "综合证据支持清理，但执行前仍需后端复核与用户确认".to_string(),
        );
    } else if risk_level == RiskLevel::NeedsConfirmation {
        push_reason(
            &mut reasons,
            "NEEDS_CONFIRMATION",
            "risk",
            "证据不足或存在冲突，默认不勾选，需用户确认".to_string(),
        );
    } else {
        push_reason(
            &mut reasons,
            "NOT_RECOMMENDED",
            "risk",
            "存在硬性保护或用途不确定，不允许普通清理流程选择".to_string(),
        );
    }

    RiskAssessment {
        candidate_id: candidate.id.clone(),
        path: candidate.file.path.clone(),
        file_name: candidate.file.file_name.clone(),
        risk_level,
        default_selected: risk_level == RiskLevel::Recommended,
        selectable: risk_level != RiskLevel::NotRecommended,
        confidence,
        matched_software: matched.map(to_public_match),
        evidence,
        reasons,
        warnings,
    }
}

fn decide_risk(
    reasons: &mut Vec<RiskReason>,
    warnings: &mut Vec<RiskReason>,
    evidence: &RiskEvidence,
    matched: Option<&SoftwareCandidateMatch>,
    confidence: IdentityConfidence,
) -> RiskLevel {
    if evidence.protected_path {
        return RiskLevel::NotRecommended;
    }
    if evidence.file_usage == FileUsageStatus::InUse {
        return RiskLevel::NotRecommended;
    }
    if evidence.active_updater || evidence.updater_component {
        return RiskLevel::NotRecommended;
    }
    if evidence.in_install_location {
        // 软件安装目录内：主目录/非更新子目录直接不建议；更新子目录最多需要确认。
        if !evidence.update_like_directory {
            return RiskLevel::NotRecommended;
        }
        push_reason(
            reasons,
            "INSTALL_DIRECTORY_CAUTION",
            "directory",
            "文件位于软件安装目录的更新子目录中，无法确认更新器是否仍在使用".to_string(),
        );
        return RiskLevel::NeedsConfirmation;
    }
    if evidence.unregistered_updater_context
        || evidence.update_service_like
        || evidence.patch_like
        || evidence.rollback_or_repair
    {
        if evidence.update_like_directory {
            push_reason(
                reasons,
                "UPDATE_DIRECTORY_STATE_UNKNOWN",
                "directory",
                "位于更新/缓存/下载目录，无法证明不属于活动更新流程；默认需要确认".to_string(),
            );
        }
        return RiskLevel::NeedsConfirmation;
    }
    if !evidence.installer_like {
        if !evidence.metadata_complete && evidence.update_like_directory {
            push_reason(
                reasons,
                "UNKNOWN_INSTALLER",
                "metadata",
                "位于更新目录但元数据缺失，可能是安装包，无法确认".to_string(),
            );
            return RiskLevel::NeedsConfirmation;
        }
        return RiskLevel::NotRecommended;
    }
    if evidence.metadata_conflict {
        return RiskLevel::NeedsConfirmation;
    }
    if matched.is_none() {
        push_reason(
            reasons,
            "UNKNOWN_OWNERSHIP",
            "ownership",
            "无法确认软件归属，不能推荐清理".to_string(),
        );
        return RiskLevel::NeedsConfirmation;
    }
    if confidence != IdentityConfidence::High {
        push_reason(
            reasons,
            "LOW_IDENTITY_CONFIDENCE",
            "ownership",
            "软件归属置信度不足，不能推荐清理".to_string(),
        );
        return RiskLevel::NeedsConfirmation;
    }
    if evidence.signature_bad {
        return RiskLevel::NeedsConfirmation;
    }
    if evidence.file_usage != FileUsageStatus::NotDetected {
        push_reason(
            reasons,
            "USAGE_NOT_CONFIRMED",
            "usage",
            "无法确认文件是否被占用，不能推荐清理".to_string(),
        );
        return RiskLevel::NeedsConfirmation;
    }
    if evidence.update_like_directory {
        push_reason(
            reasons,
            "UPDATE_DIRECTORY_STATE_UNKNOWN",
            "directory",
            "位于更新/缓存/下载目录，无法证明不属于活动更新流程；默认需要确认".to_string(),
        );
        return RiskLevel::NeedsConfirmation;
    }
    if !evidence.installer_signal_strong {
        push_reason(
            reasons,
            "WEAK_INSTALLER_EVIDENCE",
            "ownership",
            "只有目录名等弱安装包证据，不足以推荐清理".to_string(),
        );
        return RiskLevel::NeedsConfirmation;
    }
    match evidence.version_relation {
        VersionRelation::CandidateOlder => {
            push_reason(
                reasons,
                "OLDER_THAN_INSTALLED",
                "version",
                format!(
                    "候选版本 {} 低于已安装版本 {}（辅助证据）",
                    evidence.candidate_version.as_deref().unwrap_or("未知"),
                    evidence.installed_version.as_deref().unwrap_or("未知")
                ),
            );
            RiskLevel::Recommended
        }
        VersionRelation::Equal => {
            push_reason(
                reasons,
                "VERSION_EQUAL",
                "version",
                "候选版本与已安装版本相同，可能是修复包或回滚包".to_string(),
            );
            warnings.push(warning(
                "POSSIBLE_REPAIR_OR_ROLLBACK",
                "version",
                "同版本安装包仍可能用于修复安装或回滚".to_string(),
            ));
            RiskLevel::NeedsConfirmation
        }
        VersionRelation::CandidateNewer => {
            push_reason(
                reasons,
                "VERSION_NEWER",
                "version",
                "候选版本高于已安装版本，可能是待安装的新版本".to_string(),
            );
            RiskLevel::NeedsConfirmation
        }
        VersionRelation::Unknown => {
            push_reason(
                reasons,
                "VERSION_UNKNOWN",
                "version",
                "无法比较候选版本与已安装版本".to_string(),
            );
            RiskLevel::NeedsConfirmation
        }
    }
}

fn to_public_match(value: &SoftwareCandidateMatch) -> SoftwareMatch {
    SoftwareMatch {
        display_name: value.software.display_name.clone(),
        display_version: value.software.display_version.clone(),
        publisher: value.software.publisher.clone(),
        install_location: value.software.install_location.clone(),
        product_code: value.software.product_code.clone(),
        registry_hive: value.software.registry_hive.clone(),
        registry_view: value.software.registry_view.clone(),
        confidence: value.confidence,
        reasons: value.reasons.clone(),
    }
}

fn is_installer_like(candidate: &ScanCandidate) -> bool {
    let extension = candidate.file.extension.as_deref().unwrap_or_default();
    if extension == "msi" || extension == "msp" {
        return true;
    }
    let tokens = [
        candidate.file.file_name.to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.original_filename.clone())
            .unwrap_or_default()
            .to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.internal_name.clone())
            .unwrap_or_default()
            .to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.file_description.clone())
            .unwrap_or_default()
            .to_lowercase(),
    ];
    const TOKENS: &[&str] = &[
        "installer",
        "setup",
        "update",
        "updater",
        "upgrade",
        "patch",
        "package",
    ];
    tokens
        .iter()
        .any(|value| TOKENS.iter().any(|token| value.contains(token)))
        || !candidate.directory_context.directory_hints.is_empty()
}

fn has_strong_installer_signal(candidate: &ScanCandidate) -> bool {
    let extension = candidate.file.extension.as_deref().unwrap_or_default();
    if extension == "msi" || extension == "msp" {
        return true;
    }
    let values = [
        candidate.file.file_name.to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.original_filename.clone())
            .unwrap_or_default()
            .to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.internal_name.clone())
            .unwrap_or_default()
            .to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.file_description.clone())
            .unwrap_or_default()
            .to_lowercase(),
    ];
    const TOKENS: &[&str] = &[
        "installer",
        "setup",
        "update",
        "updater",
        "upgrade",
        "patch",
        "package",
    ];
    values
        .iter()
        .any(|value| TOKENS.iter().any(|token| value.contains(token)))
}

fn has_strong_update_hint(candidate: &ScanCandidate) -> bool {
    let strong = [
        "updater",
        "update",
        "updates",
        "upgrade",
        "installer",
        "installers",
        "setup",
        "setups",
        "packages",
        "patch",
        "patches",
    ];
    if candidate
        .directory_context
        .directory_hints
        .iter()
        .any(|hint| strong.iter().any(|token| hint.eq_ignore_ascii_case(token)))
    {
        return true;
    }
    let path = candidate.file.path.to_lowercase();
    [
        "\\updater\\",
        "\\update\\",
        "\\updates\\",
        "\\upgrade\\",
        "\\installer\\",
        "\\setup\\",
        "\\packages\\",
    ]
    .iter()
    .any(|token| path.contains(token))
}

fn is_updater_component(candidate: &ScanCandidate) -> bool {
    let values = [
        candidate.file.file_name.to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.original_filename.clone())
            .unwrap_or_default()
            .to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.internal_name.clone())
            .unwrap_or_default()
            .to_lowercase(),
        candidate
            .pe_metadata
            .as_ref()
            .and_then(|pe| pe.file_description.clone())
            .unwrap_or_default()
            .to_lowercase(),
    ];
    const UPDATER_SUFFIXES: &[&str] = &[
        "updater",
        "edgeupdate",
        "googleupdate",
        "maintenanceservice",
        "updateservice",
    ];
    values.iter().any(|value| {
        let stem = value
            .strip_suffix(".exe")
            .unwrap_or(value)
            .trim()
            .trim_end_matches(' ');
        UPDATER_SUFFIXES
            .iter()
            .any(|suffix| stem == *suffix || stem.ends_with(suffix))
    })
}

fn normalized_lower_path(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

fn has_update_service_metadata(candidate: &ScanCandidate) -> bool {
    let mut values = Vec::new();
    if let Some(pe) = &candidate.pe_metadata {
        for value in [
            pe.original_filename.as_deref(),
            pe.internal_name.as_deref(),
            pe.file_description.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            values.push(value.to_lowercase());
        }
    }
    values.iter().any(|value| {
        let compact = value.replace(' ', "");
        value.contains("update service")
            || value.contains("maintenance service")
            || compact.contains("updateservice")
            || compact.contains("maintenanceservice")
    })
}

fn has_unregistered_updater_context(path: &Path) -> bool {
    normalized_lower_path(path)
        .split('\\')
        .map(|component| component.trim())
        .filter(|component| !component.is_empty())
        .any(|component| {
            component == "update"
                || component == "updates"
                || component.ends_with("updater")
                || component.ends_with("edgeupdate")
                || component.ends_with("googleupdate")
        })
}

fn is_patch_like(candidate: &ScanCandidate) -> bool {
    candidate.file.extension.as_deref() == Some("msp")
        || candidate
            .msi_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.package_type == crate::models::MsiPackageType::Patch)
}

fn is_rollback_or_repair(candidate: &ScanCandidate) -> bool {
    let mut values = vec![candidate.file.file_name.to_lowercase()];
    values.extend(
        candidate
            .directory_context
            .directory_hints
            .iter()
            .map(|hint| hint.to_lowercase()),
    );
    if let Some(pe) = &candidate.pe_metadata {
        for value in [
            pe.original_filename.as_deref(),
            pe.internal_name.as_deref(),
            pe.file_description.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            values.push(value.to_lowercase());
        }
    }
    ["rollback", "backup", "restore", "repair", "recovery"]
        .iter()
        .any(|token| values.iter().any(|value| value.contains(token)))
}

fn is_known_updater_path(path: &Path) -> bool {
    let lower = normalized_lower_path(path);
    lower.contains("\\edgeupdate\\")
        || lower.contains("\\googleupdate\\")
        || lower.contains("\\microsoft\\edgeupdate")
}

fn is_update_like_directory(candidate: &ScanCandidate) -> bool {
    if !candidate.directory_context.directory_hints.is_empty() {
        return true;
    }
    let path = normalized_lower_path(Path::new(&candidate.file.path));
    [
        "\\updater\\",
        "\\update\\",
        "\\updates\\",
        "\\cache\\",
        "\\download\\",
        "\\downloads\\",
        "\\packages\\",
        "\\installer\\",
        "\\setup\\",
    ]
    .iter()
    .any(|token| path.contains(token))
}

fn path_under_install_location(path: &Path, software: &InstalledSoftware) -> bool {
    software
        .install_location
        .as_deref()
        .and_then(|value| {
            let value = value.trim().trim_matches('"').trim();
            if value.is_empty() {
                None
            } else {
                let path = PathBuf::from(value);
                if path.exists() {
                    path.canonicalize().ok()
                } else {
                    protection::absolute_lexical(&path).ok()
                }
            }
        })
        .is_some_and(|location| protection::path_starts_with(path, &location).unwrap_or(false))
}

fn push_reason(reasons: &mut Vec<RiskReason>, code: &str, category: &str, message: String) {
    reasons.push(RiskReason {
        code: code.to_string(),
        category: category.to_string(),
        message,
    });
}

fn warning(code: &str, category: &str, message: String) -> RiskReason {
    RiskReason {
        code: code.to_string(),
        category: category.to_string(),
        message,
    }
}

/// 已安装软件中具有更新器特征的软件，其安装目录视为活动更新器目录。
pub fn updater_locations(software: &[InstalledSoftware]) -> Vec<PathBuf> {
    software
        .iter()
        .filter(|item| is_updater_software(item))
        .filter_map(|item| item.install_location.as_deref())
        .filter_map(|value| {
            let value = value.trim().trim_matches('"').trim();
            if value.is_empty() {
                None
            } else {
                let path = PathBuf::from(value);
                if path.exists() {
                    path.canonicalize().ok()
                } else {
                    protection::absolute_lexical(&path).ok()
                }
            }
        })
        .collect()
}

fn is_updater_software(software: &InstalledSoftware) -> bool {
    let text = format!(
        "{} {}",
        software.display_name,
        software.publisher.as_deref().unwrap_or_default()
    )
    .to_lowercase();
    [
        "updater",
        "update",
        "googleupdate",
        "maintenance service",
        "maintenance",
    ]
    .iter()
    .any(|token| text.contains(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_software_detection() {
        let item = InstalledSoftware {
            display_name: "Microsoft Edge Update".to_string(),
            display_version: Some("1.3.0".to_string()),
            publisher: Some("Microsoft Corporation".to_string()),
            install_location: Some(r"C:\Program Files (x86)\Microsoft\EdgeUpdate".to_string()),
            uninstall_string: None,
            install_date: None,
            registry_hive: "HKLM".to_string(),
            registry_view: "64".to_string(),
            key_name: "test".to_string(),
            product_code: None,
            is_msi: false,
            system_component: false,
            release_type: None,
            parent_key_name: None,
        };
        assert!(is_updater_software(&item));
        assert_eq!(updater_locations(&[item]).len(), 1);
    }
}
