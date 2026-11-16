//! 阶段 2 风险判断引擎。
//!
//! 输入是阶段 1 的 `ScanReport` 与只读已安装软件列表；输出逐候选的风险等级、
//! 证据和可读理由。本模块不生成清理计划、不修改文件、不操作回收站。

pub mod matching;
pub mod rules;

use crate::models::{
    InstalledSoftwareReport, RiskAssessment, RiskLevel, RiskReason, RiskReport, RiskSummary,
    ScanCandidate, ScanReport,
};
use crate::protection::ProtectedPaths;
use crate::utils::time::now_ms;

pub fn analyze(report: &ScanReport, software: &InstalledSoftwareReport) -> RiskReport {
    analyze_candidates(&report.candidates, software, &report.session_id)
}

pub fn analyze_candidates(
    candidates: &[ScanCandidate],
    software: &InstalledSoftwareReport,
    session_id: &str,
) -> RiskReport {
    let protected = ProtectedPaths::default_for_system();
    let updater_locations = rules::updater_locations(&software.items);
    let context = rules::AssessmentContext {
        protected: &protected,
        software: &software.items,
        updater_locations: &updater_locations,
    };
    let assessments: Vec<RiskAssessment> = candidates
        .iter()
        .map(|candidate| rules::assess(candidate, &context))
        .collect();

    let recommended = assessments
        .iter()
        .filter(|assessment| assessment.risk_level == RiskLevel::Recommended)
        .count() as u64;
    let needs_confirmation = assessments
        .iter()
        .filter(|assessment| assessment.risk_level == RiskLevel::NeedsConfirmation)
        .count() as u64;
    let not_recommended = assessments
        .iter()
        .filter(|assessment| assessment.risk_level == RiskLevel::NotRecommended)
        .count() as u64;
    let recommended_size_bytes = candidates
        .iter()
        .filter(|candidate| {
            assessments
                .iter()
                .find(|assessment| assessment.candidate_id == candidate.id)
                .is_some_and(|assessment| assessment.risk_level == RiskLevel::Recommended)
        })
        .map(|candidate| candidate.file.size)
        .sum();

    let mut global_warnings = vec![
        warning(
            "LOCAL_TRUST_ONLY",
            "signature",
            "签名验证仅使用本地缓存，不执行在线吊销检查；“有效”不等于可清理",
        ),
        warning(
            "USAGE_HEURISTIC",
            "usage",
            "文件占用通过独占打开启发式判断，不能列出占用进程；Unknown 会阻止推荐",
        ),
        warning(
            "MSI_SIGNATURE_NOT_PARSED",
            "signature",
            "MSI 签名证书结构未解析；MSI 发布者使用 Manufacturer 字段",
        ),
        warning(
            "VERSION_AUXILIARY",
            "version",
            "版本较低只是辅助证据，不能单独触发推荐清理",
        ),
    ];
    if !software.issues.is_empty() {
        global_warnings.push(warning(
            "SOFTWARE_ENUMERATION_ISSUES",
            "metadata",
            &format!(
                "读取已安装软件时出现 {} 个问题，软件归属判断可能不完整",
                software.issues.len()
            ),
        ));
    }

    RiskReport {
        session_id: session_id.to_string(),
        generated_at_ms: now_ms(),
        software_count: software.items.len() as u64,
        summary: RiskSummary {
            total: assessments.len() as u64,
            recommended,
            needs_confirmation,
            not_recommended,
            recommended_size_bytes,
        },
        assessments,
        global_warnings,
    }
}

fn warning(code: &str, category: &str, message: &str) -> RiskReason {
    RiskReason {
        code: code.to_string(),
        category: category.to_string(),
        message: message.to_string(),
    }
}
