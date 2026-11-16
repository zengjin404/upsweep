//! 候选文件与已安装软件的关联匹配。
//!
//! 匹配只使用名称、发布者、安装路径、MSI ProductCode 与签名发布者等证据；
//! 单一发布者匹配不构成软件归属。无法确定时返回低置信度或不匹配，由规则层
//! 归入“需要确认”。

use std::path::{Path, PathBuf};

use crate::models::{
    IdentityConfidence, InstalledSoftware, ScanCandidate, SignatureStatus, VersionRelation,
};
use crate::protection;

#[derive(Debug, Clone)]
pub struct CandidateIdentity {
    pub product_name: Option<String>,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub product_code: Option<String>,
    pub signature_publisher: Option<String>,
    pub signature_bad: bool,
    pub metadata_complete: bool,
}

#[derive(Debug, Clone)]
pub struct SoftwareCandidateMatch {
    pub software: InstalledSoftware,
    pub confidence: IdentityConfidence,
    pub product_match: Option<bool>,
    pub partial_product: bool,
    pub publisher_match: Option<bool>,
    pub path_match: bool,
    pub product_code_match: bool,
    pub reasons: Vec<String>,
    pub conflict: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MatchOutcome {
    pub matched: Option<SoftwareCandidateMatch>,
    pub ambiguous: bool,
    pub conflicts: Vec<String>,
}

pub fn candidate_identity(candidate: &ScanCandidate) -> CandidateIdentity {
    let msi = candidate.msi_metadata.as_ref();
    let pe = candidate.pe_metadata.as_ref();
    let signature = candidate.signature.as_ref();

    let product_name = msi
        .and_then(|metadata| metadata.product_name.clone())
        .or_else(|| pe.and_then(|metadata| metadata.product_name.clone()));
    let publisher = msi
        .and_then(|metadata| metadata.manufacturer.clone())
        .or_else(|| pe.and_then(|metadata| metadata.company_name.clone()));
    let version = msi
        .and_then(|metadata| metadata.product_version.clone())
        .or_else(|| pe.and_then(|metadata| metadata.product_version.clone()))
        .or_else(|| pe.and_then(|metadata| metadata.file_version.clone()));
    let product_code = msi.and_then(|metadata| metadata.product_code.clone());
    let signature_publisher = signature.and_then(|info| {
        info.publisher_organization
            .clone()
            .or_else(|| info.publisher_common_name.clone())
    });
    let signature_bad = signature.is_some_and(|info| {
        matches!(
            info.trust_status,
            SignatureStatus::Invalid
                | SignatureStatus::UntrustedRoot
                | SignatureStatus::Expired
                | SignatureStatus::Revoked
                | SignatureStatus::Unknown
        )
    });
    let metadata_complete =
        msi.is_some_and(|metadata| metadata.present) || pe.is_some_and(|metadata| metadata.present);

    CandidateIdentity {
        product_name,
        publisher,
        version,
        product_code,
        signature_publisher,
        signature_bad,
        metadata_complete,
    }
}

pub fn find_software_match(
    candidate: &ScanCandidate,
    software: &[InstalledSoftware],
) -> MatchOutcome {
    let identity = candidate_identity(candidate);
    let mut scored: Vec<(i64, SoftwareCandidateMatch)> = Vec::new();
    let mut conflicts = Vec::new();

    for item in software {
        let product_strength = identity
            .product_name
            .as_deref()
            .map(|left| product_match_strength(left, &item.display_name))
            .unwrap_or(0);
        let product_match = identity.product_name.as_ref().map(|_| product_strength > 0);
        let publisher_match = match (identity.publisher.as_deref(), item.publisher.as_deref()) {
            (Some(left), Some(right)) if !left.trim().is_empty() && !right.trim().is_empty() => {
                Some(publisher_matches(left, right))
            }
            _ => None,
        };
        let signature_publisher_match = match (
            identity.signature_publisher.as_deref(),
            item.publisher.as_deref(),
        ) {
            (Some(left), Some(right)) if !left.trim().is_empty() && !right.trim().is_empty() => {
                Some(publisher_matches(left, right))
            }
            _ => None,
        };
        let path_match = item
            .install_location
            .as_deref()
            .and_then(install_path)
            .is_some_and(|location| {
                protection::path_starts_with(Path::new(&candidate.file.path), &location)
                    .unwrap_or(false)
            });
        let product_code_match = identity
            .product_code
            .as_deref()
            .zip(item.product_code.as_deref())
            .is_some_and(|(left, right)| normalize_guid(left) == normalize_guid(right));

        let has_product_signal = product_match == Some(true)
            || product_code_match
            || path_match
            || (identity.product_name.is_none() && publisher_match == Some(true));
        if !has_product_signal {
            // 仅发布者相同不足以关联软件，也不应把同发布者的其他产品视为冲突。
            continue;
        }

        let mut score = 0i64;
        let mut reasons = Vec::new();
        if product_code_match {
            score += 100;
            reasons.push("MSI ProductCode 与已安装软件一致".to_string());
        }
        match product_strength {
            2 => {
                score += 40;
                reasons.push(format!(
                    "产品名称匹配：{} / {}",
                    identity.product_name.as_deref().unwrap_or("未知"),
                    item.display_name
                ));
            }
            1 => {
                score += 15;
                reasons.push(format!(
                    "产品名称仅部分匹配：{} / {}",
                    identity.product_name.as_deref().unwrap_or("未知"),
                    item.display_name
                ));
            }
            _ => {
                if identity.product_name.is_some() {
                    score -= 30;
                    conflicts.push(format!(
                        "产品名称冲突：候选为“{}”，已安装软件为“{}”",
                        identity.product_name.as_deref().unwrap_or("未知"),
                        item.display_name
                    ));
                }
            }
        }
        match publisher_match {
            Some(true) => {
                score += 25;
                reasons.push("PE/MSI 发布者与已安装软件 Publisher 匹配".to_string());
            }
            Some(false) => {
                score -= 30;
                conflicts.push(format!(
                    "发布者冲突：候选为“{}”，已安装软件为“{}”",
                    identity.publisher.as_deref().unwrap_or("未知"),
                    item.publisher.as_deref().unwrap_or("未知")
                ));
            }
            None => {}
        }
        if signature_publisher_match == Some(true) {
            score += 10;
            reasons.push("数字签名发布者与已安装软件 Publisher 匹配".to_string());
        }
        if path_match {
            score += 30;
            reasons.push(format!(
                "候选路径位于软件安装目录：{}",
                item.install_location.as_deref().unwrap_or("未知")
            ));
        }

        if score < 35 {
            continue;
        }

        let confidence = if product_code_match
            || (product_strength == 2
                && (publisher_match == Some(true)
                    || signature_publisher_match == Some(true)
                    || path_match))
        {
            IdentityConfidence::High
        } else if product_strength == 2 || (path_match && publisher_match == Some(true)) {
            IdentityConfidence::Medium
        } else {
            IdentityConfidence::Low
        };
        let conflict = publisher_match == Some(false) || product_strength == 0;

        scored.push((
            score,
            SoftwareCandidateMatch {
                software: item.clone(),
                confidence,
                product_match,
                partial_product: product_strength == 1,
                publisher_match,
                path_match,
                product_code_match,
                reasons,
                conflict,
            },
        ));
    }

    scored.sort_by_key(|left| std::cmp::Reverse(left.0));
    let matched = scored.first().map(|(_, value)| value.clone());
    let ambiguous = scored.get(1).is_some_and(|(second, _)| {
        scored
            .first()
            .is_some_and(|(first, _)| *second >= *first - 10)
    });
    MatchOutcome {
        matched,
        ambiguous,
        conflicts,
    }
}

fn install_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim().trim_matches('"').trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = PathBuf::from(trimmed);
    if path.exists() {
        path.canonicalize().ok()
    } else {
        protection::absolute_lexical(&path).ok()
    }
}

pub fn normalize_guid(value: &str) -> String {
    value
        .trim()
        .trim_matches('{')
        .trim_matches('}')
        .to_ascii_lowercase()
}

pub fn normalized_tokens(value: &str) -> Vec<String> {
    value
        .to_lowercase()
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .filter(|token| token.len() > 1)
        .map(str::to_string)
        .collect()
}

pub fn publisher_matches(left: &str, right: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "ltd",
        "limited",
        "llc",
        "gmbh",
        "company",
        "co",
        "sa",
        "sas",
        "ag",
        "the",
    ];
    let normalize = |value: &str| -> Vec<String> {
        normalized_tokens(value)
            .into_iter()
            .filter(|token| !SUFFIXES.contains(&token.as_str()))
            .collect()
    };
    let left = normalize(left);
    let right = normalize(right);
    if left.is_empty() || right.is_empty() {
        return false;
    }
    if left == right {
        return true;
    }
    let (shorter, longer) = if left.len() <= right.len() {
        (&left, &right)
    } else {
        (&right, &left)
    };
    shorter.iter().all(|token| longer.contains(token)) && shorter.join("").len() >= 4
}

pub fn product_matches(left: &str, right: &str) -> bool {
    product_match_strength(left, right) > 0
}

/// 2 = 完全匹配；1 = 多词前缀部分匹配；0 = 不匹配。
pub fn product_match_strength(left: &str, right: &str) -> u8 {
    let left_tokens = normalized_tokens(left);
    let right_tokens = normalized_tokens(right);
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return 0;
    }
    if left_tokens == right_tokens {
        return 2;
    }
    let (shorter, longer) = if left_tokens.len() <= right_tokens.len() {
        (&left_tokens, &right_tokens)
    } else {
        (&right_tokens, &left_tokens)
    };
    // 单词产品名只接受完全匹配，避免 “PixPin” 误配 “PixPin Backup”。
    if shorter.len() >= 2 && longer.starts_with(shorter) {
        return 1;
    }
    0
}

pub fn compare_versions(candidate: Option<&str>, installed: Option<&str>) -> VersionRelation {
    let Some(candidate) = candidate.and_then(parse_version) else {
        return VersionRelation::Unknown;
    };
    let Some(installed) = installed.and_then(parse_version) else {
        return VersionRelation::Unknown;
    };
    let length = candidate.len().max(installed.len());
    for index in 0..length {
        let left = candidate.get(index).copied().unwrap_or(0);
        let right = installed.get(index).copied().unwrap_or(0);
        if left < right {
            return VersionRelation::CandidateOlder;
        }
        if left > right {
            return VersionRelation::CandidateNewer;
        }
    }
    VersionRelation::Equal
}

pub fn parse_version(value: &str) -> Option<Vec<u64>> {
    let mut parts = Vec::new();
    for part in value.split(|character: char| !character.is_ascii_digit() && character != '.') {
        if part.is_empty() {
            continue;
        }
        for segment in part.split('.') {
            if segment.is_empty() {
                continue;
            }
            parts.push(segment.parse::<u64>().ok()?);
        }
    }
    if parts.is_empty() { None } else { Some(parts) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_publishers_and_products() {
        assert!(publisher_matches("Microsoft Corporation", "Microsoft"));
        assert!(publisher_matches("UpSweep Test", "UpSweep Test, Inc."));
        assert!(!publisher_matches("Microsoft", "Google LLC"));
        assert!(product_matches("PixPin", "PixPin"));
        assert!(product_matches("Microsoft Edge", "Microsoft Edge Update"));
        assert!(!product_matches("PixPin", "PixPin Backup"));
    }

    #[test]
    fn compares_versions() {
        assert_eq!(
            compare_versions(Some("2.0.0.2"), Some("2.0.0.3")),
            VersionRelation::CandidateOlder
        );
        assert_eq!(
            compare_versions(Some("2.0"), Some("2.0.0")),
            VersionRelation::Equal
        );
        assert_eq!(
            compare_versions(Some("2.1"), Some("2.0.9")),
            VersionRelation::CandidateNewer
        );
        assert_eq!(
            compare_versions(None, Some("1.0")),
            VersionRelation::Unknown
        );
    }

    #[test]
    fn parses_versions_with_suffixes() {
        assert_eq!(parse_version("v1.2.3-beta"), Some(vec![1, 2, 3]));
        assert_eq!(parse_version("unknown"), None);
    }
}
