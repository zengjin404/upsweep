//! 候选发现规则。
//!
//! 阶段 1 只收集“为什么被列为候选”的证据，不判断是否可清理。
//! 单一维度（文件名、目录名、扩展名、大小、时间）都不构成清理依据。

use crate::models::DiscoveryEvidence;

const DIRECTORY_HINTS: &[&str] = &[
    "updater",
    "upgrade",
    "update",
    "updates",
    "patch",
    "patches",
    "packages",
    "installer",
    "installers",
    "setup",
    "setups",
    "cache",
    "temp",
    "temporary",
    "download",
    "downloads",
];

/// 允许出现在目录名内部的关键词（用于 `PixPinUpdater` 这类命名）。
const DIRECTORY_CONTAINS: &[&str] = &["updater", "installer", "upgrade", "update", "patch"];

const FILENAME_HINTS: &[&str] = &[
    "installer",
    "setup",
    "update",
    "updater",
    "upgrade",
    "patch",
    "package",
];

pub const SUPPORTED_EXTENSIONS: &[&str] = &["exe", "msi", "msp"];

/// 返回目录名命中的提示；未命中返回 None。
pub fn directory_hint(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    if DIRECTORY_HINTS.contains(&lower.as_str()) {
        return Some(lower);
    }
    for token in DIRECTORY_CONTAINS {
        if lower.contains(token) && lower.len() <= 64 {
            return Some((*token).to_string());
        }
    }
    None
}

/// 对文件执行多维度候选判断。返回 None 表示不进入候选列表。
pub fn evaluate(
    file_name: &str,
    extension: Option<&str>,
    inherited_hints: &[String],
) -> Option<DiscoveryEvidence> {
    let extension = extension?.to_ascii_lowercase();
    if !SUPPORTED_EXTENSIONS.contains(&extension.as_str()) {
        return None;
    }

    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name)
        .to_lowercase();

    let matched_filename_hints: Vec<String> = FILENAME_HINTS
        .iter()
        .filter(|hint| stem.contains(**hint))
        .map(|hint| (*hint).to_string())
        .collect();
    let has_version_token = has_version_token(&stem);

    if inherited_hints.is_empty() && matched_filename_hints.is_empty() && !has_version_token {
        // 扩展名本身不足以构成候选，避免把所有普通 EXE 都纳入。
        return None;
    }

    let mut reasons = Vec::new();
    for hint in inherited_hints {
        reasons.push(format!("位于更新/安装相关目录: {hint}"));
    }
    for hint in &matched_filename_hints {
        reasons.push(format!("文件名包含安装/更新特征: {hint}"));
    }
    if has_version_token {
        reasons.push("文件名包含版本号".to_string());
    }
    reasons.push(format!("扩展名为 .{extension}"));

    Some(DiscoveryEvidence {
        matched_directory_hints: inherited_hints.to_vec(),
        matched_filename_hints,
        has_version_token,
        supported_extension: true,
        reasons,
    })
}

/// 检测文件名/主干中是否存在至少两段由点分隔的数字，如 2.0.0.3、v2.1。
pub fn has_version_token(stem: &str) -> bool {
    let mut groups = 0usize;
    let mut current_numeric = false;

    for character in stem.chars() {
        if character.is_ascii_digit() {
            current_numeric = true;
        } else {
            if current_numeric {
                groups += 1;
            }
            current_numeric = false;
        }
    }
    if current_numeric {
        groups += 1;
    }

    // 单纯一个数字（例如 app2）不算版本号；至少两段（2.0）才算。
    groups >= 2 && stem.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_hints_are_case_insensitive_and_token_aware() {
        assert_eq!(directory_hint("Updater").as_deref(), Some("updater"));
        assert_eq!(directory_hint("PixPinUpdater").as_deref(), Some("updater"));
        assert_eq!(directory_hint("Cache").as_deref(), Some("cache"));
        assert!(directory_hint("Program Files").is_none());
    }

    #[test]
    fn installer_in_update_directory_is_candidate() {
        let evidence = evaluate(
            "random-name.exe",
            Some("exe"),
            &["updater".to_string(), "package".to_string()],
        )
        .expect("应成为候选");
        assert_eq!(evidence.matched_directory_hints.len(), 2);
        assert!(
            evidence
                .reasons
                .iter()
                .any(|reason| reason.contains("updater"))
        );
    }

    #[test]
    fn installer_named_file_outside_update_directory_is_candidate() {
        let evidence = evaluate("Application-Setup.exe", Some("exe"), &[]).expect("应成为候选");
        assert_eq!(evidence.matched_filename_hints, vec!["setup"]);
        assert!(!evidence.has_version_token);
    }

    #[test]
    fn versioned_file_is_candidate_even_without_keywords() {
        let evidence = evaluate("PixPin_2.0.0.3.exe", Some("exe"), &[]).expect("应成为候选");
        assert!(evidence.has_version_token);
        assert!(
            evidence
                .reasons
                .iter()
                .any(|reason| reason == "文件名包含版本号")
        );
    }

    #[test]
    fn ordinary_exe_is_not_candidate() {
        assert!(evaluate("app.exe", Some("exe"), &[]).is_none());
        assert!(evaluate("readme.txt", Some("txt"), &[]).is_none());
    }

    #[test]
    fn extension_alone_is_insufficient() {
        assert!(evaluate("Photoshop.exe", Some("exe"), &[]).is_none());
        assert!(evaluate("thing.msi", Some("msi"), &[]).is_none());
    }

    #[test]
    fn version_token_detection() {
        assert!(has_version_token("pixpin_2.0.0.3"));
        assert!(has_version_token("app-v2.1"));
        assert!(!has_version_token("app2"));
        assert!(!has_version_token("setup"));
    }
}
