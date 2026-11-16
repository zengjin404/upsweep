//! 阶段 2 风险判断集成测试。
//!
//! 使用临时目录与独立夹具，不修改用户软件目录。文件占用测试会独占打开
//! 临时文件，关闭后清理。

use std::fs;
use std::path::{Path, PathBuf};

use upsweep_lib::analyzer;
use upsweep_lib::models::{
    ChainStatus, DirectoryContext, DiscoveryEvidence, FileIdentity, FileInfo, InstalledSoftware,
    InstalledSoftwareReport, MsiMetadata, MsiPackageType, PeMetadata, RiskAssessment, RiskLevel,
    ScanCandidate, SignatureInfo, SignatureStatus,
};

fn temp_root(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "upsweep_analyzer_test_{}_{}",
        std::process::id(),
        name
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("应创建测试目录");
    path
}

fn fixture_exe() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("metadata")
        .join("versioned.exe")
}

fn copy_file(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("应创建父目录");
    }
    fs::copy(fixture_exe(), &path).expect("应复制夹具");
    path
}

fn pe(product: &str, publisher: &str, version: &str) -> PeMetadata {
    PeMetadata {
        present: true,
        product_name: Some(product.to_string()),
        product_version: Some(version.to_string()),
        file_description: Some(format!("{product} Setup")),
        company_name: Some(publisher.to_string()),
        file_version: Some(version.to_string()),
        original_filename: Some("setup.exe".to_string()),
        internal_name: Some("Setup".to_string()),
        language: Some("0409".to_string()),
        codepage: Some("04b0".to_string()),
        read_error: None,
    }
}

fn msi(product: &str, publisher: &str, version: &str, product_code: &str) -> MsiMetadata {
    MsiMetadata {
        present: true,
        package_type: MsiPackageType::Installer,
        product_name: Some(product.to_string()),
        product_version: Some(version.to_string()),
        manufacturer: Some(publisher.to_string()),
        product_code: Some(product_code.to_string()),
        upgrade_code: None,
        package_code: None,
        summary_title: None,
        summary_subject: None,
        summary_author: None,
        patch_codes: Vec::new(),
        read_error: None,
    }
}

fn signature(status: SignatureStatus, publisher: Option<&str>) -> SignatureInfo {
    SignatureInfo {
        signature_present: Some(status != SignatureStatus::NotSigned),
        structure_valid: Some(status != SignatureStatus::NotSigned),
        signer_certificate_found: publisher.is_some(),
        trust_status: status,
        chain_status: match status {
            SignatureStatus::Valid => ChainStatus::Valid,
            SignatureStatus::NotSigned => ChainStatus::NotChecked,
            SignatureStatus::UntrustedRoot => ChainStatus::UntrustedRoot,
            SignatureStatus::Expired => ChainStatus::Expired,
            SignatureStatus::Revoked => ChainStatus::Revoked,
            SignatureStatus::Invalid => ChainStatus::Invalid,
            SignatureStatus::Unknown | SignatureStatus::Unavailable => ChainStatus::Unknown,
        },
        signer_subject: publisher.map(|value| format!("CN={value}")),
        signer_issuer: publisher.map(|value| format!("CN={value}")),
        publisher_common_name: publisher.map(str::to_string),
        publisher_organization: publisher.map(str::to_string),
        is_self_signed: Some(false),
        error_code: None,
        diagnostic: None,
    }
}

fn candidate(
    path: PathBuf,
    hints: &[&str],
    pe_metadata: Option<PeMetadata>,
    msi_metadata: Option<MsiMetadata>,
    signature_info: Option<SignatureInfo>,
) -> ScanCandidate {
    let metadata = fs::metadata(&path).ok();
    let size = metadata.as_ref().map(|value| value.len()).unwrap_or(0);
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    let file = FileInfo {
        path: path.to_string_lossy().into_owned(),
        file_name: path
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default(),
        extension,
        size,
        created_at_ms: None,
        modified_at_ms: None,
        accessed_at_ms: None,
        attributes: 0,
        is_reparse_point: false,
        is_read_only: false,
        is_hidden: false,
        is_system: false,
        is_archive: false,
        identity: FileIdentity {
            volume_serial: None,
            file_id: None,
            size,
            created_at_ms: None,
            modified_at_ms: None,
            read_error: None,
        },
    };
    ScanCandidate {
        id: format!("candidate-{}", path.to_string_lossy().to_lowercase()),
        file,
        directory_context: DirectoryContext {
            scan_root: path
                .parent()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_default(),
            relative_directory: String::new(),
            directory_hints: hints.iter().map(|value| (*value).to_string()).collect(),
        },
        discovery: DiscoveryEvidence {
            matched_directory_hints: hints.iter().map(|value| (*value).to_string()).collect(),
            matched_filename_hints: Vec::new(),
            has_version_token: true,
            supported_extension: true,
            reasons: vec!["测试夹具".to_string()],
        },
        pe_metadata,
        signature: signature_info,
        msi_metadata,
        metadata_issues: Vec::new(),
    }
}

fn software(
    name: &str,
    version: &str,
    publisher: &str,
    install_location: Option<&Path>,
    product_code: Option<&str>,
) -> InstalledSoftware {
    InstalledSoftware {
        display_name: name.to_string(),
        display_version: Some(version.to_string()),
        publisher: Some(publisher.to_string()),
        install_location: install_location.map(|value| value.to_string_lossy().into_owned()),
        uninstall_string: None,
        install_date: Some("20260101".to_string()),
        registry_hive: "HKLM".to_string(),
        registry_view: "64".to_string(),
        key_name: "test".to_string(),
        product_code: product_code.map(str::to_string),
        is_msi: product_code.is_some(),
        system_component: false,
        release_type: None,
        parent_key_name: None,
    }
}

fn analyze_one(candidate: ScanCandidate, software: Vec<InstalledSoftware>) -> RiskAssessment {
    let report = InstalledSoftwareReport {
        items: software,
        issues: Vec::new(),
        scanned_keys: 1,
    };
    let risk = analyzer::analyze_candidates(&[candidate], &report, "test-session");
    risk.assessments.into_iter().next().expect("应有评估结果")
}

#[test]
fn older_installer_in_update_directory_needs_confirmation_not_auto_recommended() {
    let root = temp_root("older_update_dir");
    let install = root.join("install").join("PixPin");
    fs::create_dir_all(&install).expect("应创建安装目录");
    let path = copy_file(&root, "appdata/PixPin/updater/package/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["updater", "package"],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            Some(signature(SignatureStatus::NotSigned, None)),
        ),
        vec![software(
            "PixPin",
            "2.0.0.3",
            "PixPin",
            Some(&install),
            None,
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "UPDATE_DIRECTORY_STATE_UNKNOWN")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn standalone_old_installer_outside_update_directory_is_recommended() {
    let root = temp_root("standalone");
    let install = root.join("install").join("PixPin");
    fs::create_dir_all(&install).expect("应创建安装目录");
    let path = copy_file(&root, "documents/PixPin/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            Some(signature(SignatureStatus::NotSigned, None)),
        ),
        vec![software(
            "PixPin",
            "2.0.0.3",
            "PixPin",
            Some(&install),
            None,
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::Recommended);
    assert!(assessment.default_selected);
    assert!(assessment.selectable);
    assert!(assessment.evidence.installer_signal_strong);
    assert!(!assessment.evidence.update_like_directory);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn valid_signature_old_installer_is_recommended_but_signature_not_sole_evidence() {
    let root = temp_root("valid_signature");
    let path = copy_file(&root, "documents/PixPin/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            Some(signature(SignatureStatus::Valid, Some("PixPin"))),
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::Recommended);
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "SIGNATURE_VALID")
    );
    let _ = fs::remove_dir_all(root);

    // 有效签名但无法确认软件归属时，不得推荐。
    let root = temp_root("valid_signature_unknown");
    let path = copy_file(&root, "appdata/Unknown/updater/Unknown_1.0.0.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["updater"],
            Some(pe("Unknown Product", "Unknown Vendor", "1.0.0")),
            None,
            Some(signature(SignatureStatus::Valid, Some("Unknown Vendor"))),
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.matched_software.is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn old_installer_in_weak_cache_directory_needs_confirmation() {
    let root = temp_root("weak_cache");
    let path = copy_file(&root, "appdata/PixPin/cache/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["cache"],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "UPDATE_DIRECTORY_STATE_UNKNOWN")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn patch_and_rollback_packages_need_confirmation() {
    let root = temp_root("patch_rollback");
    let patch = copy_file(&root, "documents/PixPin/PixPin_2.0.0.2.msp");
    let assessment = analyze_one(
        candidate(
            patch,
            &[],
            None,
            Some(msi(
                "PixPin",
                "PixPin",
                "2.0.0.2",
                "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            )),
            None,
        ),
        vec![software(
            "PixPin",
            "2.0.0.3",
            "PixPin",
            None,
            Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "PATCH_PACKAGE")
    );
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);

    let rollback = copy_file(&root, "documents/PixPin/PixPin_rollback_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            rollback,
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "ROLLBACK_OR_REPAIR")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unknown_usage_in_non_protected_directory_needs_confirmation() {
    let root = temp_root("unknown_usage");
    let path = root
        .join("documents")
        .join("PixPin")
        .join("PixPin_2.0.0.2.exe");
    // 不创建文件：普通非保护目录中的 Unknown 占用。
    assert!(!upsweep_lib::protection::ProtectedPaths::default_for_system().is_protected(&path));
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert_eq!(
        assessment.evidence.file_usage,
        upsweep_lib::models::FileUsageStatus::Unknown
    );
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "USAGE_NOT_CONFIRMED")
    );
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unregistered_updater_context_needs_confirmation() {
    let root = temp_root("unregistered_updater");
    let path = copy_file(&root, "UnknownUpdater/Installers/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.evidence.unregistered_updater_context);
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "UNREGISTERED_UPDATER_CONTEXT")
    );
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn similar_directory_name_is_not_treated_as_updater() {
    let root = temp_root("similar_directory");
    let path = copy_file(&root, "UpdateNotes/Installers/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["update"],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert!(!assessment.evidence.active_updater);
    assert!(!assessment.evidence.updater_component);
    assert!(!assessment.evidence.unregistered_updater_context);
    // 目录名包含 update 只是弱更新信号，应降级为需要确认，而不是硬保护或直接推荐。
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.selectable);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn msi_product_code_match_with_conflicting_metadata_needs_confirmation() {
    let root = temp_root("msi_conflict");
    let path = copy_file(&root, "documents/Other/PixPin_2.0.0.2.msi");
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            None,
            Some(msi(
                "Other Product",
                "Other Vendor",
                "2.0.0.2",
                "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            )),
            None,
        ),
        vec![software(
            "PixPin",
            "2.0.0.3",
            "PixPin",
            None,
            Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);
    assert!(assessment.evidence.metadata_conflict);
    assert!(
        assessment
            .warnings
            .iter()
            .any(|warning| warning.code == "SOFTWARE_IDENTITY_CONFLICT")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn multiple_software_matches_need_confirmation() {
    let root = temp_root("multiple_matches");
    let path = copy_file(&root, "documents/PixPin/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![
            software("PixPin", "2.0.0.3", "PixPin", None, None),
            software("PixPin", "2.0.0.3", "PixPin", None, None),
        ],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert_eq!(
        assessment.confidence,
        upsweep_lib::models::IdentityConfidence::Low
    );
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn protected_path_with_unknown_usage_is_not_recommended() {
    // System Volume Information 通常拒绝普通用户访问；file_usage 应返回 Unknown。
    // 最终 NotRecommended 由受保护路径规则决定，而不是由 Unknown 本身决定。
    let path = Path::new(r"C:\System Volume Information");
    if !path.exists() {
        eprintln!("System Volume Information 不存在，跳过权限不足占用测试");
        return;
    }
    let assessment = analyze_one(
        candidate(
            path.to_path_buf(),
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(
        assessment.evidence.file_usage,
        upsweep_lib::models::FileUsageStatus::Unknown
    );
    assert_eq!(assessment.risk_level, RiskLevel::NotRecommended);
    assert!(!assessment.default_selected);
    assert!(!assessment.selectable);
    assert!(assessment.evidence.protected_path);
}

#[test]
fn newer_and_equal_installers_need_confirmation() {
    let root = temp_root("newer");
    let install = root.join("install").join("PixPin");
    fs::create_dir_all(&install).expect("应创建安装目录");
    for (name, version) in [("newer", "2.0.0.4"), ("equal", "2.0.0.3")] {
        let path = copy_file(
            &root,
            &format!("appdata/PixPin/updater/{name}/PixPin_{version}.exe"),
        );
        let assessment = analyze_one(
            candidate(
                path,
                &["updater"],
                Some(pe("PixPin", "PixPin", version)),
                None,
                Some(signature(SignatureStatus::NotSigned, None)),
            ),
            vec![software(
                "PixPin",
                "2.0.0.3",
                "PixPin",
                Some(&install),
                None,
            )],
        );
        assert_eq!(
            assessment.risk_level,
            RiskLevel::NeedsConfirmation,
            "{name}"
        );
        assert!(!assessment.default_selected);
        assert!(assessment.selectable);
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn same_product_different_publisher_needs_confirmation() {
    let root = temp_root("publisher_conflict");
    let path = copy_file(&root, "appdata/PixPin/updater/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["updater"],
            Some(pe("PixPin", "Another Vendor", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.evidence.metadata_conflict);
    assert!(
        assessment
            .warnings
            .iter()
            .any(|warning| warning.code == "SOFTWARE_IDENTITY_CONFLICT")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn same_publisher_different_product_needs_confirmation() {
    let root = temp_root("product_conflict");
    let path = copy_file(&root, "appdata/OtherApp/updater/OtherApp_1.0.0.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["updater"],
            Some(pe("OtherApp", "PixPin", "1.0.0")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.matched_software.is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn active_updater_install_directory_is_not_recommended() {
    let updater_dir = Path::new(r"C:\Program Files (x86)\Microsoft\EdgeUpdate");
    let path = updater_dir
        .join("Download")
        .join("MicrosoftEdgeUpdateSetup.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["download"],
            Some(pe(
                "Microsoft Edge Update",
                "Microsoft Corporation",
                "1.3.0",
            )),
            None,
            Some(signature(
                SignatureStatus::Valid,
                Some("Microsoft Corporation"),
            )),
        ),
        vec![software(
            "Microsoft Edge Update",
            "1.3.315.17",
            "Microsoft Corporation",
            Some(updater_dir),
            None,
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NotRecommended);
    assert!(!assessment.selectable);
    assert!(assessment.evidence.active_updater);
}

#[test]
fn updater_component_outside_install_directory_is_not_recommended() {
    let root = temp_root("updater_component");
    let path = copy_file(&root, "appdata/PixPin/updater/updater.exe");
    let mut metadata = pe("PixPin", "PixPin", "2.0.0.2");
    metadata.original_filename = Some("updater.exe".to_string());
    metadata.internal_name = Some("PixPinUpdater".to_string());
    metadata.file_description = Some("PixPin Updater".to_string());
    let assessment = analyze_one(
        candidate(path, &["updater"], Some(metadata), None, None),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NotRecommended);
    assert!(assessment.evidence.updater_component);
    assert!(!assessment.selectable);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn update_cache_under_install_directory_needs_confirmation() {
    let root = temp_root("install_cache");
    let install = root.join("install").join("PixPin");
    fs::create_dir_all(&install).expect("应创建安装目录");
    let path = copy_file(&root, "install/PixPin/updater/package/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["updater", "package"],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software(
            "PixPin",
            "2.0.0.3",
            "PixPin",
            Some(&install),
            None,
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.evidence.in_install_location);
    assert!(assessment.evidence.update_like_directory);
    assert!(!assessment.default_selected);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn install_directory_without_update_context_is_not_recommended() {
    let root = temp_root("install_dir");
    let install = root.join("install").join("PixPin");
    fs::create_dir_all(&install).expect("应创建安装目录");
    let app = copy_file(&root, "install/PixPin/app.exe");
    let assessment = analyze_one(
        candidate(
            app,
            &[],
            Some(pe("PixPin", "PixPin", "2.0.0.3")),
            None,
            None,
        ),
        vec![software(
            "PixPin",
            "2.0.0.3",
            "PixPin",
            Some(&install),
            None,
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NotRecommended);
    assert!(!assessment.selectable);
    assert!(assessment.evidence.in_install_location);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_metadata_in_update_directory_needs_confirmation() {
    let root = temp_root("corrupt_metadata");
    let path = copy_file(&root, "appdata/PixPin/updater/damaged.exe");
    let damaged = PeMetadata {
        present: false,
        product_name: None,
        product_version: None,
        file_description: None,
        company_name: None,
        file_version: None,
        original_filename: None,
        internal_name: None,
        language: None,
        codepage: None,
        read_error: Some("PE 解析失败".to_string()),
    };
    let assessment = analyze_one(
        candidate(path, &["updater"], Some(damaged), None, None),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(!assessment.evidence.metadata_complete);
    assert!(!assessment.default_selected);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn ordinary_exe_is_not_recommended() {
    let root = temp_root("ordinary");
    let path = copy_file(&root, "normal/app.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            Some(PeMetadata {
                present: true,
                product_name: Some("PixPin".to_string()),
                product_version: Some("2.0.0.2".to_string()),
                file_description: Some("PixPin".to_string()),
                company_name: Some("PixPin".to_string()),
                file_version: Some("2.0.0.2".to_string()),
                original_filename: Some("app.exe".to_string()),
                internal_name: Some("PixPin".to_string()),
                language: None,
                codepage: None,
                read_error: None,
            }),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NotRecommended);
    assert!(!assessment.default_selected);
    assert!(!assessment.selectable);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn uninstalled_software_residue_needs_confirmation() {
    let root = temp_root("uninstalled");
    let path = copy_file(&root, "appdata/Removed/updater/Removed_1.0.0.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["updater"],
            Some(pe("Removed", "Vendor", "1.0.0")),
            None,
            None,
        ),
        Vec::new(),
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.matched_software.is_none());
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "NO_SOFTWARE_MATCH")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn protected_path_is_not_recommended() {
    let path = Path::new(r"C:\Windows\System32\PixPin_2.0.0.2.exe").to_path_buf();
    let assessment = analyze_one(
        candidate(
            path,
            &["updater"],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NotRecommended);
    assert!(assessment.evidence.protected_path);
    assert!(!assessment.selectable);
}

#[test]
fn invalid_signature_old_installer_needs_confirmation() {
    let root = temp_root("invalid_signature");
    let path = copy_file(&root, "appdata/PixPin/updater/PixPin_2.0.0.2.exe");
    let assessment = analyze_one(
        candidate(
            path,
            &["updater"],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            Some(signature(SignatureStatus::Invalid, Some("PixPin"))),
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(assessment.evidence.signature_bad);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn msi_product_code_match_can_be_recommended() {
    let root = temp_root("msi");
    let path = copy_file(&root, "documents/PixPin/PixPin_2.0.0.2.msi");
    let assessment = analyze_one(
        candidate(
            path,
            &[],
            None,
            Some(msi(
                "PixPin",
                "PixPin",
                "2.0.0.2",
                "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            )),
            Some(signature(SignatureStatus::NotSigned, None)),
        ),
        vec![software(
            "PixPin",
            "2.0.0.3",
            "PixPin",
            None,
            Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
        )],
    );
    assert_eq!(assessment.risk_level, RiskLevel::Recommended);
    assert!(assessment.evidence.product_code_match);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn file_in_use_is_not_recommended() {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, OPEN_EXISTING,
    };

    let root = temp_root("in_use");
    let path = copy_file(&root, "appdata/PixPin/updater/PixPin_2.0.0.2.exe");
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: 路径有效；句柄在测试结束前关闭。
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE, "应能独占打开临时文件");

    let assessment = analyze_one(
        candidate(
            path,
            &["updater"],
            Some(pe("PixPin", "PixPin", "2.0.0.2")),
            None,
            None,
        ),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    // SAFETY: handle 由 CreateFileW 成功返回。
    unsafe {
        CloseHandle(handle);
    }
    assert_eq!(assessment.risk_level, RiskLevel::NotRecommended);
    assert_eq!(
        assessment.evidence.file_usage,
        upsweep_lib::models::FileUsageStatus::InUse
    );
    assert!(!assessment.default_selected);
    assert!(!assessment.selectable);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn update_service_metadata_in_download_directory_is_not_recommended() {
    let root = temp_root("update_service_download");
    let path = copy_file(&root, "documents/Downloads/PixPin_Setup.exe");
    let mut metadata = pe("PixPin", "PixPin", "2.0.0.2");
    metadata.file_description = Some("Update Service".to_string());
    metadata.original_filename = Some("setup.exe".to_string());
    metadata.internal_name = Some("Setup".to_string());
    let assessment = analyze_one(
        candidate(path, &[], Some(metadata), None, None),
        vec![software("PixPin", "2.0.0.3", "PixPin", None, None)],
    );
    // update 只构成弱更新信号，不能凭旧版本 + 元数据推荐。
    assert_ne!(assessment.risk_level, RiskLevel::Recommended);
    assert_eq!(assessment.risk_level, RiskLevel::NeedsConfirmation);
    assert!(!assessment.default_selected);
    assert!(assessment.selectable);
    assert!(!assessment.evidence.updater_component);
    assert!(assessment.evidence.update_service_like);
    assert!(assessment.evidence.update_like_directory);
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.code == "UPDATE_DIRECTORY_STATE_UNKNOWN")
    );
    let _ = fs::remove_dir_all(root);
}
