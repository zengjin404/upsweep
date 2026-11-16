//! 扫描引擎集成测试。
//!
//! 使用 tests/fixtures 下的独立模拟目录，不扫描真实用户软件目录，也不执行任何文件。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use upsweep_lib::models::{ScanRequest, ScanStatus, SignatureStatus};
use upsweep_lib::scanner::{ScanControl, ScanObserver, engine, prepare};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn run_scan(
    root: &Path,
    excluded: Vec<String>,
    observer: &dyn ScanObserver,
    control: &ScanControl,
) -> upsweep_lib::models::ScanReport {
    let request = ScanRequest {
        include_default_roots: false,
        custom_roots: vec![root.to_string_lossy().into_owned()],
        excluded_paths: excluded,
        max_depth: None,
        include_metadata: true,
        include_signature: true,
        include_msi: true,
    };
    let plan = prepare(request).expect("扫描计划应准备成功");
    engine::run(&plan, control, observer)
}

fn has_candidate(report: &upsweep_lib::models::ScanReport, suffix: &str) -> bool {
    report
        .candidates
        .iter()
        .any(|candidate| candidate.file.path.to_lowercase().ends_with(suffix))
}

#[test]
fn scans_update_directory_and_reads_pe_metadata() {
    let report = run_scan(
        &fixture("software-a"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );

    assert_eq!(report.status, ScanStatus::Completed);
    assert!(has_candidate(&report, r"software-a\updater\installer.exe"));
    assert!(
        !has_candidate(&report, r"software-a\app.exe"),
        "普通 EXE 不应成为候选"
    );
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.file.path.ends_with("installer.exe"))
        .expect("应找到 installer.exe");
    let pe = candidate.pe_metadata.as_ref().expect("应读取 PE 元数据");
    assert!(pe.present);
    assert_eq!(pe.product_name.as_deref(), Some("UpSweep Fixture"));
    assert_eq!(
        candidate
            .signature
            .as_ref()
            .map(|signature| signature.trust_status),
        Some(SignatureStatus::NotSigned)
    );
    assert!(report.directory_summaries.iter().any(|summary| {
        summary.path.to_lowercase().ends_with("updater") && summary.candidate_count >= 1
    }));
    assert!(!candidate.discovery.reasons.is_empty());
    assert_eq!(candidate.id.len(), 32, "候选 ID 应为 SHA-256 截断十六进制");
    assert!(candidate.file.identity.volume_serial.is_some());
    assert!(candidate.file.identity.file_id.is_some());
}

#[test]
fn candidate_ids_are_stable_across_root_casing() {
    let root = fixture("software-a");
    let uppercase_root = PathBuf::from(root.to_string_lossy().to_uppercase());
    let first = run_scan(
        &root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    let second = run_scan(
        &uppercase_root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    let first_ids: Vec<&str> = first
        .candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    let second_ids: Vec<&str> = second
        .candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    assert_eq!(first_ids, second_ids);
    assert!(first_ids.iter().all(|id| id.len() == 32));
}

#[test]
fn unicode_path_is_candidate_and_id_is_stable() {
    let report = run_scan(
        &fixture("paths"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.file.path.ends_with("安装程序_2.0.0.1.exe"))
        .expect("中文路径候选应被发现");
    assert_eq!(candidate.id.len(), 32);

    let again = run_scan(
        &fixture("paths"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    let again_candidate = again
        .candidates
        .iter()
        .find(|candidate| candidate.file.path.ends_with("安装程序_2.0.0.1.exe"))
        .expect("重复扫描应发现同一候选");
    assert_eq!(candidate.id, again_candidate.id);
}

#[test]
fn candidate_id_is_not_file_identity_for_hardlinks() {
    let root = temp_root("hardlink");
    let first_dir = root.join("a").join("updater");
    let second_dir = root.join("b").join("updater");
    fs::create_dir_all(&first_dir).expect("应创建 hardlink 目录");
    fs::create_dir_all(&second_dir).expect("应创建 hardlink 目录");
    let first = first_dir.join("one.exe");
    let second = second_dir.join("two.exe");
    fs::copy(fixture("metadata").join("versioned.exe"), &first).expect("应复制夹具");
    if fs::hard_link(&first, &second).is_err() {
        eprintln!("当前文件系统不支持硬链接，跳过该用例");
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let report = run_scan(
        &root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.candidates.len(), 2);
    assert_ne!(report.candidates[0].id, report.candidates[1].id);
    assert_eq!(
        report.candidates[0].file.identity.file_id,
        report.candidates[1].file.identity.file_id
    );
    assert_eq!(
        report.candidates[0].file.identity.volume_serial,
        report.candidates[1].file.identity.volume_serial
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn scan_results_are_repeatable() {
    let first = run_scan(
        &fixture("software-c"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    let second = run_scan(
        &fixture("software-c"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    let first_ids: Vec<&str> = first
        .candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    let second_ids: Vec<&str> = second
        .candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    assert_eq!(first_ids, second_ids);
    let first_paths: Vec<&str> = first
        .candidates
        .iter()
        .map(|candidate| candidate.file.path.as_str())
        .collect();
    let second_paths: Vec<&str> = second
        .candidates
        .iter()
        .map(|candidate| candidate.file.path.as_str())
        .collect();
    assert_eq!(first_paths, second_paths);
}

#[test]
fn preset_roots_resolve_without_scanning() {
    let request = ScanRequest {
        include_default_roots: true,
        custom_roots: Vec::new(),
        excluded_paths: Vec::new(),
        max_depth: None,
        include_metadata: true,
        include_signature: true,
        include_msi: true,
    };
    let plan = prepare(request).expect("预设扫描计划应成功");
    assert!(!plan.roots.is_empty());
    assert!(plan.roots.iter().all(|root| root.path.exists()));
}

#[test]
fn scans_msi_and_msp_metadata() {
    let report = run_scan(
        &fixture("software-b"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    let msi = report
        .candidates
        .iter()
        .find(|candidate| candidate.file.path.ends_with("PixPin_2.0.0.3.msi"))
        .expect("应发现 MSI 候选");
    let metadata = msi.msi_metadata.as_ref().expect("应读取 MSI 元数据");
    assert!(metadata.present);
    assert_eq!(metadata.product_name.as_deref(), Some("PixPin"));
    assert_eq!(metadata.product_version.as_deref(), Some("2.0.0.3"));
    let signature = msi.signature.as_ref().expect("MSI 应有签名状态");
    assert_eq!(signature.signature_present, Some(false));
    assert_eq!(signature.structure_valid, None);
    assert_eq!(signature.trust_status, SignatureStatus::NotSigned);

    let report = run_scan(
        &fixture("software-c"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    let msp = report
        .candidates
        .iter()
        .find(|candidate| candidate.file.path.ends_with("patch.msp"))
        .expect("应发现 MSP 候选");
    let metadata = msp.msi_metadata.as_ref().expect("应读取 MSP 元数据");
    assert_eq!(
        metadata.package_type,
        upsweep_lib::models::MsiPackageType::Patch
    );
    assert!(has_candidate(&report, r"cache\cached-installer.exe"));
}

#[test]
fn ordinary_directory_does_not_produce_candidates() {
    let report = run_scan(
        &fixture("normal"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    assert!(report.candidates.is_empty());
}

#[test]
fn exclusion_skips_candidate_directory() {
    let excluded = fixture("software-a").join("updater");
    let report = run_scan(
        &fixture("software-a"),
        vec![excluded.to_string_lossy().into_owned()],
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    assert!(report.candidates.is_empty());
    assert!(report.totals.skipped_excluded >= 1);
}

#[test]
fn corrupt_exe_is_reported_without_crashing_scan() {
    let report = run_scan(
        &fixture("software-c"),
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    let corrupt = report
        .candidates
        .iter()
        .find(|candidate| candidate.file.path.ends_with("corrupt.exe"))
        .expect("损坏的 EXE 仍应作为候选被记录");
    assert!(
        corrupt
            .metadata_issues
            .iter()
            .any(|issue| issue.kind == "peVersion")
    );
}

struct CollectProgress {
    progress: std::sync::Mutex<Vec<upsweep_lib::models::ScanProgress>>,
}

impl CollectProgress {
    fn new() -> Self {
        Self {
            progress: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl ScanObserver for CollectProgress {
    fn on_progress(&self, progress: &upsweep_lib::models::ScanProgress) {
        self.progress.lock().expect("进度锁").push(progress.clone());
    }

    fn on_candidate(&self, _candidate: &upsweep_lib::models::ScanCandidate) {}
}

#[test]
fn progress_reports_start_finalize_and_counts() {
    let observer = CollectProgress::new();
    let report = run_scan(
        &fixture("software-a"),
        Vec::new(),
        &observer,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    let progress = observer.progress.into_inner().expect("进度锁");
    assert!(!progress.is_empty());
    assert_eq!(
        progress.first().map(|item| item.phase),
        Some(upsweep_lib::models::ScanPhase::Preparing)
    );
    assert_eq!(
        progress.last().map(|item| item.phase),
        Some(upsweep_lib::models::ScanPhase::Finalizing)
    );
    assert!(progress.iter().any(|item| item.scanned_files >= 2));
    assert!(progress.iter().any(|item| item.candidates_found >= 1));
}

struct CancelOnProgress {
    control: ScanControl,
}

impl ScanObserver for CancelOnProgress {
    fn on_progress(&self, _progress: &upsweep_lib::models::ScanProgress) {
        self.control.cancel();
    }

    fn on_candidate(&self, _candidate: &upsweep_lib::models::ScanCandidate) {}
}

#[test]
fn cancellation_returns_a_report_and_releases_threads() {
    let control = ScanControl::new();
    let observer = CancelOnProgress {
        control: control.clone(),
    };
    let report = run_scan(&fixture("software-a"), Vec::new(), &observer, &control);
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert!(
        report
            .log
            .iter()
            .any(|event| event.event == "scan_cancelled")
    );
}

struct CancelOnCandidate {
    control: ScanControl,
}

impl ScanObserver for CancelOnCandidate {
    fn on_progress(&self, _progress: &upsweep_lib::models::ScanProgress) {}

    fn on_candidate(&self, _candidate: &upsweep_lib::models::ScanCandidate) {
        self.control.cancel();
    }
}

#[test]
fn cancellation_during_metadata_finishes_without_deadlock() {
    let control = ScanControl::new();
    let observer = CancelOnCandidate {
        control: control.clone(),
    };
    let report = run_scan(&fixture("software-c"), Vec::new(), &observer, &control);
    assert_eq!(report.status, ScanStatus::Cancelled);
    // 取消发生在 worker 处理候选期间；已完成的结果可以保留，但必须无死锁地返回。
    assert!(
        report
            .log
            .iter()
            .any(|event| event.event == "scan_cancelled")
    );
}

fn temp_root(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "upsweep_scanner_test_{}_{}",
        std::process::id(),
        name
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("应创建临时目录");
    path
}

fn create_junction(link: &Path, target: &Path) -> bool {
    Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[test]
fn junction_is_not_followed() {
    let root = temp_root("junction");
    let target = root.join("target");
    let linked = root.join("linked");
    fs::create_dir_all(&target).expect("应创建目标目录");
    fs::copy(
        fixture("metadata").join("plain.exe"),
        target.join("installer.exe"),
    )
    .expect("应复制夹具");

    if !create_junction(&linked, &target) {
        eprintln!("当前环境无法创建 junction，跳过该用例");
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let report = run_scan(
        &root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    assert!(
        !report.candidates.iter().any(|candidate| candidate
            .file
            .path
            .to_lowercase()
            .contains("linked")),
        "不应跟随 junction 进入目标目录"
    );
    assert!(report.totals.skipped_reparse_points >= 1);
    assert!(
        report
            .log
            .iter()
            .any(|event| event.event == "reparse_point_skipped")
    );

    let _ = fs::remove_dir(&linked);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn junction_loop_is_not_followed() {
    let root = temp_root("junction_loop");
    let loop_link = root.join("loop");
    if !create_junction(&loop_link, &root) {
        eprintln!("当前环境无法创建 junction，跳过该用例");
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let report = run_scan(
        &root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    assert!(report.totals.skipped_reparse_points >= 1);
    assert!(
        report
            .log
            .iter()
            .any(|event| event.event == "reparse_point_skipped")
    );

    let _ = fs::remove_dir(&loop_link);
    if loop_link.exists() {
        let _ = Command::new("cmd")
            .args(["/C", "rmdir"])
            .arg(&loop_link)
            .status();
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn symlink_is_not_followed_if_creation_is_allowed() {
    let root = temp_root("symlink");
    let target = root.join("target");
    let linked = root.join("linked");
    fs::create_dir_all(&target).expect("应创建目标目录");
    fs::copy(
        fixture("metadata").join("plain.exe"),
        target.join("installer.exe"),
    )
    .expect("应复制夹具");

    if std::os::windows::fs::symlink_dir(&target, &linked).is_err() {
        eprintln!("当前环境无法创建符号链接，跳过该用例");
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let report = run_scan(
        &root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    assert!(
        !report.candidates.iter().any(|candidate| candidate
            .file
            .path
            .to_lowercase()
            .contains("linked"))
    );
    assert!(report.totals.skipped_reparse_points >= 1);
    let _ = fs::remove_dir(&linked);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn inaccessible_directory_is_recorded_and_scan_continues() {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, OPEN_EXISTING,
    };

    let root = temp_root("permission");
    let blocked = root.join("blocked");
    let allowed = root.join("allowed").join("updater");
    fs::create_dir_all(&blocked).expect("应创建受限目录");
    fs::create_dir_all(&allowed).expect("应创建可访问目录");
    fs::copy(
        fixture("metadata").join("versioned.exe"),
        blocked.join("installer.exe"),
    )
    .expect("应复制受限目录夹具");
    fs::copy(
        fixture("metadata").join("versioned.exe"),
        allowed.join("installer.exe"),
    )
    .expect("应复制可访问目录夹具");

    let wide: Vec<u16> = blocked
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // 以不共享的方式持有目录句柄，使扫描器的 read_dir 得到访问/共享冲突。
    // SAFETY: 路径为 NUL 结尾；句柄在测试结束前保持有效并显式关闭。
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        eprintln!("当前环境无法独占打开目录，跳过该用例");
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let report = run_scan(
        &root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    // SAFETY: handle 由 CreateFileW 成功返回。
    unsafe {
        CloseHandle(handle);
    }

    assert_eq!(report.status, ScanStatus::Completed);
    assert!(report.issues.iter().any(|issue| {
        issue.kind == upsweep_lib::models::ScanIssueKind::DirectoryAccess
            && issue
                .path
                .as_deref()
                .is_some_and(|path| path.contains("blocked"))
    }));
    assert!(
        has_candidate(&report, r"allowed\updater\installer.exe"),
        "一个目录不可访问不应阻止其他目录继续扫描"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn long_path_can_be_scanned() {
    let root = temp_root("longpath");
    let mut deep = root.clone();
    for index in 0..18 {
        deep.push(format!("directory_segment_{index:02}"));
    }
    if fs::create_dir_all(&deep).is_err() {
        eprintln!("当前环境无法创建长路径，跳过该用例");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    fs::copy(
        fixture("metadata").join("versioned.exe"),
        deep.join("PixPin_2.0.0.3.exe"),
    )
    .expect("应复制长路径夹具");

    let report = run_scan(
        &root,
        Vec::new(),
        &engine::NoopObserver,
        &ScanControl::new(),
    );
    assert_eq!(report.status, ScanStatus::Completed);
    assert!(has_candidate(&report, "pixpin_2.0.0.3.exe"));
    let _ = fs::remove_dir_all(&root);
}
