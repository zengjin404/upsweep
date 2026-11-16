//! 真实软件安装目录只读扫描。
//!
//! 默认使用本机 EdgeUpdate 目录；可通过 `UPSWEEP_REAL_SCAN_ROOT` 指定其他目录。
//! 只读取文件属性、PE/MSI 元数据与签名状态，不修改任何文件。
//! 默认 ignored，按需运行：
//! `cargo test --test real_scan -- --ignored --nocapture`

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use upsweep_lib::models::{ScanRequest, ScanStatus, SignatureStatus};
use upsweep_lib::scanner::{ScanControl, engine, prepare};
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

fn memory_counters() -> PROCESS_MEMORY_COUNTERS {
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: counters 是有效可写结构，cb 已设置。
    let ok = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if ok == 0 {
        eprintln!(
            "GetProcessMemoryInfo 失败: {}",
            std::io::Error::last_os_error()
        );
    }
    counters
}

fn choose_root() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("UPSWEEP_REAL_SCAN_ROOT") {
        let path = PathBuf::from(value);
        if path.is_dir() {
            return Some(path);
        }
    }
    [
        r"C:\Program Files (x86)\Microsoft\EdgeUpdate",
        r"C:\Program Files\7-Zip",
        r"C:\Program Files\Common Files\microsoft shared\ClickToRun",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| path.is_dir())
}

fn request(root: &Path) -> ScanRequest {
    ScanRequest {
        include_default_roots: false,
        custom_roots: vec![root.to_string_lossy().into_owned()],
        excluded_paths: Vec::new(),
        max_depth: None,
        include_metadata: true,
        include_signature: true,
        include_msi: true,
    }
}

#[test]
#[ignore = "真实目录只读性能/资源测量"]
fn real_install_directory_read_only_scan() {
    let Some(root) = choose_root() else {
        eprintln!("没有可用的真实软件目录，跳过");
        return;
    };

    let before = memory_counters();
    let started = Instant::now();
    let plan = prepare(request(&root)).expect("准备真实目录扫描计划");
    let report = engine::run(&plan, &ScanControl::new(), &engine::NoopObserver);
    let elapsed = started.elapsed();
    let after = memory_counters();

    assert_eq!(report.status, ScanStatus::Completed);
    let pe_candidates: Vec<_> = report
        .candidates
        .iter()
        .filter(|candidate| candidate.pe_metadata.is_some())
        .collect();
    let pe_present = pe_candidates
        .iter()
        .filter(|candidate| candidate.pe_metadata.as_ref().is_some_and(|pe| pe.present))
        .count();
    let msi_candidates: Vec<_> = report
        .candidates
        .iter()
        .filter(|candidate| candidate.msi_metadata.is_some())
        .collect();
    let msi_present = msi_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .msi_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.present)
        })
        .count();
    let signature_read = report
        .candidates
        .iter()
        .filter(|candidate| candidate.signature.is_some())
        .count();
    let signature_valid = report
        .candidates
        .iter()
        .filter(|candidate| {
            candidate
                .signature
                .as_ref()
                .is_some_and(|signature| signature.trust_status == SignatureStatus::Valid)
        })
        .count();
    let signature_not_signed = report
        .candidates
        .iter()
        .filter(|candidate| {
            candidate
                .signature
                .as_ref()
                .is_some_and(|signature| signature.trust_status == SignatureStatus::NotSigned)
        })
        .count();

    println!(
        "REAL_SCAN root={} dirs={} files={} candidates={} pe={}/{} msi={}/{} signatures={} valid={} not_signed={} issues={} elapsed_ms={} ws_before_mb={:.1} ws_after_mb={:.1} peak_ws_mb={:.1}",
        root.display(),
        report.totals.directories,
        report.totals.files,
        report.totals.candidates,
        pe_present,
        pe_candidates.len(),
        msi_present,
        msi_candidates.len(),
        signature_read,
        signature_valid,
        signature_not_signed,
        report.issues.len(),
        elapsed.as_millis(),
        before.WorkingSetSize as f64 / 1024.0 / 1024.0,
        after.WorkingSetSize as f64 / 1024.0 / 1024.0,
        after.PeakWorkingSetSize as f64 / 1024.0 / 1024.0,
    );

    // 取消响应：真实目录上启动第二次只读扫描，短暂延迟后取消并等待 join。
    let cancel_plan = prepare(request(&root)).expect("准备取消测试计划");
    let control = ScanControl::new();
    let control_for_thread = control.clone();
    let handle = std::thread::spawn(move || {
        engine::run(&cancel_plan, &control_for_thread, &engine::NoopObserver)
    });
    std::thread::sleep(Duration::from_millis(5));
    let cancel_started = Instant::now();
    control.cancel();
    let cancelled_report = handle.join().expect("取消扫描线程应正常结束");
    let cancel_response = cancel_started.elapsed();
    println!(
        "REAL_SCAN_CANCEL requested_status={:?} response_ms={} candidates={}",
        cancelled_report.status,
        cancel_response.as_millis(),
        cancelled_report.candidates.len()
    );
    assert!(matches!(
        cancelled_report.status,
        ScanStatus::Cancelled | ScanStatus::Completed
    ));
}
