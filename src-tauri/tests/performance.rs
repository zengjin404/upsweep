//! 可选性能测量。默认忽略，避免常规测试受机器负载影响。
//!
//! 运行：cargo test --test performance -- --ignored --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use upsweep_lib::models::{ScanRequest, ScanStatus};
use upsweep_lib::scanner::{ScanControl, engine, prepare};

fn fixture_exe() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("metadata")
        .join("versioned.exe")
}

#[test]
#[ignore = "性能测量，按需运行"]
fn synthetic_tree_throughput() {
    let root = std::env::temp_dir().join(format!("upsweep_perf_{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("创建性能测试根目录");

    let source = fixture_exe();
    let candidate_dirs = 50usize;
    let candidates_per_dir = 5usize;
    let normal_dirs = 100usize;
    let files_per_normal_dir = 10usize;

    for directory in 0..candidate_dirs {
        let updater = root
            .join(format!("candidate_{directory:03}"))
            .join("updater");
        fs::create_dir_all(&updater).expect("创建候选目录");
        for file in 0..candidates_per_dir {
            fs::copy(&source, updater.join(format!("installer_{file}.exe"))).expect("复制候选夹具");
        }
    }
    for directory in 0..normal_dirs {
        let normal = root.join(format!("normal_{directory:03}"));
        fs::create_dir_all(&normal).expect("创建普通目录");
        for file in 0..files_per_normal_dir {
            fs::write(normal.join(format!("note_{file}.txt")), b"x").expect("写入普通文件");
        }
    }

    let request = ScanRequest {
        include_default_roots: false,
        custom_roots: vec![root.to_string_lossy().into_owned()],
        excluded_paths: Vec::new(),
        max_depth: None,
        include_metadata: true,
        include_signature: true,
        include_msi: true,
    };
    let plan = prepare(request).expect("准备扫描计划");
    let started = Instant::now();
    let report = engine::run(&plan, &ScanControl::new(), &engine::NoopObserver);
    let elapsed = started.elapsed();

    println!(
        "PERF status={:?} dirs={} files={} candidates={} metadata={} signatures={} elapsed_ms={} files_per_sec={:.0}",
        report.status,
        report.totals.directories,
        report.totals.files,
        report.totals.candidates,
        report.totals.metadata_read,
        report.totals.signatures_read,
        elapsed.as_millis(),
        report.totals.files as f64 / elapsed.as_secs_f64().max(0.001)
    );

    assert_eq!(report.status, ScanStatus::Completed);
    assert_eq!(
        report.totals.candidates as usize,
        candidate_dirs * candidates_per_dir
    );

    let _ = fs::remove_dir_all(&root);
}
