//! Windows API 封装的外部集成测试。
//!
//! 只做只读探测（系统目录和文件属性），不执行任何写入或删除操作。

#![cfg(windows)]

use upsweep_lib::utils::windows_api;

#[test]
fn probe_reports_all_core_checks() {
    let report = windows_api::probe();

    assert!(report.ok, "探测应全部通过: {:?}", report.checks);
    assert_eq!(report.checks.len(), 3);
    assert!(report.windows_directory.is_some());
    assert!(report.system_directory.is_some());
    assert!(report.probe_file.is_some());
}
