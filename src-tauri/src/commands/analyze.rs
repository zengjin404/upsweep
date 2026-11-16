use tauri::State;

use crate::analyzer;
use crate::models::{AppError, RiskReport};
use crate::scanner::ScanManager;
use crate::software;

/// 对已完成的扫描报告执行风险判断。只读读取卸载注册表，不修改文件。
#[tauri::command]
pub async fn analyze_scan(
    manager: State<'_, ScanManager>,
    session_id: String,
) -> Result<RiskReport, AppError> {
    let report = manager.report(&session_id).ok_or_else(|| {
        AppError::new(
            "SCAN_REPORT_NOT_FOUND",
            format!("找不到扫描报告 {session_id}；请先完成扫描"),
        )
    })?;

    tauri::async_runtime::spawn_blocking(move || {
        let software = software::read_installed_software();
        analyzer::analyze(&report, &software)
    })
    .await
    .map_err(|error| AppError::new("ANALYSIS_FAILED", error.to_string()))
}
