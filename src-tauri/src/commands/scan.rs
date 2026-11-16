use tauri::{AppHandle, Emitter, State};

use crate::models::{
    AppError, InstalledSoftwareReport, ScanCandidate, ScanProgress, ScanReport, ScanRequest,
    ScanSessionInfo,
};
use crate::scanner::{ScanControl, ScanManager, ScanObserver, engine, prepare};
use crate::software;

struct TauriScanObserver {
    app: AppHandle,
}

impl ScanObserver for TauriScanObserver {
    fn on_progress(&self, progress: &ScanProgress) {
        let _ = self.app.emit("scan-progress", progress.clone());
    }

    fn on_candidate(&self, candidate: &ScanCandidate) {
        let _ = self.app.emit("scan-candidate", candidate.clone());
    }
}

/// 创建扫描会话并在后台线程执行。命令立即返回；进度与结果通过事件推送。
#[tauri::command]
pub fn start_scan(
    app: AppHandle,
    manager: State<'_, ScanManager>,
    request: ScanRequest,
) -> Result<ScanSessionInfo, AppError> {
    let plan = prepare(request)?;
    let info = ScanSessionInfo {
        session_id: plan.session_id.clone(),
        started_at_ms: plan.started_at_ms,
        roots: plan.root_infos(),
        exclusions: plan.exclusion_infos(),
    };

    let control = ScanControl::new();
    manager.register(info.session_id.clone(), control.clone());
    let manager = manager.inner().clone();
    let session_id = info.session_id.clone();
    let app_for_thread = app.clone();

    std::thread::spawn(move || {
        let observer = TauriScanObserver {
            app: app_for_thread.clone(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine::run(&plan, &control, &observer)
        }));

        match result {
            Ok(report) => {
                manager.complete(&session_id, report.clone());
                if let Err(error) = app_for_thread.emit("scan-finished", report) {
                    eprintln!("无法发送 scan-finished 事件: {error}");
                }
            }
            Err(_) => {
                manager.fail(&session_id);
                let error = AppError::new("SCAN_INTERNAL_ERROR", "扫描线程发生内部错误");
                let _ = app_for_thread.emit("scan-error", error);
            }
        }
    });

    Ok(info)
}

#[tauri::command]
pub fn cancel_scan(manager: State<'_, ScanManager>, session_id: String) -> bool {
    manager.cancel(&session_id)
}

#[tauri::command]
pub fn get_scan_report(manager: State<'_, ScanManager>, session_id: String) -> Option<ScanReport> {
    manager.report(&session_id)
}

#[tauri::command]
pub fn is_scan_active(manager: State<'_, ScanManager>, session_id: String) -> bool {
    manager.is_active(&session_id)
}

/// 只读采集已安装软件。放到阻塞线程池，避免注册表读取影响界面响应。
#[tauri::command]
pub async fn get_installed_software() -> Result<InstalledSoftwareReport, AppError> {
    tauri::async_runtime::spawn_blocking(software::read_installed_software)
        .await
        .map_err(|error| AppError::new("SOFTWARE_READ_FAILED", error.to_string()))
}
