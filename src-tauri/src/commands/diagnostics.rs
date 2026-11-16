use tauri::State;

use crate::database::DatabaseState;
use crate::models::{AppError, DatabaseCheckReport, WindowsProbeReport};

/// 对应用数据库执行一次真实事务自检（写入、读回、删除）。
#[tauri::command]
pub fn run_database_check(
    state: State<'_, DatabaseState>,
) -> Result<DatabaseCheckReport, AppError> {
    state.run_self_check()
}

/// 执行最小 Windows API 探测（系统目录解析 + 文件属性读取）。
#[tauri::command]
pub fn probe_windows_api() -> Result<WindowsProbeReport, AppError> {
    #[cfg(windows)]
    {
        Ok(crate::utils::windows_api::probe())
    }

    #[cfg(not(windows))]
    {
        Err(AppError::new(
            "UNSUPPORTED_PLATFORM",
            "Windows API 探测仅在 Windows 上可用",
        ))
    }
}
