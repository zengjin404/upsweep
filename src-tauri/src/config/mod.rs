//! 应用级常量与路径解析。
//!
//! 路径必须通过 Tauri/Windows 提供的目录 API 获取，不能假定用户机器的盘符或目录布局。

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

use crate::models::AppError;

pub const PRODUCT_NAME: &str = "过河拆包";
pub const PRODUCT_SUBTITLE: &str = "升级残留清理器";

/// 应用数据目录名。按开发手册约定位于 `%LOCALAPPDATA%\upsweep`，
/// 而不是 Tauri 默认的 `%LOCALAPPDATA%\<bundle identifier>`。
pub const APP_DIR_NAME: &str = "upsweep";

pub const DATABASE_FILENAME: &str = "upsweep.db";

/// 解析应用数据目录（不保证目录已存在，数据库打开时会创建）。
pub fn app_data_dir(app: &AppHandle) -> Result<PathBuf, AppError> {
    let base = app.path().local_data_dir().map_err(|error| {
        AppError::new(
            "PATH_RESOLVE_FAILED",
            format!("无法获取本地应用数据目录: {error}"),
        )
    })?;
    Ok(base.join(APP_DIR_NAME))
}
