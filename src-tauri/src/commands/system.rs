use tauri::AppHandle;

use crate::config;
use crate::models::{AppError, AppInfo};

/// 返回应用名称、版本、标识符和数据目录。
///
/// 数据目录通过 Tauri 路径解析器获取，用于确认运行时权限和路径 API 正常。
#[tauri::command]
pub fn get_app_info(app: AppHandle) -> Result<AppInfo, AppError> {
    let data_dir = config::app_data_dir(&app)?;
    let product_name = app
        .config()
        .product_name
        .clone()
        .unwrap_or_else(|| config::PRODUCT_NAME.to_string());

    Ok(AppInfo {
        product_name,
        package_name: app.package_info().crate_name.to_string(),
        version: app.package_info().version.to_string(),
        identifier: app.config().identifier.clone(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        build_profile: if cfg!(debug_assertions) {
            "debug".to_string()
        } else {
            "release".to_string()
        },
    })
}
