//! UpSweep 后端入口。
//!
//! 阶段 1 增加只读扫描与元数据采集；仍不包含风险分类、清理计划或任何文件修改操作。
//! 命令层只做编排，文件系统/Windows API 访问集中在独立模块。

pub mod analyzer;
pub mod commands;
pub mod config;
pub mod database;
pub mod metadata;
pub mod models;
pub mod protection;
pub mod scanner;
pub mod signature;
pub mod software;
pub mod utils;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .setup(|app| {
            // 数据库初始化失败时不阻止窗口启动，错误会通过诊断命令返回前端。
            let state = match config::app_data_dir(app.handle()) {
                Ok(directory) => {
                    database::DatabaseState::initialize(directory.join(config::DATABASE_FILENAME))
                }
                Err(error) => database::DatabaseState::failed(error.to_string()),
            };
            app.manage(state);
            app.manage(scanner::ScanManager::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::system::get_app_info,
            commands::diagnostics::run_database_check,
            commands::diagnostics::probe_windows_api,
            commands::scan::start_scan,
            commands::scan::cancel_scan,
            commands::scan::get_scan_report,
            commands::scan::is_scan_active,
            commands::scan::get_installed_software,
            commands::analyze::analyze_scan,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("UpSweep 启动失败: {error}");
        std::process::exit(1);
    }
}
