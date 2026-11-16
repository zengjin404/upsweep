//! UpSweep 后端入口。
//!
//! 阶段 0 只注册诊断类命令；不包含文件扫描、删除或目录清理逻辑。
//! 后续模块必须按开发手册分阶段接入，不能在命令层直接操作文件系统。

pub mod commands;
pub mod config;
pub mod database;
pub mod models;
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
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::system::get_app_info,
            commands::diagnostics::run_database_check,
            commands::diagnostics::probe_windows_api,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("UpSweep 启动失败: {error}");
        std::process::exit(1);
    }
}
