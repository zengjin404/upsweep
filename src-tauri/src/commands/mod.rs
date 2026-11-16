//! Tauri 命令入口。
//!
//! 命令只负责参数接收和结果返回；文件系统、数据库和 Windows API 操作
//! 必须委托给底层模块，便于独立测试和后续安全复核。

pub mod diagnostics;
pub mod system;
