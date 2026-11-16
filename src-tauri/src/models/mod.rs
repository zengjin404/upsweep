//! 前后端共享的数据结构。
//!
//! 阶段 0 只包含诊断相关模型。扫描、风险分析、清理计划等模型将在对应阶段加入，
//! 避免提前定义尚未验证的业务契约。

mod error;
mod reports;

pub use error::AppError;
pub use reports::{AppInfo, DatabaseCheckReport, WindowsApiCheck, WindowsProbeReport};
