//! 阶段 1 扫描引擎。
//!
//! `plan` 负责路径解析与安全校验，`discovery` 负责多维度候选发现，
//! `engine` 负责遍历、并发元数据读取、进度/取消/错误收集。
//! 本模块不包含风险分类、清理计划或任何文件修改操作。

pub mod discovery;
pub mod engine;
pub mod manager;
pub mod plan;

pub use engine::{NoopObserver, ScanControl, ScanObserver};
pub use manager::ScanManager;
pub use plan::{ScanPlan, prepare};
