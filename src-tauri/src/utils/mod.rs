//! 通用底层封装。
//!
//! Windows 原生 API 只在 Windows 目标编译；业务代码通过本模块访问，
//! 不直接依赖 `windows-sys`。

#[cfg(windows)]
pub mod windows_api;
