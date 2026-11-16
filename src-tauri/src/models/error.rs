use std::fmt;

use serde::Serialize;

/// 可序列化到前端的应用错误。
///
/// Tauri 命令返回的错误必须实现 `Serialize`。这里保留稳定的错误码和可读信息，
/// 前端可以据此展示提示，但不向界面暴露底层调用栈。
#[derive(Debug, Clone, Serialize)]
pub struct AppError {
    pub code: String,
    pub message: String,
}

impl AppError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}
