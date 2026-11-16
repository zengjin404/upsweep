use serde::Serialize;

/// 应用基础信息，用于验证 Tauri 运行时和路径解析是否正常。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub product_name: String,
    pub package_name: String,
    pub version: String,
    pub identifier: String,
    pub data_dir: String,
    pub build_profile: String,
}

/// SQLite 自检结果。全部字段来自真实数据库操作，不使用模拟数据。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseCheckReport {
    pub ok: bool,
    pub engine_version: String,
    pub schema_version: i64,
    pub database_path: Option<String>,
    pub database_size_bytes: Option<u64>,
    pub roundtrip_ok: bool,
    pub elapsed_ms: u64,
}

/// 单次 Windows API 调用的结果。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsApiCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Windows API 探测结果。单项失败不会中断其余探测，便于定位环境问题。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProbeReport {
    pub ok: bool,
    pub windows_directory: Option<String>,
    pub system_directory: Option<String>,
    pub probe_file: Option<String>,
    pub checks: Vec<WindowsApiCheck>,
}
