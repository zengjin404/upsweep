//! Windows 原生 API 的安全封装。
//!
//! 业务模块不得直接调用 `unsafe` FFI。阶段 0 只封装路径与文件属性查询，
//! 用于验证 Windows API 调用链路；文件删除、回收站等接口将在阶段 6 按手册要求
//! 单独实现并测试，禁止提前引入。
//!
//! 本阶段调用的 API：
//! - `GetWindowsDirectoryW` / `GetSystemDirectoryW`：获取系统目录，验证路径解析。
//! - `GetFileAttributesW`：读取文件属性，验证文件系统元数据访问。

use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_CASE_SENSITIVE_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileCaseSensitiveInfo,
    GetFileAttributesW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    INVALID_FILE_ATTRIBUTES, OPEN_EXISTING,
};

/// `FILE_CS_FLAG_CASE_SENSITIVE_DIR`（Win32 SystemServices 常量）。
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 1;
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

use crate::models::{WindowsApiCheck, WindowsProbeReport};

/// `GetWindowsDirectoryW` 文档中的常规缓冲区大小（MAX_PATH）。
const INITIAL_PATH_BUFFER: usize = 260;

#[derive(Debug, Clone)]
pub struct WindowsApiError {
    operation: &'static str,
    message: String,
}

impl fmt::Display for WindowsApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} 调用失败: {}", self.operation, self.message)
    }
}

impl std::error::Error for WindowsApiError {}

fn last_error(operation: &'static str) -> WindowsApiError {
    WindowsApiError {
        operation,
        message: std::io::Error::last_os_error().to_string(),
    }
}

/// 调用返回系统路径的 Win32 API，并正确处理缓冲区不足的情况。
///
/// API 返回值为不含终止符的字符数；缓冲区不足时返回所需大小。
fn query_system_path<F>(operation: &'static str, mut call: F) -> Result<PathBuf, WindowsApiError>
where
    F: FnMut(*mut u16, u32) -> u32,
{
    let mut buffer = vec![0u16; INITIAL_PATH_BUFFER];
    let mut length = call(buffer.as_mut_ptr(), buffer.len() as u32);

    if length == 0 {
        return Err(last_error(operation));
    }

    if length as usize >= buffer.len() {
        buffer.resize(length as usize + 1, 0);
        length = call(buffer.as_mut_ptr(), buffer.len() as u32);
        if length == 0 {
            return Err(last_error(operation));
        }
        if length as usize >= buffer.len() {
            return Err(WindowsApiError {
                operation,
                message: "系统返回的路径长度超出缓冲区".to_string(),
            });
        }
    }

    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(length as usize);
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..end])))
}

pub fn windows_directory() -> Result<PathBuf, WindowsApiError> {
    query_system_path("GetWindowsDirectoryW", |buffer, length| unsafe {
        GetWindowsDirectoryW(buffer, length)
    })
}

pub fn system_directory() -> Result<PathBuf, WindowsApiError> {
    query_system_path("GetSystemDirectoryW", |buffer, length| unsafe {
        GetSystemDirectoryW(buffer, length)
    })
}

/// 读取路径的 `FILE_ATTRIBUTE_*` 标志位。路径不存在或无权限时返回错误。
pub fn file_attributes(path: &Path) -> Result<u32, WindowsApiError> {
    let wide_path = to_wide_null(path);
    // SAFETY: `wide_path` 以 NUL 结尾并保持存活直到调用返回；API 不保留该指针。
    let attributes = unsafe { GetFileAttributesW(wide_path.as_ptr()) };

    if attributes == INVALID_FILE_ATTRIBUTES {
        Err(last_error("GetFileAttributesW"))
    } else {
        Ok(attributes)
    }
}

pub fn is_directory(path: &Path) -> Result<bool, WindowsApiError> {
    Ok(file_attributes(path)? & FILE_ATTRIBUTE_DIRECTORY != 0)
}

/// 只读文件身份信息：卷序列号与文件 ID，用于后续清理前复核。
#[derive(Debug, Clone)]
pub struct FileIdentityInfo {
    pub volume_serial: Option<u32>,
    pub file_id: Option<u64>,
    pub read_error: Option<String>,
}

/// 以 FILE_READ_ATTRIBUTES 打开文件并读取卷序列号/文件 ID。
///
/// 使用 `FILE_FLAG_OPEN_REPARSE_POINT`，不会跟随重解析点；调用方仍应在
/// 扫描阶段先拒绝重解析点。失败只返回错误信息，不影响扫描任务。
pub fn file_identity(path: &Path) -> FileIdentityInfo {
    let wide_path = to_wide_null(path);
    // SAFETY: 路径为 NUL 结尾；不请求写权限；句柄在函数内关闭。
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return FileIdentityInfo {
            volume_serial: None,
            file_id: None,
            read_error: Some(format!(
                "CreateFileW({}) 失败: {}",
                path.display(),
                std::io::Error::last_os_error()
            )),
        };
    }

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: handle 有效；info 是有效可写结构。
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    // SAFETY: handle 由 CreateFileW 成功返回，且只关闭一次。
    unsafe {
        CloseHandle(handle);
    }

    if ok == 0 {
        return FileIdentityInfo {
            volume_serial: None,
            file_id: None,
            read_error: Some(format!(
                "GetFileInformationByHandle({}) 失败: {}",
                path.display(),
                std::io::Error::last_os_error()
            )),
        };
    }

    FileIdentityInfo {
        volume_serial: Some(info.dwVolumeSerialNumber),
        file_id: Some((u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)),
        read_error: None,
    }
}

/// 查询目录是否启用了 NTFS 目录级大小写敏感（需要 Windows 10 1803+）。
///
/// 查询失败时不改变扫描比较语义；扫描器会把失败记录为警告，并继续使用
/// Windows 默认的大小写不敏感路径键。
pub fn is_case_sensitive_directory(path: &Path) -> Result<bool, WindowsApiError> {
    let wide_path = to_wide_null(path);
    // SAFETY: 路径为 NUL 结尾；目录使用 FILE_FLAG_BACKUP_SEMANTICS；
    // 只请求属性访问，句柄在函数内关闭。
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(WindowsApiError {
            operation: "CreateFileW",
            message: format!("{}: {}", path.display(), std::io::Error::last_os_error()),
        });
    }

    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: handle 有效；info 是有效可写结构，大小与 API 要求一致。
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileCaseSensitiveInfo,
            (&mut info as *mut FILE_CASE_SENSITIVE_INFO).cast::<core::ffi::c_void>(),
            std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    };
    // SAFETY: handle 由 CreateFileW 成功返回，且只关闭一次。
    unsafe {
        CloseHandle(handle);
    }

    if ok == 0 {
        return Err(WindowsApiError {
            operation: "GetFileInformationByHandleEx(FileCaseSensitiveInfo)",
            message: format!("{}: {}", path.display(), std::io::Error::last_os_error()),
        });
    }
    Ok(info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileUsageInfo {
    NotInUse,
    InUse,
    Unknown(String),
}

/// 以独占方式尝试打开文件，用于启发式判断文件是否被占用。
///
/// 共享冲突（ERROR_SHARING_VIOLATION）视为可能正在使用；权限不足或其他错误
/// 返回 Unknown。该接口不能列出占用进程，也不能证明文件绝对未被使用。
pub fn file_usage(path: &Path) -> FileUsageInfo {
    let wide_path = to_wide_null(path);
    // SAFETY: 路径为 NUL 结尾；请求只读访问，不写入；句柄在函数内关闭。
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(32) {
            FileUsageInfo::InUse
        } else {
            FileUsageInfo::Unknown(error.to_string())
        };
    }
    // SAFETY: handle 由 CreateFileW 成功返回，且只关闭一次。
    unsafe {
        CloseHandle(handle);
    }
    FileUsageInfo::NotInUse
}

pub(crate) fn to_wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// 执行一组最小 Windows API 探测。
///
/// 单项失败不会中断其余调用，结果逐项返回给前端，便于定位环境问题。
pub fn probe() -> WindowsProbeReport {
    let mut checks = Vec::new();

    let windows_dir = match windows_directory() {
        Ok(path) => {
            let is_dir = is_directory(&path).unwrap_or(false);
            checks.push(WindowsApiCheck {
                name: "GetWindowsDirectoryW".to_string(),
                passed: is_dir,
                detail: format!(
                    "{}（{}）",
                    path.display(),
                    if is_dir {
                        "目录存在"
                    } else {
                        "目录不可访问"
                    }
                ),
            });
            Some(path)
        }
        Err(error) => {
            checks.push(WindowsApiCheck {
                name: "GetWindowsDirectoryW".to_string(),
                passed: false,
                detail: error.to_string(),
            });
            None
        }
    };

    let system_dir = match system_directory() {
        Ok(path) => {
            let is_dir = is_directory(&path).unwrap_or(false);
            checks.push(WindowsApiCheck {
                name: "GetSystemDirectoryW".to_string(),
                passed: is_dir,
                detail: format!(
                    "{}（{}）",
                    path.display(),
                    if is_dir {
                        "目录存在"
                    } else {
                        "目录不可访问"
                    }
                ),
            });
            Some(path)
        }
        Err(error) => {
            checks.push(WindowsApiCheck {
                name: "GetSystemDirectoryW".to_string(),
                passed: false,
                detail: error.to_string(),
            });
            None
        }
    };

    let mut probe_file = None;
    match &windows_dir {
        Some(directory) => {
            // kernel32.dll 是每个 Windows 安装都存在的系统文件，适合做只读属性探测。
            let candidate = directory.join("System32").join("kernel32.dll");
            match file_attributes(&candidate) {
                Ok(attributes) => {
                    let passed = attributes & FILE_ATTRIBUTE_DIRECTORY == 0;
                    checks.push(WindowsApiCheck {
                        name: "GetFileAttributesW".to_string(),
                        passed,
                        detail: format!("{}（属性 0x{:08X}）", candidate.display(), attributes),
                    });
                    probe_file = Some(candidate);
                }
                Err(error) => {
                    checks.push(WindowsApiCheck {
                        name: "GetFileAttributesW".to_string(),
                        passed: false,
                        detail: error.to_string(),
                    });
                    probe_file = Some(candidate);
                }
            }
        }
        None => {
            checks.push(WindowsApiCheck {
                name: "GetFileAttributesW".to_string(),
                passed: false,
                detail: "无法取得 Windows 目录，已跳过文件属性探测".to_string(),
            });
        }
    }

    let ok = checks.iter().all(|check| check.passed);

    WindowsProbeReport {
        ok,
        windows_directory: windows_dir.map(|path| path.to_string_lossy().into_owned()),
        system_directory: system_dir.map(|path| path.to_string_lossy().into_owned()),
        probe_file: probe_file.map(|path| path.to_string_lossy().into_owned()),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_directory_is_a_directory() {
        let path = windows_directory().expect("GetWindowsDirectoryW 应成功");
        assert!(path.is_absolute(), "Windows 目录应为绝对路径");
        assert!(
            is_directory(&path).expect("GetFileAttributesW 应成功"),
            "Windows 目录应具有目录属性"
        );
    }

    #[test]
    fn system_directory_is_a_directory() {
        let path = system_directory().expect("GetSystemDirectoryW 应成功");
        assert!(
            is_directory(&path).expect("GetFileAttributesW 应成功"),
            "System32 目录应具有目录属性"
        );
    }

    #[test]
    fn missing_path_returns_error() {
        let missing = windows_directory()
            .expect("GetWindowsDirectoryW 应成功")
            .join("__upsweep_stage0_missing_probe__");
        assert!(
            file_attributes(&missing).is_err(),
            "不存在的路径不应返回有效属性"
        );
    }

    #[test]
    fn probe_passes_on_windows() {
        let report = probe();
        assert!(report.ok, "Windows API 探测应全部通过: {:?}", report.checks);
        assert_eq!(report.checks.len(), 3);
        assert!(report.windows_directory.is_some());
        assert!(report.system_directory.is_some());
        assert!(report.probe_file.is_some());
    }

    #[test]
    fn normal_temp_directory_is_not_case_sensitive() {
        let path = std::env::temp_dir();
        match is_case_sensitive_directory(&path) {
            Ok(value) => assert!(!value, "普通临时目录默认应为大小写不敏感"),
            Err(error) => eprintln!("当前文件系统不支持目录大小写敏感查询: {error}"),
        }
    }

    #[test]
    fn file_identity_is_stable_and_case_insensitive() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("metadata")
            .join("versioned.exe");
        let first = file_identity(&path);
        assert!(first.read_error.is_none(), "{:?}", first.read_error);
        assert!(first.volume_serial.is_some());
        assert!(first.file_id.is_some());

        let second = file_identity(&path);
        assert_eq!(first.volume_serial, second.volume_serial);
        assert_eq!(first.file_id, second.file_id);

        let uppercase = std::path::PathBuf::from(path.to_string_lossy().to_uppercase());
        let upper = file_identity(&uppercase);
        assert!(upper.read_error.is_none(), "{:?}", upper.read_error);
        assert_eq!(first.volume_serial, upper.volume_serial);
        assert_eq!(first.file_id, upper.file_id);
    }
}
