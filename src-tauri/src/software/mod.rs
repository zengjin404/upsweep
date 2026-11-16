//! 已安装软件信息（只读）。
//!
//! 读取 Windows 卸载注册表项：HKLM 64 位视图、HKLM 32 位视图、HKCU。
//! 只调用 `RegOpenKeyExW` / `RegEnumKeyExW` / `RegQueryValueExW`，不写注册表。
//! 单个键或值读取失败时记录结构化问题并继续。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_DWORD, REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
};

use crate::models::{InstalledSoftware, InstalledSoftwareReport, ScanIssue, ScanIssueKind};

const UNINSTALL_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const MAX_KEY_NAME: usize = 512;
const MAX_REGISTRY_KEYS: u64 = 20_000;

struct KeyHandle(HKEY);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        // SAFETY: 句柄由 RegOpenKeyExW 成功返回，且只在这里关闭一次。
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

struct RegistryView {
    hive_name: &'static str,
    hive: HKEY,
    view_name: &'static str,
    access: u32,
}

/// 读取三处卸载注册表项。永远返回报告；注册表完全不可用时 items 为空并带 issue。
pub fn read_installed_software() -> InstalledSoftwareReport {
    let views = [
        RegistryView {
            hive_name: "HKLM",
            hive: HKEY_LOCAL_MACHINE,
            view_name: "64",
            access: KEY_READ | KEY_WOW64_64KEY,
        },
        RegistryView {
            hive_name: "HKLM",
            hive: HKEY_LOCAL_MACHINE,
            view_name: "32",
            access: KEY_READ | KEY_WOW64_32KEY,
        },
        RegistryView {
            hive_name: "HKCU",
            hive: HKEY_CURRENT_USER,
            view_name: "user",
            access: KEY_READ,
        },
    ];

    let mut items = Vec::new();
    let mut issues = Vec::new();
    let mut scanned_keys = 0u64;

    for view in views {
        let root = match open_key(view.hive, UNINSTALL_PATH, view.access) {
            Ok(root) => root,
            Err(error) => {
                issues.push(issue(
                    "REGISTRY_OPEN_FAILED",
                    format!("无法打开卸载注册表项: {error}"),
                    Some(format!(r"{}\{}", view.hive_name, UNINSTALL_PATH)),
                ));
                continue;
            }
        };

        let mut index = 0u32;
        loop {
            if scanned_keys >= MAX_REGISTRY_KEYS {
                issues.push(issue(
                    "REGISTRY_KEY_LIMIT",
                    format!("超过单次读取上限 {MAX_REGISTRY_KEYS} 个注册表键"),
                    None,
                ));
                break;
            }

            let mut name_buffer = vec![0u16; MAX_KEY_NAME];
            let mut name_length = name_buffer.len() as u32;
            // SAFETY: name_buffer 足够大；其余输出指针为 null，表示不关心。
            let status = unsafe {
                RegEnumKeyExW(
                    root.0,
                    index,
                    name_buffer.as_mut_ptr(),
                    &mut name_length,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                issues.push(issue(
                    "REGISTRY_ENUM_FAILED",
                    format!("RegEnumKeyExW 返回错误码 {status}"),
                    Some(format!(r"{}\{}", view.hive_name, UNINSTALL_PATH)),
                ));
                break;
            }

            index += 1;
            let key_name = String::from_utf16_lossy(&name_buffer[..name_length as usize]);
            let full_key = format!(r"{}\{}\{}", view.hive_name, UNINSTALL_PATH, key_name);

            let key = match open_key(
                view.hive,
                &format!(r"{UNINSTALL_PATH}\{key_name}"),
                view.access,
            ) {
                Ok(key) => key,
                Err(error) => {
                    issues.push(issue(
                        "REGISTRY_OPEN_FAILED",
                        format!("无法打开子键: {error}"),
                        Some(full_key),
                    ));
                    continue;
                }
            };

            scanned_keys += 1;
            let display_name = match read_string(key.0, "DisplayName") {
                Ok(value) => value,
                Err(error) => {
                    issues.push(issue("REGISTRY_READ_FAILED", error, Some(full_key.clone())));
                    continue;
                }
            };
            let Some(display_name) = display_name.filter(|value| !value.trim().is_empty()) else {
                continue;
            };

            let uninstall_string = read_string(key.0, "UninstallString").unwrap_or(None);
            let product_code = if is_product_code(&key_name) {
                Some(key_name.clone())
            } else {
                None
            };
            let is_msi = product_code.is_some()
                || uninstall_string
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains("msiexec"));

            items.push(InstalledSoftware {
                display_name,
                display_version: read_string(key.0, "DisplayVersion").unwrap_or(None),
                publisher: read_string(key.0, "Publisher").unwrap_or(None),
                install_location: read_string(key.0, "InstallLocation")
                    .unwrap_or(None)
                    .filter(|value| !value.trim().is_empty()),
                uninstall_string,
                install_date: read_string(key.0, "InstallDate").unwrap_or(None),
                registry_hive: view.hive_name.to_string(),
                registry_view: view.view_name.to_string(),
                key_name,
                product_code,
                is_msi,
                system_component: read_u32(key.0, "SystemComponent").unwrap_or(None) == Some(1),
                release_type: read_string(key.0, "ReleaseType").unwrap_or(None),
                parent_key_name: read_string(key.0, "ParentKeyName").unwrap_or(None),
            });
        }
    }

    items.sort_by(|left, right| {
        left.display_name
            .to_lowercase()
            .cmp(&right.display_name.to_lowercase())
            .then_with(|| left.display_version.cmp(&right.display_version))
            .then_with(|| left.registry_view.cmp(&right.registry_view))
    });

    InstalledSoftwareReport {
        items,
        issues,
        scanned_keys,
    }
}

fn open_key(root: HKEY, path: &str, access: u32) -> Result<KeyHandle, String> {
    let wide_path = to_wide(path);
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: wide_path 为 NUL 结尾；handle 是有效可写指针。
    let status = unsafe { RegOpenKeyExW(root, wide_path.as_ptr(), 0, access, &mut handle) };
    if status == ERROR_SUCCESS {
        Ok(KeyHandle(handle))
    } else {
        Err(format!("RegOpenKeyExW 返回错误码 {status}"))
    }
}

fn read_string(key: HKEY, value_name: &str) -> Result<Option<String>, String> {
    let wide_name = to_wide(value_name);
    let mut value_type = 0u32;
    let mut size = 0u32;

    // SAFETY: 第一次调用只查询类型和大小，数据指针为 null。
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut value_type,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "RegQueryValueExW({value_name}) 返回错误码 {status}"
        ));
    }
    if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
        return Ok(None);
    }
    if size == 0 {
        return Ok(None);
    }

    let mut data = vec![0u8; size as usize];
    // SAFETY: data 长度由上一次调用返回；size 传入有效长度。
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut value_type,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "RegQueryValueExW({value_name}) 读取数据失败: {status}"
        ));
    }

    let units: Vec<u16> = data[..size as usize]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .take_while(|unit| *unit != 0)
        .collect();
    if units.is_empty() {
        return Ok(None);
    }
    Ok(Some(String::from_utf16_lossy(&units)))
}

fn read_u32(key: HKEY, value_name: &str) -> Result<Option<u32>, String> {
    let wide_name = to_wide(value_name);
    let mut value_type = 0u32;
    let mut data = [0u8; 4];
    let mut size = data.len() as u32;

    // SAFETY: data 是 4 字节缓冲区，size 与之一致。
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut value_type,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "RegQueryValueExW({value_name}) 返回错误码 {status}"
        ));
    }
    if value_type != REG_DWORD || size < 4 {
        return Ok(None);
    }
    Ok(Some(u32::from_le_bytes(data)))
}

fn is_product_code(key_name: &str) -> bool {
    key_name.is_ascii()
        && key_name.len() == 38
        && key_name.starts_with('{')
        && key_name.ends_with('}')
        && key_name[1..37]
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '-')
}

fn to_wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn issue(code: &str, message: String, path: Option<String>) -> ScanIssue {
    ScanIssue {
        kind: ScanIssueKind::Registry,
        code: code.to_string(),
        message,
        path,
        recoverable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_code_detection() {
        assert!(is_product_code("{11111111-2222-3333-4444-555555555555}"));
        assert!(!is_product_code("NotAGuid"));
        assert!(!is_product_code("{11111111-2222-3333-4444-55555555555}"));
    }

    #[test]
    fn registry_read_is_resilient() {
        let report = read_installed_software();
        assert!(report.scanned_keys <= MAX_REGISTRY_KEYS);
        // 编码或权限问题应被记录为 issue，而不是 panic。
        assert!(report.issues.len() < 10_000);
    }
}
