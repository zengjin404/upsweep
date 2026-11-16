//! PE 版本资源读取。
//!
//! 使用 Windows `version.dll` 的 `GetFileVersionInfo*` / `VerQueryValueW`，
//! 只读取版本资源，不加载或执行目标文件。版本资源可以缺失，缺失不是扫描失败。

use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};

use crate::models::PeMetadata;
use crate::utils::windows_api::to_wide_null;

const ERROR_RESOURCE_TYPE_NOT_FOUND: i32 = 1813;
const DEFAULT_LANGUAGE: u16 = 0x0409;
const DEFAULT_CODEPAGE: u16 = 0x04b0;

/// 读取 PE 版本资源。成功但无版本资源时返回 `present = false`。
pub fn read(path: &Path) -> PeMetadata {
    match read_inner(path) {
        Ok(metadata) => metadata,
        Err(message) => PeMetadata {
            present: false,
            product_name: None,
            product_version: None,
            file_description: None,
            company_name: None,
            file_version: None,
            original_filename: None,
            internal_name: None,
            language: None,
            codepage: None,
            read_error: Some(message),
        },
    }
}

fn read_inner(path: &Path) -> Result<PeMetadata, String> {
    let wide_path = to_wide_null(path);
    let mut handle = 0u32;

    // SAFETY: `wide_path` 是 NUL 结尾的 UTF-16 字符串；handle 是有效可写指针。
    let size = unsafe { GetFileVersionInfoSizeW(wide_path.as_ptr(), &mut handle) };
    if size == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_RESOURCE_TYPE_NOT_FOUND)
            || error.raw_os_error() == Some(0)
        {
            return Ok(empty_metadata());
        }
        return Err(format!("GetFileVersionInfoSizeW 失败: {error}"));
    }

    let mut buffer = vec![0u8; size as usize];
    // SAFETY: buffer 长度由 GetFileVersionInfoSizeW 返回；指针在调用期间有效。
    let ok = unsafe {
        GetFileVersionInfoW(
            wide_path.as_ptr(),
            0,
            size,
            buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "GetFileVersionInfoW 失败: {}",
            std::io::Error::last_os_error()
        ));
    }

    let (language, codepage) =
        read_translation(&buffer).unwrap_or((DEFAULT_LANGUAGE, DEFAULT_CODEPAGE));
    let prefix = format!("\\StringFileInfo\\{language:04x}{codepage:04x}\\");
    let product_name = query_string(&buffer, &format!("{prefix}ProductName"));
    let product_version = query_string(&buffer, &format!("{prefix}ProductVersion"));
    let file_description = query_string(&buffer, &format!("{prefix}FileDescription"));
    let company_name = query_string(&buffer, &format!("{prefix}CompanyName"));
    let file_version = query_string(&buffer, &format!("{prefix}FileVersion"));
    let original_filename = query_string(&buffer, &format!("{prefix}OriginalFilename"));
    let internal_name = query_string(&buffer, &format!("{prefix}InternalName"));

    let present = product_name.is_some()
        || product_version.is_some()
        || file_description.is_some()
        || company_name.is_some()
        || file_version.is_some()
        || original_filename.is_some()
        || internal_name.is_some();

    Ok(PeMetadata {
        present,
        product_name,
        product_version,
        file_description,
        company_name,
        file_version,
        original_filename,
        internal_name,
        language: Some(format!("{language:04x}")),
        codepage: Some(format!("{codepage:04x}")),
        read_error: None,
    })
}

fn empty_metadata() -> PeMetadata {
    PeMetadata {
        present: false,
        product_name: None,
        product_version: None,
        file_description: None,
        company_name: None,
        file_version: None,
        original_filename: None,
        internal_name: None,
        language: None,
        codepage: None,
        read_error: None,
    }
}

fn read_translation(buffer: &[u8]) -> Option<(u16, u16)> {
    let sub_block = to_utf16_null("\\VarFileInfo\\Translation");
    let mut pointer: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length = 0u32;

    // SAFETY: buffer 来自 GetFileVersionInfoW；sub_block 为 NUL 结尾；
    // pointer/length 是有效可写指针，调用成功后指向 buffer 内部。
    let ok = unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast::<core::ffi::c_void>(),
            sub_block.as_ptr(),
            &mut pointer,
            &mut length,
        )
    };
    if ok == 0 || length < 4 || pointer.is_null() {
        return None;
    }

    // SAFETY: VerQueryValueW 保证返回至少 length 字节；Translation 每项 4 字节。
    let language_id = unsafe { *(pointer as *const u32) };
    Some(((language_id & 0xffff) as u16, (language_id >> 16) as u16))
}

fn query_string(buffer: &[u8], sub_block: &str) -> Option<String> {
    let wide_sub_block = to_utf16_null(sub_block);
    let mut pointer: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length = 0u32;

    // SAFETY: 同 read_translation；字符串长度由 VerQueryValueW 返回。
    let ok = unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast::<core::ffi::c_void>(),
            wide_sub_block.as_ptr(),
            &mut pointer,
            &mut length,
        )
    };
    if ok == 0 || length == 0 || pointer.is_null() {
        return None;
    }

    // VerQueryValueW 对字符串返回字符数（含结尾 NUL）。按 UTF-16 单元读取并去掉 NUL。
    // SAFETY: 指针指向版本资源缓冲区内部，长度由 Windows API 返回。
    let units = unsafe { std::slice::from_raw_parts(pointer as *const u16, length as usize) };
    let value: String = String::from_utf16_lossy(units)
        .trim_end_matches('\0')
        .to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn to_utf16_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("metadata")
            .join(name)
    }

    #[test]
    fn reads_version_resource_from_fixture() {
        let metadata = read(&fixture("versioned.exe"));
        if !metadata.present {
            panic!("夹具应包含版本资源: {:?}", metadata.read_error);
        }
        assert_eq!(metadata.product_name.as_deref(), Some("UpSweep Fixture"));
        assert_eq!(metadata.product_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(metadata.company_name.as_deref(), Some("UpSweep Test"));
        assert_eq!(metadata.original_filename.as_deref(), Some("versioned.exe"));
        assert!(metadata.read_error.is_none());
    }

    #[test]
    fn missing_version_resource_is_not_an_error() {
        let metadata = read(&fixture("plain.exe"));
        assert!(!metadata.present);
        assert!(
            metadata.read_error.is_none()
                || metadata.read_error.as_deref()
                    == Some(
                        "GetFileVersionInfoSizeW 失败: The specified resource type cannot be found in the image file. (os error 1813)"
                    )
        );
    }
}
