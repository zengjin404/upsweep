//! 路径安全边界。
//!
//! 阶段 1 的扫描是只读的，但后续清理阶段会复用这里的路径规范化、组件边界比较、
//! 受保护路径与重解析点判定。所有比较都基于路径组件，不使用字符串前缀。
//!
//! 大小写语义通过 Windows `LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE)`
//! 生成组件键，再按组件精确比较；不使用 Rust 的 Unicode `to_lowercase` 近似。

use std::env;
use std::fmt;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Globalization::{LCMAP_UPPERCASE, LCMapStringEx, LOCALE_NAME_INVARIANT};

use crate::utils::windows_api::{self, WindowsApiError};

/// `FILE_ATTRIBUTE_REPARSE_POINT`，包含 Junction、Mount Point、Symbolic Link。
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

#[derive(Debug, Clone)]
pub struct PathSafetyError {
    pub code: &'static str,
    pub message: String,
}

impl PathSafetyError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for PathSafetyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PathSafetyError {}

impl From<WindowsApiError> for PathSafetyError {
    fn from(error: WindowsApiError) -> Self {
        Self::new("WINDOWS_API_FAILED", error.to_string())
    }
}

/// 读取路径属性；路径不存在或无权限时返回错误。
pub fn file_attributes(path: &Path) -> Result<u32, PathSafetyError> {
    windows_api::file_attributes(path).map_err(PathSafetyError::from)
}

pub fn is_reparse_point(path: &Path) -> Result<bool, PathSafetyError> {
    Ok(file_attributes(path)? & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

pub fn is_directory(path: &Path) -> Result<bool, PathSafetyError> {
    Ok(file_attributes(path)? & FILE_ATTRIBUTE_DIRECTORY != 0)
}

/// 把路径转换为绝对路径并消解 `.` / `..` 组件（不解析符号链接）。
pub fn absolute_lexical(path: &Path) -> Result<PathBuf, PathSafetyError> {
    let base = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| PathSafetyError::new("CURRENT_DIR_FAILED", error.to_string()))?
            .join(path)
    };

    let mut normalized = PathBuf::new();
    for component in base.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

/// Windows 路径的比较键。
///
/// 每个组件使用 Windows invariant 大写映射；组件边界在映射前已经由路径分隔符确定。
/// 该键用于大小写不敏感比较、HashSet 去重和路径边界判断，**不是文件身份**。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathKey {
    components: Vec<Vec<u16>>,
}

impl PathKey {
    pub fn components(&self) -> &[Vec<u16>] {
        &self.components
    }

    /// 组件前缀判断；`C:\Program Files Backup` 不会匹配 `C:\Program Files`。
    pub fn starts_with(&self, base: &Self) -> bool {
        self.components.len() >= base.components.len()
            && self.components[..base.components.len()] == base.components[..]
    }

    /// 用于 SHA-256 候选 ID 的稳定字节编码（含域分隔符与组件长度）。
    pub fn identity_bytes(&self) -> Vec<u8> {
        let mut bytes = b"upsweep:path-key:v1\0".to_vec();
        bytes.extend_from_slice(&(self.components.len() as u32).to_le_bytes());
        for component in &self.components {
            bytes.extend_from_slice(&(component.len() as u32).to_le_bytes());
            for unit in component {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
        }
        bytes
    }
}

/// 生成 Windows 大小写不敏感的路径比较键。
pub fn path_key(path: &Path) -> Result<PathKey, PathSafetyError> {
    let absolute = absolute_lexical(path)?;
    let wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    let normalized = normalize_wide(&wide);
    let mut components = split_components(&normalized);
    for component in &mut components {
        if !component.is_empty() {
            *component = uppercase_component(component)?;
        }
    }
    Ok(PathKey { components })
}

/// 按组件边界判断 `child` 是否位于 `base` 之内（或等于 `base`）。
pub fn path_starts_with(child: &Path, base: &Path) -> Result<bool, PathSafetyError> {
    Ok(path_key(child)?.starts_with(&path_key(base)?))
}

fn normalize_wide(input: &[u16]) -> Vec<u16> {
    const BACKSLASH: u16 = b'\\' as u16;
    const SLASH: u16 = b'/' as u16;
    const VERBATIM_UNC: [u16; 8] = [92, 92, 63, 92, 85, 78, 67, 92]; // \\?\UNC\
    const VERBATIM: [u16; 4] = [92, 92, 63, 92]; // \\?\
    const DEVICE: [u16; 4] = [92, 92, 46, 92]; // \\.\

    let mut wide: Vec<u16> = input
        .iter()
        .map(|unit| if *unit == SLASH { BACKSLASH } else { *unit })
        .collect();

    if wide.starts_with(&VERBATIM_UNC) {
        let mut replaced = vec![BACKSLASH, BACKSLASH];
        replaced.extend_from_slice(&wide[VERBATIM_UNC.len()..]);
        wide = replaced;
    } else if wide.starts_with(&VERBATIM) {
        wide.drain(..VERBATIM.len());
    } else if wide.starts_with(&DEVICE) {
        wide.drain(..DEVICE.len());
    }
    wide
}

fn split_components(wide: &[u16]) -> Vec<Vec<u16>> {
    const BACKSLASH: u16 = b'\\' as u16;
    let unc = wide.len() >= 2 && wide[0] == BACKSLASH && wide[1] == BACKSLASH;
    let mut components = Vec::new();
    if unc {
        // 保留 UNC 根标记，避免与盘符路径混淆。
        components.push(Vec::new());
        components.push(Vec::new());
    }
    for part in wide.split(|unit| *unit == BACKSLASH) {
        if part.is_empty() {
            continue;
        }
        components.push(part.to_vec());
    }
    components
}

fn uppercase_component(component: &[u16]) -> Result<Vec<u16>, PathSafetyError> {
    let source_length = i32::try_from(component.len()).map_err(|_| {
        PathSafetyError::new(
            "PATH_COMPONENT_TOO_LONG",
            "路径组件长度超出 Windows API 限制",
        )
    })?;
    // 大写映射在极少数情况下可能扩展字符；预留额外空间。
    let mut destination = vec![0u16; component.len().saturating_mul(2).saturating_add(8)];

    // SAFETY: 源字符串是有效 UTF-16 切片；目标缓冲区足够大且可写；
    // LOCALE_NAME_INVARIANT 是静态 NUL 结尾字符串；其余指针为 null。
    let result = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            component.as_ptr(),
            source_length,
            destination.as_mut_ptr(),
            i32::try_from(destination.len()).unwrap_or(i32::MAX),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if result == 0 {
        return Err(PathSafetyError::new(
            "PATH_CASE_MAP_FAILED",
            format!("LCMapStringEx 失败: {}", std::io::Error::last_os_error()),
        ));
    }
    let result_length = result as usize;
    if result_length > destination.len() {
        return Err(PathSafetyError::new(
            "PATH_CASE_MAP_OVERFLOW",
            "LCMapStringEx 返回长度超出目标缓冲区",
        ));
    }
    destination.truncate(result_length);
    Ok(destination)
}

/// 判断路径是否位于集合中任一条目之下。
pub fn any_path_contains(entries: &[PathBuf], path: &Path) -> Result<bool, PathSafetyError> {
    for entry in entries {
        if path_starts_with(path, entry)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 判断是否为磁盘根目录（例如 `C:\`）。
pub fn is_drive_root(path: &Path) -> bool {
    path.parent().is_none()
}

#[derive(Debug)]
struct ProtectedEntry {
    path: PathBuf,
    key: PathKey,
    code: &'static str,
    reason: &'static str,
}

/// 默认受保护路径集合。扫描时跳过这些目录，后续清理阶段也不得越过。
pub struct ProtectedPaths {
    entries: Vec<ProtectedEntry>,
}

impl ProtectedPaths {
    pub fn default_for_system() -> Self {
        let windows_dir = windows_api::windows_directory().ok();
        let system_drive = windows_dir
            .as_ref()
            .and_then(|path| path.parent().map(Path::to_path_buf));

        let mut builder = ProtectedPathsBuilder::default();

        if let Some(windows_dir) = &windows_dir {
            // 先加入更具体的路径，便于报告具体原因。
            builder.add(
                windows_dir.join("System32").join("DriverStore"),
                "DRIVER_STORE",
                "Windows 驱动程序存储目录",
            );
            builder.add(windows_dir.join("WinSxS"), "WINSXS", "Windows 组件存储目录");
            builder.add(windows_dir.join("System32"), "SYSTEM32", "Windows 系统目录");
            builder.add(
                windows_dir.join("Installer"),
                "WINDOWS_INSTALLER",
                "Windows Installer 缓存目录",
            );
            builder.add(
                windows_dir.join("SoftwareDistribution"),
                "WINDOWS_UPDATE",
                "Windows 更新分发目录",
            );
            builder.add(
                windows_dir.join("SystemApps"),
                "SYSTEM_APPS",
                "Windows 系统应用目录",
            );
            builder.add(windows_dir.to_path_buf(), "WINDOWS_DIR", "Windows 系统目录");
        }

        if let Some(system_drive) = &system_drive {
            builder.add(
                system_drive.join("$Recycle.Bin"),
                "RECYCLE_BIN",
                "系统回收站目录",
            );
            builder.add(
                system_drive.join("System Volume Information"),
                "SYSTEM_VOLUME_INFORMATION",
                "系统卷信息目录",
            );
            builder.add(system_drive.join("Recovery"), "RECOVERY", "系统恢复目录");
            builder.add(
                system_drive.join("Windows.old"),
                "WINDOWS_OLD",
                "旧版 Windows 目录",
            );
            builder.add(
                system_drive.join("Config.Msi"),
                "CONFIG_MSI",
                "Windows Installer 配置缓存",
            );
        }

        if let Some(program_data) = env_path("ProgramData") {
            builder.add(
                program_data.join("Microsoft"),
                "PROGRAM_DATA_MICROSOFT",
                "ProgramData 公共系统数据",
            );
            builder.add(
                program_data.join("Package Cache"),
                "PACKAGE_CACHE",
                "Windows Installer 安装包缓存",
            );
        }

        for key in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(program_files) = env_path(key) {
                builder.add(
                    program_files.join("WindowsApps"),
                    "WINDOWS_APPS",
                    "Microsoft Store 应用目录",
                );
            }
        }

        builder.build()
    }

    /// 返回匹配的受保护条目路径与原因。
    pub fn match_protected(&self, path: &Path) -> Option<(&Path, &'static str)> {
        let key = path_key(path).ok()?;
        self.match_protected_key(&key)
    }

    /// 已计算路径键时复用，避免对每个受保护条目重复做 Windows 大小写映射。
    pub fn match_protected_key(&self, key: &PathKey) -> Option<(&Path, &'static str)> {
        self.entries
            .iter()
            .find(|entry| key.starts_with(&entry.key))
            .map(|entry| (entry.path.as_path(), entry.reason))
    }

    pub fn is_protected(&self, path: &Path) -> bool {
        self.match_protected(path).is_some()
    }

    /// 转换到扫描排除列表，供扫描器直接跳过。
    pub fn exclusions(&self) -> Vec<(PathBuf, String)> {
        self.entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.reason.to_string()))
            .collect()
    }

    pub fn codes(&self) -> impl Iterator<Item = (&Path, &'static str)> {
        self.entries
            .iter()
            .map(|entry| (entry.path.as_path(), entry.code))
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[derive(Default)]
struct ProtectedPathsBuilder {
    entries: Vec<ProtectedEntry>,
    seen: Vec<PathKey>,
}

impl ProtectedPathsBuilder {
    fn add(&mut self, path: PathBuf, code: &'static str, reason: &'static str) {
        let absolute = absolute_lexical(&path).unwrap_or(path);
        let Ok(key) = path_key(&absolute) else {
            return;
        };
        if self.seen.iter().any(|existing| existing == &key) {
            return;
        }
        self.seen.push(key.clone());
        self.entries.push(ProtectedEntry {
            path: absolute,
            key,
            code,
            reason,
        });
    }

    fn build(self) -> ProtectedPaths {
        ProtectedPaths {
            entries: self.entries,
        }
    }
}

/// 校验用户自定义扫描根：必须存在、为目录、非重解析点、非磁盘根、非受保护路径。
pub fn validate_scan_root(
    path: &Path,
    protected: &ProtectedPaths,
) -> Result<PathBuf, PathSafetyError> {
    if path.as_os_str().is_empty() {
        return Err(PathSafetyError::new("EMPTY_PATH", "扫描根不能为空"));
    }

    // 必须在 canonicalize 之前检查：canonicalize 会跟随重解析点，检查目标没有意义。
    if is_reparse_point(path)? {
        return Err(PathSafetyError::new(
            "ROOT_IS_REPARSE_POINT",
            format!("扫描根是重解析点，拒绝扫描: {}", path.display()),
        ));
    }

    let canonical = fs::canonicalize(path).map_err(|error| {
        PathSafetyError::new(
            "ROOT_NOT_ACCESSIBLE",
            format!("无法访问扫描根 {}: {error}", path.display()),
        )
    })?;

    if !is_directory(&canonical)? {
        return Err(PathSafetyError::new(
            "ROOT_NOT_DIRECTORY",
            format!("扫描根不是目录: {}", canonical.display()),
        ));
    }
    if is_reparse_point(&canonical)? {
        return Err(PathSafetyError::new(
            "ROOT_IS_REPARSE_POINT",
            format!("扫描根是重解析点，拒绝扫描: {}", canonical.display()),
        ));
    }
    if is_drive_root(&canonical) {
        return Err(PathSafetyError::new(
            "ROOT_IS_DRIVE",
            "不允许将整个磁盘根目录作为扫描根，请选择具体目录",
        ));
    }
    if let Some((protected_path, reason)) = protected.match_protected(&canonical) {
        return Err(PathSafetyError::new(
            "ROOT_IS_PROTECTED",
            format!(
                "扫描根 {} 位于受保护路径 {}（{}）内，拒绝扫描",
                canonical.display(),
                protected_path.display(),
                reason
            ),
        ));
    }

    Ok(canonical)
}

/// 校验排除路径；允许不存在（后续新建的目录仍应被排除）。
pub fn normalize_exclusion(path: &Path) -> Result<PathBuf, PathSafetyError> {
    if path.as_os_str().is_empty() {
        return Err(PathSafetyError::new("EMPTY_PATH", "排除路径不能为空"));
    }
    if path.exists() {
        fs::canonicalize(path)
            .map_err(|error| PathSafetyError::new("EXCLUSION_NOT_ACCESSIBLE", error.to_string()))
    } else {
        absolute_lexical(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_boundary_rejects_similar_prefix() {
        assert!(
            path_starts_with(
                Path::new(r"C:\Program Files\App"),
                Path::new(r"C:\Program Files")
            )
            .expect("比较应成功")
        );
        assert!(
            !path_starts_with(
                Path::new(r"C:\Program Files Backup\App"),
                Path::new(r"C:\Program Files")
            )
            .expect("比较应成功")
        );
        assert!(
            path_starts_with(
                Path::new(r"c:\program files\app"),
                Path::new(r"C:\Program Files")
            )
            .expect("Windows 路径应大小写不敏感")
        );
    }

    #[test]
    fn path_key_matches_windows_case_semantics() {
        let lower = path_key(Path::new(r"c:\program files\app\")).expect("应生成路径键");
        let mixed = path_key(Path::new(r"C:\Program Files\App")).expect("应生成路径键");
        assert_eq!(lower, mixed);
        assert_eq!(
            path_key(Path::new(r"\\?\C:\Windows")).expect("应生成路径键"),
            path_key(Path::new(r"C:\Windows")).expect("应生成路径键")
        );
        assert_eq!(
            path_key(Path::new(r"\\.\C:\Windows")).expect("应生成路径键"),
            path_key(Path::new(r"C:\Windows")).expect("应生成路径键")
        );
        assert_eq!(
            path_key(Path::new(r"C:\")).expect("盘符根键"),
            path_key(Path::new(r"c:\")).expect("盘符根键")
        );
        assert_ne!(
            path_key(Path::new(r"C:\Program Files")).expect("应生成路径键"),
            path_key(Path::new(r"C:\Program Files Backup")).expect("应生成路径键")
        );
    }

    #[test]
    fn path_key_handles_unicode_and_special_characters() {
        for value in [
            r"C:\中文\测试\应用 名称\安装程序.exe",
            r"C:\日本語\テスト\ファイル.exe",
            r"C:\Users\ÄÖÜ\Ω\应用.exe",
            r"C:\ä\ö\ü\应用.exe",
        ] {
            let key = path_key(Path::new(value)).expect("应生成路径键");
            let upper = value.to_uppercase();
            assert_eq!(
                key,
                path_key(Path::new(&upper)).expect("大写路径应生成相同键"),
                "路径 {value} 的大写比较键应一致"
            );
            assert_eq!(key, path_key(Path::new(value)).expect("重复生成应一致"));
        }
    }

    #[test]
    fn path_key_handles_unc_verbatim_and_device_paths() {
        assert_eq!(
            path_key(Path::new(r"\\server\share\目录\文件.exe")).expect("UNC 键"),
            path_key(Path::new(r"\\SERVER\SHARE\目录\文件.exe")).expect("UNC 键")
        );
        assert_eq!(
            path_key(Path::new(r"\\?\UNC\server\share\dir")).expect("verbatim UNC 键"),
            path_key(Path::new(r"\\server\share\dir")).expect("UNC 键")
        );
        assert!(
            path_starts_with(
                Path::new(r"\\server\share\dir\child"),
                Path::new(r"\\server\share\dir")
            )
            .expect("UNC 边界比较应成功")
        );
        assert!(
            !path_starts_with(
                Path::new(r"\\server\share\dir2"),
                Path::new(r"\\server\share\dir")
            )
            .expect("UNC 边界比较应成功")
        );
    }

    #[test]
    fn path_key_agrees_with_compare_string_ordinal() {
        use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

        fn ordinal_equal(left: &str, right: &str) -> bool {
            let left: Vec<u16> = left.encode_utf16().collect();
            let right: Vec<u16> = right.encode_utf16().collect();
            // SAFETY: 两个指针和长度均有效；bIgnoreCase=TRUE。
            let result = unsafe {
                CompareStringOrdinal(
                    left.as_ptr(),
                    left.len() as i32,
                    right.as_ptr(),
                    right.len() as i32,
                    1,
                )
            };
            result == CSTR_EQUAL
        }

        for (left, right) in [
            (r"C:\Program Files", r"c:\program files"),
            (r"C:\ÄÖÜ\应用", r"C:\äöü\应用"),
            (r"C:\中文\テスト", r"C:\中文\テスト"),
            (r"C:\ß", r"C:\SS"),
            (r"C:\İ", r"C:\i"),
            (r"C:\Program Files", r"C:\Program Files Backup"),
        ] {
            assert_eq!(
                path_key(Path::new(left)).expect("left key")
                    == path_key(Path::new(right)).expect("right key"),
                ordinal_equal(left, right),
                "PathKey 与 CompareStringOrdinal 应一致: {left} / {right}"
            );
        }
    }

    #[test]
    fn path_key_handles_long_paths() {
        let long = format!(r"C:\{}", "segment_".repeat(45));
        let key = path_key(Path::new(&long)).expect("长路径应生成键");
        assert!(key.components().len() >= 2);
        assert_eq!(
            key,
            path_key(Path::new(&long.to_uppercase())).expect("长路径键")
        );
    }

    #[test]
    fn drive_root_is_detected() {
        assert!(is_drive_root(Path::new(r"C:\")));
        assert!(!is_drive_root(Path::new(r"C:\Windows")));
    }

    #[test]
    fn lexical_normalization_removes_parent_components() {
        let base =
            absolute_lexical(Path::new(r"C:\Program Files\App\..\Other")).expect("绝对化应成功");
        assert!(base.to_string_lossy().ends_with(r"Program Files\Other"));
    }

    #[test]
    fn windows_directory_is_protected_by_default() {
        let protected = ProtectedPaths::default_for_system();
        let windows = windows_api::windows_directory().expect("应取得 Windows 目录");
        assert!(protected.is_protected(&windows));
        assert!(protected.is_protected(&windows.join("System32").join("kernel32.dll")));
        assert!(!protected.is_protected(Path::new(r"C:\WindowsBackup")));
    }

    #[test]
    fn temp_file_is_not_reparse_point() {
        let path = std::env::temp_dir().join(format!(
            "upsweep_protection_test_{}.tmp",
            std::process::id()
        ));
        fs::write(&path, b"test").expect("应创建临时文件");
        assert!(!is_reparse_point(&path).expect("属性读取应成功"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn drive_root_is_rejected_as_scan_root() {
        let protected = ProtectedPaths::default_for_system();
        let result = validate_scan_root(Path::new(r"C:\"), &protected);
        assert!(result.is_err());
    }

    #[test]
    fn protected_directory_is_rejected_as_scan_root() {
        let protected = ProtectedPaths::default_for_system();
        let windows = windows_api::windows_directory().expect("应取得 Windows 目录");
        let result = validate_scan_root(&windows, &protected);
        assert!(result.is_err());
    }

    #[test]
    fn reparse_point_root_is_rejected() {
        let root =
            std::env::temp_dir().join(format!("upsweep_reparse_root_{}", std::process::id()));
        let target = root.join("target");
        let link = root.join("link");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&target).expect("应创建目标目录");

        let created = std::os::windows::fs::symlink_dir(&target, &link).is_ok()
            || std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
        if !created {
            eprintln!("当前环境无法创建重解析点，跳过该用例");
            let _ = fs::remove_dir_all(&root);
            return;
        }

        let protected = ProtectedPaths::default_for_system();
        let result = validate_scan_root(&link, &protected);
        assert!(result.is_err(), "扫描根自身是重解析点时必须拒绝");

        let _ = fs::remove_dir(&link);
        let _ = fs::remove_dir_all(&root);
    }
}
