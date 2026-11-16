//! MSI / MSP 元数据读取。
//!
//! 使用纯 Rust 的 `msi` 解析库读取结构化存储与表，不调用安装服务，
//! 不执行安装、修复或任何会改变系统的操作。损坏或非 MSI 文件返回
//! `present = false` 并记录错误，不中断扫描。

use std::collections::HashMap;
use std::path::Path;

use msi::{PackageType as MsiFileType, Select, Value};

use crate::models::{MsiMetadata, MsiPackageType};

const MAX_MSI_BYTES: u64 = 512 * 1024 * 1024;

pub fn read(path: &Path) -> MsiMetadata {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > MAX_MSI_BYTES => {
            return empty_with_error(format!(
                "文件大小 {} 字节超过 MSI 解析上限 {} 字节",
                metadata.len(),
                MAX_MSI_BYTES
            ));
        }
        Err(error) => return empty_with_error(format!("读取文件信息失败: {error}")),
        Ok(_) => {}
    }

    match read_inner(path) {
        Ok(metadata) => metadata,
        Err(message) => empty_with_error(message),
    }
}

fn read_inner(path: &Path) -> Result<MsiMetadata, String> {
    let mut package = msi::open(path).map_err(|error| format!("MSI 解析失败: {error}"))?;

    let package_type = match package.package_type() {
        MsiFileType::Installer => MsiPackageType::Installer,
        MsiFileType::Patch => MsiPackageType::Patch,
        MsiFileType::Transform => MsiPackageType::Transform,
    };

    let summary_title = package.summary_info().title().map(str::to_string);
    let summary_subject = package.summary_info().subject().map(str::to_string);
    let summary_author = package.summary_info().author().map(str::to_string);
    let package_code = package.summary_info().uuid().map(|uuid| uuid.to_string());

    let mut properties = HashMap::new();
    if package.has_table("Property") {
        let rows = package
            .select_rows(Select::table("Property"))
            .map_err(|error| format!("读取 Property 表失败: {error}"))?;
        for row in rows {
            let Some(name_index) = row
                .columns()
                .iter()
                .position(|column| column.name().eq_ignore_ascii_case("Property"))
            else {
                continue;
            };
            let Some(value_index) = row
                .columns()
                .iter()
                .position(|column| column.name().eq_ignore_ascii_case("Value"))
            else {
                continue;
            };
            let name = value_string(&row[name_index]);
            let value = value_string(&row[value_index]);
            if !name.is_empty() && !value.is_empty() {
                properties.insert(name.to_lowercase(), value);
            }
        }
    }

    let patch_codes = read_patch_codes(&mut package)?;

    Ok(MsiMetadata {
        present: true,
        package_type,
        product_name: property(&properties, "ProductName"),
        product_version: property(&properties, "ProductVersion"),
        manufacturer: property(&properties, "Manufacturer"),
        product_code: property(&properties, "ProductCode"),
        upgrade_code: property(&properties, "UpgradeCode"),
        package_code,
        summary_title,
        summary_subject,
        summary_author,
        patch_codes,
        read_error: None,
    })
}

fn read_patch_codes(package: &mut msi::Package<std::fs::File>) -> Result<Vec<String>, String> {
    if !package.has_table("Patch") {
        return Ok(Vec::new());
    }

    let rows = package
        .select_rows(Select::table("Patch"))
        .map_err(|error| format!("读取 Patch 表失败: {error}"))?;

    let mut codes = Vec::new();
    for row in rows {
        let Some(index) = row.columns().iter().position(|column| {
            column.name().eq_ignore_ascii_case("PatchId")
                || column.name().eq_ignore_ascii_case("PatchCode")
        }) else {
            continue;
        };
        let value = value_string(&row[index]);
        if !value.is_empty() {
            codes.push(value);
        }
    }
    Ok(codes)
}

fn property(properties: &HashMap<String, String>, name: &str) -> Option<String> {
    properties.get(&name.to_lowercase()).cloned()
}

fn value_string(value: &Value) -> String {
    match value {
        Value::Str(text) => text.clone(),
        Value::Int(number) => number.to_string(),
        Value::Null | Value::Binary => String::new(),
    }
}

fn empty_with_error(message: String) -> MsiMetadata {
    MsiMetadata {
        present: false,
        package_type: MsiPackageType::Unknown,
        product_name: None,
        product_version: None,
        manufacturer: None,
        product_code: None,
        upgrade_code: None,
        package_code: None,
        summary_title: None,
        summary_subject: None,
        summary_author: None,
        patch_codes: Vec::new(),
        read_error: Some(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use msi::{Column, Insert, Package, PackageType, Value};
    use std::fs::{self, OpenOptions};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("upsweep_msi_test_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("应创建测试目录");
        dir.join(format!("{name}.msi"))
    }

    fn create_package(path: &Path, package_type: PackageType) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .expect("应创建 MSI 文件");
        let mut package = Package::create(package_type, file).expect("应创建 MSI 包");
        package
            .summary_info_mut()
            .set_title("UpSweep Fixture Package");
        package.summary_info_mut().set_subject("Fixture Subject");
        package.summary_info_mut().set_author("UpSweep Test");

        let columns = vec![
            Column::build("Property").primary_key().id_string(72),
            Column::build("Value").nullable().string(255),
        ];
        package
            .create_table("Property", columns)
            .expect("应创建 Property 表");
        package
            .insert_rows(
                Insert::into("Property")
                    .row(vec![
                        Value::Str("ProductName".into()),
                        Value::Str("UpSweep Fixture MSI".into()),
                    ])
                    .row(vec![
                        Value::Str("ProductVersion".into()),
                        Value::Str("9.8.7".into()),
                    ])
                    .row(vec![
                        Value::Str("Manufacturer".into()),
                        Value::Str("UpSweep Test".into()),
                    ])
                    .row(vec![
                        Value::Str("ProductCode".into()),
                        Value::Str("{11111111-2222-3333-4444-555555555555}".into()),
                    ])
                    .row(vec![
                        Value::Str("UpgradeCode".into()),
                        Value::Str("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".into()),
                    ]),
            )
            .expect("应插入 Property 行");
        let _file = package.into_inner().expect("应写入并关闭 MSI");
    }

    #[test]
    fn reads_installer_properties_and_summary() {
        let path = temp_path("installer");
        create_package(&path, PackageType::Installer);

        let metadata = read(&path);
        assert!(metadata.present, "{:?}", metadata.read_error);
        assert_eq!(metadata.package_type, MsiPackageType::Installer);
        assert_eq!(
            metadata.product_name.as_deref(),
            Some("UpSweep Fixture MSI")
        );
        assert_eq!(metadata.product_version.as_deref(), Some("9.8.7"));
        assert_eq!(metadata.manufacturer.as_deref(), Some("UpSweep Test"));
        assert_eq!(
            metadata.product_code.as_deref(),
            Some("{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(
            metadata.summary_title.as_deref(),
            Some("UpSweep Fixture Package")
        );
        assert!(metadata.read_error.is_none());

        let _ = fs::remove_dir_all(path.parent().expect("应有父目录"));
    }

    #[test]
    fn reads_patch_package_type() {
        let path = temp_path("patch");
        create_package(&path, PackageType::Patch);

        let metadata = read(&path);
        assert!(metadata.present, "{:?}", metadata.read_error);
        assert_eq!(metadata.package_type, MsiPackageType::Patch);

        let _ = fs::remove_dir_all(path.parent().expect("应有父目录"));
    }

    #[test]
    fn corrupt_file_returns_error_without_panicking() {
        let path = temp_path("corrupt");
        fs::write(&path, b"this is not an MSI file").expect("应写入损坏文件");

        let metadata = read(&path);
        assert!(!metadata.present);
        assert!(metadata.read_error.is_some());

        let _ = fs::remove_dir_all(path.parent().expect("应有父目录"));
    }
}
