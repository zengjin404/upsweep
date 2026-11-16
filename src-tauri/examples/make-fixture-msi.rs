//! 开发期一次性辅助程序：生成 MSI/MSP 测试夹具。
//!
//! 运行后应删除本文件；生成的夹具不执行，只用于解析测试。

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use msi::{Column, Insert, Package, PackageType, Value};

fn build(path: &Path, package_type: PackageType, product_name: &str, version: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture directory");
    }
    let _ = fs::remove_file(path);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("create msi");
    let mut package = Package::create(package_type, file).expect("create package");
    package.summary_info_mut().set_title("UpSweep Fixture MSI");
    package.summary_info_mut().set_subject("Fixture Subject");
    package.summary_info_mut().set_author("UpSweep Test");
    package
        .create_table(
            "Property",
            vec![
                Column::build("Property").primary_key().id_string(72),
                Column::build("Value").nullable().string(255),
            ],
        )
        .expect("create Property table");
    package
        .insert_rows(
            Insert::into("Property")
                .row(vec![
                    Value::Str("ProductName".into()),
                    Value::Str(product_name.into()),
                ])
                .row(vec![
                    Value::Str("ProductVersion".into()),
                    Value::Str(version.into()),
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
        .expect("insert properties");
    let _file = package.into_inner().expect("finish package");
    println!("wrote {}", path.display());
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("project root")
        .join("tests")
        .join("fixtures");
    build(
        &root
            .join("software-b")
            .join("upgrade")
            .join("package")
            .join("PixPin_2.0.0.3.msi"),
        PackageType::Installer,
        "PixPin",
        "2.0.0.3",
    );
    build(
        &root.join("software-c").join("update").join("patch.msp"),
        PackageType::Patch,
        "PixPin",
        "2.0.0.3",
    );
}
