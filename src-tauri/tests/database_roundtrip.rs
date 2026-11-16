//! 数据库模块的外部集成测试。
//!
//! 从库 crate 视角验证公开 API，确保后续业务模块和测试不依赖私有实现。

use upsweep_lib::database::{Database, SCHEMA_VERSION};

#[test]
fn self_check_succeeds_through_public_api() {
    let mut database = Database::open_in_memory().expect("内存数据库应能打开");
    let report = database.self_check().expect("自检不应失败");

    assert!(report.ok);
    assert!(report.roundtrip_ok);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert!(!report.engine_version.is_empty());
    assert_eq!(
        database.schema_version().expect("应能读取版本"),
        SCHEMA_VERSION
    );
}
