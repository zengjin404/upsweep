//! SQLite 数据访问层。
//!
//! 阶段 0 只验证连接、建表、读写与事务能力，并提供应用元数据表 `app_meta`。
//! 业务表（设置、扫描记录、清理记录）将在后续阶段按需迁移，避免提前固化未确认的数据模型。

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};

use crate::models::{AppError, DatabaseCheckReport};

/// 当前数据库结构版本，写入 SQLite 的 `user_version`。
pub const SCHEMA_VERSION: i64 = 1;

const SELF_CHECK_KEY: &str = "__stage0_self_check__";
const SELF_CHECK_VALUE: &str = "upsweep-stage0-ok";

#[derive(Debug)]
pub enum DatabaseError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    UnsupportedSchemaVersion(i64),
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "文件系统错误: {error}"),
            Self::Sqlite(error) => write!(formatter, "SQLite 错误: {error}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "数据库结构版本 {version} 高于当前程序支持的版本 {SCHEMA_VERSION}，请升级 UpSweep"
                )
            }
        }
    }
}

impl std::error::Error for DatabaseError {}

impl From<std::io::Error> for DatabaseError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub struct Database {
    connection: Connection,
    path: Option<PathBuf>,
}

impl Database {
    /// 打开（或创建）指定路径的数据库，并执行结构迁移。
    pub fn open(path: &Path) -> Result<Self, DatabaseError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        Self::from_connection(connection, Some(path.to_path_buf()))
    }

    /// 打开内存数据库，用于单元测试和只读验证。
    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let connection = Connection::open_in_memory()?;
        Self::from_connection(connection, None)
    }

    fn from_connection(
        connection: Connection,
        path: Option<PathBuf>,
    ) -> Result<Self, DatabaseError> {
        // 避免多个扫描/清理任务同时写入时立即失败。
        connection.busy_timeout(Duration::from_secs(5))?;
        // 后续外键约束需要显式开启；当前表结构尚无外键，但保持行为一致。
        connection.pragma_update(None, "foreign_keys", "ON")?;

        let mut database = Self { connection, path };
        database.migrate()?;
        Ok(database)
    }

    fn migrate(&mut self) -> Result<(), DatabaseError> {
        let current: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;

        if current > SCHEMA_VERSION {
            return Err(DatabaseError::UnsupportedSchemaVersion(current));
        }
        if current == SCHEMA_VERSION {
            return Ok(());
        }

        // v1：应用元数据表。建表语句必须幂等，允许迁移中断后重新执行。
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_meta (
                key        TEXT PRIMARY KEY NOT NULL,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );",
        )?;
        self.connection
            .pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i64, DatabaseError> {
        Ok(self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// 在真实事务中执行写入、读回、删除，确认 SQLite 基本读写能力。
    ///
    /// 自检键在同一个事务内删除，不向用户数据库遗留测试数据。
    pub fn self_check(&mut self) -> Result<DatabaseCheckReport, DatabaseError> {
        let started = Instant::now();

        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO app_meta (key, value)
             VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![SELF_CHECK_KEY, SELF_CHECK_VALUE],
        )?;

        let read_back: String = transaction.query_row(
            "SELECT value FROM app_meta WHERE key = ?1",
            params![SELF_CHECK_KEY],
            |row| row.get(0),
        )?;

        let deleted = transaction.execute(
            "DELETE FROM app_meta WHERE key = ?1",
            params![SELF_CHECK_KEY],
        )?;
        transaction.commit()?;

        let roundtrip_ok = read_back == SELF_CHECK_VALUE && deleted == 1;
        let schema_version = self.schema_version()?;
        let database_size_bytes = self
            .path
            .as_ref()
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len());

        Ok(DatabaseCheckReport {
            ok: roundtrip_ok,
            engine_version: rusqlite::version().to_string(),
            schema_version,
            database_path: self
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            database_size_bytes,
            roundtrip_ok,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

/// 供 Tauri 状态管理使用的数据库句柄。
///
/// 初始化失败不会阻止应用启动：界面上会显示具体错误，而不是静默崩溃。
pub struct DatabaseState {
    slot: Mutex<DatabaseSlot>,
}

struct DatabaseSlot {
    database: Option<Database>,
    init_error: Option<String>,
}

impl DatabaseState {
    pub fn initialize(path: PathBuf) -> Self {
        match Database::open(&path) {
            Ok(database) => Self {
                slot: Mutex::new(DatabaseSlot {
                    database: Some(database),
                    init_error: None,
                }),
            },
            Err(error) => Self::failed(format!("SQLite 初始化失败: {error}")),
        }
    }

    pub fn failed(message: String) -> Self {
        Self {
            slot: Mutex::new(DatabaseSlot {
                database: None,
                init_error: Some(message),
            }),
        }
    }

    pub fn run_self_check(&self) -> Result<DatabaseCheckReport, AppError> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| AppError::new("DB_LOCK_FAILED", "数据库锁已损坏，请重启应用"))?;

        if let Some(message) = &slot.init_error {
            return Err(AppError::new("DB_UNAVAILABLE", message.clone()));
        }

        let database = slot
            .database
            .as_mut()
            .ok_or_else(|| AppError::new("DB_UNAVAILABLE", "数据库尚未初始化"))?;

        database
            .self_check()
            .map_err(|error| AppError::new("DB_CHECK_FAILED", error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_database_migrates_to_v1() {
        let database = Database::open_in_memory().expect("内存数据库应能打开");
        assert_eq!(
            database.schema_version().expect("应能读取 schema 版本"),
            SCHEMA_VERSION
        );
        assert!(database.path().is_none());
    }

    #[test]
    fn self_check_roundtrip_succeeds_and_leaves_no_residue() {
        let mut database = Database::open_in_memory().expect("内存数据库应能打开");
        let report = database.self_check().expect("自检不应失败");

        assert!(report.ok);
        assert!(report.roundtrip_ok);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert!(!report.engine_version.is_empty());

        let remaining: i64 = database
            .connection
            .query_row(
                "SELECT COUNT(*) FROM app_meta WHERE key = ?1",
                params![SELF_CHECK_KEY],
                |row| row.get(0),
            )
            .expect("应能统计自检键");
        assert_eq!(remaining, 0, "自检必须在同一事务内删除测试键");
    }

    #[test]
    fn file_database_reopens_with_persisted_schema() {
        let path = std::env::temp_dir().join(format!(
            "upsweep_stage0_db_test_{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        {
            let mut database = Database::open(&path).expect("文件数据库应能创建");
            let report = database.self_check().expect("自检不应失败");
            assert!(report.ok);
            assert!(report.database_path.is_some());
            assert!(report.database_size_bytes.unwrap_or(0) > 0);
        }

        let reopened = Database::open(&path).expect("数据库应能重新打开");
        assert_eq!(
            reopened.schema_version().expect("应能读取 schema 版本"),
            SCHEMA_VERSION
        );
        drop(reopened);

        let _ = fs::remove_file(&path);
    }
}
