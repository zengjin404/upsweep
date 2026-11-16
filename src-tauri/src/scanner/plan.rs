//! 扫描计划准备：解析预设目录、自定义目录、排除目录与安全边界。
//!
//! 前端传入的是路径字符串；后端负责绝对化、规范化、重解析点检查与受保护路径校验。
//! 无效的自定义目录记录为问题并跳过，不会导致整个扫描请求被静默忽略。

use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::metadata::MetadataOptions;
use crate::models::{
    AppError, LogLevel, ScanExclusionInfo, ScanIssue, ScanIssueKind, ScanLogEvent, ScanRequest,
    ScanRootInfo, ScanRootSource,
};
use crate::protection::{self, PathKey, ProtectedPaths};
use crate::utils::time::now_ms;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct PlanRoot {
    pub path: PathBuf,
    pub info: ScanRootInfo,
}

#[derive(Debug)]
pub struct PlanExclusion {
    pub path: PathBuf,
    pub info: ScanExclusionInfo,
    pub key: PathKey,
}

pub struct ScanPlan {
    pub session_id: String,
    pub started_at_ms: u64,
    pub roots: Vec<PlanRoot>,
    pub exclusions: Vec<PlanExclusion>,
    pub protected: ProtectedPaths,
    pub max_depth: Option<usize>,
    pub concurrency: usize,
    pub metadata: MetadataOptions,
    pub issues: Vec<ScanIssue>,
    pub log: Vec<ScanLogEvent>,
}

impl ScanPlan {
    pub fn root_infos(&self) -> Vec<ScanRootInfo> {
        self.roots.iter().map(|root| root.info.clone()).collect()
    }

    pub fn exclusion_infos(&self) -> Vec<ScanExclusionInfo> {
        self.exclusions
            .iter()
            .map(|exclusion| exclusion.info.clone())
            .collect()
    }
}

pub fn prepare(request: ScanRequest) -> Result<ScanPlan, AppError> {
    let started_at_ms = now_ms();
    let session_id = format!(
        "scan-{}-{}",
        started_at_ms,
        SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let protected = ProtectedPaths::default_for_system();
    let mut issues = Vec::new();
    let mut log = Vec::new();

    let max_depth = match request.max_depth {
        Some(depth) if depth > 256 => {
            return Err(AppError::new("MAX_DEPTH_INVALID", "maxDepth 不能超过 256"));
        }
        Some(depth) => Some(depth as usize),
        None => None,
    };

    let mut roots: Vec<PlanRoot> = Vec::new();
    let mut root_keys: Vec<PathKey> = Vec::new();

    if request.include_default_roots {
        for (source, variable) in [
            (ScanRootSource::LocalAppData, "LOCALAPPDATA"),
            (ScanRootSource::RoamingAppData, "APPDATA"),
            (ScanRootSource::ProgramData, "ProgramData"),
            (ScanRootSource::ProgramFiles, "ProgramFiles"),
            (ScanRootSource::ProgramFilesX86, "ProgramFiles(x86)"),
        ] {
            let Some(value) = env::var_os(variable) else {
                log.push(log_event(
                    LogLevel::Debug,
                    "preset_root_missing",
                    format!("环境变量 {variable} 不存在，跳过该预设目录"),
                    None,
                ));
                continue;
            };
            let path = PathBuf::from(value);
            match add_root(&path, source, &protected, &mut roots, &mut root_keys) {
                Ok(true) => {}
                Ok(false) => log.push(log_event(
                    LogLevel::Debug,
                    "preset_root_duplicate",
                    format!("预设目录重复，已跳过: {}", path.display()),
                    Some(path.to_string_lossy().into_owned()),
                )),
                Err(error) => issues.push(issue(
                    ScanIssueKind::PathValidation,
                    "PRESET_ROOT_INVALID",
                    error.to_string(),
                    Some(path.to_string_lossy().into_owned()),
                )),
            }
        }
    }

    for custom in &request.custom_roots {
        let path = PathBuf::from(custom);
        match add_root(
            &path,
            ScanRootSource::Custom,
            &protected,
            &mut roots,
            &mut root_keys,
        ) {
            Ok(true) => log.push(log_event(
                LogLevel::Info,
                "custom_root_added",
                format!("已加入自定义扫描根: {}", path.display()),
                Some(path.to_string_lossy().into_owned()),
            )),
            Ok(false) => log.push(log_event(
                LogLevel::Debug,
                "custom_root_duplicate",
                format!("自定义目录重复，已跳过: {}", path.display()),
                Some(path.to_string_lossy().into_owned()),
            )),
            Err(error) => issues.push(issue(
                ScanIssueKind::PathValidation,
                "CUSTOM_ROOT_INVALID",
                error.to_string(),
                Some(custom.clone()),
            )),
        }
    }

    let mut exclusions: Vec<PlanExclusion> = Vec::new();
    let mut exclusion_keys: Vec<PathKey> = Vec::new();
    for (path, reason) in protected.exclusions() {
        push_exclusion(&path, &reason, &mut exclusions, &mut exclusion_keys);
    }
    for custom in &request.excluded_paths {
        let path = PathBuf::from(custom);
        match protection::normalize_exclusion(&path) {
            Ok(path) => push_exclusion(&path, "用户排除目录", &mut exclusions, &mut exclusion_keys),
            Err(error) => issues.push(issue(
                ScanIssueKind::PathValidation,
                "EXCLUSION_INVALID",
                error.to_string(),
                Some(custom.clone()),
            )),
        }
    }

    if roots.is_empty() {
        issues.push(issue(
            ScanIssueKind::PathValidation,
            "NO_SCAN_ROOTS",
            "没有可用的扫描根；请启用预设目录或提供有效的自定义目录".to_string(),
            None,
        ));
    }

    log.push(log_event(
        LogLevel::Info,
        "scan_plan_ready",
        format!(
            "扫描计划准备完成：{} 个扫描根，{} 个排除目录，最大深度 {}",
            roots.len(),
            exclusions.len(),
            max_depth
                .map(|depth| depth.to_string())
                .unwrap_or_else(|| "不限".to_string())
        ),
        None,
    ));

    let concurrency = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .clamp(1, 8)
        .min(4);

    Ok(ScanPlan {
        session_id,
        started_at_ms,
        roots,
        exclusions,
        protected,
        max_depth,
        concurrency,
        metadata: MetadataOptions {
            include_metadata: request.include_metadata,
            include_signature: request.include_signature,
            include_msi: request.include_msi,
        },
        issues,
        log,
    })
}

fn add_root(
    path: &Path,
    source: ScanRootSource,
    protected: &ProtectedPaths,
    roots: &mut Vec<PlanRoot>,
    root_keys: &mut Vec<PathKey>,
) -> Result<bool, protection::PathSafetyError> {
    let canonical = protection::validate_scan_root(path, protected)?;
    let key = protection::path_key(&canonical)?;
    if root_keys.iter().any(|existing| existing == &key) {
        return Ok(false);
    }
    root_keys.push(key);
    roots.push(PlanRoot {
        path: canonical.clone(),
        info: ScanRootInfo {
            path: canonical.to_string_lossy().into_owned(),
            source,
        },
    });
    Ok(true)
}

fn push_exclusion(
    path: &std::path::Path,
    reason: &str,
    exclusions: &mut Vec<PlanExclusion>,
    keys: &mut Vec<PathKey>,
) {
    let Ok(key) = protection::path_key(path) else {
        return;
    };
    if keys.iter().any(|existing| existing == &key) {
        return;
    }
    keys.push(key.clone());
    exclusions.push(PlanExclusion {
        path: path.to_path_buf(),
        info: ScanExclusionInfo {
            path: path.to_string_lossy().into_owned(),
            reason: reason.to_string(),
        },
        key,
    });
}

fn issue(kind: ScanIssueKind, code: &str, message: String, path: Option<String>) -> ScanIssue {
    ScanIssue {
        kind,
        code: code.to_string(),
        message,
        path,
        recoverable: true,
    }
}

pub fn log_event(
    level: LogLevel,
    event: &str,
    message: String,
    path: Option<String>,
) -> ScanLogEvent {
    ScanLogEvent {
        timestamp_ms: now_ms(),
        level,
        event: event.to_string(),
        message,
        path,
    }
}
