//! 扫描引擎主循环。
//!
//! 目录遍历是单线程、确定性的；候选文件的 PE/签名/MSI 读取由有界工作线程并发执行。
//! 遍历与元数据读取都检查取消令牌；任何单文件/单目录错误都会记录并继续，
//! 不会让扫描任务崩溃。

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::metadata::{self, MetadataOptions};
use crate::models::{
    DirectoryContext, DirectorySummary, DiscoveryEvidence, FileIdentity, FileInfo, LogLevel,
    ScanCandidate, ScanIssue, ScanIssueKind, ScanLogEvent, ScanPhase, ScanProgress, ScanReport,
    ScanReportConfig, ScanStatus, ScanTotals, ScanTruncation,
};
use crate::protection::{
    self, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_SYSTEM, PathKey,
};
use crate::scanner::discovery;
use crate::scanner::plan::{ScanPlan, log_event};
use crate::utils::time::unix_ms;

const MAX_ISSUES: usize = 5_000;
const MAX_LOG_EVENTS: usize = 5_000;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone, Default)]
pub struct ScanControl {
    cancel: Arc<AtomicBool>,
}

impl ScanControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    fn flag(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }
}

pub trait ScanObserver: Send + Sync {
    fn on_progress(&self, progress: &ScanProgress);
    fn on_candidate(&self, candidate: &ScanCandidate);
}

pub struct NoopObserver;

impl ScanObserver for NoopObserver {
    fn on_progress(&self, _progress: &ScanProgress) {}
    fn on_candidate(&self, _candidate: &ScanCandidate) {}
}

#[derive(Default)]
struct Stats {
    directories: AtomicU64,
    files: AtomicU64,
    candidates: AtomicU64,
    metadata_read: AtomicU64,
    signatures_read: AtomicU64,
    skipped_reparse: AtomicU64,
    skipped_protected: AtomicU64,
    skipped_excluded: AtomicU64,
    skipped_depth: AtomicU64,
    errors: AtomicU64,
    warnings: AtomicU64,
    roots_read: AtomicU64,
}

impl Stats {
    fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

struct ProgressTracker<'a> {
    session_id: &'a str,
    started: Instant,
    stats: &'a Stats,
    phase: AtomicU8,
    current_path: Mutex<String>,
    last_emit: Mutex<Instant>,
    observer: &'a dyn ScanObserver,
    cancel: &'a AtomicBool,
}

impl<'a> ProgressTracker<'a> {
    fn new(
        session_id: &'a str,
        stats: &'a Stats,
        observer: &'a dyn ScanObserver,
        cancel: &'a AtomicBool,
    ) -> Self {
        Self {
            session_id,
            started: Instant::now(),
            stats,
            phase: AtomicU8::new(ScanPhase::Preparing as u8),
            current_path: Mutex::new(String::new()),
            last_emit: Mutex::new(Instant::now() - PROGRESS_INTERVAL),
            observer,
            cancel,
        }
    }

    fn set_phase(&self, phase: ScanPhase) {
        self.phase.store(phase as u8, Ordering::Release);
    }

    fn set_current(&self, path: &Path) {
        let mut current = self
            .current_path
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = path.to_string_lossy().into_owned();
    }

    fn snapshot(&self) -> ScanProgress {
        let current = self
            .current_path
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        ScanProgress {
            session_id: self.session_id.to_string(),
            phase: phase_from_u8(self.phase.load(Ordering::Acquire)),
            scanned_directories: Stats::get(&self.stats.directories),
            scanned_files: Stats::get(&self.stats.files),
            candidates_found: Stats::get(&self.stats.candidates),
            metadata_read: Stats::get(&self.stats.metadata_read),
            signatures_read: Stats::get(&self.stats.signatures_read),
            skipped_reparse_points: Stats::get(&self.stats.skipped_reparse),
            skipped_protected: Stats::get(&self.stats.skipped_protected),
            skipped_excluded: Stats::get(&self.stats.skipped_excluded),
            errors: Stats::get(&self.stats.errors),
            current_path: if current.is_empty() {
                None
            } else {
                Some(current)
            },
            elapsed_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            cancelled: self.cancel.load(Ordering::Acquire),
        }
    }

    fn emit(&self, force: bool) {
        let mut last = self
            .last_emit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !force && last.elapsed() < PROGRESS_INTERVAL {
            return;
        }
        *last = Instant::now();
        drop(last);
        self.observer.on_progress(&self.snapshot());
    }
}

fn phase_from_u8(value: u8) -> ScanPhase {
    match value {
        1 => ScanPhase::Enumerating,
        2 => ScanPhase::ReadingMetadata,
        3 => ScanPhase::Finalizing,
        _ => ScanPhase::Preparing,
    }
}

struct Collector<'a> {
    stats: &'a Stats,
    issues: Mutex<Vec<ScanIssue>>,
    logs: Mutex<Vec<ScanLogEvent>>,
    dropped_issues: AtomicU64,
    dropped_logs: AtomicU64,
}

impl<'a> Collector<'a> {
    fn new(stats: &'a Stats) -> Self {
        Self {
            stats,
            issues: Mutex::new(Vec::new()),
            logs: Mutex::new(Vec::new()),
            dropped_issues: AtomicU64::new(0),
            dropped_logs: AtomicU64::new(0),
        }
    }

    fn add_issue(&self, issue: ScanIssue) {
        Stats::inc(&self.stats.errors);
        let mut issues = self
            .issues
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if issues.len() >= MAX_ISSUES {
            self.dropped_issues.fetch_add(1, Ordering::Relaxed);
            return;
        }
        issues.push(issue);
    }

    fn add_log(&self, event: ScanLogEvent) {
        if matches!(event.level, LogLevel::Warn | LogLevel::Error) {
            Stats::inc(&self.stats.warnings);
        }
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if logs.len() >= MAX_LOG_EVENTS {
            self.dropped_logs.fetch_add(1, Ordering::Relaxed);
            return;
        }
        logs.push(event);
    }

    fn log(&self, level: LogLevel, event: &str, message: String, path: Option<String>) {
        self.add_log(log_event(level, event, message, path));
    }

    fn issue(&self, kind: ScanIssueKind, code: &str, message: String, path: Option<String>) {
        self.add_issue(ScanIssue {
            kind,
            code: code.to_string(),
            message,
            path,
            recoverable: true,
        });
    }
}

struct PendingCandidate {
    file: FileInfo,
    directory_context: DirectoryContext,
    discovery: DiscoveryEvidence,
    path_key: PathKey,
}

struct WorkQueue {
    items: Mutex<VecDeque<PendingCandidate>>,
    available: Condvar,
    closed: AtomicBool,
}

impl WorkQueue {
    fn new() -> Self {
        Self {
            items: Mutex::new(VecDeque::new()),
            available: Condvar::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn push(&self, candidate: PendingCandidate) {
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        items.push_back(candidate);
        self.available.notify_one();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.available.notify_all();
    }

    fn pop(&self) -> Option<PendingCandidate> {
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(candidate) = items.pop_front() {
                return Some(candidate);
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            items = self
                .available
                .wait(items)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

/// 执行一次扫描。调用方负责在另一个线程中调用，以避免阻塞 Tauri 主线程。
pub fn run(plan: &ScanPlan, control: &ScanControl, observer: &dyn ScanObserver) -> ScanReport {
    let stats = Stats::default();
    let cancel = control.flag();
    let collector = Collector::new(&stats);
    for issue in &plan.issues {
        collector.add_issue(issue.clone());
    }
    for log in &plan.log {
        collector.add_log(log.clone());
    }

    collector.log(
        LogLevel::Info,
        "scan_started",
        format!(
            "开始扫描：{} 个根目录，并发度 {}",
            plan.roots.len(),
            plan.concurrency
        ),
        None,
    );

    let progress = ProgressTracker::new(&plan.session_id, &stats, observer, &cancel);
    progress.set_phase(ScanPhase::Preparing);
    progress.emit(true);

    let queue = WorkQueue::new();
    let sink = Mutex::new(Vec::new());
    progress.set_phase(ScanPhase::Enumerating);
    progress.emit(true);

    let directory_summaries = std::thread::scope(|scope| {
        for _ in 0..plan.concurrency.max(1) {
            scope.spawn(|| {
                while let Some(pending) = queue.pop() {
                    if cancel.load(Ordering::Acquire) {
                        break;
                    }
                    enrich_candidate(
                        pending,
                        plan.metadata,
                        &collector,
                        &progress,
                        &sink,
                        observer,
                        &cancel,
                    );
                }
            });
        }

        let summaries = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            traverse(plan, &queue, &progress, &collector, &cancel, &stats)
        })) {
            Ok(summaries) => summaries,
            Err(_) => {
                collector.issue(
                    ScanIssueKind::Internal,
                    "TRAVERSAL_PANIC",
                    "目录遍历发生内部错误，扫描已保留已完成的结果".to_string(),
                    None,
                );
                Vec::new()
            }
        };
        queue.close();
        summaries
    });

    if cancel.load(Ordering::Acquire) {
        collector.log(
            LogLevel::Warn,
            "scan_cancelled",
            "扫描已取消，已保留取消前完成的结果".to_string(),
            None,
        );
    }

    progress.set_phase(ScanPhase::Finalizing);
    progress.emit(true);

    let status = if cancel.load(Ordering::Acquire) {
        ScanStatus::Cancelled
    } else if plan.roots.is_empty() || Stats::get(&stats.roots_read) == 0 {
        ScanStatus::Failed
    } else {
        ScanStatus::Completed
    };
    collector.log(
        LogLevel::Info,
        "scan_finished",
        format!(
            "扫描结束：{:?}，目录 {}，文件 {}，候选 {}，错误 {}",
            status,
            Stats::get(&stats.directories),
            Stats::get(&stats.files),
            Stats::get(&stats.candidates),
            Stats::get(&stats.errors)
        ),
        None,
    );

    let mut candidates = sink
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    candidates.sort_by(|left, right| {
        left.file
            .path
            .to_lowercase()
            .cmp(&right.file.path.to_lowercase())
    });

    let issues = collector
        .issues
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let log = collector
        .logs
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let finished_at_ms = crate::utils::time::now_ms();

    ScanReport {
        session_id: plan.session_id.clone(),
        status,
        started_at_ms: plan.started_at_ms,
        finished_at_ms,
        duration_ms: finished_at_ms.saturating_sub(plan.started_at_ms),
        roots: plan.root_infos(),
        exclusions: plan.exclusion_infos(),
        config: ScanReportConfig {
            include_metadata: plan.metadata.include_metadata,
            include_signature: plan.metadata.include_signature,
            include_msi: plan.metadata.include_msi,
            max_depth: plan.max_depth.map(|depth| depth as u32),
            concurrency: plan.concurrency as u32,
        },
        totals: ScanTotals {
            directories: Stats::get(&stats.directories),
            files: Stats::get(&stats.files),
            candidates: Stats::get(&stats.candidates),
            metadata_read: Stats::get(&stats.metadata_read),
            signatures_read: Stats::get(&stats.signatures_read),
            skipped_reparse_points: Stats::get(&stats.skipped_reparse),
            skipped_protected: Stats::get(&stats.skipped_protected),
            skipped_excluded: Stats::get(&stats.skipped_excluded),
            skipped_max_depth: Stats::get(&stats.skipped_depth),
            errors: Stats::get(&stats.errors),
            warnings: Stats::get(&stats.warnings),
        },
        candidates,
        directory_summaries,
        issues,
        log,
        truncation: ScanTruncation {
            issues_truncated: collector.dropped_issues.load(Ordering::Relaxed) > 0,
            log_truncated: collector.dropped_logs.load(Ordering::Relaxed) > 0,
            dropped_issues: collector.dropped_issues.load(Ordering::Relaxed),
            dropped_log_events: collector.dropped_logs.load(Ordering::Relaxed),
        },
    }
}

fn enrich_candidate(
    pending: PendingCandidate,
    options: MetadataOptions,
    collector: &Collector<'_>,
    progress: &ProgressTracker<'_>,
    sink: &Mutex<Vec<ScanCandidate>>,
    observer: &dyn ScanObserver,
    cancel: &AtomicBool,
) {
    if cancel.load(Ordering::Acquire) {
        return;
    }
    progress.set_phase(ScanPhase::ReadingMetadata);
    progress.set_current(Path::new(&pending.file.path));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        metadata::collect(
            Path::new(&pending.file.path),
            pending.file.extension.as_deref(),
            options,
        )
    }));

    let metadata = match result {
        Ok(metadata) => metadata,
        Err(_) => {
            collector.log(
                LogLevel::Error,
                "metadata_panic",
                format!("元数据读取发生内部错误: {}", pending.file.path),
                Some(pending.file.path.clone()),
            );
            metadata::CandidateMetadata::default()
        }
    };

    let signature_read = metadata.signature.is_some();
    let mut metadata_issues = metadata.issues;
    if let Some(signature) = &metadata.signature
        && let Some(message) = &signature.diagnostic
        && signature.trust_status == crate::models::SignatureStatus::Unknown
    {
        metadata_issues.push(crate::models::MetadataIssue {
            kind: "signature".to_string(),
            message: message.clone(),
        });
    }

    let candidate = ScanCandidate {
        id: stable_id(&pending.path_key),
        file: pending.file,
        directory_context: pending.directory_context,
        discovery: pending.discovery,
        pe_metadata: metadata.pe,
        signature: metadata.signature,
        msi_metadata: metadata.msi,
        metadata_issues,
    };

    {
        let mut candidates = sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        candidates.push(candidate.clone());
    }
    Stats::inc(&progress.stats.metadata_read);
    if signature_read {
        Stats::inc(&progress.stats.signatures_read);
    }
    observer.on_candidate(&candidate);
    progress.emit(false);
}

struct DirectoryTask {
    path: PathBuf,
    depth: usize,
    hints: Vec<String>,
    root: PathBuf,
}

fn traverse(
    plan: &ScanPlan,
    queue: &WorkQueue,
    progress: &ProgressTracker<'_>,
    collector: &Collector<'_>,
    cancel: &AtomicBool,
    stats: &Stats,
) -> Vec<DirectorySummary> {
    let mut visited: HashSet<PathKey> = HashSet::new();
    let mut summaries: Vec<DirectorySummary> = Vec::new();

    for root in &plan.roots {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        let hints = root
            .path
            .file_name()
            .and_then(|name| discovery::directory_hint(&name.to_string_lossy()))
            .into_iter()
            .collect::<Vec<_>>();
        let mut stack = vec![DirectoryTask {
            path: root.path.clone(),
            depth: 0,
            hints,
            root: root.path.clone(),
        }];

        while let Some(task) = stack.pop() {
            if cancel.load(Ordering::Acquire) {
                break;
            }
            progress.set_current(&task.path);

            let canonical = match fs::canonicalize(&task.path) {
                Ok(path) => path,
                Err(error) => {
                    collector.issue(
                        ScanIssueKind::DirectoryAccess,
                        "DIRECTORY_CANONICALIZE_FAILED",
                        format!("目录规范化失败: {error}"),
                        Some(task.path.to_string_lossy().into_owned()),
                    );
                    continue;
                }
            };

            let key = match protection::path_key(&canonical) {
                Ok(key) => key,
                Err(error) => {
                    collector.issue(
                        ScanIssueKind::PathValidation,
                        "DIRECTORY_KEY_FAILED",
                        error.to_string(),
                        Some(canonical.to_string_lossy().into_owned()),
                    );
                    continue;
                }
            };
            if !visited.insert(key.clone()) {
                collector.log(
                    LogLevel::Warn,
                    "loop_directory_skipped",
                    format!("检测到重复目录，已跳过: {}", canonical.display()),
                    Some(canonical.to_string_lossy().into_owned()),
                );
                continue;
            }

            if let Some((protected_path, reason)) = plan.protected.match_protected_key(&key) {
                Stats::inc(&stats.skipped_protected);
                collector.log(
                    LogLevel::Debug,
                    "protected_path_skipped",
                    format!("跳过受保护目录 {}（{}）", canonical.display(), reason),
                    Some(protected_path.to_string_lossy().into_owned()),
                );
                continue;
            }

            if plan
                .exclusions
                .iter()
                .any(|exclusion| key.starts_with(&exclusion.key))
            {
                Stats::inc(&stats.skipped_excluded);
                collector.log(
                    LogLevel::Debug,
                    "excluded_path_skipped",
                    format!("跳过排除目录: {}", canonical.display()),
                    Some(canonical.to_string_lossy().into_owned()),
                );
                continue;
            }

            let read_dir = match fs::read_dir(&canonical) {
                Ok(entries) => entries,
                Err(error) => {
                    let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
                        "DIRECTORY_ACCESS_DENIED"
                    } else {
                        "DIRECTORY_READ_FAILED"
                    };
                    collector.issue(
                        ScanIssueKind::DirectoryAccess,
                        code,
                        format!("无法读取目录: {error}"),
                        Some(canonical.to_string_lossy().into_owned()),
                    );
                    continue;
                }
            };

            Stats::inc(&stats.directories);
            if task.depth == 0 {
                Stats::inc(&stats.roots_read);
            }

            let mut entries = Vec::new();
            for entry in read_dir {
                match entry {
                    Ok(entry) => entries.push(entry),
                    Err(error) => collector.issue(
                        ScanIssueKind::DirectoryAccess,
                        "DIRECTORY_ENTRY_FAILED",
                        format!("读取目录项失败: {error}"),
                        Some(canonical.to_string_lossy().into_owned()),
                    ),
                }
            }
            entries.sort_by(|left, right| {
                left.file_name()
                    .to_string_lossy()
                    .to_lowercase()
                    .cmp(&right.file_name().to_string_lossy().to_lowercase())
            });

            let mut file_count = 0u64;
            let mut subdirectory_count = 0u64;
            let mut candidate_count = 0u64;
            let mut skipped_reparse_here = 0u64;

            for entry in entries {
                if cancel.load(Ordering::Acquire) {
                    break;
                }
                let path = entry.path();
                let file_name = entry.file_name().to_string_lossy().into_owned();

                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        collector.issue(
                            ScanIssueKind::FileAccess,
                            "FILE_METADATA_FAILED",
                            format!("无法读取文件属性: {error}"),
                            Some(path.to_string_lossy().into_owned()),
                        );
                        continue;
                    }
                };

                let attributes = match protection::file_attributes(&path) {
                    Ok(attributes) => attributes,
                    Err(error) => {
                        // 属性读取失败时无法可靠判断重解析点，保守地跳过该条目。
                        collector.issue(
                            ScanIssueKind::FileAccess,
                            "FILE_ATTRIBUTES_FAILED",
                            format!("无法读取文件属性标志: {error}"),
                            Some(path.to_string_lossy().into_owned()),
                        );
                        continue;
                    }
                };
                let is_reparse = attributes & protection::FILE_ATTRIBUTE_REPARSE_POINT != 0
                    || metadata.file_type().is_symlink();
                if is_reparse {
                    Stats::inc(&stats.skipped_reparse);
                    skipped_reparse_here += 1;
                    collector.log(
                        LogLevel::Warn,
                        "reparse_point_skipped",
                        format!("跳过重解析点，不跟随链接: {}", path.display()),
                        Some(path.to_string_lossy().into_owned()),
                    );
                    continue;
                }

                if metadata.is_dir() {
                    subdirectory_count += 1;
                    if let Some(max_depth) = plan.max_depth
                        && task.depth >= max_depth
                    {
                        Stats::inc(&stats.skipped_depth);
                        collector.log(
                            LogLevel::Debug,
                            "max_depth_reached",
                            format!("达到最大扫描深度，跳过子目录: {}", path.display()),
                            Some(path.to_string_lossy().into_owned()),
                        );
                        continue;
                    }
                    let mut hints = task.hints.clone();
                    if let Some(hint) = discovery::directory_hint(&file_name)
                        && !hints.contains(&hint)
                    {
                        hints.push(hint);
                    }
                    stack.push(DirectoryTask {
                        path,
                        depth: task.depth + 1,
                        hints,
                        root: task.root.clone(),
                    });
                    continue;
                }

                if !metadata.is_file() {
                    continue;
                }

                file_count += 1;
                Stats::inc(&stats.files);
                progress.set_current(&path);
                progress.emit(false);

                let extension = path
                    .extension()
                    .map(|value| value.to_string_lossy().to_ascii_lowercase());
                let Some(evidence) =
                    discovery::evaluate(&file_name, extension.as_deref(), &task.hints)
                else {
                    continue;
                };

                let candidate_key = match protection::path_key(&path) {
                    Ok(key) => key,
                    Err(error) => {
                        collector.issue(
                            ScanIssueKind::PathValidation,
                            "CANDIDATE_PATH_KEY_FAILED",
                            error.to_string(),
                            Some(path.to_string_lossy().into_owned()),
                        );
                        continue;
                    }
                };
                let file = file_info(&path, &file_name, extension, &metadata, attributes);
                let relative_directory = path
                    .parent()
                    .and_then(|parent| parent.strip_prefix(&task.root).ok())
                    .map(|relative| relative.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let context = DirectoryContext {
                    scan_root: task.root.to_string_lossy().into_owned(),
                    relative_directory,
                    directory_hints: task.hints.clone(),
                };

                candidate_count += 1;
                Stats::inc(&stats.candidates);
                queue.push(PendingCandidate {
                    file,
                    directory_context: context,
                    discovery: evidence,
                    path_key: candidate_key,
                });
            }

            if !task.hints.is_empty() || candidate_count > 0 {
                let relative_path = canonical
                    .strip_prefix(&task.root)
                    .map(|relative| relative.to_string_lossy().into_owned())
                    .unwrap_or_default();
                summaries.push(DirectorySummary {
                    path: canonical.to_string_lossy().into_owned(),
                    relative_path,
                    directory_hints: task.hints,
                    file_count,
                    subdirectory_count,
                    candidate_count,
                    skipped_reparse_points: skipped_reparse_here,
                });
            }
        }
    }

    summaries.sort_by_key(|summary| summary.path.to_lowercase());
    summaries
}

fn file_info(
    path: &Path,
    file_name: &str,
    extension: Option<String>,
    metadata: &fs::Metadata,
    attributes: u32,
) -> FileInfo {
    let created_at_ms = metadata.created().ok().and_then(unix_ms);
    let modified_at_ms = metadata.modified().ok().and_then(unix_ms);
    let identity = crate::utils::windows_api::file_identity(path);

    FileInfo {
        path: path.to_string_lossy().into_owned(),
        file_name: file_name.to_string(),
        extension,
        size: metadata.len(),
        created_at_ms,
        modified_at_ms,
        accessed_at_ms: metadata.accessed().ok().and_then(unix_ms),
        attributes,
        is_reparse_point: false,
        is_read_only: attributes & FILE_ATTRIBUTE_READONLY != 0,
        is_hidden: attributes & FILE_ATTRIBUTE_HIDDEN != 0,
        is_system: attributes & FILE_ATTRIBUTE_SYSTEM != 0,
        is_archive: attributes & FILE_ATTRIBUTE_ARCHIVE != 0,
        identity: FileIdentity {
            volume_serial: identity.volume_serial,
            file_id: identity.file_id,
            size: metadata.len(),
            created_at_ms,
            modified_at_ms,
            read_error: identity.read_error,
        },
    }
}

/// 候选 ID 是规范化路径身份的 SHA-256 截断值，不是文件身份。
fn stable_id(path_key: &PathKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path_key.identity_bytes());
    let digest = hasher.finalize();
    let mut id = String::with_capacity(32);
    for byte in &digest[..16] {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}
