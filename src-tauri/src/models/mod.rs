//! 前后端共享的数据结构。
//!
//! 包含诊断、扫描与元数据模型；风险分类/清理计划模型将在后续阶段加入，
//! 避免提前定义尚未验证的业务契约。

mod error;
mod reports;
mod scan;

pub use error::AppError;
pub use reports::{AppInfo, DatabaseCheckReport, WindowsApiCheck, WindowsProbeReport};
pub use scan::{
    ChainStatus, DirectoryContext, DirectorySummary, DiscoveryEvidence, FileIdentity, FileInfo,
    InstalledSoftware, InstalledSoftwareReport, LogLevel, MetadataIssue, MsiMetadata,
    MsiPackageType, PeMetadata, ScanCandidate, ScanExclusionInfo, ScanIssue, ScanIssueKind,
    ScanLogEvent, ScanPhase, ScanProgress, ScanReport, ScanReportConfig, ScanRequest, ScanRootInfo,
    ScanRootSource, ScanSessionInfo, ScanStatus, ScanTotals, ScanTruncation, SignatureInfo,
    SignatureStatus,
};
