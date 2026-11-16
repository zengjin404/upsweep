//! 扫描会话管理。
//!
//! Tauri 命令只创建会话并立即返回；实际扫描在独立线程中执行。
//! 取消令牌与最近报告由本模块保存，避免前端持有任意文件路径或线程句柄。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::models::ScanReport;
use crate::scanner::engine::ScanControl;

const MAX_RETAINED_REPORTS: usize = 10;

#[derive(Clone, Default)]
pub struct ScanManager {
    inner: Arc<Mutex<ManagerState>>,
}

#[derive(Default)]
struct ManagerState {
    active: HashMap<String, ScanControl>,
    reports: HashMap<String, ScanReport>,
}

impl ScanManager {
    pub fn register(&self, session_id: String, control: ScanControl) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active.insert(session_id, control);
    }

    pub fn cancel(&self, session_id: &str) -> bool {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match state.active.get(session_id) {
            Some(control) => {
                control.cancel();
                true
            }
            None => false,
        }
    }

    pub fn complete(&self, session_id: &str, report: ScanReport) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active.remove(session_id);
        state.reports.insert(session_id.to_string(), report);
        while state.reports.len() > MAX_RETAINED_REPORTS {
            let oldest = state
                .reports
                .iter()
                .min_by_key(|(_, report)| report.finished_at_ms)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                state.reports.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn fail(&self, session_id: &str) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active.remove(session_id);
    }

    pub fn report(&self, session_id: &str) -> Option<ScanReport> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.reports.get(session_id).cloned()
    }

    pub fn is_active(&self, session_id: &str) -> bool {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active.contains_key(session_id)
    }
}
