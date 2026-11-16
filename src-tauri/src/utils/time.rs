//! 时间转换。报告统一使用 Unix 毫秒，避免时区格式依赖。

use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

pub fn now_ms() -> u64 {
    unix_ms(SystemTime::now()).unwrap_or(0)
}
