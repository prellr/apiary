//! Spend authority — SPEC §8. Token budgets and money budgets are one system
//! of human-owned floors enforced in the host core, before every inference
//! call. The model is never asked to be frugal; a hijacked agent is bounded
//! by construction.
//!
//! Phase 1 implements the token side: `governance.budgets.tokens_per_day`.
//! Counters live in the agent dir (`spend.json`), keyed by UTC date.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DaySpend {
    pub date: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

pub struct SpendLedger {
    path: PathBuf,
}

fn utc_date_today() -> String {
    // Days since epoch → civil date (no chrono dependency for one field).
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86_400;
    // Howard Hinnant's civil_from_days algorithm.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

impl SpendLedger {
    pub fn open(agent_dir: &Path) -> Self {
        Self {
            path: agent_dir.join("spend.json"),
        }
    }

    pub fn today(&self) -> Result<DaySpend, crate::Error> {
        let today = utc_date_today();
        if !self.path.exists() {
            return Ok(DaySpend { date: today, ..Default::default() });
        }
        let stored: DaySpend = serde_json::from_str(&std::fs::read_to_string(&self.path)?)?;
        if stored.date == today {
            Ok(stored)
        } else {
            Ok(DaySpend { date: today, ..Default::default() })
        }
    }

    /// Enforce the floor: error when today's total has reached the cap.
    /// Call BEFORE inference; the request that would cross is refused.
    pub fn check(&self, tokens_per_day: Option<u64>) -> Result<(), crate::Error> {
        let Some(cap) = tokens_per_day else { return Ok(()) };
        let today = self.today()?;
        let used = today.input_tokens + today.output_tokens;
        if used >= cap {
            return Err(crate::Error::Budget(format!(
                "daily token budget reached ({used}/{cap}); a human raises the floor, not the agent"
            )));
        }
        Ok(())
    }

    pub fn record(&self, input_tokens: u64, output_tokens: u64) -> Result<DaySpend, crate::Error> {
        let mut today = self.today()?;
        today.input_tokens += input_tokens;
        today.output_tokens += output_tokens;
        std::fs::write(&self.path, serde_json::to_string_pretty(&today)?)?;
        Ok(today)
    }
}

/// Read the tokens/day cap from the manifest's governance budgets.
/// Accepts `tokens_per_day` or the SPEC's `tokens/day` spelling.
pub fn tokens_per_day(budgets: &std::collections::BTreeMap<String, serde_json::Value>) -> Option<u64> {
    budgets
        .get("tokens_per_day")
        .or_else(|| budgets.get("tokens/day"))
        .and_then(|v| v.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_enforced() {
        let dir = std::env::temp_dir().join(format!("apiary-spend-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = SpendLedger::open(&dir);
        ledger.check(Some(100)).unwrap();
        ledger.record(60, 50).unwrap(); // 110 total
        assert!(ledger.check(Some(100)).is_err());
        assert!(ledger.check(None).is_ok()); // no cap, no floor
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn date_format_sane() {
        let d = utc_date_today();
        assert_eq!(d.len(), 10);
        assert!(d.starts_with("20"));
    }
}
