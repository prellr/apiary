//! Spend authority — SPEC §8. Token budgets and money budgets are one system
//! of human-owned floors enforced in the host core, before every inference
//! call. The model is never asked to be frugal; a hijacked agent is bounded
//! by construction.
//!
//! The cap is a HARD ceiling, not a turnstile: capacity is RESERVED under an
//! exclusive file lock before inference (concurrent runs cannot all pass),
//! the reservation bounds what the provider may generate (max_tokens is
//! clamped to it), and actual usage settles the reservation afterward.
//! Crashed runs leak nothing: reservations expire.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A run may reserve at most this much at once — bounds a single run's
/// worst case even under a huge daily cap.
pub const MAX_RESERVATION: u64 = 64_000;
/// Reservations from crashed runs expire after this many seconds.
const RESERVATION_TTL_SECS: u64 = 600;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DaySpend {
    pub date: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub reservations: Vec<ReservationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservationRecord {
    pub id: u64,
    pub amount: u64,
    pub at: u64,
}

/// A claim on today's remaining capacity. Settle it with actual usage (or
/// zero on failure); unsettled reservations expire after the TTL.
#[derive(Clone, Copy)]
pub struct Reservation {
    pub id: u64,
    pub amount: u64,
}

pub struct SpendLedger {
    path: PathBuf,
    lock_path: PathBuf,
}

/// Releases an inference reservation when a fallible run exits before it can
/// record actual usage. Explicit settlement disarms the guard.
pub struct ReservationGuard<'a> {
    ledger: &'a SpendLedger,
    reservation: Option<Reservation>,
}

impl<'a> ReservationGuard<'a> {
    pub fn new(ledger: &'a SpendLedger, reservation: Reservation) -> Self {
        Self {
            ledger,
            reservation: Some(reservation),
        }
    }

    pub fn release(&mut self) -> Result<(), crate::Error> {
        let Some(reservation) = self.reservation else {
            return Ok(());
        };
        self.ledger.settle(reservation, 0, 0)?;
        self.reservation = None;
        Ok(())
    }

    pub fn settle(
        &mut self,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<(DaySpend, bool), crate::Error> {
        let reservation = self.reservation.take().ok_or_else(|| {
            crate::Error::Budget("inference reservation was already settled".into())
        })?;
        self.ledger.settle(reservation, input_tokens, output_tokens)
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn utc_date_today() -> String {
    let days = now_secs() / 86_400;
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
            lock_path: agent_dir.join("spend.lock"),
        }
    }

    /// Run `f` with the ledger loaded under an exclusive lock; persist what
    /// it returns. This is the ONLY way state changes — check-then-act
    /// races are structurally impossible.
    fn with_locked<T>(
        &self,
        f: impl FnOnce(&mut DaySpend) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let mut lock_opts = std::fs::OpenOptions::new();
        lock_opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_opts.mode(0o600);
        }
        let lock = lock_opts.open(&self.lock_path)?;
        lock.lock_exclusive()
            .map_err(|e| crate::Error::Budget(format!("ledger lock: {e}")))?;
        let today = utc_date_today();
        let mut state: DaySpend = if self.path.exists() {
            let stored: DaySpend = serde_json::from_str(&std::fs::read_to_string(&self.path)?)?;
            if stored.date == today {
                stored
            } else {
                DaySpend {
                    date: today,
                    ..Default::default()
                }
            }
        } else {
            DaySpend {
                date: today,
                ..Default::default()
            }
        };
        // Expire stale reservations from crashed runs.
        let cutoff = now_secs().saturating_sub(RESERVATION_TTL_SECS);
        state.reservations.retain(|r| r.at > cutoff);
        let out = f(&mut state);
        if out.is_ok() {
            std::fs::write(&self.path, serde_json::to_string_pretty(&state)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
            }
        }
        let _ = fs2::FileExt::unlock(&lock);
        out
    }

    pub fn today(&self) -> Result<DaySpend, crate::Error> {
        let mut lock_opts = std::fs::OpenOptions::new();
        lock_opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_opts.mode(0o600);
        }
        let lock = lock_opts.open(&self.lock_path)?;
        lock.lock_shared()
            .map_err(|e| crate::Error::Budget(format!("ledger lock: {e}")))?;
        let today = utc_date_today();
        let mut state = if self.path.exists() {
            let stored: DaySpend = serde_json::from_str(&std::fs::read_to_string(&self.path)?)?;
            if stored.date == today {
                stored
            } else {
                DaySpend {
                    date: today,
                    ..Default::default()
                }
            }
        } else {
            DaySpend {
                date: today,
                ..Default::default()
            }
        };
        // Expiry affects the observed capacity immediately, but a status GET
        // is not a mutation. The next reserve/settle persists this projection.
        let cutoff = now_secs().saturating_sub(RESERVATION_TTL_SECS);
        state
            .reservations
            .retain(|reservation| reservation.at > cutoff);
        let _ = fs2::FileExt::unlock(&lock);
        Ok(state)
    }

    /// Atomically reserve remaining capacity for one run. With no cap the
    /// reservation is MAX_RESERVATION (bounded, not infinite). Refuses when
    /// nothing remains after counting used + already-reserved.
    pub fn reserve(&self, cap: Option<u64>) -> Result<Reservation, crate::Error> {
        self.reserve_up_to(cap, None)
    }

    /// Reserve with an additional per-run ceiling (a routine's
    /// tokens_per_run): the claim is min(remaining, MAX_RESERVATION, per_run).
    pub fn reserve_up_to(
        &self,
        cap: Option<u64>,
        per_run: Option<u64>,
    ) -> Result<Reservation, crate::Error> {
        self.with_locked(|s| {
            let used = s.input_tokens + s.output_tokens;
            let reserved: u64 = s.reservations.iter().map(|r| r.amount).sum();
            let remaining = match cap {
                Some(c) => c.saturating_sub(used + reserved),
                None => MAX_RESERVATION,
            };
            let remaining = match per_run {
                Some(p) => remaining.min(p.max(1)),
                None => remaining,
            };
            if remaining == 0 {
                return Err(crate::Error::Budget(format!(
                    "daily token budget exhausted ({} used + {} reserved / {:?} cap); \
                     a human raises the floor, not the agent",
                    used, reserved, cap
                )));
            }
            let amount = remaining.min(MAX_RESERVATION);
            let id = now_secs() ^ (amount << 20) ^ s.reservations.len() as u64;
            s.reservations.push(ReservationRecord {
                id,
                amount,
                at: now_secs(),
            });
            Ok(Reservation { id, amount })
        })
    }

    /// Settle a reservation with actual usage (zero on failure is fine).
    /// Returns the day plus an OVERRUN flag when real usage exceeded the
    /// reservation — always recorded (the ledger is truth, and the API
    /// call already happened); callers surface it in the signed log, and
    /// the shortfall reduces the next reservation automatically.
    pub fn settle(
        &self,
        reservation: Reservation,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<(DaySpend, bool), crate::Error> {
        let overran = input_tokens + output_tokens > reservation.amount;
        let day = self.with_locked(move |s| {
            s.reservations.retain(|r| r.id != reservation.id);
            s.input_tokens += input_tokens;
            s.output_tokens += output_tokens;
            Ok(DaySpend {
                date: s.date.clone(),
                input_tokens: s.input_tokens,
                output_tokens: s.output_tokens,
                reservations: s.reservations.clone(),
            })
        })?;
        Ok((day, overran))
    }
}

/// Read and VALIDATE the tokens/day cap: a malformed value is an error, not
/// silently "no cap" (fail closed on governance config).
pub fn tokens_per_day(
    budgets: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<Option<u64>, crate::Error> {
    match budgets
        .get("tokens_per_day")
        .or_else(|| budgets.get("tokens/day"))
    {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| {
            crate::Error::Budget(format!(
                "governance.budgets tokens_per_day must be a non-negative integer, got {v}"
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(tag: &str) -> (SpendLedger, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("apiary-spend-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        (SpendLedger::open(&dir), dir)
    }

    #[test]
    fn reservation_is_a_hard_ceiling() {
        let (l, dir) = ledger("ceiling");
        // Cap 100: first reservation claims all of it…
        let r1 = l.reserve(Some(100)).unwrap();
        assert_eq!(r1.amount, 100);
        // …so a concurrent second run is refused BEFORE any inference.
        assert!(l.reserve(Some(100)).is_err());
        // Settle with actual usage below the reservation; remainder frees up.
        l.settle(r1, 30, 30).unwrap();
        let r2 = l.reserve(Some(100)).unwrap();
        assert_eq!(r2.amount, 40);
        l.settle(r2, 40, 0).unwrap();
        assert!(l.reserve(Some(100)).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dropped_guard_releases_capacity() {
        let (ledger, dir) = ledger("guard");
        {
            let reservation = ledger.reserve(Some(100)).unwrap();
            let _guard = ReservationGuard::new(&ledger, reservation);
            assert!(ledger.reserve(Some(100)).is_err());
        }
        assert_eq!(ledger.reserve(Some(100)).unwrap().amount, 100);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_cap_is_bounded_not_infinite() {
        let (l, dir) = ledger("nocap");
        let r = l.reserve(None).unwrap();
        assert_eq!(r.amount, MAX_RESERVATION);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_budget_fails_closed() {
        let mut b = std::collections::BTreeMap::new();
        b.insert("tokens_per_day".to_string(), serde_json::json!("lots"));
        assert!(tokens_per_day(&b).is_err());
        b.insert("tokens_per_day".to_string(), serde_json::json!(-5));
        assert!(tokens_per_day(&b).is_err());
        b.insert("tokens_per_day".to_string(), serde_json::json!(1000));
        assert_eq!(tokens_per_day(&b).unwrap(), Some(1000));
    }

    #[test]
    fn date_format_sane() {
        let d = utc_date_today();
        assert_eq!(d.len(), 10);
        assert!(d.starts_with("20"));
    }
}
