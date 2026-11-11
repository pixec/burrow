//! Keeping the guest's wall clock on the host's between handshakes.
//!
//! A step is taken only past a threshold, and a larger one while a time
//! daemon in the guest keeps the clock synchronised: small errors are the
//! daemon's to slew away, and stepping under it would only argue with it.
//! Past the larger one, one of the two clocks missed a sleep, and a daemon
//! that slews would take days to make that up. A step marks the kernel clock
//! unsynchronised, so the daemon starts again from the host's time rather
//! than undoing it.

use tonic::Status;

use burrow_proto::guest::v1 as guestpb;

use crate::os;

const STEP_THRESHOLD_NANOS: i64 = 1_000_000_000;
const DISCIPLINED_STEP_THRESHOLD_NANOS: i64 = 60 * 1_000_000_000;

fn needs_step(offset_nanos: i64, is_disciplined: bool) -> bool {
    let threshold = match is_disciplined {
        true => DISCIPLINED_STEP_THRESHOLD_NANOS,
        false => STEP_THRESHOLD_NANOS,
    };
    offset_nanos.unsigned_abs() > threshold as u64
}

fn unix_nanos_now() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => since.as_nanos() as i64,
        Err(before) => -(before.duration().as_nanos() as i64),
    }
}

#[allow(clippy::result_large_err)]
pub fn sync(req: guestpb::SyncClockRequest) -> Result<guestpb::SyncClockResponse, Status> {
    if req.host_time_unix_nanos <= 0 {
        return Err(Status::invalid_argument("no host time"));
    }
    let arrived = std::time::Instant::now();
    let offset_nanos = unix_nanos_now().saturating_sub(req.host_time_unix_nanos);
    let is_disciplined = os::is_clock_disciplined();
    let is_stepped = needs_step(offset_nanos, is_disciplined);
    if is_stepped {
        let target = req.host_time_unix_nanos + arrived.elapsed().as_nanos() as i64;
        os::set_clock(target)
            .map_err(|err| Status::internal(format!("setting the clock: {err}")))?;
        tracing::info!(
            offset_ms = offset_nanos / 1_000_000,
            is_disciplined,
            "guest clock had drifted from the host's; stepped it"
        );
    }
    Ok(guestpb::SyncClockResponse {
        offset_nanos,
        is_stepped,
        is_disciplined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_only_past_the_threshold() {
        assert!(!needs_step(0, false));
        assert!(!needs_step(STEP_THRESHOLD_NANOS, false));
        assert!(needs_step(STEP_THRESHOLD_NANOS + 1, false));
        assert!(needs_step(-STEP_THRESHOLD_NANOS - 1, false));
        assert!(needs_step(-3 * 86_400 * 1_000_000_000, false));
    }

    #[test]
    fn leaves_a_disciplined_clock_its_small_errors() {
        assert!(!needs_step(5 * 1_000_000_000, true));
        assert!(!needs_step(-DISCIPLINED_STEP_THRESHOLD_NANOS, true));
        assert!(needs_step(DISCIPLINED_STEP_THRESHOLD_NANOS + 1, true));
        assert!(needs_step(-3 * 86_400 * 1_000_000_000, true));
    }

    #[test]
    fn extreme_offsets_do_not_overflow() {
        assert!(needs_step(i64::MIN, false));
        assert!(needs_step(i64::MAX, true));
    }
}
