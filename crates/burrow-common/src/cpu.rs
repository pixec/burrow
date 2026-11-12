//! A sandbox's host CPU and IO limits, with Docker's names and units.
//!
//! `vcpus` is the CPUs the guest sees. `cpus` is `docker run --cpus`: a hard
//! cap on host CPU time, and what placement and admission charge a node when
//! it is set, so two vCPUs capped at half a CPU take half a CPU of the node.
//! `reserved_cpus` is Compose's `deploy.resources.reservations.cpus` and
//! Swarm's `--reserve-cpu`: what a node is charged in place of the cap, and
//! what the sandbox weighs under contention, so it can burst past it up to
//! the cap, or to its vCPUs without one.
//! `cpu_shares` is `--cpu-shares`, a weight that only matters under
//! contention; `cpuset_cpus` is `--cpuset-cpus`; `blkio_weight` is
//! `--blkio-weight`. The cgroup v2 conversions are runc's, so a value means
//! what it means to Docker.

/// Docker's `--cpu-shares` default, and what one charged CPU weighs when a
/// sandbox names no shares.
pub const DEFAULT_CPU_SHARES: u64 = 1024;
const MIN_CPU_SHARES: u32 = 2;
const MAX_CPU_SHARES: u32 = 262_144;
const MIN_BLKIO_WEIGHT: u32 = 10;
const MAX_BLKIO_WEIGHT: u32 = 1000;

/// A cap in CPUs as thousandths of a CPU, 0 for none.
pub fn cap_millis(cpus: f64) -> u64 {
    if cpus > 0.0 {
        (cpus * 1000.0).round() as u64
    } else {
        0
    }
}

/// The host CPU a node is charged for a sandbox, in thousandths of a CPU:
/// its reservation when it has one, otherwise its cap, otherwise every vCPU.
pub fn charge_millis(vcpus: u32, cap_millis: u64, reserve_millis: u64) -> u64 {
    match (reserve_millis, cap_millis) {
        (0, 0) => u64::from(vcpus.max(1)) * 1000,
        (0, cap) => cap,
        (reserve, _) => reserve,
    }
}

/// Thousandths of a CPU as CPUs, for a message: 2000 is "2", 500 is "0.5".
pub fn cpus_text(millis: u64) -> String {
    let text = format!("{:.3}", millis as f64 / 1000.0);
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// The shares a sandbox weighs: its own, or Docker's default for each CPU it
/// is charged, so what placement promised is what contention honours.
pub fn shares(cpu_shares: u32, charge_millis: u64) -> u64 {
    match cpu_shares {
        0 => (DEFAULT_CPU_SHARES * charge_millis / 1000).max(u64::from(MIN_CPU_SHARES)),
        shares => u64::from(shares),
    }
}

/// `cpu.weight` for Docker shares, as runc converts them.
pub fn shares_to_weight(shares: u64) -> u64 {
    let shares = shares.clamp(u64::from(MIN_CPU_SHARES), u64::from(MAX_CPU_SHARES));
    1 + ((shares - 2) * 9999) / 262_142
}

/// `io.weight` for a Docker blkio weight, as runc converts it.
pub fn blkio_to_io_weight(weight: u32) -> u64 {
    1 + (u64::from(weight) - 10) * 9999 / 990
}

/// The host CPUs a Docker cpuset list such as `0-3,6` names, in order.
pub fn parse_cpuset(list: &str) -> Result<Vec<u32>, String> {
    let mut cpus = Vec::new();
    for part in list.split(',') {
        let bad = || format!("cpuset_cpus {list:?} is not a list like \"0-3,6\"");
        let (first, last) = match part.split_once('-') {
            Some((first, last)) => (first, last),
            None => (part, part),
        };
        let first: u32 = first.trim().parse().map_err(|_| bad())?;
        let last: u32 = last.trim().parse().map_err(|_| bad())?;
        if first > last {
            return Err(bad());
        }
        cpus.extend(first..=last);
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

/// Checks the limits a sandbox asks for against its vCPUs and, where known,
/// the node's CPU count.
pub fn validate(
    vcpus: u32,
    cpus: f64,
    reserved_cpus: f64,
    cpu_shares: u32,
    cpuset_cpus: &str,
    blkio_weight: u32,
    node_cpus: Option<u32>,
) -> Result<(), String> {
    let vcpus = vcpus.max(1);
    if !cpus.is_finite() || cpus < 0.0 {
        return Err(format!(
            "cpus {cpus} must be a number of CPUs, 0 for no cap"
        ));
    }
    if cpus > 0.0 && cpus < 0.01 {
        return Err(format!("cpus {cpus} is below the smallest cap, 0.01"));
    }
    if cpus > f64::from(vcpus) {
        return Err(format!(
            "cpus {cpus} is more than the sandbox's {vcpus} vcpus; a guest cannot use more"
        ));
    }
    if !reserved_cpus.is_finite() || reserved_cpus < 0.0 {
        return Err(format!(
            "reserved_cpus {reserved_cpus} must be a number of CPUs, 0 for no reservation"
        ));
    }
    if reserved_cpus > 0.0 && reserved_cpus < 0.01 {
        return Err(format!(
            "reserved_cpus {reserved_cpus} is below the smallest reservation, 0.01"
        ));
    }
    if cpus > 0.0 && reserved_cpus > cpus {
        return Err(format!(
            "reserved_cpus {reserved_cpus} is more than the cap of {cpus} cpus; a sandbox \
             cannot be promised more than it may use"
        ));
    }
    if reserved_cpus > f64::from(vcpus) {
        return Err(format!(
            "reserved_cpus {reserved_cpus} is more than the sandbox's {vcpus} vcpus; a guest \
             cannot use more"
        ));
    }
    if cpu_shares != 0 && !(MIN_CPU_SHARES..=MAX_CPU_SHARES).contains(&cpu_shares) {
        return Err(format!(
            "cpu_shares {cpu_shares} out of range ({MIN_CPU_SHARES}..={MAX_CPU_SHARES}; 0 for the default)"
        ));
    }
    if blkio_weight != 0 && !(MIN_BLKIO_WEIGHT..=MAX_BLKIO_WEIGHT).contains(&blkio_weight) {
        return Err(format!(
            "blkio_weight {blkio_weight} out of range ({MIN_BLKIO_WEIGHT}..={MAX_BLKIO_WEIGHT}; 0 for none)"
        ));
    }
    if !cpuset_cpus.is_empty() {
        let set = parse_cpuset(cpuset_cpus)?;
        if let (Some(node_cpus), Some(&last)) = (node_cpus, set.last())
            && last >= node_cpus
        {
            return Err(format!(
                "cpuset_cpus {cpuset_cpus:?} names CPU {last}, and the node has CPUs 0-{}",
                node_cpus - 1
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_then_a_cap_is_charged_and_otherwise_every_vcpu_is() {
        assert_eq!(charge_millis(2, cap_millis(0.5), 0), 500);
        assert_eq!(charge_millis(2, cap_millis(0.0), 0), 2000);
        assert_eq!(charge_millis(0, 0, 0), 1000);
        assert_eq!(charge_millis(8, 0, cap_millis(4.0)), 4000);
        assert_eq!(charge_millis(8, cap_millis(6.0), cap_millis(4.0)), 4000);
        assert_eq!(cap_millis(0.3), 300);
        assert_eq!(cap_millis(1.5), 1500);
    }

    #[test]
    fn cpus_read_as_docker_writes_them() {
        assert_eq!(cpus_text(2000), "2");
        assert_eq!(cpus_text(500), "0.5");
        assert_eq!(cpus_text(1250), "1.25");
    }

    /// The figures runc and Docker produce for the same flags.
    #[test]
    fn conversions_match_runc() {
        assert_eq!(shares_to_weight(1024), 39);
        assert_eq!(shares_to_weight(2), 1);
        assert_eq!(shares_to_weight(262_144), 10_000);
        assert_eq!(blkio_to_io_weight(10), 1);
        assert_eq!(blkio_to_io_weight(500), 4950);
        assert_eq!(blkio_to_io_weight(1000), 10_000);
    }

    #[test]
    fn unset_shares_follow_the_charge() {
        assert_eq!(shares(0, 2000), 2048);
        assert_eq!(shares(0, 500), 512);
        assert_eq!(shares(0, 1), 2);
        assert_eq!(shares(300, 2000), 300);
    }

    #[test]
    fn cpusets_parse_like_docker() {
        assert_eq!(parse_cpuset("0-3,6").unwrap(), vec![0, 1, 2, 3, 6]);
        assert_eq!(parse_cpuset("2").unwrap(), vec![2]);
        assert!(parse_cpuset("3-1").is_err());
        assert!(parse_cpuset("a").is_err());
        assert!(parse_cpuset("").is_err());
    }

    #[test]
    fn limits_are_held_to_the_vcpus_and_the_node() {
        assert!(validate(2, 0.5, 0.0, 0, "", 0, None).is_ok());
        assert!(validate(2, 2.5, 0.0, 0, "", 0, None).is_err());
        assert!(validate(2, f64::NAN, 0.0, 0, "", 0, None).is_err());
        assert!(validate(2, -1.0, 0.0, 0, "", 0, None).is_err());
        assert!(validate(2, 0.0, 0.0, 1, "", 0, None).is_err());
        assert!(validate(2, 0.0, 0.0, 0, "", 5, None).is_err());
        assert!(validate(2, 0.0, 0.0, 0, "0-3", 0, Some(4)).is_ok());
        assert!(validate(2, 0.0, 0.0, 0, "0-4", 0, Some(4)).is_err());
    }

    /// 0.01 <= reserved_cpus <= cpus, where set, <= vcpus.
    #[test]
    fn a_reservation_sits_under_the_cap_and_the_vcpus() {
        assert!(validate(8, 0.0, 4.0, 0, "", 0, None).is_ok());
        assert!(validate(8, 6.0, 4.0, 0, "", 0, None).is_ok());
        assert!(validate(8, 4.0, 4.0, 0, "", 0, None).is_ok());
        assert!(validate(8, 3.0, 4.0, 0, "", 0, None).is_err());
        assert!(validate(2, 0.0, 4.0, 0, "", 0, None).is_err());
        assert!(validate(2, 0.0, 0.001, 0, "", 0, None).is_err());
        assert!(validate(2, 0.0, -1.0, 0, "", 0, None).is_err());
    }
}
