//! The rule a root filesystem shrinks by, the same for ext4 and APFS.

const MIB: u64 = 1 << 20;

/// What the least a filesystem needing `estimate` bytes may shrink to: a
/// tenth more, at least 128 MiB more, so it is not full the moment it boots.
pub fn minimum(estimate: u64) -> u64 {
    (estimate + (estimate / 10).max(128 * MIB)).div_ceil(MIB) * MIB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_minimum_leaves_room_and_lands_on_a_mib() {
        assert_eq!(minimum(100 * MIB), 228 * MIB);
        assert_eq!(minimum(10_000 * MIB), 11_000 * MIB);
        assert_eq!(minimum(10_000 * MIB + 1) % MIB, 0);
    }
}
