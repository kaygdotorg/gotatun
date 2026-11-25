//! The hasher behind every per-packet hash table (#260, D345).
//!
//! The tables a packet touches on the way through the device (receiver index to peer, peer-cell
//! set, per-batch runs, the side socket's recency map) used to hash with std's SipHash. That is
//! sound but costs about 50 ns per received packet more than needed. [`PacketHash`] is
//! `foldhash::fast::RandomState`: every table that uses it gets its own random seed, drawn once
//! per process, so a remote peer cannot precompute keys that collide.
//!
//! Rule for new tables: any map or set whose keys a peer can choose (receiver indices arrive in
//! handshakes, endpoints in roaming) must use a seeded hasher like this one, never an unkeyed
//! one (`FxHasher`, identity). foldhash is "minimally DoS-resistant": it defeats offline
//! precomputation, not an attacker who can observe outputs; the tables here are bounded, so the
//! worst case is a slower lookup in the attacker's own peer, not unbounded memory.
//!
//! Use it as `HashMap<K, V, PacketHash>` and build it with `HashMap::default()`.

/// Seeded fast hasher state for per-packet tables; see the module docs for when it is required.
pub(crate) type PacketHash = foldhash::fast::RandomState;

#[cfg(test)]
mod tests {
    use super::PacketHash;
    use std::hash::BuildHasher;

    /// Two tables must not share a seed: the same key hashes differently under independently
    /// built states, so one table's layout reveals nothing about another's. (Probability of a
    /// false failure over 64 keys is negligible.)
    #[test]
    fn independent_states_are_seeded_differently() {
        let (a, b) = (PacketHash::default(), PacketHash::default());
        assert!((0u32..64).any(|k| a.hash_one(k) != b.hash_one(k)));
    }
}
