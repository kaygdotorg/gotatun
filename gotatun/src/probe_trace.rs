// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Per-stage timestamps for latency probe packets (profiling builds only, #260 J88h).
//!
//! This module exists to answer one question: when an ICMP echo probe sits in the loaded p99
//! tail, which stage of the packet path holds it? It is compiled only with the `probe-trace`
//! cargo feature and records only when the `GOTATUN_PROBE_TRACE` environment variable names an
//! output path prefix at start. No shipping build enables the feature.
//!
//! # What is recorded
//! An ICMP or ICMPv6 echo request or reply is a *probe*. At each stage, the code calls
//! [`record_ip`] with the plaintext packet, or [`record_wg`] with a WireGuard data message.
//! For a probe, that writes one 32-byte [`Stage`] record: `CLOCK_MONOTONIC` nanoseconds, the
//! probe key (echo type, identifier, sequence), the stage, the CPU, the thread id and a free
//! `extra` word (batch size and position, or the WireGuard counter). Every other packet costs
//! one relaxed load of the enabled flag plus a few header byte compares.
//!
//! After encryption, a probe is known only by its WireGuard counter. [`arm_wg`] parks
//! `(counter, key)` in a small table. The UDP send worker then checks a batch against that table
//! only while something is armed ([`armed`]), so it pays nothing between probes.
//!
//! # Output
//! Records go into one preallocated buffer, shared by all threads and indexed by a global atomic
//! counter. Only probe packets touch it, a few thousand times a second, so the counter is never
//! contended. A background thread appends finished records to `<prefix>.<pid>.bin` every 200 ms,
//! after a 32-byte header holding the realtime and monotonic clocks, so offline tools can line
//! the records up with `ping -D`. A record is published by storing its timestamp last, with
//! `Release`. The flusher stops at the first unpublished slot and resumes there next time.
//! When the buffer is full, recording stops and the overflow is counted in the file's trailer
//! records (stage [`Stage::Overflow`]).
//!
//! The record layout is `[ts_ns, key, stage | cpu << 8 | tid << 32, extra]`, little-endian u64s.

use std::{
    fs::File,
    io::Write,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

/// The packet path stages a probe can be timestamped at. The numbers are the on-disk codes;
/// the stages that belong to the integration (TUN device reads and writes) are recorded by the
/// embedding application through the same functions.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// The application's TUN reader decoded the frame holding the probe.
    TunRead = 1,
    /// The TUN reader's channel send into the buffer before encryption returned.
    BufIn = 2,
    /// The encryption task took the probe out of that buffer. `extra` = batch size << 32 | index.
    BufOut = 3,
    /// Encryption finished. `extra` = WireGuard counter.
    EncDone = 4,
    /// The channel send into the UDP send worker returned.
    UdpQueueIn = 5,
    /// The UDP send worker took the probe's batch. `extra` = batch size << 32 | index.
    UdpDequeue = 6,
    /// The `sendmmsg`/`sendmsg` holding the probe returned.
    UdpSent = 7,
    /// The `recvmmsg` batch that held the probe returned (timestamp of the batch).
    /// `extra` = batch size << 32 | index.
    UdpRecv = 8,
    /// Decryption finished and the plaintext was accepted.
    DecDone = 9,
    /// The channel send into the TUN send task returned.
    TunQueueIn = 10,
    /// The TUN send task took the probe.
    TunQueueOut = 11,
    /// The application's TUN writer queue accepted the probe.
    WriterQueueIn = 12,
    /// The application's TUN writer took the probe's batch. `extra` = batch size << 32 | index.
    WriterQueueOut = 13,
    /// The TUN `write` holding the probe returned.
    TunWritten = 14,
    /// Trailer: `extra` = records dropped because the buffer was full.
    Overflow = 255,
}

/// Records kept per process: 2^18 × 32 bytes = 8 MiB, written once at start, so a traced
/// process's RSS is 8 MiB higher. That is enough for about 109 s of 200 probes/s at 12 stages
/// each, more than the R4b hold's two 9 s ping phases per case.
const CAPACITY: usize = 1 << 18;
/// Probes that may be armed between encryption and the UDP send at the same time.
const ARMED_SLOTS: usize = 32;

struct Tracer {
    /// Four words per record; see the module docs for the layout.
    slots: Box<[AtomicU64]>,
    next: AtomicUsize,
    dropped: AtomicU64,
    /// WireGuard counter + 1 (0 = free) and the probe key, per armed slot.
    armed_counter: [AtomicU64; ARMED_SLOTS],
    armed_key: [AtomicU64; ARMED_SLOTS],
    armed_count: AtomicUsize,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static TRACER: OnceLock<Tracer> = OnceLock::new();

thread_local! {
    // SAFETY: gettid has no preconditions and cannot fail.
    static TID: u32 = unsafe { libc::gettid() } as u32;
}

/// Turn the tracer on if `GOTATUN_PROBE_TRACE` is set. Call once at start; later calls do
/// nothing. Without the variable, every record call returns after one relaxed load.
pub fn init_from_env() {
    let Some(prefix) = std::env::var_os("GOTATUN_PROBE_TRACE") else {
        return;
    };
    if TRACER.get().is_some() {
        return;
    }
    let slots: Vec<AtomicU64> = (0..CAPACITY * 4).map(|_| AtomicU64::new(0)).collect();
    let tracer = Tracer {
        slots: slots.into_boxed_slice(),
        next: AtomicUsize::new(0),
        dropped: AtomicU64::new(0),
        armed_counter: std::array::from_fn(|_| AtomicU64::new(0)),
        armed_key: std::array::from_fn(|_| AtomicU64::new(0)),
        armed_count: AtomicUsize::new(0),
    };
    if TRACER.set(tracer).is_err() {
        return;
    }
    let path = format!("{}.{}.bin", prefix.to_string_lossy(), std::process::id());
    let Ok(file) = File::create(&path) else {
        return;
    };
    ENABLED.store(true, Ordering::Release);
    std::thread::Builder::new()
        .name("gotatun-probe-flush".into())
        .spawn(move || flush_forever(file))
        .ok();
}

/// Whether probe records are being kept.
#[inline(always)]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// `CLOCK_MONOTONIC` in nanoseconds, the clock every record uses.
#[inline]
pub fn now_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The probe key of an IP packet, if it is an ICMP(v6) echo request or reply:
/// `type << 32 | identifier << 16 | sequence`, with the ICMPv6 types mapped to the ICMP ones.
#[inline]
pub fn probe_key(ip: &[u8]) -> Option<u64> {
    let first = *ip.first()?;
    let (proto, header_len) = match first >> 4 {
        4 => (*ip.get(9)?, usize::from(first & 0x0f) * 4),
        6 => (*ip.get(6)?, 40),
        _ => return None,
    };
    let kind = match (proto, *ip.get(header_len)?) {
        (1, 8) | (58, 128) => 8u64,
        (1, 0) | (58, 129) => 0u64,
        _ => return None,
    };
    let id = u16::from_be_bytes([*ip.get(header_len + 4)?, *ip.get(header_len + 5)?]);
    let seq = u16::from_be_bytes([*ip.get(header_len + 6)?, *ip.get(header_len + 7)?]);
    Some(kind << 32 | u64::from(id) << 16 | u64::from(seq))
}

/// The counter of a WireGuard data message (type 4), the probe's identity after encryption.
#[inline]
pub fn wg_counter(message: &[u8]) -> Option<u64> {
    if message.len() < 16 || message[0] != 4 {
        return None;
    }
    Some(u64::from_le_bytes(message[8..16].try_into().ok()?))
}

/// Record `stage` at `ts` for an IP packet if it is a probe. Returns the probe key, so a caller
/// can arm the encrypted message or record a later stage without parsing again.
#[inline]
pub fn record_ip(stage: Stage, ip: &[u8], ts: u64, extra: u64) -> Option<u64> {
    if !enabled() {
        return None;
    }
    let key = probe_key(ip)?;
    record(stage, key, ts, extra);
    Some(key)
}

/// [`record_ip`] for a typed IP packet, so an embedding application needs no byte-view import.
#[inline]
pub fn record_ip_packet(
    stage: Stage,
    packet: &crate::packet::Packet<crate::packet::Ip>,
    ts: u64,
    extra: u64,
) -> Option<u64> {
    if !enabled() {
        return None;
    }
    record_ip(stage, zerocopy::IntoBytes::as_bytes(&**packet), ts, extra)
}

/// Record `stage` for a probe already identified by `key`.
pub fn record(stage: Stage, key: u64, ts: u64, extra: u64) {
    let Some(tracer) = TRACER.get() else { return };
    let index = tracer.next.fetch_add(1, Ordering::Relaxed);
    if index >= CAPACITY {
        tracer.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // SAFETY: sched_getcpu has no preconditions.
    let cpu = unsafe { libc::sched_getcpu() }.max(0) as u64 & 0xff_ffff;
    let tid = TID.with(|t| u64::from(*t));
    let base = index * 4;
    let s = &tracer.slots;
    s[base + 1].store(key, Ordering::Relaxed);
    s[base + 2].store(stage as u64 | cpu << 8 | tid << 32, Ordering::Relaxed);
    s[base + 3].store(extra, Ordering::Relaxed);
    // Published last: the flusher reads a slot only once its timestamp is non-zero.
    s[base].store(ts.max(1), Ordering::Release);
}

/// Remember that the WireGuard data message with `counter` carries probe `key`, so the UDP send
/// worker can find it.
pub fn arm_wg(counter: u64, key: u64) {
    let Some(tracer) = TRACER.get() else { return };
    for i in 0..ARMED_SLOTS {
        if tracer.armed_counter[i]
            .compare_exchange(0, counter + 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            tracer.armed_key[i].store(key, Ordering::Release);
            tracer.armed_count.fetch_add(1, Ordering::Release);
            return;
        }
    }
    tracer.dropped.fetch_add(1, Ordering::Relaxed);
}

/// Whether any probe waits between encryption and the UDP send. The UDP worker checks its
/// batch only when this is true.
#[inline(always)]
pub fn armed() -> bool {
    enabled() && TRACER.get().is_some_and(|t| t.armed_count.load(Ordering::Acquire) != 0)
}

/// The probe key of an encrypted message, if it was armed. With `take`, the slot is freed.
pub fn armed_key(message: &[u8], take: bool) -> Option<u64> {
    let tracer = TRACER.get()?;
    let wanted = wg_counter(message)? + 1;
    for i in 0..ARMED_SLOTS {
        if tracer.armed_counter[i].load(Ordering::Acquire) == wanted {
            let key = tracer.armed_key[i].load(Ordering::Acquire);
            if take {
                tracer.armed_counter[i].store(0, Ordering::Release);
                tracer.armed_count.fetch_sub(1, Ordering::AcqRel);
            }
            return Some(key);
        }
    }
    None
}

/// `size << 32 | index`, the `extra` word for a probe's position in a batch.
#[inline]
pub fn batch_pos(size: usize, index: usize) -> u64 {
    (size as u64) << 32 | index as u64 & 0xffff_ffff
}

fn header() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
    out[8..16].copy_from_slice(&clock_ns(libc::CLOCK_REALTIME).to_le_bytes());
    out[16..24].copy_from_slice(&now_ns().to_le_bytes());
    out[24..32].copy_from_slice(&u64::from(std::process::id()).to_le_bytes());
    out
}

/// Append published records to `file` forever. A record whose first word is `u64::MAX` is a
/// clock header: `[MAX, realtime_ns, monotonic_ns, pid]`.
fn flush_forever(mut file: File) {
    let Some(tracer) = TRACER.get() else { return };
    let mut done = 0usize;
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut last_dropped = 0;
    loop {
        buf.clear();
        buf.extend_from_slice(&header());
        let end = tracer.next.load(Ordering::Acquire).min(CAPACITY);
        while done < end {
            let base = done * 4;
            let ts = tracer.slots[base].load(Ordering::Acquire);
            if ts == 0 {
                break;
            }
            for w in 0..4 {
                let v = if w == 0 {
                    ts
                } else {
                    tracer.slots[base + w].load(Ordering::Relaxed)
                };
                buf.extend_from_slice(&v.to_le_bytes());
            }
            done += 1;
        }
        let dropped = tracer.dropped.load(Ordering::Relaxed);
        if dropped != last_dropped {
            last_dropped = dropped;
            for v in [now_ns(), 0, Stage::Overflow as u64, dropped] {
                buf.extend_from_slice(&v.to_le_bytes());
            }
        }
        if file.write_all(&buf).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn icmp4(kind: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut p = vec![0u8; 84];
        p[0] = 0x45;
        p[9] = 1;
        p[20] = kind;
        p[24..26].copy_from_slice(&id.to_be_bytes());
        p[26..28].copy_from_slice(&seq.to_be_bytes());
        p
    }

    /// Echo requests and replies are probes, keyed by type, identifier and sequence; TCP is not.
    #[test]
    fn probe_key_matches_only_echo() {
        assert_eq!(probe_key(&icmp4(8, 7, 9)), Some(8 << 32 | 7 << 16 | 9));
        assert_eq!(probe_key(&icmp4(0, 7, 9)), Some(7 << 16 | 9));
        assert_eq!(probe_key(&icmp4(3, 7, 9)), None);
        let mut tcp = icmp4(8, 7, 9);
        tcp[9] = 6;
        assert_eq!(probe_key(&tcp), None);
        assert_eq!(probe_key(&[0x45, 0, 0]), None);
    }

    /// The counter is read from bytes 8..16 of a type-4 message only.
    #[test]
    fn wg_counter_reads_data_messages() {
        let mut m = vec![0u8; 32];
        m[0] = 4;
        m[8..16].copy_from_slice(&42u64.to_le_bytes());
        assert_eq!(wg_counter(&m), Some(42));
        m[0] = 1;
        assert_eq!(wg_counter(&m), None);
    }
}
