// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Shared packet storage with small and full-size buffers under one retention limit.

use bytes::BytesMut;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crate::packet::Packet;

/// A pool of packet buffers.
#[derive(Clone)]
pub struct PacketBufPool<const N: usize = 4096> {
    queue: Arc<Mutex<PoolQueue>>,
    capacity: usize,
}

/// Buffers waiting for re-use, plus the use count the idle release reads.
///
/// All of it sits behind the mutex that every `get` and every returned buffer already take,
/// so counting use adds no extra synchronisation to the packet path.
struct PoolQueue {
    /// Full-size buffers, also usable by small packets when already available.
    buffers: VecDeque<BytesMut>,
    /// Half-size buffers for known packet lengths that fit below the full receive size.
    small_buffers: VecDeque<BytesMut>,
    /// Most buffers both queues retain in total. Stored, not read from deque capacity, because
    /// an idle release frees the deque's storage too.
    capacity: usize,
    /// Buffers taken since the last [`PacketBufPool::take_count`]. Read only by `device`.
    #[cfg_attr(not(feature = "device"), allow(dead_code))]
    taken: u32,
}

impl<const N: usize> PacketBufPool<N> {
    /// Create a new [`PacketBufPool`] with space for at least `capacity` packets,
    /// each allocated with a capacity of `N` bytes.
    pub fn new(capacity: usize) -> Self {
        let mut buffers = VecDeque::with_capacity(capacity);

        // pre-allocate buffers
        for _ in 0..capacity {
            buffers.push_back(BytesMut::zeroed(N).split_to(0));
        }

        Self::from_buffers(buffers, capacity)
    }

    /// Create an empty [`PacketBufPool`] with space for at least `capacity` returned buffers.
    #[cfg(feature = "device")]
    pub(crate) fn new_lazy(capacity: usize) -> Self {
        Self::from_buffers(VecDeque::new(), capacity)
    }

    fn from_buffers(buffers: VecDeque<BytesMut>, capacity: usize) -> Self {
        PacketBufPool {
            queue: Arc::new(Mutex::new(PoolQueue {
                buffers,
                small_buffers: VecDeque::new(),
                capacity,
                taken: 0,
            })),
            capacity,
        }
    }

    /// Get the configured capacity of this pool.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of buffers taken from the pool since the previous call (saturating).
    #[cfg(feature = "device")]
    pub(crate) fn take_count(&self) -> u32 {
        std::mem::take(&mut self.queue.lock().unwrap().taken)
    }

    /// Free every retained buffer, including the queue's own storage.
    ///
    /// Buffers still in flight return to the pool as usual afterwards, so the pool keeps
    /// working and refills on demand.
    #[cfg(feature = "device")]
    pub(crate) fn release(&self) {
        let released = {
            let mut queue = self.queue.lock().unwrap();
            (
                std::mem::take(&mut queue.buffers),
                std::mem::take(&mut queue.small_buffers),
            )
        };
        // Free outside the lock; a packet arriving now must not wait on thousands of frees.
        drop(released);
    }

    #[cfg(all(test, feature = "device"))]
    fn retained(&self) -> usize {
        let queue = self.queue.lock().unwrap();
        queue.buffers.len() + queue.small_buffers.len()
    }

    /// Reuse a buffer in the requested class, falling back to existing full-size storage.
    fn re_use(&self, prefer_small: bool) -> Option<Packet<[u8]>> {
        while let Some((mut pointer_to_start_of_allocation, small)) = {
            let mut queue = self.queue.lock().unwrap();
            queue.taken = queue.taken.saturating_add(1);
            if prefer_small {
                queue
                    .small_buffers
                    .pop_front()
                    .map(|buffer| (buffer, true))
                    .or_else(|| queue.buffers.pop_front().map(|buffer| (buffer, false)))
            } else {
                queue.buffers.pop_front().map(|buffer| (buffer, false))
            }
        } {
            let buffer_len = if small { N / 2 } else { N };
            debug_assert_eq!(pointer_to_start_of_allocation.len(), 0);
            if pointer_to_start_of_allocation.try_reclaim(buffer_len) {
                let mut buf = pointer_to_start_of_allocation.split_off(0);

                debug_assert!(buf.capacity() >= buffer_len);

                // SAFETY:
                // - buf was split from the BytesMut allocated below.
                // - buf has not been mutated, and still points to the original allocation.
                // - try_reclaim succeeded, so capacity covers this buffer's original size.
                // - the allocation was created using `BytesMut::zeroed`, so the bytes are
                //   initialized. The immutable size-class tag stays with its start pointer,
                //   even if the packet grows and moves its payload to another allocation.
                unsafe { buf.set_len(buffer_len) };

                let return_to_pool = ReturnToPool {
                    pointer_to_start_of_allocation: Some(pointer_to_start_of_allocation),
                    queue: self.queue.clone(),
                    small,
                };

                return Some(Packet::new_from_pool(return_to_pool, buf));
            } else {
                // Backing buffer is still in use. Someone probably called split_* on it.
                continue;
            }
        }

        None
    }

    /// Get a new [`Packet`] from the pool.
    ///
    /// This will try to re-use an already allocated packet if possible, or allocate one otherwise.
    pub fn get(&self) -> Packet<[u8]> {
        self.get_sized(false)
    }

    /// Copy a packet into reusable storage sized for its known length.
    ///
    /// With the default pool, packets up to 2 KiB use a 2 KiB backing allocation. Existing
    /// full-size buffers remain reusable, and oversized packets grow as needed. Both classes
    /// share the same retained-buffer limit. Unlike this copying path, [`Self::get`] always
    /// returns a full `N` bytes so callers reading directly into it keep their receive limit.
    pub fn copy_from(&self, data: &[u8]) -> Packet<[u8]> {
        let mut packet = self.get_sized(N > 1 && data.len() <= N / 2);
        packet.buf_mut().clear();
        packet.buf_mut().extend_from_slice(data);
        packet
    }

    /// Reuse or allocate one buffer, preserving its initialized size class for recycling.
    fn get_sized(&self, small: bool) -> Packet<[u8]> {
        if let Some(packet) = self.re_use(small) {
            return packet;
        }

        let buffer_len = if small { N / 2 } else { N };
        let mut buf = BytesMut::zeroed(buffer_len);
        let pointer_to_start_of_allocation = buf.split_to(0);

        debug_assert_eq!(pointer_to_start_of_allocation.len(), 0);
        debug_assert_eq!(buf.len(), buffer_len);

        let return_to_pool = ReturnToPool {
            pointer_to_start_of_allocation: Some(pointer_to_start_of_allocation),
            queue: self.queue.clone(),
            small,
        };

        Packet::new_from_pool(return_to_pool, buf)
    }
}

/// This sends a previously allocated [`BytesMut`] back to [`PacketBufPool`] when its dropped.
pub struct ReturnToPool {
    /// This is a pointer to the allocation allocated by [`PacketBufPool::get`].
    /// By making sure we never modify this (by calling reserve, etc), we can efficiently re-use
    /// this allocation later.
    ///
    /// INVARIANT:
    /// - Points to the start of an allocation initialized for its immutable size class.
    // Note: Option is faster than mem::take
    pointer_to_start_of_allocation: Option<BytesMut>,
    queue: Arc<Mutex<PoolQueue>>,
    /// The original allocation is half-size; growing the packet must never change this tag.
    small: bool,
}

impl Drop for ReturnToPool {
    fn drop(&mut self) {
        let p = self.pointer_to_start_of_allocation.take().unwrap();
        let mut queue_g = self.queue.lock().unwrap();
        if queue_g.buffers.len() + queue_g.small_buffers.len() < queue_g.capacity {
            // The classes share one bound, so adding small packets cannot double retention.
            if self.small {
                queue_g.small_buffers.push_back(p);
            } else {
                queue_g.buffers.push_back(p);
            }
        }
    }
}

/// Ask the C allocator to hand freed heap pages back to the OS.
///
/// glibc keeps freed small chunks inside its arenas, so the packet buffers released by an
/// idle pool would stay resident without this. Other allocators return memory on their own
/// schedule, and there this does nothing. It walks every arena, so call it only when idle.
#[cfg(feature = "device")]
pub(crate) fn return_freed_heap_to_os() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim takes no pointers; it only releases glibc's own free pages.
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(test)]
mod tests {
    use std::{hint::black_box, thread};

    #[cfg(feature = "device")]
    use std::sync::{Arc, Barrier};

    use super::PacketBufPool;

    /// Growing a packet's buffer beyond the pool's `N` (e.g. via `extend_from_slice`)
    /// reallocates the data away from the shared allocation. Tests that the pool stays healthy
    /// The original `N`-sized buffer is recycled via the start pointer and the pool keeps
    /// handing out usable buffers.
    #[test]
    fn packet_grow_beyond_capacity() {
        const N: usize = 4096;
        let pool = PacketBufPool::<N>::new(1);

        // Record the address of the pool's single pre-allocated buffer.
        let buffer_ptr = {
            let packet = pool.get();
            let ptr = packet.as_ptr();
            drop(packet);
            ptr
        };

        for _ in 0..10 {
            // The pool must hand back the original N buffer - recycled after the
            // previous iteration grew (and so detached) its data - not a fresh one.
            let mut packet = pool.get();
            assert_eq!(
                packet.as_ptr(),
                buffer_ptr,
                "the original N buffer must be recycled into the pool after a grow"
            );
            assert_eq!(packet.len(), N);

            // Grow well past N; this reallocates the data onto a fresh, larger buffer,
            // detaching it from the pooled allocation.
            packet.buf_mut().clear();
            packet.buf_mut().extend_from_slice(&vec![0x55u8; N * 4]);
            assert_eq!(packet.len(), N * 4);
            assert_ne!(packet.as_ptr(), buffer_ptr, "growing must reallocate");
        }
    }

    /// Test pre-allocation semantics of [PacketBufPool].
    #[test]
    fn pool_prealloc() {
        const N: usize = 1024;
        let buffer_count = 10;
        let pool = PacketBufPool::<N>::new(10);

        let mut packets = vec![];

        for _ in 0..buffer_count {
            let packet = pool.re_use(false).expect("10 buffers was pre-allocated");
            assert_eq!(packet.buf().len(), N);
            packets.push(packet); // save packets so they don't get re-used
        }

        assert!(
            pool.re_use(false).is_none(),
            "pool is empty and a new packet must be allocated"
        );
    }

    /// Test demand-driven allocation and recycle semantics of [PacketBufPool].
    #[cfg(feature = "device")]
    #[test]
    fn pool_lazy_allocation_and_recycle() {
        const N: usize = 1024;
        let pool = PacketBufPool::<N>::new_lazy(1);

        assert!(pool.re_use(false).is_none(), "lazy pool must start empty");

        let packet = pool.get();
        let buffer_ptr = packet.as_ptr();
        assert_eq!(packet.len(), N);
        assert!(packet.iter().all(|byte| *byte == 0));
        drop(packet);

        let recycled = pool
            .re_use(false)
            .expect("returned buffer must be retained");
        assert_eq!(recycled.as_ptr(), buffer_ptr);
    }

    /// Test that concurrent allocations do not grow lazy pool retention beyond its capacity.
    #[cfg(feature = "device")]
    #[test]
    fn lazy_pool_retention_is_bounded() {
        const CAPACITY: usize = 4;
        const CONCURRENT_PACKETS: usize = CAPACITY * 2;

        let pool = PacketBufPool::<1024>::new_lazy(CAPACITY);
        let barrier = Arc::new(Barrier::new(CONCURRENT_PACKETS));

        thread::scope(|scope| {
            for _ in 0..CONCURRENT_PACKETS {
                let pool = pool.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let packet = pool.get();
                    barrier.wait();
                    drop(packet);
                });
            }
        });

        assert_eq!(pool.retained(), CAPACITY);
    }

    /// Both size classes must share a bound even when buffers return from concurrent workers.
    #[cfg(feature = "device")]
    #[test]
    fn mixed_size_pool_retention_is_bounded() {
        let pool = PacketBufPool::<4096>::new_lazy(4);
        let barrier = Arc::new(Barrier::new(8));
        thread::scope(|scope| {
            for index in 0..8 {
                let pool = pool.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let packet = if index % 2 == 0 {
                        pool.get()
                    } else {
                        pool.copy_from(b"small")
                    };
                    barrier.wait();
                    drop(packet);
                });
            }
        });
        assert_eq!(pool.retained(), 4);
        assert_eq!(pool.take_count(), 8);
        pool.release();
        assert_eq!(pool.retained(), 0);
    }

    /// Reusing a small buffer must not shorten full receives or lose its original allocation.
    #[cfg(feature = "device")]
    #[test]
    fn small_buffers_recycle_after_growth_and_keep_full_receive_capacity() {
        let pool = PacketBufPool::<4096>::new_lazy(4);
        let packet = pool.copy_from(b"first");
        let small_address = packet.as_ptr();
        drop(packet);
        let full = pool.get();
        assert_eq!(full.len(), 4096);
        assert_ne!(full.as_ptr(), small_address);
        drop(full);
        let mut packet = pool.copy_from(b"second");
        assert_eq!(packet.as_ptr(), small_address);
        packet.buf_mut().resize(16_384, 0xAA);
        drop(packet);
        let recycled = pool.copy_from(b"third");
        assert_eq!(recycled.as_ptr(), small_address);
        assert_eq!(recycled.as_ref(), b"third");
    }

    /// A split packet can outlive its pool lease without its bytes being overwritten on reuse.
    #[cfg(feature = "device")]
    #[test]
    fn small_buffer_split_remains_valid_across_reuse_and_release() {
        let pool = PacketBufPool::<4096>::new_lazy(1);
        let mut packet = pool.copy_from(b"abcdef");
        let prefix = packet.buf_mut().split_to(3);
        drop(packet);
        let next = pool.copy_from(b"next");
        assert_eq!(prefix.as_ref(), b"abc");
        assert_eq!(next.as_ref(), b"next");
        pool.release();
        assert_eq!(prefix.as_ref(), b"abc");
    }

    /// The pool counts every buffer taken, and after a release it keeps recycling, bounded by
    /// its capacity.
    #[cfg(feature = "device")]
    #[test]
    fn release_frees_retained_buffers_and_pool_keeps_working() {
        let pool = PacketBufPool::<1024>::new_lazy(4);

        drop((pool.get(), pool.get(), pool.get()));
        assert_eq!(pool.take_count(), 3);
        assert_eq!(pool.take_count(), 0, "reading the count resets it");
        assert_eq!(pool.retained(), 3);

        pool.release();
        assert_eq!(pool.retained(), 0);

        let packets: Vec<_> = (0..6).map(|_| pool.get()).collect();
        drop(packets);
        assert_eq!(
            pool.retained(),
            4,
            "returned buffers are retained again, up to capacity"
        );
    }

    /// Test buffer recycle semantics of [PacketBufPool].
    #[test]
    fn pool_buffer_recycle() {
        let pool = PacketBufPool::<4096>::new(1);

        for i in 0..10 {
            // Get a packet and record its address.
            let mut packet1 = black_box(pool.get());
            let packet1_addr = packet1.buf().as_ptr();

            // Mutate the packet for good measure
            let data = format!("Hello there. x{i}\nGeneral Kenobi! You are a bold one.");
            let data = data.as_bytes();
            packet1.truncate(data.len());
            packet1.copy_from_slice(data);

            // Drop the packet, allowing it to be re-used.
            // Do it on another thread for good measure.
            thread::spawn(move || drop(packet1)).join().unwrap();

            // Get another packet. This should be the same as packet1.
            let packet2 = black_box(pool.get());
            let packet2_addr = packet2.buf().as_ptr();

            // Get a third packet.
            // Since we're still holding packet2, this will result in an allocation.
            let packet3 = black_box(pool.get());
            let packet3_addr = packet3.buf().as_ptr();

            assert!(
                packet2.starts_with(data),
                "old data should remain in the recycled buffer",
            );

            assert!(
                !packet3.starts_with(data),
                "old data should not exist in the new buffer",
            );

            assert_eq!(packet1_addr, packet2_addr);
            assert_ne!(packet1_addr, packet3_addr);

            drop((packet2, packet3));
        }
    }
}
