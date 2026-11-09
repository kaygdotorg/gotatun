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
#![cfg(any(feature = "device", feature = "tun"))]

use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use tokio::task::JoinHandle;

/// Best-effort text of a panic payload, for logs and fatal device errors.
pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

/// A wrapper around [`JoinHandle`] that.
/// - Aborts the task on Drop.
/// - If the task returns an `Err`, logs it.
/// - If the task panics, logs the panic at error level when it happens, not only when the task
///   is stopped. Device tasks that must also fail the device wrap their future first (see
///   `fatal_on_panic` in `device`).
pub struct Task {
    name: &'static str,

    /// [`JoinHandle`] for the tokio task.
    ///
    /// INVARIANT: This will be `Some` until either of:
    /// - Self is dropped.
    /// - [`Self::stop`] is called.
    handle: Option<JoinHandle<()>>,
}

pub trait TaskOutput: Sized + Send + 'static {
    fn handle(self, task_name: &'static str) {
        tracing::trace!("task {task_name:?} exited");
    }
}

impl TaskOutput for () {}

impl<T, E> TaskOutput for Result<T, E>
where
    Self: Send + 'static,
    E: std::fmt::Debug,
{
    fn handle(self, task_name: &'static str) {
        match self {
            Ok(..) => ().handle(task_name),
            Err(e) => tracing::error!("task {task_name:?} errored: {e:?}"),
        }
    }
}

impl Task {
    #[track_caller]
    pub fn spawn<Fut, O>(name: &'static str, fut: Fut) -> Self
    where
        Fut: Future<Output = O> + Send + 'static,
        O: TaskOutput,
    {
        let handle = tokio::spawn(async move {
            // Unwind safety: a panicking task is over; nothing it owned is used afterwards.
            match AssertUnwindSafe(fut).catch_unwind().await {
                Ok(output) => TaskOutput::handle(output, name),
                Err(payload) => {
                    tracing::error!("task {name:?} panicked: {}", panic_message(&*payload));
                }
            }
        });

        Task {
            name,
            handle: Some(handle),
        }
    }

    #[cfg(feature = "device")]
    pub async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            match handle.await {
                Err(e) if e.is_panic() => {
                    tracing::error!("task {} panicked: {e:#?}", self.name);
                }
                _ => {
                    tracing::trace!("stopped task {}", self.name);
                }
            }
        }
    }
}

impl Future for Task {
    type Output = <JoinHandle<()> as Future>::Output;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.handle
            .as_mut()
            .map(Pin::new)
            .expect("Handle is Some until task is stopped or dropped")
            .poll(cx)
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            tracing::trace!("dropped task {}", self.name);

            // Note that the task future isn't dropped when calling abort.
            // It is dropped by the tokio runtime at some point in the future.
            // Prefer calling `Task::stop` for tasks that need to be promptly cleaned up.
            handle.abort();
        }
    }
}
