// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Best-effort Linux process policy for avoiding transparent huge page collapse.

use std::io;

/// Disable transparent huge pages for this process where the kernel supports it.
///
/// This is best-effort: a rejected prctl must not prevent the tunnel from starting.
pub(super) fn disable_if_supported() -> io::Result<()> {
    // SAFETY: PR_SET_THP_DISABLE consumes scalar arguments and retains no pointers.
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_THP_DISABLE,
            libc::c_ulong::from(1_u32),
            libc::c_ulong::from(0_u32),
            libc::c_ulong::from(0_u32),
            libc::c_ulong::from(0_u32),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    const CHILD: &str = "GOTATUN_THP_TEST_CHILD";
    const TEST: &str = "thp::tests::process_policy_disables_thp_when_supported";

    #[test]
    fn process_policy_disables_thp_when_supported() {
        if std::env::var_os(CHILD).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        if super::disable_if_supported().is_ok() {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let enabled = status
                .lines()
                .find_map(|line| line.strip_prefix("THP_enabled:").map(str::trim))
                .expect("Linux process status must expose THP_enabled");
            assert_eq!(enabled, "0");
        }
    }
}
