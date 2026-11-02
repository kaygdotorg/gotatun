// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Linux-specific TUN setup and software fallback policy.

use std::os::fd::AsRawFd;

pub(super) fn create_tun_with_vnet_fallback(
    config: &mut tun::Configuration,
) -> Result<(tun::AsyncDevice, bool), tun::Error> {
    open_with_vnet_fallback(|vnet_header| {
        config.platform_config(|platform| {
            platform.vnet_hdr(vnet_header);
        });
        tun::create_as_async(config)
    })
}

pub(super) fn enable_tso_with_fallback(tun: &impl AsRawFd) -> bool {
    match super::tso::try_enable_tso(tun) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(%error, "TUN TSO unavailable; using software packet handling");
            false
        }
    }
}

fn open_with_vnet_fallback<T, E>(
    mut create: impl FnMut(bool) -> Result<T, E>,
) -> Result<(T, bool), E> {
    match create(true) {
        Ok(device) => Ok((device, true)),
        Err(vnet_error) => match create(false) {
            Ok(device) => Ok((device, false)),
            Err(_) => Err(vnet_error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::open_with_vnet_fallback;
    use std::fs::File;

    #[test]
    fn unsupported_vnet_header_retries_without_the_header() {
        let mut requests = Vec::new();
        let (device, vnet_header) = open_with_vnet_fallback(|requested| {
            requests.push(requested);
            if requested {
                Err("IFF_VNET_HDR unsupported")
            } else {
                Ok("plain TUN")
            }
        })
        .unwrap();

        assert_eq!(device, "plain TUN");
        assert!(!vnet_header);
        assert_eq!(requests, [true, false]);
    }

    #[test]
    fn failure_of_both_open_modes_returns_the_original_error() {
        let mut requests = Vec::new();
        let result: Result<(&str, bool), &str> = open_with_vnet_fallback(|requested| {
            requests.push(requested);
            Err(if requested {
                "vnet failure"
            } else {
                "plain failure"
            })
        });

        assert_eq!(result, Err("vnet failure"));
        assert_eq!(requests, [true, false]);
    }

    #[test]
    fn unsupported_tun_tso_ioctl_keeps_the_software_path_available() {
        let file = File::open("/dev/null").unwrap();

        assert!(!super::enable_tso_with_fallback(&file));
    }
}
