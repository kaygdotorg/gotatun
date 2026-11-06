# SPDX-License-Identifier: AGPL-3.0-only
"""Add temporary, jemalloc-only SIGUSR1 heap reports to the diagnostic build."""
from pathlib import Path

path = Path("gotatun-cli/src/unix/mod.rs")
source = path.read_text()
needle = "async fn wait_for_shutdown(mut device: Device<DefaultDeviceTransports>) {"
instrument = '''
    gotatun::noise::j324_sizes();
    gotatun::device::j324_sizes();
    #[cfg(feature = "jemalloc")]
    let heap_reporter = tokio::spawn(async {
        unsafe extern "C" {
            fn _rjem_malloc_stats_print(
                callback: Option<unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char)>,
                opaque: *mut libc::c_void,
                options: *const libc::c_char,
            );
        }
        let mut requests = signal(SignalKind::user_defined1()).expect("heap diagnostic signal");
        while requests.recv().await.is_some() {
            // SAFETY: a null callback/opaque selects stderr; J requests the documented JSON format.
            unsafe { _rjem_malloc_stats_print(None, std::ptr::null_mut(), c"J".as_ptr()); }
        }
    });
'''
source = source.replace(needle, needle + instrument)
source = source.replace('    info!("GotaTun is shutting down");', '''    #[cfg(feature = "jemalloc")]
    heap_reporter.abort();
    info!("GotaTun is shutting down");''')
path.write_text(source)

for module, names in {
    "noise": ["Tunn", "handshake::Handshake", "timers::Timers", "session::Session", "[Option<session::Session>; N_SESSIONS]", "crate::packet::Packet", "std::collections::VecDeque<crate::packet::Packet>"],
    "device": ["peer_state::PeerState", "tokio::sync::Mutex<peer_state::PeerState>", "ipnetwork::IpNetwork"],
}.items():
    path = Path(f"gotatun/src/{module}/mod.rs")
    with path.open("a") as stream:
        stream.write('\n/// Print fixed heap-type sizes for the temporary J324 diagnostic binary.\npub fn j324_sizes() {\n')
        for name in names:
            stream.write(f'    eprintln!("J324_TYPE {module}::{name} {{}}", std::mem::size_of::<{name}>());\n')
        stream.write('}\n')
