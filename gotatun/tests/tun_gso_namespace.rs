// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Exercise GotaTun's Linux TUN GSO path with real TCP and UDP traffic in isolated namespaces.

#![cfg(all(target_os = "linux", feature = "device", feature = "tun"))]

use std::{
    env, io,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

use gotatun::{device::DeviceBuilder, device::Peer};
use ipnetwork::Ipv4Network;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
    time::timeout,
};
use x25519_dalek::{PublicKey, StaticSecret};

/// Name used by the test harness when it starts another copy of this test binary.
const TEST_NAME: &str = "real_tcp_udp_namespace_through_tunnel";

/// TCP port used by the echo service on the receiving tunnel endpoint.
const TCP_ECHO_PORT: u16 = 19_410;

/// UDP port used by the echo service on the receiving tunnel endpoint.
const UDP_ECHO_PORT: u16 = 19_411;

/// UDP listen port used by the first tunnel endpoint.
const ENDPOINT_A_PORT: u16 = 51_820;

/// UDP listen port used by the second tunnel endpoint.
const ENDPOINT_B_PORT: u16 = 51_821;

/// Run the root-only namespace test, or one of its tunnel endpoint/client child modes.
#[tokio::test]
#[ignore = "requires root and creates temporary Linux network namespaces"]
async fn real_tcp_udp_namespace_through_tunnel() {
    match env::var("GOTATUN_GSO_ROLE").as_deref() {
        Ok("a") => run_endpoint("a").await.unwrap(),
        Ok("b") => run_endpoint("b").await.unwrap(),
        Ok("client") => run_client().await.unwrap(),
        Ok(role) => panic!("unknown namespace test role: {role}"),
        Err(_) => run_namespace_test().await.unwrap(),
    }
}

/// Create two isolated peers and verify ordered TCP and UDP payloads across their encrypted link.
async fn run_namespace_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut namespaces = NamespacePair::new();
    namespaces.create()?;
    let namespace_a = namespaces.a.clone();
    namespaces.start_endpoint("a", &namespace_a).await?;
    let namespace_b = namespaces.b.clone();
    namespaces.start_endpoint("b", &namespace_b).await?;
    namespaces.configure_tun_interfaces()?;
    namespaces.run_client()?;
    Ok(())
}

/// Own only the namespaces, veth names, readiness sockets, and child processes created by this test.
struct NamespacePair {
    a: String,
    b: String,
    veth_a: String,
    veth_b: String,
    children: Vec<Child>,
    readiness_paths: Vec<PathBuf>,
}

impl NamespacePair {
    /// Build collision-resistant names from this test process's identifier.
    fn new() -> Self {
        let pid = std::process::id();
        Self {
            a: format!("gso-j316-{pid}-a"),
            b: format!("gso-j316-{pid}-b"),
            veth_a: format!("j3a{pid}"),
            veth_b: format!("j3b{pid}"),
            children: Vec::new(),
            readiness_paths: Vec::new(),
        }
    }

    /// Create the two namespaces and their directly connected underlay veth pair.
    fn create(&self) -> Result<(), Box<dyn std::error::Error>> {
        run_ip(&["netns", "add", &self.a])?;
        run_ip(&["netns", "add", &self.b])?;
        run_ip(&[
            "link",
            "add",
            &self.veth_a,
            "type",
            "veth",
            "peer",
            "name",
            &self.veth_b,
        ])?;
        run_ip(&["link", "set", &self.veth_a, "netns", &self.a])?;
        run_ip(&["link", "set", &self.veth_b, "netns", &self.b])?;
        run_ip(&["-n", &self.a, "link", "set", "lo", "up"])?;
        run_ip(&["-n", &self.b, "link", "set", "lo", "up"])?;
        run_ip(&[
            "-n",
            &self.a,
            "addr",
            "add",
            "192.0.2.1/30",
            "dev",
            &self.veth_a,
        ])?;
        run_ip(&[
            "-n",
            &self.b,
            "addr",
            "add",
            "192.0.2.2/30",
            "dev",
            &self.veth_b,
        ])?;
        run_ip(&["-n", &self.a, "link", "set", &self.veth_a, "up"])?;
        run_ip(&["-n", &self.b, "link", "set", &self.veth_b, "up"])?;
        Ok(())
    }

    /// Start one tunnel endpoint and wait until its device and UDP socket are ready.
    async fn start_endpoint(
        &mut self,
        role: &str,
        namespace: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ready_path =
            env::temp_dir().join(format!("gotatun-j316-{}-{role}.sock", std::process::id()));
        let _ = std::fs::remove_file(&ready_path);
        let listener = UnixListener::bind(&ready_path)?;
        self.readiness_paths.push(ready_path.clone());

        let child = Command::new("ip")
            .args(["netns", "exec", namespace])
            .arg(env::current_exe()?)
            .args(["--exact", TEST_NAME, "--ignored", "--nocapture"])
            .env("GOTATUN_GSO_ROLE", role)
            .env("GOTATUN_GSO_READY_SOCKET", &ready_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        self.children.push(child);

        let accept = timeout(Duration::from_secs(15), listener.accept()).await??;
        let mut socket = accept.0;
        let mut ready = [0; 5];
        socket.read_exact(&mut ready).await?;
        if &ready != b"ready" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad endpoint readiness message",
            )
            .into());
        }
        Ok(())
    }

    /// Assign tunnel addresses and set the overlay interfaces to the workload MTU.
    fn configure_tun_interfaces(&self) -> Result<(), Box<dyn std::error::Error>> {
        run_ip(&["-n", &self.a, "addr", "add", "10.77.0.1/24", "dev", "gtun0"])?;
        run_ip(&["-n", &self.b, "addr", "add", "10.77.0.2/24", "dev", "gtun0"])?;
        run_ip(&[
            "-n", &self.a, "link", "set", "dev", "gtun0", "mtu", "1420", "up",
        ])?;
        run_ip(&[
            "-n", &self.b, "link", "set", "dev", "gtun0", "mtu", "1420", "up",
        ])?;
        run_ip(&[
            "-n",
            &self.a,
            "route",
            "replace",
            "10.77.0.2/32",
            "dev",
            "gtun0",
        ])?;
        run_ip(&[
            "-n",
            &self.b,
            "route",
            "replace",
            "10.77.0.1/32",
            "dev",
            "gtun0",
        ])?;
        Ok(())
    }

    /// Run the TCP and UDP echo client inside the first namespace and require a clean exit.
    fn run_client(&self) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new("ip")
            .args(["netns", "exec", &self.a])
            .arg(env::current_exe()?)
            .args(["--exact", TEST_NAME, "--ignored", "--nocapture"])
            .env("GOTATUN_GSO_ROLE", "client")
            .output()?;
        assert_output_ok("namespace TCP/UDP client", output)?;
        Ok(())
    }
}

impl Drop for NamespacePair {
    /// Stop this test's endpoint processes and remove only its temporary namespaces and sockets.
    fn drop(&mut self) {
        for child in &mut self.children {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        for namespace in [&self.a, &self.b] {
            let _ = Command::new("ip")
                .args(["netns", "del", namespace])
                .status();
        }
        for path in &self.readiness_paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Build and hold one real GotaTun endpoint in the current namespace.
async fn run_endpoint(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    let is_a = role == "a";
    let private_key = test_secret(is_a);
    let peer_public_key = PublicKey::from(&test_secret(!is_a));
    let (peer_underlay, listen_port, peer_port, peer_overlay) = if is_a {
        (
            Ipv4Addr::new(192, 0, 2, 2),
            ENDPOINT_A_PORT,
            ENDPOINT_B_PORT,
            Ipv4Addr::new(10, 77, 0, 2),
        )
    } else {
        (
            Ipv4Addr::new(192, 0, 2, 1),
            ENDPOINT_B_PORT,
            ENDPOINT_A_PORT,
            Ipv4Addr::new(10, 77, 0, 1),
        )
    };
    let peer = Peer::new(peer_public_key)
        .with_endpoint(SocketAddrV4::new(peer_underlay, peer_port).into())
        .with_allowed_ip(Ipv4Network::new(peer_overlay, 32)?.into());
    let _device = DeviceBuilder::new()
        .with_default_udp()
        .with_listen_port(listen_port)
        .create_tun("gtun0")?
        .with_private_key(private_key)
        .with_peer(peer)
        .build()
        .await?;

    if !is_a {
        start_echo_servers().await?;
    }
    signal_ready().await?;
    std::future::pending::<()>().await;
    Ok(())
}

/// Serve TCP byte streams and UDP datagrams unchanged from the receiving TUN endpoint.
async fn start_echo_servers() -> Result<(), Box<dyn std::error::Error>> {
    let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, TCP_ECHO_PORT)).await?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut bytes = [0; 8192];
                while let Ok(length) = stream.read(&mut bytes).await {
                    if length == 0 || stream.write_all(&bytes[..length]).await.is_err() {
                        break;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, UDP_ECHO_PORT)).await?;
    tokio::spawn(async move {
        let mut bytes = [0; 1200];
        while let Ok((length, address)) = udp.recv_from(&mut bytes).await {
            if udp.send_to(&bytes[..length], address).await.is_err() {
                break;
            }
        }
    });
    Ok(())
}

/// Send ordered TCP bytes and sequence-numbered UDP datagrams, then verify each echo exactly.
async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let target = (Ipv4Addr::new(10, 77, 0, 2), TCP_ECHO_PORT);
    let tcp = timeout(Duration::from_secs(15), TcpStream::connect(target)).await??;
    let payload: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let send_payload = payload.clone();
    let (mut reader, mut writer) = tokio::io::split(tcp);
    let send = async {
        timeout(Duration::from_secs(30), async {
            writer.write_all(&send_payload).await?;
            writer.shutdown().await
        })
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))??;
        Ok::<(), io::Error>(())
    };
    let receive = async {
        let mut echo = Vec::with_capacity(payload.len());
        timeout(Duration::from_secs(30), reader.read_to_end(&mut echo))
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))??;
        assert_eq!(echo, payload, "TCP echo changed or reordered bytes");
        Ok::<(), io::Error>(())
    };
    tokio::try_join!(send, receive)?;

    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    udp.connect((Ipv4Addr::new(10, 77, 0, 2), UDP_ECHO_PORT))
        .await?;
    let datagrams: Vec<Vec<u8>> = (0u32..256)
        .map(|sequence| {
            let mut bytes = vec![0; 1200];
            bytes[..4].copy_from_slice(&sequence.to_be_bytes());
            for (index, byte) in bytes[4..].iter_mut().enumerate() {
                *byte = sequence.wrapping_add(index as u32) as u8;
            }
            bytes
        })
        .collect();
    for datagram in &datagrams {
        udp.send(datagram).await?;
    }
    for (sequence, expected) in datagrams.iter().enumerate() {
        let mut received = vec![0; 1200];
        let length = timeout(Duration::from_secs(10), udp.recv(&mut received))
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("UDP echo datagram {sequence} timed out: {error}"),
                )
            })??;
        assert_eq!(
            &received[..length],
            expected,
            "UDP echo changed or reordered a datagram"
        );
    }
    Ok(())
}

/// Notify the parent test after an endpoint has opened its device and listeners.
async fn signal_ready() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::var_os("GOTATUN_GSO_READY_SOCKET")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "readiness socket is missing"))?;
    let mut socket = UnixStream::connect(path).await?;
    socket.write_all(b"ready").await?;
    Ok(())
}

/// Return one of two fixed test-only private keys.
fn test_secret(is_a: bool) -> StaticSecret {
    StaticSecret::from([if is_a { 0x31 } else { 0x82 }; 32])
}

/// Execute `ip` with checked arguments and include its stderr when setup fails.
fn run_ip(arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("ip").args(arguments).output()?;
    assert_output_ok("ip", output)?;
    Ok(())
}

/// Return an error that includes command output when a child process exits unsuccessfully.
fn assert_output_ok(operation: &str, output: Output) -> Result<(), Box<dyn std::error::Error>> {
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{operation} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    ))
    .into())
}
