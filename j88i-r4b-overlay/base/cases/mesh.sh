#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Mesh data-plane case (#260, part A): one system between two network
# namespaces on this machine, then the same probes for every system.
#
#   mesh.sh <underlay|infraternal|gotatun|boringtun|tailscale|netbird|netbird-userspace|kernel-plain>
#
# Topology (all inside private namespaces; the root namespace is untouched):
#
#   h2h-a (10.220.0.1, a0) ─┐
#   h2h-b (10.220.0.2, b0) ─┼─ bridge br0 in h2h-u
#   h2h-c (10.220.0.3, c0) ─┘   coordination: Tailscale test control + DERP/STUN,
#                               NetBird combined server; idle for the others
#
# Probes run from h2h-a to the peer's mesh address in h2h-b, where one
# `h2h net-server` answers TCP and UDP. The DE↔IN profile adds 99 ms of netem
# delay on a0 and on b0 (198 ms round trip on the a–b path).
source "$H2H_KIT/lib/common.sh"
SYSTEM=$1
H2H_CASE=mesh-$SYSTEM
trap cleanup EXIT

LAT_COUNT=$(h2h_lan_latency_count)
WAN_LAT_COUNT=$(dur 300 60)
TPUT_S=$(h2h_lan_tput_duration 10 2)
WAN_TPUT_S=$(dur 20 4)
IDLE_S=$(dur 15 3)
GOTATUN_BIN=${H2H_GOTATUN_BIN:-$H2H_BIN/gotatun}

record_memcg() {
    local tag=$1 rel path
    rel=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
    path="/sys/fs/cgroup$rel"
    if [[ -r "$path/memory.current" && -r "$path/memory.stat" ]]; then
        {
            printf 'memory.current '
            cat "$path/memory.current"
            cat "$path/memory.stat"
        } > "$D/memcg-$tag.txt"
    else
        printf 'unavailable\n' > "$D/memcg-$tag.txt"
    fi
    cp "$D/memcg-$tag.txt" "$H2H_RESULTS/$H2H_CASE/memcg-$tag.txt"
}

for x in u a b c; do netns_add "h2h-$x"; done
ip -n h2h-u link add br0 type bridge
ip -n h2h-u link set br0 up
n=1
for x in a b c; do
    ip link add "${x}0" netns "h2h-$x" type veth peer name "u$x" netns h2h-u
    ip -n h2h-u link set "u$x" master br0 up
    ip -n "h2h-$x" addr add "10.220.0.$n/24" dev "${x}0"
    ip -n "h2h-$x" link set "${x}0" up
    n=$((n + 1))
done
ns_holder A_PID h2h-a
ns_holder B_PID h2h-b
ns_holder C_PID h2h-c
spawn_in_ns NET_SERVER_PID h2h-b "$H" net-server --bind 0.0.0.0:5201
wait_for 10 in_ns h2h-a "$H" net-wait --to 10.220.0.2:5201 --timeout-s 1 || die "underlay not up"

D=$H2H_RUN/$SYSTEM
mkdir -p "$D"
WATCH=""      # comma-separated PIDs whose process trees are the system's daemons
PEER=""       # the peer's address on the system's own network
TUN_A=""      # tunnel interface on the first measured endpoint, when present
TUN_B=""      # tunnel interface on the second measured endpoint, when present

# fifo_daemon <name> <cmd...>: a child whose stdin we hold open; it stops when
# we close it. Its PID is left in DAEMON_PID.
fifo_daemon() {
    local name=$1 fd; shift
    mkfifo "$D/$name.in"
    "$@" < "$D/$name.in" > "$D/$name.out" 2> "$D/$name.err" &
    DAEMON_PID=$!
    register_pid "$DAEMON_PID"
    exec {fd}> "$D/$name.in"
    register_cmd "echo quit >&$fd; exec $fd>&-; sleep 1"
}
# first_line <file> <seconds>: the daemon's first output line, or failure as soon as it exits.
first_line() {
    local deadline=$((SECONDS + $2))
    until [[ -s $1 ]]; do
        kill -0 "$DAEMON_PID" 2>/dev/null || return 1
        ((SECONDS < deadline)) || return 1
        sleep 0.1
    done
    head -n1 "$1"
}

start_infraternal() {
    note version "{\"infraternal\":\"$("$H2H_BIN/infraternal" --version | head -1)\",\"source\":\"$(cat "$H2H_KIT/SOURCE_COMMIT")\"}"
    fifo_daemon ix sandboxed "$A_PID" env PYTHONPATH="$H2H_KIT/lib" python3 -I "$H2H_KIT/lib/mesh_ix.py" \
        --binary "$H2H_BIN/infraternal" --coordinator "$H2H_BIN/coordinator_fixture" \
        --scratch "$D" --pid-b "$B_PID"
    local ready
    ready=$(first_line "$D/ix.out" 60) || die "infraternal mesh did not come up: $(tail -c 600 "$D/ix.err")"
    START=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["start_ns"])' "$ready")
    PEER=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["peer_ipv4"])' "$ready")
    WATCH=$(python3 -c 'import json,sys; print(",".join(map(str, json.loads(sys.argv[1])["pids"])))' "$ready")
    TUN_A=infraternal0
    TUN_B=infraternal0
    note setup "$ready"
}

start_tailscale() {
    mkdir -p "$D/a" "$D/b"
    fifo_daemon ctl sandboxed "$C_PID" "$H2H_BIN/tscontrol" -addr 10.220.0.3 -control-port 9911
    first_line "$D/ctl.out" 30 > /dev/null || die "local Tailscale control did not start: $(tail -c 600 "$D/ctl.err")"
    START=$("$H" now)
    local x pid pids=() ups=()
    for x in a b; do
        local nspid=$A_PID; [[ $x == b ]] && nspid=$B_PID
        H2H_SCOPE_LOG="$D/$x/daemon.log" spawn_sandboxed pid "$nspid" \
            "$H2H_BIN/tailscaled" --tun=tailscale0 --statedir="$D/$x" \
            --socket="$D/$x/sock" --port=41641 --no-logs-no-support
        pids+=("$pid")
    done
    for x in a b; do
        local nspid=$A_PID; [[ $x == b ]] && nspid=$B_PID
        wait_for 30 test -S "$D/$x/sock" || die "tailscaled $x has no socket"
        H2H_SCOPE_LOG="$D/$x/up.log" spawn_sandboxed pid "$nspid" \
            "$H2H_BIN/tailscale" --socket="$D/$x/sock" up --login-server=http://10.220.0.3:9911 \
            --hostname="h2h-$x" --accept-dns=false --accept-routes=false --timeout=60s
        ups+=("$H2H_SCOPE_CLIENT_PID")
    done
    for pid in "${ups[@]}"; do wait "$pid" || die "tailscale up failed: $(tail -c 600 "$D/a/up.log" "$D/b/up.log")"; done
    PEER=$(sandboxed "$B_PID" "$H2H_BIN/tailscale" --socket="$D/b/sock" ip -4)
    WATCH=$(IFS=,; echo "${pids[*]}")
    TUN_A=tailscale0
    TUN_B=tailscale0
    note version "{\"tailscale\":\"$("$H2H_BIN/tailscale" version | head -1)\"}"
}

start_gotatun() {
    local gotatun_version
    mkdir -p "$D/a" "$D/b" "$D/keys"
    command -v openssl >/dev/null || die "GotaTun key setup requires OpenSSL"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    START=$("$H" now)
    H2H_SCOPE_LOG="$D/a/daemon.log" spawn_sandboxed GOTA_A_PID "$A_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$GOTATUN_BIN" --foreground wgA
    H2H_SCOPE_LOG="$D/b/daemon.log" spawn_sandboxed GOTA_B_PID "$B_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$GOTATUN_BIN" --foreground wgB
    wait_for 20 nsenter -t "$GOTA_A_PID" -m -- test -S /var/run/wireguard/wgA.sock \
        || die "GotaTun a UAPI socket did not appear: $(tail -c 600 "$D/a/daemon.log")"
    wait_for 20 nsenter -t "$GOTA_B_PID" -m -- test -S /var/run/wireguard/wgB.sock \
        || die "GotaTun b UAPI socket did not appear: $(tail -c 600 "$D/b/daemon.log")"
    {
        printf 'binary_sha256 '
        sha256sum "$GOTATUN_BIN" | awk '{print $1}'
        awk -v endpoint=a '$1 == "THP_enabled:" {print endpoint, $2}' "/proc/$GOTA_A_PID/status"
        awk -v endpoint=b '$1 == "THP_enabled:" {print endpoint, $2}' "/proc/$GOTA_B_PID/status"
    } > "$H2H_RESULTS/$H2H_CASE/thp-status.txt"

    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    nsenter -t "$GOTA_A_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgA --private-key "$D/keys/a.private" --peer-public "$D/keys/b.public" \
        --endpoint 10.220.0.2:51821 --listen-port 51820 --allowed-ip 10.66.0.2/32
    nsenter -t "$GOTA_B_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgB --private-key "$D/keys/b.private" --peer-public "$D/keys/a.public" \
        --endpoint 10.220.0.1:51820 --listen-port 51821 --allowed-ip 10.66.0.1/32
    rm -f "$D/keys/"*.private
    WATCH="$GOTA_A_PID,$GOTA_B_PID"
    PEER=10.66.0.2
    TUN_A=wgA
    TUN_B=wgB
    gotatun_version=$("$GOTATUN_BIN" --version | head -1)
    note version "{\"gotatun\":\"$gotatun_version\",\"source\":\"${H2H_GOTATUN_SOURCE:-unknown}\",\"binary_sha256\":\"$(sha256sum "$GOTATUN_BIN" | awk '{print $1}')\",\"mtu\":1420,\"tun_vnet_hdr\":\"attempted-with-fallback\",\"linux_udp_gso_gro_path\":true}"
}

pin_locality_workers() {
    [[ ${H2H_CPUSET_AUDIT_WORKER_PLACEMENT:-default} == round-robin ]] || return 0
    [[ ${H2H_CPUSET_AUDIT_ROW_TAG:-} =~ ^gotatun-j88i-(locality-)?33ca6fe-[0-9]+$ ]] || return 0
    [[ $SYSTEM == gotatun && ${H2H_CPUSET_AUDIT_ENGINE:-} == gotatun ]] \
        || die "round-robin worker placement is only valid for a GotaTun row"
    [[ -n ${GOTA_A_PID:-} && -n ${GOTA_B_PID:-} ]] \
        || die "round-robin worker placement has no live GotaTun endpoints"

    local endpoint pid cpus
    for endpoint in a b; do
        pid=$GOTA_A_PID
        cpus=${H2H_CPUSET_A:?D348 side A mask is required}
        [[ $endpoint == a ]] || {
            pid=$GOTA_B_PID
            cpus=${H2H_CPUSET_B:?D348 side B mask is required}
        }
        python3 -I "$H2H_KIT/lib/tokio_affinity.py" "$pid" "$cpus" \
            > "$H2H_RESULTS/$H2H_CASE/tokio-affinity-$endpoint.json" \
            || die "could not pin GotaTun $endpoint Tokio workers to $cpus"
    done
    export H2H_CPUSET_AUDIT_TARGET_PIDS="$GOTA_A_PID,$GOTA_B_PID"
}

start_wireguard_go() {
    local version
    mkdir -p "$D/a" "$D/b" "$D/keys"
    command -v openssl >/dev/null || die "WireGuard key setup requires OpenSSL"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    START=$("$H" now)
    H2H_SCOPE_LOG="$D/a/daemon.log" spawn_sandboxed WG_A_PID "$A_PID" \
        env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=error "$H2H_BIN/wireguard-go" wgA
    H2H_SCOPE_LOG="$D/b/daemon.log" spawn_sandboxed WG_B_PID "$B_PID" \
        env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=error "$H2H_BIN/wireguard-go" wgB
    wait_for 20 nsenter -t "$WG_A_PID" -m -- test -S /var/run/wireguard/wgA.sock \
        || die "wireguard-go a UAPI socket did not appear: $(tail -c 600 "$D/a/daemon.log")"
    wait_for 20 nsenter -t "$WG_B_PID" -m -- test -S /var/run/wireguard/wgB.sock \
        || die "wireguard-go b UAPI socket did not appear: $(tail -c 600 "$D/b/daemon.log")"

    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    nsenter -t "$WG_A_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgA --private-key "$D/keys/a.private" --peer-public "$D/keys/b.public" \
        --endpoint 10.220.0.2:51821 --listen-port 51820 --allowed-ip 10.66.0.2/32
    nsenter -t "$WG_B_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgB --private-key "$D/keys/b.private" --peer-public "$D/keys/a.public" \
        --endpoint 10.220.0.1:51820 --listen-port 51821 --allowed-ip 10.66.0.1/32
    rm -f "$D/keys/"*.private
    WATCH="$WG_A_PID,$WG_B_PID"
    PEER=10.66.0.2
    TUN_A=wgA
    TUN_B=wgB
    version="upstream commit b3bc704ef0ee21a36298601a9e1e5ff90377ac52"
    note version "{\"wireguard_go\":\"$version\",\"source\":\"b3bc704ef0ee21a36298601a9e1e5ff90377ac52\",\"mtu\":1420,\"udp_gso_gro\":true,\"tun_vnet_hdr\":true}"
}

start_boringtun() {
    local boringtun_version
    mkdir -p "$D/a" "$D/b" "$D/keys"
    command -v openssl >/dev/null || die "BoringTun key setup requires OpenSSL"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    START=$("$H" now)
    H2H_SCOPE_LOG="$D/a/daemon.log" spawn_sandboxed BORING_A_PID "$A_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$H2H_BIN/boringtun-cli" --foreground wgA
    H2H_SCOPE_LOG="$D/b/daemon.log" spawn_sandboxed BORING_B_PID "$B_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$H2H_BIN/boringtun-cli" --foreground wgB
    wait_for 20 nsenter -t "$BORING_A_PID" -m -- test -S /var/run/wireguard/wgA.sock \
        || die "BoringTun a UAPI socket did not appear: $(tail -c 600 "$D/a/daemon.log")"
    wait_for 20 nsenter -t "$BORING_B_PID" -m -- test -S /var/run/wireguard/wgB.sock \
        || die "BoringTun b UAPI socket did not appear: $(tail -c 600 "$D/b/daemon.log")"

    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    nsenter -t "$BORING_A_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgA --private-key "$D/keys/a.private" --peer-public "$D/keys/b.public" \
        --endpoint 10.220.0.2:51821 --listen-port 51820 --allowed-ip 10.66.0.2/32
    nsenter -t "$BORING_B_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgB --private-key "$D/keys/b.private" --peer-public "$D/keys/a.public" \
        --endpoint 10.220.0.1:51820 --listen-port 51821 --allowed-ip 10.66.0.1/32
    rm -f "$D/keys/"*.private
    WATCH="$BORING_A_PID,$BORING_B_PID"
    PEER=10.66.0.2
    TUN_A=wgA
    TUN_B=wgB
    boringtun_version=$("$H2H_BIN/boringtun-cli" --version | head -1)
    note version "{\"boringtun\":\"$boringtun_version\",\"source\":\"boringtun-cli-0.5.2\",\"workers\":4,\"multi_queue\":true}"
}

start_netbird() {
    local mode=$1
    mkdir -p "$D/a" "$D/b" "$D/srv"
    python3 -I - "$D/srv/config.yaml" "$D/srv" <<'PY'
import os, secrets, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(f"""server:
  listenAddress: "10.220.0.3:8080"
  exposedAddress: "http://10.220.0.3:8080"
  stunPorts: [3478]
  healthcheckAddress: "10.220.0.3:9000"
  metricsPort: 9090
  logLevel: "warn"
  logFile: "console"
  authSecret: "{secrets.token_urlsafe(32)}"
  dataDir: "{sys.argv[2]}"
  disableAnonymousMetrics: true
  disableGeoliteUpdate: true
  auth:
    issuer: "http://10.220.0.3:8080/oauth2"
  store:
    engine: "sqlite"
""")
PY
    H2H_SCOPE_LOG="$D/srv/server.log" spawn_sandboxed NETBIRD_SERVER_PID "$C_PID" \
        env NB_SETUP_PAT_ENABLED=true NB_DISABLE_GEOLOCATION=true \
        "$H2H_BIN/netbird-server" --config "$D/srv/config.yaml"
    nsenter -t "$C_PID" -n python3 -I "$H2H_KIT/lib/nb_bootstrap.py" http://10.220.0.3:8080 "$D/setup-key" > /dev/null \
        || die "NetBird bootstrap failed: $(tail -c 600 "$D/srv/server.log")"
    START=$("$H" now)
    local x pid pids=() kernel_env=()
    [[ $mode == userspace ]] && kernel_env=(NB_WG_KERNEL_DISABLED=true)
    for x in a b; do
        local nspid=$A_PID; [[ $x == b ]] && nspid=$B_PID
        H2H_SCOPE_LOG="$D/$x/up.log" spawn_sandboxed pid "$nspid" \
            env NB_STATE_DIR="$D/$x" "${kernel_env[@]}" "$H2H_BIN/netbird" up --foreground-mode \
            --management-url http://10.220.0.3:8080 --setup-key-file "$D/setup-key" --config "$D/$x/config.json" \
            --daemon-addr "unix://$D/$x/sock" --log-file "$D/$x/client.log" --disable-dns --hostname "h2h-$x"
        pids+=("$pid")
    done
    wait_for 60 sh -c "ip -n h2h-b -4 -o addr show dev wt0 | grep -q inet" || die "NetBird gave b no address: $(tail -c 600 "$D/b/client.log")"
    PEER=$(ip -n h2h-b -4 -o addr show dev wt0 | awk '{print $4}' | cut -d/ -f1)
    WATCH=$(IFS=,; echo "${pids[*]}")
    TUN_A=wt0
    TUN_B=wt0
    if [[ $mode == kernel ]]; then
        ip -n h2h-a link set wt0 mtu 1280
        ip -n h2h-b link set wt0 mtu 1280
    fi
    note version "{\"netbird\":\"$("$H2H_BIN/netbird" version | head -1)\",\"wireguard\":\"$(ip -n h2h-a -d link show wt0 | grep -q wireguard && echo kernel || echo userspace)\",\"mtu\":$(ip -n h2h-a -o link show wt0 | sed -n 's/.* mtu \\([0-9][0-9]*\\).*/\\1/p')}"
}

start_kernel_plain() {
    # Build the native WireGuard data path directly, without a coordinating daemon.
    mkdir -p "$D/keys"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    python3 -I "$H2H_KIT/lib/wg_cli_keys.py" "$D/keys"
    START=$("$H" now)
    ip -n h2h-a link add wgA type wireguard
    ip -n h2h-b link add wgB type wireguard
    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    ip netns exec h2h-a "$H2H_BIN/wg" set wgA \
        private-key "$D/keys/a.wg.private" listen-port 51820 \
        peer "$(cat "$D/keys/b.wg.public")" endpoint 10.220.0.2:51821 \
        allowed-ips 10.66.0.2/32
    ip netns exec h2h-b "$H2H_BIN/wg" set wgB \
        private-key "$D/keys/b.wg.private" listen-port 51821 \
        peer "$(cat "$D/keys/a.wg.public")" endpoint 10.220.0.1:51820 \
        allowed-ips 10.66.0.1/32
    ip netns exec h2h-a "$H2H_BIN/wg" show wgA
    ip netns exec h2h-b "$H2H_BIN/wg" show wgB
    rm -f "$D/keys/"*.private "$D/keys/"*.public "$D/keys/"*.wg.private "$D/keys/"*.wg.public
    TUN_A=wgA
    TUN_B=wgB
    PEER=10.66.0.2
    note version '{"wireguard":"kernel","method":"ip-link-add-and-wg-set","netbird":false,"mtu":1420}'
}

record_link_offloads() {
    local ethtool=${H2H_ETHTOOL_BIN:-}
    local -a arguments
    if [[ -z $ethtool ]]; then
        ethtool=$(command -v ethtool || true)
    fi
    [[ -x $ethtool ]] || die "ethtool is required to record per-row link offloads"
    arguments=(
        --system "$SYSTEM"
        --ethtool "$ethtool"
        --output-dir "$H2H_RESULTS/$H2H_CASE/offloads"
        --interface h2h-a a0 underlay
        --interface h2h-b b0 underlay
    )
    [[ -z $TUN_A ]] || arguments+=(--interface h2h-a "$TUN_A" tunnel)
    [[ -z $TUN_B ]] || arguments+=(--interface h2h-b "$TUN_B" tunnel)
    python3 -I "$H2H_KIT/lib/link_offloads.py" "${arguments[@]}" \
        || die "ethtool offload capture failed for $SYSTEM"
}

case $SYSTEM in
    underlay) START=$("$H" now); PEER=10.220.0.2 ;;
    infraternal) start_infraternal ;;
    gotatun) start_gotatun ;;
    boringtun) start_boringtun ;;
    wireguard-go) start_wireguard_go ;;
    tailscale) start_tailscale ;;
    netbird) start_netbird kernel ;;
    netbird-userspace) start_netbird userspace ;;
    kernel-plain) start_kernel_plain ;;
    *) die "unknown system $SYSTEM" ;;
esac

record_link_offloads

measure first-packet in_ns h2h-a "$H" net-wait --to "$PEER:5201" --since-ns "$START" --timeout-s 120
in_ns h2h-a ip -o link show > "$H2H_RESULTS/$H2H_CASE/links-a.txt" 2>&1 || true
pin_locality_workers
measure idle "$H" proc-idle --pids "$WATCH" --seconds "$IDLE_S"
record_memcg one

profile() { # profile <tag> <lat-count> <lat-interval-us> <tput-seconds>
    local tag=$1 count=$2 interval=$3 secs=$4 size flows ping_pid tput_pid
    local ping_client tput_client ping_raw ping_status_file tput_file tput_tmp tput_err
    local ping_status tput_status audit_status
    for size in 64 512 1400; do
        measure "lat-$tag-$size" in_ns h2h-a "$H" net-lat --to "$PEER:5201" --size "$size" --count "$count" --interval-us "$interval"
    done
    for flows in 1 8; do
        ping_raw="$H2H_RESULTS/$H2H_CASE/icmp-$tag-$flows.raw"
        ping_status_file="$H2H_RESULTS/$H2H_CASE/icmp-$tag-$flows.exit"
        tput_file="$H2H_RESULTS/$H2H_CASE/tput-$tag-$flows.json"
        tput_tmp="$tput_file.tmp"
        tput_err="$tput_file.err"
        # `ping -w` can send beyond -c while waiting for that many replies.
        # Keep this sample's -c value as the exact transmitted-probe count.
        H2H_SCOPE_PAUSE=1 \
            H2H_SCOPE_LOG="$D/icmp-scope-$tag-$flows.log" \
            H2H_SCOPE_STDOUT="$ping_raw" H2H_SCOPE_STDERR="$ping_raw" \
            spawn_in_ns ping_pid h2h-a ping -D -O -n -i 0.005 -c "$count" "$PEER"
        ping_client=$H2H_SCOPE_CLIENT_PID
        H2H_SCOPE_PAUSE=1 \
            H2H_SCOPE_LOG="$D/tput-scope-$tag-$flows.log" \
            H2H_SCOPE_STDOUT="$tput_tmp" H2H_SCOPE_STDERR="$tput_err" \
            spawn_in_ns tput_pid h2h-a "$H" net-tput --to "$PEER:5201" \
                --flows "$flows" --seconds "$secs" --pids "$WATCH"
        tput_client=$H2H_SCOPE_CLIENT_PID
        h2h_cpu_audit_start "$tag-$flows"
        kill -CONT "$ping_pid" "$tput_pid"

        tput_status=0
        if wait "$tput_client"; then
            mv "$tput_tmp" "$tput_file"
            rm -f "$tput_err"
            log "tput-$tag-$flows: $(head -c 400 "$tput_file")"
        else
            tput_status=$?
            log "tput-$tag-$flows failed: $(tail -c 400 "$tput_err")"
            mv "$tput_tmp" "$tput_file.failed" 2>/dev/null || true
        fi
        ping_status=0
        if wait "$ping_client"; then :; else ping_status=$?; fi
        printf '%s\n' "$ping_status" > "$ping_status_file"
        audit_status=0
        if h2h_cpu_audit_stop; then :; else audit_status=$?; fi
        ((tput_status == 0)) || die "throughput probe failed for $tag/$flows flows"
        ((audit_status == 0)) || die "D348 audit failed for $tag/$flows flows"
        summarize_icmp "$tag" "$flows" "$count"
    done
}

# Preserve raw ping output so the keep p99 comes from ICMP replies and cannot
# hide loss behind the harness's RTT estimator.
raw_icmp() { # raw_icmp <profile> <flows> <count> <interval-seconds>
    local tag=$1 flows=$2 count=$3 interval=$4
    local directory="$H2H_RESULTS/$H2H_CASE" raw summary status_file ping_status=0
    local deadline
    if [[ $interval == 1.0 ]]; then
        deadline=$((count + 10))
    else
        deadline=$((count / 100 + 5))
    fi
    ((deadline < 5)) && deadline=5
    mkdir -p "$directory"
    raw="$directory/icmp-$tag-$flows.raw"
    summary="$directory/icmp-$tag-$flows.summary.txt"
    status_file="$directory/icmp-$tag-$flows.exit"
    in_ns h2h-a ping -D -O -n -i "$interval" -c "$count" -w "$deadline" "$PEER" \
        > "$raw" 2>&1 || ping_status=$?
    printf '%s\n' "$ping_status" > "$status_file"
}

summarize_icmp() { # summarize_icmp <profile> <flows> <expected-count>
    local tag=$1 flows=$2 count=$3
    local directory="$H2H_RESULTS/$H2H_CASE" raw summary ping_status
    raw="$directory/icmp-$tag-$flows.raw"
    summary="$directory/icmp-$tag-$flows.summary.txt"
    ping_status=$(cat "$directory/icmp-$tag-$flows.exit")
    python3 -I "$H2H_KIT/lib/pingstat.py" --expected-sent "$count" "$raw" > "$summary"
    log "icmp-$tag-$flows: $(cat "$summary") (ping exit $ping_status)"
}
capture_soak_counters() { # capture_soak_counters <before|after>
    local phase=$1 ns
    for ns in h2h-a h2h-b h2h-u; do
        {
            printf 'namespace=%s phase=%s\n' "$ns" "$phase"
            printf '\n--- links ---\n'
            ip -n "$ns" -s link show
            printf '\n--- snmp ---\n'
            ip netns exec "$ns" cat /proc/net/snmp
            printf '\n--- netstat ---\n'
            ip netns exec "$ns" cat /proc/net/netstat
            printf '\n--- udp sockets and drops ---\n'
            ip netns exec "$ns" cat /proc/net/udp
        } > "$H2H_RESULTS/$H2H_CASE/soak-counters-$phase-$ns.txt"
    done
}

run_soak() {
    local seconds=${H2H_SOAK_SECONDS:-0} ping_pid tput_pid ping_client tput_client
    local ping_status_file ping_raw tput_file tput_tmp tput_err rc=0 ping_rc=0 audit_rc=0
    [[ $seconds == 3600 ]] || die "kept-cut soak must be exactly 3,600 seconds"
    capture_soak_counters before
    ping_raw="$H2H_RESULTS/$H2H_CASE/icmp-soak-8.raw"
    ping_status_file="$H2H_RESULTS/$H2H_CASE/icmp-soak-8.exit"
    tput_file="$H2H_RESULTS/$H2H_CASE/tput-soak-8.json"
    tput_tmp="$tput_file.tmp"
    tput_err="$tput_file.err"
    H2H_SCOPE_PAUSE=1 \
        H2H_SCOPE_LOG="$D/icmp-scope-soak-8.log" \
        H2H_SCOPE_STDOUT="$ping_raw" H2H_SCOPE_STDERR="$ping_raw" \
        spawn_in_ns ping_pid h2h-a ping -D -O -n -i 1.0 -c "$seconds" \
            -w "$((seconds + 10))" "$PEER"
    ping_client=$H2H_SCOPE_CLIENT_PID
    H2H_SCOPE_PAUSE=1 \
        H2H_SCOPE_LOG="$D/tput-scope-soak-8.log" \
        H2H_SCOPE_STDOUT="$tput_tmp" H2H_SCOPE_STDERR="$tput_err" \
        spawn_in_ns tput_pid h2h-a "$H" net-tput --to "$PEER:5201" \
            --flows 8 --seconds "$seconds" --pids "$WATCH"
    tput_client=$H2H_SCOPE_CLIENT_PID
    h2h_cpu_audit_start soak
    kill -CONT "$ping_pid" "$tput_pid"
    if wait "$tput_client"; then
        mv "$tput_tmp" "$tput_file"
        rm -f "$tput_err"
        log "tput-soak-8: $(head -c 400 "$tput_file")"
    else
        rc=$?
        log "tput-soak-8 failed: $(tail -c 400 "$tput_err")"
        mv "$tput_tmp" "$tput_file.failed" 2>/dev/null || true
    fi
    if wait "$ping_client"; then :; else ping_rc=$?; ((rc != 0)) || rc=$ping_rc; fi
    printf '%s\n' "$ping_rc" > "$ping_status_file"
    if h2h_cpu_audit_stop; then :; else audit_rc=$?; ((rc != 0)) || rc=$audit_rc; fi
    ((rc == 0 && audit_rc == 0)) \
        || die "one-hour soak workload or D348 audit failed with status $rc/$audit_rc"
    summarize_icmp soak 8 "$seconds"
    sleep 2
    capture_soak_counters after
    measure mem-after-soak "$H" proc-mem --pids "$WATCH"
}

if [[ ${H2H_SOAK_SECONDS:-0} == 3600 ]]; then
    run_soak
else
    profile lan "$LAT_COUNT" 1000 "$TPUT_S"
    measure mem-after-load "$H" proc-mem --pids "$WATCH"

    netem_set h2h-a a0 delay 99ms
    netem_set h2h-b b0 delay 99ms
    sleep 2
    profile de-in "$WAN_LAT_COUNT" 10000 "$WAN_TPUT_S"
    # Loss is at the packet layer on both egress interfaces. Two independent 2%
    # drops imply 3.96% round-trip exposure, not a single 2% end-to-end profile.
    netem_set h2h-a a0 delay 99ms loss 2%
    netem_set h2h-b b0 delay 99ms loss 2%
    sleep 2
    profile de-in-loss "$WAN_LAT_COUNT" 10000 "$WAN_TPUT_S"
    netem_clear h2h-a a0
    netem_clear h2h-b b0

    if [[ ${H2H_REORDER_CHECK:-0} == 1 ]]; then
        netem_set h2h-a a0 delay 99ms reorder 25% 50%
        netem_set h2h-b b0 delay 99ms reorder 25% 50%
        sleep 2
        profile de-in-reorder "$WAN_LAT_COUNT" 10000 "$WAN_TPUT_S"
        netem_clear h2h-a a0
        netem_clear h2h-b b0
    fi
fi

if [[ $SYSTEM == tailscale ]]; then
    note peer-scale '{"configured_peers_per_endpoint":1,"at_1000":"not supported by the two-node testcontrol fixture"}'
elif [[ $SYSTEM == infraternal ]]; then
    for x in a b; do
        nspid=$A_PID
        [[ $x == b ]] && nspid=$B_PID
        python3 -I "$H2H_KIT/lib/peer_scale.py" kernel-config --count 1000 --start 0 --output "$D/peers-$x.conf"
        nsenter -t "$nspid" -n -- "$H2H_BIN/wg" setconf infraternal0 "$D/peers-$x.conf"
        test "$(nsenter -t "$nspid" -n -- "$H2H_BIN/wg" show infraternal0 peers | wc -l)" -eq 1000 \
            || die "kernel WireGuard peer count is not 1,000 on $x"
    done
    sleep 2
    measure idle-1000 "$H" proc-idle --pids "$WATCH" --seconds "$IDLE_S"
    measure mem-1000 "$H" proc-mem --pids "$WATCH"
    record_memcg 1000
    note peer-scale '{"configured_peers_per_endpoint":1000,"method":"wg setconf"}'
elif [[ $SYSTEM == gotatun || $SYSTEM == boringtun || $SYSTEM == wireguard-go ]]; then
    case $SYSTEM in
        gotatun) peer_a=$GOTA_A_PID; peer_b=$GOTA_B_PID; iface_a=wgA; iface_b=wgB ;;
        boringtun) peer_a=$BORING_A_PID; peer_b=$BORING_B_PID; iface_a=wgA; iface_b=wgB ;;
        wireguard-go) peer_a=$WG_A_PID; peer_b=$WG_B_PID; iface_a=wgA; iface_b=wgB ;;
    esac
    nsenter -t "$peer_a" -n -m -- python3 -I "$H2H_KIT/lib/peer_scale.py" add-uapi --interface "$iface_a" --count 999 --start 1 > "$D/peers-a.json"
    nsenter -t "$peer_b" -n -m -- python3 -I "$H2H_KIT/lib/peer_scale.py" add-uapi --interface "$iface_b" --count 999 --start 1 > "$D/peers-b.json"
    sleep 2
    measure idle-1000 "$H" proc-idle --pids "$WATCH" --seconds "$IDLE_S"
    measure mem-1000 "$H" proc-mem --pids "$WATCH"
    record_memcg 1000
    note peer-scale '{"configured_peers_per_endpoint":1000,"method":"WireGuard UAPI, 999 additional non-traffic peers per endpoint"}'
fi

if [[ $SYSTEM == tailscale ]]; then
    sandboxed "$A_PID" "$H2H_BIN/tailscale" --socket="$D/a/sock" status --json \
        | python3 -c 'import json,sys; s=json.load(sys.stdin); print(json.dumps([{"cur_addr":p.get("CurAddr"),"relay":p.get("Relay")} for p in (s.get("Peer") or {}).values()]))' \
        > "$H2H_RESULTS/$H2H_CASE/path.json" || true
fi
if [[ $SYSTEM == netbird* ]]; then
    # NetBird logs whether each peer connection is peer-to-peer or relayed.
    grep -ihE 'p2p|relay' "$D/a/client.log" | tail -n 20 > "$H2H_RESULTS/$H2H_CASE/path.txt" || true
fi
log done
