#!/usr/bin/env bash
#
# End-to-end acceptance test for kernel-table ingestion + RIB leaking,
# verified via OSPFv3 AS-external route redistribution.
#
# Topology (two network namespaces):
#
#   holo-a (ASBR, router-id 10.0.0.1) --veth-- holo-b (10.0.0.2)
#     ts0 dummy, kernel table 52 carries the "Tailscale" routes
#
# Asserts:
#   a) routes in table 52 are ingested into tailscale-v6 and leaked
#      into the default IPv6 RIB through IMPORT-TAILSCALE;
#   b) the leak is originated as an OSPFv3 AS-external LSA, flooded to
#      holo-b, and installed in holo-b's IPv6 RIB;
#   c) policy-rejected routes never appear in the LSDB;
#   d) deleting the route from table 52 flushes the LSA and withdraws
#      the route on holo-b.
#
# Requires root (netns + netlink) and a built target/debug/holod.
#
set -euo pipefail
cd "$(dirname "$0")"
REPO=$(cd ../.. && pwd)

VENV=${HOLO_TEST_VENV:-$HOME/.hermes/cache/scratch/holovenv}
HOLOD=$REPO/target/debug/holod
NB=$REPO/tests/kernel-leak-bgp/nb.py
NS_A=holo-a
NS_B=holo-b
WORK=$(mktemp -d /tmp/holo-kernel-leak-ospf.XXXXXX)
GEN=$WORK/gen
SOCK_A=$WORK/a/holod.sock
SOCK_B=$WORK/b/holod.sock
PIDS=()
FAILED=0

fail() { echo "FAIL: $*"; FAILED=1; }
ok()   { echo "ok:   $*"; }

cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    ip netns del $NS_A 2>/dev/null || true
    ip netns del $NS_B 2>/dev/null || true
    rm -rf /tmp/holo-kernel-leak-ospf-last
    mkdir -p /tmp/holo-kernel-leak-ospf-last
    cp -r "$WORK/logs" /tmp/holo-kernel-leak-ospf-last/ 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

nb() { "$VENV/bin/python" "$NB" "$@"; }

assert_contains() {
    local socket=$1 path=$2 pattern=$3 out
    for _ in $(seq 150); do
        out=$(nb get "$socket" "$path" 2>/dev/null || true)
        if grep -q -- "$pattern" <<<"$out"; then ok "$path contains $pattern"; return 0; fi
        sleep 0.1
    done
    fail "$path never contained $pattern (last: ${out:0:400})"
}
assert_absent() {
    local socket=$1 path=$2 pattern=$3 out
    sleep 1
    for _ in $(seq 50); do
        out=$(nb get "$socket" "$path" 2>/dev/null || true)
        if grep -q -- "$pattern" <<<"$out"; then fail "$path unexpectedly contains $pattern"; return 0; fi
        sleep 0.1
    done
    ok "$path does not contain $pattern"
}

# --- Toolchain --------------------------------------------------------------
[ -x "$HOLOD" ] || { echo "build holod first: cargo build -p holo-daemon"; exit 1; }
[ -x "$VENV/bin/python" ] || { echo "missing venv $VENV"; exit 1; }
mkdir -p "$GEN" "$WORK/a" "$WORK/b" "$WORK/logs"
chown holo:holoadm "$WORK" "$WORK/a" "$WORK/b" "$WORK/logs"
"$VENV/bin/python" -m grpc_tools.protoc -I "$REPO/proto" \
    --python_out="$GEN" --grpc_python_out="$GEN" "$REPO/proto/holo.proto"
export HOLO_GEN=$GEN

# --- Namespaces ---------------------------------------------------------------
ip netns add $NS_A
ip netns add $NS_B
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns $NS_A
ip link set veth-b netns $NS_B
ip netns exec $NS_A ip link set lo up
ip netns exec $NS_A ip link set veth-a up
ip netns exec $NS_A ip -6 addr add fd10:0:0:1::1/64 dev veth-a
ip netns exec $NS_A ip link add ts0 type dummy
ip netns exec $NS_A ip link set ts0 up
ip netns exec $NS_B ip link set lo up
ip netns exec $NS_B ip link set veth-b up
ip netns exec $NS_B ip -6 addr add fd10:0:0:1::2/64 dev veth-b

# --- Daemon instances ---------------------------------------------------------
for inst in a b; do
    cat > "$WORK/$inst.toml" <<EOF
user = "holo"
group = "holoadm"
state_dir = "$WORK/$inst"

[logging.journald]
enabled = false

[logging.file]
enabled = true
dir = "$WORK/logs"
name = "$inst.log"
rotation = "never"
style = "compact"

[logging.stdout]
enabled = false
EOF
done
ip netns exec $NS_A "$HOLOD" -c "$WORK/a.toml" & PIDS+=($!)
ip netns exec $NS_B "$HOLOD" -c "$WORK/b.toml" & PIDS+=($!)
for sock in "$SOCK_A" "$SOCK_B"; do
    for _ in $(seq 50); do [ -S "$sock" ] && break; sleep 0.2; done
    [ -S "$sock" ] || { echo "holod did not create $sock"; exit 1; }
done

# --- Inject the "Tailscale" routes into kernel table 52 -------------------------
# (before the config commit, so the redistribute dump-on-subscribe is
# exercised, not just the live-notify path)
ip netns exec $NS_A ip -6 route add fd7a:115c:a1e0::42/128 dev ts0 table 52
ip netns exec $NS_A ip -6 route add fd00:beef::1/128 dev ts0 table 52  # policy-blocked

# --- Configuration --------------------------------------------------------------
nb commit "$SOCK_A" config-a.json
nb commit "$SOCK_B" config-b.json

RIB_A=/ietf-routing:routing/ribs/rib=name=tailscale-v6/routes/route
RIB_4A=/ietf-routing:routing/ribs/rib=name=ipv6/routes/route
RIB_4B=/ietf-routing:routing/ribs/rib=name=ipv6/routes/route
LSDB_B=/ietf-routing:routing/control-plane-protocols/control-plane-protocol=type=ietf-ospf:ospfv3,name=main/ietf-ospf:ospf/database

# a) Ingestion + policy-filtered leak on the ASBR.
assert_contains "$SOCK_A" "$RIB_A" "fd7a:115c:a1e0::42/128"
assert_contains "$SOCK_A" "$RIB_A" "fd00:beef::1/128"
assert_contains "$SOCK_A" "$RIB_4A" "fd7a:115c:a1e0::42/128"
assert_absent "$SOCK_A" "$RIB_4A" "fd00:beef::1/128"

# b) AS-external LSA flooded to holo-b and installed via SPF.
assert_contains "$SOCK_B" "$LSDB_B" "fd7a:115c:a1e0::42/128"
assert_contains "$SOCK_B" "$RIB_4B" "fd7a:115c:a1e0::42/128"

# c) Policy-rejected route never enters the LSDB.
assert_absent "$SOCK_B" "$LSDB_B" "fd00:beef::1/128"

# d) Withdrawal: delete from table 52 -> maxage LSA flooded -> route
#    withdrawn on holo-b. (The maxage LSA itself lingers in the LSDB
#    for RemoveInterval, per RFC 2328, so only the RIB is asserted.)
ip netns exec $NS_A ip -6 route del fd7a:115c:a1e0::42/128 dev ts0 table 52
assert_absent "$SOCK_B" "$RIB_4B" "fd7a:115c:a1e0::42/128"
assert_absent "$SOCK_A" "$RIB_4A" "fd7a:115c:a1e0::42/128"

# e) Kernel main table was never touched by the leak.
if ip netns exec $NS_A ip -6 route show table main | grep -q "fd00:beef::1"; then
    fail "leaked route appeared in kernel main table"
else
    ok "kernel main table untouched"
fi

if [ "$FAILED" -eq 0 ]; then
    echo "PASS: kernel-leak-ospf acceptance test"
else
    echo "FAILURES present"
    exit 1
fi
