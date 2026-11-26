#!/usr/bin/env bash
#
# End-to-end acceptance test for kernel-table ingestion + RIB leaking,
# verified via RIPng route redistribution.
#
# Topology (two network namespaces):
#
#   holo-a (ASBR) --veth-- holo-b
#     ts0 dummy, kernel table 52 carries the "Tailscale" routes
#
# Asserts:
#   a) routes in table 52 are ingested into tailscale-v6 and leaked
#      into the default IPv6 RIB through IMPORT-TAILSCALE;
#   b) the leak is advertised in RIPng updates (route-type external)
#      and installed in holo-b's IPv6 RIB via ietf-rip:ripng;
#   c) policy-rejected routes are never advertised;
#   d) deleting the route from table 52 poisons it and withdraws the
#      route on holo-b.
#
# Requires root (netns + netlink) and a built target/debug/holod.
#
set -euo pipefail
cd "$(dirname "$0")"
REPO=$(cd ../.. && pwd)

VENV=${HOLO_TEST_VENV:-$HOME/.hermes/cache/scratch/holovenv}
HOLOD=$REPO/target/debug/holod
NB=$REPO/tests/kernel-leak-bgp/nb.py
NS_A=holo-rip-a
NS_B=holo-rip-b
WORK=$(mktemp -d /tmp/holo-kernel-leak-rip.XXXXXX)
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
    rm -rf /tmp/holo-kernel-leak-rip-last
    mkdir -p /tmp/holo-kernel-leak-rip-last
    cp -r "$WORK/logs" /tmp/holo-kernel-leak-rip-last/ 2>/dev/null || true
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
    return 0
}
assert_absent() {
    local socket=$1 path=$2 pattern=$3 out
    sleep 1
    for _ in $(seq 100); do
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
ip netns exec $NS_A ip -6 addr add fd10:0:0:2::1/64 dev veth-a
ip netns exec $NS_A ip link add ts0 type dummy
ip netns exec $NS_A ip link set ts0 up
ip netns exec $NS_B ip link set lo up
ip netns exec $NS_B ip link set veth-b up
ip netns exec $NS_B ip -6 addr add fd10:0:0:2::2/64 dev veth-b

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
RIP_A=/ietf-routing:routing/control-plane-protocols/control-plane-protocol=type=ietf-rip:ripng,name=main/ietf-rip:rip/ipv6/routes
RIP_B=$RIP_A

# a) Ingestion + policy-filtered leak on the ASBR.
assert_contains "$SOCK_A" "$RIB_A" "fd7a:115c:a1e0::42/128"
assert_contains "$SOCK_A" "$RIB_A" "fd00:beef::1/128"
assert_contains "$SOCK_A" "$RIB_4A" "fd7a:115c:a1e0::42/128"
assert_absent "$SOCK_A" "$RIB_4A" "fd00:beef::1/128"

# b) Redistributed route advertised in RIPng and installed via RIPng.
assert_contains "$SOCK_A" "$RIP_A" "fd7a:115c:a1e0::42/128"
assert_contains "$SOCK_A" "$RIP_A" "external"
assert_contains "$SOCK_B" "$RIP_B" "fd7a:115c:a1e0::42/128"
assert_contains "$SOCK_B" "$RIB_4B" "fd7a:115c:a1e0::42/128"

# c) Policy-rejected route is never advertised.
assert_absent "$SOCK_B" "$RIP_B" "fd00:beef::1/128"

# c2) Learned vs redistributed coexistence: B learns fd10:0:0:9::1/128
# as a connected route on lo9 and advertises it; A also gets it as a
# redistributed candidate from table 52. The learned route must win,
# must survive withdrawal of the candidate, and the candidate must be
# re-promoted when the learned route times out.
route_type_of() {
    nb get "$1" "$RIP_A" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
def find(o):
    if isinstance(o, dict):
        if "route" in o and isinstance(o["route"], list):
            return o["route"]
        for v in o.values():
            r = find(v)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = find(v)
            if r is not None:
                return r
    return None
for r in find(d) or []:
    if r.get("ipv6-prefix") == sys.argv[1]:
        print(r.get("route-type", ""))
        break
' "$2"
}
assert_route_type() {
    local prefix=$1 want=$2 got
    for _ in $(seq 150); do
        got=$(route_type_of "$SOCK_A" "$prefix" || true)
        if [ "$got" = "$want" ]; then ok "$prefix route-type $want"; return 0; fi
        sleep 0.1
    done
    fail "$prefix route-type is '$got', want '$want' entry: $(nb get "$SOCK_A" "$RIP_A" 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin)
def find(o):
    if isinstance(o, dict):
        if "route" in o and isinstance(o["route"], list): return o["route"]
        for v in o.values():
            r=find(v)
            if r is not None: return r
    elif isinstance(o, list):
        for v in o:
            r=find(v)
            if r is not None: return r
for x in find(d) or []:
    if x.get("ipv6-prefix")==sys.argv[1]: print(json.dumps(x))
' "$prefix" 2>/dev/null)"
}
ip netns exec $NS_B ip link add lo9 type dummy
ip netns exec $NS_B ip link set lo9 up
ip netns exec $NS_B ip -6 addr add fd10:0:0:9::1/128 dev lo9
cat > "$WORK/b-lo9.json" <<'EOF'
{
  "ietf-interfaces:interfaces": {
    "interface": [
      { "name": "lo9", "type": "iana-if-type:softwareLoopback",
        "ietf-ip:ipv6": {} }
    ]
  },
  "ietf-routing:routing": {
    "control-plane-protocols": {
      "control-plane-protocol": [
        {
          "type": "ietf-rip:ripng",
          "name": "main",
          "ietf-rip:rip": {
            "interfaces": { "interface": [ { "interface": "lo9" } ] }
          }
        }
      ]
    }
  }
}
EOF
nb commit "$SOCK_B" "$WORK/b-lo9.json"
sleep 2
ip netns exec $NS_A ip -6 route add fd10:0:0:9::1/128 dev ts0 table 52
assert_contains "$SOCK_A" "$RIP_A" "fd10:0:0:9::1/128"
# learned (rip) wins over the redistributed candidate
assert_route_type "fd10:0:0:9::1/128" "rip"
# withdrawing the candidate leaves the learned route untouched
ip netns exec $NS_A ip -6 route del fd10:0:0:9::1/128 dev ts0 table 52
assert_route_type "fd10:0:0:9::1/128" "rip"
# re-adding the candidate: learned still wins
ip netns exec $NS_A ip -6 route add fd10:0:0:9::1/128 dev ts0 table 52
assert_route_type "fd10:0:0:9::1/128" "rip"
# B's veth goes down: A's interface-stop invalidation drops the
# learned route (ifindex match), and the still-present redistributed
# candidate is re-promoted without waiting for any resend.
ip netns exec $NS_B ip link set veth-b down
assert_route_type "fd10:0:0:9::1/128" "external"
ip netns exec $NS_A ip -6 route del fd10:0:0:9::1/128 dev ts0 table 52

# d) Withdrawal: delete from table 52 -> poisoned -> route withdrawn.
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
    echo "PASS: kernel-leak-rip acceptance test"
else
    echo "FAILURES present"
    exit 1
fi
