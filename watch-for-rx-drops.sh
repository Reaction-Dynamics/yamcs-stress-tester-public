#!/usr/bin/env bash
# Watch per-socket UDP drop counters (skmem 'd' field) for a set of ports.
# Flags any increment with a timestamp, plus the receive-buffer fill at that moment.

PORTS=(9900 9901 9902 9903 9904 9905 9906 9907)
INTERVAL=0.50            # seconds between polls

declare -A prev

ts() { date '+%Y-%m-%d %H:%M:%S.%3N'; }

# Read "d r rb" for a port. Looks at v4 and v6 sockets (ss covers both).
# Missing 'd' (counter omitted while zero) is reported as 0.
read_sock() {
    local p="$1" line d r rb
    line=$(ss -uamn "sport = :$p" 2>/dev/null | grep -m1 skmem)
    [ -z "$line" ] && return 1
    d=$(printf '%s' "$line"  | sed -n 's/.*,d\([0-9]*\)).*/\1/p');  [ -z "$d" ]  && d=0
    r=$(printf '%s' "$line"  | sed -n 's/.*skmem:(r\([0-9]*\),.*/\1/p')
    rb=$(printf '%s' "$line" | sed -n 's/.*,rb\([0-9]*\),.*/\1/p')
    printf '%s %s %s' "$d" "${r:-?}" "${rb:-?}"
}

# Seed baselines so only post-startup increments are flagged.
for p in "${PORTS[@]}"; do
    if out=$(read_sock "$p"); then
        prev[$p]=${out%% *}
    else
        prev[$p]=0
        echo "$(ts) port $p: no bound socket found (will keep checking)"
    fi
done

echo "$(ts) monitoring drops on ${PORTS[*]} every ${INTERVAL}s"

while true; do
    for p in "${PORTS[@]}"; do
        out=$(read_sock "$p") || continue
        d=${out%% *}; rest=${out#* }; r=${rest%% *}; rb=${rest##* }
        if [ "$d" -gt "${prev[$p]}" ]; then
            echo "$(ts) port $p: +$(( d - prev[$p] )) drops (total $d) | rcvbuf ${r}/${rb}"
        fi
        prev[$p]=$d
    done
    sleep "$INTERVAL"
done