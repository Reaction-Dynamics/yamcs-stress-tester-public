#!/bin/bash

SCRIPT_DIR=$(dirname ${0})
LOGFILE="${SCRIPT_DIR}/set_cpu_affinity.log"

while true; do
    # Clear the log each time so it doesn't grow
    echo "Running at: $(date)" > ${LOGFILE}

    # Get the PID of the YAMCS server
    yamcs_pid=$(ps -aux | grep '[o]rg.yamcs.YamcsServer' | awk '{print $2}')
    if [ -z "$yamcs_pid" ]; then
        echo "YAMCS PID not found. Retrying..." >> ${LOGFILE}
        sleep 2
        continue
    fi
    echo "YAMCS PID: ${yamcs_pid} >> ${LOGFILE}"


    # Set thread CPU affinity based on class
    ps -T -p "${yamcs_pid}" -o tid=,comm= | while read -r tid comm; do
        echo "Setting CPU affinity for thread: ${tid}:${comm}" >> ${LOGFILE}
        if echo "${comm}" | grep -q "UdpTmDataLink"; then
            cpus="1-4"
        elif echo "${comm}" | grep -q "RdbTableReader"; then
            cpus="5-12"
        elif echo "${comm}" | grep -q "ParameterArchiv"; then
            cpus="9"
        else
            cpus="8-15"
        fi
        taskset -p -c "${cpus}" "${tid}" | sed 's/^/  /' >> ${LOGFILE} || true
    done

    sleep 2
done