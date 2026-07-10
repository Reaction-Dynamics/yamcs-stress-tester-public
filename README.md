# YAMCS-STRESS-TESTER

NOTE: This README is very much a work in progress....


The repository contains:

 - Scripting to start a YAMCS server with 8 UDP data links.
 - Scripting to start a Python program to send N packets/sec of data to YAMCS
 - Scripting to watch for dropped packets at the RX socket YAMCS is using


## YAMCS

To start, stop, restart the server:

`make start-yamcs`

`make stop-yamcs`

`make restart-yamcs`


The YAMCS server runs in a docker container. On startup, docker executes the `run.sh` script to get things going. IT also attemptes to set the CPU affinity for variosu YAMCS threads using the `set_cpu_affinity.sh` script. The script assumes a minimum 16 CPU machine. If your machine is less than this, please adjust the script.


## Stressor

The main script that sends packets is written in Python and needs the 'uv' package manager. You need to make the virtual env for it before running it:

`make venv`

The script has several configurable options:

`uv run stressor.py --help`

Some pre-done settings are available via the Makefile:

`make stress-N`

Where N is the packet rate and can be, [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000]

NOTE: This script needs sudo/root to run as it needs to elevate the sender thread priorites so it will prompt you for the password.


## RX Packet Loss

A BASH script is in the repo that can be invoked to watch for dropped packets at the sockets used by the YAMCS TM data links.

`make watch-for-rx-drops`

The script monitors the output of `ss` for dropped packets on the relevent sockets and reports them.



## Additional scripting

There is a daemon that runs inside the container that set the CPU affinity for various YAMCS threads. That script is:

`set_cpu_affinity.sh`

It runs every 2 seconds after YAMCS starts and outputs it's current work to the log file:

`set_cpu_affinity.log`




