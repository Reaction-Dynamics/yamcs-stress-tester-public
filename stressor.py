#!/usr/bin/env python

from datetime import datetime, timezone
import gc
import logging
from logging.handlers import QueueHandler, QueueListener
import multiprocessing
import os
import queue
import random
import signal
import socket
import struct
import sys
import time
from typing import Annotated, List


import crc
import typer

app = typer.Typer()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(process)d] %(levelname)s: %(message)s'
)

#
#
#
PRIMARY_PKT_HDR_LEN_BYTES = 6     # The CCSDS primary packet header
SECONDARY_PKT_HDR_LEN_BYTES = 14  # The PUS packet header
TOTAL_PKT_HDR_LEN_BYTES = PRIMARY_PKT_HDR_LEN_BYTES + SECONDARY_PKT_HDR_LEN_BYTES
TOTAL_PKT_HDR_LEN_BITS = TOTAL_PKT_HDR_LEN_BYTES*8

ENTRY_ID_LEN_BYTES = 1
ENTRY_ID_LEN_BITS = ENTRY_ID_LEN_BYTES * 8

NUM_MEASUREMENTS = 16
MEASUREMENT_LEN_BYTES = 2
MEASUREMENT_LEN_BITS = MEASUREMENT_LEN_BYTES * 8
MEASUREMENT_MASK = (2**(MEASUREMENT_LEN_BYTES*8)) - 1

CRC_LEN_BYTES = 2
CRC_LEN_BITS = CRC_LEN_BYTES * 8

TOTAL_PKT_LEN_BYTES = TOTAL_PKT_HDR_LEN_BYTES + ENTRY_ID_LEN_BYTES + MEASUREMENT_LEN_BYTES + CRC_LEN_BYTES
TOTAL_PKT_LEN_BITS = TOTAL_PKT_LEN_BYTES * 8

#
# The CCSDS Primary Packet Header Fields
#
CCSDS_VERSION = 0  # Version 1 CCSDS Packet
CCSDS_VERSION_BIT_SIZE = 3
CCSDS_VERSION_MASK = (2**CCSDS_VERSION_BIT_SIZE)-1
CCSDS_VERSION_HEADER_HIGH_BIT_IDX = TOTAL_PKT_HDR_LEN_BITS-1
CCSDS_VERSION_HEADER_LOW_BIT_IDX = CCSDS_VERSION_HEADER_HIGH_BIT_IDX-CCSDS_VERSION_BIT_SIZE+1

CCSDS_TYPE = 0  # TM
CCSDS_TYPE_BIT_SIZE = 1
CCSDS_TYPE_MASK = (2**CCSDS_TYPE_BIT_SIZE)-1
CCSDS_TYPE_HEADER_HIGH_BIT_IDX = CCSDS_VERSION_HEADER_LOW_BIT_IDX-1
CCSDS_TYPE_HEADER_LOW_BIT_IDX = CCSDS_TYPE_HEADER_HIGH_BIT_IDX-CCSDS_TYPE_BIT_SIZE+1

CCSDS_SEC_HDR_FLAG = 1  # PUS header present
CCSDS_SEC_HDR_FLAG_BIT_SIZE = 1
CCSDS_SEC_HDR_FLAG_MASK = (2**CCSDS_SEC_HDR_FLAG_BIT_SIZE)-1
CCSDS_SEC_HDR_FLAG_HIGH_BIT_IDX = CCSDS_TYPE_HEADER_LOW_BIT_IDX - 1
CCSDS_SEC_HDR_FLAG_LOW_BIT_IDX = CCSDS_SEC_HDR_FLAG_HIGH_BIT_IDX-CCSDS_SEC_HDR_FLAG_BIT_SIZE+1

CCSDS_APID = 0  # Specified later
CCSDS_APID_BIT_SIZE = 11
CCSDS_APID_MASK = (2**CCSDS_APID_BIT_SIZE)-1
CCSDS_APID_HIGH_BIT_IDX =  CCSDS_SEC_HDR_FLAG_LOW_BIT_IDX-1
CCSDS_APID_LOW_BIT_IDX = CCSDS_APID_HIGH_BIT_IDX-CCSDS_APID_BIT_SIZE+1

CCSDS_SEQ_FLAGS = 3  # Unsegmented data
CCSDS_SEQ_FLAGS_BIT_SIZE = 2
CCSDS_SEQ_FLAGS_MASK = (2**CCSDS_SEQ_FLAGS_BIT_SIZE)-1
CCSDS_SEQ_FLAGS_HIGH_BIT_IDX = CCSDS_APID_LOW_BIT_IDX-1
CCSDS_SEQ_FLAGS_LOW_BIT_IDX = CCSDS_SEQ_FLAGS_HIGH_BIT_IDX-CCSDS_SEQ_FLAGS_BIT_SIZE+1

CCSDS_SEQ_COUNT = 0  # Will be updated later dynamically
CCSDS_SEQ_COUNT_BIT_SIZE = 14
CCSDS_SEQ_COUNT_MASK = (2**CCSDS_SEQ_COUNT_BIT_SIZE)-1
CCSDS_SEQ_COUNT_HIGH_BIT_IDX = CCSDS_SEQ_FLAGS_LOW_BIT_IDX-1
CCSDS_SEQ_COUNT_LOW_BIT_IDX = CCSDS_SEQ_COUNT_HIGH_BIT_IDX-CCSDS_SEQ_COUNT_BIT_SIZE+1

CCSDS_PKT_DATA_LEN = SECONDARY_PKT_HDR_LEN_BYTES + MEASUREMENT_LEN_BYTES - 1  # Spec calls for this to be N-1
CCSDS_PKT_DATA_LEN_BIT_SIZE = 16
CCSDS_PKT_DATA_LEN_MASK = (2**CCSDS_PKT_DATA_LEN_BIT_SIZE)-1
CCSDS_PKT_DATA_LEN_HIGH_BIT_IDX = CCSDS_SEQ_COUNT_LOW_BIT_IDX-1
CCSDS_PKT_DATA_LEN_LOW_BIT_IDX = CCSDS_PKT_DATA_LEN_HIGH_BIT_IDX-CCSDS_PKT_DATA_LEN_BIT_SIZE+1


#
# The CCSDS Secondary (PUS) Packet Header Fields
#
PUS_VERSION = 2
PUS_VERSION_BIT_SIZE = 4
PUS_VERSION_MASK = (2**PUS_VERSION_BIT_SIZE)-1
PUS_VERSION_HIGH_BIT_IDX = CCSDS_PKT_DATA_LEN_LOW_BIT_IDX-1
PUS_VERSION_LOW_BIT_IDX = PUS_VERSION_HIGH_BIT_IDX-PUS_VERSION_BIT_SIZE+1

PUS_TRS = 0  # We have not enumerated values for this script. Use "not-supported". Ignored by YAMCS anyway.
PUS_TRS_BIT_SIZE = 4
PUS_TRS_MASK = (2**PUS_TRS_BIT_SIZE)-1
PUS_TRS_HIGH_BIT_IDX = PUS_VERSION_LOW_BIT_IDX-1
PUS_TRS_LOW_BIT_IDX = PUS_TRS_HIGH_BIT_IDX-PUS_TRS_BIT_SIZE+1

PUS_MSG_TYPE_ID = 0x0319
PUS_MSG_TYPE_ID_BIT_SIZE = 16
PUS_MSG_TYPE_ID_MASK = (2**PUS_MSG_TYPE_ID_BIT_SIZE)-1
PUS_MSG_TYPE_ID_HIGH_BIT_IDX = PUS_TRS_LOW_BIT_IDX-1
PUS_MSG_TYPE_ID_LOW_BIT_IDX = PUS_MSG_TYPE_ID_HIGH_BIT_IDX-PUS_MSG_TYPE_ID_BIT_SIZE+1

PUS_MSG_TYPE_COUNTER = 0  # We don't support this
PUS_MSG_TYPE_COUNTER_BIT_SIZE = 16
PUS_MSG_TYPE_COUNTER_MASK = (2**PUS_MSG_TYPE_COUNTER_BIT_SIZE)-1
PUS_MSG_TYPE_COUNTER_HIGH_BIT_IDX = PUS_MSG_TYPE_ID_LOW_BIT_IDX-1
PUS_MSG_TYPE_COUNTER_LOW_BIT_IDX = PUS_MSG_TYPE_COUNTER_HIGH_BIT_IDX-PUS_MSG_TYPE_COUNTER_BIT_SIZE+1

PUS_DEST_ID = 0
PUS_DEST_ID_BIT_SIZE = 16
PUS_DEST_ID_MASK = (2**PUS_DEST_ID_BIT_SIZE)-1
PUS_DEST_ID_HIGH_BIT_IDX = PUS_MSG_TYPE_COUNTER_LOW_BIT_IDX-1
PUS_DEST_ID_LOW_BIT_IDX = PUS_DEST_ID_HIGH_BIT_IDX-PUS_DEST_ID_BIT_SIZE+1

PUS_PFIELD = 29  #  1958/01/01 epoch, 4-bytes for course time, 2-bytes for fractional time
PUS_PFIELD_BIT_SIZE = 8
PUS_PFIELD_MASK = (2**PUS_PFIELD_BIT_SIZE)-1
PUS_PFIELD_HIGH_BIT_IDX = PUS_DEST_ID_LOW_BIT_IDX-1
PUS_PFIELD_LOW_BIT_IDX = PUS_PFIELD_HIGH_BIT_IDX-PUS_PFIELD_BIT_SIZE+1

PUS_TFIELD = 0  # To be filled in dynamically
PUS_TFIELD_BIT_SIZE = 48
PUS_TFIELD_MASK = (2**PUS_TFIELD_BIT_SIZE)-1
PUS_TFIELD_HIGH_BIT_IDX = PUS_PFIELD_LOW_BIT_IDX-1
PUS_TFIELD_LOW_BIT_IDX = PUS_TFIELD_HIGH_BIT_IDX-PUS_TFIELD_BIT_SIZE+1

#
#
#
CUC_EPOCH = datetime(1958, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
EPOCH_OFFSET_NS = int((UNIX_EPOCH - CUC_EPOCH).total_seconds()) * 1_000_000_000


#
# CRC-16-CCITT Setup
#
CCSDS_CRC_CONFIG = crc.Configuration(
    width=16,
    polynomial=0x1021,
    init_value=0xFFFF,      # CCSDS uses 0xFFFF (unlike XMODEM's 0x0000)
    final_xor_value=0x0000,
    reverse_input=False,
    reverse_output=False
)
crc_calculator = crc.Calculator(CCSDS_CRC_CONFIG, optimized=True)


def create_pkt_hdr() -> int:
    ''' Returns a packet header generated from initial values
    '''
    retval = 0
    retval += CCSDS_VERSION << CCSDS_VERSION_HEADER_LOW_BIT_IDX
    retval += CCSDS_TYPE << CCSDS_TYPE_HEADER_LOW_BIT_IDX
    retval += CCSDS_SEC_HDR_FLAG << CCSDS_SEC_HDR_FLAG_LOW_BIT_IDX
    retval += CCSDS_APID << CCSDS_APID_LOW_BIT_IDX
    retval += CCSDS_SEQ_FLAGS << CCSDS_SEQ_FLAGS_LOW_BIT_IDX
    retval += CCSDS_SEQ_COUNT << CCSDS_SEQ_COUNT_LOW_BIT_IDX
    retval += CCSDS_PKT_DATA_LEN << CCSDS_PKT_DATA_LEN_LOW_BIT_IDX
    retval += PUS_VERSION << PUS_VERSION_LOW_BIT_IDX
    retval += PUS_TRS << PUS_TRS_LOW_BIT_IDX
    retval += PUS_MSG_TYPE_ID << PUS_MSG_TYPE_ID_LOW_BIT_IDX
    retval += PUS_MSG_TYPE_COUNTER << PUS_MSG_TYPE_COUNTER_LOW_BIT_IDX
    retval += PUS_DEST_ID << PUS_DEST_ID_LOW_BIT_IDX
    retval += PUS_PFIELD << PUS_PFIELD_LOW_BIT_IDX
    retval += PUS_TFIELD << PUS_TFIELD_LOW_BIT_IDX
    return retval


def update_pkt_hdr(pkt_hdr: int, apid: int, seq_count: int, ts: int) -> int:
    ''' Retuns the packet header with updated values for dynamic fields

        The APID, sequence count and timestamp are adjusted in the packet

    '''
    # Everyone loves bit manipulation puzzles....
    #   - Zero out the bits in the packet header for the field being adjusted
    #   - OR in the new field value
    retval = pkt_hdr
    retval = (retval & ~(CCSDS_APID_MASK << CCSDS_APID_LOW_BIT_IDX)) | \
             ((apid & CCSDS_APID_MASK) << CCSDS_APID_LOW_BIT_IDX)
    retval = (retval & ~(CCSDS_SEQ_COUNT_MASK << CCSDS_SEQ_COUNT_LOW_BIT_IDX)) | \
             ((seq_count & CCSDS_SEQ_COUNT_MASK) << CCSDS_SEQ_COUNT_LOW_BIT_IDX)
    retval = (retval & ~(PUS_TFIELD_MASK << PUS_TFIELD_LOW_BIT_IDX)) | \
             ((ts & PUS_TFIELD_MASK) << PUS_TFIELD_LOW_BIT_IDX)
    return retval


def gen_timestamp():
    ''' Generate current time as a timestamp in CUC format
    '''
    ns_since_cuc_epoc = time.time_ns() + EPOCH_OFFSET_NS
    course_sec, remainder_ns = divmod(ns_since_cuc_epoc, 1_000_000_000)
    fine_frac = (remainder_ns << 16) // 1_000_000_000
    ts = (course_sec << 16) | fine_frac
    return ts



def subproc_main(pkt_rate_hz: int, apid: int, ip_addr: str, port: int):
    # sys.setswitchinterval(0.0005)   # 500 µs
    # gc.disable()

    # Setup logging to use a queue, so that the messages can be
    # printer to STDOUT on a seperate thread so as to not block
    # the main thread (the signal handlers)
    # log -> QueueHanlder -> Q -> QueueListener -> StdOut Stream
    log_q = queue.SimpleQueue()
    formatter = logging.Formatter('%(asctime)s [%(process)d] %(levelname)s: %(message)s')
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    listener = QueueListener(log_q, stream_handler)
    listener.start()
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers[:] = [QueueHandler(log_q)]

    logger.info(f"Stressor (PID={os.getpid()}, APID={apid}, port={port}) starting up...")

    # Setup signal handler to gracefully handle terminate.
    # NOTE: We ignore the
    def _on_terminate(signum, frame):
        logger.info(f"Stressor (PID={os.getpid()}, APID={apid}, port={port}) exiting...")
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
        signal.setitimer(signal.ITIMER_REAL, 0, 0)
        sys.exit(0)
    signal.signal(signal.SIGTERM, _on_terminate)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Connect to YAMCS
    # WARN: We need the socket to be in non-blocking state so that backpressure from
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.connect((ip_addr, port))


    # Starting state
    in_handler = False  # Guard to prevent re-entrancy
    seq_count = 0
    last_measured_seq_count = 0
    measurements = [0] * NUM_MEASUREMENTS
    conn_error_count = 0
    last_measured_conn_error_count = 0
    missed_deadlines_count = 0
    last_measured_missed_deadlines_count = 0
    backpressure_drops_count = 0
    last_measured_backpressure_drops_count = 0
    pkt_hdr = create_pkt_hdr()


    # The signal handler that sends packets
    def _pkt_send_handler(signum, frame):
        # NOTE: Must mark these nonlocal or will get an UnboundLocalError
        #       due to the lines that mutate them which results in
        #       rebinding the name.
        nonlocal in_handler
        nonlocal seq_count
        nonlocal measurements
        nonlocal conn_error_count
        nonlocal missed_deadlines_count
        nonlocal backpressure_drops_count
        nonlocal pkt_hdr

        # Prevent re-entrancy if the processing should fall behind and another
        # signal is received. Signals that arrive when executing the handler
        # can cause re-entrancy into the handler, which then causes the new
        # handler call to execute in place of the previous one. When the new
        # call completes, the old call resumes. This is not a new thread, it
        # is another method call with a new frame pushed on the stack.
        if in_handler:
            missed_deadlines_count += 1
            return
        in_handler = True


        # Randomly Select the measurement to send
        entry_id = random.randrange(NUM_MEASUREMENTS)

        # Construct packet
        ts = gen_timestamp()
        pkt_hdr = update_pkt_hdr(pkt_hdr, apid, seq_count, ts)
        pkt_bytes = bytearray()
        pkt_bytes += pkt_hdr.to_bytes(TOTAL_PKT_HDR_LEN_BYTES, 'big')
        pkt_bytes += entry_id.to_bytes(ENTRY_ID_LEN_BYTES, 'big')
        pkt_bytes += measurements[entry_id].to_bytes(MEASUREMENT_LEN_BYTES, 'big')
        pkt_bytes += crc_calculator.checksum(pkt_bytes).to_bytes(2, 'big')
        # Send packet
        try:
            # t0_wall = time.perf_counter()
            # t0_cpu = time.clock_gettime(time.CLOCK_THREAD_CPUTIME_ID)
            sock.send(pkt_bytes)
            # dt_wall_us = int((time.perf_counter() - t0_wall) * 1000000)
            # dt_cpu_us  = (time.clock_gettime(time.CLOCK_THREAD_CPUTIME_ID) - t0_cpu) * 1e6
            # if dt_wall_us > 500:
            #     logger.info(f"{apid}: W={dt_wall_us} C={dt_cpu_us}")
        except BlockingIOError:
            backpressure_drops_count += 1
        except (ConnectionRefusedError, ConnectionAbortedError, ConnectionResetError):
            # It's UDP, we don't care. Keep sending. Just track the number of errors.
            conn_error_count += 1

        # Update counters for next transmission
        seq_count = (seq_count + 1) & CCSDS_SEQ_COUNT_MASK
        measurements[entry_id] = (measurements[entry_id] + 1) & MEASUREMENT_MASK

        in_handler=False

    # Set up an interval timer to call the send packet method
    interval = 1.0 / pkt_rate_hz
    signal.signal(signal.SIGALRM, _pkt_send_handler)
    signal.setitimer(signal.ITIMER_REAL, interval, interval)


    # Setup a signal handler to report stats when SIGHUP is received
    def _report_stats(signum, frame):
        nonlocal seq_count
        nonlocal last_measured_seq_count
        nonlocal conn_error_count
        nonlocal last_measured_conn_error_count
        nonlocal missed_deadlines_count
        nonlocal last_measured_missed_deadlines_count
        nonlocal backpressure_drops_count
        nonlocal last_measured_backpressure_drops_count
        if seq_count < last_measured_seq_count:
            num_pkts_sent = 2**CCSDS_SEQ_COUNT_BIT_SIZE - last_measured_seq_count + seq_count
        else:
            num_pkts_sent = seq_count - last_measured_seq_count
        num_conn_errors = conn_error_count - last_measured_conn_error_count
        num_missed_deadlines = missed_deadlines_count - last_measured_missed_deadlines_count
        num_backpressure_drops = backpressure_drops_count - last_measured_backpressure_drops_count
        logger.info(f"Stats (PID={os.getpid()} APID={apid} PORT={port}) blk: {sock.getblocking()}  num pkts send: {num_pkts_sent: 4}  num conn errors: {num_conn_errors: 3}  num_backpressure_drops: {num_backpressure_drops:6}  missed deadlines: {num_missed_deadlines: 3}")
        last_measured_seq_count = seq_count
        last_measured_conn_error_count = conn_error_count
        last_measured_missed_deadlines_count = missed_deadlines_count
    signal.signal(signal.SIGHUP, _report_stats)


    # The main thread now sits idle. The packet send and stats methods
    # runs whenever they are triggered
    while True:
        signal.pause()



def setup_signal_handlers():
    """ Install signal handlers to support gracefull shutdown
    """
    def _shutdown_handler(signum, frame):
        logging.info(f"Main process caught signal {signum}. Starting shutdown...")
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
        signal.setitimer(signal.ITIMER_REAL, 0, 0)
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGHUP, _shutdown_handler)
    signal.signal(signal.SIGQUIT, _shutdown_handler)


def start_sub_procs(num_procs: int, pkt_rate_hz: int, base_apid: int, hostname: str, base_port: int) -> List:

    ip_addr = socket.gethostbyname(hostname)

    procs = []
    for i in range(num_procs):
        apid = base_apid + i
        port = base_port + i
        proc = multiprocessing.Process(target=subproc_main,
                                    kwargs=({"pkt_rate_hz": pkt_rate_hz,
                                            "apid": apid,
                                            "ip_addr": ip_addr,
                                            "port": port}),
                                    name=f"Stressor{apid}")
        procs.append(proc)
        logging.info(f"Starting stressor process with APID: {apid} on port: {port}")
        proc.start()

        # Elevate it's process priority
        #os.sched_setaffinity(proc.pid, [i+8])
        logging.info(f"Elevating priority of stressor process with APID: {apid} on port: {port}")
        os.sched_setscheduler(proc.pid, os.SCHED_FIFO, os.sched_param(40))

    return procs


def stop_sub_procs(procs: List[multiprocessing.Process]):
    for proc in procs:
        if proc.is_alive:
            proc.terminate()
            proc.join()


def start_stats_printer(procs):
    # Setup a timer to routinly trigger stats printing every
    # second
    def trigger_stats_output(signum, frame):
        logging.info(f"--- START OF STATS ---")
        for proc in procs:
            os.kill(proc.pid, signal.SIGHUP)
    signal.signal(signal.SIGALRM, trigger_stats_output)
    signal.setitimer(signal.ITIMER_REAL, 1, 1)



@app.command()
def stress(
    num_stressors: Annotated[int, typer.Option(help="Number of stressor processes to create")] = 8,
    pkt_rate_hz: Annotated[int, typer.Option(help="Packets/sec to sent packets to the server at")] = 10,
    base_apid: Annotated[int, typer.Option(help="Starting APID value to use in CCSDS packets")] = 100,
    hostname: Annotated[str, typer.Option(help="Server hostname")] = "localhost",
    base_port: Annotated[int, typer.Option(help="Starting server port to connect to")] = 9900,
):
    ''' Create N stressor processes to send packets to the server

        Each process connects to the same server given by 'hostname' but to a
        different port and using it's own APID (process N uses port, base_port+N, and
        APID, base_apid+N). All processes try to send packets at 'pkt_rate_hz'.
    '''
    procs = []
    try:
        setup_signal_handlers()
        procs = start_sub_procs(num_stressors, pkt_rate_hz, base_apid, hostname, base_port)
        start_stats_printer(procs)
        while True:
            signal.pause()
    except (KeyboardInterrupt, SystemExit):
        # Swallow these exceptions as they are the expected when the
        # program is terminated with ctrl-c or sys.exit()
        pass
    finally:
        stop_sub_procs(procs)
    sys.exit(0)


if __name__ == "__main__":
    app()
