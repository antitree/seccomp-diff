from lib.pybpf.disassembler import BPFDecoder, BPFDisassembler
from common.sockfilter import SockFilter, SockFprog, RUNTIMEDEFAULT

import os
import sys
import ctypes
import ctypes.util

from rich.console import Console
from rich.table import Table
from rich import box

# Constants for ptrace and seccomp operations
PTRACE_ATTACH = 16  # Attach to a process using ptrace
PTRACE_DETACH = 17  # Detach from a process using ptrace
PTRACE_SECCOMP_GET_FILTER = 16908  # Request to get seccomp filters
SECCOMP_GET_FILTER = 0x16  # Seccomp operation to retrieve filters
SECCOMP_MODE_FILTER = 2  # Filter mode for seccomp (BPF)

# Define syscall numbers for the platform
SYS_PTRACE = 101  # Syscall number for ptrace

# Load the C standard library
libc = ctypes.CDLL(ctypes.util.find_library('c'))



def ptrace(request, pid, addr, data):
    """Wrapper for ptrace syscall to interact with a process."""
    result = libc.syscall(SYS_PTRACE, request, pid, addr, data)
    if result == -1:
        errno = ctypes.get_errno()
        if errno > 0:
            print(f"PTRACE error: {os.strerror(errno)}")
        print(f"Error PTRACE'ing the process {pid}. Are you sure you have the right permissions? {result}")
    return result

def get_default_seccomp():
    no_instructions = len(RUNTIMEDEFAULT)
    disassembler = BPFDisassembler()
    disassembled_filters = disassembler.disassemble(RUNTIMEDEFAULT)
    # Generate a syscall summary
    disassembler.syscallSummary["total"] = {"count": no_instructions}
    return disassembled_filters, disassembler

    
def get_seccomp_filters(pid):
    """Retrieve seccomp filters applied to the process with the given PID."""
    # Attach to the target process
    result = ptrace(PTRACE_ATTACH, pid, 0, 0)
    

    # Wait for the process to stop
    try: 
        os.waitpid(pid, 0)
    except ChildProcessError as e:
        print(f"Error: Either the process {pid} doesn't exist or it's not ptraceable")
        b = BPFDisassembler()
        return b.disassemble(""), b

    # Retrieve the seccomp filter length
    no_instructions = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, 0, None)
    if no_instructions <= 0:
        print(f"WARNING: No seccomp profile found for {pid}")
        b = BPFDisassembler()
        return b.disassemble(""), b

    # Allocate buffer for the filters
    buffer = (SockFilter * no_instructions)()
    fprog = SockFprog()
    fprog.len = no_instructions
    fprog.filter = ctypes.cast(buffer, ctypes.POINTER(SockFilter))

    # Retrieve the actual filters
    ptrace(PTRACE_SECCOMP_GET_FILTER, pid, 0, ctypes.byref(fprog))

    # Detach from the process
    ptrace(PTRACE_DETACH, pid, 0, 0)

    # Disassemble the filters using pybpf
    disassembler = BPFDisassembler()
    disassembled_filters = disassembler.disassemble(buffer)

    # Generate a syscall summary
    disassembler.syscallSummary["total"] = {"count": no_instructions}

    return disassembled_filters, disassembler

def list_seccomp_filters(pid, dump=False, summary=True, allarch=True):
    """Display seccomp filters applied to a process with a given PID."""
    filters, dissassembled = get_seccomp_filters(pid)
    summary_data = dissassembled.syscallSummary

    if dump:
        print("\n".join(filters))

    if summary:
        console = Console()
        table = Table(show_header=False, show_lines=True, box=box.HEAVY_EDGE, style="green", pad_edge=False)
        table.add_column(header="Syscall", justify="left", min_width=20)
        table.add_column(header=pid, justify="left", min_width=20)

        if not summary_data:
            sys.exit()

        for syscall in sorted(summary_data, key=lambda x: (isinstance(x, str), x)):
            if syscall == "total":
                continue

            count = summary_data.get(syscall, {"count": 0})["count"] if syscall in summary_data else None
            if "action" in summary_data[syscall].keys():
                action = summary_data.get(syscall, {"action": 0})["action"] if syscall in summary_data else None
            else: 
                action = -42

            if count is not None:
                table.add_row(str(syscall), str(action))

        console.print(table)

    if allarch:
        print("Filtering for non-x86-specific instructions is not implemented yet.")
        


def list_seccomp_pids():
    # Iterate through all the folders in /proc
    FILTER = True
    
    console = Console()
    table = Table(show_header=False, show_lines=True, box=box.HEAVY_EDGE, style="green", pad_edge=False)
    table.add_column(header="PID", justify="left", min_width=20)
    table.add_column(header="Seccomp Mode", justify="left", min_width=20)

    for pid in os.listdir('/proc'):
        if pid.isdigit():
            status_path = f"/proc/{pid}/status"
            # Check if the status file exists for this PID
            cmd = "Unknown"
            if os.path.isfile(status_path):
                with open(status_path, 'r') as status_file:
                    for line in status_file:
                        if line.startswith("Name:"):
                            cmd = line.split()[1]
                        if line.startswith("Seccomp_filters:"):
                            no_instructions = line.split()[1]
                            if FILTER and int(no_instructions) < 1:
                                break
                            else: 
                                # Print the PID and the seccomp value
                                table.add_row(f"{cmd}({pid})",no_instructions)
                            break
    return table