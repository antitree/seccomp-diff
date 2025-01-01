from lib.pybpf.disassembler import BPFDecoder, BPFDisassembler

import os
import sys
import ctypes
import ctypes.util
import argparse
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

# Define BPF structures and constants for seccomp filters
class SockFilter(ctypes.Structure):
    """Represents a single filter instruction for seccomp."""
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32)
    ]

    def __iter__(self):
        for field_name, _ in self._fields_:
            yield getattr(self, field_name)

class SockFprog(ctypes.Structure):
    """Represents a set of seccomp filter instructions."""
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter))
    ]

    def __iter__(self):
        for field_name, _ in self._fields_:
            yield getattr(self, field_name)

def ptrace(request, pid, addr, data):
    """Wrapper for ptrace syscall to interact with a process."""
    result = libc.syscall(SYS_PTRACE, request, pid, addr, data)
    if result == -1:
        errno = ctypes.get_errno()
        if errno > 0:
            print(f"PTRACE error: {os.strerror(errno)}")
        print(f"Error PTRACE'ing the process {pid}. Are you sure you have the right permissions?")
    return result

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
    sock_fprog = SockFprog()
    no_instructions = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, 0, None)
    if no_instructions <= 0:
        print(f"WARNING: No seccomp profile found for {pid}")
        b = BPFDisassembler()
        return b.disassemble(""), b

    # Allocate buffer for the filters
    buffer = (SockFilter * no_instructions)()

    # Retrieve the actual filters
    ptrace(PTRACE_SECCOMP_GET_FILTER, pid, 0, ctypes.byref(buffer))

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

def main():
    """Entry point for the script."""
    parser = argparse.ArgumentParser(description="Inspect seccomp profiles for a given PID.")
    parser.add_argument("pid", type=int, help="PID of the process to inspect")
    parser.add_argument("--dump", action="store_true", help="Dump the raw seccomp filters")
    parser.add_argument("--summary", action="store_true", help="Display a summary of the seccomp filters")
    parser.add_argument("--allarch", action="store_true", help="Search for all syscalls across any architecture")

    args = parser.parse_args()
    list_seccomp_filters(args.pid, dump=args.dump, summary=args.summary, allarch=args.allarch)

if __name__ == "__main__":
    main()