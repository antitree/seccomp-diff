import common.ptrace as ptrace
import argparse
from rich.console import Console


def main():
    """Entry point for the script."""
    parser = argparse.ArgumentParser(description="Inspect seccomp profiles for a given PID.")
    parser.add_argument("pid", type=int, nargs="?", help="PID of the process to inspect")
    parser.add_argument("--dump", action="store_true", help="Dump the raw seccomp filters")
    parser.add_argument("--summary", action="store_true", help="Display a summary of the seccomp filters")
    parser.add_argument("--list", action="store_true", help="Display a list of pids with seccomp filters")
    parser.add_argument("--allarch", action="store_true", help="Search for all syscalls across any architecture")

    args = parser.parse_args()
    
    if not args.list and args.pid is None:
        parser.error("PID is required unless --list is specified.")
        
     # If PID is provided and no other options are set, assume --dump
    if args.pid is not None and not (args.dump or args.summary or args.list or args.allarch):
        args.dump = True
    
    if args.list:
        table = ptrace.list_seccomp_pids()
        c = Console()
        c.print(table)
    else: 
        ptrace.list_seccomp_filters(args.pid, dump=args.dump, summary=args.summary, allarch=args.allarch)

if __name__ == "__main__":
    main()