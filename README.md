# Seccomp-Diff

Analyze binaries and containers to extract and disassemble seccomp-bpf profiles. 
This tools is designed to help you determine whether or not a given seccomp-bpf
profile is more or less constrained than others as well as give you the ground 
truth for the filters applied to a process. 


#### Features:
- Attaches to a running process (via `ptrace`) to extract its seccomp filter.
- Disassemble the BPF filter for the given seccomp profile
- Lists all allowed and blocked syscalls based on the active seccomp profile.
- Outputs a summary of system call rules for analysis.

## `seccomp_diff.py`

CLI tool that will diff two given containers' given seccomp profiles.

![](/examples/happy_shmoocon.gif)

### Useage:
```
usage: seccomp_diff.py [-h] [-k] [-d]

Get container information from Docker or Kubernetes.

optional arguments:
  -h, --help        show this help message and exit
  -k, --kubernetes  Use Kubernetes to fetch container info.
  -d, --docker      Use Docker to fetch container info (default).
```

Example: 
```bash
sudo python seccomp_diff.py -d
```
## `seccomp-dump`
Disassemble and display the seccomp-bpf profiles applied to a given process or container. 

### Useage
```
usage: seccomp_dump.py [-h] [--dump] [--summary] [--list] [--allarch] [pid]

Inspect seccomp profiles for a given PID.

positional arguments:
  pid         PID of the process to inspect

optional arguments:
  -h, --help  show this help message and exit
  --dump      Dump the raw seccomp filters
  --summary   Display a summary of the seccomp filters
  --list      Display a list of pids with seccomp filters
  --allarch   Search for all syscalls across any architecture
```
Example: List processes with seccomp profiles
```bash
python seccomp_dump.py --list
```
Example Dump given process' seccomp profile
```bash
 sudo python seccomp_dump.py --dump 436762
l0000: 20 00 00 00000004        A = [4](ARCH)
l0001: 15 00 04 c000003e        IF ARCH != X86_64: 6(l0006)
l0002: 20 00 00 00000000        A = [0](SYSCALL)
l0003: 35 00 01 40000000        jlt #0x40000000, l5
l0004: 15 00 01 ffffffff        IF SYSCALL != 0xffffffff: KILL(l0006)
l0005: 06 00 00 7ffc0000        RETURN LOG
l0006: 06 00 00 00000000        RETURN KILL
``` 

## `web.py`
A web interface for seccomp-diff to visually diff system calls. Ideal for use
within a Kubernetes cluster. 

### Useage

Example run locally:
```bash
sudo python web.py
```

Example Docker run:
```bash
docker run --rm -d antitree/seccomp-diff:latest
```

Example helm chart:
```bash
helm install seccomp-diff charts/seccomp-diff
```

### Installation:
Install required Python libraries:
```bash
pip install -r requirements.txt
```
---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Related work

https://github.com/david942j/seccomp-tools - original powerful seccomp tool set written in Ruby that inspired this project
https://github.com/kleptog/PyBPF - module that does some of the heavy lifting of the BPF struct

## Acknowledgments

- Jay Beale
- Mike Yamamoto
- Alex Page
