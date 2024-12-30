# Docker Seccomp Analysis Tools

This repository contains a set of tools designed to analyze Docker containers using seccomp profiles. These tools facilitate the inspection, comparison, and validation of seccomp profiles applied to running containers.

## Tools Overview

### `seccomp_diff.py`

A script that retrieves and displays the system call filters applied to a running local containers. Ideal for testing in a container/Docker environment. 

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock --privileged --pid=host -v /proc:/host/proc:ro --cap-add=CAP_SYS_PTRACE -it antitree/seccomp-dumper python seccomp_diff.py
```

#### Features:
- Attaches to a running process (via `ptrace`) to extract its seccomp filter.
- Lists all allowed and blocked syscalls based on the active seccomp profile.
- Outputs a summary of system call rules for analysis.

#### Usage:
```bash
python get_seccomp_syscall.py <PID>
```
- **`<PID>`**: The process ID of the container to inspect.

#### Example:
```bash
python get_seccomp_syscall.py 12345
```

---

### `web.py`

Web version of seccomp_diff.py. Better for deplying into Kubernetes clusters. 

#### Features:
- Same seccomp diffing features as CLI
- Support for containerd runtimes
- Better visual display of differences
- Cross-references system calls to other users

#### Example Usage:
```bash
apiVersion: apps/v1
kind: Deployment
metadata:
  name: seccomp-diff
  labels:
    app: seccomp-diff
spec:
  replicas: 1
  selector:
    matchLabels:
      app: seccomp-diff
  template:
    metadata:
      labels:
        app: seccomp-diff
    spec:
      hostPID: true
      containers:
      - name: seccomp-diff
        image: antitree/seccomp-dumper:latest
        securityContext:
          privileged: true  # Allow ptrace and host-level access
          capabilities:
            add:
            - SYS_PTRACE  # Add ptrace capability
        volumeMounts:
        - name: host-proc
          mountPath: /host/proc
          readOnly: true
        - name: docker-socket
          mountPath: /var/run/docker.sock  # Mount Docker socket
        - name: containerd-socket
          mountPath: /var/run/containerd/containerd.sock  
        env:
        - name: PROC_PATH
          value: "/host/proc"
        command: ["flask"]
        args: ["run", "--debug"]
      volumes:
      - name: host-proc
        hostPath:
          path: /proc
      - name: docker-socket
        hostPath:
          path: /var/run/docker.sock  # Host path for Docker socket
      - name: containerd-socket
        hostPath:
          path: /var/run/containerd/containerd.sock  # Host path for Docker socket
```
---

## Prerequisites

### Dependencies:
- Python 3.8+
- Docker
- Python Libraries:
  - `docker`
  - `pytest`
  - `rich`

### Installation:
Install required Python libraries:
```bash
pip install -r requirements.txt
```
---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments

Special thanks to the following people that have provided feedback and support:
- Jay Beale


