# Seccomp-Diff

Analyze binaries and containers to extract and disassemble seccomp-bpf profiles. 
This tools is designed to help you determine whether or not a given seccomp-bpf
profile is more or less constrained than others as well as give you the ground 
truth for the filters applied to a process.


#### Features:
- Extracts true seccomp filter from a process/container via `ptrace`
- Disassembles the seccomp-BPF filter for the given seccomp profile
- Lists all allowed and blocked syscalls based on the active seccomp profile.
- Reduces down the various actions (KILL_THREAD, KILL_PROCESS, ERRNO, BLOCK) into a restriction or an allowance for easier understanding
- Outputs a summary of system call rules for analysis.

![](/examples/demo_web.png)

## `seccomp_diff.py`

CLI tool that will diff two given containers' given seccomp profiles.

![](/examples/demo.gif)

### Usage:
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

### Usage
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



### Usage

Example run locally:
```bash
sudo pip install -r requirements.txt
sudo python web.py
```

Example Docker run:
```bash
docker run --rm -it \                                                                                                     
  --pid=host --privileged \                            
  --cap-add=SYS_PTRACE \                                             
  --security-opt seccomp=unconfined -v /var/run/docker.sock:/var/run/docker.sock \  
  -v /proc:/host/proc:ro -v /run/containerd/containerd.sock:/run/containerd/containerd.sock \
  antitree/seccomp-diff
```


Example helm chart:
```bash
helm install seccomp-diff charts/seccomp-diff
kubectl port-forward service/seccomp-diff 5000:5000
```

When running inside Kubernetes with the agent DaemonSet, set the `AGENT_ENDPOINTS`
environment variable on the web deployment to a comma-separated list of agent
service URLs (for example `http://seccomp-diff-agent.seccomp-diff.svc.cluster.local:8000`).
The web interface will query each agent for container details and seccomp
summaries.

### New DaemonSet Architecture

`seccomp-diff` can now be deployed in two parts: a lightweight web interface and
an agent that runs as a DaemonSet on every node.  The agent collects container
information, communicates with containerd and extracts seccomp bytecode.  The
web service queries each agent over HTTP and aggregates the results so a single
instance can display seccomp information for the whole cluster.

To deploy the agent use the provided `agent-daemonset.yaml` and
`agent-service.yaml` templates.  The web deployment no longer requires host
privileges because all low level operations are handled by the agents.

Example k8s deployment
```yaml
Example k8s deployment:
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
        image: antitree/seccomp-diff:latest
        securityContext:
          privileged: true  
          capabilities:
            add:
            - SYS_PTRACE  
        volumeMounts:
        - name: host-proc
          mountPath: /host/proc
          readOnly: true
        - name: docker-socket
          mountPath: /var/run/docker.sock  # OPTIONAL for Docker
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

## Current Limitations
* [ ] Only visually diffs x86_64 for now
* [ ] For k8s, data is gathered by a node agent DaemonSet. Additional features
      like RBAC hardening are still in progress


## Related work

https://github.com/david942j/seccomp-tools - original powerful seccomp tool set written in Ruby that inspired this project
https://github.com/kleptog/PyBPF - module that does some of the heavy lifting of the BPF struct

## Thanks

- Jay Beale
- Mike Yamamoto
- Alex Page

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

