# Docker Seccomp Analysis Tools

This repository contains a set of tools designed to analyze Docker containers using seccomp profiles. These tools facilitate the inspection, comparison, and validation of seccomp profiles applied to running containers.

## Tools Overview

### `get_seccomp_syscall.py`

A script that retrieves and displays the system call filters applied to a running Docker container.

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

### `seccomp_diff.py`

A script to compare two seccomp profiles and identify differences.

#### Features:
- Highlights discrepancies between profiles, such as syscalls present in one but not the other.
- Useful for ensuring profile consistency across containers or validating updates.

#### Usage:
```bash
python seccomp_diff.py <profile1.json> <profile2.json>
```
- **`<profile1.json>`**: Path to the first seccomp profile.
- **`<profile2.json>`**: Path to the second seccomp profile.

#### Example:
```bash
python seccomp_diff.py default.json updated.json
```

---

## Testing

This repository includes automated tests for the tools to ensure reliability and correctness.

### Test Setup:
- Docker must be installed and running on your system.
- Python dependencies can be installed using:
  ```bash
  pip install -r requirements.txt
  ```

### Running Tests:
Tests are written using `pytest` and can be executed with:
```bash
pytest tests/
```

#### Example Tests:
- `test_valid_filters`: Verifies that the seccomp profile matches the retrieved filters.
- `test_invalid_syscall_handling`: Ensures invalid syscalls in a profile are handled appropriately.
- `test_empty_filters`: Checks behavior when the profile is empty.

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

## Contributing

We welcome contributions to improve or extend the functionality of these tools. Feel free to fork this repository and submit a pull request.

### Guidelines:
- Follow PEP 8 coding standards.
- Include tests for new features or bug fixes.
- Provide clear commit messages and documentation.

# TODO
* [] When you have net_admin + sys_time, there does not appear to be a difference even tho instructions are different
* [] Need to support more non-x86/64 architectures
* [] Work on better support for bpf argument inspection breakdown

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments

Special thanks to the open-source community for their contributions to seccomp analysis and container security tools.


