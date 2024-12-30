# list seccomp pids
import os

FILTER = True

# Iterate through all the folders in /proc
print("PID    Seccomp Mode")
for pid in os.listdir('/proc'):
    if pid.isdigit():
        # Get the command of the pid
        # cmdline_path = f"/proc/{pid}/cmdline"
        # if os.path.isfile(cmdline_path):
        #     with open(cmdline_path, 'r') as cmdline_file:
        #         cmd = cmdline_file.readlines()
        #         print(cmd)
        
        status_path = f"/proc/{pid}/status"
        # Check if the status file exists for this PID
        cmd = "Unknown"
        if os.path.isfile(status_path):
            with open(status_path, 'r') as status_file:
                for line in status_file:
                    if line.startswith("Name:"):
                        cmd = line.split()[1]
                    if line.startswith("Seccomp:"):
                        seccomp_mode = line.split()[1]
                        if FILTER and int(seccomp_mode) == 0:
                            break
                        else: 
                            # Print the PID and the seccomp value
                            print(f"{cmd}({pid})    {seccomp_mode}")
                        break

