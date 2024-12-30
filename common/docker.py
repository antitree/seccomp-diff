import docker

def get_containers(with_seccomp = False):
    client = docker.from_env()
    docker_containers = client.containers.list()
    containers = dict()
    
    for dc in docker_containers:
        containers[dc.name] = {"name": dc.name}
        details = dc.attrs
        state = details.get("State", {})
        pid = state.get("Pid")
        
        if pid:
            containers[dc.name]["pid"] = pid
            host_config = details.get("HostConfig", {})
            
            # Check the seccomp status from the container's HostConfig
            security_opts = host_config.get("SecurityOpt", [])
            if security_opts: 
                seccomp_profiles = [opt for opt in security_opts if "seccomp" in opt]
                if len(seccomp_profiles) > 0:
                    containers[dc.name]["seccomp"] = seccomp_profiles[0].split("=")[1]
                else:
                    containers[dc.name]["seccomp"] = "Runtime Default"
            else: containers[dc.name]["seccomp"] = "Runtime Default"
            
            # List added capabilities
            caps = host_config.get("CapAdd", [])
            containers[dc.name]["caps"] = "\n".join(caps) if caps else None
    
    return containers
        
def legacy():
    print("WARNING: THIS FUNCTION SHOULD NOT BE CALLED")

def get_container_pids(with_seccomp = False):
    legacy()
    client = docker.from_env()
    containers = client.containers.list()
    container_pids = {}

    for container in containers:
        try:
            # Inspect the container to get detailed information
            details = container.attrs
            state = details.get("State", {})
            pid = state.get("Pid")
            
            if pid:
                # Check the seccomp status from the container's HostConfig
                if with_seccomp:
                    seccomp_profile = details.get("HostConfig", {}).get("SecurityOpt", [])
                    if any("seccomp" in opt for opt in seccomp_profile):
                        container_pids[container.name] = pid
                else: 
                    container_pids[container.name] = pid
        except Exception as e:
            print(f"Error processing container {container.name}: {e}")
    
    return container_pids

def get_container_caps(container_name):
    legacy()
    """
    Get the capabilities added to a specific container by its name.
    """
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        details = container.attrs
        host_config = details.get("HostConfig", {})
        capabilities = host_config.get("CapAdd", [])
        return capabilities if capabilities else None
    except Exception as e:
        return f"Error processing container {container_name}: {e}"

def get_container_seccomp(container_name):
    legacy()
    """
    Get the seccomp profile applied to a specific container by its name.
    """
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        details = container.attrs
        host_config = details.get("HostConfig", {})
        security_opt = host_config.get("SecurityOpt", [])
        if security_opt: 
            # print(security_opt)
            seccomp_profiles = [opt for opt in security_opt if "seccomp" in opt]
            if len(seccomp_profiles) > 0:
                seccomp_profiles = seccomp_profiles[0].split("=")[1]
            else:
                seccomp_profiles = "Runtime Default"
        else: 
            seccomp_profiles = "Runtime Default"

        return seccomp_profiles if seccomp_profiles else "Runtime Default"
    except ValueError as e:
        #return f"Error processing container {container_name}: {e}"
        return "Error"


def main():
    #container_pids = get_container_pids()
    containers = get_containers()
    if containers: 
        for name, values in containers.items():
            print(f"Container: {name}, PID: {values['pid']}")
    else:
        print("No running containers with seccomp profiles applied found.")

if __name__ == "__main__":
    main()
