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
            config = details.get("Config", {})
            
            # Check the seccomp status from the container's HostConfig
            security_opts = host_config.get("SecurityOpt", [])
            if security_opts: 
                seccomp_profiles = [opt for opt in security_opts if "seccomp" in opt]
                if len(seccomp_profiles) > 0:
                    containers[dc.name]["seccomp"] = seccomp_profiles[0].split("=")[1]
                else:
                    containers[dc.name]["seccomp"] = "Runtime Default"
            else: containers[dc.name]["seccomp"] = "Runtime Default"
            
            image = config.get("Image",{})
            if image:
                if "@" in image:
                    image = image.split("@")[0]
                containers[dc.name]["image"] = image
            
            # List added capabilities
            caps = host_config.get("CapAdd", [])
            containers[dc.name]["caps"] = "\n".join(caps) if caps else None
    
    return containers
        
def legacy():
    print("WARNING: THIS FUNCTION SHOULD NOT BE CALLED")


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
