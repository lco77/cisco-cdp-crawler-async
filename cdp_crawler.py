#!/usr/bin/python3
import asyncio
import json
import re
import os
import time
import aiodns
from dotenv import load_dotenv
from asyncssh import SSHClientConnection, connect
from ipaddress import IPv4Address, IPv4Network
from dataclasses import dataclass
from lib.vmanage_async import Vmanage
load_dotenv()

###############################################################################
##                                  ASYNCIO                                  ##
###############################################################################

# Semaphore wrapper to limit concurent execution
semaphore = asyncio.Semaphore(int(os.getenv("semaphore",1000)))
async def sem_task(task):
    async with semaphore:
        return await task

# Hearbeat for event loop monitoring
async def heartbeat():
    while True:
        tasks = asyncio.all_tasks()
        print(f"🔄 Event loop is running with {len(tasks)} active tasks")
        await asyncio.sleep(2)

###############################################################################
##                                  CLASSES                                  ##
###############################################################################
@dataclass
class Node:
    id:str
    hostname:str
    ip_address:IPv4Address
    parent:str|None
    description:str=""
    credential:str|None=""

    def to_csv(self):
        return f'"{self.id}","{self.hostname}","{str(self.ip_address)}","{self.parent}","{self.description}","{self.credential}"'

    def to_dict(self):
        return {"id":self.id,"hostname":self.hostname,"ip_address":str(self.ip_address),"parent":self.parent,"description":self.description,"credential":self.credential}

    def to_json(self):
        return json.dumps(self.to_dict())

@dataclass
class Credential:
    id:str
    username:str
    password:str

@dataclass
class CDPNeighbor:
    id:str
    ip_address:IPv4Address
    platform:str
    interface:str
    #mac_address:str

    def to_json(self):
        return json.dumps({"id":self.id, "ip_address":str(self.ip_address), "platform":self.platform, "interface":self.interface, "mac_address":self.mac_address}, indent=4)

###############################################################################
##                                  CONFIG                                   ##
###############################################################################

# Name
name = "CDP Crawler"
# Version
version = "1.0"

# /!\ Create a ".env" file with JSON strings to override default values below

# SSH settings
ssh_timeout = os.getenv("ssh_timeout","10s")
ssh_kex_algs = os.getenv("ssh_kex_algs","*")
ssh_encryption_algs = os.getenv("ssh_encryption_algs","*")
ssh_mac_algs = os.getenv("ssh_mac_algs","*")

# Skip CDP devices with platform field matching these values
cdp_skip_patterns = json.loads(os.getenv("cdp_skip_patterns","[]"))

# Vmanage credentials to fetch discovery seeds
vmanage_credentials = [Credential(id=e["id"],username=e["username"],password=e["password"]) for e in json.loads(os.getenv("vmanage_credentials","[]"))]

# SSH credentials - try these credentials from first to last in the list
ssh_credentials = [Credential(id=e["id"],username=e["username"],password=e["password"]) for e in json.loads(os.getenv("ssh_credentials","[]"))]

# SSH valid IP ranges - skip SSH to IPs which do not belong to these ranges
ssh_valid_ip_ranges = [IPv4Network(cidr) for cidr in json.loads(os.getenv("ssh_valid_ip_ranges","[]"))]

# DNS domains - try these domains to resolve device IP when it is unreachable (i.e. not in "ssh_valid_ip_ranges")
dns_domains = json.loads(os.getenv("dns_domains","[]"))

# CSV output file name
csv_filename = "./assets/cdp_discovery.csv"

###############################################################################
##                                FUNCTIONS                                  ##
###############################################################################

# Fetch seed nodes from Vmanage
async def get_seeds_from_vmanage(host:str,username:str,password:str)->dict[str,Node]|None:
    session = Vmanage(host=host, username=username, password=password)
    if not session.connected:
        print(f'❌ get_seeds_from_vmanage: connection to {host} failed')
        return None
    print(f'🔍 get_seeds_from_vmanage: {host}')
    devices = await sem_task(session.get_devices())
    nodes = { v.hostname:Node(id=v.hostname,hostname=v.hostname,ip_address=v.system_ip,description=v.model,parent=host) for k,v in devices.items() if v.persona == "vedge" and v.is_reachable }
    return nodes

# Acquire SSH connection to node
async def ssh_connect(node:Node, credential:Credential,timeout:str=ssh_timeout,kex_algs:str=ssh_kex_algs,encryption_algs:str=ssh_encryption_algs,mac_algs:str=ssh_mac_algs)->SSHClientConnection|None:
    try:
        connection = await sem_task(connect(host=str(node.ip_address), username=credential.username, password=credential.password, known_hosts=None, connect_timeout=timeout, kex_algs="*", encryption_algs="*", mac_algs="*"))
    except Exception as error:
        # print(error)
        return None
    return connection

# Run CMD from an existing session
async def ssh_cmd(session:SSHClientConnection, cmd:str)->str|None:
    try:
        return await sem_task(session.run(cmd, check=True))
    except Exception as error:
        #print(f'ssh_cmd: {error}')
        return None

# Parse "sh cdp entry *" or "sh cdp entry all" output
def parse_cdp_output(text)->list[CDPNeighbor]:
    neighbors = []
    separator = r"-{25,}"
    device_blocks = re.split(separator, text)
    device_blocks = [s.strip() for s in device_blocks if s.strip()]
    # split by device block
    for block in device_blocks:
        block = block.strip()
        if not block:
            continue
        # match fields
        id_match = re.search(r"Device ID:(.+)", block)
        ip_match = re.search(r"IP(?:v4)? address: ([\d\.]+)", block, re.IGNORECASE)
        platform_match = re.search(r"Platform: ([^,]+)", block)
        interface_match = re.search(r"Interface: ([^,]+)", block)
        # process fields
        if id_match:
            id = id_match.group(1).strip()
            neighbor = CDPNeighbor(
                id=id,
                ip_address=IPv4Address(ip_match.group(1)) if ip_match else None,
                platform=platform_match.group(1) if platform_match else None,
                interface=interface_match.group(1) if interface_match else None,
            )
            neighbors.append(neighbor)
    return neighbors

# Discover CDP tree from a set of seed nodes
async def discover_tree(seeds:list[Node], credentials:list[Credential])->dict[str,Node]:
    visited = {}
    tasks = [ discover_node(node=seed, credentials=credentials, visited=visited) for seed in seeds ]
    await asyncio.gather(*[sem_task(task) for task in tasks])
    return visited

# Discover a CDP node + recursion
async def discover_node(node:Node, credentials:list[Credential], visited:dict[str,Node], cdp_skip_patterns:list[str]=cdp_skip_patterns):

    # internal func to check for valid IP
    def is_in_ip_range(node:Node,ip_ranges:list[IPv4Network])->bool:
        test = [ not node.ip_address == None and node.ip_address in ip_range for ip_range in ip_ranges ]
        if any(test):
            return True
        else:
            return False

    # skip visited nodes
    if node.id in visited:
        return
    
    # add new node
    visited[node.id] = node
    print(f'✅ discover_node: new node {node.hostname}')

    # Test credentials
    connection = None
    for credential in credentials:

        # Early break for unsupported devices
        for pattern in cdp_skip_patterns:
            if node.description.startswith(pattern):
                return
        
        # Early break for unreachable devices
        if not is_in_ip_range(node,ssh_valid_ip_ranges):
            # Attempt DNS resolution
            resolver = aiodns.DNSResolver()
            dns=None
            for dns_domain in dns_domains:
                try:
                    dns = await sem_task(resolver.query(f'{node.hostname}.{dns_domain}', 'A'))
                    print(f'✅ discover_node: DNS name {node.hostname}.{dns_domain} resolved to {dns[0].host}')
                except:
                    pass
                # Ensure DNS actually points to a valid ip
                if dns:
                    node.ip_address = IPv4Address(dns[0].host)
                    if not is_in_ip_range(node,ssh_valid_ip_ranges):
                        break
            if not dns:
                return
        
        # Continue with supported device
        try:
            connection = await sem_task(ssh_connect(node=node, credential=credential))
            if connection:
                updated_node = node.to_dict()|{"credential":credential.id}
                visited[node.id] = Node(**updated_node)
                break
        except Exception as error:
            print(error)
            pass
    if not connection:
        print(f'❌ discover_node: failed to SSH into {node.hostname} ({node.description})')
        return
    
    # Test command(s)
    result = None
    neighbors = []
    for cmd in ['sh cdp entry *','sh cdp entry all']:
        result = await sem_task(ssh_cmd(connection,cmd))
        if result:
            connection.close()
            await sem_task(connection.wait_closed())
            neighbors = parse_cdp_output(result.stdout)
            break
    
    # Parse children
    children = []
    for neighbor in neighbors:
        hostname = neighbor.id.split(".")[0].upper()
        children.append(
            Node(
                id = neighbor.id,
                ip_address = neighbor.ip_address,
                parent = node.id,
                hostname = hostname,
                description = neighbor.platform
            )
        )

    # Process children
    tasks = [ discover_node(node=child, credentials=credentials, visited=visited) for child in children ]
    await asyncio.gather(*[sem_task(task) for task in tasks])

###############################################################################
##                                    MAIN                                   ##
###############################################################################

async def main():
    # start heartbeat
    asyncio.create_task(heartbeat())

    # Get some seeds
    tasks = [get_seeds_from_vmanage(host=v.id, username=v.username, password=v.password) for v in vmanage_credentials ]
    results = await asyncio.gather(*[sem_task(task) for task in tasks])
    devices = {}
    for e in results:
        devices = devices | e or {}
    seeds = [seed for k,seed in devices.items()]
    print(f'🔍 {len(seeds)} seeds found')

    # Start crawling
    tree = await sem_task(discover_tree(seeds=seeds, credentials=ssh_credentials))
    
    # Export to file
    csv = []
    csv.append('"id","hostname","ip","parent","description","credential"\n')
    for node_id, node in tree.items():
        csv.append(f'{node.to_csv()}\n')
    try:
        with open(csv_filename, "w") as f:
            f.writelines(csv)
            print(f'✅ CSV results saved as {csv_filename}')
    except Exception as error:
        print(f'❌ Error saving CSV to {csv_filename} ({error})')

if __name__ == "__main__":
    print(f'🚀 {name} {version} is starting...')
    # Fix event loop on Windows
    import platform
    if platform.system()=='Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    # Run
    try:
        start_time = time.time()
        asyncio.run(main())
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"🔍 Discovery took {elapsed_time} seconds")
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    print(f'🚀 {name} {version} has finished.')
