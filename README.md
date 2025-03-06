# cisco-cdp-crawler-async
AsyncIO CDP crawler to discover devices on your network

🚀 CDP Crawler 1.0 is starting...

🔍 1 seed(s) found

🔄 Event loop is running with 2 active tasks

✅ discover_node: new node HOST_A

🔄 Event loop is running with 3 active tasks

✅ discover_node: new node HOST_B

✅ discover_node: DNS name HOST_B.mycompany.com resolved to 192.168.0.1

🔄 Event loop is running with 1 active tasks

✅ CSV results saved as ./export.csv

🔍 Discovery took 1.636002063751221 seconds

🚀 CDP Crawler 1.0 has finished.




- This is a discovery tool using DFS algorithm to discover CDP devices on your network.
- It is optimized for performances using AsyncIO.
- Tested on Cisco Catalyst/ISR/Nexus switches and router with various software releases
- Tested to discover ~2500 devices in ~100 locations wordwide under 90 seconds

# Overview

Discovery requires some "seed" device(s) to start the discovery from somewhere.

Seeds can be configured:
- manually using the "manual_seed" parameter
- dynamically from Cisco Catalyst SDWAN manager using the "vmanage_credentials" parameter

Once some seeds are configured, CDP Crawler will concurently connect to those seeds using SSH, based on a list of credentials defined in "ssh_credentials" parameter:
- credentials are tested one after another
- testing stops at first credential to succeed

Once connected to these seeds, CDP Crawler will issue commands configured in "ssh_commands" parameter:
- commands are tested one after another
- testing stops at first command to succeeed

SSH ccommand output is then passed to a parser currently written for CDP entries on Cisco routers/switches (IOS or Nexus).
- this parser will discover CDP neighbors
- CDP neighbors are then added as new seeds to continue the process, and search deeper into the network

CDP Crawler has some parameters to control the discovery process:
- "semaphore" (integer) influences the amount of concurent discovery tasks (higher is faster, lower is slower)
- "ssh_timeout" (ex: 10s) tells the SSH process how long to wait until a connection succeeds before giving up
- "ssh_kex_algs" defines what key exchange algorithms are accepted. It is a comma separated list of algorithms
- "ssh_encryption_algs" defines what encrpytion algorithms are accepted. It is a comma separated list of algorithms
- "ssh_mac_algs" defines what MAC algorithms are accepted. It is a comma separated list of algorithms
- "ssh_valid_ip_ranges" is a list of IPv4 CIDRs to restrict the scope of discovery. CDP neighbors advertising an IP outside one of these ranges are skipped, BUT:
- "dns_domains" is a list of DNS suffixes. Should the CDP neighbor advertise an IP outside of "ssh_valid_ip_ranges", CDP Crawler attempts to resolve its hostname using these suffixes. If a DNS A record is found AND it belongs to "ssh_valid_ip_ranges", then CDP Crawler attempts SSH discovery on this node.
- "cdp_skip_patterns" is a list of strings that CDP Crawler will match against the platform field of CDP neighbors. Matching neighbors are dismissed from SSH discovery. Useful for IP Phones or other types of IOT devices. NOTE that such dismissed devices are reported as discovered in the inventory. CDP Crawler will simply skip SSH into them, hence blocking further discoveries.
- "csv_filename" is a filesystem path to a file that CDP Crawler will create/overwrite with the discovery result in CSV format
