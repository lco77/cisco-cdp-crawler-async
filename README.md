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

# Installation

CDP Crawler has minimal dependencies:

```python
pip install aiodns
pip install dotenv
pip install asyncssh
pip install ipaddress
```

You will also need to add https://github.com/lco77/cisco-catalyst-sdwan-client-async

# Configuration

Although CDP Crawler comes with default settings, it is not useable out of the box. You have to create a ".env" file and add your own settings.

## semaphore (string)
Max number of concurent AsyncIO tasks

Example:
```shell
semaphore="1000"
```

## ssh_timeout (string)
SSH connect timeout
Example:
```shell
ssh_timeout="10s"
```

## ssh_kex_algs (string)
Accepted SSH key exchange algorithms in CSV string format

Example:
```shell
ssh_kex_algs="*"
```
or
```shell
ssh_kex_algs="gss-group14-sha256,diffie-hellman-group14*"
```

## ssh_encryption_algs (string)
Accepted SSH encryption algorithms in CSV string format

Example:
```shell
ssh_encryption_algs="*"
```
or
```shell
ssh_encryption_algs="chacha20-poly1305@openssh.com,aes256*"
```

## ssh_mac_algs (string)
Accepted SSH MAC algorithms in CSV string format

Example:
```shell
ssh_mac_algs="*"
```
or
```shell
ssh_mac_algs="hmac-sha2-256*,hmac-sha256*"
```
## ssh_valid_ip_ranges (JSON list string)
IPv4 CIDRs that CDP Crawler will attempt connecting to

Example:
```shell
ssh_valid_ip_ranges=["10.0.0.0/8"]
```

## ssh_credentials (JSON object string)
SSH credentials that CDP Crawler will try in order. Note that "id" is an arbitrary reference to uniquely identify the credential

Example:
```shell
ssh_credentials=[{"id":"tacacs","username":"username","password":"password"}]
```

## vmanage_credentials (JSON object string)
Vmanage/Cisco Catalyst SDWAN Manager credentials that CDP Crawler will use to discover initials seeds. NOTE that "id" refers to the Vmanage hostname

Example:
```shell
ssh_credentials=[{"id":"hostname","username":"username","password":"password"}]
```

## csv_filename (string)
A filesystem path to a file that will contain exported results

Example:
```shell
csv_filename="./cdp_crawler.csv"
```

## dns_domains (JSON list string)
A list of DNS suffixes that will be used to resolve unreachable CDP neighbors (by mean of: does not belong to "ssh_valid_ip_ranges")

Example:
```shell
dns_domains=["companyA.com","companyB.com"]
```

## manual_seeds (JSON object string)
A dictionary of initial seeds

NOTE that "credential" property MUST refer to a valid "id" property defined in "ssh_credentials"

NOTE that "id" property MUST be equal to the CDP ID of the device. Otherwise the device will be discovered twice

Example:
```shell
manual_seeds=[{"id":"tacacs","hostname":"myhost","ip_address":"192.168.0.1","description":"Cisco Core Switch","parent":"","credential":"tacacs"}]
```

# Usage
Hmm, well. Once configured, using CDP Crawler is just about running it:

```shell
python ./cdp_crawler.py
```
