# prisma_access_ip_api
Tool to retrieve Palo Alto Prisma Access IP Addresses through API.
API Details: https://docs.paloaltonetworks.com/prisma/prisma-access/prisma-access-panorama-admin/prisma-access-overview/prisma-access-infrastructure-ip-addresses/run-the-api-script-used-to-retrieve-ip-addresses

# Installation
You need first to have a working installation of python (> 3.6). Please refer to https://www.python.org/downloads/  
  
Once python is installed, you should have a "pip" command available in your default shell. This is the python package installer.

This script can be installed via pip:
```
pip install -U git+https://github.com/PaloAltoNetworks/prisma-access-ip-api-client.git
```

Alternately, you can clone the git repository to your desktop, and use `pip install .`from within the folder it was extracted, or run the script `run.py` directly.  
In this case, make sure `xmltodict` is installed (`pip install xmltodict`)

# Usage
If installation was made with pip, you should have a command `prisma-access-ip-api` assuming your environment variables are correct.  
On windows for example, you need to have your python install in PATH:  
- C:\Users\xxx\AppData\Local\Programs\Python\Python3xx\Scripts
- C:\Users\xxx\AppData\Local\Programs\Python\Python3xx\bin  

You can also run directly from the run.py script

```
python3 run.py -h
usage: run.py [-h] [-k KEY] [-s {all,remote_network,gp_gateway,gp_portal,clean_pipe,swg_proxy}] [-a {all,active,reserved,service_ip,auth_cache_service,network_load_balancer}] [-c {pre_allocate}] [-l {all,deployed}] [-v] [-f {csv,json,xml}] [-o OUTPUT] [-i] [-e ENV] [-n] [-v4] [-v6] [--silent]

options:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     API Key
  -s {all,remote_network,gp_gateway,gp_portal,clean_pipe,swg_proxy}, --service-type {all,remote_network,gp_gateway,gp_portal,clean_pipe,swg_proxy}
                        Service Type
  -a {all,active,reserved,service_ip,auth_cache_service,network_load_balancer}, --address-type {all,active,reserved,service_ip,auth_cache_service,network_load_balancer}
                        Address Type
  -c {pre_allocate}, --action-type {pre_allocate}
                        Action Type. Only for Mobile Users.
  -l {all,deployed}, --location {all,deployed}
                        Location
  -v, --verbose         Verbose output
  -f {csv,json,xml}, --format {csv,json,xml}
                        Output Format
  -o OUTPUT, --output OUTPUT
                        Output File (By default writes to terminal)
  -i, --ignore-ssl-warnings
                        Ignore SSL Warnings. NOT RECOMMENDED. ONLY USE WITH CAUTION
  -e ENV, --env ENV     Env for URL: api.{env}.datapath.prismaaccess.com. Default = prod
  -n, --no-subnets      Do not print subnets, only addresses
  -v4                   Print only IPv4
  -v6                   Print only IPv6
  --silent              Suppress logging (Except for error)
```
Note:  
The API key can be given as argument with -k or via the Environment variable `PRISMA_API_KEY`.  
This means:
```
run.py -k xxx yyy
```
is equivalent to
```
set PRISMA_API_KEY="xxx" 
python run.py yyy
```
or for mac/linux
```
export PRISMA_API_KEY="xxx" python run.py yyy
```
# Examples
Export all data to CSV:
```
 python .\run.py -k xxxxxx -f csv

2022-02-14 14:58:21,691 - prisma_access_ip_api - main - INFO - Output:

 Zone, service-type, entry-type, address, address-type, node_name, create_time, allow_listed
US East,remote_network,address_detail,1.1.41.152,active,US_RN,,
US East,N/A,zone_subnet,1.2.192.0/18,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,1.1.128.0/17,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,1.127.0.0/16,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,1.3.64.0/19,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,1.4.64.0/19,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,1.4.4.0/19,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,1.2.0.0/16,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,2.4.0.0/16,N/A,N/A,N/A,N/A
US East,gp_gateway,address_detail,4.5.22.71,reserved,,1631568710,False
US East,N/A,zone_subnet,1.5.192.0/18,N/A,N/A,N/A,N/A
US East,N/A,zone_subnet,5.1.128.0/17,N/A,N/A,N/A,N/A
```
Get all active IPs as JSON for gateways and display only result
```
python .\run.py -k xxx -a active -s gp_gateway --silent
{
    "status": "success",
    "result": [
        {
            "address_details": [
                {
                    "address": "4.1.2.7",
                    "serviceType": "gp_gateway",
                    "addressType": "active",
                    "create_time": 1615549490,
                    "allow_listed": false
                }
            ],
            "zone": "France North",
            "addresses": [
                "1.2.3.7"
            ],
            "zone_subnet": [
                "1.2.0.0/16",
                "2.2.0.0/15",
                "1.3.0.0/15",
                "1.4.0.0/16"
            ]
        },
        {
            "address_details": [
                {
                    "address": "4.3.2.126",
                    "serviceType": "gp_gateway",
                    "addressType": "active",
                    "create_time": 1630133943,
                    "allow_listed": false
                }
            ],
            "zone": "Germany Central",
            "addresses": [
                "1.2.3.126"
            ],
            "zone_subnet": [
                "4.4.4.0/18",
                "1.1.0.0/16",
                "1.2.0.0/16",
                "1.3.0.0/16",
                "1.3.14.0/19",
                "1.1.4.0/17",
                "1.2.0.0/16",
                "1.41.0.0/16"
            ]
        }
    ]
}
```
