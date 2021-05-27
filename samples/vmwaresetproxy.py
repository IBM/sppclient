# Script to set proxy options for one or more VMs in SPP
# Use vmwaresetproxy.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--vms", dest="vms", help="VM name(s) (comma seperated)")
parser.add_option("--proxy", dest="proxy", help="VADP Proxy Name", default="")
parser.add_option("--site", dest="site", help="Site Name", default="")
(options, args) = parser.parse_args()
if(options.vms is not None):
    options.vms = options.vms.split(",")

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.vms is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)

def get_vm_info():
    vmarray = []
    for vm in options.vms:
        vmdata = {}
        searchdata = {"name":vm,"hypervisorType":"vmware"}
        vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from=hlo", data=searchdata)['vms']
        if not vmsearch:
            logger.error("Did not find VM " + vm)
            sys.exit(3)
        for foundvm in vmsearch:
            if(foundvm['name'] == vm):
                vmdata['name'] = vm
                vmdata['resource'] = {}
                vmdata['resource']['href'] = foundvm['links']['self']['href']
                vmdata['resource']['id'] = foundvm['id']
                vmdata['resource']['metadataPath'] = foundvm['metadataPath']
                vmdata['options'] = client.SppAPI(session, 'endeavour').get(url=foundvm['links']['options']['href'])['options']
                vmarray.append(copy.deepcopy(vmdata))
                break
    return vmarray

def get_proxy_url():
    proxies = client.SppAPI(session, 'endeavour').get(url=options.host+"/api/vadp")['vadps']
    for proxy in proxies:
        if proxy['displayName'] == options.proxy:
            return proxy['links']['self']['href']
    logger.error("Specified proxy was not found")
    sys.exit(4)

def get_site_url():
    sites = client.SppAPI(session, 'endeavour').get(url=options.host+"/api/site")['sites']
    for site in sites:
        if site['name'] == options.site:
            return site['links']['self']['href']
    logger.error("Specified site was not found")
    sys.exit(5)

def assign_vadp_to_vms():
    vminfo = get_vm_info()
    assignment = ""
    assigndata = {}
    assigndata['subtype'] = "vmware"
    assigndata['version'] = "1.0"
    if options.proxy is not "":
        assignment = get_proxy_url()
    elif options.site is not "":
        assignment = get_site_url()
    for vm in vminfo:
        assigndata['resources'] = []
        assigndata['resources'].append(vm['resource'])
        assigndata['options'] = vm['options']
        assigndata['options']['proxySelection'] = assignment
        client.SppAPI(session, 'spphv').post(path='?action=applyOptions', data=assigndata)
        print("Proxy options set for " + vm['name'])

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
assign_vadp_to_vms()
session.logout()
