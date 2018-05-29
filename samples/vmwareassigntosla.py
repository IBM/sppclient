# Script to assign one or more VMWare VMs to an SLA policy in SPP
# Use vmwareassigntosla.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import sppclient.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--vms", dest="vms", help="VM name(s) (comma seperated)")
parser.add_option("--sla", dest="sla", help="SLA Policy Name")
(options, args) = parser.parse_args()
if(options.vms is not None):
    options.vms = options.vms.split(",")

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.vms is None or options.sla is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def get_vm_info():
    vmarray = []
    for vm in options.vms:
        vmdata = {}
        searchdata = {"name":vm,"hypervisorType":"vmware"}
        vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from=hlo", data=searchdata)['vms']
        if not vmsearch:
            logger.warning("Did not find VM " + vm)
            break
        for foundvm in vmsearch:
            if(foundvm['name'] == vm):
                vmdata['href'] = foundvm['links']['self']['href']
                vmdata['id'] = foundvm['id']
                vmdata['metadataPath'] = foundvm['metadataPath']
                vmarray.append(copy.deepcopy(vmdata))
                logger.info("Adding VM " + vm + " to SLA " + options.sla)
                break
    return vmarray

def get_sla_info():
    slaarray = []
    sladata = {}
    slapols = client.SppAPI(session, 'sppsla').get()['slapolicies']
    for sla in slapols:
        if(sla['name'] == options.sla):
            sladata['href'] = sla['links']['self']['href']
            sladata['id'] = sla['id']
            sladata['name'] = sla['name']
            slaarray.append(copy.deepcopy(sladata))
            break
    if not slaarray:
        logger.error("No SLA Policy found with name " + options.sla)
        session.logout()
        sys.exit(2)
    else:
        return slaarray

def assign_vms_to_sla():
    assigndata = {}
    slainfo = get_sla_info()
    vminfo = get_vm_info()
    assigndata['subtype'] = "vmware"
    assigndata['version'] = "1.0"
    assigndata['resources'] = vminfo
    assigndata['slapolicies'] = slainfo
    resp = client.SppAPI(session, 'spphv').post(path='?action=applySLAPolicies', data=assigndata)
    logger.info("VMs are now assigned")

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
assign_vms_to_sla()
session.logout()
