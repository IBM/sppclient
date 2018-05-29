# Script to restore one or more VMWare VMs by name in SPP
# This script uses all default options for the restore
# It restores the latest copy of the VMs to the original host in test mode
# Use vmwaretestrestore.py -h for help

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
(options, args) = parser.parse_args()
if(options.vms is not None):
    options.vms = options.vms.split(",")

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.vms is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def build_vm_source():
    source = []
    for vm in options.vms:
        vminfo = get_vm_restore_info(vm)
        if(vminfo is not None):
            source.append(copy.deepcopy(vminfo))
    return source

def get_vm_restore_info(vm):
    vmdata = {}
    searchdata = {"name":vm,"hypervisorType":"vmware"}
    vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from=recovery", data=searchdata)['vms']
    if not vmsearch:
        logger.warning("Did not find recoverable VM " + vm)
        return None
    for foundvm in vmsearch:
        if(foundvm['name'] == vm):
            vmdata['href'] = foundvm['links']['self']['href']
            vmdata['metadata'] = {'name':foundvm['name']}
            vmdata['resourceType'] = "vm"
            vmdata['id'] = foundvm['id']
            vmdata['include'] = True
            vmdata['version'] = {}
            vmdata['version']['href'] = foundvm['links']['latestversion']['href']
            vmdata['version']['metadata'] = {'useLatest':True,'name':"Use Latest"}
            logger.info("Adding VM " + vm + " to restore job")
            return vmdata

def build_subpolicy():
    subpolicy = []
    subpol = {}
    subpol['type'] = "IV"
    subpol['destination'] = {"systemDefined": True}
    subpol['option'] = {}
    subpol['option']['protocolpriority'] = "iSCSI"
    subpol['option']['poweron'] = False
    subpol['option']['continueonerror'] = True
    subpol['option']['autocleanup'] = True
    subpol['option']['allowsessoverwrite'] = True
    subpol['option']['mode'] = "test"
    subpol['option']['vmscripts'] = False
    subpolicy.append(subpol)
    return subpolicy

def restore_vms():
    restore = {}
    sourceinfo = build_vm_source()
    subpolicy = build_subpolicy()
    restore['subType'] = "vmware"
    restore['spec'] = {}
    restore['spec']['source'] = sourceinfo
    restore['spec']['subpolicy'] = subpolicy
    resp = client.SppAPI(session, 'spphv').post(path='?action=restore', data=restore)
    logger.info("VMs are now being restored") 

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
restore_vms()
session.logout()
