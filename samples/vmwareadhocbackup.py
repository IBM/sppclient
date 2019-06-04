# Script to ad-hoc backup a VM in SPP
# Use vmwareadhocbackup.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import datetime
import time
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--filter", dest="filter", help="Filter for unique datacenter, cluster or folder name in case VM name is not unique (optional)")
parser.add_option("--vm", dest="vm", help="VM Name")
parser.add_option("--sla", dest="sla", help="SLA policy to run if VM is assigned to multiple")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.vm is None):
        print("Invalid input, use -h switch for help")
        sys.exit(1)

def find_vm():
    searchdata = {"name":options.vm,"hypervisorType":"vmware"}
    vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from=hlo", data=searchdata)['vms']
    if not vmsearch:
        logger.warning("Did not find vm " + options.vm)
        session.logout()
        sys.exit(2)
    for foundvm in vmsearch:
        if foundvm['name'] == options.vm:
            if options.filter is not None:
                if options.filter in foundvm['config']['location']:
                    return foundvm
            else:
                return foundvm
    logger.warning("Did not find vm " + options.vm)
    session.logout()
    sys.exit(3)

def backup_vm():
    vm = find_vm()
    backup = {}
    backup['resource'] = []
    backup['resource'].append(vm['links']['self']['href'])
    backup['subtype'] = "vmware"
    if len(vm['storageProfiles']) < 1:
        logger.warning("VM is not assigned to an SLA policy")
        session.logout()
        sys.exit(4)
    if options.sla is not None:
        for sp in vm['storageProfiles']:
            if sp.upper() == options.sla.upper():
                backup['slaPolicyName'] = sp
    else:
        backup['slaPolicyName'] = vm['storageProfiles'][0]
    if 'slaPolicyName' not in backup:
        logger.warning("Provided SLA policy was not found assigned to this vm")
        session.logout()
        sys.exit(5)
    try:
        response = client.SppAPI(session, 'spphv').post(path='?action=adhoc', data=backup)
        logger.info("Running backup job for vm " + options.vm)
    except:
        logger.warning("Error running backup job, please see appliance logs for details, note that concurrent runs for the same job is not supported.")

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
backup_vm()
session.logout()
