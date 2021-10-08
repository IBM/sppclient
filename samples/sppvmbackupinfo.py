# Script to show backup info for one or more VMs in SPP
# Use sppvmbackupinfo.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import time
import spplib.sdk.client as client
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
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.vms is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)

def get_vm_backup_info():
    buinfo = {}
    for vm in options.vms:
        searchdata = {"name":vm,"hypervisorType":"*"}
        vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from=hlo", data=searchdata)['vms']
        if not vmsearch:
            logger.warning("Did not find VM " + vm)
            break
        for foundvm in vmsearch:
            if(foundvm['name'] == vm):
                vmbudata = get_vm_version_info(foundvm)
                buinfo[foundvm['name']] = vmbudata
    prettyprint(buinfo)
    return buinfo

def get_vm_version_info(vm):
    vmbuinfo = []
    urlpath = vm['hypervisorKey'] + "/vm/" + vm['id'] + "/version?from=hlo"
    versions = client.SppAPI(session, 'corehv').get(path=urlpath)['versions']
    for version in versions:
        data = {}
        data['slaname'] = version['protectionInfo']['storageProfileName']
        data['jobname'] = version['protectionInfo']['policyName']
        data['butime'] = time.ctime(version['protectionInfo']['protectionTime']/1000)[4:].replace("  "," ")
        vmbuinfo.append(data)
    return vmbuinfo

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
get_vm_backup_info()
session.logout()
