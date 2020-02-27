import json
import logging
from optparse import OptionParser
import copy
import sys
import datetime
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--vm", dest="vm", help="Source VM Name")
parser.add_option("--disk", dest="disk", help="Source Disk Name")
parser.add_option("--target", dest="target", help="Target VM Name")
parser.add_option("--start", dest="start", help="Start date (d/m/y) for selecting restore version")
parser.add_option("--end", dest="end", help="End date (d/m/y) for selecting restore version")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.vm is None or options.target is None or options.disk is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)

def get_vm_info(vm, catalog):
    vmdata = {}
    searchdata = {"name":vm,"hypervisorType":"vmware"}
    vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from="+catalog, data=searchdata)['vms']
    if not vmsearch:
        logger.warning("Did not find VM " + vm)
        session.logout()
        sys.exit(3)
    for foundvm in vmsearch:
        if(foundvm['name'] == vm):
            return foundvm
    logger.warning("Did not find VM " + vm +  " please check spelling/capitalization")
    session.logout()
    sys.exit(3)

def get_source_disk_info(vm):
    vdisks = client.SppAPI(session, 'corehv').get(url=vm['links']['vdisks']['href'])['vdisks']
    for vdisk in vdisks:
        if vdisk['name'].upper() == options.disk.upper():
            return vdisk
    logger.warning("Did not find vDisk " + options.disk)
    session.logout()
    sys.exit(4)

def get_source_disk_version(disk):
    start = int(datetime.datetime.strptime(options.start, '%d/%m/%y').timestamp())*1000
    end = int(datetime.datetime.strptime(options.end, '%d/%m/%y').timestamp())*1000
    copies = client.SppAPI(session, 'spphv').get(url=disk['links']['copies']['href'])['copies']
    for copy in copies:
        prottime = int(copy['protectionInfo']['protectionTime'])
        if (start < prottime and prottime < end):
            version = {}
            version['href'] = copy['links']['version']['href']
            version['copy'] = {}
            version['copy']['href'] = copy['links']['self']['href']
            version['metadata'] = {}
            version['metadata']['useLatest'] = False
            version['metadata']['protectionTime'] = prottime
            return version
    logger.warning("No versions found in date range for this disk.")
    session.logout()
    sys.exit(3)

def build_target_info(targetvm):
    target = {}
    if 'cluster' in targetvm:
        target['name'] = targetvm['cluster']['name']
        target['resourceType'] = "cluster"
        target['href'] = options.host + "/api/hypervisor/" + targetvm['hypervisorKey'] + "/cluster/" + targetvm['cluster']['key'] + "?from=hlo"
    else:
        target['name'] = targetvm['hypervisorHostname']
        target['resourceType'] = "host"
        target['href'] = options.host + "/api/hypervisor/" + targetvm['hypervisorKey'] + "/host/" + targetvm['hypervisorHostKey'] + "?from=hlo"
    return target

def build_restore_request(sourcevm, targetvm, disk):
    restore = {}
    restore['subType'] = "vmware"
    restore['script'] = {"preGuest": None, "postGuest": None, "continueScriptsOnError": False}
    restore['spec'] = {}
    restore['spec']['source'] = []
    restore['spec']['subpolicy'] = []
    source = {}
    subpolicy = {}
    source['href'] = disk['links']['self']['href']
    source['metadata'] = {"name": disk['name']}
    source['resourceType'] = "vdisk"
    source['id'] = disk['id']
    source['include'] = True
    if(options.start is not None and options.end is not None):
        source['version'] = get_source_disk_version(disk)
    else:
        source['version'] = {}
        source['version']['href'] = disk['links']['latestversion']['href']
        source['version']['metadata'] = {'useLatest':True,'name':"Use Latest"}
    subpolicy['type'] = "IA"
    subpolicy['source'] = None
    subpolicy['destination'] = {}
    subpolicy['destination']['target'] = build_target_info(targetvm)
    subpolicy['destination']['mapvdisk'] = {}
    subpolicy['destination']['mapvdisk'][disk['links']['self']['href']] = {}
    subpolicy['destination']['mapvdisk'][disk['links']['self']['href']]['target'] = {"href": targetvm['links']['self']['href']}
    subpolicy['destination']['mapvdisk'][disk['links']['self']['href']]['mode'] = "persistent"
    subpolicy['option'] = {}
    subpolicy['option']['poweron'] = False
    subpolicy['option']['allowvmoverwrite'] = False
    subpolicy['option']['continueonerror'] = True
    subpolicy['option']['autocleanup'] = True
    subpolicy['option']['allowsessoverwrite'] = True
    subpolicy['option']['mode'] = "test"
    subpolicy['option']['vmscripts'] = False
    subpolicy['option']['protocolpriority'] = "iSCSI"
    subpolicy['option']['IR'] = False
    subpolicy['option']['streaming'] = False
    restore['spec']['source'].append(source)
    restore['spec']['subpolicy'].append(subpolicy)
    return restore

def restore_disk():
    restore = {}
    sourcevm = get_vm_info(options.vm, "recovery")
    targetvm = get_vm_info(options.target, "hlo")
    disk = get_source_disk_info(sourcevm)
    restore = build_restore_request(sourcevm, targetvm, disk)
    resp = client.SppAPI(session, 'spphv').post(path='?action=restore', data=restore)
    if resp['statusCode'] == 201:
        logger.info("Restore job " + resp['response']['name'] + " created and started")
    else:
        logger.error("Problem creating restore job:\n" + resp)

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
restore_disk()
session.logout()
