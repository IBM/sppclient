#
# This script can be used for generating chargeback data for vmware in SPP
# Script combines data transferred values from the recovery catalog with latest managed capacity for the VM
# This provides a pre compression/dedupe approximation for the VM backup storage occupancy for base and incremental backups
# The script also outputs some other relevant information about the VM
# The script provides output to screen or destination file in csv
# Example:
#    python3 vmware_chargeback.py --host="https://172.20.49.50" --user="admin" --pass="password123"
#    python3 vmware_chargeback.py --host="https://172.20.49.50" --user="admin" --pass="password123" --dest="output.csv"
# Note: Script updated for use in 10.1.4 and up
#

import json
import time
import sys
import datetime
import csv
from optparse import OptionParser
import spplib.sdk.client as client
import copy
from requests.auth import HTTPBasicAuth
try:
    import urllib3
except ImportError:
    from requests.packages import urllib3
urllib3.disable_warnings()

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--dest", dest="dest", help="Destination output file (optional)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def get_successful_vm_info():
    try:
        path = "/catalog/recovery/hypervisorvm?embed=%28children%28properties%29%29&pageSize=100000"
        info = client.SppAPI(session, 'endeavour').get(path=path)
        return info['children']
    except Exception as e:
        print("Error getting success VM info " + e)
        sys.exit(3)

def get_vm_versions(versurl):
    try:
        versions = client.SppAPI(session, 'endeavour').get(url=versurl)
        return versions['contents']
    except Exception as e:
        print("Error getting backup count " + e)
        sys.exit(6)

def parse_successful_vm_info(vms):
    vminfoarray = []
    vminfo = {}
    for vm in vms:
        if vm['properties']['hypervisorType'] != "vmware":
            continue
        try:
            versions = get_vm_versions(vm['links']['versions']['href'])
        except:
            continue
        vminfo['vm'] = vm['name']
        vminfo['tags'] = ""
        for tag in vm['properties']['tags']:
            vminfo['tags'] = vminfo['tags'] + tag['name'] + " "
        vminfo['hypervisor'] = vm['properties']['hypervisorHostName']
        vminfo['sla'] = vm['properties']['protectionInfo']['storageProfileName']
        vminfo['protectionMethod'] = vm['properties']['protectionInfo']['storageSnapshots'][0]['storageType']
        vminfo['backupStorage'] = vm['properties']['protectionInfo']['storageInfo'].split('"')[1]
        busize = 0
        managedCap = float(vm['properties']['storageSummary']['commited'])
        for version in versions:
            versize = float(version['properties']['protectionInfo']['transferSize'])
            vermgcapsize = float(version['properties']['storageSummary']['commited'])
            #don't add data transferred for base
            if not version['properties']['protectionInfo']['baseBackup']:
                busize += versize
        vminfo['backupSize'] = get_actual_size(busize + managedCap)
        vminfo['recoveryPoints'] = len(versions)
        vminfoarray.append(copy.deepcopy(vminfo))
    return vminfoarray

def get_actual_size(size,precision=2):
    suffixes=['B','KB','MB','GB','TB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1
        size = size/1024.0
    return "%.*f%s"%(precision,size,suffixes[suffixIndex])

def run():
    suc_vms = get_successful_vm_info()
    data = parse_successful_vm_info(suc_vms)
    if options.dest is not None:
        file = open(options.dest,"w")
        csvwriter = csv.writer(file)
        count = 0
        for line in data:
            if count == 0:
                csvwriter.writerow(line.keys())
                count += 1
            csvwriter.writerow(line.values())
        file.close()
        print("Chargeback data written to " + options.dest)
    else:
        print('{:20s} | {:20s} | {:20s} | {:10s}'.format('VM', 'Hypervisor', 'SLA', 'Size'))
        print('='.ljust(80,'='))
        for line in data:
            print('{:20.20s} | {:20.20s} | {:20.20s} | {:10.10s}'.format(
                line['vm'], line['hypervisor'], line['sla'], line['backupSize']))

session = client.SppSession(options.host, options.username, options.password)
session.login()
run()
session.logout()
