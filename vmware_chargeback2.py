#
# This script can be used for generating chargeback data for vmware in SPP
# The script uses the /api/hypervisor/vmresidency API to get storage utilizaiton per VM, per storage
# The script provides output to screen or destination file in csv
# Example:
#    python3 vmware_chargeback2.py --host="https://172.20.49.50" --user="admin" --pass="password123"
#    python3 vmware_chargeback2.py --host="https://172.20.49.50" --user="admin" --pass="password123" --dest="output.csv"
#

import json
import sys
import csv
from optparse import OptionParser
import spplib.sdk.client as client
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

def get_vm_residency():
    try:
        path = "/vmresidency"
        info = client.SppAPI(session, 'corehv').get(path=path)
        return info['residencies']
    except Exception as e:
        print("Error getting VM residency " + e)
        sys.exit(2)

def get_actual_size(size,precision=2):
    suffixes=['B','KB','MB','GB','TB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1
        size = size/1024.0
    return "%.*f%s"%(precision,size,suffixes[suffixIndex])

def run():
    data = get_vm_residency()
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
        print('{:20s} | {:30s} | {:20s} | {:10s}'.format('VM', 'Storage Server', 'SLA', 'Size'))
        print('='.ljust(100,'='))
        for line in data:
            print('{:20.20s} | {:30.30s} | {:20.20s} | {:10.10s}'.format(
                line['vmName'], line['storageServerName'], line['slaPolicyName'], get_actual_size(line['totalSize'])))

session = client.SppSession(options.host, options.username, options.password)
session.login()
run()
session.logout()
