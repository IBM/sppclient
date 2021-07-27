#
# This script displays recovery points for VMware vSphere virtual machines for each of the different repositories; it is 
# meant to mimic the behavior of the restore wizard view of recovery points in the user interface
#
# To show the recovery points for a single vm:
#  python3 vmware_recoverypoints.py --host=172.20.49.50 --user=admin --pass=password123 --vm=vmtest01
#
# To show the recovery points for a multile vms use a wild card and single quotes:
#  python3 vmware_recoverypoints.py --host=172.20.49.50 --user=admin --pass=password123 --vm='vmtest*'
#
# You can also show the total number of recovery points in each repository (backup, replicaton, object storage, archive) with the
# --totals flag


import json
import time
import sys
import datetime
from optparse import OptionParser
import spplib.sdk.client as client
import copy
from requests.auth import HTTPBasicAuth
from datetime import datetime

try:
    import urllib3
except ImportError:
    from requests.packages import urllib3
urllib3.disable_warnings()

parser = OptionParser()
parser.add_option("--host", dest="hostname", help="IBM Spectrum Protect Plus host IP or DNS")
parser.add_option("--user", dest="username", help="IBM Spectrum Protect Plus username")
parser.add_option("--pass", dest="password", help="IBM Spectrum Protect Plus password")
parser.add_option("--vm",   dest="vmname", help="VM display name; can use wildcard with quotes")
parser.add_option("--verbose", dest="verbose", help="verbose output", action="store_true")
parser.add_option("--totals", dest="totals", help="print totals", action="store_true")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def get_vm_id(vmname):
    
    vm_name_array = {}
    vm_names = []
    
    func_name = get_vm_id.__name__ + "(): "
    
    if options.verbose:
      print(func_name + "Enter with VM name " + vmname)
    
    searchdata = {"name":vmname,"hypervisorType":"vmware"}
    post_path = "/search?resourceType=vm&from=recovery"
      
    try:
      vmsearch = client.SppAPI(session, 'corehv').post(path=post_path, data=searchdata)['vms']
      
    except Exception as e:
      print(func_name + "Error with call POST to path: " + post_path)
      sys.exit(1)
      
    if not vmsearch:
      if options.verbose:
        print(func_name + "Did not find VM " + vmname)
      return ""
    for foundvm in vmsearch:
      if options.verbose:
        print(func_name + "Found " + foundvm['name'] + ":" + foundvm['id'] )
      vm_name_array['vm_name'] = foundvm['name']
      vm_name_array['vm_id'] = foundvm['id']
      vm_names.append(copy.deepcopy(vm_name_array))
      
    return vm_names

        
        
def get_vm_versions(vm_ids):
    func_name = get_vm_versions.__name__ + "(): "
    
    for vm_entry in vm_ids:  
      try:  
        get_path = "/1001/vm/"+vm_entry['vm_id']+"/version?from=recovery&embedCopies=true&omitIfNoCopies=true"
        if options.verbose:
          print(func_name + "Get path: " + get_path)
        vers_search = client.SppAPI(session, 'corehv').get(path=get_path)['versions']
        
      except Exception as e:
        print(func_name + "Error with call GET to path: " + get_path)
        sys.exit(2)
        
      if not vers_search:
        if options.verbose:
          print(func_name + "Did not reutrn information for path: " + get_path)
          
      total_copies = [0,0,0,0]
          
      h1 = "RESTORE POINT"
      h2 = "SNAPSHOT ID"
      h3 = "PARTNER ID"
      h4 = "-------------"
      print("Recovery points for VM: " + vm_entry['vm_name'])
      print("")
      print(f"{h1 : <20} {'BACKUP' : <7} {'REPLICATION' : <12} {'OBJECT STORAGE' : <15} {'ARCHIVE' : <8}")
      print(f"{h4 : <20} {'------' : <7} {'-----------' : <12} {'--------------' : <15} {'-------' : <8}")
      s3found = False
      
      for found_vers in vers_search:
        backup_date = found_vers['protectionInfo']['protectionTime']/1000
        timestamp = datetime.fromtimestamp(backup_date)
        recovery_copy = ['','','','']
        for backup_copy in found_vers['copies']:
          if backup_copy['protectionInfo']['subPolicyType'] == "BACKUP":
            rtype = "Backup"
            recovery_copy[0] = rtype
            total_copies[0] += 1
          elif backup_copy['protectionInfo']['subPolicyType'] == "REPLICATION":
            rtype = "Replication"
            recovery_copy[1] = rtype
            total_copies[1] += 1
          elif backup_copy['protectionInfo']['subPolicyType'] == "SPPOFFLOAD":
            rtype = "Object Storage"
            recovery_copy[2] = rtype
            total_copies[2] += 1
          elif backup_copy['protectionInfo']['subPolicyType'] == "SPPARCHIVE":
            rtype = "Archive"
            recovery_copy[3] = rtype
            total_copies[3] += 1
          else:
            rtype = backup_copy['protectionInfo']['subPolicyType']
            
          if options.verbose:
            print(func_name + "Found: " + timestamp.strftime('%Y-%m-%d %H:%M:%S') + ": " + rtype)
            
        print(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S') : <20} {recovery_copy[0] : <7} {recovery_copy[1] : <12} {recovery_copy[2] : <15} {recovery_copy[3] : <8}")
              
      if (options.totals):
        print(f"{'>>TOTALS' : <20} {total_copies[0] : <7} {total_copies[1] : <12} {total_copies[2] : <15} {total_copies[3] : <8}")
      print("")
          
def getConnectionInfo():
    func_name = getConnectionInfo.__name__ + "(): "
    connect = client.SppAPI(session, '').get(path="/api/lifecycle/ping")
    
    if (not connect) and (options.verbose):
      print(func_name + "Could not connect to IBM Spectrum Protect Plus Server")
    else:      
      print("Connected to IBM Spectrum Protect Plus Server: " + options.hostname + ", Version " + connect['version'] + ", Build " + connect['build'])
      print("")

def run():
    getConnectionInfo()
    
    vmids = get_vm_id(options.vmname)
    
    if vmids == "":
      print("Could not find a vm id for vm: " + options.vmname)
      sys.exit(3)

    get_vm_versions(vmids)        

# validate options
def check_input_parms():    
  if (options.hostname is None) or (options.username is None) or (options.password) is None or (options.vmname is None):
    return -1
    
  if ("https" in options.hostname):
    print("ERROR: you need to specify a host IP or DNS and not a URL")
    return -1
  
  return 0
  
# main code    
if check_input_parms() != 0:
  parser.print_help()
  exit()

hosturl = "https://" + options.hostname
session = client.SppSession(hosturl, options.username, options.password)
session.login()
run()
session.logout()
