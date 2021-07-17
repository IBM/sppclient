# This script display and transverse inventory information for VMwware vSphere that has been registed in the IBM Spectrum Protect Plus
# server. It is meant to mimic of the restore wizard view of inventory when you are restoring a virtual machine
# and need to determine alternate host, hostcluster, datastore, and/or network names.
#
# To transverse vSphere inventory using the ESXi (default) view:
#  python3 vmware_recoverypoints.py --host=172.20.49.50 --user=admin --pass=password123 
#
# To transverse vSphere inventory using the cluster view:
#  python3 vmware_recoverypoints.py --host=172.20.49.50 --user=admin --pass=password123 --type=cluster
#

import json
import logging
from optparse import OptionParser
import copy
import sys
#import datetime  
from datetime import datetime
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
import time
#logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--host", dest="hostname", help="IBM Spectrum Protect Plus host IP or DNS")
parser.add_option("--user", dest="username", help="IBM Spectrum Protect Plus username")
parser.add_option("--pass", dest="password", help="IBM Spectrum Protect Plus password")
parser.add_option("--type", dest="type",     help="query type: host|cluster", default="host")
parser.add_option("--debug",dest="verbose",  help="debug output", action="store_true")

(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
  if options.username is None or options.password is None or options.hostname is None:
    print("ERROR: use -h switch for help")
    sys.exit(2)
    
  if options.type != "host" and options.type != "cluster":
    print("ERROR: you must specify a type of either host or cluster")
    sys.exit(2)
    
  if ("https" in options.hostname):
    print("ERROR: you need to specify a host IP or DNS and not a URL")
    sys.exit(2)
    
def debug_msg(function_name, message):
    if options.verbose:
      timestamp = datetime.now()
      print(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " " + function_name + message)  
      
    return       

def get_input_index(max_value):

    while True:
      value = input("Enter a number beteen <1> and <" + str(max_value) + ">  <q>=quit >")
      if value == 'q':
        return 0
        
      if value.isdigit():
        value_int = int(value)
        
        if (value_int):
          if value_int > 0 and value_int <= max_value:
            return value_int

def get_input_continue():

  while True:
      value = input("Enter <c>=continue  <q>=quit >")
      if value == 'q':
        return False
      if value == 'c':
        return True
    
def get_vcenter_info():
    func_name = get_vcenter_info.__name__ + "(): "
    debug_msg(func_name, "Enter function.") 
    
    qsp= {}
    qsp['sort'] = '[{"property":"name","direction":"ASC"}]'
    
    print("Searching for registered vCenters")
    
    try:
      vcenters = client.SppAPI(session, 'corehv').get(params=qsp)
    except Exception as e:
      print("Error retrieving hypervisors " + str(e))
      return None

    debug_msg(func_name, "Received GET response") 
    
    index = 0
    vcenter_info  = []
    
    for vcenter in vcenters['hypervisors']:
      index += 1  
      print('<{:>3}>' ' {}'.format(index, vcenter['name']))
      vcenter_data = {}
      vcenter_data['name'] = vcenter['name']    
      vcenter_data['id']   = vcenter['id']
      vcenter_info.append(vcenter_data)
      

    value = get_input_index(index)
    
    if value == 0:
      return None
      
      
    print ("this is returning")
    return vcenter_info[value-1]

def get_host_cluster_info(vcenter_infos):
    func_name = get_host_cluster_info.__name__ + "(): "
    debug_msg(func_name, "Enter function.") 
    
    qsp= {}
    qsp['sort'] = '[{"property":"name","direction":"ASC"}]'
    
    if options.type  == "host":
      query_type = "host"
      query_resp = "hosts"
      query_name = "ESXi host"
      key_type   = "hypervisorHostKey"
    elif options.type == "cluster":
      query_type = "cluster"
      query_resp = "clusters"
      query_name = "cluster"
      key_type   = "cluster.key"
    else:
      return None
      
    print("\nSearching for " + query_type + " in vCenter '" + vcenter_infos['name'] + "'" )
      
    try:
      entries = client.SppAPI(session, 'corehv').get(path='/'+vcenter_infos['id']+'/'+query_type+'?from=hlo', params=qsp)
    except Exception as e:
      print("Error retrieving hosts " + str(e))
      return None     

    debug_msg(func_name, "Received GET response") 
          
    index = 0
    host_info = []

    for host in entries[query_resp]:
      index += 1
      print('<{:>3}>' ' {}'.format(index, host['name']))
      host_data = {}
      host_data['name'] = host['name']    
      host_data['id']   = host['id']
      host_data['key_type'] = key_type
      host_data['query_type'] = query_type
      host_data['vcenter_id'] = vcenter_infos['id']
      host_data['network'] = host['links']['networks']['href']
      host_info.append(host_data)
      
    value = get_input_index(index)
    
    if value == 0:
      return None
      
    return host_info[value-1]
  
def get_size_str(size):
    func_name = get_size_str.__name__ + "(): "
    
    #um_format = '{:>4.3}'
    
    if (size <= 1024 ):
      new_size = size
      size_str = " B" 
    elif (size <= 1024**2):
      new_size = size/1024
      size_str = " KB"  
    elif (size <= 1024**3):
      new_size = size/1024**2
      size_str = " MB"    
    elif (size <= 1024**4): 
      new_size = size/1024**3
      size_str = " GB" 
    else:
      new_size = size/1024**4
      size_str = " TB" 
    
    return ('[{:>7.5}' '{}]'.format(new_size, size_str))
      
    
def get_datastore_info(host_info):
    func_name = get_datastore_info.__name__ + "(): "
    debug_msg(func_name, "Enter function.") 

    print("\nSearching for datastores in " + host_info['query_type'] + ": " + host_info['name'])

    qsp = {}
    qsp['filter'] = '[{"property":"'+host_info['key_type']+'","value":"'+host_info['id']+'","op":"="}]'
    qsp['sort'] = '[{"property":"name","direction":"ASC"}]'
              
    try:
      entries = client.SppAPI(session, 'corehv').get(path='/'+host_info['vcenter_id']+'/volume?from=hlo', params=qsp)
    except Exception as e:
      print("Error retrieving datastores " + str(e))
      return None
                
    debug_msg(func_name, "Received GET response") 
    
    for volume in entries['volumes']:
      size_str = get_size_str(volume['size'])
      print(size_str + " " + volume['name'])


def get_network_info(host_info):
    func_name = get_network_info.__name__ + "(): "
    debug_msg(func_name, "Enter function.") 

    print("\nSearching for networks in " + host_info['query_type'] + ": " + host_info['name'])

    qsp = {}
    #qsp['filter'] = '[{"property":"'+host_info['key_type']+'","value":"'+host_info['id']+'","op":"="}]'
    qsp['sort'] = '[{"property":"name","direction":"ASC"}]'
              
    try:
      entries = entries = client.SppAPI(session, '').get(path=host_info['network'][len(options.host):], params=qsp)
    except Exception as e:
      print("Error retrieving datastores " + str(e))
      return None
      
    debug_msg(func_name, "Received GET response")
                
    for network in entries['networks']:
      print(network['name'])
    
def getConnectionInfo():
    func_name = getConnectionInfo.__name__ + "(): "
    #connect = client.SppAPI(session, 'ngp').get(path="/version")
    connect = client.SppAPI(session, '').get(path="/api/lifecycle/ping")
    
    if (not connect) and (options.verbose):
      print(func_name + "Could not connect to IBM Spectrum Protect Plus Server")
    else:     
      #prettyprint(connect)
      print("Connected to IBM Spectrum Protect Plus Server: " + options.hostname + ", Version " + connect['version'] + ", Build " + connect['build'])
      print("")

#main code
validate_input()
hosturl = "https://" + options.hostname
session = client.SppSession(hosturl, options.username, options.password)
session.login()
getConnectionInfo()   

vcenter_info = get_vcenter_info()

if vcenter_info is not None:
  print ("Chose vCenter: " + vcenter_info['name'])   
  
  host_info = get_host_cluster_info(vcenter_info)
  if host_info is not None:
    get_datastore_info(host_info)
    
    if get_input_continue():
      get_network_info(host_info)
      print("\nFinished! ")
      
session.logout()
