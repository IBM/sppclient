# Script to restore a VMware virtual machine using IBM Spectrum Protect Plus
#
# This script allows a user to restore a single vm with IBM Spectrum Protect Plus. It allows the user to choose the following options:
# - recovery method of test, production, copy, or clone
# - recover from either the backup or replication repository
# - recover to a new VM display name, alternate ESXi host or cluster, alternate datastore, and/or alternate network
# - use streaming restore or storage vMotion
# - recovery the latest copy or a copy from a specified time range
# - actively view the job log status and reconnect to view the job log status if a disconnection occurs
#
# To simulate a preview restore (no data movement) of a virtual machine with default options; this is especially helpful
# when you are using alternate locations and want to validate the names of the resources
#  python3 vmware_recoverypoints.py --host=172.20.49.50 --user=admin --pass=password123  --vm=vmname01 --rename=newname01
#
# To clone a virtual machine with default options
#  python3 vmware_recoverypoints.py --host=172.20.49.50 --user=admin --pass=password123  --vm=vmname01 --rename=newname01 --type=clone
#
# To reconnect to a job session to view the logs in real time:
#   python3 vmware_recoverypoints.py --host=172.20.49.50 --user=admin --pass=password123  --jobname=onDemandRestore_1234567890123
#
# To clone a virtual machine from the replication repository with alternate locations
#    python3 vmware_restore.py --host=172.20.49.50 --user=admin --pass=password123 --pass=far31let --vm=pod1lnxgrp15_101 
#                              --vcenter=vcenter.company.com --esxhost=host01.company.com
#                               --datastore=spppod1h_39 --network=p1_vm3 --rename=mynewname --repo=replication --type=clone
#
# To specify a time range, you must specify both a start and end time in the YYYY-MM-DD HH:MM format, for example:
#   --start="2021-05-21 00:00" --end="2021-05-21 23:59"
# this will look for the most recent version within the date range
#
# future:
# - option to clean-up test restore
# - option to disconnect after job has submitted (do not display log)
# - option to overwrite VMDKs only (vm doesn't have to be deleted in production)

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
parser.add_option("--user",     dest="username", help="Spectrum Protect Plus username")
parser.add_option("--pass",     dest="password", help="Spectrum Protect Plus password")
parser.add_option("--vm",       dest="vm", 			 help="VM name to restore")
parser.add_option("--start",    dest="start", 	 help="start date for copy to restore from (optional)")
parser.add_option("--end",      dest="end", 		 help="end date for copy to restore from (optional)")
parser.add_option("--repo",     dest="repo",     help="repository (backup | replication (optional)", default="backup")
parser.add_option("--type",     dest="type", 	   help="restore type: test|production|clone|query (default)", default="query")
parser.add_option("--rename",   dest="rename",	 help="new vm name (optional)")
parser.add_option("--vcenter",  dest="vcenter",  help="vCenter name (required for alt. host, datastore, or network")
parser.add_option("--esxhost",  dest="esxhost",  help="ESXi host destiatnion (optional)")
parser.add_option("--cluster",  dest="cluster",  help="cluster destination (optional)")
parser.add_option("--datastore", dest="datastore", help="datastore destination (optional)")
parser.add_option("--network",  dest="network",  help="network destination (optional)")
parser.add_option("--nostream", dest="stream",   help="use storage vMotion (optional)", action="store_false", default=True)
parser.add_option("--jobname",  dest="jobname",  help="reconnect to previous restore session (opitonal)")
parser.add_option("--logging",  dest="logging",  help="logging format 1=std 2=no type", default="1")
parser.add_option("--debug",    dest="verbose",  help="debug output", action="store_true")
(options, args) = parser.parse_args()
if(options.vm is not None):
    options.vm = options.vm.split(",")

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
	if(options.username is None or options.password is None or options.hostname is None):
		print("ERROR: You must specify a hostname, username, and password")
		sys.exit(2)
	if options.jobname is None and options.vm is None:
		print("ERROR: You must specify a vm name")
		sys.exit(2)	
	if(options.start is None and options.end is not None):
		print("ERROR: Start date required if end date is defined")
		sys.exit(2)
	if(options.start is not None and options.end is None):
	  print("ERROR: End date required if start date is defined")
	  sys.exit(2)
	validTypes = ['query','production','test','clone']
	if (options.type not in validTypes):
	 	print("ERROR: Not a valid type of restore request")
	 	sys.exit(2)
	validTypes = ['backup','replication']
	if (options.repo not in validTypes):
	 	print("ERROR: Not a valid type of repository")
	 	sys.exit(2)
	if (options.esxhost and options.cluster):
		print("ERROR: You cannot specify both an ESXi host name and a cluster name as a destination")
		sys.exit(2)
	if (options.datastore or options.network):
		if not options.vcenter:
			print("ERROR: You must specify a vCenter name and ESXi host name (or cluster name) if using an alternate ESXi host, datastore, or network")
			sys.exit(2)
		if not (options.esxhost or options.cluster):	
			print("ERROR: You must specify a vCenter name and ESXi host name (or cluster name) if using an alternate ESXi host, datastore, or network")
			sys.exit(2)

	if ("https" in options.hostname):
		print("ERROR: you need to specify a host IP or DNS and not a URL")
		sys.exit(2) 	
	 	
def get_message_type(inString):
		
		if inString == "INFO":
			return "Info"
			
		if inString == "DETAIL":
			return "Detail"
			
		if inString == "WARN":
			return "Warning"
			
		if inString == "ERROR":
			return "Error"
			
		if inString == "SUMMARY":
			return "Summary"
			
		return inString       
		
	
def debug_msg(function_name, message):
		if options.verbose:
			timestamp = datetime.now()
			print(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " " + function_name + message)	
			
		return
		
msg_id_script = "MsgScript"
def print_msg(msg_time, msg_type, msg_id, msg_text):
	
		if msg_time == 0:
			msg_time = datetime.now()

		if options.logging == "1":
			print('{:19.19s} {:7.7s} {:9.9s} {:10s}'.format(msg_time.strftime('%Y-%m-%d %H:%M:%S'), msg_type, msg_id, msg_text))
			
		elif options.logging == "2":
			print('{:19.19s} {:9.9s} {:10s}'.format(msg_time.strftime('%Y-%m-%d %H:%M:%S'), msg_id, msg_text))
			
		return            
		
		
def validate_alt_location():
		func_name = validate_alt_location.__name__ + "(): "

		altData = {}
     
		if options.vcenter is None:
			debug_msg(func_name, "No alternate locations to process; returning")
			altData['bUseAltData'] = False
			return altData
			
		debug_msg(func_name, "searching for inventory reference for vcenter: " + options.vcenter)
		
		# start by getting the venter ID
		try:
			vcenters = client.SppAPI(session, 'corehv').get()
		except Exception as e:
			print("Error retrieving hypervisors " + str(e))
			return None
		
		for vcenter in vcenters['hypervisors']:
			debug_msg(func_name, "found vcenter: " + vcenter['name'] + " id: " + vcenter['id'])
			if options.vcenter == vcenter['name']:
				altData['bUseAltData'] = True
				altData['vcenter']     = vcenter['name']
				altData['vcenterId']   = vcenter['id']
				
				#resolve host if specified
				altData['host_href'] = None
				if options.esxhost is not None:
					debug_msg(func_name, "searching for inventory reference for host: " + options.esxhost)

					try:
						entries = client.SppAPI(session, 'corehv').get(path='/'+vcenter['id']+'/host?from=hlo')
					except Exception as e:
						print("Error retrieving hosts " + str(e))
						return None
						
					for host in entries['hosts']:
						debug_msg(func_name, "found host: " + host['name'] + " id=" + host['id'])
						if options.esxhost == host['name']:
							debug_msg(func_name, "found match; href=" + host['links']['self']['href'])
							altData['host_string'] = "ESXi host"
							altData['key_type'] = "hypervisorHostKey"
							altData['host_href'] = host['links']['self']['href']
							altData['host_name'] = host['name']
							altData['host_type'] = "host"
							altData['host_id']   = host['id']
							altData['host_network'] = host['links']['networks']['href']
					
					if altData['host_href'] is None:
						print ("ERROR - ESXi host: '" + options.esxhost + "' is not registered with the IBM Spectrum Protect Plus server; make sure to use the fully qualfied DNS name of the host")
						return None

				#resolve cluster if specified
				# 	https://spplusc-19.storage.tucson.ibm.com/api/hypervisor?from=hlo&pageSize=100&sort=[{"property":"name","direction":"ASC"}]&filter=[{"property":"type","value":"vmware","op":"="}]
				altData['cluster_href'] = None				
				if options.cluster is not None:
					debug_msg(func_name, "searching for inventory reference for cluster: " + options.cluster)
					
					try:
						entries = client.SppAPI(session, 'corehv').get(path='/'+vcenter['id']+'/cluster?from=hlo')
					except Exception as e:
						print("Error retrieving clusters " + str(e))
						return None
						
					for cluster in entries['clusters']:
						debug_msg(func_name, "found cluster: " + cluster['name'] + " id=" + cluster['id'])
						if options.cluster == cluster['name']:
							debug_msg(func_name, "found match; href=" + cluster['links']['self']['href'])
							altData['host_string'] = "host cluster"
							altData['key_type'] = "cluster.key"
							altData['host_id']   = cluster['id']
							altData['host_name'] = cluster['name']
							altData['host_type'] = "cluster"
							altData['cluster_href'] = cluster['links']['self']['href']
							altData['host_network'] = cluster['links']['networks']['href']
							
					if altData['cluster_href'] is None:
						print ("ERROR - cluster: '" + options.cluster + "' is not registered with the IBM Spectrum Protect Plus server")
						return None

				#resolve datastore if specified
				altData['datastore_href'] = None
				#https://spplusc-19.storage.tucson.ibm.com/api/hypervisor/1002/volume?from=hlo&filter=[{"property":"hypervisorHostKey","op":"=","value":"ae2145b7238b7a3df57d10b4b5c86c4d"}]&sort=[{"property":"name","direction":"ASC"}]

				if options.datastore is not None:
					debug_msg(func_name, "searching for inventory reference for datastore: " + options.datastore)
					
					qsp = {}
					qsp['filter'] = '[{"property":"'+altData['key_type']+'","value":"'+altData['host_id']+'","op":"="}]'
					
					try:
						entries = client.SppAPI(session, 'corehv').get(path='/'+vcenter['id']+'/volume?from=hlo', params=qsp)
					except Exception as e:
						print("Error retrieving datastores " + str(e))
						return None

					for volume in entries['volumes']:
						debug_msg(func_name, "found datastore: " + volume['name'])
						if options.datastore == volume['name']:
							debug_msg(func_name, "found match; href=" + volume['links']['self']['href'])
							altData['datastore_href'] = volume['links']['self']['href']
					
					if altData['datastore_href'] is None:
						print ("ERROR - datastore: '" + options.datastore + "' is not registered with the IBM Spectrum Protect Plus server or not associated with " + altData['host_string'] + " '" + altData['host_name'] + "'")
						return None


				# resolve network if specified
				# future currently only using the network opiton to specify both the production and test network
				# https://spplusc-19.storage.tucson.ibm.com/api/hypervisor/1002/host/e416c55118c94bf0dce21c0dc61e59db/network?from=hlo&sort=[{"property":"name","direction":"ASC"}]
				
				
				altData['network_href'] = None
				if options.network is not None:
					debug_msg(func_name, "searching for inventory reference for network: " + options.network)

					try:
						# we have to advance the input string past the https: host name
						entries = client.SppAPI(session, '').get(path=altData['host_network'][len(hosturl):])
					except Exception as e:
						print("Error retrieving networks " + str(e))
						return None

					for network in entries['networks']:
						debug_msg(func_name, "found network: " + network['name'])
						
						if options.network == network['name']:
							debug_msg(func_name, "found match; href=" + network['links']['self']['href'])
							altData['network_href'] = network['links']['self']['href']
	
					if altData['network_href'] is None:
						print ("ERROR - network: '" + options.network + "' is not registered with the IBM Spectrum Protect Plus server or not associated with " + altData['host_string'] + " '" + altData['host_name'] + "'")	
						return None
					
				# finihsed searches; exit
				return altData
		
		print ("vCenter: '" + options.vcenter + "' is not registered with the IBM Spectrum Protect Plus server")
		return None
     
def build_vm_source():
    source = []
    for vm in options.vm:
        vminfo = get_vm_restore_info(vm)
        if(vminfo is not None):
            source.append(copy.deepcopy(vminfo))
    return source

def get_vm_restore_info(vm):
	func_name = get_vm_restore_info.__name__ + "(): "
	vmdata = {}
	searchdata = {"name":vm,"hypervisorType":"vmware"}
	vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from=recovery", data=searchdata)['vms']
	if not vmsearch:
		print("No recovery points found for vm: " + vm)
		return None
	for foundvm in vmsearch:
		if(foundvm['name'] == vm):
			vmdata['href'] = foundvm['links']['self']['href']
			vmdata['metadata'] = {'name':foundvm['name']}
			vmdata['resourceType'] = "vm"
			vmdata['id'] = foundvm['id']
			vmdata['include'] = True
			vmdata['version'] = build_vm_version(foundvm)

			logger.info("Adding VM " + vm + " to restore job")  		
			return vmdata    
			
def sort_protection_time(value):                                        
        return (value['protectionInfo']['protectionTime'])     
        
def get_volume_info(volume_href):
		func_name = get_volume_info.__name__ + "(): "   
		
		debug_msg(func_name, "enter with href: " + volume_href)
		
		try:
			# we have to advance the input string past the https: host name
			volume = client.SppAPI(session, '').get(path=volume_href[len(hosturl):])
		except Exception as e:
			print("Error retrieving version information " + str(e))
			return None

		if volume['total'] > 1:
			print("WARNING - found more then one datastore mapping for this virtual machine.")
			
		debug_msg(func_name, "Found volume href: " + volume['volumes'][0]['links']['self']['href'])
		debug_msg(func_name, "Found volume name: " + volume['volumes'][0]['name'])
		
		datastore_info = {}
		datastore_info['href'] = volume['volumes'][0]['links']['self']['href']
		datastore_info['name'] = volume['volumes'][0]['name']
		return datastore_info
        
def get_version_info(copy_href):
		func_name = get_version_info.__name__ + "(): "
	
		debug_msg(func_name, "enter with href: " + copy_href)
	
		try:
			# we have to advance the input string past the https: host name
			copy = client.SppAPI(session, '').get(path=copy_href[len(hosturl):])
		except Exception as e:
			print("Error retrieving version information " + str(e))
			return None

		#prettyprint(copy)

		version_info = {}
		version_info['hostname'] = copy['hypervisorHostname']

		#get volume information (datastore) for version         
		debug_msg(func_name, "Get volume href: " + copy['links']['volumes']['href'])

		try:
			# we have to advance the input string past the https: host name
			volume = client.SppAPI(session, '').get(path=copy['links']['volumes']['href'][len(hosturl):])
		except Exception as e:
			print("Error retrieving volume information for version " + str(e))
			return None

		# future - handle cases where there are more then 1 entry
		if volume['total'] > 1:
			print("WARNING - found more then one datastore mapping for the virtual machine version.")
			
		debug_msg(func_name, "Found volume href: " + volume['volumes'][0]['links']['self']['href'])
		debug_msg(func_name, "Found volume name: " + volume['volumes'][0]['name'])
		
		version_info['volume_href'] = volume['volumes'][0]['links']['self']['href']
		version_info['volume_name'] = volume['volumes'][0]['name']
		
		#get network information (datastore) for version         
		debug_msg(func_name, "Get vnics href: " + copy['links']['vnics']['href'])
		
		try:
			# we have to advance the input string past the https: host name
			vnic = client.SppAPI(session, '').get(path=copy['links']['vnics']['href'][len(hosturl):])
		except Exception as e:
			print("Error retrieving vnic information for version " + str(e))
			return None

		# future - handle cases where there are more then 1 entry
		if vnic['total'] > 1:
			print("WARNING - found more then one vnic mapping for the virtual machine version.")
			
		# now call to get networks links networks	
		debug_msg(func_name, "Get network href: " + vnic['vnics'][0]['links']['networks']['href'])
		
		try:
			# we have to advance the input string past the https: host name
			network = client.SppAPI(session, '').get(path=vnic['vnics'][0]['links']['networks']['href'][len(hosturl):])
		except Exception as e:
			print("Error retrieving network information for version " + str(e))
			return None
					
		# future - handle cases where there are more then 1 entry
		if network['total'] > 1:
			print("WARNING - found more then one vnic mapping for the virtual machine version.")
		
		debug_msg(func_name, "Found network href: " + network['networks'][0]['links']['self']['href'])
		debug_msg(func_name, "Found network name: " + network['networks'][0]['name'])

		version_info['network_href'] = network['networks'][0]['links']['self']['href']
		version_info['network_name'] = network['networks'][0]['name']
		
		return version_info
     
def build_vm_version(vm):
	func_name = build_vm_version.__name__ + "(): "	
	
	if(options.start is not None and options.end is not None):
		start = datetime.strptime(options.start, '%Y-%m-%d %H:%M')
		end = datetime.strptime(options.end, '%Y-%m-%d %H:%M')
		start_sec = start.timestamp()*1000
		end_sec  = end.timestamp()*1000
		useStartEnd = True
	else:
		useStartEnd = False
		
	vmcpurl = vm['links']['copies']['href']                                 
	
	debug_msg(func_name, "getting copies from URL: " + vmcpurl)
	
	vmcopies = client.SppAPI(session, 'spphv').get(url=vmcpurl)['copies']     
	vmcopies.sort(key=sort_protection_time, reverse=True)
	copy_num = 0
	
	debug_msg(func_name, "found versions: " + str(len(vmcopies)))
		
	for copy in vmcopies:
		copy_num += 1
		prottime = int(copy['protectionInfo']['protectionTime'])

		backup_date = copy['protectionInfo']['protectionTime']/1000
		timestamp = datetime.fromtimestamp(backup_date)

		debug_msg(func_name, "Found version: " + timestamp.strftime('%Y-%m-%d %H:%M:%S') + " from reposiitory: " + copy['protectionInfo']['subPolicyType'] + " id: "  +  copy['id'] )
		
		# we eaither found a match based on start and end times or this is a copy in the BACKUP repository
		if copy['protectionInfo']['subPolicyType'] == options.repo.upper() and (not useStartEnd or (useStartEnd and start_sec < prottime and prottime < end_sec)):
			version = {}
			version['href'] = copy['links']['version']['href']
			version['copy'] = {}
			version['copy']['href'] = copy['links']['self']['href']
			version['metadata'] = {}
			version['metadata']['useLatest'] = False
			version['metadata']['protectionTime'] = prottime  
			version['metadata']['id'] = copy['id']  
			version['metadata']['repo'] = copy['protectionInfo']['subPolicyType']
			version['metadata']['backupDate'] = timestamp.strftime('%Y-%m-%d %H:%M:%S') 
						
			if (useStartEnd):
				debug_msg(func_name, "Found version based on start and end date")
			else:
				debug_msg(func_name, "Found first version in " + copy['protectionInfo']['subPolicyType'] + " repository")

			version_info = get_version_info(copy['links']['version']['href'])
			
			if version_info is None:
				print("Cannot get copy and version info for: " + copy['links']['version']['href'])
				return None 
			
			version['metadata']['src_datastore_href'] = version_info['volume_href']
			version['metadata']['src_datastore_name'] = version_info['volume_name']
			version['metadata']['src_network_href'] = version_info['network_href']
			version['metadata']['src_network_name'] = version_info['network_name']
			version['metadata']['src_hostname'] = version_info['hostname']
			
			return version
			
	#logger.warning("No specified versions found in date range for " + vm['name'])
	session.logout()
	sys.exit("No specified versions found in date range for vm: " + vm['name'])

def build_subpolicy(source_info, altInfos):                                                      
		func_name = build_subpolicy.__name__ + "(): "
		
		debug_msg(func_name, "enter with href: " + source_info['href'])

		subpolicy = []
		subpol = {}
		subpol['type'] = "IV"      
		subpol['destination'] = {}
		subpol['destination'] = {"systemDefined": True}    
			
		if options.rename is not None:     
			subpol['destination']['mapvm'] = {}
			subpol['destination']['mapvm'][source_info['href']] = {}
			subpol['destination']['mapvm'][source_info['href']]['name'] = options.rename
			
		if altInfos['bUseAltData']:
			if altInfos['host_href'] is not None:
				debug_msg(func_name, "adding alternate ESXi host information to request")
				subpol['destination']['target'] = {}
				subpol['destination']['target']['href'] = altInfos['host_href']
				subpol['destination']['target']['name'] = altInfos['host_name']
				subpol['destination']['target']['resourceType'] = altInfos['host_type']
			if altInfos['cluster_href'] is not None:
				debug_msg(func_name, "adding alternate cluster information to request")
				subpol['destination']['target'] = {}
				subpol['destination']['target']['href'] = altInfos['cluster_href']
				subpol['destination']['target']['name'] = altInfos['host_name']
				subpol['destination']['target']['resourceType'] = altInfos['host_type']
			if altInfos['datastore_href'] is not None:
				debug_msg(func_name, "adding alternate datastore information to request")
				subpol['destination']['mapRRPdatastore'] = {}
				subpol['destination']['mapRRPdatastore'][source_info['version']['metadata']['src_datastore_href']] = altInfos['datastore_href']
			if altInfos['network_href'] is not None:
				debug_msg(func_name, "adding alternate network information to request")
				subpol['destination']['mapvirtualnetwork'] = {}
				subpol['destination']['mapvirtualnetwork'][source_info['version']['metadata']['src_network_href']] = {}
				subpol['destination']['mapvirtualnetwork'][source_info['version']['metadata']['src_network_href']]['recovery'] = altInfos['network_href']
				subpol['destination']['mapvirtualnetwork'][source_info['version']['metadata']['src_network_href']]['test'] = altInfos['network_href']
				

		subpol['option'] = {}
		subpol['option']['protocolpriority'] = "iSCSI"
		subpol['option']['poweron'] = False
		subpol['option']['continueonerror'] = True
		subpol['option']['autocleanup'] = True
		subpol['option']['allowsessoverwrite'] = True
		if (options.type == "production"):
			subpol['option']['mode'] = "recovery"
		else:
			subpol['option']['mode'] = options.type
		subpol['option']['vmscripts'] = False
		subpol['option']['streaming'] = options.stream
		subpolicy.append(subpol)
		return subpolicy

def restore_vms(alt_infos):
		func_name = restore_vms.__name__ + "(): "
		restore = {}
		sourceinfo = build_vm_source()
		
		if len(sourceinfo) == 0:
			return None
		
		#subpolicy = build_subpolicy(sourceinfo[0]['href'], alt_infos)
		subpolicy = build_subpolicy(sourceinfo[0], alt_infos)
		restore['subType'] = "vmware"
		restore['spec'] = {}
		restore['spec']['source'] = sourceinfo
		restore['spec']['subpolicy'] = subpolicy
		#prettyprint(restore)
		
		if restore['spec']['source'][0]['version'] is None:
			return None
		
		timestamp = datetime.now()
		print_msg(timestamp, "Info", msg_id_script, "--- Restore request information")
		print_msg(timestamp, "Info", msg_id_script, "Restoing virtual machine: " + options.vm[0])
		print_msg(timestamp, "Info", msg_id_script, "Backup date: " + restore['spec']['source'][0]['version']['metadata']['backupDate'])
		print_msg(timestamp, "Info", msg_id_script, "recovery repository: " + restore['spec']['source'][0]['version']['metadata']['repo'])
		print_msg(timestamp, "Info", msg_id_script, "vSnap snapshot id: " + restore['spec']['source'][0]['version']['metadata']['id'])
		print_msg(timestamp, "Info", msg_id_script, "streaming restore: " + str(options.stream))

		if options.rename:
			newname = options.rename
		else: 
			newname = options.vm[0]
		print_msg(timestamp, "Info", msg_id_script, "vm display name: " + options.vm[0] + " -> " + newname )
		
		if options.cluster is not None:
			print_msg(timestamp, "Info", msg_id_script, "ESXi host: " + restore['spec']['source'][0]['version']['metadata']['src_hostname'] + " ->  cluster: " + newname)
		else:
			if options.esxhost is not None:
				newname = options.esxhost
			else:
				newname = restore['spec']['source'][0]['version']['metadata']['src_hostname']
			print_msg(timestamp, "Info", msg_id_script, "ESXi host: " + restore['spec']['source'][0]['version']['metadata']['src_hostname'] + " -> " + newname)
		
		if options.datastore is not None:
			newname = options.datastore
		else:
			newname = restore['spec']['source'][0]['version']['metadata']['src_datastore_name']
		print_msg(timestamp, "Info", msg_id_script, "datastore: " + restore['spec']['source'][0]['version']['metadata']['src_datastore_name'] + " -> " + newname )

		if options.network is not None:
			newname = options.network
		else:
			newname = restore['spec']['source'][0]['version']['metadata']['src_network_name']
		print_msg(timestamp, "Info", msg_id_script, "network: " + restore['spec']['source'][0]['version']['metadata']['src_network_name'] + " -> " + newname )

			
		if options.type == "query":
			print("\nQuery only; exiting")
			return None
	  
		print_msg(timestamp, "Info", msg_id_script, "restore type: " + options.type)
		print_msg(timestamp, "Info", msg_id_script, "--- End restore request information")

			                                                      
		try:
			esp = client.SppAPI(session, 'spphv').post(path='?action=restore', data=restore)
		except Exception as e:
			print("Error issuing restore " + str(e))
			return None
			
		return esp['response']['name']
		
def get_job_infos(jobName):
		# get job information based on request type
		# get_id returns the job id 
		# get_status returns the job status
		func_name = get_job_infos.__name__ + "(): "
		
		qsp = {}

		qsp['filter'] = '[{"property":"jobName","value":"'+jobName+'","op":"="}]'
		
		try:		
			jobs = client.SppAPI(session, '').get(path="api/endeavour/jobsession", params=qsp)
		except Exception as e:
			print("Error getting job status " + str(e))
			return None

		infos = {}				
		# there should only be 1 entry at this time for a restore job since they have unique names
		for job in jobs['sessions']:
			infos['id'] = job['id']
			infos['status'] = job['statusDisplayName']
			return infos
			
		return None		
    
def getConnectionInfo():
		func_name = getConnectionInfo.__name__ + "(): "
		connect = client.SppAPI(session, '').get(path="/api/lifecycle/ping")
		
		if (not connect) and (options.verbose):
			print(func_name + "Could not connect to IBM Spectrum Protect Plus Server")
		else:     
			print("Connected to IBM Spectrum Protect Plus Server: " + options.hostname + ", Version " + connect['version'] + ", Build " + connect['build'])
			print("")

def get_job_log(job_name, job_id):
		func_name = get_job_log.__name__ + "(): "
		
		if (options.verbose):
			print(func_name + "Get job log for job id: " + job_id)
			
		qsp = {}
		pagesize = 1000
		pagestart = 0
		iteration = 0
		
		while True:			
			qsp['filter'] = '[{"property":"jobsessionId","value":'+job_id+',"op":"="},{"property":"type","value":["INFO","ERROR","SUMMARY","WARN","DEBUG"],"op":"IN"}]&sort=[{"property":"logTime","direction":"ASC"}]'
			try:
				jobs = client.SppAPI(session, 'log').get(path="/job?pageStartIndex="+str(pagestart)+"&pageSize="+str(pagesize), params=qsp)
			except Exception as e:
				print("Error getting job logs " + str(e))
				print("Try to reconnect with the session: " + sys.argv[0]  + " --jobname="+job_name)
				sys.exit(-2)
				
			#print("i seem to have job logs! " + str(jobs['total']))
			
			if jobs['total'] > 0:
				pagestart = jobs['total']
			
			for messages in jobs['logs']:
				timestamp = datetime.fromtimestamp(messages['logTime']/1000)
				messageType = get_message_type(messages['type'])
				print_msg(timestamp, messageType, messages['messageId'], messages['message'])
		
			jobStatus = get_job_infos(job_name)
			
			if jobStatus is None:
				print ("ERROR - Could not obtain job status; exiting.")
				return

			if jobStatus['status'] != "Running":
				timestamp = datetime.now()
				print_msg(timestamp, "Info", msg_id_script, "Final job status: " + jobStatus['status'])
				return

			#print ("iteration: " + str(iteration) + " next page start: " + str(pagestart)) 
			time.sleep(15)  
			iteration += 1


#main code
validate_input()

hosturl = "https://" + options.hostname
session = client.SppSession(hosturl, options.username, options.password)
session.login()
getConnectionInfo()

#ensure that any alt. resources can be found 
if options.jobname is None:
	jobName = None
	altLocationInfo = validate_alt_location()
	
	if altLocationInfo is not None:
		if options.jobname is None:
	  	#submit request and get job name
			jobName = restore_vms(altLocationInfo)
else:
	jobName = options.jobname     
	print_msg(0, "Info", msg_id_script, "Reconnecting to restore job '" + options.jobname + "'; all other options are ignored." )
	
if jobName is not None:
	jobInfo = get_job_infos(jobName)
	if jobInfo is not None:   
		#get job messages until job finishes
		get_job_log(jobName, jobInfo['id'])
	
	
session.logout()
