# This script updates an IBM Spectrum Protect Plus server to the latest level. 
# Only online update is supported.
#
# input:
#   --host     IBM Spectrum Protect Plus server hostname (IP or DNS, no URL)
#   --user     user 
#   --pass		 password
#   --update   update the server; if this flag is not set only check if update is available
#   --version  destination version for online update
#   --iso      path to ISO image for offline update
#   --verbose  verbose output for debug (optional)
#
# examples:
# check for online updates:
#   python update_spp.py --host=host.ibm.com --user=user --pass=pass 
#
# online update
#   python update_spp.py --host=host.ibm.com --user=user --pass=pass --update --version=10.1.12
# 
# offline update
#		python update_spp.py --host=host.ibm.com --user=user --pass=pass --iso="./iso-file-name.iso"

# exit codes:
# 0 = normal exit
# 1 = unexpected error in REST request
# 2 = unexpected error from REST response
# 3 = invalid input

import json
import time
import sys
import os
from optparse import OptionParser
from datetime import datetime
from os.path  import exists
import spplib.sdk.client as client

# offline update globals
update_path = "/tmp/spp-update"
update_iso  = "spp-update.iso"
update_file = "/" + update_iso
update_mnt  = "/mnt/cslocalupdate"
prepare_script = '/opt/SPP/update/scripts/prepare.sh'
no_console  = " 2>&1"

parser = OptionParser()
parser.add_option("--host", dest="hostname", help="IBM Spectrum Protect Plus host IP or DNS")
parser.add_option("--user", dest="username", help="IBM Spectrum Protect Plus username")
parser.add_option("--pass", dest="password", help="IBM Spectrum Protect Plus password")
parser.add_option("--version", dest="version", help="destination version (required for online update)")
parser.add_option("--update", dest="update", help="update SPP server if update is available", action="store_true")
parser.add_option("--debug", dest="verbose",  help="debug output", action="store_true")
parser.add_option("--iso", dest="iso_path",  help="iso path (offline udpate)")

(options, args) = parser.parse_args()

def prettyprint(indata, infunc):
	if (options.verbose):
		print("Response from call: %s" % infunc)
		print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
  if options.username is None or options.password is None or options.hostname is None:
    print("ERROR: use -h switch for help")
    sys.exit(3)
    
  if ("https" in options.hostname):
    print("ERROR: you need to specify a host IP or DNS and not a URL")
    sys.exit(3)
    
  if (options.iso_path is not None):
  	if not exists(options.iso_path):
  		print("ERROR: The specified ISO does not exist")
  		sys.exit(3)  
  	try:
  		from requests_toolbelt import MultipartEncoder  
  	except ImportError:
  		print("ERROR: you need to install the Python library requests_toolbelt for offline updates")
  		sys.exit(3)
  elif (options.update and options.version is None):
  	print("ERROR: you need to specify a destination version (--version) if you are requesting an update")
  	sys.exit(3)  
    
def build_host_url(hostname):
	return "https://" + hostname
                        
def client_session(url, username, password):
	try:
		session = client.SppSession(url, username, password)
	except Exception as e:
		time_msg("Could not establish session: %s" % str(e))
		sys.exit(1)
	return session

def getConnectionInfo(session):
    #connect = client.SppAPI(session, 'ngp').get(path="/version")  
    try:
    	connect = client.SppAPI(session, '').get(path="/api/lifecycle/ping")
    except Exception as e:
      time_msg("Could not connect to IBM Spectrum Protect Plus Server: %s" % str(e))    
      sys.exit(2)
    else:     
      time_msg("Connected to IBM Spectrum Protect Plus server:")
      time_msg("  Hostname: %s" % options.hostname)
      time_msg("  Version:  %s" % connect['version'])
      time_msg("  Build:    %s" % connect['build'])
 	    		                        
def login_to_admin_console(session):
	try:
		session.login_to_admin_console()
	except Exception as e:
		time_msg("Could not login to admin console: %s" % str(e))
		sys.exit(1)
	else:
		time_msg("Establised login to admin console.")

def time_msg(message):
	timestamp = datetime.now()
	print(timestamp.strftime('%Y-%m-%d %H:%M:%S'),message,sep=" ")  

def check_repository_availability(session): 
	#check for IBM Spectrum Protect Plus server license 
	if (options.verbose):
		time_msg("Checking connectivity to update repository.")
	
	try:
		response = session.admin_get("checkinternetavailability")
	except Exception as e:
		time_msg("Error checking connectivity to update repository. : %s" % str(e))
		sys.exit(1)
	
	prettyprint(response, "checkinternetavailability")
		
	#check for response from yum update - should be 0
	if response['commandoutput']['errorCode'] != "0":
		time_msg("Error checking connectivity to update repository.")
		time_msg("  Error code:   %s" % response['commandoutput']['errorCode'] )
		time_msg("  Error output: %s" % response['commandoutput']['commandErrorOutput'])
		sys.exit(2)
	
	if (options.verbose):
		time_msg("Checking internet availability: %s" % response['commandoutput']['commandOutput'])
	
def check_license(session):
	#check for IBM Spectrum Protect Plus server license 
	
	if (options.verbose):
		time_msg("Checking for IBM Spectrum Protect Plus server license.")
		
	try:
		response = session.admin_check_license()
	except Exception as e:
		time_msg("Error checking for IBM Spectrum Protect Plus server license: %s" % str(e))
		sys.exit(1)
	
	prettyprint(response, "admin_check_license")
		
	SPP_license = response['filedetails']['doesFileExist']     
	if SPP_license is False:
		time_msg("IBM Spectrum Protect Plus server license does not exist! Exiting ...")
		sys.exit(2)
	                                   
	time_msg("IBM Spectrum Protect Plus server license found; timestamp: %s" % response['filedetails']['fileTime']) 

def check_self_update(session): 
	#check self update
	
	if (options.verbose):
		time_msg("Checking self update.")
		
	try:
		response = session.admin_get("checkselfupdate")
	except Exception as e:
		time_msg("Error checking for self update: %s" % str(e))
		sys.exit(1)
	
		prettyprint(response, "checkselfupdate")
		
	#check for response from yum update - should be 0
	if response['commandoutput']['errorCode'] != "0":
		time_msg("Error checking self update!")
		time_msg("  Error code:   %s" % response['commandoutput']['errorCode'] )
		time_msg("  Error output: %s" % response['commandoutput']['commandErrorOutput'])
		sys.exit(2)
	
	if (options.verbose):
		time_msg("Checking self-update: %s" % response['commandoutput']['commandOutput'])
	
def check_update(session):
	# check for server update
	try:
		response = session.admin_get("checkupgrade")
	except Exception as e:
		time_msg("Error checking for update! %s" % str(e))
		sys.exit(1)
	
	prettyprint(response, "checkupgrade")
	
	update_string = response['commandoutput']['commandOutput']
	if (update_string == "[]\n"):
		time_msg("There are no available updates!")
		sys.exit(0)
	else:
		# response is string in format: [{"version": "10.1.12", "build": "301"}]
		update_string = update_string.replace('[','')
		update_string = update_string.replace(']','')
		update_string = update_string.replace('}, {','}::{')
		
		update_version = 0
		update_build   = 0
		
		updates = update_string.split('::')
		for update in updates:
			update_json = json.loads(update)
			prettyprint(update_json, "update_json")
			
			time_msg("IBM Spectrum Protect Plus Server update available: Version: %s Build: %s" % (update_json['version'], update_json['build']))
			
			if (options.version is not None and options.version == update_json['version']):
				update_version = (update_json['version'])
				update_build   = (update_json['build'])	
				
		# validate target version				
		if (options.update and update_version == 0):
			time_msg("No versions available for update matching desired update destination '%s'. Exiting." % options.version)
			sys.exit(2)
		
		return update_version, update_build

def exit_if_no_update():
	if not options.update:
			time_msg("Exiting. Use the --update flag to execute an update of the server")
			sys.exit(0)

def upload_update_remote_copy():

	if options.verbose:
		time_msg("Securely copying ISO image from path: '%s'" % (options.iso_path))	

	remote_path = update_path + update_file
	remote_loc = "serveradmin@" + options.hostname + ":" + remote_path
	remote_cmd = "ssh serveradmin@" + options.hostname + " sudo mkdir " + update_path
	if (options.verbose):
		time_msg("Executing remote command: %s" % remote_cmd)
	os.system(remote_cmd)

	remote_cmd = 'rsync --rsync-path=\"sudo rsync\" ' + options.iso_path + " " + remote_loc
	if (options.verbose):
		time_msg("Executing remote command: %s" % remote_cmd)
	time_msg("Copying local ISO image '%s' to remote location '%s'" % (options.iso_path, remote_loc))
	time_msg("This might take a few minutes ...")
	os.system(remote_cmd)	

  # run install script on SPP server for setup
	remote_cmd = "ssh serveradmin@" + options.hostname + " sudo " + prepare_script + " -m setup -n " + update_iso + " -l " + update_path + no_console
	if (options.verbose):
		time_msg("Executing remote command: %s" % remote_cmd)
	os.system(remote_cmd)

	time_msg("ISO update uploaded to tempoary directory: '%s'" % remote_path)

def upload_update_image(session):
	# upload ISO image
	if options.verbose:
		time_msg("Uploading ISO image from path: '%s'" % (options.iso_path))
	
	try:
		response = session.admin_upload_update(options.iso_path)
	except Exception as e:
			
		time_msg("Error updating ISO image! %s" % str(e))	
		sys.exit(1)

	prettyprint(response, "upload_update_image")
	
	# response should be 0
	command_response = response['commandoutputupdateimage']
	if command_response['errorCode'] != "0":
		time_msg("Error uploading update!")
		time_msg("  Error code:   %s" % command_response['errorCode'])
		time_msg("  Error output: %s" % command_response['commandErrorOutput'])
		time_msg("You can delete this temporary directory from the IBM Spectrum Protect Plus server: %s" % command_response['imageDirectory'])
		time_msg("You can umount this directory from the IBM Spectrum Protect Plus server: %s" % "/mnt/cslocalupdate")
		sys.exit(2)
		
	time_msg("ISO update uploaded to tempoary directory: '%s'" % command_response['imageDirectory'])

def update_yum(session, version, build):
	# update yum catalog
	if options.verbose:
		time_msg("Updating yum repository: Version: '%s', Build: '%s'" % (version, build))
	try:
		response = session.admin_update_yum(version, build)
	except Exception as e:
		time_msg("Error updating yum repository! %s" % str(e))
		sys.exit(1)

	prettyprint(response, "update_yum")
		
	#check for response from yum update - should be 0
	if response['commandoutput']['errorCode'] != "0":
		time_msg("Error updating yum repsository!")
		time_msg("  Error code:   %s" % response['commandoutput']['errorCode'] )
		time_msg("  Error output: %s" % response['commandoutput']['commandErrorOutput'])
		sys.exit(2)
		
	time_msg("Updated yum repository.")

def update_SPP(session, version, build):
	#now let's try to update this !!!
	time_msg("Updating IBM Spectrum Protect Plus server to Version: '%s' Build: '%s'" % (version, build))
	time_msg("This might take a few minutes ...")
	
	try:
		response = session.admin_update_server("action=full")
	except Exception as e:
		time_msg("Error updating IBM Spectrum Protect Plus server: %s" % str(e))
		sys.exit(2)
	
	prettyprint(response, "admin_update_server")	

	#check for response from yum update - should be 0
	if response['commandoutput']['errorCode'] != "0":
		time_msg("Error updating yum repsository!")
		time_msg("  Error code:   %s" % response['commandoutput']['errorCode'] )
		time_msg("  Error output: %s" % response['commandoutput']['commandErrorOutput'])
		sys.exit(2)
	
	time_msg("IBM Spectrum Protect Plus server updated with no errors.")

def update_admin_console(session):
	time_msg("Updating IBM Spectrum Protect Plus admin console")
	try:
		session.admin_update_ac()
	except Exception as e:
		time_msg("Error updating IBM Spectrum Protect Plus admin console: %s" % str(e))
		sys.exit(2)
		
	time_msg("IBM Spectrum Protect Plus admin console has been updated.")
	
def restart_spp(session):
	time_msg("IBM Spectrum Protect Plus virtual appliance is now being rebooted to complete the update process.")
	time_msg("This might take a few minutes ...")

	try:
		session.restart_spp()
	except Exception as e:
		time_msg("Error restarting IBM Spectrum Protect Plus server: %s" % str(e))
		sys.exit(2)
		
	time_msg("IBM Spectrum Protect Plus server has been restarted!")
	
def cleanup():
	
	# no clean-up for online backups
	if (options.iso_path is None):
		return
		
	#input("Press any key to cleanup ...")

	# umount volume:
	remote_cmd = "ssh serveradmin@" + options.hostname + " sudo " + prepare_script + " -m cleanup -n " + update_iso + " -l " + update_path + no_console
	if (options.verbose):
		time_msg("Executing remote command: %s" % remote_cmd)
	os.system(remote_cmd)

# main code 
# validate and check environment for upgrad
validate_input()
hosturl = build_host_url(options.hostname)
session = client_session(hosturl, options.username, options.password)
getConnectionInfo(session) 
login_to_admin_console(session)  

# check updates for online update
if (options.iso_path is None):
	check_repository_availability(session)
	new_version, new_build = check_update(session)
	exit_if_no_update()
	# update server and restart if user requests update
	update_yum(session, new_version, new_build)
	update_SPP(session, new_version, new_build)
else:
	# offline update from ISO image 
	upload_update_remote_copy()
	update_SPP(session, "from ISO", "from ISO")

update_admin_console(session)
restart_spp(session)	

# validate session with new build
session = client_session(hosturl, options.username, options.password)
getConnectionInfo(session) 
cleanup()