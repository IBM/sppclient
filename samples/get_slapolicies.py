# Display all SLA policies on an IBM Spectrum Protect Plus server
#
# To write output to console:
#  python3 get_slapolicies.py --host=172.20.49.50 --user=admin --pass=password123 
#
# To write output in JSON format to console:
#  python3 get_slapolicies.py --host=172.20.49.50 --user=admin --pass=password123 --file=json
#
# To write output in csv:
#  python3 get_slapolicies.py --host=172.20.49.50 --user=admin --pass=password123 --file=out.csv

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
parser.add_option("--file", dest="filename", help="optional fomrat: JSON or <filename>; default is CONSOLE", default="")

(options, args) = parser.parse_args()

options.json = False
options.csv_file = ""


def console_msg(message):
    
    timestamp = datetime.now()
    #print(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " " + message)  
    print(message)  
    return

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
	if options.username is None or options.password is None or options.hostname is None:
		print("ERROR: use -h switch for help")
		sys.exit(2)
        
	if ("https" in options.hostname):
		print("ERROR: you need to specify a host IP or DNS and not a URL")
		sys.exit(2)

	if options.filename.lower() == "json":
		options.json = True
	else:
		options.csv_file = options.filename
    
def debug_msg(function_name, message):
    if options.verbose:
      timestamp = datetime.now()
      print(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " " + function_name + message)  
      
    return
        
def getConnectionInfo():
    func_name = getConnectionInfo.__name__ + "(): "
    #connect = client.SppAPI(session, 'ngp').get(path="/version")
    connect = client.SppAPI(session, '').get(path="/api/lifecycle/ping")
    
    if (not connect) and (options.verbose):
      console_mmsg(func_name + "Could not connect to IBM Spectrum Protect Plus Server")
    else:     
      #prettyprint(connect)
      console_msg("Connected to IBM Spectrum Protect Plus Server: " + options.hostname + ", Version " + connect['version'] + ", Build " + connect['build'])
      console_msg("")
      
def getSlaPolicies():
	func_name = getConnectionInfo.__name__ + "(): "
	
	bWriteFile = False
	
	if (options.csv_file != ""):
		try:
			file = open(options.csv_file, "w")
			
		except Exception as e:
			print("Error " + str(e))
			sys.exit(-1)
		
		bWriteFile = True
		
	#get sla policies from server
	slapols = client.SppAPI(session, 'sppsla').get()['slapolicies']
	
	if (options.json):
		prettyprint(slapols)
		return
	
	table = '{:30} {:15} {:12} {:10} {:>10} {:60}'
	out_hdr = ["SLA NAME", "TYPE", "SUBPOLICY", "FREQUENCY", "RETENTION (DAYS)", "TARGET"]  
	if not bWriteFile:
		print(table.format("SLA Name", "Tyoe", "Subpolicy", "Frequency", "Retention", "Target"))	
		print(table.format("", "", "", "", "(Days)", ""))
		print(table.format("----------","----------", "----------", "----------", "----------", "----------"))
	else:
		file.write("SLA NAME, TYPE, SUBPOLICY, FREQUENCY, RETENTION (DAYS), TARGET\n")
		
	for sla in slapols: 
		for subpol in sla['spec']['subpolicy']:     
			if "frequency" in subpol['trigger']:           
				frequency = str(subpol['trigger']['frequency']) + " " + subpol['trigger']['type']  
			else:
				freqency = "UNDEFINED"    
			retention = str(subpol['retention']['age'])
			if "target" in subpol:
				target = subpol['target']['href']
			else:
				target = "NONE" 
 
			if bWriteFile:
				file.write(sla['name'] + "," + sla['type'] + "," + subpol['type'] + "," + frequency + "," + retention + "," + target + "\n")
			else:
				print(table.format(sla['name'], sla['type'], subpol['type'], frequency, retention, target))

	if bWriteFile:
		file.close()

#main code
validate_input()
hosturl = "https://" + options.hostname

try:
	session = client.SppSession(hosturl, options.username, options.password)
except Exception as e:
	print("Error " + str(e))
	sys.exit(-1)
	
session.login()
getConnectionInfo()   
getSlaPolicies()
session.logout()
