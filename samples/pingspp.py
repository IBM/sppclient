# Ping SPP server to validate it is running and accepting logins
#
# Usage
#  python3 pingspp.py --host=172.20.49.50 --user=admin --pass=password123

import json
from optparse import OptionParser
from datetime import datetime
import spplib.sdk.client as client
import time

parser = OptionParser()
parser.add_option("--host", dest="hostname", help="IBM Spectrum Protect Plus host IP or DNS")
parser.add_option("--user", dest="username", help="IBM Spectrum Protect Plus username")
parser.add_option("--pass", dest="password", help="IBM Spectrum Protect Plus password")
parser.add_option("--time", dest="sleep_time", help="time between pings in seconds", type=int, default=3)
parser.add_option("--debug",dest="verbose",  help="debug output", action="store_true")

(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
  if options.username is None or options.password is None or options.hostname is None:
    print("ERROR: use -h switch for help")
    sys.exit(2)
    
  if ("https" in options.hostname):
    print("ERROR: you need to specify a host IP or DNS and not a URL")
    sys.exit(2)
   
def time_msg(message):
	timestamp = datetime.now()
	print(timestamp.strftime('%Y-%m-%d %H:%M:%S'),message,sep=" ")  
    
def getConnectionInfo():
    func_name = getConnectionInfo.__name__ + "(): "
    #connect = client.SppAPI(session, 'ngp').get(path="/version")
    connect = client.SppAPI(session, '').get(path="/api/lifecycle/ping")
    
    if (not connect) and (options.verbose):
      print(func_name + "Could not connect to IBM Spectrum Protect Plus Server")
    else:     
      #prettyprint(connect)
      time_msg("Connected to IBM Spectrum Protect Plus Server: " + options.hostname + ", Version " + connect['version'] + ", Build " + connect['build'])

#main code
validate_input()
hosturl = "https://" + options.hostname

while True:
	try:
		session = client.SppSession(hosturl, options.username, options.password)
	except:
		time_msg("Unable to login; unable to establish session")
		time.sleep(options.sleep_time)
	else:
		try:
			connect = client.SppAPI(session, '').get(path="/api/lifecycle/ping")
		except:
			time_msg("Unable to login; session establed but cannot ping server")
		else:
			getConnectionInfo()
			
		time.sleep(options.sleep_time)
session.logout()