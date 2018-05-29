# Script to check the status of vSnap provider(s) in SPP
# Use registervsnap.py -h for help

import json
import logging
from optparse import OptionParser
import sys
import sppclient.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def get_vsnap_status():
    try:
        storages = client.SppAPI(session, 'corestorage').get()['storages']
        if(len(storages) < 1):
            print "No vSnap storage providers found"
            session.logout()
            sys.exit(2)
        for storage in storages:
            if(storage['type'] == "vsnap"):
                print "vSnap provider " + storage['name'] + " is " + storage['initializeStatus']
    except:
        print "Error connecting to SPP host"
    


validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
get_vsnap_status()
session.logout()
