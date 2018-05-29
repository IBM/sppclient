# Script to register a new vSnap Backup Storage provider in SPP
# Use registervsnap.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import sppclient.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--vshost", dest="vshost", help="vSnap hostname or IP")
parser.add_option("--vssite", dest="vssite", help="vSnap site name (example: Primary)")
parser.add_option("--vsuser", dest="vsuser", help="vSnap username")
parser.add_option("--vspass", dest="vspass", help="vSnap password")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.vshost is None or options.vssite is None or options.vsuser is None
       or options.vspass is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def find_site_by_name():
    sites = client.SppAPI(session, 'coresite').get()['sites']
    for site in sites:
        if(site['name'].upper() == options.vssite.upper()):
            return site['id']
    logger.error("Site name not found")
    session.logout()
    sys.exit(2)

def register_vsnap():
    vsnapinfo = {}
    vsnapinfo['siteId'] = find_site_by_name()
    vsnapinfo['hostAddress'] = options.vshost
    vsnapinfo['username'] = options.vsuser
    vsnapinfo['password'] = options.vspass
    vsnapinfo['portNumber'] = "8900"
    vsnapinfo['sslConnection'] = True
    vsnapinfo['type'] = "vsnap"
    try:
        response = client.SppAPI(session, 'storage').post(data=vsnapinfo)
        print options.vshost + " is registered"
    except client.requests.exceptions.HTTPError as err:
        errmsg = json.loads(err.response.content)
        print errmsg['response']['description']

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
register_vsnap()
session.logout()
