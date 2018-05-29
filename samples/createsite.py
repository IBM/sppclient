# Script to create a new vSnap site in SPP
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
parser.add_option("--sitename", dest="sitename", help="Site name")
parser.add_option("--sitedesc", dest="sitedesc", help="Site description")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.sitename is None or options.sitedesc is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def create_site():
    siteinfo = {}
    siteinfo['name'] = options.sitename
    siteinfo['description'] = options.sitedesc
    siteinfo['defaultSite'] = False
    try:
        response = client.SppAPI(session, 'coresite').post(data=siteinfo)
        print options.sitename + " is created"
    except client.requests.exceptions.HTTPError as err:
        errmsg = json.loads(err.response.content)
        print errmsg['response']

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
create_site()
session.logout()
