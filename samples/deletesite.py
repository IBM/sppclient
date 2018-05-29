# Script to delete a vSnap site in SPP
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
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.sitename is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def find_site_by_name():
    sites = client.SppAPI(session, 'coresite').get()['sites']
    for site in sites:
        if(site['name'].upper() == options.sitename.upper()):
            return site['id']
    logger.error("Site name not found")
    session.logout()
    sys.exit(2)

def delete_site():
    siteid = find_site_by_name()
    try:
        response = client.SppAPI(session, 'coresite').delete(resid=siteid)
        print options.sitename + " is deleted"
    except client.requests.exceptions.HTTPError as err:
        errmsg = json.loads(err.response.content)
        print errmsg['response']

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
delete_site()
session.logout()
