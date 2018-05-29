# Script to finish deployment of new SPP server
# Sets admin password based on argument and initializes onboard vSnap
# Use sppdeploy.py -h for help
# example:
# python sppdeploy.py --host="https://172.20.58.59" --pass="newpass123"

import json
import logging
from optparse import OptionParser
import copy
import sys
import imp
import requests
import time
try:
    import urllib3
except ImportError:
    from requests.packages import urllib3
import spplib.sdk.client as client
urllib3.disable_warnings()
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--pass", dest="password", help="New SPP admin Password")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.host is None or options.password is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)

def wait_for_deployment():
    logger.info("Waiting for SPP deployment")
    time.sleep(5)
    deployfinished = False
    while(deployfinished is False):
        deployfinished = call_session_options()
        time.sleep(10)

def call_session_options():
    hdrs = {'Content-Type': 'application/json','Accept': 'application/json'}
    r = requests.options(options.host + '/api/endeavour/session', timeout=None, verify=False)
    if(r.status_code is not 200):
        return False
    else:
        return True
    
def change_password():
    logger.info("Setting admin password")
    hdrs = {'Content-Type': 'application/json','Accept': 'application/json'}
    payload = {'changePassword': 'true'}
    body = {"newPassword": options.password}
    r = requests.post(options.host + '/api/endeavour/session', json=body,
                      auth=requests.auth.HTTPBasicAuth('admin','password'),
                      verify=False, headers=hdrs, params=payload)
    if 'sessionid' not in r.json():
        logger.info("Deployment not finished, trying again.")
        time.sleep(5)
        change_password()
    else:
        return r.json()['sessionid']

def init_onboard_vsnap():
    logger.info("Initializing onboard vsnap provider")
    initbody = {'async': True}
    response = client.SppAPI(session, 'corestorage').post(path='/2000/management?action=init', data=initbody)
    return response

validate_input()
wait_for_deployment()
sessionid = change_password()
session = client.SppSession(options.host, 'admin', options.password, sessionid)
init_onboard_vsnap()
session.logout()
