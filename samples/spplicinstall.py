# Script to call license installation API for SPP
# Be sure new license file is in /opt/virgo/repository/spp-usr/
# Use spplicinstall.py -h for help
# example:
# python spplicinstall.py --host="https://172.20.58.59"

import json
import logging
from optparse import OptionParser
import sys
import requests
try:
    import urllib3
except ImportError:
    from requests.packages import urllib3
urllib3.disable_warnings()
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.host is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)
    
def install_license():
    hdrs = {'Content-Type': 'application/json','Accept': 'application/json'}
    r = requests.post(options.host + '/api/endeavour/session?action=installLicense',
                      auth=requests.auth.HTTPBasicAuth('admin','password'), verify=False, headers=hdrs)
    if(r.status_code == 204):
        logger.info("License installed.")
    else:
        logger.info("Error installing license.")

validate_input()
install_license()
