# Script to register a new hypervisor provider in SPP
# Use registerhypervisor.py -h for help
# Example:
# python registerhypervisor.py --host="https://172.20.49.49" --user="admin" --pass="spppass" --hvtype="hyperv" --hvhost="my.host.name" --hvuser="hvdomain\hvuser" --hvpass="hvpassword"

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
parser.add_option("--hvtype", dest="hvtype", help="vmware or hyperv (Required)")
parser.add_option("--hvhost", dest="hvhost", help="hypervisor IP or hostname (Required)")
parser.add_option("--hvuser", dest="hvuser", help="hypervisor username (Required)")
parser.add_option("--hvpass", dest="hvpass", help="hypervisor password (Required)")
parser.add_option("--hvport", dest="hvport", help="hypervisor port (Optional) (default 443 for vmware 5985 for hyperv)")
parser.add_option("--hvssl", dest="hvssl", help="hypervisor ssl setting (Optional, true or false) (default true vmware false hyperv)")
parser.add_option("--hvssc", dest="hvssc", help="hypervisor snapshot concurrency (Optional) (default is 3)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.hvhost is None or options.hvuser is None or options.hvpass is None
       or options.hvtype is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def build_hypervisor():
    hvinfo={}
    hvinfo['hostAddress'] = options.hvhost
    hvinfo['username'] = options.hvuser
    hvinfo['password'] = options.hvpass

    if(options.hvtype.lower() == "vmware" or options.hvtype.lower() == "hyperv"):
        hvinfo['type'] = options.hvtype.lower()
    else:
        logger.error("Invalid hypervisor type, must be vmware or hyperv")
        session.logout()
        sys.exit(2)
    
    if(options.hvport is not None):
        hvinfo['portNumber'] = int(options.hvport)
    elif(hvinfo['type'] == "hyperv"):
        hvinfo['portNumber'] = 5985
    else:
        hvinfo['portNumber'] = 443
    
    if(options.hvssl is not None):
        if(options.hvssl.upper() == "TRUE"):
            hvinfo['sslConnection'] = True
        else:
            hvinfo['sslConnection'] = False
    elif(hvinfo['type'] == "hyperv"):
        hvinfo['sslConnection'] = False
    else:
        hvinfo['sslConnection'] = True

    if(options.hvssc is not None):
        hvinfo['opProperties'] = {'snapshotConcurrency': options.hvssc}
    else:
        hvinfo['opProperties'] = {'snapshotConcurrency': 3}
    return hvinfo        

def register_hypervisor(hvinfo):
    try:
        response = client.SppAPI(session, 'spphv').post(data=hvinfo)
        print options.hvhost + " is registered"
    except client.requests.exceptions.HTTPError as err:
        errmsg = json.loads(err.response.content)
        print errmsg['response']['description']

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
hvinfo = build_hypervisor()
register_hypervisor(hvinfo)
session.logout()
