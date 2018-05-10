# example:
# python register_appserver.py --user="admin" --pass="password123" --host="https://172.20.58.1:8443" --provname="PSDEMO-DB2" --provhost="172.20.58.20" --provsite="New York" --provcred="credentials" --provtype="osvolume" --provst="physical" --provos="Linux"

import sys
import httplib
import json
import logging
from optparse import OptionParser
import time
import csv
import ecxclient.sdk.client as client

logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="ECX Username")
parser.add_option("--pass", dest="password", help="ECX Password")
parser.add_option("--host", dest="host", help="ECX Host, (ex. https://172.20.58.10:8443)")
parser.add_option("--provname", dest="provname", help="Provider Name")
parser.add_option("--provhost", dest="provhost", help="Provider Host Address")
parser.add_option("--provsite", dest="provsite", help="Porivder Site")
parser.add_option("--provcred", dest="provcred", help="Provider Credentials (ECX object name)")
parser.add_option("--provtype", dest="provtype", help="Provider Type (oracle, sql, osvolume, saphana, cache)")
parser.add_option("--provst", dest="provst", help="Provider Server Type (physical or virtual)")
parser.add_option("--provport", dest="provport", help="Provider Port (optional)")
parser.add_option("--provos", dest="provos", help="Provider OS (required if filesystem/osvolume, windows, linux, aix)")
parser.add_option("--provvc", dest="provvc", help="Provider vCenter (required if Virtual)")
parser.add_option("--provcom", dest="provcom", help="Provider Comment (optional)")

(options, args) = parser.parse_args()

session = client.EcxSession(options.host, options.username, options.password)

def validate_input():

    if (options.username is None or options.password is None or options.host is None):
        print "ECX login information missing"
        sys.exit(2)
        
    if (options.provname is None):
        print "Provider name missing"
        sys.exit(2)

    if (options.provhost is None):
        print "Provider hostname or IP missing"
        sys.exit(2)

    if (options.provsite is None):
        print "Provider site missing"
        sys.exit(2)

    if (options.provcred is None):
        print "Provider credentials missing"
        sys.exit(2)

    if (options.provtype is None or options.provst is None):
        print "Provider type or server type is missing"
        sys.exit(2)

    if (options.provtype.upper() == "ORACLE" or options.provtype.upper() == "SQL"
        or options.provtype.upper() == "OSVOLUME" or options.provtype.upper == "SAPHANA"
        or options.provtype.upper() == "CACHE"):
        options.provtype = options.provtype.lower()
    else:
        print "Provider type is invalid (oracle, sql, osvolume, saphana or cache)"
        sys.exit(2)

    if (options.provst.upper() == "VIRTUAL" or options.provst.upper() == "PHYSICAL"):
        options.provst = options.provst.lower()
    else:
        print "Provider server type is invalid (virtual or physical)"
        sys.exit(2)

    if (options.provtype == "osvolume" and options.provos is None):
        print "Provider OS is required if type is osvolume"
        sys.exit(2)
    elif (options.provos.upper() == "WINDOWS" or options.provos.upper() == "LINUX"
          or options.provos.upper() == "AIX"):
        options.provos = options.provos.lower()
    elif (options.provtype.upper() == "ORACLE" or options.provtype.upper() == "SAPHANA"
          or options.provtype.upper() == "CACHE"):
        options.provos = "linux"
    elif (options.provtype.upper() == "SQL"):
        options.provos = "windows"
    else:
        print "Provider OS is invalid (windows, linux or aix)"
        sys.exit(2)

    if (options.provst == "virtual" and options.provvc is None):
        print "Provider vCenter is required for virtual providers"
        sys.exit(2)
    return None

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def find_credential():
    userlist = client.EcxAPI(session, 'identityuser').list()
    for user in userlist:
        if (user['name'].upper() == options.provcred.upper()):
            return {"href": user['links']['self']['href']}
    print "Provider credentials not found"
    sys.exit(2)

def find_vcenter():
    vcenterlist = client.EcxAPI(session, 'vsphere').list()
    for vcenter in vcenterlist:
        if (vcenter['name'].upper() == options.provvc.upper()):
            return vcenter['id']
    print "Provider vCenter not found"
    sys.exit(2)

def find_site_id_by_name():
    sitelist = client.EcxAPI(session, 'site').list()
    for site in sitelist:
        if (site['name'].upper() == options.provsite.upper()):
            return site['id']
    print "Provider site not found"
    sys.exit(2)

def build_provider():
    provider = {}
    provider['name'] = options.provname
    provider['siteId'] = find_site_id_by_name()
    provider['hostAddress'] = options.provhost
    provider['applicationType'] = options.provtype
    provider['serverType'] = options.provst
    
    if (options.provcom is not None):
        provider['comment'] = options.provcom
    else:
        provider['comment'] = ""
        
    if (options.provtype == "sql"):
        options.provos = "windows"
        
    if (options.provst == "virtual"):
        provider['vsphereId'] = find_vcenter()
    else:
        provider['vsphereId'] = ""
        
    if (options.provtype == "osvolume"):
        provider['osType'] = options.provos

    if (options.provport is not None):
        provider['portNumber'] = options.provport.int()
    elif (options.provos == "windows"):
        provider['portNumber'] = 5985
    elif (options.provtype == "osvolume"):
        provider['portNumber'] = 22
    else:
        provider['portNumber'] = None

    provider['osuser'] = find_credential()      
    provider['appCredentials'] = []
    provider['addToCatJob'] = True
    provider['useKeyAuthentication'] = False
    return provider

def register_provider():
    provider = build_provider()
    try:
        resp = client.EcxAPI(session, 'appserver').post(data=provider)
        print "Provider " + options.provname + " registerd."
    except client.requests.exceptions.HTTPError as e:
        error = json.loads(e.response.content)
        print "Error registering provider: " + error['id']

validate_input()
session.login()
register_provider()
session.delete('endeavour/session/')
