# script to register multiple appservers given a .csv file with parameters
# example:
# python register_appserver.py --user="admin" --pass="password123" --host="https://172.20.58.1:8443" --csv="/tmp/provs.csv"

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
parser.add_option("--csv", dest="csv", help="Full path to .csv providers file")

(opt, args) = parser.parse_args()

class Options(object):
    provname = None
    provhost = None
    provsite = None
    provcred = None
    provtype = None
    provst = None
    provport = None
    provos = None
    provvc = None
    provcom = None

options = Options()
credentials_found = False
validation_passed = False
site_found = False
vcenter_found = True

session = client.EcxSession(opt.host, opt.username, opt.password)

def validate_input():
    if (opt.username is None or opt.password is None or opt.host is None):
        print "ECX login information missing"
        sys.exit(2)
    if (opt.csv is None):
        print "Source .csv path missing"
        sys.exit(2)

def validate_provider_info():
    global validation_passed
    validation_passed = False

    if (options.provname is None):
        print "Provider name missing"
        return

    if (options.provhost is None):
        print "Provider hostname or IP missing"
        return

    if (options.provsite is None):
        print "Provider site missing"
        return

    if (options.provcred is None):
        print "Provider credentials missing"
        return

    if (options.provtype is None or options.provst is None):
        print "Provider type or server type is missing"
        return

    if (options.provtype.upper() == "ORACLE" or options.provtype.upper() == "SQL"
        or options.provtype.upper() == "OSVOLUME" or options.provtype.upper == "SAPHANA"
        or options.provtype.upper() == "CACHE"):
        options.provtype = options.provtype.lower()
    else:
        print "Provider type is invalid (oracle, sql, osvolume, saphana or cache)"
        return

    if (options.provst.upper() == "VIRTUAL" or options.provst.upper() == "PHYSICAL"):
        options.provst = options.provst.lower()
    else:
        print "Provider server type is invalid (virtual or physical)"
        return

    if (options.provtype == "osvolume" and options.provos is None):
        print "Provider OS is required if type is osvolume"
        return
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
        return

    if (options.provst == "virtual" and options.provvc is None):
        print "Provider vCenter is required for virtual providers"
        return
    
    validation_passed = True

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def find_credential():
    global credentials_found
    credentials_found = False
    userlist = client.EcxAPI(session, 'identityuser').list()
    for user in userlist:
        if (user['name'].upper() == options.provcred.upper()):
            credentials_found = True
            return {"href": user['links']['self']['href']}
    print "Provider credentials not found"

def find_vcenter():
    global vcenter_found
    vcenter_found = False
    vcenterlist = client.EcxAPI(session, 'vsphere').list()
    for vcenter in vcenterlist:
        if (vcenter['name'].upper() == options.provvc.upper()):
            vcenter_found = True
            return vcenter['id']
    print "Provider vCenter not found"

def find_site_id_by_name():
    global site_found
    site_found = False
    sitelist = client.EcxAPI(session, 'site').list()
    for site in sitelist:
        if (site['name'].upper() == options.provsite.upper()):
            site_found = True
            return site['id']
    print "Provider site not found"

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
    #prettyprint(provider)
    return provider

def register_provider():
    validate_provider_info()
    provider = build_provider()
    global validation_passed
    global credentials_found
    global site_found
    global vcenter_found
    if (validation_passed and credentials_found and site_found and vcenter_found):
        try:
            resp = client.EcxAPI(session, 'appserver').post(data=provider)
            print "Provider " + options.provname + " registerd."
        except client.requests.exceptions.HTTPError as e:
            error = json.loads(e.response.content)
            print "Error registering provider: " + provider['name'] + " " + error['id']
    else:
        print "Skipping provider " + provider['name'] + " registration for above reason"
        vcenter_found = True

def read_csv():
    with open(opt.csv) as csvfile:
        provs = csv.DictReader(csvfile, delimiter=',')
        for prov in provs:
            if(prov['provider name'] == ""):
                options.provname = None
            else:
                options.provname = prov['provider name']
            if(prov['provider host'] == ""):
                options.provhost = None
            else:
                options.provhost = prov['provider host']
            options.provsite = prov['provider site']
            options.provcred = prov['provider credentials']
            options.provtype = prov['provider type']
            options.provst = prov['provider server type']
            if(prov['provider port'] == ""):
               options.provport = None
            else:
                options.provport = int(prov['provider port'])
            options.provos = prov['provider os']
            options.provvc = prov['provider vcenter']
            options.provcom = prov['provider comment']
            register_provider()

validate_input()
session.login()
read_csv()
session.delete('endeavour/session/')
