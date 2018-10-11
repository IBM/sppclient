# Script to get info about copies of a sql database from SPP
# Use sqlcopies.py -h for help

import json
import logging
from optparse import OptionParser
import sys
import datetime
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--inst", dest="inst", help="Instance name in case db name exists in multiple (optional)")
parser.add_option("--db", dest="db", help="db name")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.db is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)

def find_db():
    searchdata = {"name":options.db}
    dbsearch = client.SppAPI(session, 'apiapp').post(path="/search?resourceType=database&applicationType=sql&from=recovery", data=searchdata)['databases']
    if not dbsearch:
        logger.warning("Did not find recoverable db " + options.db)
        session.logout()
        sys.exit(3)
    for founddb in dbsearch:
        if(founddb['name'] == options.db):
            if(options.inst is not None):
                inst = client.SppAPI(session, 'apiapp').get(url=founddb['links']['instance']['href'])
                if(options.inst.upper() in inst['name']):
                    return founddb
            else:
                return founddb
    logger.warning("Did not find recoverable db " + options.db)
    session.logout()
    sys.exit(4)

def show_copies():
    db = find_db()
    sites = client.SppAPI(session, 'coresite').get()['sites']
    dbcpurl = db['links']['copies']['href']
    dbcopies = client.SppAPI(session, 'apiapp').get(url=dbcpurl)['copies']
    print('{:25.25s} {:25.25s} {:12.12s} {:10.10s}'.format("SLA Policy", "Backup Time", "Site", "Type"))
    for copy in dbcopies:
        butime = datetime.datetime.fromtimestamp(copy['copyTime']/1000).strftime('%Y-%m-%d %H:%M:%S')
        sitename = "Not Found"
        for site in sites:
            if(site['id'] == copy['siteId']):
                sitename = site['name']
        print('{:25.25s} {:25.25s} {:12.12s} {:10.10s}'.format(copy['protectionInfo']['policyName'], butime, sitename, copy['mappings'][0]['storageType']))

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
show_copies()
session.logout()
