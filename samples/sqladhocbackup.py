# Script to ad-hoc backup a SQL database in SPP
# Use sqlrestore.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import datetime
import time
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--inst", dest="inst", help="Instance name in case db name exists in multiple (optional)")
parser.add_option("--ag", dest="ag", help="Availability group name in case db name exists in multiple (optional)")
parser.add_option("--db", dest="db", help="db name")
parser.add_option("--sla", dest="sla", help="SLA policy to run if database is assigned to multiple")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.db is None):
        print("Invalid input, use -h switch for help")
        sys.exit(1)

def find_db():
    searchdata = {"name":options.db}
    dbsearch = client.SppAPI(session, 'apiapp').post(path="/search?resourceType=database&applicationType=sql&from=hlo", data=searchdata)['databases']
    if not dbsearch:
        logger.warning("Did not find db " + options.db)
        session.logout()
        sys.exit(2)
    for founddb in dbsearch:
        if founddb['name'] == options.db:
            if options.inst is not None:
                inst = client.SppAPI(session, 'apiapp').get(url=founddb['links']['instance']['href'])
                if options.inst.upper() in inst['name']:
                    return founddb
            elif options.ag is not None:
                dag = client.SppAPI(session, 'apiapp').get(url=founddb['links']['databaseGroup']['href'])
                if options.ag.upper() in dag['name']:
                    return founddb
            else:
                return founddb
    logger.warning("Did not find db " + options.db)
    session.logout()
    sys.exit(3)

def backup_db():
    db = find_db()
    backup = {}
    backup['resource'] = []
    backup['resource'].append(db['links']['self']['href'])
    backup['subtype'] = "sql"
    if len(db['storageProfiles']) < 1:
        logger.warning("Database is not assigned to an SLA policy")
        session.logout()
        sys.exit(4)
    if options.sla is not None:
        for sp in db['storageProfiles']:
            if sp.upper() == options.sla.upper():
                backup['slaPolicyName'] = sp
    else:
        backup['slaPolicyName'] = db['storageProfiles'][0]
    if 'slaPolicyName' not in backup:
        logger.warning("Provided SLA policy was not found assigned to this database")
        session.logout()
        sys.exit(5)
    try:
        response = client.SppAPI(session, 'ngpapp').post(path='?action=adhoc', data=backup)
        logger.info("Running backup job for db " + options.db)
    except:
        logger.warning("Error running backup job, please see appliance logs for details, note that concurrent runs for the same job is not supported.")

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
backup_db()
session.logout()
