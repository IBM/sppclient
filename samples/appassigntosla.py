# Script to assign one or more databases (SQL, Oracle or DB2) to an SLA policy in SPP
# Use appassigntosla.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--type", dest="type", help="Application type: sql, oracle or db2")
parser.add_option("--dbs", dest="dbs", help="Database name(s) (comma seperated)")
parser.add_option("--sla", dest="sla", help="SLA Policy Name", default="")
(options, args) = parser.parse_args()
if(options.dbs is not None):
    options.dbs = options.dbs.split(",")

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.dbs is None or options.sla is None or options.type is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)

def validate_app_types():
    if(options.type not in ['sql','db2','oracle']):
       print("Invalid type, valid types are 'sql', 'db2', and 'oracle'")
       sys.exit(3)

def get_db_info():
    dbarray = []
    for db in options.dbs:
        dbdata = {}
        searchdata = {"name":db}
        dbsearch = client.SppAPI(session, 'apiapp').post(path="/search?resourceType=database&applicationType="+options.type+"&from=hlo", data=searchdata)['databases']
        if not dbsearch:
            logger.warning("Did not find database " + db)
            break
        for founddb in dbsearch:
            if(founddb['name'] == db):
                dbdata['href'] = founddb['links']['self']['href']
                dbdata['id'] = founddb['id']
                dbdata['metadataPath'] = founddb['metadataPath']
                dbarray.append(copy.deepcopy(dbdata))
                logger.info("Adding db " + founddb['name'] + " to SLA " + options.sla)
                break
    return dbarray

def get_sla_info():
    sladata = {}
    slaarray = []
    if(options.sla != ""):
        slapols = client.SppAPI(session, 'sppsla').get()['slapolicies']
        for sla in slapols:
            if(sla['name'] == options.sla):
                sladata['href'] = sla['links']['self']['href']
                sladata['id'] = sla['id']
                sladata['name'] = sla['name']
                slaarray.append(copy.deepcopy(sladata))
                break
        if not slaarray:
            logger.error("No SLA Policy found with name " + options.sla)
            session.logout()
            sys.exit(2)
        else:
            return slaarray
    else:
        return ""

def assign_vms_to_sla():
    assigndata = {}
    slainfo = get_sla_info()
    dbinfo = get_db_info()
    assigndata['subtype'] = options.type
    assigndata['version'] = "1.0"
    assigndata['resources'] = dbinfo
    assigndata['slapolicies'] = slainfo
    if(slainfo == ""):
        assigndata['slapolicies'] = []
        client.SppAPI(session, 'ngpapp').post(path='?action=applySLAPolicies', data=assigndata)
        logger.info("dbs are now unassigned")
    else:
        resp = client.SppAPI(session, 'ngpapp').post(path='?action=applySLAPolicies', data=assigndata)
        logger.info("dbs are now assigned")

validate_input()
validate_app_types()
session = client.SppSession(options.host, options.username, options.password)
session.login()
assign_vms_to_sla()
session.logout()
