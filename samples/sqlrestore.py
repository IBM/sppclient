# Script to restore a SQL db by name in SPP
# Use sqlrestore.py -h for help

import json
import logging
from optparse import OptionParser
import copy
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
parser.add_option("--db", dest="db", help="db name")
parser.add_option("--newname", dest="newname", help="New db name")
parser.add_option("--mode", dest="mode", help="restore mode, ie 'test', 'production', or 'IA'")
parser.add_option("--start", dest="start", help="Start Date for copy to restore from (optional)")
parser.add_option("--end", dest="end", help="End Date for copy to restore from (optional)")
parser.add_option("--tinst", dest="tinst", help="Target instance to restore to (optional)")
parser.add_option("--site", dest="site", help="Site to restore from (optional)")
parser.add_option("--recovery", dest="recovery", help="Set to false for no recovery (optional, defaults to recovery)")
parser.add_option("--pit", dest="pit", help="PIT recovery date/time (optional, requires latest copy)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.db is None or options.newname is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)
    if(options.start is None and options.end is not None):
        print("Start date required if end date is defined")
        sys.exit(2)
    if(options.start is not None and options.end is None):
        print("End date required if start date is defined")
        sys.exit(2)
    if(options.mode not in ['test','production','IA']):
        print("Mode invalid, please use: test, production or IA")
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
            return founddb
    logger.warning("Did not find recoverable db " + options.db)
    session.logout()
    sys.exit(4)
        
def build_db_source(dbinfo):
    source = []
    dbdata = {}
    dbdata['href'] = dbinfo['links']['self']['href']
    dbmd = {}
    dbmd['name'] = dbinfo['name']
    instanceinfo = client.SppAPI(session, 'apiapp').get(url=dbinfo['links']['instance']['href'])
    dbmd['instanceVersion'] = instanceinfo['version']
    dbmd['instanceId'] = instanceinfo['id']
    dbdata['metadata'] = dbmd
    dbdata['resourceType'] = "database"
    dbdata['id'] = dbinfo['id']
    dbdata['include'] = True
    if(options.start is not None and options.end is not None and options.pit is None):
        dbdata['version'] = build_db_version(dbinfo)
    elif(options.site is not None and options.pit is None):
        dbdata['version'] = build_db_version(dbinfo)
    else:
        dbdata['version'] = {}
        dbdata['version']['href'] = dbinfo['links']['latestversion']['href']
        dbdata['version']['metadata'] = {'useLatest':True}
        dbdata['metadata']['useLatest'] = True
    logger.info("Adding db " + dbdata['metadata']['name'] + " to restore job")
    if(options.pit is not None):
        dbdata['pointInTime'] = int(datetime.datetime.strptime(options.pit, '%m/%d/%Y %H:%M:%S').timestamp())*1000
    source.append(copy.deepcopy(dbdata))
    return source

def build_db_version(db):
    #find for datetime window only
    if(options.start is not None and options.site is None):
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').timestamp())*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').timestamp())*1000
        dbcpurl = db['links']['copies']['href']
        dbcopies = client.SppAPI(session, 'apiapp').get(url=dbcpurl)['copies']
        for copy in dbcopies:
            prottime = int(copy['protectionInfo']['protectionTime'])
            if (start < prottime and prottime < end):
                version = {}
                version['href'] = copy['links']['version']['href']
                version['copy'] = {}
                version['copy']['href'] = copy['links']['self']['href']
                version['metadata'] = {}
                version['metadata']['useLatest'] = False
                version['metadata']['protectionTime'] = prottime
                return version
    #find for site only
    elif(options.start is None and options.site is not None):
        dbcpurl = db['links']['copies']['href']
        dbcopies = client.SppAPI(session, 'apiapp').get(url=dbcpurl)['copies']
        site = find_site_by_name(options.site)
        for copy in dbcopies:
            prottime = int(copy['protectionInfo']['protectionTime'])
            if (copy['siteId'] == site['id']):
                version = {}
                version['href'] = copy['links']['version']['href']
                version['copy'] = {}
                version['copy']['href'] = copy['links']['self']['href']
                version['metadata'] = {}
                version['metadata']['useLatest'] = False
                version['metadata']['protectionTime'] = prottime
                return version
    #find copy for both
    elif(options.start is not None and options.site is not None):
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').timestamp())*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').timestamp())*1000
        dbcpurl = db['links']['copies']['href']
        dbcopies = client.SppAPI(session, 'apiapp').get(url=dbcpurl)['copies']
        site = find_site_by_name(options.site)
        for copy in dbcopies:
            prottime = int(copy['protectionInfo']['protectionTime'])
            if (start < prottime and prottime < end and copy['siteId'] == site['id']):
                version = {}
                version['href'] = copy['links']['version']['href']
                version['copy'] = {}
                version['copy']['href'] = copy['links']['self']['href']
                version['metadata'] = {}
                version['metadata']['useLatest'] = False
                version['metadata']['protectionTime'] = prottime
                return version
    logger.warning("No specified versions found in date range and/or specified site for " + db['name'])
    session.logout()
    sys.exit(3)

def find_site_by_name(sitename):
    sites = client.SppAPI(session, 'coresite').get()['sites']
    for site in sites:
        if(site['name'].upper() == options.site.upper()):
            return site
    logger.warning("Site " + site['name'] + " not found")
    session.logout()
    sys.exit(3)

def build_restore_dest(dbinfo):
    destination = {}
    if(options.tinst is None):
        destination['targetLocation'] = "original"
    else:
        destination['targetLocation'] = "alternate"
        destination['target'] = build_target_instance()
    if(options.mode in ['test','production']):
        destination['mapdatabase'] = {dbinfo['links']['self']['href']:{'name':options.newname,'paths':[]}}
    return destination


def build_subpol_source(dbinfo):
    if options.start is not None:
        return None
    else:
    #    source = {}
    #    source['copy'] = {}
    #    source['copy']['site'] = {'href':dbinfo['links']['site']['href']}
    #    source['copy']['isOffload'] = None
    #    return source
        return None
    

def build_target_instance():
    instances = client.SppAPI(session, 'apiapp').get(path='/sql/instance?from=hlo')['instances']
    for instance in instances:
        if(instance['name'] == options.tinst):
            target = {}
            target['href'] = instance['links']['self']['href']
            target['resourceType'] = instance['resourceType']
            return target
    logger.warning("No target instance found named " + options.tinst)
    session.logout()
    sys.exit(6)

def build_subpolicy(dbinfo):
    subpolicy = []
    subpol = {}
    if(options.mode in ['test','IA']):
        subpol['mode'] = "test"
    if(options.mode in ['test','production']):
        subpol['type'] = "restore"
    if(options.mode == "IA"):
        subpol['type'] = "IA"
    if(options.mode == "production"):
        subpol['mode'] = "production"
    subpol['option'] = {}
    subpol['option']['allowsessoverwrite'] = True
    subpol['option']['applicationOption'] = {"overwriteExistingDb": False}
    subpol['option']['applicationOption']['recoveryType'] = set_recovery_type()
    subpol['option']['autocleanup'] = True
    subpol['option']['continueonerror'] = True
    subpol['destination'] = build_restore_dest(dbinfo)
    subpol['source'] = build_subpol_source(dbinfo)
    subpolicy.append(subpol)
    return subpolicy

def set_recovery_type():
    if(options.pit is not None):
        return "pitrecovery"
    elif(options.recovery is None):
        return "recovery"
    elif(options.recovery.upper() == "FALSE"):
        return "norecovery"
    else:
        return "recovery"

def restore_dbs():
    restore = {}
    dbinfo = find_db()
    sourceinfo = build_db_source(dbinfo)
    subpolicy = build_subpolicy(dbinfo)
    restore['subType'] = "sql"
    restore['script'] = {"continueScriptsOnError": False, "postGuest": None, "preGuest": None}
    restore['spec'] = {}
    restore['spec']['source'] = sourceinfo
    restore['spec']['subpolicy'] = subpolicy
    restore['spec']['view'] = "applicationview"
    resp = client.SppAPI(session, 'ngpapp').post(path='?action=restore', data=restore)
    logger.info("dbs are now being restored") 

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
restore_dbs()
session.logout()
