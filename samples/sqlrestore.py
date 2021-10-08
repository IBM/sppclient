# Script to restore a SQL db by name in SPP
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
parser.add_option("--newname", dest="newname", help="New db name")
parser.add_option("--mode", dest="mode", help="restore mode, ie 'test', 'production', or 'IA'")
parser.add_option("--start", dest="start", help="Start Date for copy to restore from (optional)")
parser.add_option("--end", dest="end", help="End Date for copy to restore from (optional)")
parser.add_option("--tinst", dest="tinst", help="Target instance to restore to (optional)")
parser.add_option("--site", dest="site", help="Site to restore from (optional)")
parser.add_option("--recovery", dest="recovery", help="Set to false for no recovery (optional, defaults to recovery)")
parser.add_option("--pit", dest="pit", help="PIT recovery date/time (optional, requires latest copy)")
parser.add_option("--dpath", dest="dpath", help="Path to restore SQL data file(s) (optional, for production mode only)")
parser.add_option("--lpath", dest="lpath", help="Path to restore SQL log file(s) (optional, for production mode only)")
parser.add_option("--overwrite", dest="overwrite", help="Overwrite existing database (optional, defaults to false)")
parser.add_option("--wait", dest="wait", help="Wait for restore to finish and report status (optional, defaults to false)")
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
    dbsearch = client.SppAPI(session, 'apiapp').post(path="/search?resourceType=database&applicationType=sql&from=recovery", data=searchdata)['contents']
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
            elif(options.ag is not None):
                dag = client.SppAPI(session, 'apiapp').get(url=founddb['links']['databaseGroup']['href'])
                if(options.ag.upper() in dag['name']):
                    return founddb
            else:
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
    if(options.mode == 'production' and options.dpath is not None):
        for sourcepath in dbinfo['paths']:
            mapping = {}
            mapping['source'] = sourcepath['name']
            if(sourcepath['fileType'] == "DATA"):
                mapping['destination'] = options.dpath
            elif(sourcepath['fileType'] == "LOGS"):
                if(options.lpath is None):
                    logger.warning("Log files found, please define destination path")
                    session.logout()
                    sys.exit(7)
                mapping['destination'] = options.lpath
            destination['mapdatabase'][dbinfo['links']['self']['href']]['paths'].append(mapping)
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
    if(options.overwrite is not None):
        if(options.overwrite.upper() == "TRUE"):
            subpol['option']['applicationOption'] = {"overwriteExistingDb": True}
    else:
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

def wait_for_completion(resp):
    activejobses = client.SppAPI(session, 'ngpapp').get(url=resp['response']['links']['activejobsessions']['href'])
    time.sleep(3)
    if(len(activejobses['sessions']) < 1):
        logger.warning("Something went wrong, please check restore logs on SPP appliance")
        session.logout()
        sys.exit(8)
    jobses = activejobses['sessions'][0]
    jobsesurl = jobses['links']['self']['href']
    logsurl = jobses['links']['log']['href'] + "&pageSize=50000&sort=%5B%7B%22property%22:%22logTime%22,%22direction%22:%22ASC%22%7D%5D"
    currlogtime = 0
    while jobses['status'] == "RUNNING":
        logs = client.SppAPI(session, 'ngpapp').get(url=logsurl)['logs']
        for log in logs:
            if(log['logTime'] >= currlogtime): # some logs have same timestamp down to ms
                timestring = datetime.datetime.fromtimestamp(int(log['logTime']/1000)).strftime('%Y-%m-%d %H:%M:%S')
                print(timestring + " " + log['type'] + " " + log['message'])
                currlogtime = log['logTime']
        jobses = client.SppAPI(session, 'ngpapp').get(url=jobsesurl)
        currlogtime += 1 # prevent double prints if we are waiting on same timestamp
        time.sleep(10)
    print("Job ended with status: " + jobses['status'])

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
    prettyprint(restore)
    #resp = client.SppAPI(session, 'ngpapp').post(path='?action=restore', data=restore)
    if(options.wait is not None):
        if(options.wait.upper() == "TRUE"):
            wait_for_completion(resp)
    else:
        print("Restore job created")

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
restore_dbs()
session.logout()
