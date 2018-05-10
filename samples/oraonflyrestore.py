#
# Script to create an Oracle Instant Database Recovery (use data) policy
# and run the auto-generated job automatically.
# Please use python oraonflyrestore.py -h to get help with input parameters/options
#

import imp
import json
import sys
import time
from optparse import OptionParser
import logging

import ecxclient.sdk.client as client

logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="ECX Username")
parser.add_option("--pass", dest="password", help="ECX Password")
parser.add_option("--host", dest="host", help="ECX Host, (ex. https://172.20.58.10:8443)")
parser.add_option("--instance", dest="instance", help="Instance Name")
parser.add_option("--source", dest="sourcedb", help="Source Database Name")
parser.add_option("--dest", dest="destdb", help="Destination Database Name")
parser.add_option("--mounttype", dest="mounttype",
                  help="Mount Point Rename Type (optional), (prefix|suffix|replace|none|timestamp (default))")
parser.add_option("--mountstring1", dest="mountstring1", help="Mountpoint Rename String (needed for prefix, suffix, and replace, for replace this is the old string)")
parser.add_option("--mountstring2", dest="mountstring2", help="Mountpoint Rename String (needed for replace, for replace this is the new string)")
parser.add_option("--copy", dest="copypol", help="Copy Policy Name")

(options, args) = parser.parse_args()

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.instance is None or options.sourcedb is None or options.destdb is None):
        logger.warning("Invalid input, use -h switch for help")
        sys.exit(2)

def get_instances_info():
    return client.OracleAPI(session).get_instances()
    
def get_database_info(instance):
    return client.OracleAPI(session).get_databases_in_instance(instance['id'])

def find_instance_in_list(instances):
    for instance in instances:
        if (instance['name'] == options.instance):
            return instance
    logger.warning("Instance not found")
    sys.exit(2)

def find_database_in_instance(databases):
    for database in databases:
        if (database['name'] == options.sourcedb):
            return database
    logger.warning("Source database not found")
    sys.exit(2)

def get_site_info(database):
    return client.EcxAPI(session, 'site').get(resid=database['siteId'])

def get_database_copy_versions(instance, database):
    return client.OracleAPI(session).get_database_copy_versions(instance['id'], database['id'])

def get_latest_version_for_filter(versions):
    filteredversion = {'protectionInfo':{'protectionTime':0}}
    found = False
    for version in versions:
        if (version['protectionInfo']['policyName'] == options.copypol and
            version['protectionInfo']['protectionTime'] > filteredversion['protectionInfo']['protectionTime']):
            filteredversion = version
            found = True

    if (found == False):
        logger.warning("Copy name not found")
        sys.exit(2)
    return filteredversion

def create_policy_and_job(policy):
    polresp = client.EcxAPI(session, 'policy').post(data=policy)
    generatedjob = {"name":policy['name'],"description":"Auto-generated job for Policy " + policy['name'],"policyId":polresp['id'],"triggerIds":[]}
    jobresp = client.EcxAPI(session, 'job').post(data=generatedjob)
    return jobresp

def run_generated_job(job):
    return client.JobAPI(session).run(job['id'])
    
def build_restore_policy(database, instance, siteinfo):
    policy = {}
    spec = {}
    subpolicyarray = []
    subpolicy = {}
    destination = {}
    mapdatabase = {}
    sourcearray = []
    source = {}
    option = {}

    source['href'] = database['links']['self']['href'] + "?time=0"
    source['resourceType'] = "database"
    source['id'] = database['id']
    source['include'] = True
    source['metadata'] = {"path": siteinfo['name'] + ":" + siteinfo['id'] + "/"
                          + instance['name'] + ":" + instance['id'],
                          "name": database['name'], "id": database['id']}
    source['version'] = {"href": database['links']['self']['href'] + "/version/latest"}
    source['version']['metadata'] = {"id": "latest", "name": "Use Latest"}
    
    sourcearray.append(source)

    destination['target'] = {"href": database['links']['instance']['href'],
                             "resourceType": "applicationinstance",
                             "metadata": { "path": siteinfo['name'] + ":" + siteinfo['id'],
                                           "name": instance['name'], "id": instance['id']}}
    destination['mapdatabase'] = {database['links']['self']['href'] + "?time=0": {"name": options.destdb}}

    option['autocleanup'] = True
    option['continueonerror'] = True
    option['createRmanEntries'] = False
    option['overwritesession'] = False
    option['overwriteExistingDb'] = False
    option['makepermanent'] = "user"
    option['protocol'] = "FC"
    option['applicationOption'] = {"leaveDbShutDown": False, "mountPointRename": "default",
                                   "mountPointPrefix": "", "mountPointSuffix": "",
                                   "mountPointOldSubstring": "", "mountPointNewSubstring": "",
                                   "initParams": "source", "initParamsTemplateFile": ""}
    option['metadata'] = {"hasPolicyOptions": True, "hasStorageOptions": True}

    subpolicy['type'] = "restore"
    subpolicy['name'] = "OracleOnFlyRestore" + str(int(time.time()))
    subpolicy['description'] = "Policy created automatically by on-the-fly restore script."
    subpolicy['source'] = {"copy": {"site" : {"href": siteinfo['links']['self']['href'],
                                  "metadata": {"name": siteinfo['name'], "pointintime": False}}}}
    subpolicy['destination'] = destination
    subpolicy['option'] = option
    subpolicyarray.append(subpolicy)
    
    spec['applicationType'] = "oracle"
    spec['view'] = ""
    spec['notification'] = []
    spec['subpolicy'] = subpolicyarray
    spec['source'] = sourcearray

    policy['name'] = "OracleOnFlyRestore" + str(int(time.time()))
    policy['serviceId'] = "com.catalogic.ecx.serviceprovider.recovery.application"
    policy['type'] = "recovery"
    policy['subType'] = "application"
    policy['description'] = "Policy created automatically by on-the-fly restore script."
    policy['version'] = "2.0"
    policy['spec'] = spec
    policy['script'] = {}

    return policy

def update_policy_options(policy):
    if (options.copypol is not None):
        versions = get_database_copy_versions(instance, database)['versions']
        version = get_latest_version_for_filter(versions)
        updatedversion = {"href": version['links']['self']['href']}
        updatedversion['metadata'] = {"id": version['id'],
                                      "name": time.strftime('%b %d %H:%M:%S %Y',
                                                            time.localtime(version['protectionInfo']['protectionTime']/1000))}
        policy['spec']['source'][0]['version'] = updatedversion

    if (options.mounttype == "prefix"):
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointRename'] = "prefix"
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointPrefix'] = options.mountstring1
    if (options.mounttype == "suffix"):
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointRename'] = "suffix"
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointSuffix'] = options.mountstring1
    if (options.mounttype == "none"):
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointRename'] = "none"
    if (options.mounttype == "replace"):
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointRename'] = "replace"
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointOldSubstring'] = options.mountstring1
        policy['spec']['subpolicy'][0]['option']['applicationOption']['mountPointNewSubstring'] = options.mountstring2

    return policy

validate_input()
session = client.EcxSession(options.host, options.username, options.password)
session.login()

instances = get_instances_info()['instances']
instance = find_instance_in_list(instances)
databases = get_database_info(instance)
database = find_database_in_instance(databases['databases'])
siteinfo = get_site_info(database)
policy = build_restore_policy(database, instance, siteinfo)
policy = update_policy_options(policy)

generatedjob = create_policy_and_job(policy)
run_generated_job(generatedjob)
session.delete('endeavour/session/')

