#
# Script to update and run an existing SQL restore job
# --restore parameter is always required
# Use the --cancel="True" parameter to cancel an active restore job
# --source, --tinst, and --tdb, parameters are required for restore
# --start, --end, and --backup are optional to determine copy version used for restore
# Latest copy version will be used unless start and end parameters specified
# Note that script currently supports only one database source/target
# 

import json
import sys
import time
import datetime
from optparse import OptionParser
import logging
import ecxclient.sdk.client as client

logger = logging.getLogger('logger')
logging.basicConfig()
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="ECX Username")
parser.add_option("--pass", dest="password", help="ECX Password")
parser.add_option("--host", dest="host", help="ECX Host, (ex. https://172.20.58.10:8443)")
parser.add_option("--restore", dest="restore", help="Restore Job Name")
parser.add_option("--source", dest="source", help="Source database name")
parser.add_option("--start", dest="start", help="Start Date filter for backup version (optional)")
parser.add_option("--end", dest="end", help="End Date filter for backup version (optional)")
parser.add_option("--backup", dest="backup", help="Backup job name for copy to use (optional)")
parser.add_option("--tinst", dest="tinst", help="Target instance name")
parser.add_option("--tdb", dest="tdb", help="Target database name")
parser.add_option("--cancel", dest="cancel", help="Enter 'true' for Cancel/Cleanup restore (optional)")
(options, args) = parser.parse_args()
if (options.cancel is None):
    options.cancel = "false"

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def get_restore_job():
    jobs = client.EcxAPI(session, 'job').list()
    for job in jobs:
        if(job['name'].upper() == options.restore.upper()):
            return job
    logger.info("No job found with name %s" % options.restore)
    session.delete('endeavour/session/')
    sys.exit(2)

def get_policy_for_job(job):
    policy = client.EcxAPI(session, 'policy').get(resid=job['policyId'])
    return policy

def get_pending_job_session(job):
    sessionurl = job['links']['pendingjobsessions']['href']
    jobsession = client.EcxAPI(session, 'jobsession').get(url=sessionurl)
    if (len(jobsession['sessions']) < 1):
        logger.info("No pending job sessions found.")
        session.delete('endeavour/session/')
        sys.exit(2)
    return jobsession['sessions'][0]

def cancel_restore_job(jobsession):
    sessioninfo = jobsession['id'] + "?action=resume&actionname=end_ia"
    logger.info("Cancelling restore session: %s" % jobsession['id'])
    cancel = client.EcxAPI(session, 'jobsession').post(path=sessioninfo)
    return cancel

def run_restore_job(job):
    logger.info("Running restore job: %s" % job['name'])
    job = client.JobAPI(session).run(job['id'])
    return job

def get_source_info():
    sourceinsdbinfo = {}
    instances = client.EcxAPI(session, 'application').get(path="/sql/instance")['instances']
    for instance in instances:
        sourcedbs = client.EcxAPI(session, 'application').get(url=instance['links']['databases']['href'])['databases']
        for sourcedb in sourcedbs:
            if (sourcedb['name'].upper() == options.source.upper()):
                sourceinsdbinfo['instance'] = instance
                sourceinsdbinfo['database'] = sourcedb
                return sourceinsdbinfo
    logger.info("No source dbs found with name %s" % options.source)
    session.delete('endeavour/session/')
    sys.exit(2)

def get_versions_for_source(source):
    versionurl = source['database']['links']['self']['href']+"/version"
    versionparams = {'filter': '[{"property":"siteId","op":"=","value":"%s"}]'%source['instance']['siteId']}
    versions = client.EcxAPI(session, 'application').get(url=versionurl, params=versionparams)['versions']
    if (not versions):
        logger.info("No copy versions found")
        session.delete('endeavour/session/')
        sys.exit(2)
    return versions

def get_site_for_source(source):
    siteurl = source['instance']['links']['site']['href']
    sourcesite = client.EcxAPI(session, 'application').get(url=siteurl)
    return sourcesite

def get_site_for_target(target):
    siteurl = target['links']['site']['href']
    targetsite = client.EcxAPI(session, 'application').get(url=siteurl)
    return targetsite

def find_version_for_parameters(versions, source):
    version = {}
    metadata = {}
    # no backup filters supplied use latest
    if (options.end is None and options.start is None and options.backup is None):
        version['href'] = source['database']['links']['self']['href']+"/version/latest"
        metadata['id'] = "latest"
        metadata['name'] = "Use Latest"
        version['metadata'] = metadata
        logger.info("Using latest backup copy version.")
        return version
    # match on backup copy name no dates supplied
    elif (options.end is None and options.start is None and options.backup is not None):
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (options.backup.upper() == vers['protectionInfo']['policyName'].upper()):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:].replace("  "," ")
                version['metadata'] = metadata
                logger.info("Using backup copy version from: %s" % metadata['name'])
                return version
    # match on dates and backup copy name
    elif (options.end is not None and options.start is not None and options.backup is not None):
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (prottime > start and prottime < end and options.backup.upper() == vers['protectionInfo']['policyName'].upper()):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:].replace("  "," ")
                version['metadata'] = metadata
                logger.info("Using backup copy version from: %s" % metadata['name'])
                return version
    # match on dates no copy named supplied    
    else:
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (prottime > start and prottime < end):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:].replace("  "," ")
                version['metadata'] = metadata
                logger.info("Using backup copy version from: %s" % metadata['name'])
                return version
    logger.info("No backup copy found with provided dates or backup copy name")
    session.delete('endeavour/session/')
    sys.exit(2)

def get_target_info():
    instances = client.EcxAPI(session, 'application').get(path="/sql/instance")['instances']
    for instance in instances:
        if (instance['name'].upper() == options.tinst):
            return instance
    logger.info("No target instance found with name %s" % options.tinst)
    session.delete('endeavour/session/')
    sys.exit(2)

def update_restore_policy_object(policy, source, version, target, sourcesite, targetsite):
    policy['spec']['source'][0]['version'] = version
    policy['spec']['source'][0]['href'] = source['database']['links']['self']['href']+"?time=0"
    policy['spec']['source'][0]['id'] = source['database']['id']
    specsormd = {}
    specsormd['id'] = source['database']['id']
    specsormd['name'] = source['database']['name']
    specsorpath = sourcesite['name'] + ":" + sourcesite['id'] + "/" + source['instance']['name'] + ":" + source['instance']['id']
    specsormd['path'] = specsorpath
    policy['spec']['source'][0]['metadata'] = specsormd
    policy['spec']['subpolicy'][0]['source']['copy']['site']['href'] = sourcesite['links']['self']['href']
    policy['spec']['subpolicy'][0]['source']['copy']['site']['metadata']['name'] = sourcesite['name']
    specdestmdb = {source['database']['links']['self']['href']+"?time=0": {"name": options.tdb}}
    policy['spec']['subpolicy'][0]['destination']['mapdatabase'] = specdestmdb
    policy['spec']['subpolicy'][0]['destination']['target']['href'] = target['links']['self']['href']
    policy['spec']['subpolicy'][0]['destination']['target']['metadata']['id'] = target['id']
    policy['spec']['subpolicy'][0]['destination']['target']['metadata']['name'] = target['name']
    policy['spec']['subpolicy'][0]['destination']['target']['metadata']['path'] = targetsite['name'] + ":" + targetsite['id']
    return policy

def update_restore_policy(updatedpolicy):
    polid = updatedpolicy['id']
    del updatedpolicy['id']
    del updatedpolicy['links']
    del updatedpolicy['lastUpdated']
    del updatedpolicy['creationTime']
    del updatedpolicy['logicalDelete']
    del updatedpolicy['rbacPath']
    del updatedpolicy['tenantId']
    newpolicy = client.EcxAPI(session, 'policy').put(resid=polid, data=updatedpolicy)
    return newpolicy

def run_restore():
    job = get_restore_job()
    if (options.cancel.upper() == "TRUE"):
        jobsession = get_pending_job_session(job)
        job = cancel_restore_job(jobsession)
    else:
        policy = get_policy_for_job(job)
        source = get_source_info()
        versions = get_versions_for_source(source)
        sourcesite = get_site_for_source(source)
        version = find_version_for_parameters(versions, source)
        target = get_target_info()
        targetsite = get_site_for_target(target)
        updatedpolicy = update_restore_policy_object(policy, source, version, target, sourcesite, targetsite)
        newpolicy = update_restore_policy(updatedpolicy)
        job = run_restore_job(job)

session = client.EcxSession(options.host, options.username, options.password)
session.login()

run_restore()

session.delete('endeavour/session/')
