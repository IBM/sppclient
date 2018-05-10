#
# Script to do an Oracle restore given an optional date range of the copy
# An existing restore job is required, copy version of that job will be updated if applicable
# If no date range is provided the latest copy will be used
# Backup job name for the copy to use can also be provided
# Set the cancel parameter = true if using this script to cancel/clean up an existing restore job
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
parser.add_option("--start", dest="start", help="Start Date filter for backup version (optional)")
parser.add_option("--end", dest="end", help="End Date filter for backup version (optional)")
parser.add_option("--backup", dest="backup", help="Backup job name for copy to use (optional)")
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

def get_version_for_policy(policy):
    version = {}
    metadata = {}
    sourceurl = policy['spec']['source'][0]['href']
    source = client.EcxAPI(session, 'oracle').get(url=sourceurl)
    # no backup filters supplied use latest
    if (options.end is None and options.start is None and options.backup is None):
        version['href'] = source['links']['latestversion']['href']
        metadata['id'] = "latest"
        metadata['name'] = "Use Latest"
        version['metadata'] = metadata
        logger.info("Using latest backup copy version.")
        return version
    # match on backup copy name no dates supplied
    elif (options.end is None and options.start is None and options.backup is not None):
        versionsurl = source['links']['versions']['href']
        versions = client.EcxAPI(session, 'oracle').get(url=versionsurl)['versions']
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (options.backup.upper() == vers['protectionInfo']['policyName'].upper()):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:]
                version['metadata'] = metadata
                logger.info("Using backup copy version from: %s" % metadata['name'])
                return version
    # match on dates and backup copy name
    elif (options.end is not None and options.start is not None and options.backup is not None):
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        versionsurl = source['links']['versions']['href']
        versions = client.EcxAPI(session, 'oracle').get(url=versionsurl)['versions']
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (prottime > start and prottime < end and options.backup.upper() == vers['protectionInfo']['policyName'].upper()):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:]
                version['metadata'] = metadata
                logger.info("Using backup copy version from: %s" % metadata['name'])
                return version
    # match on dates no copy named supplied    
    else:
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        versionsurl = source['links']['versions']['href']
        versions = client.EcxAPI(session, 'oracle').get(url=versionsurl)['versions']
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (prottime > start and prottime < end):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:]
                version['metadata'] = metadata
                logger.info("Using backup copy version from: %s" % metadata['name'])
                return version
    logger.info("No backup copy found with provided dates or backup copy name")
    session.delete('endeavour/session/')
    sys.exit(2)

def update_restore_policy(policy):
    polid = policy['id']
    del policy['id']
    del policy['links']
    del policy['lastUpdated']
    del policy['creationTime']
    del policy['logicalDelete']
    del policy['rbacPath']
    del policy['tenantId']
    policy = client.EcxAPI(session, 'policy').put(resid=polid, data=policy)
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

def run_restore():
    job = get_restore_job()
    if (options.cancel.upper() == "TRUE"):
        jobsession = get_pending_job_session(job)
        job = cancel_restore_job(jobsession)
    else:
        policy = get_policy_for_job(job)
        version = get_version_for_policy(policy)
        policy['spec']['source'][0]['version'] = version
        policy = update_restore_policy(policy)
        job = run_restore_job(job)

session = client.EcxSession(options.host, options.username, options.password)
session.login()

run_restore()

session.delete('endeavour/session/')

