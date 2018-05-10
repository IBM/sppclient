#
# Script to run existing backup job and then run restore for that backup
# Parameters are user, pass, host, backup job name, and restore job name
#

import imp
import json
import logging
from optparse import OptionParser
import time
import sys
import ecxclient.sdk.client as client

parser = OptionParser()
parser.add_option("--user", dest="username", help="ECX Username")
parser.add_option("--pass", dest="password", help="ECX Password")
parser.add_option("--host", dest="host", help="ECX Host, (ex. https://172.20.58.10:8443)")
parser.add_option("--bu", dest="bujobname", help="ECX Backup Job Name")
parser.add_option("--res", dest="resjobname", help="ECX Restore Job Name")
(options, args) = parser.parse_args()

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.bujobname is None or options.resjobname is None):
        logger.warning("Invalid input, use -h switch for help")
        sys.exit(2)

def setup_logging():
    logging.basicConfig(level=logging.WARNING)
    return logging.getLogger('logger')

def prettyprint(indata):
    logger.warning(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def logout():
    session.delete('endeavour/session/')

def find_backup_job_by_name():
    alljobs = client.EcxAPI(session, 'job').list()
    for job in alljobs:
        if(job['type'] == "protection" and job['name'].upper() == options.bujobname.upper()):
            return job
    logger.warning("Unable to find backup job")
    logout()
    sys.exit(2)

def find_restore_job_by_name():
    alljobs = client.EcxAPI(session, 'job').list()
    for job in alljobs:
        if(job['type'] == "recovery" and job['name'].upper() == options.resjobname.upper()):
            return job
    logger.warning("Unable to find restore job")
    logout()
    sys.exit(2)

def run_backup_job_and_wait_for_finish(backupjob):
    run = client.JobAPI(session).run(backupjob['id'])
    logger.info("Running backup job, please wait.")
    time.sleep(5)
    job = client.EcxAPI(session, 'job').get(resid=backupjob['id'])
    while (job['lastrun']['status'] == "RUNNING"):
        time.sleep(5)
        job = client.EcxAPI(session, 'job').get(resid=backupjob['id'])
    return job

def run_restore_job(restorejob):
    client.JobAPI(session).run(restorejob['id'])

def run_jobs():
    backupjob = find_backup_job_by_name()
    restorejob = find_restore_job_by_name()
    run_backup_job_and_wait_for_finish(backupjob)
    run_restore_job(restorejob)

logger = setup_logging()
validate_input()
session = client.EcxSession(options.host, options.username, options.password)
session.login()
run_jobs()
logout()

    
