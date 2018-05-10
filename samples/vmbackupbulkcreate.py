#
# Script to bulk create VMWare backup jobs from a CSV
# --csv is the full path to the csv template (ex. /tmp/vmbackups.csv)
#

import json
import sys
import time
import copy
import datetime
import csv
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
parser.add_option("--csv", dest="csv", help="Full path to the csv template (ex. /tmp/vmbackups.csv)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def get_backup_job(jobparams):
    jobs = client.EcxAPI(session, 'job').list()
    for job in jobs:
        if(job['name'].upper() == jobparams['template'].upper()):
            return job
    logger.info("No template job found with name %s" % jobparams['template'])
    session.delete('endeavour/session/')
    sys.exit(2)

def get_policy_for_job(templatejob):
    policy = client.EcxAPI(session, 'policy').get(resid=templatejob['policyId'])
    return policy

def get_all_vms():
    vspheres = client.EcxAPI(session, 'vsphere').list()
    allvms = []
    for vsphere in vspheres:
        vspherevms = client.EcxAPI(session, 'vsphere').get(url=vsphere['links']['vms']['href'])['vms']
        allvms.extend(vspherevms)
    return allvms

def get_info_for_vms(allvms, jobparams):
    vmparams = jobparams['vms'].split("|")
    selectedvms = []
    for vm in allvms:
        if (vm['name'] in vmparams):
            selectedvms.append(copy.deepcopy(vm))
    return selectedvms

def build_source_info_for_vms(vmlist):
    source = []
    vmsource = {}
    vmsourcemd = {}
    for vm in vmlist:
        vmsource['href'] = vm['links']['self']['href']
        vmsource['resourceType'] = "vm"
        vmsource['id'] = vm['id']
        vmsource['include'] = True
        vmsourcemd['id'] = vm['id']
        vmsourcemd['path'] = build_path_for_vm(vm)
        vmsourcemd['name'] = vm['name']
        vmsourcemd['resourceType'] = "vm"
        vmsource['metadata'] = vmsourcemd
        source.append(copy.deepcopy(vmsource))
    return source
    

def build_path_for_vm(vm):
    vsphere = client.EcxAPI(session, 'vsphere').get(url=vm['links']['vsphere']['href'])
    dc = client.EcxAPI(session, 'vsphere').get(url=vm['links']['datacenter']['href'])
    sitepath = vsphere['siteName'] + ":" + vsphere['siteId']
    vcpath = vsphere['name'] + ":" + vsphere['id']
    dcpath = dc['name'] + ":" + dc['id']
    # seems like we're unable to build folder path without iterating through all of them
    # this causes minor issue with autodirect to selected VMs in folders in the ECX UI
    # not needed for succesful creation of the policy or running it, leaving it out for performance
    folderpath = "folder"
    path = sitepath + "/" + vcpath + "/" + dcpath + "/" + folderpath
    return path

def build_policy_for_create(policy, sourceinfo):
    policy['spec']['source'] = sourceinfo
    return policy

def create_policy(updatedpolicy, jobparams):
    del updatedpolicy['id']
    del updatedpolicy['links']
    del updatedpolicy['lastUpdated']
    del updatedpolicy['creationTime']
    del updatedpolicy['logicalDelete']
    del updatedpolicy['rbacPath']
    del updatedpolicy['tenantId']
    updatedpolicy['name'] = jobparams['backup']
    newpolicy = client.EcxAPI(session, 'policy').post(data=updatedpolicy)
    return newpolicy

def create_job(newpolicy, jobparams):
    newjob = {}
    newjob['name'] = jobparams['backup']
    newjob['policyId'] = newpolicy['id']
    newjob['description'] = "Auto-generated job for Policy " + jobparams['backup']
    newjob['triggerIds'] = []
    return client.EcxAPI(session, 'job').post(data=newjob)

def build_jobs_list():
    with open(options.csv) as csvfile:
        jobparamslist = [{k: str(v) for k, v in row.items()} for row in csv.DictReader(csvfile)]
    return jobparamslist

def create_new_backup_jobs():
    logger.info("Getting VM Information...")
    allvms = get_all_vms()
    logger.info("Reading CSV...")
    jobparamslist = build_jobs_list()
    for jobparams in jobparamslist:
        templatejob = get_backup_job(jobparams)
        templatepolicy = get_policy_for_job(templatejob)
        vmlist = get_info_for_vms(allvms, jobparams)
        sourceinfo = build_source_info_for_vms(vmlist)
        updatedpolicy = build_policy_for_create(templatepolicy, sourceinfo)
        newpolicy = create_policy(updatedpolicy, jobparams)
        newjob = create_job(newpolicy, jobparams)
        logger.info("Created job %s" % newjob['name'])


session = client.EcxSession(options.host, options.username, options.password)
session.login()
create_new_backup_jobs()

session.delete('endeavour/session/')

