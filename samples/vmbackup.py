#
# Script to update and run an existing VMWare backup job
# --backup is always required (existing back up job name)
# --vms is optional, job will run as-is without it, use commas to seperate list of VMs
# --sla is optional, must be selected as one of the optional SLAs in job defintion
#

import json
import sys
import time
import copy
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
parser.add_option("--backup", dest="backup", help="Backup Job Name")
parser.add_option("--vms", dest="vms", help="List of VMs to backup/snapshot (comma seperated)")
parser.add_option("--sla", dest="sla", help="SLA Policy to use for backup (optional)")
(options, args) = parser.parse_args()
if(options.vms is not None):
    options.vms = options.vms.split(",")

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def get_backup_job():
    jobs = client.EcxAPI(session, 'job').list()
    for job in jobs:
        if(job['name'].upper() == options.backup.upper()):
            return job
    logger.info("No job found with name %s" % options.backup)
    session.delete('endeavour/session/')
    sys.exit(2)

def get_policy_for_job(job):
    policy = client.EcxAPI(session, 'policy').get(resid=job['policyId'])
    return policy

def get_info_for_vms():
    vspheres = client.EcxAPI(session, 'vsphere').list()
    allvms = []
    selectedvms = []
    for vsphere in vspheres:
        vspherevms = client.EcxAPI(session, 'vsphere').get(url=vsphere['links']['vms']['href'])['vms']
        allvms.extend(vspherevms)
    for vm in allvms:
        if (vm['name'] in options.vms):
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
    # not needed for succesful updating of the policy or running it, leaving it out for performance
    folderpath = "folder"
    path = sitepath + "/" + vcpath + "/" + dcpath + "/" + folderpath
    return path

def build_policy_for_update(policy, sourceinfo):
    policy['spec']['source'] = sourceinfo
    return policy

def update_policy(updatedpolicy):
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

def get_swf_id(policy):
    for swf in policy['spec']['storageworkflow']:
        if (swf['name'].upper() == options.sla.upper()):
            return swf['id']
    logger.info("No SLA found with name %s" % options.sla)
    session.delete('endeavour/session/')
    sys.exit(2)

def run_backup_job(job, swfid=None):
    run = client.JobAPI(session).run(job['id'], swfid)
    return run

def update_policy_and_run_backup():
    job = get_backup_job()
    policy = get_policy_for_job(job)
    if(options.vms is not None):
        logger.info("Getting VM Information for %s" % options.vms)
        vmlist = get_info_for_vms()
        sourceinfo = build_source_info_for_vms(vmlist)
        updatedpolicy = build_policy_for_update(policy, sourceinfo)
        newpolicy = update_policy(updatedpolicy)
        logger.info("Updating job %s" % job['name'])
    logger.info("Running job %s" % job['name'])
    if(options.sla is not None):
        swfid = get_swf_id(policy)
        run_backup_job(job, swfid)
    else:
        run_backup_job(job)


session = client.EcxSession(options.host, options.username, options.password)
session.login()
update_policy_and_run_backup()

session.delete('endeavour/session/')

