#
# Script to update and run an existing VMWare restore job
# --restore is always required (existing restore job name)
# --mode is always required (restore run mode, Test|Production|Clone)
# --desttype corresponds to the type of restore being performed
#       1 = use orig host/cluster with sys defined IP (default)
#       2 = use orig host/cluster with original IP
#       3 = use alternate host/cluster (requires hostdest,
#           pvlan, tvlan, and dsdest to be defined)
#           Note: all source datastores and networks will be mapped to a single target
# --vms is optional, job will run as-is without it, use commas to seperate list of VMs
# --start and --end determine time window of copy to use, latest will be used if blank
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
parser.add_option("--restore", dest="restore", help="Restore Job Name")
parser.add_option("--mode", dest="mode", help="Restore Job Run Mode")
parser.add_option("--vms", dest="vms", help="List of VMs to restore (comma seperated)")
parser.add_option("--start", dest="start", help="Start date/time of copy to use")
parser.add_option("--end", dest="end", help="End date/time of copy to use")
parser.add_option("--desttype", dest="desttype", default="1", help="Destination type (1|2|3)")
parser.add_option("--hostdest", dest="hostdest", help="Destination host/cluster (requireed for type 3)")
parser.add_option("--pvlan", dest="pvlan", help="Destination prod. VLAN (requireed for type 3)")
parser.add_option("--tvlan", dest="tvlan", help="Destination test VLAN (requireed for type 3)")
parser.add_option("--dsdest", dest="dsdest", help="Destination datastore (requireed for type 3)")
parser.add_option("--folder", dest="folder", help="Destination folder (optional) (ex. /testvms)")
parser.add_option("--cancel", dest="cancel", help="Set to \"True\" to cancel restore job")

(options, args) = parser.parse_args()
if(options.vms is not None):
    options.vms = options.vms.split(",")
if(options.cancel is None):
    options.cancel = ""

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

def get_info_for_vms():
    logger.info("Getting information for VMs...")
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
        vmsource['href'] = vm['links']['self']['href']+"?time=0"
        vmsource['resourceType'] = "vm"
        vmsource['id'] = vm['id']
        vmsource['include'] = True
        vmsourcemd['id'] = vm['id']
        vmsourcemd['path'] = build_path_for_vm(vm)
        vmsourcemd['name'] = vm['name']
        vmsource['metadata'] = vmsourcemd
        vmsource['version'] = build_version_for_vm(vm)
        source.append(copy.deepcopy(vmsource))
    return source

def build_version_for_vm(vm):
    vmurl = vm['links']['self']['href']+"?time=0"
    vmurlarray = [vmurl]
    assdata = {'associatedWith': vmurlarray,"resourceType": "site"}
    association = client.EcxAPI(session, 'vsphere').post(path="query", data=assdata)['sites'][0]
    versionurl = vm['links']['self']['href']+"/version"
    versionparams = {'time': 0, 'filter': '[{"property":"siteId","op":"=","value":"%s"}]'%association['id']}
    versions = client.EcxAPI(session, 'vsphere').get(url=versionurl, params=versionparams)['versions']
    version = {}
    metadata = {}
    # no copy filters supplied use latest
    if (options.end is None or options.start is None):
        version['href'] = vm['links']['self']['href']+"/version/latest?time=0"
        metadata['id'] = "latest"
        metadata['name'] = "Use Latest"
        version['metadata'] = metadata
        logger.info("Using latest backup copy version.")
        return version
    # match on dates
    else:
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (start < prottime and prottime < end):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:].replace("  "," ")
                version['metadata'] = metadata
                logger.info("Using backup copy version from: " + metadata['name'] + " for " + vm['name'])
                return version
    logger.info("No backup copy found with provided dates")
    session.delete('endeavour/session/')
    sys.exit(2)

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

def build_policy_for_update(policy, sourceinfo, vmlist):
    policy['spec']['source'] = sourceinfo
    if(options.desttype == "1"):
        policy['spec']['subpolicy'][0]['destination'] = {"systemDefined": True}
        policy['spec']['subpolicy'][0]['option']['poweron'] = True
    elif(options.desttype == "2"):
        policy['spec']['subpolicy'][0].pop('destination', None)
        policy['spec']['subpolicy'][0]['option']['poweron'] = False
    elif(options.desttype == "3"):
        policy['spec']['subpolicy'][0]['destination'] = build_alt_dest(policy, vmlist)
    return policy

def build_alt_dest(policy, vmlist):
    vmurls = []
    # need to call query api at this point to get proper href format for mapping def
    for vm in vmlist:
        vmurls.append(copy.deepcopy(vm['links']['self']['href']+"/version/latest"))
    qd = {'associatedWith': vmurls,"resourceType": "vm"}
    vmqlist = client.EcxAPI(session, 'vsphere').post(path="query", data=qd)['vms']
    destination = {}
    destination['target'] = build_alt_dest_target()
    destination['mapvirtualnetwork'] = build_alt_dest_vlan(destination, vmqlist)
    destination['mapRRPdatastore'] = build_alt_dest_ds(destination, vmqlist)
    destination['mapsubnet'] = {"systemDefined": True}
    if(options.folder is not None and options.folder.startswith('/')):
        destination['vmfolderpath'] = options.folder
    return destination

def build_alt_dest_target():
    logger.info("Building alternate host/cluster destination")
    target = {}
    targetmd = {}
    targethost = ""
    vspheres = client.EcxAPI(session, 'vsphere').list()
    for vsphere in vspheres:
        hosts = client.EcxAPI(session, 'vsphere').get(url=vsphere['links']['hosts']['href'])['hosts']
        for host in hosts:
            if(host['name'] == options.hostdest):
                targethost = host
                targetvsphere = vsphere
                targetdc = client.EcxAPI(session, 'vsphere').get(url=host['links']['datacenter']['href'])
                break
        if(targethost == ""):
            clusters = client.EcxAPI(session, 'vsphere').get(url=vsphere['links']['clusters']['href'])['clusters']
            for cluster in clusters:
                if(cluster['name'] == options.hostdest):
                    targethost = cluster
                    targetvsphere = vsphere
                    targetdc = client.EcxAPI(session, 'vsphere').get(url=host['links']['datacenter']['href'])
                    break
    if(targethost == ""):
        logger.info("No target host found with name provided")
        session.delete('endeavour/session/')
        sys.exit(2)
    target['href'] = targethost['links']['self']['href']
    target['resourceType'] = targethost['resourceType']
    targetmd['path'] = targetvsphere['siteName'] + ":" + targetvsphere['siteId'] + "/" + targetvsphere['name'] + ":"
    targetmd['path'] += targetvsphere['id'] + "/" + targetdc['name'] + ":" + targetdc['id']
    targetmd['name'] = targethost['name']
    target['metadata'] = targetmd
    return target

def build_alt_dest_vlan(destination, vmqlist):
    logger.info("Building alternate VLAN")
    mapvirtualnetwork = {}
    mapvnmetadata = {}
    targethost = client.EcxAPI(session, 'vsphere').get(url=destination['target']['href'])
    targetnetworks = client.EcxAPI(session, 'vsphere').get(url=targethost['links']['networks']['href'])['networks']
    sourcenetworks = []
    for tnw in targetnetworks:
        if(tnw['name'] == options.pvlan):
            recoverynetwork = tnw
    for tnw in targetnetworks:
        if(tnw['name'] == options.tvlan):
            testnetwork = tnw
    try:
        recoverynetwork
    except NameError:
        logger.info("No prod. network found with provided name")
        session.delete('endeavour/session/')
        sys.exit(2)
    try:
        testnetwork
    except NameError:
        logger.info("No test network found with provided name")
        session.delete('endeavour/session/')
        sys.exit(2)
    vmurls = []
    for vm in vmqlist:
        vmurls.append(copy.deepcopy(vm['links']['self']['href']))
    querydata = {'associatedWith': vmurls,"resourceType": "network"}
    sourcenetworks = client.EcxAPI(session, 'vsphere').post(path="query", data=querydata)['networks']
    for snw in sourcenetworks:
        snwkey = snw['links']['self']['href']
        mapvirtualnetwork[snwkey] = {}
        mapvirtualnetwork[snwkey]['recovery'] = recoverynetwork['links']['self']['href']
        mapvirtualnetwork[snwkey]['test'] = testnetwork['links']['self']['href']
        mapvnmetadata[snwkey] = {}
        mapvnmetadata[snwkey]['source'] = {}
        mapvnmetadata[snwkey]['recovery'] = {}
        mapvnmetadata[snwkey]['test'] = {}
        mapvnmetadata[snwkey]['source']['name'] = snw['name']
        mapvnmetadata[snwkey]['source']['href'] = snwkey
        mapvnmetadata[snwkey]['recovery']['name'] = recoverynetwork['name']
        mapvnmetadata[snwkey]['recovery']['href'] = recoverynetwork['links']['self']['href']
        mapvnmetadata[snwkey]['test']['name'] = testnetwork['name']
        mapvnmetadata[snwkey]['test']['href'] = testnetwork['links']['self']['href']
    mapvirtualnetwork['metadata'] = mapvnmetadata
    return mapvirtualnetwork
        

def build_alt_dest_ds(destination, vmqlist):
    logger.info("Building alternate datastore")
    mapRRPdatastore = {}
    mapRRPdatastoremd = {}
    targethost = client.EcxAPI(session, 'vsphere').get(url=destination['target']['href'])
    targetdatastores = client.EcxAPI(session, 'vsphere').get(url=targethost['links']['datastores']['href'])['datastores']
    for tds in targetdatastores:
        if(tds['name'] == options.dsdest):
            targetds = tds
    try:
        targetds
    except NameError:
        logger.info("No datastore found with provided name")
        session.delete('endeavour/session/')
        sys.exit(2)
    vmurls = []
    for vm in vmqlist:
        vmurls.append(copy.deepcopy(vm['links']['self']['href']))
    querydata = {'associatedWith': vmurls,"resourceType": "datastore"}
    sourcedatastores = client.EcxAPI(session, 'vsphere').post(path="query", data=querydata)['datastores']
    for sds in sourcedatastores:
        sdskey = sds['links']['self']['href']
        mapRRPdatastore[sdskey] = targetds['links']['self']['href']
        mapRRPdatastoremd[sdskey] = {}
        mapRRPdatastoremd[sdskey]['source'] = {}
        mapRRPdatastoremd[sdskey]['source']['name'] = sds['name']
        mapRRPdatastoremd[sdskey]['source']['href'] = sdskey
        mapRRPdatastoremd[sdskey]['destination'] = {}
        mapRRPdatastoremd[sdskey]['destination']['name'] = targetds['name']
        mapRRPdatastoremd[sdskey]['destination']['href'] = targetds['links']['self']['href']
    mapRRPdatastore['metadata'] = mapRRPdatastoremd
    return mapRRPdatastore

def update_policy(updatedpolicy):
    polid = updatedpolicy['id']
    del updatedpolicy['id']
    del updatedpolicy['links']
    del updatedpolicy['lastUpdated']
    del updatedpolicy['creationTime']
    del updatedpolicy['logicalDelete']
    del updatedpolicy['rbacPath']
    del updatedpolicy['tenantId']
    #prettyprint(updatedpolicy)
    newpolicy = client.EcxAPI(session, 'policy').put(resid=polid, data=updatedpolicy)
    return newpolicy

def get_pending_job_session(job):
    sessionurl = job['links']['pendingjobsessions']['href']
    jobsession = client.EcxAPI(session, 'jobsession').get(url=sessionurl)
    if (len(jobsession['sessions']) < 1):
        logger.info("No pending job sessions found.")
        session.delete('endeavour/session/')
        sys.exit(2)
    return jobsession['sessions'][0]

def run_restore_job(job):
    if(options.cancel.upper() == "TRUE"):
        jobsession = get_pending_job_session(job)
        logger.info("Cleaning up job %s" % job['name'])
        sessioninfo = jobsession['id'] + "?action=resume&actionname=end_iv"
        return client.EcxAPI(session, 'jobsession').post(path=sessioninfo)
    logger.info("Running job %s" % job['name'])
    if(options.mode.upper() == "TEST"):
        run = client.JobAPI(session).run(job['id'], "start_test_iv")
    elif(options.mode.upper() == "PRODUCTION"):
        run = client.JobAPI(session).run(job['id'], "start_recovery_iv")
    elif(options.mode.upper() == "CLONE"):
        run = client.JobAPI(session).run(job['id'], "start_clone_iv")
    return run

def update_policy_and_run_restore():
    job = get_restore_job()
    if(options.vms is not None and options.cancel.upper() != "TRUE"):
        policy = get_policy_for_job(job)
        vmlist = get_info_for_vms()
        sourceinfo = build_source_info_for_vms(vmlist)
        updatedpolicy = build_policy_for_update(policy, sourceinfo, vmlist)
        newpolicy = update_policy(updatedpolicy)
        logger.info("Updating job %s" % job['name'])
    run_restore_job(job)

session = client.EcxSession(options.host, options.username, options.password)
session.login()
update_policy_and_run_restore()

session.delete('endeavour/session/')

