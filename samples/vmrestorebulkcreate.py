#
# Script to bulk create VMWare restore jobs from a CSV
# --csv is the full path to the csv template (ex. /tmp/vmrestores.csv)
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
parser.add_option("--csv", dest="csv", help="Full path to the csv template (ex. /tmp/vmrestores.csv)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def get_restore_job(jobparams):
    jobs = client.EcxAPI(session, 'job').list()
    for job in jobs:
        if(job['name'].upper() == jobparams['template'].upper()):
            return job
    logger.info("No template job found with name %s" % jobparams['template'].upper())
    session.delete('endeavour/session/')
    sys.exit(2)

def get_policy_for_job(job):
    policy = client.EcxAPI(session, 'policy').get(resid=job['policyId'])
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

def build_source_info_for_vms(vmlist, jobparams):
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
        vmsource['version'] = build_version_for_vm(vm, jobparams)
        source.append(copy.deepcopy(vmsource))
    return source

def build_version_for_vm(vm, jobparams):
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
    if (jobparams['end'] is None or jobparams['start'] is None or jobparams['end'] == "" or jobparams['start'] == ""):
        version['href'] = vm['links']['self']['href']+"/version/latest?time=0"
        metadata['id'] = "latest"
        metadata['name'] = "Use Latest"
        version['metadata'] = metadata
        return version
    # match on dates
    else:
        start = int(datetime.datetime.strptime(jobparams['start'], '%m/%d/%Y %H:%M').strftime("%s"))*1000
        end = int(datetime.datetime.strptime(jobparams['end'], '%m/%d/%Y %H:%M').strftime("%s"))*1000
        for vers in versions:
            prottime = int(vers['protectionInfo']['protectionTime'])
            if (start < prottime and prottime < end):
                version['href'] = vers['links']['self']['href']
                metadata['id'] = vers['id']
                metadata['name'] = time.ctime(prottime/1000)[4:].replace("  "," ")
                version['metadata'] = metadata
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

def build_policy_for_update(policy, sourceinfo, vmlist, jobparams):
    policy['spec']['source'] = sourceinfo
    if(jobparams['desttype'] == "1"):
        policy['spec']['subpolicy'][0]['destination'] = {"systemDefined": True}
        policy['spec']['subpolicy'][0]['option']['poweron'] = True
    elif(jobparams['desttype'] == "2"):
        policy['spec']['subpolicy'][0].pop('destination', None)
        policy['spec']['subpolicy'][0]['option']['poweron'] = False
    elif(jobparams['desttype'] == "3"):
        policy['spec']['subpolicy'][0]['destination'] = build_alt_dest(policy, vmlist, jobparams)
    return policy

def build_alt_dest(policy, vmlist, jobparams):
    vmurls = []
    # need to call query api at this point to get proper href format for mapping def
    for vm in vmlist:
        vmurls.append(copy.deepcopy(vm['links']['self']['href']+"/version/latest"))
    qd = {'associatedWith': vmurls,"resourceType": "vm"}
    vmqlist = client.EcxAPI(session, 'vsphere').post(path="query", data=qd)['vms']
    destination = {}
    destination['target'] = build_alt_dest_target(jobparams)
    destination['mapvirtualnetwork'] = build_alt_dest_vlan(destination, vmqlist, jobparams)
    destination['mapRRPdatastore'] = build_alt_dest_ds(destination, vmqlist, jobparams)
    destination['mapsubnet'] = {"systemDefined": True}
    return destination

def build_alt_dest_target(jobparams):
    target = {}
    targetmd = {}
    targethost = ""
    vspheres = client.EcxAPI(session, 'vsphere').list()
    for vsphere in vspheres:
        hosts = client.EcxAPI(session, 'vsphere').get(url=vsphere['links']['hosts']['href'])['hosts']
        for host in hosts:
            if(host['name'] == jobparams['hostdest']):
                targethost = host
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

def build_alt_dest_vlan(destination, vmqlist, jobparams):
    mapvirtualnetwork = {}
    mapvnmetadata = {}
    targethost = client.EcxAPI(session, 'vsphere').get(url=destination['target']['href'])
    targetnetworks = client.EcxAPI(session, 'vsphere').get(url=targethost['links']['networks']['href'])['networks']
    sourcenetworks = []
    for tnw in targetnetworks:
        if(tnw['name'] == jobparams['pvlan']):
            recoverynetwork = tnw
        elif(tnw['name'] == jobparams['tvlan']):
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
        

def build_alt_dest_ds(destination, vmqlist, jobparams):
    mapRRPdatastore = {}
    mapRRPdatastoremd = {}
    targethost = client.EcxAPI(session, 'vsphere').get(url=destination['target']['href'])
    targetdatastores = client.EcxAPI(session, 'vsphere').get(url=targethost['links']['datastores']['href'])['datastores']
    for tds in targetdatastores:
        if(tds['name'] == jobparams['dsdest']):
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

def create_policy(updatedpolicy, jobparams):
    del updatedpolicy['id']
    del updatedpolicy['links']
    del updatedpolicy['lastUpdated']
    del updatedpolicy['creationTime']
    del updatedpolicy['logicalDelete']
    del updatedpolicy['rbacPath']
    del updatedpolicy['tenantId']
    updatedpolicy['name'] = jobparams['restore']
    newpolicy = client.EcxAPI(session, 'policy').post(data=updatedpolicy)
    return newpolicy

def create_job(newpolicy, jobparams):
    newjob = {}
    newjob['name'] = jobparams['restore']
    newjob['policyId'] = newpolicy['id']
    newjob['description'] = "Auto-generated job for Policy " + jobparams['restore']
    newjob['triggerIds'] = []
    return client.EcxAPI(session, 'job').post(data=newjob)

def build_jobs_list():
    with open(options.csv) as csvfile:
        jobparamslist = [{k: str(v) for k, v in row.items()} for row in csv.DictReader(csvfile)]
    return jobparamslist

def create_new_restore_jobs():
    logger.info("Getting VM Information...")
    allvms = get_all_vms()
    logger.info("Reading CSV...")
    jobparamslist = build_jobs_list()
    for jobparams in jobparamslist:
        templatejob = get_restore_job(jobparams)
        templatepolicy = get_policy_for_job(templatejob)
        vmlist = get_info_for_vms(allvms, jobparams)
        sourceinfo = build_source_info_for_vms(vmlist, jobparams)
        updatedpolicy = build_policy_for_update(templatepolicy, sourceinfo, vmlist, jobparams)
        newpolicy = create_policy(updatedpolicy, jobparams)
        newjob = create_job(newpolicy, jobparams)
        logger.info("Created job %s" % newjob['name'])

session = client.EcxSession(options.host, options.username, options.password)
session.login()
create_new_restore_jobs()

session.delete('endeavour/session/')

