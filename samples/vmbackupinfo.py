#
# Script to get VM info from SPP
# Example:
# python vmbackupinfo.py 172.20.66.120 admin sp3ctrum
# Note:
# This script does not require the sppclient module
#

import string
import json
import time
import sys
import copy
import urllib2
import ssl
import base64
import httplib

host=sys.argv[1]
username=sys.argv[2]
password=sys.argv[3]

if(hasattr(ssl, '_create_unverified_context')):
    ssl._create_default_https_context = ssl._create_unverified_context


def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def session_login():
    url = "/api/endeavour/session"
    auth = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
    webservice = httplib.HTTPS(host)
    webservice.putrequest("POST", url)
    webservice.putheader("Content-type", "text/html; charset=\"UTF-8\"")
    webservice.putheader("Authorization", "Basic %s" % auth)
    webservice.endheaders()
    statuscode, statusmessage, header = webservice.getreply()
    res = json.loads(webservice.getfile().read())
    try:
        sessionid = res['sessionid']
        #print "Session ID: " + sessionid
        return sessionid
    except Exception, e:
        print e
        sys.exit(2)

def session_logout(sessionid):
    url = "/api/endeavour/session"
    webservice = httplib.HTTPS(host)
    webservice.putrequest("DELETE", url)
    webservice.putheader("Content-type", "text/html; charset=\"UTF-8\"")
    webservice.putheader('x-endeavour-sessionid', sessionid)
    webservice.endheaders()
    statuscode, statusmessage, header = webservice.getreply()
    #if(statuscode == 204):
    #    print "Log out succesful."

def get_successful_vm_info(sessionid):
    try:
        url = "/api/endeavour/catalog/recovery/hypervisorvm?embed=%28children%28properties%29%29"
        webservice = httplib.HTTPS(host)
        webservice.putrequest("GET", url)
        webservice.putheader("Content-type", "application/json; charset=\"UTF-8\"")
        webservice.putheader('x-endeavour-sessionid', sessionid)
        webservice.endheaders()
        statuscode, statusmessage, header = webservice.getreply()
        res = json.loads(webservice.getfile().read())
        return res['children']
    except Exception, e:
        print e
        sys.exit(3)
        
def get_bs_name(bsid, sessionid):
    try:
        url = "/api/storage/" + bsid
        webservice = httplib.HTTPS(host)
        webservice.putrequest("GET", url)
        webservice.putheader("Content-type", "application/json; charset=\"UTF-8\"")
        webservice.putheader('x-endeavour-sessionid', sessionid)
        webservice.endheaders()
        statuscode, statusmessage, header = webservice.getreply()
        res = json.loads(webservice.getfile().read())
        return res['name']
    except Exception, e:
        print "Error getting backup storage info " + e
        sys.exit(5)

def get_count_of_backups(versurl, sessionid):
    try:
        url = str.split(versurl.encode("utf-8"), ":443")[1]
        webservice = httplib.HTTPS(host)
        webservice.putrequest("GET", url)
        webservice.putheader("Content-type", "application/json; charset=\"UTF-8\"")
        webservice.putheader('x-endeavour-sessionid', sessionid)
        webservice.endheaders()
        statuscode, statusmessage, header = webservice.getreply()
        res = json.loads(webservice.getfile().read())
        versions = res['contents']
        return len(versions)
    except Exception, e:
        print "Error getting backup count " + e
        sys.exit(6)

def parse_successful_vm_info(vms, sessionid):
    vminfoarray = []
    vminfo = {}
    for vm in vms:
        vminfo['vm'] = vm['name']
        vminfo['tags'] = ""
        for tag in vm['properties']['tags']:
            vminfo['tags'] = vminfo['tags'] + tag['name'] + " "
        vminfo['hypervisor'] = vm['properties']['hypervisorHostName']
        vminfo['sla'] = vm['properties']['protectionInfo']['storageProfileName']
        vminfo['protectionMethod'] = vm['properties']['protectionInfo']['storageSnapshots'][0]['storageType']
        vminfo['backupStorage'] = get_bs_name(vm['properties']['protectionInfo']['storageSnapshots'][0]['storageId'], sessionid)
        # in MB
        vminfo['backupSize'] = float(vm['properties']['protectionInfo']['transferSize']) / 1000000
        # in MB/s
        buspeed = float(vm['properties']['protectionInfo']['transferSize']) / float(vm['properties']['protectionInfo']['transferDuration']) / 1000000
        vminfo['backupSpeed'] = buspeed
        versurl = vm['links']['versions']['href']
        vminfo['totalRuns'] = get_count_of_backups(versurl, sessionid)
        vminfoarray.append(copy.deepcopy(vminfo))
    return vminfoarray


def run():
    sessionid = session_login()
    suc_vms = get_successful_vm_info(sessionid)
    data_suc = parse_successful_vm_info(suc_vms, sessionid)
    data = data_suc
    prettyprint(data)
    session_logout(sessionid)
    

run()
