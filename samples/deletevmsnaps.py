# script to delete VM versions from catalog
# example usage:
# python3 deletevmsnaps.py https://10.250.250.189 sysadmin sp3ctrumLAB labmongodb13 "7/2/19 8:00" "7/11/19 12:00"

import string
import json
import time
import sys
import datetime
import requests
import copy
from requests.auth import HTTPBasicAuth
try:
    import urllib3
except ImportError:
    from requests.packages import urllib3
urllib3.disable_warnings()

host=sys.argv[1]
username=sys.argv[2]
password=sys.argv[3]
vmname=sys.argv[4]
start=sys.argv[5]
end=sys.argv[6]

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def session_login():
    try:
        r = requests.post("%s/api/endeavour/session" % host, auth=HTTPBasicAuth(username, password), verify=False)
        sessionid = r.json()['sessionid']
        return sessionid
    except Exception as e:
        print(e)
        print("Could not obtain session ID from SPP, please verify host and credentials")
        sys.exit(1)

def session_logout(sesheaders):
    try:
        r = requests.delete("%s/api/endeavour/session" % host, headers=sesheaders, verify=False)
    except Exception as e:
        print("Error logging out of SPP " + e)
        sys.exit(2)

def get_vm_info(sesheaders):
    try:
        url = host + "/api/hypervisor/search?resourceType=vm&from=recovery"
        body = {"name":vmname,"hypervisorType":"vmware"}
        r = requests.post(url, headers=sesheaders, data=json.dumps(body), verify=False)
        for vm in r.json()['vms']:
            if vm['name'].upper() == vmname.upper():
                return vm
        print("VM not found in recovery catalog")
        sys.exit(3)
    except Exception as e:
        print("Error getting VM info " + e)
        sys.exit(3)

def get_vm_versions(versurl, sesheaders):
    try:
        r = requests.get(versurl, headers=sesheaders, verify=False)
        versions = r.json()['versions']
        return versions
    except Exception as e:
        print("Error getting backup count " + e)
        sys.exit(6)

def delete_snapshots_in_range(versions, sesheaders):
    sts = int(datetime.datetime.strptime(start, '%m/%d/%y %H:%M').timestamp())*1000
    ets = int(datetime.datetime.strptime(end, '%m/%d/%y %H:%M').timestamp())*1000
    for version in versions:
        if version['protectionInfo']['protectionTime'] > sts and version['protectionInfo']['protectionTime'] < ets:
            print("Deleting version " + version['sessionId'])
            try:
                r = requests.post(version['links']['deletefromversioncatalog']['href'], headers=sesheaders, verify=False)
            except Exception as e:
                print("Error deleting snapshot " + e)

def run():
    sessionid = session_login()
    sesheaders = {'x-endeavour-sessionid': sessionid, 'Accept': 'application/json', 'Content-type': 'application/json; charset="UTF-8"'}
    vm = get_vm_info(sesheaders)
    versions = get_vm_versions(vm['links']['versions']['href'], sesheaders)
    delete_snapshots_in_range(versions, sesheaders)
    session_logout(sesheaders)
run()
