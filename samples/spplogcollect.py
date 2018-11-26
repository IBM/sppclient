import requests
import re
import os
import json
import time
import sys
from optparse import OptionParser
from requests.auth import HTTPBasicAuth
try:
    import urllib3
except ImportError:
    from requests.packages import urllib3

urllib3.disable_warnings()

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--logtype", dest="logtype", help="SPP log type (system, job, or audit)")
parser.add_option("--dest", dest="dest", help="Log destination")
parser.add_option("--jobname", dest="jobname", help="Job name (required for job log type)")
parser.add_option("--startdate", dest="startdate", help="Start date to filter request logs (use format m/d/y h:m:s)")

(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def get_spp_sessionid():
    url = options.host + "/api/endeavour/session"
    r = requests.post(url, verify=False, auth=HTTPBasicAuth(options.username, options.password))
    print("Logged in to SPP with sessionid: " + r.json()['sessionid'])
    return r.json()['sessionid']

def delete_spp_sessionid(sessionid):
    url = options.host + "/api/endeavour/session"
    header = {'X-Endeavour-Sessionid': sessionid}
    r = requests.delete(url, headers=header, verify=False)
    if r.status_code == 204:
        print("Succesfully logged out of SPP")
    else:
        print("Error logging out of SPP, status code: " + str(r.status_code))

def get_system_logs(sessionid):
    url = options.host + "/api/endeavour/log/download/diagnostics?esessionid=" + sessionid
    r = requests.get(url, allow_redirects=True, verify=False)
    filename = get_filename_from_cd(r.headers.get('content-disposition'))
    if options.dest:
        fullfilepath = os.path.join(options.dest, filename)
    else:
        fullfilepath = filename
    open(fullfilepath, 'wb').write(r.content)
    print("System logs saved to " + fullfilepath)

def get_filename_from_cd(cd):
    if not cd:
        return None
    fname = re.findall('filename=(.+)', cd)
    if len(fname) == 0:
        return None
    return fname[0]

def get_audit_logs(sessionid):
    url = options.host + "/api/endeavour/log/audit/download/csv"
    qsp = {"esessionid":sessionid}
    if options.startdate:
        startepoch = int(time.mktime(time.strptime(options.startdate, '%m/%d/%Y %H:%M:%S')))*1000
        qsp['filter'] = json.dumps([{"property":"accessTime","value":startepoch,"op":">="}])
    r = requests.get(url, params=qsp, allow_redirects=True, verify=False)
    filename = get_filename_from_cd(r.headers.get('content-disposition'))
    if options.dest:
        fullfilepath = os.path.join(options.dest, filename)
    else:
        fullfilepath = filename
    open(fullfilepath, 'wb').write(r.content)
    print("Audit logs saved to " + fullfilepath)

def get_job_logs(sessionid):
    jobsesid = get_latest_jobsession(sessionid)
    url = options.host + "/api/endeavour/log/job/download/diagnostics"
    qsp = {"esessionid":sessionid}
    qsp['filter'] = json.dumps([{"property":"jobsessionId","value":jobsesid}])
    r = requests.get(url, params=qsp, allow_redirects=True, verify=False)
    filename = get_filename_from_cd(r.headers.get('content-disposition'))
    if options.dest:
        fullfilepath = os.path.join(options.dest, filename)
    else:
        fullfilepath = filename
    open(fullfilepath, 'wb').write(r.content)
    print("Audit logs saved to " + fullfilepath)

def get_latest_jobsession(sessionid):
    url = options.host + "/api/endeavour/job?pageSize=9999"
    header = {'X-Endeavour-Sessionid': sessionid}
    r = requests.get(url, headers=header, verify=False)
    for job in r.json()['jobs']:
        if job['name'] == options.jobname:
            return job['lastrun']['sessionId']
    print("Job not found, please check name")
    delete_spp_sessionid(sessionid)
    sys.exit(1)

def run():
    sessionid = get_spp_sessionid()
    if(options.logtype == "system"):
        get_system_logs(sessionid)
    elif(options.logtype == "audit"):
        get_audit_logs(sessionid)
    elif(options.logtype == "job"):
        get_job_logs(sessionid)
    delete_spp_sessionid(sessionid)

run()
