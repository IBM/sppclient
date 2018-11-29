import requests
import copy
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
parser.add_option("--timeframe", dest="timeframe", help="Hours back to pull job sessions")

(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def get_spp_sessionid():
    url = options.host + "/api/endeavour/session"
    r = requests.post(url, verify=False, auth=HTTPBasicAuth(options.username, options.password))
    #print("Logged in to SPP with sessionid: " + r.json()['sessionid'])
    return r.json()['sessionid']

def delete_spp_sessionid(sessionid):
    url = options.host + "/api/endeavour/session"
    header = {'X-Endeavour-Sessionid': sessionid}
    r = requests.delete(url, headers=header, verify=False)

def get_job_sessions(sessionid):
    timeframems = int(options.timeframe) * 60 * 60 * 1000
    starttime = int(round(time.time()*1000)) - timeframems
    header = {'X-Endeavour-Sessionid': sessionid}
    url = options.host + "/api/endeavour/jobsession"
    qsp = {"pageSize":10000}
    qsp['filter'] = json.dumps([{"property":"start","value":starttime,"op":">="}])
    r = requests.get(url, headers=header, params=qsp, verify=False)
    return r.json()['sessions']

def get_errors(logslink, sessionid):
    header = {'X-Endeavour-Sessionid': sessionid}
    r = requests.get(logslink, headers=header, verify=False)
    logs = r.json()['logs']
    errorlogs = parse_errors(logs)
    return errorlogs

def parse_sessions(jobsessions, sessionid):
    sessioninfolist = []
    for session in jobsessions:
        sessioninfo = {}
        sessioninfo['starttime'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session['start']/1000))
        sessioninfo['jobname'] = session['jobName']
        sessioninfo['status'] = session['status']
        if session['status'] == "PARTIAL" or session['status'] == "FAILED":
            sessioninfo['error'] = get_errors(session['links']['log']['href'], sessionid)
        sessioninfolist.append(copy.deepcopy(sessioninfo))
    return sessioninfolist

def parse_errors(logs):
    errors = []
    for log in logs:
        if log['type'] == "ERROR" or log['type'] == "WARN":
            errors.append(log['message'])
    return errors

def output_session_info(sessioninfo):
    print('{:20.20s} {:16.16s} {:8.8s}'.format("Job Name", "Start Time", "Status"))
    for session in sessioninfo:
        print('{:20.20s} {:16.16s} {:8.8s}'.format(session['jobname'], session['starttime'], session['status']))
        if 'error' in session:
            for error in session['error']:
                print(error.rjust(10," "))
        print()

def run():
    sessionid = get_spp_sessionid()
    jobsessions = get_job_sessions(sessionid)
    sessioninfo = parse_sessions(jobsessions, sessionid)
    output_session_info(sessioninfo)
    delete_spp_sessionid(sessionid)

run()
