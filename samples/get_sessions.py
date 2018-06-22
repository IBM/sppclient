#
# Script to get job session information from SPP
# Last argument represents number of hours back from present to view job sessions
# Example:
# python get_sessions.py 172.20.120.66 admin password123 24
# Note:
# This script does not require the sppclient module
#

import httplib
import string
import json
import ssl
import urllib2
#import urllib3
import time
import sys
import base64
import datetime
import copy
#urllib3.disable_warnings()

host=sys.argv[1]
username=sys.argv[2]
password=sys.argv[3]
timeframe=sys.argv[4]


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
        print "Could not obtain session ID: check that host, username and password are correct"
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

def get_all_job_sessions(sessionid):
    url = "/api/endeavour/jobsession?pageSize=1000&sort=%5B%7B%22property%22:%22start%22,%22direction%22:%22DESC%22%7D%5D"
    webservice = httplib.HTTPS(host)
    webservice.putrequest("GET", url)
    webservice.putheader("Content-type", "application/json; charset=\"UTF-8\"")
    webservice.putheader('x-endeavour-sessionid', sessionid)
    webservice.endheaders()
    statuscode, statusmessage, header = webservice.getreply()
    res = json.loads(webservice.getfile().read())
    return res['sessions']

def parse_sessions(sessions, sessionid):
    sessioninfolist = []
    for session in sessions:
        starttime = datetime.datetime.fromtimestamp(float(session['start']) / 1000)
        today = datetime.datetime.now()
        margin = datetime.timedelta(hours = int(timeframe))
        if starttime >= today - margin:
            sessioninfo = {}
            sessioninfo['starttime'] = starttime.strftime("%Y-%m-%d %H:%M:%S")
            sessioninfo['jobname'] = session['jobName']
            sessioninfo['status'] = session['status']
            if session['status'] == "PARTIAL" or session['status'] == "FAILED":
                sessioninfo['error'] = get_errors(session['links']['log']['href'], sessionid)
            sessioninfolist.append(copy.deepcopy(sessioninfo))
    return sessioninfolist

def get_errors(logslink, sessionid):
    url = str.split(logslink.encode("utf-8"), ":443")[1]
    webservice = httplib.HTTPS(host)
    webservice.putrequest("GET", url)
    webservice.putheader("Content-type", "application/json; charset=\"UTF-8\"")
    webservice.putheader('x-endeavour-sessionid', sessionid)
    webservice.endheaders()
    statuscode, statusmessage, header = webservice.getreply()
    logs = json.loads(webservice.getfile().read())['logs']
    errorlogs = parse_errors(logs)
    return errorlogs

def parse_errors(logs):
    errors = []
    for log in logs:
        if log['type'] == "ERROR":
            errors.append(log['message'])
    return errors

def output_session_info(sessioninfo):
    print '{:20.20s} {:16.16s} {:8.8s}'.format("Job Name", "Start Time", "Status")
    for session in sessioninfo:
        print '{:20.20s} {:16.16s} {:8.8s}'.format(session['jobname'], session['starttime'], session['status'])
        if 'error' in session:
            for error in session['error']:
                print error.rjust(10," ")
        print "\n"

def run():
    sessionid = session_login()
    sessions = get_all_job_sessions(sessionid)
    sessioninfo = parse_sessions(sessions, sessionid)
    output_session_info(sessioninfo)
    session_logout(sessionid)

run()
