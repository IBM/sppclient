# Script to run a job on-demand for SPP
# Use runjob.py -h for help

import json
import logging
from optparse import OptionParser
import copy
import sys
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--jobname", dest="jobname", help="Job name to run")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.jobname is None):
        print("Invalid input, use -h switch for help")
        sys.exit(1)

def find_job_from_name():
    try:
        response = client.SppAPI(session, 'endeavour').get(path='job')
        joblist = response['jobs']
        for job in joblist:
            if(job['name'].upper() == options.jobname.upper()):
                return job
        print("No job with provided name found.")
        session.logout()
        sys.exit(2)
    except client.requests.exceptions.HTTPError as err:
        print err.response.content
        session.logout()
        sys.exit(3)

def run_job(job):
    jobrunpath = "job/" + job['id'] + "?action=start&actionname=start"
    try:
        response = client.SppAPI(session, 'endeavour').post(path=jobrunpath)
        print("Running job " + job['name'])
    except client.requests.exceptions.HTTPError as err:
        print(err.response.content)
        session.logout()
        sys.exit(4)
        

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
job = find_job_from_name()
run_job(job)
session.logout()
