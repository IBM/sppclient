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
parser.add_option("--action", dest="action", help="Action name, (ex. 'backup to vSnap' or 'REPLICATION')")
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
        print(err.response.content)
        session.logout()
        sys.exit(3)

def get_action_name(job):
    try:
        response = client.SppAPI(session, 'endeavour').get(url=job['links']['start']['schema'])
        schemalist = response['parameter']['actionname']['values']
        if options.action is None:
            print("This job requires an action parameter, available are:")
            for schema in schemalist:
                print(schema['name'])
            session.logout()
            sys.exit(4)
        for schema in schemalist:
            if schema['name'].upper() == options.action.upper():
                return {'actionname':schema['value']}
    except client.requests.exceptions.HTTPError as err:
        print(err.response.content)
        session.logout()
        sys.exit(4)

def run_job(job):
    jobrunpath = "job/" + job['id'] + "?action=start&actionname=start"
    postdata = None
    if "schema" in job['links']['start']:
        postdata = get_action_name(job)
    try:
        if postdata:
            response = client.SppAPI(session, 'endeavour').post(path=jobrunpath, data=postdata)
        else:
            response = client.SppAPI(session, 'endeavour').post(path=jobrunpath)
        print("Running job " + job['name'])
    except client.requests.exceptions.HTTPError as err:
        print(err.response.content)
        session.logout()
        sys.exit(5)
        

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
job = find_job_from_name()
#prettyprint(job)
run_job(job)
session.logout()
