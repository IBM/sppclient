# Script show jobs on SPP appliance
# Use sqlrestore.py -h for help

import json
import logging
from optparse import OptionParser
import sys
import time
import spplib.sdk.client as client
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or options.host is None):
        print("Invalid input, use -h switch for help")
        sys.exit(1)

def get_job_list():
    print('{:35.35s} {:20.20s} {:20.20s} {:20.20s}'.format("Job Name", "Status", "Last Run Time", "Last Run Status"))
    jobs = client.SppAPI(session, 'job').get(path='?pageSize=10000')['jobs']
    for job in jobs:
        if job['lastrun']['start'] > 0:
            lastruntime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(job['lastrun']['start']/1000))
        else:
            lastruntime = "Never"
            job['lastSessionStatus'] = "N/A"
        print('{:35.35s} {:20.20s} {:20.20s} {:20.20s}'.format(job['name'], job['status'], lastruntime, job['lastrun']['status']))



validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
get_job_list()
session.logout()
