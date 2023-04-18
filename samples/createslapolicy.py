#
# Script to create a new SLA policy in SPP
# Use createslapolicy.py -h for help
# command example:
# python createslapolicy.py --host="https://172.20.49.49" --user="admin" --pass="password123" --slaname="Iron" --slasite="Primary" --rettype="days" --retval=15 --freqtype="hourly" --freqval="1" --starttime="10/13/2017 03:45"
#

import json
import logging
from optparse import OptionParser
import copy
import sys
import spplib.sdk.client as client
import datetime
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--slaname", dest="slaname", help="SLA Policy name")
parser.add_option("--slasite", dest="slasite", help="SLA Policy target site")
parser.add_option("--retval", dest="retval", help="Retention value")
parser.add_option("--rettype", dest="rettype", help="Retention type (days or snapshots)")
parser.add_option("--freqtype", dest="freqtype", help="Frequency type (minute, hour, day, week or month)")
parser.add_option("--freqval", dest="freqval", help="Frequency value")
parser.add_option("--starttime", dest="starttime", help="Start date/time (rounded to nearest 5 minutes)")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': ')))

def validate_input():
    if(options.username is None or options.password is None or
       options.host is None):
        print("Invalid input, use -h switch for help")
        sys.exit(2)

def build_sla_policy():
    slainfo = {}
    slainfo['name'] = options.slaname
    slainfo['version'] = "1.0"
    slainfo['spec'] = {'simple': True}
    slainfo['spec']['subpolicy'] = [{}]
    slainfo['spec']['subpolicy'][0]['type'] = "REPLICATION"
    slainfo['spec']['subpolicy'][0]['software'] = True
    slainfo['spec']['subpolicy'][0]['site'] = build_site()
    slainfo['spec']['subpolicy'][0]['retention'] = build_retention()
    slainfo['spec']['subpolicy'][0]['trigger'] = build_frequency()
    return slainfo

def build_site():
    sites = client.SppAPI(session, 'coresite').get()['sites']
    for site in sites:
        if(site['name'].upper() == options.slasite.upper()):
            return site['name']
    logger.error("Site name not found")
    session.logout()
    sys.exit(2)

def build_retention():
    retention = {}
    if(options.rettype.upper() == "DAYS"):
        retention = {'age': int(options.retval)}
        return retention
    elif(options.rettype.upper() == "SNAPSHOTS"):
        retention = {'numsnapshots': int(options.retval)}
        return retention
    logger.error("Invalid retention type, must be days or snapshots")
    session.logout()
    sys.exit(2)

def build_frequency():
    frequency = {}
    if("MINUTE" in options.freqtype.upper()):
        frequency['type'] = "SUBHOURLY"
        frequency['frequency'] = int(options.freqval)
        frequency['activateDate'] = build_start_date()
    elif("HOUR" in options.freqtype.upper()):
        frequency['type'] = "HOURLY"
        frequency['frequency'] = int(options.freqval)
        frequency['activateDate'] = build_start_date()
    elif("DAY" in options.freqtype.upper()):
        frequency['type'] = "DAILY"
        frequency['frequency'] = int(options.freqval)
        frequency['activateDate'] = build_start_date()
    elif("WEEK" in options.freqtype.upper()):
        frequency['type'] = "WEEKLY"
        frequency['frequency'] = int(options.freqval)
        frequency['activateDate'] = build_start_date()
        frequency['dowList'] = build_weekly_dowlist(frequency['activateDate'])
    elif("MONTH" in options.freqtype.upper()):
        frequency['type'] = "MONTHLY"
        frequency['frequency'] = int(options.freqval)
        frequency['activateDate'] = build_start_date()
        frequency['domList'] = build_monthly_domlist(frequency['activateDate'])
    else:
        logger.error("Invalid frequency type, must be minute, hour, day, week or month")
        session.logout()
        sys.exit(2)
    return frequency

def build_start_date():
    sdt = datetime.datetime.strptime(options.starttime, '%m/%d/%Y %H:%M')
    sdt += datetime.timedelta(minutes=2.5)
    sdt -=  datetime.timedelta(minutes=sdt.minute %5, seconds=sdt.second, microseconds=sdt.microsecond)
    starttime = int(sdt.strftime("%S"))*1000
    return starttime

def build_weekly_dowlist(adate):
    dowlist = [False,False,False,False,False,False,False,False]
    adatedt = datetime.datetime.utcfromtimestamp(adate/1000)
    if(adatedt.weekday() == 6):
        dowlist[1] = True
    elif(adatedt.weekday() == 0):
        dowlist[2] = True
    elif(adatedt.weekday() == 1):
        dowlist[3] = True
    elif(adatedt.weekday() == 2):
        dowlist[4] = True
    elif(adatedt.weekday() == 3):
        dowlist[5] = True
    elif(adatedt.weekday() == 4):
        dowlist[6] = True
    elif(adatedt.weekday() == 5):
        dowlist[7] = True
    return dowlist

def build_monthly_domlist(adate):
    domlist = [False] * 32
    adatedt = datetime.datetime.utcfromtimestamp(adate/1000)
    domlist[adatedt.day] = True
    return domlist

def create_sla_policy(slainfo):
    try:
        response = client.SppAPI(session, 'sppsla').post(data=slainfo)
        logger.info("SLA Policy " + options.slaname + " is created")
    except client.requests.exceptions.HTTPError as err:
        errmsg = json.loads(err.response.content)
        logger.error(errmsg['response'])

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
slainfo = build_sla_policy()
create_sla_policy(slainfo)
session.logout()
