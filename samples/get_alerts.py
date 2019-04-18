'''  show list of alerts, not all errors which occured are treated as an alert.
    Therefore the job logs needs to be inspected as well '''

''' 
    tested with the following versions:
        python: 3.7.2
        Spectrum Protect Plus: 10.1.3 build 236
'''



import json
from optparse import OptionParser
import sys
import requests
sys.path.insert(0, '..')          # import local sppclient, not global under user site package
import spplib.sdk.client as client
import spplib.cli.util as spputil
import time
import traceback


parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--type", dest="type", help="type of alert: ERROR or WARN")
parser.add_option("--ack",  dest="ack", help="acknowledged: True or False")
parser.add_option("--sort",  dest="sort", help="sort order: DESC or ASC ")
parser.add_option("--timeframe",  dest="timeframe", help="specify how many hours to look backwards: [int]")
parser.add_option("--search",  dest="search", help="search within the alert message text")
parser.add_option("-a", dest="authfile", action="store_true", help="use file with host address and user credentials")
(options, args) = parser.parse_args()

params_from_file = {}

def validate_input():
    if(options.username is None or options.password is None or options.host is None):
        print("Invalid input, use -h switch for help")
        sys.exit(1)




def session_start():
    try:
        session = client.SppSession(options.host, options.username, options.password)
        session.login()
    except requests.exceptions.HTTPError as err:
        print("HTTP Error: {0}".format(err))
        print("exiting ...")
        sys.exit(1)
    except:
        print("unknown ERROR: ", sys.exc_info()[0])
        print("exiting ...")
        sys.exit(1)

    return session


def get_alerts(session):
    try:
        ''' the dictionary qsp contains the filters, sort statements and others like pageSize'''
        qsp = {}
        if options.sort is not None:
            if options.sort.upper() == "DESC":
                qsp['sort'] = '[{"property": "last", "direction": "DESC"}]'
            else:
                qsp['sort'] = '[{"property": "last", "direction": "ASC"}]'
        else:
            qsp['sort'] = '[{"property": "last", "direction": "ASC"}]'


        qsp['pageSize'] = 10000       # if set too small the number of returned results is incorrect and does not match the timeframe
        if options.timeframe is not None:
            timeframems = int(options.timeframe) * 60 * 60 * 1000
            starttime = int(round(time.time() * 1000)) - timeframems
            qsp['filter'] = json.dumps([{"property": "last", "value": str(starttime), "op": ">="}])

        queryResult = client.SppAPI(session, '').get(path='/api/endeavour/alert/message', params=qsp)
        #queryResult = client.SppAPI(session, '').get(path='/api/endeavour/alert/message')
    except requests.exceptions.HTTPError as err:
        print("HTTP Error: {0}".format(err))
        spputil.get_error_details(err)
        print("exiting ...")
        sys.exit(1)
    except:
        print("other ERROR: ", traceback.print_exc())
        print("exiting ...")
        sys.exit(1)

    return queryResult



def format_alert_list(myQueryResult):
    spputil.remove_links(myQueryResult)
    print()
    alert_fmt = "  {:<19.19s} | {:<6.6s} | {:<5s} | {:s}"
    print(alert_fmt.format("   last occurance", "Type", "ackn", "description"))
    print("  " + "-" * 120)
    for alert in myQueryResult['alerts']:
        msg=alert['message']
        acknowledged=str(alert['acknowledged'])
        type=alert['type']
        displayMsg = True

        lastOccurance=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert['last']/1000))

        if options.type is not None:
            if options.type.upper() != type:
                displayMsg = False

        if options.ack is not None:
            if options.ack.upper() != acknowledged.upper():
                displayMsg = False

        if options.timeframe is not None:
            timeframems = int(options.timeframe) * 60 * 60 * 1000
            starttime = int(round(time.time() * 1000)) - timeframems
            if alert['last'] < starttime:
                displayMsg = False

        if options.search is not None:
            if options.search.upper() not in msg.upper():
                displayMsg = False

        if displayMsg == True:
            print(alert_fmt.format(lastOccurance, type, acknowledged, msg))




def main():
    if options.authfile is True:
        params_from_file = spputil.read_params_from_file(filename="auth.txt")

        if "host" in params_from_file and "username" in params_from_file and "password" in params_from_file:
            # print("INFO: using host, username and password from file")
            options.host = params_from_file['host']
            options.password = params_from_file['password']
            options.username = params_from_file['username']
        else:
            pass
            # print("INFO: using host, username and password from command line")


    validate_input()
    session = session_start()
    myQueryResult = get_alerts(session)
    format_alert_list(myQueryResult)
    session.logout()


if __name__ == "__main__":
    main()