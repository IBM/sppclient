########################################################
###                                                  ###
###   IBM Spectrum Protect Plus                      ###
###                                                  ###
###   Microsoft SQL support REST API sample script   ###
###                                                  ###
###   Function: list recovery points                 ###
###                                                  ###
###   Validated with 10.1.9                          ###
###                                                  ###
########################################################

from optparse import OptionParser
from datetime import datetime
import sys
import json
import requests
import copy
import csv
sys.path.insert(0, '..')          # import local sppclient
import spplib.sdk.client as client
import spplib.cli.util as spputil
import traceback
import operator

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("-a", dest="authfile", action="store_true", help="use file with host address and user credentials")

(options, args) = parser.parse_args()

def prettyprint(indata):
    print(json.dumps(indata, sort_keys=True,indent=3, separators=(',', ':')))

def session_start():
    try:
        session = client.SppSession(options.host, options.username, options.password)
        session.login()
    except requests.exceptions.HTTPError as err:
        spputil.get_error_details(err)
        print("exiting ...")
        sys.exit(1)
    except:
        print("other Exception: ", traceback.print_exc())
        print("exiting ...")
        sys.exit(1)
    return session

def validate_input():
    if options.authfile is True:
        params_from_file = spputil.read_params_from_file(filename="auth.txt")

        if "host" in params_from_file and "username" in params_from_file and "password" in params_from_file:
            options.host = params_from_file['host']
            options.password = params_from_file['password']
            options.username = params_from_file['username']
        else:
            pass
    if(options.username is None or options.password is None or options.host is None):
        print("Invalid input, use -h switch for help")
        sys.exit(1)
    else:
        options.host = spputil.get_ip_by_name(options.host)

def get_connection_info(session):
    ping_response = client.SppAPI(session, 'ping').get()
    return ping_response

def print_connection_info(session):
    connection_info = get_connection_info(session)
    if (not connection_info):
        print("Could not connect to IBM Spectrum Protect Plus Server")
    else:
        len = 100
        print_line(len)
        print("Connected to IBM Spectrum Protect Plus Server: " + options.host + ", Version " + connection_info['version'] + ", Build " + connection_info['build'])
        print_line(len)

def get_all_application_recovery_info(session):
    pathName = "/catalog/recovery/applicationdatabase?embed=(children)"
    sorting = "&sort=%5B%7B%22property%22:%22name%22,%22direction%22:%22ASC%22%7D%5D"
    properties = "properties%29%29&pageSize=100000"
    query = pathName + sorting + properties
    application_json_response = client.SppAPI(session, 'endeavour').get(path=query)["children"]
    # prettyprint(application_json_response)
    return application_json_response

def get_application_versions(session, versurl):
    application_json_response = client.SppAPI(session, 'endeavour').get(url=versurl)
    # prettyprint(application_json_response)
    return application_json_response

def get_all_snapshot_info(session, application_json_response):
    
    snapshot_array = []

    for database in application_json_response:

        snapshot_data = {}
        snapshot_data['instance_pk'] = ''
        snapshot_data['database_pk'] = ''
        snapshot_data['database_name'] = database['name']
        snapshot_data['host_name'] = ''
        snapshot_data['data_volume'] = ''
        snapshot_data['log_volume'] = 'NO LOG BACKUP'
        snapshot_data['SLA_policy'] = ''
        snapshot_data['SLA_sub_type'] = ''
        snapshot_data['time'] = ''
        
        database_recovery_points = get_application_versions(session, database['links']['versions']['href'])['contents']
        # prettyprint(database_recovery_points)

        for recovery_point in database_recovery_points:
            applicationType = recovery_point['properties']['applicationType']
            if applicationType == 'sql':
                snapshot_data['instance_pk']   = recovery_point['properties']['instancePk']
                snapshot_data['database_pk']   = recovery_point['properties']['pk']
                snapshot_data['host_name']     = recovery_point['properties']['host']
                snapshot_data['SLA_policy']    = recovery_point['properties']['protectionInfo']['policyName']
                snapshot_data['SLA_sub_type']  = recovery_point['properties']['protectionInfo']['subPolicyType']
                snapshot_data['time']          = datetime.fromtimestamp(int(recovery_point['catalogTime'])/1000).strftime("%Y.%m.%d %I:%M:%S")
                snapshot_data['data_volume']   = recovery_point['properties']['protectionInfo']['applicationBliDestinationInfo']['dataVolumePk']
                logVolumePK                    = recovery_point['properties']['protectionInfo']['applicationBliDestinationInfo']['logVolumePk']
                if logVolumePK is not None:
                    snapshot_data['log_volume'] = logVolumePK
                snapshot_array.append(copy.deepcopy(snapshot_data))
    return snapshot_array

def print_snapshot_data(snapshot_array):
    len = 160
    print_line(len)
    print('Number of recovery points: ' + str(snapshot_array.__len__()))
    print_line(len)
    print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:10s} | {:15s}'.format(
        'Host Name', 'Database Name', 'Data Volume', 'Log Volume', 'SLA Name', 'SLA Type', 'Time'))
    print_line(len)
    for snapshot in snapshot_array:
        print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:10s} | {:15s}'.format(
            snapshot['host_name'], snapshot['database_name'], 
            snapshot['data_volume'], snapshot['log_volume'], 
            snapshot['SLA_policy'], snapshot['SLA_sub_type'],
            snapshot['time']))
    print_line(len)
    return 0

def print_line(len):
    print('='.ljust(len,'='))

def main():
    
    validate_input()
    session = session_start()
    print_connection_info(session) 
    application_json_response = get_all_application_recovery_info(session)
    snapshot_array = get_all_snapshot_info(session, application_json_response)
    print_snapshot_data(snapshot_array)
    session.logout()

if __name__ == "__main__":
    main()

