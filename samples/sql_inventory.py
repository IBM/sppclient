########################################################
###                                                  ###
###   IBM Spectrum Protect Plus                      ###
###                                                  ###
###   Microsoft SQL support REST API sample script   ###
###                                                  ###
###   Function: backend capacity per database        ###
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

def get_sql_instances(session):
    query = "sql/instance"
    sql_instances_json_response = client.SppAPI(session, 'apiapp').get(path=query)["instances"]
    # prettyprint(sql_instances_json_response)
    instance_array = []
    for instance in sql_instances_json_response:
        instance_info = {}
        instance_info['id']      = instance['id']
        instance_info['name']    = instance['name']
        instance_info['osType']  = instance['osType']
        instance_info['version'] = instance['version']
        instance_info['host']    = instance['host']
        instance_info['sla_list'] = []
        for storageProfile in instance['storageProfiles']:
            instance_info['sla_list'].append(storageProfile)
        instance_array.append(copy.deepcopy(instance_info))
        # prettyprint(instance_array)
    return instance_array

def get_sql_databases(session, instance_list):
    database_array = []
    for instance in instance_list:
        query = "sql/instance/" + instance['id'] + "/applicationview"
        sql_databases_json_response = client.SppAPI(session, 'apiapp').get(path=query)["contents"]
        for database in sql_databases_json_response:
            database_data = {}
            database_data['name']                = database['name']
            database_data['instance_name']       = instance['name']
            database_data['eligible_backup']     = database['eligibility']['backup']['eligible']
            database_data['eligible_log_backup'] = database['eligibility']['logbackup']['eligible']
            database_data['sla_list'] = []
            for storageProfile in database['storageProfiles']:
                database_data['sla_list'].append(storageProfile)
            database_array.append(copy.deepcopy(database_data))
    # prettyprint(database_array)
    return database_array

def print_sql_instance_data(instance_array):
    len = 150
    print_line(len)
    print('Number of instances: ' + str(instance_array.__len__()))
    print_line(len)
    print('{:20s} | {:40s} | {:20s} | {:20s} | {:20s}'.format('Name', 'Host', 'Version', 'OS Type', 'SLA'))
    print_line(len)
    for instance in instance_array:
        sla_list = ""
        for sla in instance['sla_list']:
            sla_list = sla + ", " + sla_list
        print('{:20s} | {:40s} | {:20s} | {:20s} | {:20s}'.format(
            instance['name'], instance['host'], instance['version'], instance['osType'], sla_list))
    print_line(len)
    return 0

def print_sql_databases_data(database_array):
    len = 150
    print_line(len)
    print('Number of databases: ' + str(database_array.__len__()))
    print_line(len)
    print('{:20s} | {:20s} | {:20s} | {:20s} | {:20s}'.format(
            'Instance Name', 'DB Name', 'Eligible Backup', 'Eligible LogBackup', 'SLA'))
    print_line(len)
    for database in database_array:
        sla_list = ""
        for sla in database['sla_list']:
            sla_list = sla + ", " + sla_list
        print('{:20s} | {:20s} | {:20s} | {:20s} | {:20s}'.format(
                database['instance_name'], database['name'], str(database['eligible_backup']), 
                str(database['eligible_log_backup']), sla_list))
    print_line(len)
    return 0

def print_line(len):
    print('='.ljust(len,'='))

def main():
    
    validate_input()
    session = session_start()
    print_connection_info(session)
    instance_array = get_sql_instances(session)
    print_sql_instance_data(instance_array)
    database_array = get_sql_databases(session, instance_array)
    print_sql_databases_data(database_array)
    session.logout()

if __name__ == "__main__":
    main()

