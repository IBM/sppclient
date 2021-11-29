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
parser.add_option("--file", dest="filename", help="Destination output file (optional)")
parser.add_option("-i", dest="instance", action="store_true", help="Enable instance level output")
parser.add_option("-d", dest="database", action="store_true", help="Enable database level output")
parser.add_option("-s", dest="snapshot", action="store_true", help="Enable snapshot level output")

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
    
    if options.instance is None and options.database is None and options.snapshot is None:
        print("Invalid input, specify at least one of the arguments -i, -d or -s")
        print("   -i to enable instance level output")
        print("   -d to enable database level output")
        print("   -s to enable recovery point level output")
        sys.exit(1)

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


def get_instance_capacity_info(database_array):

    instance_array = []
    instance_data = {}
    instance_data['instance_pk'] = 0
    instance_data['serverName'] = ''
    instance_data['frontendCapacity'] = 0
    instance_data['sumSnapshotCapacity'] = 0
    instance_data['numberOfSnapshots'] = 0
    instance_data['backendCapacity'] = 0
    instance_data['numberOfDatabases'] = 0

    # prettyprint(database_array)

    for database in database_array:

        if instance_data['instance_pk'] != database['instance_pk']:
            # add recent instance to the array if it is not the first cycle
            if instance_data['instance_pk'] != 0:
                instance_array.append(copy.deepcopy(instance_data))
            # reset values for new instance
            instance_data['instance_pk'] = database['instance_pk']
            instance_data['serverName'] = database['serverName']
            instance_data['frontendCapacity'] = 0
            instance_data['sumSnapshotCapacity'] = 0
            instance_data['numberOfSnapshots'] = database['numberOfSnapshots']
            instance_data['backendCapacity'] = 0
            instance_data['numberOfDatabases'] = 0
        else:
            # sum up the instance
            instance_data['frontendCapacity'] += database['frontendCapacity']
            instance_data['sumSnapshotCapacity'] += database['sumSnapshotCapacity']
            instance_data['backendCapacity'] += database['backendCapacity']
            instance_data['numberOfDatabases'] += 1

    # add the final instance to the array
    instance_array.append(copy.deepcopy(instance_data))

    return instance_array

def get_database_capacity_info(session, application_json_response):
    
    database_array = []

    for database in application_json_response:

        database_data = {}
        database_data['instance_pk'] = ''
        database_data['serverName'] = ''
        database_data['databaseName'] = database['name']
        # database_data['sla'] = ''
        database_data['frontendCapacity'] = 0
        database_data['sumSnapshotCapacity'] = 0
        database_data['numberOfSnapshots'] = 0
        database_data['backendCapacity'] = 0
        applicationType = ''
        count = 0

        database_recovery_points = get_application_versions(session, database['links']['versions']['href'])['contents']
        # prettyprint(database_recovery_points)

        for recovery_point in database_recovery_points:
            applicationType = recovery_point['properties']['applicationType']
            if applicationType == 'sql':
                if count == 0:
                    # prettyprint(recovery_point)
                    database_data['instance_pk']      = recovery_point['properties']['instancePk']
                    database_data['serverName']       = recovery_point['properties']['host']
                    database_data['frontendCapacity'] = recovery_point['properties']['usedSize'] # this is the front end capacity of the application
                    # database_data['sla']              = recovery_point['properties']['protectionInfo']['policyName'] 
                count += 1
                database_data['sumSnapshotCapacity'] += recovery_point['properties']['protectionInfo']['transferSize'] # this is the snapshot size of the application
                
        if applicationType == 'sql':
            database_data['numberOfSnapshots'] = count # this is the number of recovery point (snapshots) that are known to the catalog
            database_data['backendCapacity']   = database_data['frontendCapacity'] + database_data['sumSnapshotCapacity'] # this is the backend capacity of the application
            database_array.append(copy.deepcopy(database_data))

    # sort the database array for instance primary keys to allow instance capacity calculation
    database_array.sort(key=operator.itemgetter('instance_pk'))
    # prettyprint(database_array)
    return database_array

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
        snapshot_data['snapshot_size'] = 0
        snapshot_data['snapshot_date'] = ""
        snapshot_data['snapshot_time'] = ""
        
        database_recovery_points = get_application_versions(session, database['links']['versions']['href'])['contents']
        # prettyprint(database_recovery_points)

        for recovery_point in database_recovery_points:
            applicationType = recovery_point['properties']['applicationType']
            if applicationType == 'sql':
                snapshot_data['instance_pk']   = recovery_point['properties']['instancePk']
                snapshot_data['database_pk']   = recovery_point['properties']['pk']
                snapshot_data['host_name']     = recovery_point['properties']['host']
                snapshot_data['data_volume']   = recovery_point['properties']['protectionInfo']['applicationBliDestinationInfo']['dataVolumePk']
                snapshot_data['snapshot_date'] = datetime.fromtimestamp(int(recovery_point['catalogTime'])/1000).strftime("%Y.%m.%d")
                snapshot_data['snapshot_time'] = datetime.fromtimestamp(int(recovery_point['catalogTime'])/1000).strftime("%I:%M:%S")
                snapshot_data['snapshot_size'] = recovery_point['properties']['protectionInfo']['transferSize']
                logVolumePK                    = recovery_point['properties']['protectionInfo']['applicationBliDestinationInfo']['logVolumePk']
                if logVolumePK is not None:
                    snapshot_data['log_volume'] = logVolumePK
                snapshot_array.append(copy.deepcopy(snapshot_data))
    return snapshot_array

def print_instance_data(instance_array):
    len = 130
    print_line(len)
    print('Number of instances: ' + str(instance_array.__len__()))
    print_line(len)
    print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
        'Server name', 'Number of', 'Frontend', 'Snapshot', 'Number of', 'Backend'))
    print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
        '', 'databases', 'Capacity', 'Capacity', 'snapshots', 'Capacity'))
    print_line(len)
    for instance in instance_array:
        actualSnapshotCapacity = get_actual_size(instance['sumSnapshotCapacity'])
        actualFrontendCapacity = get_actual_size(instance['frontendCapacity'])
        actualBackendCapacity = get_actual_size(instance['backendCapacity'])
        print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
            instance['serverName'], str(instance['numberOfDatabases']), str(actualFrontendCapacity), str(actualSnapshotCapacity), str(instance['numberOfSnapshots']), str(actualBackendCapacity)))
    print_line(len)
    return 0

def print_database_data(database_array):
    len = 130
    print_line(len)
    print('Number of databases: ' + str(database_array.__len__()))
    print_line(len)
    print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
        'Server name', 'Database name', 'Frontend', 'Snapshot', 'Number of', 'Backend'))
    print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
        '', '', 'Capacity', 'Capacity', 'snapshots', 'Capacity'))
    print_line(len)
    for database in database_array:
        actualSnapshotCapacity = get_actual_size(database['sumSnapshotCapacity'])
        actualFrontendCapacity = get_actual_size(database['frontendCapacity'])
        actualBackendCapacity = get_actual_size(database['backendCapacity'])
        print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
            database['serverName'], database['databaseName'], str(actualFrontendCapacity), 
            str(actualSnapshotCapacity), str(database['numberOfSnapshots']), str(actualBackendCapacity)))
    print_line(len)
    return 0

def print_snapshot_data(snapshot_array):
    len = 150
    print_line(len)
    print('Number of snapshots: ' + str(snapshot_array.__len__()))
    print_line(len)
    print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
        'Host Name', 'Database Name', 'Data Volume', 'Log Volume', 'Snapshot', 'Snapshot', 'Snapshot'))
    print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
        '', '', '', '', 'Size', 'Date', 'Time'))
    print_line(len)
    for snapshot in snapshot_array:
        actualSnapshotSize = get_actual_size(snapshot['snapshot_size'])
        print('{:40s} | {:20s} | {:15s} | {:15s} | {:15s} | {:15s} | {:15s}'.format(
            snapshot['host_name'], snapshot['database_name'], 
            snapshot['data_volume'], snapshot['log_volume'], str(actualSnapshotSize), snapshot['snapshot_date'], snapshot['snapshot_time']))
    print_line(len)
    return 0

def print_array_data_to_csv(array, fileName):
    file = open(fileName,"w")
    csvwriter = csv.writer(file)
    count = 0
    for dataset in array:
        if count == 0:
            csvwriter.writerow(dataset.keys())
            count += 1
        csvwriter.writerow(dataset.values())
    file.close()
    print("Chargeback data written to " + fileName)
    return 0

def print_line(len):
    print('='.ljust(len,'='))

def get_actual_size(size,precision=2):
    suffixes=['B','KB','MB','GB','TB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1
        size = size/1024.0
    return "%.*f%s"%(precision,size,suffixes[suffixIndex])

def main():
    
    validate_input()

    len = 100
    print_line(len)
    print('--- NOTE: SQL log backup capacity is not included in the capacity counting ---')
    print_line(len)
    print()

    session = session_start()
    print_connection_info(session)

    filename_instances = ''
    filename_databases = ''
    filename_snapshots = ''

    if options.filename is not None:
        filename_instances = options.filename + '_instances'
        filename_databases = options.filename + '_databases'
        filename_snapshots = options.filename + '_snapshots'

    # query SPP catalog to get all application recovery information  
    application_json_response = get_all_application_recovery_info(session)
    # query SPP catalog to get all snapshot information per database 
    # and calculate database level information
    database_array = get_database_capacity_info(session, application_json_response)
    # calculate instance level information
    instance_array = get_instance_capacity_info(database_array)

    if options.instance is True:
        if options.filename is None:
            print_instance_data(instance_array)
        else:
            print_array_data_to_csv(instance_array, filename_instances)
    
    if options.database is True:
        if options.filename is None:
            print_database_data(database_array)
        else:
            print_array_data_to_csv(database_array, filename_databases)

    if options.snapshot is True:
        # parse and display snapshot level data
        snapshot_array = get_all_snapshot_info(session, application_json_response)
        if options.filename is None:
            print_snapshot_data(snapshot_array)
        else:
            print_array_data_to_csv(snapshot_array, filename_snapshots)


    session.logout()

if __name__ == "__main__":
    main()