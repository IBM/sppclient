# Script show overview of system, similar to dashboard

'''
    tested with the following versions:
        python: 3.7.2
        Spectrum Protect Plus: 10.1.3 build 236
'''

import requests
from optparse import OptionParser
import sys
sys.path.insert(0, '..')          # import local sppclient, not global uder user site package
import spplib.sdk.client as client
import spplib.cli.util as spputil
import time
import datetime


parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("-a", dest="authfile", action="store_true", help="use file with host address and user credentials")
(options, args) = parser.parse_args()




def validate_input():
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


    if(options.username is None or options.password is None or options.host is None):
        print("Invalid input, use -h switch for help")
        sys.exit(1)
    else:
        options.host = spputil.get_ip_by_name(options.host)

def query_endpoint(path = None):

    try:
        myQueryResult = client.SppAPI(session, '').get(path=path)
    except requests.exceptions.HTTPError as err:
        print("HTTP Error: {0}".format(err))
        spputil.get_error_details(err)
        print("exiting ...")
        sys.exit(1)
        #return
    except:
        print("unknown ERROR: ", sys.exc_info()[0])
        print(err)
        print("exiting ...")
        sys.exit(1)

    return myQueryResult


def query_db_backupList(session):

    qsp = {}
    try:
        qsp['filter'] = '[{"property":"hasCatalog","value":"true","op":"="},{"property":"serviceId","value":"serviceprovider.protection.catalog","op":"="},{"property":"subPolicyType","value":"BACKUP","op":"="}]'
        queryResult = client.SppAPI(session, '').get(path="api/endeavour/jobsession", params=qsp)

    except requests.exceptions.HTTPError as err:
        print("HTTP Error: {0}".format(err))
        print("ERROR number: ", err.response)
        print("exiting ...")
        sys.exit(1)
    except:
        print("unknown ERROR: ", sys.exc_info()[0])
        print("exiting ...")
        sys.exit(1)

    return queryResult

def query_db_replicationList(session):

    qsp = {}
    try:
        qsp['filter'] = '[{"property":"hasCatalog","value":"true","op":"="},{"property":"serviceId","value":"serviceprovider.protection.catalog","op":"="},{"property":"subPolicyType","value":"REPLICATION","op":"="}]'
        queryResult = client.SppAPI(session, '').get(path="api/endeavour/jobsession", params=qsp)

    except requests.exceptions.HTTPError as err:
        print("HTTP Error: {0}".format(err))
        print("ERROR number: ", err.response)
        print("exiting ...")
        sys.exit(1)
    except:
        print("unknown ERROR: ", sys.exc_info()[0])
        print("exiting ...")
        sys.exit(1)

    return queryResult

def query_db_offloadList(session):

    qsp = {}
    try:
        qsp['filter'] = '[{"property":"hasCatalog","value":"true","op":"="},{"property":"serviceId","value":"serviceprovider.protection.catalog","op":"="},{"property":"subPolicyType","value":"SPPOFFLOAD","op":"="}]'
        queryResult = client.SppAPI(session, '').get(path="api/endeavour/jobsession", params=qsp)

    except requests.exceptions.HTTPError as err:
        print("HTTP Error: {0}".format(err))
        print("ERROR number: ", err.response)
        print("exiting ...")
        sys.exit(1)
    except:
        print("unknown ERROR: ", sys.exc_info()[0])
        print("exiting ...")
        sys.exit(1)

    return queryResult


def query_stats():
    pass


def get_system_info():
    pass








validate_input()

try:
    session = client.SppSession(options.host, options.username, options.password)
    session.login()
except requests.exceptions.HTTPError as err:
    #print("HTTP Error: {0}".format(err))
    spputil.get_error_details(err)
    print("exiting ...")
    sys.exit(1)
except:
    print("unknown ERROR: ", sys.exc_info()[0])
    print("exiting ...")
    sys.exit(1)


indent = " " * 2
print()
print(indent + "=" * 50)
print(indent + " SPP Server information:")
print(indent + "=" * 50 + "\n")

result_metrics = query_endpoint(path="ngp/metrics")

info = {'cpuUtil' : result_metrics['cpuUtil']}
info['memory_size'] = '%.2f'%(result_metrics['memory']['size']/ pow(1024, 3))      # append new tupel to dictionary
info.update(memory_util = result_metrics['memory']['util'])     # append new tupel to dictionary

result_stats   = query_endpoint(path="api/storage/stats")
spputil.remove_links(result_stats)
info.update(compressionRatio    = result_stats['compressionRatio'])
info.update(deduplicationRatio  = result_stats['deduplicationRatio'])
info.update(sizeFreeAllStorage  = '%.2f'%(result_stats['sizeFreeAllStorage'] / pow(1024,3)))
info.update(sizeTotalAllStorage = '%.2f'%(result_stats['sizeTotalAllStorage'] / pow(1024,3)))
info.update(sizeUsedAllStorage  = '%.2f'%(result_stats['sizeUsedAllStorage'] / pow(1024,3)))
info.update(unavailable         = result_stats['unavailable'])

for k, v in info.items():
    print('{:s} {:<25.25s}: {:>13.13s}'.format(indent,  str(k), str(v)))


print("\n\n")
print(" " + "=" * 50)
print('   unavailable storage: {:s}'.format( str(info['unavailable'])))
print(" " + "=" * 50 + "\n")


print('{:s} {:12.12s} | {:5.5s} | {:8.8s} | {:9.9s} | {:10.10s} | {:8.8s} | {:>7.7s} | {:>7.7s} | {:6.6s} | {:9.9s} | {:s}'.format( \
    indent, "site", "type", "writable", "compRatio", "dedupRatio", "GB Total", "GB free", "GB Used", "% used", "storageId", "error"))
print(indent, "-" * 140)

for storage in result_stats['unavailableStorage']:
    print('{:s} {:12.12s} | {:5.5s} | {:8.8s} | {:>9.9s} | {:>10.10s} | {:8.1f} | {:>7.1f} | {:>7.1f} | {:6.1f} | {:>9.9s} | {:s}'.format( \
        indent, storage['site'], storage['type'], str(storage['writable']), str(storage['compressionRatio']), \
        str(storage['deduplicationRatio']), storage['sizeTotal'] / 1024 / 1024 / 1024, \
        storage['sizeFree'] / 1024 / 1024 / 1024, \
        storage['sizeUsed'] / 1024 / 1024 / 1024, storage['sizeUsed'], \
        str(storage['storageId']), storage['errorDescription'] ))

    #for k, v in storage.items():
    #       print('{:s} {:<25.25s}: {:>13.13s}'.format(indent, str(k), str(v)))


print("\n\n")
print(" " + "=" * 50)
print("   available storage: " + str(len(result_stats['availableStorage'])))
print(" " + "=" * 50 + "\n")


print('{:s} {:12.12s} | {:5.5s} | {:8.8s} | {:9.9s} | {:10.10s} | {:8.8s} | {:>7.7s} | {:>7.7s} | {:6.6s} | {:9.9s} |'.format( \
        indent, "site", "type", "writable", "compRatio", "dedupRatio", "GB Total", "GB free", "GB Used", "% used", "storageId"))
print(indent, "-" * 110)

for storage in result_stats['availableStorage']:

    storage_used_pct = storage['sizeUsed'] / storage['sizeTotal'] * 100
    print( '{:s} {:12.12s} | {:5.5s} | {:8.8s} | {:>9.9s} | {:>10.10s} | {:8.1f} | {:>7.1f} | {:>7.1f} | {:6.1f} | {:>9.9s} |'.format( \
        indent, storage['site'], storage['type'], str(storage['writable']), str(storage['compressionRatio']), \
        str(storage['deduplicationRatio']), storage['sizeTotal']/1024/1024/1024, \
        storage['sizeFree']/ (1024 **3 ), \
        storage['sizeUsed']/1024/1024/1024, storage_used_pct, \
        str(storage['storageId']))   )

    #    for k, v in storage.items():
    #        print('{:s} {:<25.25s}: {:>13.13s}'.format(indent, str(k), str(v)))


print("\n\n")
print(" " + "=" * 50)
print("   full storage: " + str(len(result_stats['fullStorage'])))
print(" " + "=" * 50 + "\n")

if len(result_stats['fullStorage']) > 0:
    print('{:s} {:12.12s} | {:5.5s} | {:8.8s} | {:9.9s} | {:10.10s} | {:8.8s} | {:>7.7s} | {:>7.7s} | {:6.6s} | {:9.9s} |'.format( \
            indent, "site", "type", "writable", "compRatio", "dedupRatio", "GB Total", "GB free", "GB Used", "% used", "storageId"))
    print(indent, "-" * 110)
    for storage in result_stats['fullStorage']:

        storage_used_pct = storage['sizeUsed'] / storage['sizeTotal'] * 100
        print( '{:s} {:12.12s} | {:5.5s} | {:8.8s} | {:>9.9s} | {:>10.10s} | {:8.1f} | {:>7.1f} | {:>7.1f} | {:6.1f} | {:>9.9s} |'.format( \
            indent, storage['site'], storage['type'], str(storage['writable']), str(storage['compressionRatio']), \
            str(storage['deduplicationRatio']), storage['sizeTotal']/1024/1024/1024, \
            storage['sizeFree']/1024/1024/1024, \
            storage['sizeUsed']/1024/1024/1024, storage_used_pct, \
            str(storage['storageId']))   )

        #    for k, v in storage.items():
        #        print('{:s} {:<25.25s}: {:>13.13s}'.format(indent, str(k), str(v)))

result_filesystems = query_endpoint(path="api/endeavour/sysdiag/filesystem")
spputil.remove_links(result_filesystems)

print("\n\n")
print(" " + "=" * 50)
print("   filesystems: " + str(len(result_filesystems['filesystems'])))
print(" " + "=" * 50 + "\n")

if len(result_filesystems['filesystems']) > 0:

    '''
    catalog name    | status | GB Total | GB used | GB free| % used | type
    Configuration	| NORMAL | 48,10	| 2,60	  | 45,50  | 5.41   | null
    '''
    print('{:s} {:15.15s} | {:8.8s} | {:>10.10s} | {:>10.10s} | {:>10.10s} | {:>10.10s} | {:>5.5s}'.format( \
        indent, "catalog name", "status", "GB Total", "GB used", "GB free", "% used", "type"))
    print(indent, "-" * 87)

    ''' transform catalog names'''
    catalog_name=  {'Configuration'    : "Configuration", \
                    'Search'           : "File", \
                    'System'           : "System", \
                    'Catalog'          : "Recovery" }

    for fs in result_filesystems['filesystems']:
        catName = catalog_name[fs['name']]
        print('{:s} {:15.15s} | {:8.8s} | {:>10.2f} | {:10.2f} | {:10.2f} | {:10.2f} | {:>5.5s}'.format( \
            indent, catName, fs['status'], \
            fs['totalSize'] / pow(1024,3), fs['usedSize'] / pow(1024,3), \
            fs['availableSize'] / pow(1024,3), fs['percentUsed'], str(fs['type'])))


qsp = {}
qsp['filter'] = '[{"property":"name", "op":"=", "value":"catalog*"}]'

result_jobs = client.SppAPI(session, '').get(path="/api/endeavour/job", params=qsp) # example: --url=/api/endeavour/job

print("\n\n")
print(" " + "=" * 50)
print("   catalog backups (backup, replication & offload)" )
print(" " + "=" * 50 + "\n")

for job in result_jobs['jobs']:
    lastrun = job['lastrun']
    key_value_fmt = "{:s} {:<25.25s}: {:>20.20s}"
    key="jobName"
    print(key_value_fmt.format(indent, key, lastrun[key]))
    key="status"
    value=""
    print(key_value_fmt.format(indent, key, lastrun[key]))
    key="duration"
    value=str(datetime.timedelta(seconds=(round(lastrun[key]/1000))))
    print(key_value_fmt.format(indent, key, str(value)))
    key="results"
    print(key_value_fmt.format(indent, key, lastrun[key]))
    key="start"
    value=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lastrun[key]/1000))
    print(key_value_fmt.format(indent, key, value))
    key="end"
    value = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lastrun[key] / 1000))
    print(key_value_fmt.format(indent, key, value))
    #key="type"
    #print(key_value_fmt.format(indent, key, lastrun[key]))

    key="nextFireTime"
    nextFireTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(job[key]/1000))
    print(key_value_fmt.format(indent, key, nextFireTime))


print()
key_value_fmt = "{:s} {:<22.22s} | {:<10.10s} | {:20.20s} | {:10.10s} | {:9.9s} | {:20.20s}"
print(key_value_fmt.format(indent, "jobName", "state", "backup time", "type", "Subpolicy type", "expires on"))
print(indent + " " + "-" * 105)
db_backup_list = query_db_backupList(session)

for dbb in db_backup_list['sessions']:
    startTime=spputil.get_time(dbb['start'])
    expireTime=spputil.get_time(dbb['expirationTime'])

    print(key_value_fmt.format(indent, str(dbb['jobName']), str(dbb['statusDisplayName']), str(startTime), \
          str(dbb['subType']), str(dbb['subPolicyTypeDisplayName']), str(expireTime)))


db_replication_list = query_db_replicationList(session)
for dbr in db_replication_list['sessions']:
    startTime=spputil.get_time(dbr['start'])
    expireTime=spputil.get_time(dbr['expirationTime'])

    print(key_value_fmt.format(indent, str(dbr['jobName']), str(dbr['statusDisplayName']), str(startTime), \
          str(dbr['subType']), str(dbr['subPolicyTypeDisplayName']), str(expireTime)))

db_offload_list = query_db_offloadList(session)
for dbo in db_offload_list['sessions']:
    startTime=spputil.get_time(dbo['start'])
    expireTime=spputil.get_time(dbo['expirationTime'])

    print(key_value_fmt.format(indent, str(dbo['jobName']), str(dbo['statusDisplayName']), str(startTime), \
          str(dbo['subType']), str(dbo['subPolicyTypeDisplayName']), str(expireTime)))

session.logout()
