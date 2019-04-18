# Script show details of storage, i.e. utilization, version, ...

'''
    tested with the following versions:
        python: 3.7.2
        Spectrum Protect Plus: 10.1.3 build 236
'''

from optparse import OptionParser
import sys
import requests
sys.path.insert(0, '..')          # import local sppclient, do not use the global sppclient under user site package
import spplib.sdk.client as client
import spplib.cli.util as spputil
import traceback


parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--status", dest="status", help="status of vsnap / storage, can be READY|OFFLINE")
parser.add_option("--type", dest="type", help="type of storaga: i.e. vsnap")
parser.add_option("--default", dest="default", help="the storage type is default: True|False")
parser.add_option("--name", dest="name", help="storage name")
parser.add_option("--free_le", dest="free_le", help="filter by available capacity, LE = less or equal than")
parser.add_option("--free_ge", dest="free_ge", help="filter by available capacity, GE = greater or equal than")
parser.add_option("--used_ge", dest="used_ge", help="filter by used capacity in percent, GE = greater or equal than")
parser.add_option("--used_le", dest="used_le", help="filter by used capacity in percent, LE = less or equal than")
parser.add_option("-a", dest="authfile", action="store_true", help="use file with host address and user credentials")
(options, args) = parser.parse_args()


def session_start():
    try:
        session = client.SppSession(options.host, options.username, options.password)
        session.login()
    except requests.exceptions.HTTPError as err:
        spputil.get_error_details(err)
        print("exiting ...")
        sys.exit(1)
    except:
        #print("other Exception: ", sys.exc_info()[0])
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



def get_storage_list(session):
    print()
    print('{:25.25s} | {:8.8s} | {:8.8s} | {:7.7s} | {:7.7s} | {:9.9s} | {:>9.9s} | {:>6.6s} | {:10.10s}'.format( \
        "Storage Name", "type", "site", "default", "status", "cpty (GB)", "free (GB)", "% used", "version"))

    print('-' * 113)

    #myQueryResult = client.SppAPI(session, '').get(url='https://192.168.0.1/api/site/1000')
    corestorage_json_response = client.SppAPI(session, 'corestorage').get()['storages']
    ''' above function builds and queries the endpoint  GET:  /api/storage/
        the endpoints are defined in the module client.py in the function "resource_to_endpoint"  '''


    for storage in corestorage_json_response:
        displayMsg = True

        storage_Name = storage['name']
        storage_initStatus  = storage['initializeStatus']
        storage_hostAddress = storage['hostAddress']
        storage_type = storage['type']
        storage_version = storage['version']
        storage_free = storage['capacity']['free']
        storage_total = storage['capacity']['total']
        storage_used = storage_total - storage_free
        storage_totalGB = storage_total / (1024 ** 3)
        storage_freeGB = storage_free / 1024 / 1024 / 1024
        storage_pctUsed = (storage_used / storage_total) * 100
        storage_siteID = storage['site']

        ''' evaluating if result should be printed in output. Basically all storage objects are retrieved
            from the API and filtered in this script. Whenever a filter or limitation is evaluated to false 
            the information related to the object is not beeing printed out. '''

        if options.status is not None:
            if options.status.upper() != storage_initStatus.upper():
                displayMsg = False
                continue

        if options.type is not None:
            if options.type.upper() != storage_type.upper():
                displayMsg = False
                continue

        if options.default is not None:
            if options.default.upper() != str(storage_site_default).upper():
                displayMsg = False
                continue

        if options.name is not None:
            if options.name.upper() not in storage_Name.upper():
                displayMsg = False
                continue

        if options.free_le is not None:
            if float(storage_freeGB) > float(options.free_le):
                displayMsg = False
                continue

        if options.free_ge is not None:
            if round(float(storage_freeGB), 1) < round(float(options.free_ge), 1):
                displayMsg = False
                continue

        if options.used_ge is not None:
            if round(float(storage_pctUsed), 1) < round(float(options.used_ge), 1):
                displayMsg = False
                continue

        if options.used_le is not None:
            if round(float(storage_pctUsed), 1) > round(float(options.used_le), 1):
                displayMsg = False
                continue


        storage_site_details = client.SppAPI(session, 'coresite').get(path=storage_siteID)
        ''' above function builds and queries the endpoint:  /api/site/{siteId} using the dictionary 
            in client.py to resolve "coresite" to "/api/site/" '''

        spputil.remove_links(storage_site_details)
        storage_site_name = storage_site_details['name']
        storage_site_default = storage_site_details['defaultSite']

        if displayMsg is True:
            print('{:<25.25s} | {:8.8s} | {:8.8s} | {:7.7s} | {:7.7s} | {:>9.1f} | {:>9.1f} | {:>6.1f} | {:10.10s}'.format \
                  (storage_Name, storage_type, storage_site_name, str(storage_site_default), storage_initStatus, \
                   storage_totalGB, storage_freeGB, storage_pctUsed, storage_version))



def main():

    validate_input()
    session = session_start()

    get_storage_list(session)
    session.logout()



if __name__ == "__main__":
    main()