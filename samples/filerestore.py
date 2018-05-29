#
# Script to restore a file in SPP
# Must define vm name, path and filename to ensure match
# start and end datetime are optional to select restore point
#   both must be defined if filtering by date
#   if multiple versions are found in the time window, first found is used
#   latest will be used if not defined
#

import json
import logging
from optparse import OptionParser
import copy
import sys
import sppclient.sdk.client as client
import urllib
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--file", dest="file", help="File name")
parser.add_option("--vm", dest="vm", help="VM name where file resides")
parser.add_option("--path", dest="path", help="Path to file (not including filename)")
parser.add_option("--start", dest="start", help="Start date/time")
parser.add_option("--end", dest="end", help="End date/time")
parser.add_option("--overwrite", dest="overwrite", help="Overwrite file (Optional) set to TRUE to overwrite during restore")
parser.add_option("--destvm", dest="destvm", help="Alternate destination VM (Optional)")
parser.add_option("--destpath", dest="destpath", help="Destination Path (Required for alt dest VM")
(options, args) = parser.parse_args()
if(options.overwrite is not None):
    if(options.overwrite.upper() == "TRUE"):
        options.overwrite = True
else:
    options.overwrite = False
if(options.destpath is None):
    options.destpath = ""


def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or
       options.file is None or options.vm is None or options.path is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def search_for_file():
    searchparams = {'filter': '[{"property":"catalogProvider","value":"filecatalog","op":"="},{"property":"documentType","value":"*","op":"="},{"property":"unique","value":true,"op":"="},{"property":"name","value":"%s","op":"="}]'%options.file}
    results = client.SppAPI(session, 'endeavour').get(path="/search", params=searchparams)['results']
    for result in results:
        if(options.path.upper() == result['summary']['location'].upper() and
           options.vm.upper() == result['summary']['vmName'].upper() and
           options.file.upper() == result['summary']['name'].upper()):
            return result
    logger.info("No files found, please check filename, path, and source vm name")
    session.delete('endeavour/session/')
    sys.exit(2)

def get_versions_of_file(foundfile):
    versurl = foundfile['links']['version']['href'].split("8082")[1]
    verspath = versurl.split("endeavour")[1]
    versions = client.SppAPI(session, 'endeavour').get(path=verspath)['results']
    return versions

def get_version_for_restore(foundfile, versions):
    if(options.start is None):
        return foundfile
    elif(options.start is not None and options.end is not None):
        start = int(datetime.datetime.strptime(options.start, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        end = int(datetime.datetime.strptime(options.end, '%m/%d/%Y %H:%M').strftime("%s"))*1000
        for vers in versions:
            prottime = int(vers['summary']['catalogTime'])
            if (start < prottime and prottime < end):
                return vers
    logger.info("No backup copy found with provided dates")
    session.delete('endeavour/session/')
    sys.exit(2)

def build_restore_job(version):
    job = {}
    job['spec'] = {}
    job['spec']['view'] = ""
    job['spec']['source'] = []
    job['spec']['subpolicy'] = []
    source = {}
    source['href'] = version['links']['self']['href']
    source['resourceType'] = "file"
    source['include'] = True
    source['version'] = {"href": version['links']['self']['href']}
    subpolicy = {}
    subpolicy['option'] = {}
    subpolicy['option']['overwriteExistingFile'] = options.overwrite
    subpolicy['option']['filePath'] = options.destpath
    if(options.destvm is not None):
        subpolicy['destination'] = build_alt_destination(version)
    job['spec']['source'].append(source)
    job['spec']['subpolicy'].append(subpolicy)
    return job
    

def build_alt_destination(version):
    destination = {}
    destination['target'] = {}
    vm = find_target_vm(version)
    destination['target']['href'] = vm['links']['self']['href']
    destination['resourceType'] = "vm"
    return destination
    

def find_target_vm(version):
    searchdata = {"name":options.destvm,"hypervisorType":version['summary']['hypervisorType']}
    vmsearch = client.SppAPI(session, 'corehv').post(path="/search?resourceType=vm&from=hlo", data=searchdata)['vms']
    if not vmsearch:
        logger.warning("Did not find VM " + options.destvm)
        session.delete('endeavour/session/')
        sys.exit(2)
    for vm in vmsearch:
        if(vm['name'].upper() == options.destvm.upper()):
            return vm
    logger.warning("Did not find VM " + options.destvm)
    session.delete('endeavour/session/')
    sys.exit(2)
        
def restore_file():
    foundfile = search_for_file()
    versions = get_versions_of_file(foundfile)
    version = get_version_for_restore(foundfile, versions)
    restorejob = build_restore_job(version)
    restore = client.SppAPI(session, 'spphv').post(path="?action=restorefile", data=restorejob)

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
restore_file()
session.logout()
