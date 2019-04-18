# Script performs GET actions from the SPP REST API. The returned JSON
# response gets pre-filtered (removes the link objects) and prints out the JSON response
# in readable format, unless -v (verbose) and / or -r (raw) is specified, check tool help for details
# The script uses the REST API client functions, i.e. session handling, etc..

'''
    tested with the following versions:
        python: 3.7.2
        Spectrum Protect Plus: 10.1.3 build 236
'''

import sys
'''
 add search parent directory to module search path and import local sppclient, installed spp client under global or local 
 site-package will be ignored if sppclient and utils is found in search path, 
 parent directory is added at the beginning of sys.path and after the first hit no further directory is searched for the 
 modules which needs to be imported... 
'''
sys.path.insert(0, '..')

import json
from optparse import OptionParser
import requests
import spplib.sdk.client as client
import spplib.cli.util as spputil
import traceback


''' option parser for command line parsing'''
parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (i.e. https://172.20.49.49)")
parser.add_option("--endpoint", "--url",  dest="url", help="API endpoint, i.e. --endpoint=\"api/site/{siteID}\"")
parser.add_option("--filter", dest="filter", help="optional, filter as JSON,  i.e.: \
                   [{\"property\": \"type\", \"op\": \"=\", \"value\": \"WARN\"}]")
parser.add_option("--sort", dest="sort",
                  help="optional, sort as JSON,  i.e.: \n[{\"property\": \"name\", \"direction\": \"DESC|ASC\"}]")
parser.add_option("--pagesize", dest="pagesize", help="optional, number of max results")
parser.add_option("-v", dest="verbose", action="store_true", help="verbose information, incl. links objects")
parser.add_option("-a", dest="authfile", action="store_true", help="use file with host address and user credentials")
parser.add_option("-r", dest="raw", action="store_true", help="do not format JSON, display RAW message")
(options, args) = parser.parse_args()




def validate_input():

    if options.authfile is True:
        params_from_file = spputil.read_params_from_file(filename="auth.txt")

        if "host" in params_from_file and "username" in params_from_file and "password" in params_from_file:
            options.host = params_from_file['host']
            options.password = params_from_file['password']
            options.username = params_from_file['username']
        else:
            pass

    if(options.username is None or options.password is None or options.host is None or options.url is None):
        print(options)
        print("Invalid input, use -h switch for help")
        sys.exit(1)
    else:
        options.host = spputil.get_ip_by_name(options.host)


validate_input()

''' create session and login '''
try:
    session = client.SppSession(options.host, options.username, options.password)
    session.login()
except requests.exceptions.HTTPError as err:
    spputil.get_error_details(err)
    print("exiting ...")
    sys.exit(1)
except:
    print(traceback.format_exc())
    print("exiting ...")
    sys.exit(1)


endpoint = options.host + "/" + options.url
print(file=sys.stderr)
print("Endpoint:       " + endpoint, file=sys.stderr)

path = None
filter = None
restURL = endpoint
symbol = "?"
qsp = {}

if (options.filter is not None):

    if len(qsp) == 0:
        symbol = "?"
    else:
        symbol = "&"

    qsp['filter'] = options.filter
    restURL = restURL + symbol + "filter=" + options.filter

if options.sort is not None:
    if len(qsp) == 0:
        symbol = "?"
    else:
        symbol = "&"

    qsp['sort'] = options.sort
    restURL = restURL + symbol + "sort=" + options.sort

if options.pagesize is not None:
    if len(qsp) == 0:
        symbol = "?"
    else:
        symbol = "&"

    qsp['pageSize'] = options.pagesize
    restURL = restURL + symbol + "pageSize=" + options.pagesize

''' the output stream for the information is set to error on purpose. If it would be stdout then also this 
    text would be piped to i.e. jq and leading to parsing problems.. '''

print("Options filter: " + str(filter), file=sys.stderr)
print("restURL:        " + restURL, file=sys.stderr)
print(file=sys.stderr)


try:
    myQueryResult = client.SppAPI(session, '').get(path=options.url, params=qsp) # example: --url=/api/endeavour/job

    # other example calls:
    # myQueryResult = client.SppAPI(session, 'job').get(params=qsp)
    # myQueryResult = client.SppAPI(session,'').get(url=restURL)  # example: restURL:  https://spphost/api/endeavour/job?filter=[{"property":"name", "op":"=", "value":"catalog_SPP-backup"}]&sort=[{"property":"name", "direction":"DESC"}]


except requests.exceptions.HTTPError as err:
    spputil.get_error_details(err)
    print("exiting ...")
    sys.exit(1)
except:
    print("other ERROR: ", traceback.print_exc())
    print("exiting ...")
    sys.exit(1)

if options.verbose is not True:
    spputil.remove_links(myQueryResult)

if options.raw is True:
    print(json.dumps(myQueryResult))
else:
    print(json.dumps(myQueryResult, sort_keys=True, indent=4, separators=(',', ': ')))

session.logout()

