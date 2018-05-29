# Script to change user password 
# Use changeuserpassword.py -h for help
# Example:
# python changeuserpassword.py --host="https://172.20.66.100" --user="admin" --pass="oldpass123" --newpass="newpass123"

import json
import logging
from optparse import OptionParser
import copy
import sys
import sppclient.sdk.client as client
import requests
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

parser = OptionParser()
parser.add_option("--user", dest="username", help="SPP Username")
parser.add_option("--pass", dest="password", help="SPP Password")
parser.add_option("--host", dest="host", help="SPP Host, (ex. https://172.20.49.49)")
parser.add_option("--newpass", dest="newPassword", help="SPP New Password")
(options, args) = parser.parse_args()

def prettyprint(indata):
    print json.dumps(indata, sort_keys=True,indent=4, separators=(',', ': '))

def validate_input():
    if(options.username is None or options.password is None or options.host is None or options.newPassword is None):
        print "Invalid input, use -h switch for help"
        sys.exit(2)

def change_password():
    hdrs = {'Content-Type': 'application/json','Accept': 'application/json', 'X-Endeavour-Sessionid': session.sessionid}
    userURL = options.host + '/api/security/user'
    response = requests.get(userURL, verify=False, headers=hdrs)
    users = response.json()['users']
    for user in users:
        if user['name'] == options.username:
          body = {"newPassword": options.newPassword, "oldPassword": options.password}
          changePasswordURL = userURL + "/" + user['id'] + "?action=changePassword"
          try:
            changeResponse = requests.post(changePasswordURL, json=body, verify=False, headers=hdrs)
            changeResponse.raise_for_status()
            print "Password changed for " + options.username
          except requests.exceptions.HTTPError as err:
            errmsg = json.loads(err.response.content)
            print errmsg['description']

validate_input()
session = client.SppSession(options.host, options.username, options.password)
session.login()
change_password()
session.logout()
