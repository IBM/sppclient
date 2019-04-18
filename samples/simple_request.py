import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3
import sys

''' supress WARNING InsecureRequestWarning'''
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


host = 'https://spphost/'
username = 'testuser'
password = 'pass4AP!'

''' purpose of this script is to demonstrate the basic steps to interact with a REST API without sppclient '''


def login():
    ''' login process '''
    myAuth=HTTPBasicAuth(username, password)
    url=host + "api/endeavour/session"
    myHeaders = {'Accept' : 'application/json', 'Content-type' : 'application/json'}
    response = requests.post(url, headers=myHeaders, auth=myAuth, verify=False)


    returnCode = response.status_code
    response_json = response.json()
    sessionid = response_json['sessionid']

    if returnCode != 200:
        print("request not successfull. responseCode: " + returnCode)
        sys.exit(1)
    else:
        print("Session ID: {0}".format(sessionid))

    return sessionid


def logout(sessionid):
    url = host + "api/endeavour/session"
    myHeaders = {'Accept': 'application/json', 'Content-type': 'application/json'}
    myHeaders.update({'X-Endeavour-Sessionid': sessionid})
    response_logout = requests.delete(url, headers=myHeaders, verify=False)

    returnCode = response_logout.status_code

    print("myHeaders: " + json.dumps(myHeaders))


    if returnCode != 204:
        print("request not successfull. responseCode: " + str(returnCode))
        sys.exit(1)
    else:
        print("Logout successfull")

    return returnCode


def query_endpoint(sessionid, endpoint):

    url = host + endpoint
    print("endpoint to query: " + url)
    myHeaders = {'Accept': 'application/json', 'Content-type': 'application/json'}
    myHeaders.update({'X-Endeavour-Sessionid': sessionid})
    print("query myHeaders: " + json.dumps(myHeaders))

    response_query = requests.get(url, headers=myHeaders, verify=False)
    return response_query



def main():
    print()
    sessionid = login()
    endpoint = "/api/site"
    response_query = query_endpoint(sessionid, endpoint)
    if response_query.status_code == 200:
        print(json.dumps(response_query.json()))
        #print(json.dumps(response_query.json(), sort_keys=False,indent=2))
    else:
        print("response == " + str(response_query.status_code))

    print()
    logout(sessionid)




if __name__ == "__main__":
    main()


