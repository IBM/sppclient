''' tested with the following versions:
    python: 3.7.2
    Spectrum Protect Plus: 10.1.3 build 236
'''

import json
import time
import click
import traceback
import sys
import os
import socket

def get_time(time_in_ms):
    ''' convert linux time to human readble format '''
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time_in_ms / 1000))


def remove_links(obj):
    ''' removes the link attributes from the JSON response for readability, links are used to build GUI '''
    if type(obj) is dict:
        """ modified function to work with python 3.x methods, obj.has_key s depricated  """
        #if obj.has_key("links"):       # changes from python 2.x to 3.x , in 3.x no has_key is implemented
        if "links" in obj:
            del obj["links"]

        #for k, v in obj.iteritems():   # changes from python 2.x to 3.x , in 3.x no has_key is implemented
        for k, v in obj.items():
            remove_links(v)

        return

    if type(obj) is list:
        for item in obj:
            remove_links(item)
        return

    return

class Context(object):
    def __init__(self):
        self.links = False
        self.json = False

    def print_response(self, resp):
        if not self.links:
            remove_links(resp)

        click.echo_via_pager(json.dumps(resp, indent=4))

pass_context = click.make_pass_decorator(Context, ensure=True)


def pretty_print(indata):
    return json.dumps(indata, sort_keys=True,indent=4)



def read_params_from_file(filename):
    ''' if scripts (new ones provided by DPR) are invoked with option -a then this function parses a file
        for hostname or IP, username and password. '''
    params = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                key_value = line.split("=")
                if len(key_value) == 2:
                    params[key_value[0].strip()] = key_value[1].strip()
    except FileNotFoundError as err:
        print("ERROR: file not found")
    return params

def get_ip_by_name(host):
    ''' if a hostname is specified i.e. in local hosts file some scripts will not properly resolve the name.
        this function tries to resolve the hostname in the first place and ensures that the hostname starts
        with https:// protocoll '''
    host = host.replace("http://", "")
    host = host.replace("https://", "")
    hostIP = socket.gethostbyname(host)
    return "https://" + hostIP


def get_request_response_details_by_code(retCode):
    responseCode = {
                    200:        "OK - response completed successfully",
                    201:        "Created - A new resource has been created successfully. The resource’s URI is \
                                 available from the response’s Location header",
                    204:        "No Content - An update to an existing resource has been applied successfully",
                    400:        "Bad Request - The request was malformed. The response body will include an error \
                                 providing further information",
                    401:        "Unauthorized - Login attempt with invalid credentials",
                    403:        "Forbidden - Generally related to permissioning through Role Base Access Control",
                    404:        "Not Found - The requested resource did not exist",
                    405:        "Method Not Allowed - URL is unsupported",
                    500:        "Unrecoverable Error - Diagnosed in Virgo log",
                    503:        "Service Unavailable - This status is returned when too many requests are \
                                 going to the same controller",
                    "other":    "unknown return code"
                    }

    if responseCode.get(retCode) is None:
        return responseCode['other']
    else:
        return responseCode.get(retCode)


def get_error_details(error):
    ''' building customized execption error message instead of printing the whole trace... '''
    errNo = error.response.status_code
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print("Exception in FILE: {0}, Line: {1}, Exception: {2}".format(fname, exc_tb.tb_lineno, exc_type))

    responseCode = get_request_response_details_by_code(errNo)

    print("ERROR {0}: {1}".format(errNo, responseCode))
