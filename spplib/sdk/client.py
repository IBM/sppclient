
import configparser
import json
import logging
import os
import re
import tempfile
import time

import requests
from requests.auth import HTTPBasicAuth

try:
    import urllib3
except ImportError:
    from requests.packages import urllib3

try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client

# http://stackoverflow.com/questions/10588644/how-can-i-see-the-entire-http-request-thats-being-sent-by-my-python-application
# Uncomment this to see requests and responses.
# TODO: We need better way and we should log requests and responses in
# log file.
#http_client.HTTPConnection.debuglevel = 1
urllib3.disable_warnings()

resource_to_endpoint = {
    'job': 'api/endeavour/job',
	'jobsession': 'api/endeavour/jobsession',
    'log': 'endeavour/log',
    'association': 'endeavour/association',
    'workflow': 'spec/storageprofile',
    'policy': 'endeavour/policy',
    'user': 'security/user',
    'resourcepool': 'security/resourcepool',
    'role': 'security/role',
    'identityuser': 'identity/user',
    'identitycredential': 'identity/user',
    'appserver': 'appserver',
    'oracle': 'api/application/oracle',
    'sql':'api/application/sql',
    'sppsla': 'ngp/slapolicy',
    'site': 'site',
    'appserver': 'ngp/appserver',
    'apiappsever':'api/appserver'
}

resource_to_listfield = {
    'identityuser': 'users',
    'identitycredential': 'users',
    'policy': 'policies',
    'ldap': 'ldapServers',
    'pure': 'purestorages',
    'workflow': 'storageprofiles',
    'resourcepool': 'resourcePools',
}

def build_url(baseurl, restype=None, resid=None, path=None, endpoint=None):
    url = baseurl

    if restype is not None:
        ep = resource_to_endpoint.get(restype, None)
        if not ep:
            if endpoint is not None:
                ep = endpoint
            else:
                ep = restype

        url = url + "/" + ep

    if resid is not None:
        url = url + "/" + str(resid)

    if path is not None:
        if not path.startswith('/'):
            path = '/' + path
        url = url + path

    return url.replace("/api/ngp", "/ngp")

def raise_response_error(r, *args, **kwargs):
    r.raise_for_status()

def pretty_print(data):
    return logging.info(json.dumps(data, sort_keys=True,indent=4, separators=(',', ': ')))


def change_password(url, username, password, newpassword):
    data = {'newPassword': newpassword}
    conn = requests.Session()
    conn.verify = False
    # conn.hooks.update({'response': raise_response_error})
    # conn.headers.update({'X-Endeavour-Sessionid': self.sessionid})
    conn.headers.update({'Content-Type': 'application/json'})
    conn.headers.update({'Accept': 'application/json'})
    return conn.post("%s/api/endeavour/session?changePassword=true&screenInfo=1" % url, json=data,
                         auth=HTTPBasicAuth(username, password))
    
class EcxSession(object):
    def __init__(self, url, username=None, password=None, sessionid=None):
        self.url = url
        self.sess_url = url + '/api'
        self.api_url = url + ''
        self.username = username
        self.password = password
        self.sessionid = sessionid

        self.conn = requests.Session()
        self.conn.verify = False
        self.conn.hooks.update({'response': raise_response_error})
        
        
        if not self.sessionid:
            if self.username and self.password:
                self.login()
            else:
                raise Exception('Please provide login credentials.')
        
        self.conn.headers.update({'X-Endeavour-Sessionid': self.sessionid})
        self.conn.headers.update({'Content-Type': 'application/json'})
        self.conn.headers.update({'Accept': 'application/json'})

    def login(self):
        r = self.conn.post("%s/endeavour/session" % self.sess_url, auth=HTTPBasicAuth(self.username, self.password))
        self.sessionid = r.json()['sessionid']
    
        
    def __repr__(self):
        return 'EcxSession: user: %s' % self.username

    def get(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        # return json.loads(self.conn.get(url, params=params).content)
        return self.conn.get(url, params=params).json()

    def stream_get(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None, outfile=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        r = self.conn.get(url, params=params)
        logging.info("headers: %s" % r.headers)

        # The response header Content-Disposition contains default file name
        #   Content-Disposition: attachment; filename=log_1490030341274.zip
        default_filename = re.findall('filename=(.+)', r.headers['Content-Disposition'])[0]

        if not outfile:
            if not default_filename:
                raise Exception("Couldn't get the file name to save the contents.")

            outfile = os.path.join(tempfile.mkdtemp(), default_filename)

        with open(outfile, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=64*1024):
                fd.write(chunk)

        return outfile

    def delete(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        resp = self.conn.delete(url, params=params)

        # return json.loads(resp.content) if resp.content else None
        return resp.json() if resp.content else None

    def post(self, restype=None, resid=None, path=None, data={}, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        logging.info(json.dumps(data, indent=4))
        r = self.conn.post(url, json=data, params=params)

        if r.content:
            return r.json()

        return {}
    
    def put(self, restype=None, resid=None, path=None, data={}, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        logging.info(json.dumps(data, indent=4))
        r = self.conn.put(url, json=data, params=params)

        if r.content:
            return r.json()

        return {}  
    

class EcxAPI(object):
    def __init__(self, ecx_session, restype=None, endpoint=None):
        self.ecx_session = ecx_session
        self.restype = restype
        self.endpoint = endpoint
        self.list_field = resource_to_listfield.get(restype, self.restype + 's')

    def get(self, resid=None, path=None, params={}, url=None):
        return self.ecx_session.get(restype=self.restype, resid=resid, path=path, params=params, url=url)

    def stream_get(self, resid=None, path=None, params={}, url=None, outfile=None):
        return self.ecx_session.stream_get(restype=self.restype, resid=resid, path=path,
                                           params=params, url=url, outfile=outfile)

    def delete(self, resid):
         return self.ecx_session.delete(restype=self.restype, resid=resid)

    def list(self):
        return self.ecx_session.get(restype=self.restype)[self.list_field]

    def post(self, resid=None, path=None, data={}, params={}, url=None):
        return self.ecx_session.post(restype=self.restype, resid=resid, path=path, data=data,
                                     params=params, url=url)
                                     
    def put(self, resid=None, path=None, data={}, params={}, url=None):
        return self.ecx_session.put(restype=self.restype, resid=resid, path=path, data=data,
                                     params=params, url=url)
    
        

class JobAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(JobAPI, self).__init__(ecx_session, 'job')

    # TODO: May need to check this API seems to return null instead of current status
    # Can use lastSessionStatus property in the job object for now
    def status(self, jobid):
        return self.ecx_session.get(restype=self.restype, resid=jobid, path='status')
    
    def getjob(self,name):
        jobs = self.get()['jobs']
        for job in jobs:
            if(job['name']==name):
                job_id = job['id']
                return job
    # TODO: Accept a callback that can be called every time job status is polled.
    # The process of job start is different depending on whether jobs have storage
    # workflows.
    def run(self, jobid, workflowid=None):
        job = self.ecx_session.get(restype=self.restype, resid=jobid)

        links = job['links']
        if 'start' not in links:
            raise Exception("'start' link not found for job: %d" % jobid)

        start_link = links['start']
        reqdata = {}

        if 'schema' in start_link:
            # The job has storage profiles.
            schema_data = self.ecx_session.get(url=start_link['schema'])
            workflows = schema_data['parameter']['actionname']['values']
            if not workflows:
                raise Exception("No workflows for job: %d" % jobid)
            if len(workflows) > 1:
                if(workflowid is None):
                    raise Exception("Workflow ID not provided")
                else:
                    reqdata["actionname"] = workflowid
            else:
                reqdata["actionname"] = workflows[0]['value']

        jobrun = self.ecx_session.post(url=start_link['href'], data=reqdata)

        # The session ID corresponding to the latest run is not sent back
        # in response. Rather, we need to query to get it.
        for i in range(5):
            live_sessions = self.ecx_session.get(url=jobrun['links']['livejobsessions']['href'])
            pretty_print(live_sessions)

            try:
                jobrun["curr_jobsession_id"] = live_sessions["sessions"][0]["id"]
            except Exception:
                logging.info("Attempt {}: Error in getting live job sessions".format(i))
                time.sleep(2)

        # In case, we failed in finding job session ID, we don't throw exception
        # but just return job object without that information. It is upto the
        # callers to check for this condition and act accordingly.
        return jobrun

    def get_log_entries(self, jobsession_id, page_size=1000, page_start_index=0):
        logging.info("*** get_log_entries: jobsession_id = %s, page_start_index: %s ***" % (jobsession_id, page_start_index))

        resp = self.ecx_session.get(restype='log', path='job',
                                    params={'pageSize': page_size, 'pageStartIndex': page_start_index,
                                            'sort': '[{"property":"logTime","direction":"ASC"}]',
                                            'filter': '[{"property":"jobsessionId","value":"%s"}]'%jobsession_id})

        logging.info("*** get_log_entries:     Received %d entries..." % len(resp['logs']))

        return resp['logs']
    
    def monitor(self,jobStatus,job_id,job_name):
        jobIsActive = False
        while (True):
            if (jobIsActive and ((jobStatus=="PENDING") or (jobStatus=="RESOURCE ACTIVE"))):
                break
            if (jobStatus == "IDLE"):
                break
            if (not jobIsActive and (jobStatus != "PENDING")):
                jobIsActive = True
            print(" Sleeping for 30 seconds...")
            time.sleep(30)
            jobStatus = self.status(job_id)['currentStatus'] 
            print(jobStatus)
        
        
        sessionId = self.getjob(job_name)['lastrun']['sessionId']
        print(sessionId)
        sessionStatus = self.ecx_session.get(path='api/endeavour/jobsession/'+sessionId)['status']
        return jobStatus,sessionStatus

class UserIdentityAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(UserIdentityAPI, self).__init__(ecx_session, 'identityuser')

    def create(self, data):
        return self.post(data=data)

class AppserverAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(AppserverAPI, self).__init__(ecx_session, 'appserver')

class VsphereAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(VsphereAPI, self).__init__(ecx_session, 'vsphere')

class ResProviderAPI(EcxAPI):
    # Credential info is passed in different field names so we need to maintain
    # the mapping.
    user_field_name_map = {"appserver": "osuser", "purestorage": "user", "emcvnx": "user"}

    # Resource type doesn't always correspond to API so we need a map.
    res_api_map = {"purestorage": "pure"}

    def __init__(self, ecx_session, restype):
        super(ResProviderAPI, self).__init__(ecx_session, ResProviderAPI.res_api_map.get(restype, restype))

    def register(self, name, host, osuser_identity, appType=None, osType=None, catalog=True, ssl=True, vsphere_id=None):
        osuser_field = ResProviderAPI.user_field_name_map.get(self.restype, 'user')
        reqdata = {
            "name": name, "hostAddress": host, "addToCatJob": catalog,
        }

        reqdata[osuser_field] = {
            "href": osuser_identity['links']['self']['href']
        }

        if vsphere_id:
            reqdata["serverType"] = "virtual"
            reqdata["vsphereId"] = vsphere_id

        if appType:
            reqdata["applicationType"] = appType
            reqdata["useKeyAuthentication"] = False

        if osType:
            reqdata["osType"] = osType

        return self.post(data=reqdata)

class AssociationAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(AssociationAPI, self).__init__(ecx_session, 'association')

    def get_using_resources(self, restype, resid):
        return self.get(path="resource/%s/%s" % (restype, resid), params={"action": "listUsingResources"})

class LogAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(LogAPI, self).__init__(ecx_session, 'log')

    def download_logs(self, outfile=None):
        return self.stream_get(path="download/diagnostics", outfile=outfile)

class OracleAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(OracleAPI, self).__init__(ecx_session, 'oracle')
        
    def get_instances(self):
        return self.get(path="/instance?from=hlo")
    
    def get_instance(self,instances,name):
        for inst in instances:
            if inst['name'] == name:
                return inst
class SqlAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(SqlAPI, self).__init__(ecx_session, 'sql')
        
    def get_instances(self):
        return self.get(path="/instance?from=hlo")
    
    def get_instance(self,instances,name):
        for inst in instances:
            if inst['name'] == name:
                return inst
        
    def get_databases_in_instance(self, instanceid):
        return self.get(path="oraclehome/%s/database" % instanceid)

    def get_database_copy_versions(self, instanceid, databaseid):
        return self.get(path="oraclehome/%s/database/%s" % (instanceid, databaseid) + "/version")
    
class slaAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(slaAPI, self).__init__(ecx_session, 'sppsla')
        
    def createSla(self,name):
        slainfo = {"name":name,
           "version":"1.0",
           "spec":{"simple":True,
                   "subpolicy":[{"type":"REPLICATION",
                                 "software":True,"retention":{"age":15},
                                 "trigger":{"frequency":1,"type":"DAILY","activateDate":1524110400000},
                                 "site":"Primary"}]}}
        resp = self.post(data = slainfo)
        return resp
    
    def assign_sla(self,instance,sla,subtype):
        applySLAPolicies = {"subtype":subtype,
                    "version":"1.0",
                    "resources":[{
                        "href":instance['links']['self']['href'],
                        "id":instance['id'],
                        "metadataPath":instance['metadataPath']}],
                    "slapolicies":[{
                        "href":sla['links']['self']['href'],
                        "id":sla['id'],
                        "name":sla['name']}]}
        return self.ecx_session.post(data = applySLAPolicies, path='ngp/application?action=applySLAPolicies')
    
class restoreAPI(EcxAPI):
    def __init__(self, ecx_session):
        super(restoreAPI, self).__init__(ecx_session, 'ngp/application')
        
    def restore(self,subType,database_href,database_version,database_torestore,database_id,restoreName):
        restore = {"subType":subType,
           "script":
           {"preGuest":None,
            "postGuest":None,
            "continueScriptsOnError":False},
           "spec":
           {"source":[{"href":database_href,
                       "resourceType":"database",
                       "include":True,
                       "version":{"href":database_version,
                                  "metadata":{"useLatest":True}},
                       "metadata":
                       {"name":database_torestore},
                       "id":database_id}],
            "subpolicy":
            [{"type":"restore",
              "mode":"test",
              "destination":
              {"mapdatabase":{database_href:
                              {"name":restoreName,
                               "paths":[]}}},
              "option":
              {"autocleanup":False,
               "allowsessoverwrite":False,
               "continueonerror":False,
               "applicationOption":
               {"overwriteExistingDb":False,
                "maxParallelStreams":1,
                "initParams":"source"}},
              "source":
              {"copy":
               {"site":{"href":"https://172.20.47.47:443/api/site/1000"}}}}],
            "view":"applicationview"}}

        #return EcxAPI(session, 'ngp/application').post(path='?action=restore', data=restore)['response']
        return self.ecx_session.post(data = restore, path='ngp/application?action=restore')['response']
    
    def getStatus(self,job_id):
        jobsession = self.ecx_session.get(path='api/endeavour/jobsession?pageSize=200')['sessions']
        for session in jobsession:
            if(session['jobId'] == job_id):
                print(session['status'])
                currentstatus = session['status']
                break
        return currentstatus
    


        
    
