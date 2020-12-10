import json
import os
import re
import tempfile
import time
import logging
import traceback
from spplib.sdk import system

import requests
from requests.utils import requote_uri
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
# http_client.HTTPConnection.debuglevel = 1
urllib3.disable_warnings()

resource_to_endpoint = {
    'job': 'api/endeavour/job',
    'jobsession': 'api/endeavour/jobsession',
    'log': 'api/endeavour/log',
    'association': 'endeavour/association',
    'workflow': 'spec/storageprofile',
    'policy': 'endeavour/policy',
    'user': 'security/user',
    'resourcepool': 'security/resourcepool',
    'role': 'security/role',
    'identityuser': 'identity/user',
    'identitycredential': 'identity/user',
    'oracle': 'api/application/oracle',
    'file': 'api/application/file',
    'sql': 'api/application/sql',
    'sppsla': 'ngp/slapolicy',
    'site': 'site',
    'appserver': 'ngp/appserver',
    'apiappserver': 'api/appserver',
    'apiapp': 'api/application',
    'ngpapp': 'ngp/application',
    'corehv': 'api/hypervisor',
    'coresite': 'api/site',
    'spphv': 'ngp/hypervisor',
    'storage': 'ngp/storage',
    'corestorage': 'api/storage',
    'endeavour': 'api/endeavour',
    'search': 'api/endeavour/search',
    'cloud': 'api/cloud',
    'key': '/api/identity/key',
    'certificate': '/api/security/certificate'
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

    def replace_double_slash(url, old, new, occurrence):
        li = url.rsplit(old, occurrence)
        return new.join(li)
 
    url = replace_double_slash(url, '//', '/', url.count('//') - 1)

    return url.replace("/api/ngp", "/ngp")


def raise_response_error(r, *args, **kwargs):
    '''
    if r.content:
        try:
            pretty_print(r.json())
        except:
            pretty_print(r)
    '''

    r.raise_for_status()


def pretty_print(data):
    return logging.info(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))


def change_password(url, initusername, password, newusername, newpassword):
    data = {'newPassword': newpassword,
            'newUsername': newusername}
    conn = requests.Session()
    conn.verify = False
    # conn.hooks.update({'response': raise_response_error})
    # conn.headers.update({'X-Endeavour-Sessionid': self.sessionid})
    conn.headers.update({'Content-Type': 'application/json'})
    conn.headers.update({'Accept': 'application/json'})
    return conn.post("%s/api/endeavour/session?changePassword=true&screenInfo=1" % url, json=data,
                     auth=HTTPBasicAuth(initusername, password))


def change_ospassword(url, oldpassword, newpassword):
    data = {"osOldPassword": oldpassword,
            "osNewPassword": newpassword,
            "osConfirmNewPassword": newpassword}
    conn = requests.Session()
    conn.verify = False
    # conn.hooks.update({'response': raise_response_error})
    # conn.headers.update({'X-Endeavour-Sessionid': self.sessionid})
    conn.headers.update({'Content-Type': 'application/json'})
    conn.headers.update({'Accept': 'application/json'})
    return conn.post("%s/api/endeavour/session?changeOsPassword=true&screenInfo=1" % url, json=data)


class SppSession(object):
    def __init__(self, url, username=None, password=None, sessionid=None, raise_error=True, admin_console_sessionid=None):
        self.url = url
        self.sess_url = url + '/api'
        self.api_url = url + ''
        self.username = username
        self.password = password
        self.sessionid = sessionid
        self.admin_console_sessionid = admin_console_sessionid

        self.conn = requests.Session()
        self.conn.verify = False
        if raise_error:
            self.conn.hooks.update({'response': raise_response_error})

        if not self.sessionid:
            if self.username and self.password:
                self.login()
            else:
                raise Exception('Please provide login credentials.')

        self.conn.headers.update({'X-Endeavour-Sessionid': self.sessionid})
        # self.conn.headers.update({'Content-Type': 'application/json'})
        self.conn.headers.update({'Accept': 'application/json'})
        self.conn.headers.update({'X-Endeavour-Locale': 'en-us'})

    def login(self):
        r = self.conn.post("%s/endeavour/session" % self.sess_url,
                           auth=HTTPBasicAuth(self.username, self.password))
        self.sessionid = r.json()['sessionid']

    def login_to_admin_console(self):
        data = {
            'ltype': 'product',
            'username': self.username,
            'password': self.password
        }
        
        r = self.conn.post("%s:8090/emi/api/login" % self.url, data=data)
        self.admin_console_sessionid = r.json()['authoutput']['sessionId']
        self.conn.headers.update({'x-ac-sessionid': self.admin_console_sessionid})

    def restart_spp(self):
        data = {
            'appaction': 'restartapp'
        }
        try: 
            r = self.conn.post("%s:8090/emi/api/manageapp" % self.url, data=data)
        except requests.exceptions.HTTPError as e:
           
            logging.warning(e)
            raise e

        # Wait for the server to actually go down.
        time.sleep(60)

        # Periodically check if the server is already up.
        for _ in range(90):
            resp = requests.get(self.url + '/api/lifecycle/ping', verify=False)
            if resp.status_code == 200:
                return resp

            time.sleep(10)

        raise Exception('Server is taking too long to respond!')
        

    def logout(self):
        r = self.conn.delete("%s/endeavour/session" % self.sess_url)

    def __repr__(self):
        return 'sppSession: user: %s' % self.username

    def get(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        url = requote_uri(url)
        url = url.replace("[", "%5B")
        url = url.replace("]", "%5D")

        logging.info('\n\n')
        logging.info('GET  {}'.format(url))

        # return json.loads(self.conn.get(url, params=params).content)
        resp = self.conn.get(url, params=params)

        logging.info("{} {}".format(resp.status_code,
                                    requests.status_codes._codes[resp.status_code][0]))
        logging.info('\n')
        if resp.content:
            response_json = resp.json()
            logging.info('\n')
            # Commenting this line to reduce the xml file size
            #logging.info(json.dumps(response_json, sort_keys=True, indent=4, separators=(',', ': ')))

        return resp.json()

    def diag_get(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None, outfile=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        url = requote_uri(url)
        url = url.replace("[", "%5B")
        url = url.replace("]", "%5D")

        logging.info('\n\n')
        logging.info('GET  {}'.format(url))

        # return json.loads(self.conn.get(url, params=params).content)
        resp = self.conn.get(url, params=params)
        default_filename = re.findall(
            'filename=(.+)', resp.headers['Content-Disposition'])[0]

        if not outfile:
            if not default_filename:
                raise Exception(
                    "Couldn't get the file name to save the contents.")

            outfile = os.path.join(tempfile.mkdtemp(), default_filename)

        with open(outfile, 'wb') as fd:
            fd.write(resp.content)

        return outfile

    def stream_get(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None, outfile=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        url = requote_uri(url)
        url = url.replace("[", "%5B")
        url = url.replace("]", "%5D")

        r = self.conn.get(url, params=params)
        # The response header Content-Disposition contains default file name
        #   Content-Disposition: attachment; filename=log_1490030341274.zip
        default_filename = re.findall(
            'filename=(.+)', r.headers['Content-Disposition'])[0]

        if not outfile:
            if not default_filename:
                raise Exception(
                    "Couldn't get the file name to save the contents.")

            outfile = os.path.join(tempfile.mkdtemp(), default_filename)

        with open(outfile, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=64*1024):
                fd.write(chunk)

        return outfile

    def delete(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        url = requote_uri(url)
        url = url.replace("[", "%5B")
        url = url.replace("]", "%5D")

        logging.info('\n\n')
        logging.info('DELETE {}'.format(url))

        resp = self.conn.delete(url, params=params)

        logging.info("{} {}".format(resp.status_code,
                                    requests.status_codes._codes[resp.status_code][0]))
        logging.info('\n')
        if resp.content:
            response_json = resp.json()
            logging.info('\n')
            # Commenting this line to reduce the xml file size
            #logging.info(json.dumps(response_json, sort_keys=True, indent=4, separators=(',', ': ')))

        # return json.loads(resp.content) if resp.content else None
        return resp.json() if resp.content else None

    def post(self, restype=None, resid=None, path=None, data={}, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        url = requote_uri(url)
        url = url.replace("[", "%5B")
        url = url.replace("]", "%5D")

        logging.info('\n\n')
        logging.info('POST  {}'.format(url))

        r = self.conn.post(url, json=data, params=params)

        logging.info("{} {}".format(
            r.status_code, requests.status_codes._codes[r.status_code][0]))
        logging.info('\n')
        if r.content:
            response_json = r.json()
            logging.info('\n')
            # Commenting this line to reduce the xml file size
            #logging.info(json.dumps(response_json, sort_keys=True, indent=4, separators=(',', ': ')))

        if r.content:
            return r.json()

        return {}

    def put(self, restype=None, resid=None, path=None, data={}, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

        url = requote_uri(url)
        url = url.replace("[", "%5B")
        url = url.replace("]", "%5D")

        logging.info('\n\n')
        logging.info('PUT  {}'.format(url))

        r = self.conn.put(url, json=data, params=params)

        logging.info("{} {}".format(
            r.status_code, requests.status_codes._codes[r.status_code][0]))
        logging.info('\n')
        if r.content:
            response_json = r.json()
            logging.info('\n')
            # Commenting this line to reduce the xml file size
            #logging.info(json.dumps(response_json, sort_keys=True, indent=4, separators=(',', ': ')))

        if r.content:
            return r.json()

        return {}


class SppAPI(object):
    def __init__(self, spp_session, restype=None, endpoint=None):
        self.spp_session = spp_session
        self.restype = restype
        self.endpoint = endpoint
        if restype is not None:
            self.list_field = resource_to_listfield.get(
                restype, self.restype + 's')

    def get(self, resid=None, path=None, params={}, url=None):
        return self.spp_session.get(restype=self.restype, resid=resid, path=path, params=params, url=url)

    def get_log(self, resid=None, path=None, params={}, url=None, outfile=None):
        return self.spp_session.diag_get(restype=self.restype, resid=resid, path=path, params=params, url=url, outfile=outfile)

    def stream_get(self, resid=None, path=None, params={}, url=None, outfile=None):
        return self.spp_session.stream_get(restype=self.restype, resid=resid, path=path,
                                           params=params, url=url, outfile=outfile)

    def delete(self, resid):
        return self.spp_session.delete(restype=self.restype, resid=resid)

    def list(self):
        return self.spp_session.get(restype=self.restype)[self.list_field]

    def post(self, resid=None, path=None, data={}, params={}, url=None):
        return self.spp_session.post(restype=self.restype, resid=resid, path=path, data=data,
                                     params=params, url=url)

    def put(self, resid=None, path=None, data={}, params={}, url=None):
        return self.spp_session.put(restype=self.restype, resid=resid, path=path, data=data,
                                    params=params, url=url)


class JobSessionAPI(SppAPI):
    def __init__(self, spp_session):
        super(JobSessionAPI, self).__init__(spp_session, 'jobsession')

    def get_jobsession(self, job_session_id):

        job_session = self.spp_session.get(
            path='api/endeavour/jobsession/{}'.format(job_session_id))

        return job_session

    def expire_job_session(self, job_session_id):

        response = self.spp_session.post(
            path='api/endeavour/jobsession/{}?action=expire'.format(job_session_id)
        )

        return response

    def expire_job_session_all(self, job_session_id):

        response = self.spp_session.post(
            path='api/endeavour/jobsession/{}?action=expireall'.format(job_session_id)
        )

        return response
    
    def get_job_history(self, page_size=100, page_start_index=0):
        
        job_sessions = self.spp_session.get(path='api/endeavour/jobsession',
                                    params={'pageSize': page_size, 'pageStartIndex': page_start_index,
                                            'sort': '[{"property":"start","direction":"DESC"}]',
                                            'filter': '[{"property":"status","value":["COMPLETED","PARTIAL","FAILED","CANCELLED","ABORTED"],"op":"IN"},' +
                                            '{"property":"rangeunit","value":"hour","op":"="},{"property":"range","value":12,"op":"="}]'}
                                        )

        return job_sessions['sessions']


class DiagAPI(SppAPI):
    def __init__(self, spp_session):
        super(DiagAPI, self).__init__(spp_session, 'jobsession')

    def get_joblogs(self, url, outfile):
        resp_diag = SppAPI.get_log(self, url=url, outfile=outfile)
        return resp_diag


class JobAPI(SppAPI):
    def __init__(self, spp_session):
        super(JobAPI, self).__init__(spp_session, 'job')

    # TODO: May need to check this API seems to return null instead of current status
    # Can use lastSessionStatus property in the job object for now
    def status(self, jobid):
        return self.spp_session.get(restype=self.restype, resid=jobid, path='status')

    def getjob(self, name):
        jobs = self.get()['jobs']
        for job in jobs:
            if(job['name'] == name):
                job_id = job['id']
                return job
    # TODO: Accept a callback that can be called every time job status is polled.
    # The process of job start is different depending on whether jobs have storage
    # workflows.

    def run(self, jobid, workflowid=None):
        job = self.spp_session.get(restype=self.restype, resid=jobid)

        links = job['links']
        if 'start' not in links:
            raise Exception("'start' link not found for job: %d" % jobid)

        start_link = links['start']
        reqdata = {}

        if 'schema' in start_link:
            # The job has storage profiles.
            schema_data = self.spp_session.get(url=start_link['schema'])
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

        jobrun = self.spp_session.post(url=start_link['href'], data=reqdata)

        # The session ID corresponding to the latest run is not sent back
        # in response. Rather, we need to query to get it.
        for i in range(5):
            live_sessions = self.spp_session.get(
                url=jobrun['links']['livejobsessions']['href'])

            try:
                jobrun["curr_jobsession_id"] = live_sessions["sessions"][0]["id"]
            except Exception:
                time.sleep(2)

        # In case, we failed in finding job session ID, we don't throw exception
        # but just return job object without that information. It is upto the
        # callers to check for this condition and act accordingly.
        return jobrun

    def get_log_entries(self, jobsession_id, page_size=1000, page_start_index=0):

        resp = self.spp_session.get(restype='log', path='job',
                                    params={'pageSize': page_size, 'pageStartIndex': page_start_index,
                                            'sort': '[{"property":"logTime","direction":"ASC"}]',
                                            'filter': '[{"property":"jobsessionId","value":"%s"}]' % jobsession_id})

        return resp['logs']

    def monitor(self, jobStatus, job_id, job_name, timeout=0, number_of_jobs = None):
        jobIsActive = False
        current_time = time.time()

        while (True):
            if (jobIsActive and ((jobStatus == "PENDING") or (jobStatus == "WAITING") or (jobStatus == "RESOURCE ACTIVE"))):
                break
            if (jobStatus == "IDLE"):
                break
            if (not jobIsActive and ((jobStatus != "PENDING") or (jobStatus == "WAITING"))):
                jobIsActive = True

            #print(" Sleeping for 30 seconds...")
            time.sleep(30)
            jobStatus = self.status(job_id)['currentStatus']
            # print(jobStatus)
            job_time_taken = time.time()
            time_elasped = int(job_time_taken - current_time)
            if(timeout != 0) and (time_elasped > timeout) and jobIsActive:
                try:
                    canceldatapayload = {"catalogCompletedObjects": False}
                    self.spp_session.post(
                        path='api/endeavour/job/'+job_id+'?action=cancel&actionname=cancel', data=canceldatapayload)
                    sessionId = self.getjob(job_name)['lastrun']['sessionId']
                    sessionStatus = self.spp_session.get(
                        path='api/endeavour/jobsession/' + sessionId)['status']
                    return jobStatus, sessionStatus
                except:
                    raise Exception(
                        'Job exceeded maximum time limit and hence job is cancelling')

        if number_of_jobs:
            job = self.getjob(job_name)
            job_sessions = self.spp_session.get(
                path='api/endeavour/jobsession?filter=[{"property":"jobId","value":' + job['id'] + ',"op":"="}]&sort=[{"property":"start","direction":"ASC"}]'
            )['sessions'][:number_of_jobs]
            sessionStatus = 'COMPLETED'
            for j in job_sessions:
                if j['status'] in ['PARTIAL', 'FAILED']:
                    sessionStatus = j['status']
        else:
            sessionId = self.getjob(job_name)['lastrun']['sessionId']
            sessionStatus = self.spp_session.get(
                path='api/endeavour/jobsession/' + sessionId)['status']

            # downloading job log if status is PARTIAL or FAILED
            try:

                if sessionStatus in ['PARTIAL', 'FAILED']:
                    diagapi = DiagAPI(spp_session=self.spp_session)
                    jobsessapi = JobSessionAPI(spp_session=self.spp_session)
                    jobsession = jobsessapi.get_jobsession(sessionId)
                    diag_href = jobsession['links']['diagnostics']['href']

                    outfile = diagapi.get_joblogs(
                        url=diag_href, outfile="joblog_{}.zip".format(sessionId))
                    logging.info(
                        "Job log has been downloaded file name is : {} ".format(outfile))
                    logging.info("Uploading log file to Prolog server")
                    upload_url, rc = system.run_shell_command(
                        "vsdiag upload {}".format(outfile))
                    logging.info(
                        "Download and Upload compelete, the url is :{}".format(rc))
            except:
                traceback.print_exc()

        return jobStatus, sessionStatus


class UserIdentityAPI(SppAPI):
    def __init__(self, spp_session):
        super(UserIdentityAPI, self).__init__(spp_session, 'identityuser')

    def create(self, data):
        return self.post(data=data)


class AppserverAPI(SppAPI):
    def __init__(self, spp_session):
        super(AppserverAPI, self).__init__(spp_session, 'appserver')


class VsphereAPI(SppAPI):
    def __init__(self, spp_session):
        super(VsphereAPI, self).__init__(spp_session, 'vsphere')


class ResProviderAPI(SppAPI):
    # Credential info is passed in different field names so we need to maintain
    # the mapping.
    user_field_name_map = {"appserver": "osuser",
                           "purestorage": "user", "emcvnx": "user"}

    # Resource type doesn't always correspond to API so we need a map.
    res_api_map = {"purestorage": "pure"}

    def __init__(self, spp_session, restype):
        super(ResProviderAPI, self).__init__(spp_session,
                                             ResProviderAPI.res_api_map.get(restype, restype))

    def register(self, name, host, osuser_identity, appType=None, osType=None, catalog=True, ssl=True, vsphere_id=None):
        osuser_field = ResProviderAPI.user_field_name_map.get(
            self.restype, 'user')
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


class AssociationAPI(SppAPI):
    def __init__(self, spp_session):
        super(AssociationAPI, self).__init__(spp_session, 'association')

    def get_using_resources(self, restype, resid):
        return self.get(path="resource/%s/%s" % (restype, resid), params={"action": "listUsingResources"})


class LogAPI(SppAPI):
    def __init__(self, spp_session):
        super(LogAPI, self).__init__(spp_session, 'log')

    def download_logs(self, outfile=None):
        return self.stream_get(path="download/diagnostics", outfile=outfile)

    def download_joblogs(self, jobname):

        spp_sess = SppSession()
        all_sessions = SppAPI().get(
            path='api/endeavour/jobsession')['sessions']
        for sess in all_sessions:
            if sess['jobName'] == job_name:
                sess_id = sess['id']
                diag_href = sess['links']['diagnostics']['href']

                resp_diag = (spp_sess.diag_get(url=diag_href)).content

        return resp_diag


class OracleAPI(SppAPI):
    def __init__(self, spp_session):
        super(OracleAPI, self).__init__(spp_session, 'oracle')

    def get_instances(self):
        return self.get(path="/instance?from=hlo")

    def get_instance(self, instances, name):
        for inst in instances:
            if inst['name'] == name:
                return inst

    def get_databases_in_instance(self, instanceid):
        return self.get(path="instance/%s/database?from=hlo" % instanceid)

    def get_database_by_name(self, databases, db_name):
        for db in databases:
            if db['name'] == db_name:
                return db

    def get_latest_database_version(self, instanceid, databaseid):
        version = self.get(
            path='instance/%s/database/%s/version?from=recovery&sort=[\
                {"property": "protectionTime", "direction": "DESC"}\
            ]' % (instanceid, databaseid)
        )

        return version

    def get_database_copy_versions(self, instanceid, databaseid):
        return self.get(path="oraclehome/%s/database/%s" % (instanceid, databaseid) + "/version")

    def apply_options(
        self, resource_href, database_id, metadataPath, activation_time
    ):

        applyoptionsdata = {
            "resources": [
                {
                    "href": resource_href,
                    "id": database_id,
                    "metadataPath": metadataPath
                }
            ],
            "subtype": "oracle",
            "options": {
                "maxParallelStreams": 1,
                "dbFilesForParallelStreams": "SINGLE_FILE",
                "backupPreferredNode": "",
                "logbackup": {
                    "purgePrimaryLogs": False,
                    "primaryLogRetentionDays": 3,
                    "performlogbackup": True,
                    "rpo": {
                        "frequency": 5,
                        "frequencyType": "MINUTE",
                        "triggerTime": "6:00:00 AM",
                        "metadata": {
                            "activateDate": activation_time
                        }
                    }
                }
            }
        }
        return self.spp_session.post(data=applyoptionsdata, path='ngp/application?action=applyOptions')

    def adhoc_backup(self, sla_name, resources):
        data = {
            "slaPolicyName": sla_name,
            "subtype": "oracle",
            "resource": resources
        }
        return self.spp_session.post(data=data, path='ngp/application?action=adhoc')


class FileSystemAPI(SppAPI):
    def __init__(self, spp_session):
        super(FileSystemAPI, self).__init__(spp_session, 'file')

    def get_disks_in_instance(self, instanceid):
        return self.get(path="instance/%s/database?from=hlo" % instanceid)

    def get_disk_by_name(self, disks, disk_name):
        for d in disks:
            if d['name'] == disk_name:
                return d

    def apply_options(self, disk1_info, disk2_info, files_excluded):
        data = {
            "resources": [{
                    "href": disk1_info['links']['self']['href'],
                    "id": disk1_info['id'],
                    "metadataPath": disk1_info['metadataPath']
                },
                {
                    "href": disk2_info['links']['self']['href'],
                    "id": disk2_info['id'],
                    "metadataPath": disk2_info['metadataPath']
                }
            ],
            "subtype": "file",
            "options": {
                "maxParallelStreams": 1,
                "dbFilesForParallelStreams": "SINGLE_FILE",
                "backupPreferredNode": "",
                "agentOptions": {
                    "exclusions": {
                        "enableExclusions": True,
                        "exclusionPaths": [
                            files_excluded
                        ]
                    }
                },
                "enableFH": True,
                "FHExcludedPath": files_excluded,
                "logbackup": {}
            }
        }

        return self.spp_session.post(data=data, path='ngp/application?action=applyOptions')


class VmwareAPI(SppAPI):
    def __init__(self, spp_session):
        super(VmwareAPI, self).__init__(spp_session, 'spphv')

    def get_instances(self):
        return self.get(path="/vm")

    def get_vminstance(self, vmwares, name):
        for vm in vmwares['vms']:
            if vm['name'] == name:
                return vm

    def get_databases_in_instance(self, instanceid):
        return self.get(path="oraclehome/%s/database" % instanceid)

    def get_database_copy_versions(self, instanceid, databaseid):
        return self.get(path="oraclehome/%s/database/%s" % (instanceid, databaseid) + "/version")

    def apply_options(self, subtype, resource_href, vm_id, metadataPath, username, password):

        applyoptionsdata = {
            "subtype": subtype,
            "version": "1.0",
            "resources": [{
                "href": resource_href,
                "id": vm_id,
                "metadataPath": metadataPath}],
            "options": {
                "makeApplicationConsistent": True,
                "snapshotRetries": 1,
                "fullcopymethod": "vadp",
                "proxySelection": "",
                "skipReadonlyDS": True,
                "skipIAMounts": True,
                "enableFH": True,
                "enableLogTruncate": False,
                "username": username,
                "password": password
            }
        }

        return self.spp_session.post(data=applyoptionsdata, path='ngp/hypervisor?action=applyOptions')

    def adhoc_backup(self, sla_name, resources):
        data = {
            "slaPolicyName": sla_name,
            "subtype": "vmware",
            "resource": resources
        }
        return self.spp_session.post(data=data, path='ngp/hypervisor?action=adhoc')


class HypervAPI(SppAPI):
    def __init__(self, spp_session):
        super(HypervAPI, self).__init__(spp_session, 'spphv')

    def get_instances(self):
        return self.get(path="/vm")

    def get_hypervinstance(self, hypervs, name):
        for hyperv in hypervs['vms']:
            if hyperv['name'] == name:
                return hyperv

    def get_hyperv_from_folder(self, hypervs, name):
        for hyperv in hypervs['contents']:
            if hyperv['name'] == name:
                return hyperv

    def get_databases_in_instance(self, instanceid):
        return self.get(path="oraclehome/%s/database" % instanceid)

    def get_database_copy_versions(self, instanceid, databaseid):
        return self.get(path="oraclehome/%s/database/%s" % (instanceid, databaseid) + "/version")

    def apply_options(self, subtype, resource_href, vm_id, metadataPath, username, password):

        applyoptionsdata = {
            "subtype": subtype,
            "version": "1.0",
            "resources": [{
                "href": resource_href,
                "id": vm_id,
                "metadataPath": metadataPath}],
            "options": {
                "makeApplicationConsistent": True,
                "snapshotRetries": 2,
                "fullcopymethod": "vadp",
                "proxySelection": "",
                "skipReadonlyDS": True,
                "skipIAMounts": True,
                "enableFH": True,
                "enableLogTruncate": False,
                "username": username,
                "password": password
            }
        }

        return self.spp_session.post(data=applyoptionsdata, path='ngp/hypervisor?action=applyOptions')

    def adhoc_backup(self, sla_name, resources):
        data = {
            "slaPolicyName": sla_name,
            "subtype": "hyperv",
            "resource": resources
        }
        return self.spp_session.post(data=data, path='ngp/hypervisor?action=adhoc')


class SqlAPI(SppAPI):
    def __init__(self, spp_session):
        super(SqlAPI, self).__init__(spp_session, 'sql')

    def get_instances(self):
        return self.get(path="/instance?from=hlo")

    def get_instance(self, instances, name):
        for inst in instances:
            if inst['name'] == name:
                return inst

    def get_databases_in_instance(self, instanceid):
        return self.get(path="instance/%s/database" % instanceid)

    def get_database(self, databases, name):
        for db in databases:
            if db['name'] == name:
                return db

    def get_database_copy_versions(self, instanceid, databaseid):
        return self.get(path="instance/%s/database/%s" % (instanceid, databaseid) + '/version?from=recovery&sort=[{"property": "protectionTime", "direction": "DESC"}]')

    def apply_options(self, resource_href, db_id, metadataPath, log_backup):

        applyoptionsdata = {
            "resources": [
                {
                    "href": resource_href,
                    "id": db_id,
                    "metadataPath": metadataPath
                }
            ],
            "subtype": "sql",
            "options": {
                "maxParallelStreams": 1,
                "dbFilesForParallelStreams": "SINGLE_FILE",
                "backupPreferredNode": "",
                "logbackup": log_backup
            }
        }

        return self.spp_session.post(data=applyoptionsdata, path='ngp/application?action=applyOptions')

    def adhoc_backup(self, sla_name, resources):
        data = {
            "slaPolicyName": sla_name,
            "subtype": "sql",
            "resource": resources
        }
        return self.spp_session.post(data=data, path='ngp/application?action=adhoc')


class slaAPI(SppAPI):
    def __init__(self, spp_session):
        super(slaAPI, self).__init__(spp_session, 'sppsla')

    def get_slas(self):
        return self.spp_session.get(path="api/spec/storageprofile")

    def getsla(self, slas, name):
        for sla in slas:
            #slaname = sla['name']
            if sla['name'] == name:
                return sla

    def createSla(self, name, site="Primary"):
        slainfo = {"name": name,
                   "version": "1.0",
                   "spec": {"simple": True,
                            "subpolicy": [{"type": "REPLICATION",
                                           "software": True, "retention": {"age": 15},
                                           "trigger": {},
                                           "site": site}]}}
        resp = self.post(data=slainfo)
        return resp

    def create_replication_sla(self, name, sites):
        slainfo = {
            "name": name,
            "version": "1.0",
            "spec": {
                "simple": True,
                "subpolicy": [
                    {
                        "type": "REPLICATION",
                        "software": True,
                        "retention": {"age": 15},
                        "useEncryption": False,
                        "trigger": {},
                        "site": sites[0]
                    },
                    {
                        "type": "REPLICATION",
                        "retention": {},
                        "useEncryption": False,
                        "software": False,
                        "trigger": {},
                        "site": sites[1]
                    }
                ]
            }
        }
        resp = self.post(data=slainfo)
        return resp

    def create_ec2_sla(self, name, snapshot_prefix=""):
        slainfo = {
            "name": name,
            "version": "1.0",
            "type": "snapshot",
            "spec": {
                "simple": True,
                "subpolicy": [
                    {
                        "description": "Storage Snapshot",
                        "label": snapshot_prefix,
                        "name": "Storage Snapshot",
                        "type": "SNAPSHOT",
                        "retention": {
                            "age": 15
                        },
                        "trigger": {},
                    }
                ]
            }
        }
        resp = self.post(data=slainfo)
        return resp

    def edit_sla(self, id, data):
        response = self.put(
            path=id,
            data=data
        )

        return response

    def create_cloud_sla(self, name, cloud_server, site="Primary"):
        slainfo = {
            "name": name,
            "version": "1.0",
            "spec": {
                "simple": True,
                "subpolicy": [{
                    "type": "REPLICATION",
                    "software": True,
                    "retention": {
                            "age": 15
                    },
                    "useEncryption": False,
                    "trigger": {},
                    "site": site
                },
                    {
                        "type": "SPPOFFLOAD",
                        "retention": {},
                        "trigger": {},
                        "source": "backup",
                        "target": {
                            "href": cloud_server['links']['self']['href'],
                            "resourceType": cloud_server['provider'],
                            "id": cloud_server['id'],
                            "wormProtected": False
                        }
                },
                    {
                        "type": "SPPARCHIVE",
                        "retention": {
                            "age": 90
                        },
                        "trigger": {},
                        "source": "backup",
                        "target": {
                            "href": cloud_server['links']['self']['href'],
                            "resourceType": cloud_server['provider'],
                            "id": "4",
                            "wormProtected": False
                        }
                }
                ]
            }
        }
        resp = self.post(data=slainfo)
        return resp

    def assign_sla(self, instances, sla=None, subtype='vmware', target='application'):
        # Added target variable to make the function more generic (ex. 'hypervisor' or 'application')
        # without breaking backwards compatibility thanks to target defaulting to 'application'.

        # Added functionality to add multiple instances to apply policies to them
        if not isinstance(instances, list):
            instances = [instances]

        # Get resources from instance
        temp_resources = []
        for instance in instances:
            temp_resources.append({
                "href": instance['links']['self']['href'],
                "id": instance['id'],
                "metadataPath": instance['metadataPath']})

        applySLAPolicies = {"subtype": subtype,
                            "version": "1.0",
                            "resources": temp_resources,
                            "slapolicies": [] if sla == None else [{
                                "href": sla['links']['self']['href'],
                                "id":sla['id'],
                                "name":sla['name']}]}
        return self.spp_session.post(data=applySLAPolicies, path='ngp/'+target+'?action=applySLAPolicies')

    def assign_hypervisorsla(self, instance_href, instance_id, instance_metadataPath, sla_href, sla_id, sla_name, subtype):
        applySLAPolicies = {"subtype": subtype,
                            "version": "1.0",
                            "resources": [{
                                "href": instance_href,
                                "id": instance_id,
                                "metadataPath": instance_metadataPath
                            }],
                            "slapolicies": [{
                                "href": sla_href,
                                "id": sla_id,
                                "name": sla_name}]}
        return self.spp_session.post(data=applySLAPolicies, path='ngp/hypervisor?action=applySLAPolicies')


class ScriptAPI(SppAPI):
    def __init__(self, spp_session):
        super(ScriptAPI, self).__init__(spp_session, 'api/script')

    def upload_script(self, data, files):
        headers = {
            'X-Endeavour-sessionid': self.spp_session.sessionid, 'Accept': '*/*'}
        url = build_url(self.spp_session.api_url, 'api/script')
        resp = requests.post(url, headers=headers,
                             data=data, files=files, verify=False)
        return resp

    def remove_script(self, script_id):
        headers = {
            'X-Endeavour-sessionid': self.spp_session.sessionid, 'Accept': '*/*'}
        url = build_url(self.spp_session.api_url, 'api/script/')
        url = url + script_id
        resp = requests.delete(url, headers=headers, verify=False)

        return resp


class restoreAPI(SppAPI):
    def __init__(self, spp_session):
        super(restoreAPI, self).__init__(spp_session, 'ngp/application')

    def restore(self, subType, database_href, database_version, database_torestore, database_id, restoreName):
        restore = {"subType": subType,
                   "script":
                   {"preGuest": None,
                    "postGuest": None,
                    "continueScriptsOnError": False},
                   "spec":
                   {"source": [{"href": database_href,
                                "resourceType": "database",
                                "include": True,
                                "version": {"href": database_version,
                                            "metadata": {"useLatest": True}},
                                "metadata":
                                {"name": database_torestore},
                                "id": database_id}],
                       "subpolicy":
                       [{"type": "restore",
                         "mode": "test",
                         "destination":
                         {"mapdatabase": {database_href:
                                          {"name": restoreName,
                                           "paths": []}}},
                           "option":
                           {"autocleanup": False,
                            "allowsessoverwrite": False,
                            "continueonerror": False,
                            "applicationOption":
                            {"overwriteExistingDb": False,
                             "maxParallelStreams": 1,
                             "initParams": "source"}},
                           "source":
                           {"copy":
                            {"site": {"href": "https://172.20.47.47:443/api/site/1000"}}}}],
                       "view": "applicationview"}}

        # return sppAPI(session, 'ngp/application').post(path='?action=restore', data=restore)['response']
        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_sql_test(self, database_href, version_href, version_copy_href, protection_time, database_name, restore_instance_version,
                         restore_instance_id, database_id, database_restore_name="", post_guest=None, recoveryType='recovery'):
        restore = {
                  "subType": "sql",
                  "script": {
                    "preGuest": None,
                    "postGuest": post_guest,
                    "continueScriptsOnError": False
                  },
                  "spec": {
                    "source": [{
                      "href": database_href,
                      "resourceType": "database",
                      "include": True,
                      "version": {
                        "href": version_href,
                        "copy": {
                          "href": version_copy_href
                        },
                        "metadata": {
                          "useLatest": False,
                          "protectionTime": protection_time
                        }
                      },
                      "metadata": {
                        "name": database_name,
                        "osType": "windows",
                        "instanceVersion": restore_instance_version,
                        "instanceId": restore_instance_id,
                        "useLatest": False
                      },
                      "id": database_id
                    }],
                    "subpolicy": [{
                      "type": "restore",
                      "mode": "test",
                      "destination": {
                        "mapdatabase": {
                          database_href: {
                            "name": database_restore_name,
                            "paths": [{
                              "source": "C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\DATA",
                              "destination": ""
                            }]
                          }
                        },
                        "targetLocation": "original"
                      },
                      "option": {
                        "autocleanup": True,
                        "allowsessoverwrite": True,
                        "continueonerror": True,
                        "applicationOption": {
                          "overwriteExistingDb": False,
                          "recoveryType": recoveryType
                        }
                      },
                      "source": None
                    }],
                    "view": "applicationview"
                  }
                }

        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_sql_production(self, database_href, version_href, version_copy_href, protection_time, database_name,
                         restore_instance_version, restore_instance_id, database_id, destination_path1, destination_path2, database_restore_name="", post_guest=None):

        restore = {
            "subType": "sql",
            "script": {
                "preGuest": None,
                "postGuest": post_guest,
                "continueScriptsOnError": False
            },
            "spec": {
                "source": [{
                    "href": database_href,
                    "resourceType": "database",
                    "include": True,
                    "version": {
                        "href": version_href,
                        "copy": {
                            "href": version_copy_href
                        },
                        "metadata": {
                            "useLatest": False,
                            "protectionTime": protection_time
                        }
                    },
                    "metadata": {
                        "name": database_name,
                        "osType": "windows",
                        "instanceVersion": restore_instance_version,
                        "instanceId": restore_instance_id,
                        "useLatest": False
                    },
                    "id": database_id
                }],
                "subpolicy": [{
                    "type": "restore",
                    "mode": "production",
                    "destination": {
                        "mapdatabase": {
                            database_href: {
                                "name": database_restore_name,
                                "paths": [
                                    {
                                        "source": "A:\\Program Files\\Microsoft SQL Server\\MSSQL13.MSSQLSERVER\\MSSQL\\Data",
                                        "destination": destination_path1
                                    },
                                    {
                                        "source": "L:\\Program Files\\Microsoft SQL Server\\MSSQL13.MSSQLSERVER\\MSSQL\\Logs",
                                        "destination": destination_path2
                                    }
                                ]
                            }
                        },
                        "targetLocation": "original"
                    },
                    "option": {
                        "autocleanup": True,
                        "allowsessoverwrite": True,
                        "continueonerror": True,
                        "applicationOption": {
                            "overwriteExistingDb": False,
                            "recoveryType": "recovery",
                            "maxParallelStreams": 1
                        }
                    },
                    "source": None
                }],
                "view": "applicationview"
            }
        }

        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_sql_instant_access(self, database_href, version_href, version_copy_href, protection_time, database_name,
                         restore_instance_version, restore_instance_id, database_id):
        restore = {
                  "subType": "sql",
                  "script": {
                    "preGuest": None,
                    "postGuest": None,
                    "continueScriptsOnError": False
                  },
                  "spec": {
                    "source": [{
                      "href": database_href,
                      "resourceType": "database",
                      "include": True,
                      "version": {
                        "href": version_href,
                        "copy": {
                          "href": version_copy_href
                        },
                        "metadata": {
                          "useLatest": False,
                          "protectionTime": protection_time
                        }
                      },
                      "metadata": {
                        "name": database_name,
                        "osType": "windows",
                        "instanceVersion": restore_instance_version,
                        "instanceId": restore_instance_id,
                        "useLatest": False
                      },
                      "id": database_id
                    }],
                    "subpolicy": [{
                      "type": "IA",
                      "mode": "IA",
                      "destination": {
                        "targetLocation": "original"
                      },
                      "option": {
                        "autocleanup": True,
                        "allowsessoverwrite": True,
                        "continueonerror": True,
                      },
                      "source": None
                    }],
                    "view": "applicationview"
                  }
        }

        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_sql_pit_test(self, database_href, database_name, restore_instance_version, restore_instance_id,
                             database_id, PIT_time, site_href, database_restore_name="", post_guest=None):
        restore = {
            "subType": "sql",
            "script": {
                "preGuest": None,
                "postGuest": post_guest,
                "continueScriptsOnError": False

            },
            "spec": {
                "source": [
                    {
                        "href": database_href,
                        "resourceType": "database",
                        "include": True,
                        "version": None,
                        "metadata": {
                            "name": database_name,
                            "osType": "windows",
                            "instanceVersion": restore_instance_version,
                            "instanceId": restore_instance_id,
                            "useLatest": True

                        },
                        "id": database_id,
                        "pointInTime": PIT_time

                    }

                ],
                "subpolicy": [
                    {
                        "type": "restore",
                        "mode": "test",
                        "destination": {
                            "mapdatabase": {
                                database_href: {
                                    "name": database_restore_name,
                                    "paths": [
                                        {
                                            "source": "A:\\Program Files\\Microsoft SQL Server\\MSSQL13.MSSQLSERVER\\MSSQL\\Data",
                                            "destination": "",
                                            "mountPoint": "a:",
                                            "fileType": "DATA"

                                        },
                                        {
                                            "source": "L:\\Program Files\\Microsoft SQL Server\\MSSQL13.MSSQLSERVER\\MSSQL\\Logs",
                                            "destination": "",
                                            "mountPoint": "l:",
                                            "fileType": "LOGS"

                                        }

                                    ]

                                }

                            },
                            "targetLocation": "original"

                        },
                        "option": {
                            "autocleanup": True,
                            "allowsessoverwrite": True,
                            "continueonerror": True,
                            "applicationOption": {
                                "overwriteExistingDb": False,
                                "recoveryType": "pitrecovery"

                            }

                        },
                        "source": {
                            "copy": {
                                "site": {
                                    "href": site_href

                                }

                            }

                        }

                    }

                ],
                "view": "applicationview"

            }
        }

        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']


    def restore_oracle(self, database_href, version_href, version_copy_href, protection_time,
                       database_name, restore_instance_version, restore_instance_id, database_id,
                       database_restore_name, restore_mode='test', database_paths=[]):
        restore = {
            "subType": "oracle",
            "script": {
                "preGuest": None,
                "postGuest": None,
                "continueScriptsOnError": False
            },
            "spec": {
                "source": [{
                    "href": database_href,
                    "resourceType": "database",
                    "include": True,
                    "version": {
                        "href": version_href,
                        "copy": {
                            "href": version_copy_href
                        },
                        "metadata": {
                            "useLatest": False,
                            "protectionTime": protection_time
                        }
                    },
                    "metadata": {
                        "name": database_name,
                        "instanceVersion": restore_instance_version,
                        "instanceId": restore_instance_id,
                        "useLatest": False
                    },
                    "id": database_id
                }],
                "subpolicy": [{
                    "type": "restore",
                    "mode": restore_mode,
                    "destination": {
                        "mapdatabase": {
                            database_href: {
                                "name": database_restore_name,
                                "paths": database_paths
                            }
                        },
                        "targetLocation": "original"
                    },
                    "option": {
                        "autocleanup": True,
                        "allowsessoverwrite": True,
                        "continueonerror": True,
                        "applicationOption": {
                            "overwriteExistingDb": False,
                            "recoveryType": "recovery",
                            "initParams": "source"
                        }
                    },
                    "source": None
                }],
                "view": "applicationview"
            }
        }

        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_instant_accesss_oracle(self, database_href, version_href, version_copy_href, protection_time,
                       database_name, restore_instance_version, restore_instance_id, database_id):
        restore = {
            "subType": "oracle",
            "script": {
                "preGuest": None,
                "postGuest": None,
                "continueScriptsOnError": False
            },
            "spec": {
                "source": [{
                    "href": database_href,
                    "resourceType": "database",
                    "include": True,
                    "version": {
                        "href": version_href,
                        "copy": {
                            "href": version_copy_href
                        },
                        "metadata": {
                            "useLatest": False,
                            "protectionTime": protection_time
                        }
                    },
                    "metadata": {
                        "name": database_name,
                        "instanceVersion": restore_instance_version,
                        "instanceId": restore_instance_id,
                        "useLatest": False
                    },
                    "id": database_id
                }],
                "subpolicy": [{
                    "type": "IA",
                    "mode": "IA",
                    "destination": {
                        "targetLocation": "original"
                    },
                    "option": {
                        "autocleanup": True,
                        "allowsessoverwrite": True,
                        "continueonerror": True,
                    },
                    "source": None
                }],
                "view": "applicationview"
            }
        }

        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_oracle_pit_test(self, database_href, database_name, restore_instance_version, restore_instance_id,
                                database_id, PIT_time, site_href, database_restore_name, database_paths):
        restore = {
            "subType": "oracle",
            "script": {
                "preGuest": None,
                "postGuest": None,
                "continueScriptsOnError": False
            },
            "spec": {
                "source": [{
                    "href": database_href,
                    "resourceType": "database",
                    "include": True,
                    "version": None,
                    "metadata": {
                        "name": database_name,
                        "instanceVersion": restore_instance_version,
                        "instanceId": restore_instance_id,
                        "useLatest": True
                    },
                    "id": database_id,
                    "pointInTime": PIT_time
                }],
                "subpolicy": [{
                    "type": "restore",
                    "mode": "test",
                    "destination": {
                        "mapdatabase": {
                            database_href: {
                                "name": database_restore_name,
                                "paths": database_paths
                            }
                        },
                        "targetLocation": "original"
                    },
                    "option": {
                        "autocleanup": True,
                        "allowsessoverwrite": True,
                        "continueonerror": True,
                        "applicationOption": {
                            "overwriteExistingDb": False,
                            "recoveryType": "recovery",
                            "initParams": "source"
                        },
                    },
                    "source": {
                        "copy": {
                            "site": {
                                "href": site_href
                            }
                        }
                    }
                }],
                "view": "applicationview"
            }
        }

        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_vm_clone(self, subType, vm_href, vm_name, vm_id, vm_version, vm_clone_name, streaming=True):
        restore = {
            "subType": subType,
            "spec": {
                "source": [
                    {
                        "href": vm_href,
                        "metadata": {
                            "name": vm_name
                        },
                        "resourceType": "vm",
                        "id": vm_id,
                        "include": True,
                        "version": {
                            "href": vm_version,
                            "metadata": {
                                "useLatest": True,
                                "name": "Use Latest"
                            }
                        }
                    }
                ],
                "subpolicy": [
                    {
                        "type": "IV",
                        "destination": {
                            "systemDefined": True,
                            "mapvirtualnetwork": {},
                            "mapRRPdatastore": {},
                            "mapsubnet": {},
                            "mapvm": {
                                vm_href: {
                                    "name": vm_clone_name
                                }
                            }
                        },
                        "source": None,
                        "option": {
                            "poweron": False,
                            "allowvmoverwrite": False,
                            "continueonerror": True,
                            "autocleanup": True,
                            "allowsessoverwrite": True,
                            "restorevmtag": None,
                            "mode": "clone",
                            "vmscripts": False,
                            "protocolpriority": "iSCSI",
                            "IR": False,
                            "streaming": streaming
                        }
                    }
                ]
            },
            "script": {
                "preGuest": None,
                "postGuest": None,
                "continueScriptsOnError": False
            }
        }
        
        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restore')['response']

    def restoreHyperV(self, subType, hyperv_href, hyperv_name, hyperv_id, hyperv_version, site_href, vm_overwrite=False, poweron=False):
        restore = {"subType": subType,
                   "spec": {
                       "source": [{
                           "href": hyperv_href,
                           "metadata": {
                               "name": hyperv_name
                           },
                           "resourceType": "vm",
                           "id": hyperv_id,
                           "include": True,
                           "version": {
                               "href": hyperv_version,
                               "metadata": {
                                   "useLatest": True,
                                   "name": "Use Latest"}}}],
                       "subpolicy": [{
                           "type": "IV",
                           "destination": {
                               "systemDefined": True},
                           "source": {"copy": {"site": {
                               "href": site_href
                           }
                           }
                           },
                           "option": {
                               "protocolpriority": "iSCSI",
                               "poweron": poweron,
                               "continueonerror": True,
                               "autocleanup": True,
                               "allowsessoverwrite": True,
                               "allowvmoverwrite": vm_overwrite,
                               "mode": "test",
                               "vmscripts": False,
                               "restorevmtag": True,
                               "update_vmx": True}}]},
                   "script": {}
                   }
        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restore')['response']
    

    def restore_vmware_detailed(self, subType, hyperv_href, hyperv_name, hyperv_id, hyperv_version, 
                                copy_href, vm_overwrite=False, system_ip=True):
        restore = {
                    "subType": subType,
                    "spec": {
                        "source": [{
                            "href": hyperv_href,
                            "metadata": {
                                "name": hyperv_name
                            },
                            "resourceType": "vm",
                            "id": hyperv_id,
                            "include": True,
                            "version": {
                                "href": hyperv_version,
                                "copy": {
                                    "href": copy_href
                                },
                                "metadata": {
                                    "useLatest": False
                                }
                            }
                        }],
                        "subpolicy": [{
                            "type": "IV",
                            "destination": {
                            "systemDefined": system_ip
                            },
                            "source": None,
                            "option": {
                                "protocolpriority": "iSCSI",
                                "poweron": False,
                                "continueonerror": True,
                                "autocleanup": True,
                                "allowsessoverwrite": True,
                                "allowvmoverwrite": vm_overwrite,
                                "mode": "test",
                                "vmscripts": False,
                                "restorevmtag": True,
                                "update_vmx": True
                            }
                        }]
                        },
                        "script": {}
                    }
        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restore')['response']


    def restoreVMCloneAlteranteHost(self, subType, hyperv_href, hyperv_name,
                                    hyperv_id, hyperv_latestversion, host_name, host_resource_type,
                                    host_href, map_virtual_ntwk_link, network_href, vol_href, map_RRP, vm_clone_name):

        restore = {
            "subType": "vmware",
            "spec": {
                "source": [
                    {
                        "href": hyperv_href,
                        "metadata": {
                            "name": hyperv_name},
                        "resourceType": subType,
                        "id": hyperv_id,
                        "include": True,
                        "version": {
                            "href": hyperv_latestversion,
                            "metadata": {
                                "useLatest": True,
                                "name": "Use Latest"}}}],
                "subpolicy": [
                    {
                        "type": "IV",
                        "destination": {
                            "target": {
                                "name": host_name,
                                "resourceType": host_resource_type,
                                "href": host_href},
                            "mapvirtualnetwork": {
                                map_virtual_ntwk_link: {
                                    "recovery": network_href,
                                    "test": network_href}},
                            "mapRRPdatastore": {
                                map_RRP: vol_href},
                            "mapsubnet": {
                                "systemDefined": True
                            },
                            "mapvm": {
                                hyperv_href: {
                                    "name": vm_clone_name
                                }
                            }
                        },
                        "source": None,
                        "option": {
                            "poweron": False,
                            "allowvmoverwrite": False,
                            "continueonerror": True,
                            "autocleanup": True,
                            "allowsessoverwrite": True,
                            "restorevmtag": True,
                            "update_vmx": True,
                            "mode": "clone",
                            "vmscripts": False,
                            "protocolpriority": "iSCSI",
                            "streaming": True}}]},
            "script": {
                "preGuest": None,
                "postGuest": None,
                "continueScriptsOnError": False}}

        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restore')['response']

    def restore_Old_HyperV(self, subType, hyperv_href, hyperv_name, hyperv_id, hyperv_version, site_href):
        restore = {"subType": subType,
                   "spec":
                   {"source":
                    [{
                        "href": hyperv_href,
                        "metadata": {
                            "name": hyperv_name
                        },
                        "resourceType": "vm",
                        "id": hyperv_id,
                        "include": True,
                        "version": {
                            "href": hyperv_version,
                            "metadata": {
                                "useLatest": True,
                                "name": "Use Latest"
                            }}}],
                       "subpolicy": [{
                           "type": "IV",
                           "destination": {
                               "systemDefined": True,
                               "mapvirtualnetwork": {},
                               "mapRRPdatastore": {},
                               "mapsubnet": {}},
                           "source": {
                               "copy": {
                                   "site": {
                                       "href": site_href
                                   }}},
                           "option": {
                               "poweron": False,
                               "allowvmoverwrite": False,
                               "continueonerror": True,
                               "autocleanup": True,
                               "allowsessoverwrite": True,
                               "restorevmtag": True,
                               "update_vmx": True,
                               "mode": "test",
                               "vmscripts": False,
                               "protocolpriority": "iSCSI"
                           }}]},
                   "script": {
                       "preGuest": None,
                       "postGuest": None,
                       "continueScriptsOnError": False
                   }}

        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restore')['response']

    def restore_multiple_vm(self, vm_info_list):
        restore = {
            "subType": "vmware",
            "spec": {
                "source": vm_info_list,
                "subpolicy": [{
                    "type": "IV",
                    "destination": {
                        "systemDefined": True
                    },
                    "source": {
                        "copy": {
                            "site": {
                                "href": None
                            },
                            "isOffload": None
                        }
                    },
                    "option": {
                        "protocolpriority": "iSCSI",
                        "poweron": False,
                        "continueonerror": True,
                        "autocleanup": True,
                        "allowsessoverwrite": True,
                        "mode": "test",
                        "vmscripts": False,
                        "restorevmtag": True,
                        "update_vmx": True
                    }
                }]
            },
            "script": {}
        }
        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restore')['response']

    def fileRestoreVM(self, sourcehref, resourcetype, copylink, copyversion):
        restore = {"spec": {
            "view": "",
            "source": [{
                    "href": sourcehref,
                    "resourceType": resourcetype,
                    "include": True,
                    "version": {
                        "copy": {
                            "href": copylink
                        },
                        "href": copyversion
                    }
            }],
            "subpolicy": [{
                "option": {
                    "overwriteExistingFile": True,
                    "filePath": ""
                }
            }]
        }
        }
        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restorefile')['response']

    def fileRestoreVMAltLoc(self, sourcehref, resourcetype, copylink, copyversion, vm_href, target_directory):
        restore = {"spec": {
            "view": "",
            "source": [{
                    "href": sourcehref,
                    "resourceType": resourcetype,
                    "include": True,
                    "version": {
                        "copy": {
                            "href": copylink
                        },
                        "href": copyversion
                    }
            }],
            "subpolicy": [{
                "option": {
                    "overwriteExistingFile": True,
                    "filePath": target_directory
                },
                "destination": {
                    "target": {
                        "href": vm_href,
                        "resourceType": "vm"
                    }
                }
            }]
        }
        }

        return self.spp_session.post(data=restore, path='ngp/hypervisor?action=restorefile')['response']

    def restoreLog(self, subType, database_href, database_version, database_torestore, database_id, restoreName, restoreTime):
        restore = {"subType": subType,
                   "script":
                   {"preGuest": None,
                    "postGuest": None,
                    "continueScriptsOnError": False},
                   "spec":
                   {"source": [{"href": database_href,
                                "resourceType": "database",
                                "include": True,
                                "version": {"href": database_version,
                                            "metadata": {"useLatest": True}},
                                "metadata":
                                {"name": database_torestore},
                                "id": database_id,
                                "pointInTime": restoreTime}],
                       "subpolicy":
                       [{"type": "restore",
                         "mode": "test",
                         "destination":
                         {"mapdatabase": {database_href:
                                          {"name": restoreName,
                                           "paths": []}}},
                           "option":
                           {"autocleanup": True,
                            "allowsessoverwrite": True,
                            "continueonerror": True,
                            "applicationOption":
                            {"overwriteExistingDb": False,
                             "maxParallelStreams": 1,
                             "recoverymode": "recovery"}},
                           "source":
                           {"copy":
                            {"site": {"href": "https://172.20.47.47:443/api/site/1000"}}}}],
                       "view": "applicationview"}}
        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restoreLogOracle(self, subType, database_href, database_version, database_torestore, database_id, restoreName, restoreTime, instanceid, instanceVersion):
        restore = {"subType": subType,
                   "script":
                   {"preGuest": None,
                    "postGuest": None,
                    "continueScriptsOnError": False},
                   "spec":
                   {"source": [{"href": database_href,
                                "resourceType": "database",
                                "include": True,
                                "version": None,
                                "metadata":
                                {"name": database_torestore,
                                 "instanceVersion": instanceVersion,
                                 "instanceId": instanceid},
                                "id": database_id,
                                "pointInTime": restoreTime}],
                       "subpolicy":
                       [{"type": "restore",
                         "mode": "test",
                         "destination":
                         {"mapdatabase": {database_href:
                                          {"name": restoreName,
                                           "paths": []}}},
                           "option":
                           {"autocleanup": None,
                            "allowsessoverwrite": None,
                            "continueonerror": None,
                            "applicationOption":
                            {"overwriteExistingDb": False,
                             "recoveryType": "pitrecovery"}},
                           "source":
                           {"copy":
                            {"site": {"href": "https://172.20.47.47:443/api/site/1000"}}}}],
                       "view": "applicationview"}}
        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_script(self, subType, scriptserver, server_add, script_href, script_name, database_href, database_version, database_torestore, instance_version, instance_id, databaseid, restoreName):
        restore = {"subType": subType,
                   "script": {
                       "preGuest": None,
                       "postGuest": {
                           "appserver": {
                               "href": scriptserver,
                               "name": server_add},
                           "script": {
                               "href": script_href,
                               "args": [],
                               "metadata": {
                                   "name": script_name}}},
                       "continueScriptsOnError": False},
                   "spec": {
                       "source": [{
                           "href": database_href,
                           "resourceType": "database",
                           "include": True,
                           "version": {
                               "href": database_version,
                               "metadata": {
                                   "useLatest": True}},
                           "metadata": {
                               "name": database_torestore,
                               "instanceVersion": instance_version,
                               "instanceId": instance_id,
                               "useLatest": True},
                           "id": databaseid}],
                       "subpolicy": [{
                           "type": "restore",
                           "mode": "test",
                           "destination": {
                               "mapdatabase": {
                                   database_href: {
                                       "name": restoreName,
                                       "paths": []}}},
                           "option": {
                               "autocleanup": True,
                               "allowsessoverwrite": True,
                               "continueonerror": True,
                               "applicationOption": {
                                   "overwriteExistingDb": False,
                                   "recoveryType": "recovery"}},
                           "source": {
                               "copy": {
                                   "site": {
                                       "href": "https://172.20.2.134/api/site/1000"},
                                   "isOffload": None}}}], "view": "applicationview"}}
        return self.spp_session.post(data=restore, path='ngp/application?action=restore')['response']

    def restore_vm_production(self, hv_type, hv_href, hv_name, hv_id, hv_version, site_href, streaming=True, restore_mode="recovery"):
        data = {
            "subType": hv_type,
            "spec": {
                "source": [
                    {
                        "href": hv_href,
                        "metadata": {
                            "name": hv_name
                        },
                        "resourceType": "vm",
                        "id": hv_id,
                        "include": True,
                        "version": {
                            "href": hv_version,
                            "metadata": {
                                "useLatest": True,
                                "name": "Use Latest"
                            }
                        }
                    }
                ],
                "subpolicy": [
                    {
                        "type": "IV",
                        "destination": {
                            "systemDefined": True,
                            "mapvirtualnetwork": {},
                            "mapRRPdatastore": {},
                            "mapsubnet": {},
                            "mapvm": {}
                        },
                        "source": {
                            "copy": {
                                "site": {
                                    "href": site_href
                                }
                            }
                        },
                        "option": {
                            "poweron": True,
                            "allowvmoverwrite": True,
                            "continueonerror": True,
                            "autocleanup": True,
                            "allowsessoverwrite": True,
                            "restorevmtag": None,
                            "mode": restore_mode,
                            "vmscripts": False,
                            "protocolpriority": "iSCSI",
                            "IR": False,
                            "streaming": streaming
                        }
                    }
                ]
            },
            "script": {
                "preGuest": None,
                "postGuest": None,
                "continueScriptsOnError": False
            }
        }

        return self.spp_session.post(data=data, path='ngp/hypervisor?action=restore')['response']

    def restore_ec2(self, hyperv_href, hyperv_name, hyperv_id, hyperv_version_href, hyperv_copy_href,
                          hyperv_copy_time, restore_hyperv_name, restore_mode="clone"):

        data = {
            "subType": "awsec2",
            "spec": {
                "source": [
                    {
                        "href": hyperv_href,
                        "metadata": {
                            "name": hyperv_name
                        },
                        "resourceType": "vm",
                        "id": hyperv_id,
                        "include": True,
                        "version": {
                            "href": hyperv_version_href,
                            "copy": {
                                "href": hyperv_copy_href
                            },
                            "metadata": {
                                "useLatest": False,
                                "protectionTime": hyperv_copy_time
                            }
                        }
                    }
                ],
                "subpolicy": [
                    {
                        "type": "IV",
                        "destination": {
                            "systemDefined": True,
                            "mapvirtualnetwork": {},
                            "mapRRPdatastore": {},
                            "mapsubnet": {},
                            "mapvm": {
                                hyperv_href: {
                                    "name": restore_hyperv_name
                                }
                            }
                        },
                        "source": None,
                        "option": {
                            "poweron": False,
                            "allowvmoverwrite": False,
                            "continueonerror": True,
                            "autocleanup": True,
                            "allowsessoverwrite": True,
                            "restorevmtag": True,
                            "mode": restore_mode,
                            "vmscripts": False,
                            "protocolpriority": "iSCSI",
                            "IR": False,
                            "streaming": False
                        }
                    }
                ]
            },
            "script": {
                "preGuest": None,
                "postGuest": None,
                "continueScriptsOnError": False
            }
        }

        return self.spp_session.post(data=data, path='ngp/hypervisor?action=restore')['response']


    def getStatus(self, job_id):
        jobsession = self.spp_session.get(
            path='api/endeavour/jobsession?pageSize=200')['sessions']
        for session in jobsession:
            if(session['jobId'] == job_id):
                # print(session['status'])
                currentstatus = session['status']
                break
        return currentstatus


class searchAPI(SppAPI):

    def __init__(self, spp_session):
        super(searchAPI, self).__init__(spp_session, 'search')

    def get_fileRestoreOptions(self, filename, filepath, vmname):
        return self.get(params={
            'filter': '[{"property":"name","op":"=","value":"%s"}],\
            {"property":"location","value":"%s","op":"="},\
            {"property":"vmName","op":"=","value":"%s"}' 
            % (filename, filepath, vmname)})


class keyAPI(SppAPI):

    def __init__(self, spp_session):
        super(keyAPI, self).__init__(spp_session, 'key')

    def register_key(self, cloud_data, name="azurekey1"):
        key_data = {"name": name, "keytype": "iam_key", "access": cloud_data['api_key'],
                    "secret": cloud_data['api_secret']}
        registered_key = self.spp_session.post(
            data=key_data, path='/api/identity/key')
        return registered_key

    def unregister_key(self, key_id):
        deleted_key = self.spp_session.delete(path='/api/identity/key/{0}'.format(str(key_id)))
        return deleted_key


class CertificateAPI(SppAPI):

    def __init__(self, spp_session):
        super(CertificateAPI, self).__init__(spp_session, 'certificate')

    def upload_certificate(self, data, files):
        url = build_url(self.spp_session.api_url, 'api/security/certificate')

        headers = {'X-Endeavour-sessionid': self.spp_session.sessionid, 'Accept': '*/*'}
        resp = requests.post(url=url, headers=headers, data=data, files=files, verify=False)

        return resp

    def remove_certificate(self, script_id):
        url = build_url(self.spp_session.api_url, 'api/security/certificate/')
        url = url + str(script_id)
        headers = {'X-Endeavour-sessionid': self.spp_session.sessionid, 'Accept': '*/*'}
        resp = requests.delete(url, headers=headers, verify=False)
        print(resp)

        return resp


class cloudAPI(SppAPI):

    def __init__(self, spp_session):
        super(cloudAPI, self).__init__(spp_session, 'cloud')

    def get_azure_buckets(self, cloud_data, registered_key):
        data = {"provider": cloud_data['provider'], "accesskey": registered_key['links']['self']['href'],
                "properties": {"endpoint": cloud_data['endpoint']}}
        buckets = self.spp_session.post(
            data=data, path='/api/cloud' + '?action=getBuckets')['buckets']
        return buckets

    def get_aws_buckets(self, cloud_data, registered_key):
        data = {"provider": cloud_data['provider'], "accesskey": registered_key['links']['self']['href'],
                "properties": {"region": cloud_data['region']}}
        buckets = self.spp_session.post(
            data=data, path='/api/cloud' + '?action=getBuckets')['buckets']
        return buckets

    def register_azure_cloud(self, cloud_data, registered_key, cloud_bucket, archive_bucket, name="testazure11"):
        data = {"type": "s3", "provider": cloud_data['provider'], "accesskey": registered_key['links']['self']['href'],
                "properties": {"type": "s3", "endpoint": cloud_data['endpoint'], "bucket": cloud_bucket['id'],
                               "archiveBucket": archive_bucket['id']}, "name": name}
        cloud_server = self.spp_session.post(
            data=data, path='ngp/cloud')['response']
        return cloud_server

    def register_aws_cloud(self, cloud_data, registered_key, cloud_bucket, archive_bucket, name="testazure11"):
        data = {"type": "s3", "provider": cloud_data['provider'], "accesskey": registered_key['links']['self']['href'],
                "properties": {"type": "s3", "region": cloud_data['region'], "bucket": cloud_bucket['id'],
                               "archiveBucket": archive_bucket['id']}, "name": name}
        cloud_server = self.spp_session.post(
            data=data, path='ngp/cloud')['response']
        return cloud_server

    def register_ec2_cloud(self, cloud_data):
        data = {
            "type": cloud_data['type'],
            "provider": cloud_data['provider'],
            "accesskey": cloud_data['accesskey'],
            "name": cloud_data['name']
        }
        cloud_server = self.spp_session.post(data=data, path='ngp/cloud')['response']
        return cloud_server

    def unregister_cloud(self, cloud_id):
        response = self.spp_session.delete(path='api/cloud/{0}'.format(cloud_id))
        return response
    
    def ec2_adhoc_backup(self, sla_name, resources):
        data = {
            "slaPolicyName": sla_name,
            "subtype": "awsec2",
            "resource": resources
        }
        return self.spp_session.post(data=data, path='ngp/hypervisor?action=adhoc')

    def register_repo_server(self, name, hostname, port, key_name, access_key, secret_key, certificate_href):
        data = {
            "type": "s3",
            "provider": "sp",
            "accesskey": {
                "name": key_name,
                "keytype": "iam_key",
                "access": access_key,
                "secret": secret_key
            },
            "properties": {
                "type": "s3",
                "certificate": {
                    "href": certificate_href

                },
                "hostname": hostname,
                "port": port

            },
            "name": name
        }

        repo_server = self.spp_session.post(data=data, path='ngp/cloud')['response']
        return repo_server


class catalogAPI(SppAPI):

    def __init__(self, spp_session):
        self.session = spp_session
        super(catalogAPI, self).__init__(spp_session, 'ngp/catalog')

    # Assign an SLA for your SPP catalog backup.
    def assign_sla(self, sla):
        SLAPolicies = {
            "subtype": "catalog",
            "version": "1.0",
            "slapolicies": [{
                "href": sla['links']['self']['href'],
                "id":sla['id'],
                "name":sla['name']
            }]
        }

        return self.spp_session.post(data=SLAPolicies, path='ngp/catalog/system?action=applySLAPolicies')

    # Returns a previously defined (by assign_sla()) backup job.
    def get_job(self):
        jobs = self.spp_session.get(path='api/endeavour/job')['jobs']
        for job in jobs:
            if job['subType'] == "catalog":
                return job

        raise Exception(
            "No SLA assigned for the catalog. You have to run assign_sla() first.")

    # Runs provided backup job and returns status similarly to JobAPI.monitor() (ex. "COMPLETED").
    def run_backup_job(self, job):
        self.spp_session.post(path="api/endeavour/job/" +
                              job['id']+"?action=start")
        job_status = JobAPI(self.spp_session).status(job['id'])

        _, session_status = JobAPI(self.spp_session).monitor(
            job_status, job['id'], job['name'])

        return session_status

    # Restores your SPP catalog from the latest backup in the storage of a given id.
    def run_restore_job(self, global_config, storage_id):
        path = '?view=catalogbackup&pageSize=100&sort=[{"property":"creationTime","direction":"DESC"}]&filter=[{"property":"type","value":"vsnap","op":"="}]'
        snapshots = self.spp_session.get(
            path='api/storage/'+storage_id+path)['snapshots']
        href = snapshots[0]['links']['self']['href']

        restore_options = {
            "subtype": "catalog",
            "spec": {
                "source": [{
                    "href": href
                }], "options": {
                    "mode": "production"
                }, "subpolicy": [{}], "script": {}
            }
        }

        # Initiate the restore.
        response = self.post(path='/system?action=restore',
                             data=restore_options)

        url = global_config.serverurl + '/api/lifecycle/ping'
        time.sleep(200)  # Wait for the server to actually go down.

        # Periodically check if the server is back up yet.
        # (Wait out "Server is being brought up. Wait...")
        for i in range(90):
            resp = requests.get(url, verify=False)
            if resp.status_code == 200:
                return response
            time.sleep(10)

        raise Exception('Server is taking too long to respond!')
    
    # TODO Only return after maintenance is done.
    def run_maintenance(self):
        resp = self.spp_session.post('api/endeavour/job/1001?action=start')
        
        return JobAPI(self.session).monitor(resp['status'], resp['id'], resp['name'])
         

class vadpAPI(SppAPI):
    def __init__(self, spp_session):
        super(vadpAPI, self).__init__(spp_session, 'ngp/vadp')

    # Points to site "Secondary" by default.
    def install_vadp(self, ip_address, username, password, site_id="2000"):
        data = {
            "pushinstall": {
                "hostAddress": ip_address
            },
            "identityId": {
                "username": username,
                "password": password
            },
            "registration": {
                "siteId": site_id
            }
        }

        response = self.post(
            path='?action=installandregister',
            data=data
        )['response']

        return response

    def suspend_vadp(self, vadp_id):

        response = self.spp_session.post(
            path="api/vadp/{0}?action=suspend".format(vadp_id)
        )

        return response

    def resume_vadp(self, vadp_id):

        response = self.spp_session.post(
            path="api/vadp/{0}?action=resume".format(vadp_id)
        )

        return response

    def uninstall_vadp(self, vadp_id):

        response = self.spp_session.post(
            path="api/vadp/{0}?action=uninstall".format(vadp_id)
        )

        return response


class vsnapAPI(SppAPI):
    def __init__(self, spp_session):
        super(vsnapAPI, self).__init__(spp_session, 'api/storage')

    def install_vsnap(self, data):
        response = self.post(data=data)

        return response

    def register_vsnap(self, session, data):
        # register vsnap
        vsnap_response = SppAPI(session, 'ngp/storage').post(data=data)['response']
        
        # check if vsnap is ready
        if vsnap_response['initializeStatus'] != "Ready":
            self.initialize_vsnap(
                vsnap_response['storageId']
            )

        return vsnap_response

    def initialize_vsnap(self, vsnap_id):
        response = self.post(
            path="/{0}/management?action=init".format(vsnap_id),
            data={"async": True}
        )
        for i in range(30):
            time.sleep(30)
            status = self.refresh_vsnap(vsnap_id)['initializeStatus']
            if status != "Initializing":
                break
        if status != "Ready":
            raise Exception("Initialization failed")

        return response
    
    def refresh_vsnap(self, vsnap_id):
        status = self.post(
            path="{0}?action=refresh".format(vsnap_id)
        )
        return status

    def get_network_adapters(self, vsnap_id):
        response = self.get("{0}/management/network".format(vsnap_id))

        return response

    def update_network_adapter(self, vsnap_id, adapter_id, data):
        response = self.put("{0}/management/network/{1}".format(vsnap_id, adapter_id), data=data)

        return response

    def get_disks(self, vsnap_id):
        response = self.get("{0}/management/disk".format(vsnap_id))

        return response

    def attach_disk(self, vsnap_id, disk_id):
        data = { "disk_list": [disk_id] }
        
        try:
            self.post("{0}/management?action=rescan".format(vsnap_id))
            time.sleep(30)
            response = self.post("{0}/management/pool/1?action=expand".format(vsnap_id), data = data)
        
            return response

        except requests.HTTPError as er:
            logger = logging.getLogger()
            logger.error(er)
            return False


"""
Used for communication with the MongoDB database that the SPP application runs on.
"""
class MongoAPI:
    def __init__(self, ssh_username, ssh_password, ssh_address):
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_address = ssh_address

    """
    This method is implemented as a context manager to ensure the SSHTunnelForwarder server is closed after
    we're done using the class. Otherwise the program would just hang indefinitely. 

    Example:

    with MongoAPI('serveradmin', 'password', '172.20.79.0').connect() as conn:
        print(conn.db.recovery_StorageCatalogStorage.find_one())

    It should only be called by end users with the intention of using pymongo directly. Using other methods
    of this class doesn't require calling connect() as they call it themselves.
    """
    from contextlib import contextmanager
    @contextmanager
    def connect(self, mongo_user='ecxadmin', mongo_password='Ecx8dmin', port=27018, auth_database="ECDB_master"):
        # Handling imports here to avoid requiring these for users not interested in mongo functionality.
        import pymongo
        from sshtunnel import SSHTunnelForwarder
        
        # We're using an SSH forwarder because mongoDB on SPP products doesn't allow remote connections.
        server = SSHTunnelForwarder(
            self.ssh_address,
            ssh_username=self.ssh_username,
            ssh_password=self.ssh_password,
            remote_bind_address=('127.0.0.1', port)
        )
        server.daemon_forward_servers = True
        server.start()

        client = pymongo.MongoClient('127.0.0.1', server.local_bind_port)
        self.client = client

        db = client[auth_database]
        db.authenticate(mongo_user, mongo_password)
        self.db = db

        try:
            yield self
        finally:
            server.close()

    """
    Returns all snapshots by default, but can be modified with a standard MongoDB query.

    Examples: 
        get_snapshots({"pk": "2000.snapshot.4"})
        get_snapshots({"sessionId": 82137912309})
    """
    def get_snapshots(self, query=None):

        with self.connect() as conn:
            return [snapshot for snapshot in conn.db.recovery_StorageCatalogSnapshot.find(query)]

"""
API wrapper for Vsnap CLI API.
Allows for direct communication with a vsnap (not through SPP).
"""
class VsnapAPI_CLI:
    def __init__(self, address, username, password):
        self.api_address = "https://{}:8900/api/".format(address)
        self.credentials = (username, password)

    def get_snapshots(self):
        return requests.get(self.api_address+'snapshot', auth=self.credentials, verify=False).json()
    
    def get_snapshot_by_name(self, name):
        snapshots = self.get_snapshots()['snapshots']
        for snapshot in snapshots:
            if snapshot['name'] == name:
                return snapshot

        return None
    
    def delete_snapshot_by_id(self, snapshot_id):
        return requests.delete(
            self.api_address+'snapshot/{}'.format(snapshot_id),
            auth=self.credentials,
            verify=False
        )

    def get_volumes(self):
        return requests.get(self.api_address+'volume', auth=self.credentials, verify=False).json()
    
    def get_volume_by_name(self, name):
        volumes = self.get_volumes()['volumes']
        for volume in volumes:
            if volume['name'] == name:
                return volume

        return None
    
    def delete_volume_by_id(self, volume_id):
        return requests.delete(
            self.api_address+'volume/{}'.format(volume_id),
            auth=self.credentials,
            verify=False
        )
