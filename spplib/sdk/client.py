import configparser
import json
import pprint
import os
import re
import tempfile
import time
import logging
import traceback
from spplib.sdk import system

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
    'log': 'api/endeavour/log',
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
    'key': '/api/identity/key'
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
        self.conn.headers.update({'X-Endeavour-Locale': 'en-us'})

    def login(self):
        r = self.conn.post("%s/endeavour/session" % self.sess_url,
                           auth=HTTPBasicAuth(self.username, self.password))
        self.sessionid = r.json()['sessionid']

    def logout(self):
        r = self.conn.delete("%s/endeavour/session" % self.sess_url)

    def __repr__(self):
        return 'sppSession: user: %s' % self.username

    def get(self, restype=None, resid=None, path=None, params={}, endpoint=None, url=None):
        if url is None:
            url = build_url(self.api_url, restype, resid, path, endpoint)

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

    def get_jobsession(self, jobsessionid):

        jobsession = self.spp_session.get(
            path='api/endeavour/jobsession/{}'.format(jobsessionid))

        return jobsession


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

    def monitor(self, jobStatus, job_id, job_name, timeout=0):
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
        return self.get(path="oraclehome/%s/database" % instanceid)

    def get_database_copy_versions(self, instanceid, databaseid):
        return self.get(path="oraclehome/%s/database/%s" % (instanceid, databaseid) + "/version")


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


class HypervAPI(SppAPI):
    def __init__(self, spp_session):
        super(HypervAPI, self).__init__(spp_session, 'spphv')

    def get_instances(self):
        return self.get(path="/vm")

    def get_hypervinstance(self, hypervs, name):
        for hyperv in hypervs['vms']:
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
        return self.get(path="oraclehome/%s/database" % instanceid)

    def get_database_copy_versions(self, instanceid, databaseid):
        return self.get(path="oraclehome/%s/database/%s" % (instanceid, databaseid) + "/version")


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
                                           "trigger": {"frequency": 1, "type": "DAILY", "activateDate": 1524110400000},
                                           "site": site}]}}
        resp = self.post(data=slainfo)
        return resp

    def edit_sla(self, id, data):
        response = self.put(
            path=id,
            data=data
        )

        return response

    def create_cloud_sla(self, name, cloud_server, site="Primary"):
        slainfo = {"name": name, "version": "1.0",
                   "spec": {"simple": True, "subpolicy": [{"type": "REPLICATION", "software": True,
                                                           "retention": {"age": 15},
                                                           "useEncryption": False,
                                                           "trigger": {"frequency": 1, "type": "DAILY",
                                                                       "activateDate": 1532577600000}, "site": site},
                                                          {"type": "SPPOFFLOAD", "retention": {},
                                                           "trigger": {"frequency": 1, "type": "DAILY",
                                                                       "activateDate": 1532584800000},
                                                           "source": "backup",
                                                           "target": {"href": cloud_server['links']['self']['href'],
                                                                      "resourceType": cloud_server['provider'],
                                                                      "id": cloud_server['id'],
                                                                      "wormProtected": False}}]}}
        resp = self.post(data=slainfo)
        return resp

    def assign_sla(self, instance, sla, subtype, target='application'):
        # Added target variable to make the function more generic (ex. 'hypervisor' or 'application')
        # without breaking backwards compatibility thanks to target defaulting to 'application'.
        applySLAPolicies = {"subtype": subtype,
                            "version": "1.0",
                            "resources": [{
                                "href": instance['links']['self']['href'],
                                "id":instance['id'],
                                "metadataPath":instance['metadataPath']}],
                            "slapolicies": [{
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

    def restore_vm_clone(self, subType, vm_href, vm_name, vm_id, vm_version, vm_clone_name):
        restore = {
            "subType": "vmware",
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
                            "streaming": True
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

    def restoreHyperV(self, subType, hyperv_href, hyperv_name, hyperv_id, hyperv_version, site_href):
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
                               "poweron": False,
                               "continueonerror": True,
                               "autocleanup": True,
                               "allowsessoverwrite": True,
                               "mode": "test",
                               "vmscripts": False,
                               "restorevmtag": True,
                               "update_vmx": True}}]},
                   "script": {}
                   }
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

    def restore_vm_production(self, hv_type, hv_href, hv_name, hv_id, hv_version, site_href):
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
                            "poweron": False,
                            "allowvmoverwrite": True,
                            "continueonerror": True,
                            "autocleanup": True,
                            "allowsessoverwrite": True,
                            "restorevmtag": None,
                            "mode": "recovery",
                            "vmscripts": False,
                            "protocolpriority": "iSCSI",
                            "IR": False,
                            "streaming": True
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

    def get_fileRestoreOptions(self, filename):
        return self.get(params={'filter': '[{"property":"*","op":"=","value":"%s"}]' % filename})


class keyAPI(SppAPI):

    def __init__(self, spp_session):
        super(keyAPI, self).__init__(spp_session, 'key')

    def register_azure_key(self, cloud_data, name="azurekey1"):
        key_data = {"name": name, "keytype": "iam_key", "access": cloud_data['api_key'],
                    "secret": cloud_data['api_secret']}
        registered_key = self.spp_session.post(
            data=key_data, path='/api/identity/key')
        return registered_key


class cloudAPI(SppAPI):

    def __init__(self, spp_session):
        super(cloudAPI, self).__init__(spp_session, 'cloud')

    def get_buckets(self, cloud_data, registered_key):
        data = {"provider": cloud_data['provider'], "accesskey": registered_key['links']['self']['href'],
                "properties": {"endpoint": cloud_data['endpoint']}}
        buckets = self.spp_session.post(
            data=data, path='/api/cloud' + '?action=getBuckets')['buckets']
        return buckets

    def register_azure_cloud(self, cloud_data, registered_key, cloud_bucket, name="testazure11"):
        data = {"type": "s3", "provider": cloud_data['provider'], "accesskey": registered_key['links']['self']['href'],
                "properties": {"type": "s3", "endpoint": cloud_data['endpoint'], "bucket": cloud_bucket['id']},
                "name": name}
        cloud_server = self.spp_session.post(
            data=data, path='ngp/cloud')['response']
        return cloud_server


class catalogAPI(SppAPI):

    def __init__(self, spp_session):
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
