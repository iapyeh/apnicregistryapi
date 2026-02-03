## implementation of a client for APNIC Registry API
## API Objects Ref: https://www.apnic.net/manage-ip/using-whois/guide/aut-num/
## Version History
##  2025/3/24
##  2025/6/24
##  2025/7/17 integrating logging with twisted.python.log
import requests
import json
import time, os, sys, datetime
import logging
import logging.handlers
import threading
import ipaddress
import urllib.parse
__version__ = '0.9.20251204'
global logger
logger = None
def setLogger(_logger=None,level=None):
    global logger
    if _logger is None:
        logger = Logger(level)
    else:
        logger = _logger
    logger.msg(f"APNIC Registry API {__version__} Loaded")
    return logger

class Logger:
    ## default logger (wrapping logging and twisted.python.log)
    def __init__(self,level=None):
        self.logger = None
        self.setupLogger()
        if level:
            self.logger.setLevel(level)
    def setupLogger(self):
        logPath = 'log'
        if not os.path.exists(logPath): os.mkdir(logPath)
        logHandler = logging.handlers.WatchedFileHandler(os.path.join(logPath,'registry_api_client.log'))
        formatter = logging.Formatter( '%(asctime)s:%(levelname)s:%(message)s','%Y-%m-%d %H:%M:%S')
        #formatter.converter = time.gmtime  # if you want UTC time
        logHandler.setFormatter(formatter)
        self.logger = logging.getLogger('registry_api_client')
        self.logger.addHandler(logHandler)

        if sys.stdout.isatty(): 
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(formatter) 
            self.logger.addHandler(handler)
        return self.logger
    def msg(self,mesg,level=None):
        if level == logging.DEBUG:
            self.logger.debug(mesg)
        elif level == logging.INFO:
            self.logger.info(mesg)
        elif level == logging.WARNING:
            self.logger.warning(mesg)
    def err(self,mesg):
        self.logger.error(mesg)

class APIRequestError(Exception):
    def __init__(self,errno,mesg):
        super(APIRequestError,self).__init__()
        self.errno = errno
        self.message = mesg
    def __str__(self):
        return f'[Errno: {self.errno}] {self.message}'

class PagedRequest(object):
    def __init__(self,apiclient,path):
        self.api = apiclient
        self.path = path
    def __call__(self):
        path = self.path
        error_count = 0
        while True:
            if logger: logger.msg(f'requesting: {path},error_count={error_count}',level=logging.DEBUG)
            r = self.api.session.get(path,verify=self.api.verifySSL)   
            try:     
                print('r=',r.text)
                data = r.json()
            except json.decoder.JSONDecodeError:
                if logger: logger.msg(f'responsed with json error={[r.text]}',level=logging.WARNING)
                error_count += 1
                if error_count > 3:
                    raise APIRequestError(1,f'responsed with json error over 3 times')
                else:
                    time.sleep(3)
                    continue
            else:
                error_count = 0
                yield data
                try:
                    path = data['_links']['next']['href']
                    time.sleep(1)
                except KeyError:
                    break
## 物件有特定的欄位必須放在第一個，否則會遇到""Object type in URL does not match object type in posted data." 的錯誤
id_attribute = {
    'person':'person', ## 不是nic-hdl
    'role':'role', ## 不是nic-hdl
    'irt':'irt',
    'aut-num':'aut-num',
    'inetnum':'inetnum',
    'inet6num':'inet6num',
    'mnter':'mnter',
    'route':'range',
    'whois_route':'route',
    'whois_route6':'route6',
    'domain':'domain',
    'rdns':'range',
}

class ApnicApiClient(object):
    def __init__(self, account, apikey,verifySSL=True):
        ## initialize logger if necessary
        if logger is None: setLogger()
        ## the url to make nir-api requests
        self.baseurl = f'https://registry-api.apnic.net/v1/{account}'
        if logger: logger.msg(f"base url={self.baseurl}",level=logging.DEBUG)
        ## only the http://<hostname:port?
        self.hostname = 'registry-api.apnic.net'
        self.apikey = apikey
        self.verifySSL = verifySSL
        self._session = requests.Session()
        self.throttle_of_session = 1
        self._session_last_request = 0
    @property
    def logger(self):
        return logger
    @property
    def session(self):
        self._session.headers.update({
            'Authorization': f'Bearer {self.apikey}',
            'Content-Type': 'application/json',
            'Host':self.hostname
        })
        return self._session
    @property
    def throttled_session(self):
        now = time.time()
        diff = now - self._session_last_request
        
        if diff >= self.throttle_of_session:
            #print((now,self._session_last_request,diff,0))
            self._session_last_request = now
            return self.session
        else:
            time.sleep(self.throttle_of_session-diff+0.1)
            #print((now,self._session_last_request,diff,self.throttle_of_session-diff+0.1))
            self._session_last_request = time.time()
            return self.session
    
    def get_url(self,url):
        return self.throttled_session.get(url,verify=self.verifySSL)

    def list_request(path):
        def delegation_of_wrapper(wrapper):
            ## do_the_job() receives caller's arguments
            def do_the_job(self,id=None,**kw):
                for item in wrapper(self,id,path,kw or None):
                    return item
            return do_the_job
        return delegation_of_wrapper
    
    def delegation(topic):
        def delegation_of_topic(func):
            def wrapper(self,id,path,kw):
                if kw:
                    vars = []
                    for k,v in kw.items():
                        if v is None: continue
                        vars.append(f"{k}={v}")
                    if len(vars):
                        query_string = f"?{'&'.join(vars)}"
                    else:
                        query_string = ''
                else:
                    query_string = ''
                id = func(self,id)
                if id is None:       
                    url = f"{self.baseurl}/{path}{topic}{query_string}"
                    if logger: logger.msg('questing paged %s' % url,level=logging.DEBUG)
                    yield PagedRequest(self,url)()
                else:
                    url = f"{self.baseurl}/{path}{topic}/{id}{query_string}"
                    if logger: logger.msg('questing %s' % url,level=logging.DEBUG)
                    r = self.throttled_session.get(url,verify=self.verifySSL)
                    if r.status_code == 200:
                        yield r.json()
                    else:
                        raise APIRequestError(r.status_code,r.text)
            return wrapper
        return delegation_of_topic


    @list_request('task')
    @delegation('')
    def get_task(self,id=None,**kw):
        return id

    @list_request('test-object')
    @delegation('')
    def get_test_object(self,id=None):
        return id

    @list_request('delegation/')
    @delegation('ipv4')
    def get_delegation_ipv4(self,id=None):
        return id

    @list_request('delegation/aggregate-')
    @delegation('ipv4')
    def get_delegation_aggregate_ipv4(self,id=None):
        return id

    @list_request('delegation/')
    @delegation('ipv6')
    def get_delegation_ipv6(self,id=None):
        return id

    @list_request('delegation/aggregate-')
    @delegation('ipv6')
    def get_delegation_aggregate_ipv6(self,id=None):
        return id

    @list_request('delegation/')
    @delegation('autnum')
    def get_delegation_asn(self,id=None):
        return id

    @list_request('delegation/aggregate-')
    @delegation('autnum')
    def get_delegation_aggregate_asn(self,id=None):
        return id
    
    def get_delegation(self,typename,*args):
        assert typename in ('asn','ipv4','ipv6')
        func = getattr(self,f'get_delegation_{typename}')
        return func(*args)

    @list_request('mntner')
    @delegation('')
    def get_mntner(self,id=None):
        return id

    @list_request('irt')
    @delegation('')
    def get_irt(self,id=None):
        return id

    @list_request('route')
    @delegation('')
    def get_route(self,route_id=None):
        """ route_id is an integer """
        return str(route_id) if route_id else None

    @list_request('rdns')
    @delegation('')
    def get_rdns(self,range):
        """ range is a cidr, like 203.119.94.0/24 """
        return range

    @list_request('version-update')
    @delegation('')
    def get_version_update(self,id=None):
        return None

    def whois_object(topic):
        def whois_object_of_topic(func):
            def wrapper(self,*args):
                id = func(self,*args)
                path = f"{self.baseurl}/whois/{topic}/{id}"
                if logger: logger.msg('requesting %s' % path,level=logging.DEBUG)
                r = self.throttled_session.get(path,verify=self.verifySSL)
                if r.status_code == 200:
                    return r.json()
                else:
                    raise APIRequestError(r.status_code,r.text)
            return wrapper
        return whois_object_of_topic

    @whois_object('aut-num')
    def whois_get_asn(self,asn):
        """ asn is an integer or digits string """
        return 'AS%s' % asn if isinstance(asn,int) else asn

    @whois_object('inetnum')
    def whois_get_ipv4(self,range):
        if '-' in range:
            return range
        else:
            ## cidr (ip/mask)
            network = ipaddress.ip_network(range)
            return f'{network[0]} - {network[-1]}'

    @whois_object('inet6num')
    def whois_get_ipv6(self,range):
        return range

    @whois_object('person')
    def whois_get_person(self,nic_hdl):
        return nic_hdl

    @whois_object('role')
    def whois_get_role(self,nic_hdl):
        return nic_hdl

    @whois_object('route')
    def whois_get_route(self,range,asn):
        return f'{range}AS{asn}'

    @whois_object('route6')
    def whois_get_route6(self,range,asn):
        return f'{range}AS{asn}'

    @whois_object('irt')
    def whois_get_irt(self,irt):
        return irt
    
    @whois_object('mntner')
    def whois_get_mntner(self,mntner):
        return mntner
    
    ## rdns
    @whois_object('domain')
    def whois_get_domain(self,domain):
        return domain

    ## wrapper function
    def whois_get(self,typename,*args):
        alias = {
            'inetnum':'ipv4',
            'inet6num':'ipv6',
            'aut-num':'asn',
        }
        typename = alias.get(typename) or typename
        func = getattr(self,'whois_get_'+typename)
        return func(*args)
    ## deprecated alias
    get_whois = whois_get

    
    def wait_task_complete(func):
        def wrapper(self,*args,**kw):
            response = func(self,*args,**kw)
            ## response's example: {'location': 'https://registry-api.apnic.net/v1/TWNIC-TW/task/34'}
            paths = response['location'].split('/')
            assert paths[-2] == 'task',f"response={response}"
            task_id = paths[-1]
            ret = None
            while 1:
                ret = self.get_task(task_id)
                if ret['status'] == 'completed':
                    break
                else:
                    time.sleep(1)
            return ret
        return wrapper
    ##
    ## routines about writing (add,update,delete)
    ## 
    def whois_create_raw(self,attributes):
        url = f"{self.baseurl}/whois"
        if logger: logger.msg('questing %s' % url,level=logging.DEBUG)
        r = self.throttled_session.post(url,verify=self.verifySSL,headers={'content-type':'application/json'},json={'attributes':attributes})
        if r.status_code == 202:
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)        
    
    @wait_task_complete
    def whois_create(self,object_data):
        """
        if succeeded, the nic-hdl is in "content/location", eg.
            "response": {
                    "content": {
                        "location": "https://registry-api.apnic.net/v1/TWNIC-TW/whois/person/TO219-AP",
                        "type": "success-response"
                    },
                    "created": "2025-08-08 08:54:41",
                    "status_code": 201
                },        
        """
        attributes = []
        assert 'source' in object_data
        assert 'mnt-by' in object_data
        if 'last-modified' in object_data: del object_data['last-modified']
        keys = list(object_data.keys())
        keys.sort(key=lambda x: 0 if id_attribute.get(x) else 1)
        for k in keys:
            v = object_data[k]
            if not isinstance(v,list):
                values = [v]
            else:
                values = v
            for v in values:
                attributes.append({'name':k,'value':str(v)})
        return self.whois_create_raw(attributes)
    def whois_update_raw(self,typename,id,attributes):
        assert isinstance(attributes,list)
        if typename in ('inet6num',):
            ## 2025/9/30 currently, apnic's api requires fully-expanded form
            msbip,prefixlength = id.split('/')
            id = ipaddress.ip_address(msbip).exploded + '/' + prefixlength
        #elif typename == 'role':
        #    for item in attributes:
        #        print(item)
        if typename in ('whois_route','whois_route6'):
            url = f"{self.baseurl}/{typename.replace('_','/')}/{id}"
        else:
            url = f"{self.baseurl}/whois/{typename}/{id}"
        if logger: logger.msg('apnic api whois update requesting %s' % url,level=logging.INFO)
        r = self.throttled_session.put(url,verify=self.verifySSL,headers={'content-type':'application/json'},json={'attributes':attributes})
        if r.status_code == 202:
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)        
    @wait_task_complete
    def whois_update(self,typename,id,object_data):
        """
        convert python dict to apnic api whois object
        Args:
            object_data:(dict)
        """
        alias = {
            'ipv4':'inetnum',
            'ipv6':'inet6num',
            'asn':'aut-num',
        }
        typename = alias.get(typename) or typename
        assert typename in id_attribute
        ## ensure key attribute is at first
        attributes = [{'name':id_attribute[typename],'value':object_data[id_attribute[typename]]}]
        assert 'source' in object_data,f"'source' is required"
        assert 'mnt-by' in object_data,f"'mnt-by' is required"
        for k,v in object_data.items():
            if k == id_attribute[typename]:
                continue
            elif k == 'last-modified':
                continue
            else:
                if not isinstance(v,list):
                    values = [v]
                else:
                    values = v
                for v in values:
                    attributes.append({'name':k,'value':str(v)})
        if logger: logger.msg('update '+json.dumps({'attributes':attributes},indent=4))
        return self.whois_update_raw(typename,id,attributes)
    @wait_task_complete
    def whois_delete(self,typename,id):
        alias = {
            'ipv4':'inetnum',
            'ipv6':'inet6num',
            'asn':'aut-num'
        }
        typename = alias.get(typename) or typename
        assert typename in ('aut-num','inetnum','inet6num','route','irt','mnter','person','role','domain','rdns')
        url = f"{self.baseurl}/whois/{typename}/{id}"
        if logger: logger.msg('whois_delete by %s' % url,level=logging.DEBUG)
        r = self.throttled_session.delete(url,verify=self.verifySSL)
        if r.status_code in (200,202):
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)        

    @wait_task_complete
    def rdns_create(self,rdns_records):
        if isinstance(rdns_records,dict): rdns_records = [rdns_records]
        url = f"{self.baseurl}/rdns"
        if logger: logger.msg('rdns creation by %s' % url,level=logging.DEBUG)
        data = {'create':rdns_records}
        r = self.throttled_session.post(url,verify=self.verifySSL,headers={'content-type':'application/json'},json=data)
        if r.status_code in (200,202):
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)

    @wait_task_complete
    def rdns_update(self,rdns_records):
        if isinstance(rdns_records,dict): rdns_records = [rdns_records]
        url = f"{self.baseurl}/rdns"
        if logger: logger.msg('rdns updating by %s' % url,level=logging.DEBUG)
        data = {'update':rdns_records}
        r = self.throttled_session.post(url,verify=self.verifySSL,headers={'content-type':'application/json'},json=data)
        if r.status_code in (200,202):
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)
    
    @wait_task_complete
    def rdns_delete(self,rdns_ranges):
        if isinstance(rdns_ranges,dict): rdns_ranges = [rdns_ranges]
        url = f"{self.baseurl}/rdns"
        if logger: logger.msg('rdns deletion by %s' % url,level=logging.DEBUG)
        data = {'delete':rdns_ranges}
        r = self.throttled_session.post(url,verify=self.verifySSL,headers={'content-type':'application/json'},json=data)
        if r.status_code in (200,202):
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)

    #batch route operation
    @wait_task_complete
    def route(self,action,route_records):
        if not isinstance(route_records,list): route_records = [route_records]
        ## convert dict to name-value pair list
        name_value_records = []
        for record in route_records:
            name_value_records.append(record)
        url = f"{self.baseurl}/route"
        if logger: logger.msg('route prevalidation by %s' % url,level=logging.DEBUG)
        data = {action:name_value_records}
        r = self.throttled_session.post(url,verify=self.verifySSL,headers={'content-type':'application/json'},json=data)
        if r.status_code in (200,202):
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)
    def route_create(self,route_records):
        """
        route_records: list of route record (dict) or single route record (dict)
        Example:
            route_record = {
                "range": "61.67.121.0/24",
                'autnum':56789,
                'max_length':24,
                'roa_enabled':False,
                'whois_enabled':True,
            }   
        """ 
        return self.route('create',route_records)
    def route_update(self,route_records):
        """
        route_records: list of route record (dict) or single route record (dict), same as route_create(), but must include 'id' field
        """
        return self.route('update',route_records)
    def route_delete(self,route_ids):
        """
        route_ids: list of route id (integers) or single route id (integer)
        """
        ## convert route_ids to route_records
        if not isinstance(route_ids,list): route_ids = [route_ids]
        route_records = []
        for route_id in route_ids:
            route_records.append({'id':route_id})
        ## requires route id
        return self.route('delete',route_records)

    #route-prevalidation
    @wait_task_complete
    def route_prevalidation(self,action,route_records):
        if isinstance(route_records,dict): route_records = [route_records]
        ## convert dict to name-value pair list
        name_value_records = []
        for record in route_records:
            name_value_records.append(record)
        url = f"{self.baseurl}/route-prevalidation"
        if logger: logger.msg('route prevalidation by %s' % url,level=logging.DEBUG)
        data = {action:name_value_records}
        r = self.throttled_session.post(url,verify=self.verifySSL,headers={'content-type':'application/json'},json=data)
        if r.status_code in (200,202):
            return r.json()
        else:
            raise APIRequestError(r.status_code,r.text)
    def route_prevalidation_create(self,route_records):
        return self.route_prevalidation('create',route_records)
    def route_prevalidation_update(self,route_records):
        return self.route_prevalidation('update',route_records)
    def route_prevalidation_delete(self,route_records):
        return self.route_prevalidation('delete',route_records)
