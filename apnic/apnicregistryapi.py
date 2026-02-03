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
global loger
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

def unitest_task(client,id=34,after=None):
    task_gen = client.get_task(id,after=after)
    results = []
    if isinstance(task_gen,dict):
        results.append({'_embedded':{'task':[task_gen]}})
    else:
        while 1:
            try:
                """
                Example:
                    {'_embedded': {'task': [{'_links': {'self': {'href': 'https://registry-api.apnic.net/v1/TWNIC-TW/task/1'}}, 'operation': 'put_whois_object', 'request': {'content': {'attributes': [{'name': 'role', 'value': 'Testing Role'}, {'name': 'org', 'value': 'TWNIC'}, {'name': 'address', 'value': '3F., No. 123, Sec. 4, Bade Rd.,'}, {'name': 'address', 'value': 'Songshan Dist., Taipei 105'}, {'name': 'country', 'value': 'TW'}, {'name': 'phone', 'value': '886-2-25289696'}, {'name': 'e-mail', 'value': 'iap@twnic.tw'}, {'name': 'admin-c', 'value': 'AT939-AP'}, {'name': 'tech-c', 'value': 'AT939-AP'}, {'name': 'abuse-mailbox', 'value': 'iap@twnic.tw'}, {'name': 'mnt-by', 'value': 'MAINT-TW-TWNIC'}, {'name': 'nic-hdl', 'value': 'AUTO-1'}]}, 'created': '2025-07-15 04:27:42'}, 'response': {'content': {'errors': ['No source: found in AUTO-1'], 'title': 'Failed Whois update', 'type': 'failed-whois-update'}, 'created': '2025-07-15 04:27:43', 'status_code': 400}, 'status': 'completed'}]}, '_links': {'self': {'href': 'https://registry-api.apnic.net/v1/TWNIC-TW/task'}}}
                """            
                result = next(task_gen)
                results.append(result)                
            except StopIteration:
                break
    if len(results):
        #result = results[-1]
        for result in results:
            print("-" * 40)
            #print(result)
            for task in result['_embedded']['task']:
                '''
                {'_links': {'self': {'href': 'https://registry-api.apnic.net/v1/TWNIC-TW/task/3'}}, 'operation': 'put_whois_object', 'request': {'content': {'attributes': [{'name': 'role', 'value': 'Testing Role'}, {'name': 'org', 'value': 'TWNIC'}, {'name': 'address', 'value': '3F., No. 123, Sec. 4, Bade Rd.,'}, {'name': 'address', 'value': 'Songshan Dist., Taipei 105'}, {'name': 'country', 'value': 'TW'}, {'name': 'phone', 'value': '886-2-25289696'}, {'name': 'e-mail', 'value': 'iap@twnic.tw'}, {'name': 'admin-c', 'value': 'AT939-AP'}, {'name': 'tech-c', 'value': 'AT939-AP'}, {'name': 'abuse-mailbox', 'value': 'iap@twnic.tw'}, {'name': 'mnt-by', 'value': 'MAINT-TW-TWNIC'}, {'name': 'nic-hdl', 'value': 'AUTO'}]}, 'created': '2025-07-15 04:34:34'}, 'response': {'content': {'errors': ['No source: found in AUTO'], 'title': 'Failed Whois update', 'type': 'failed-whois-update'}, 'created': '2025-07-15 04:34:34', 'status_code': 400}, 'status': 'completed'}'''
                print(json.dumps(task,indent=4))

def unittest_person(client,action):
    person = 'Li-Heng Yu, TDC'
    nic_hdl = 'TN437-AP'
    if action == 'add':
        object_data = {
            'person':person,
            'address':[
                "6F., No. 119-1, Baozhong Rd., Xindian Dist.",
                "New Taipei City"
            ],
            'country':['TW'],
            'phone':['+886-2-25289696'],
            'e-mail':['iap@twnic.tw'],
            'abuse-mailbox':['iap@twnic.tw'],
            'mnt-by':['MAINT-TW-TWNIC'],
            'nic-hdl':'AUTO-1',
            'source':'APNIC',
        }
        ## this would create role "TP655-AP"
        print(json.dumps(client.whois_create(object_data),indent=4))
    elif action == 'update':
        object_data = {
            'person':person,
            'address':['3F., No. 123, Sec. 4, Bade Rd.,','Songshan Dist., Taipei 105'],
            'country':'TW',
            'phone':'+886-2-25289696',
            'e-mail':'iap@twnic.tw',
            'abuse-mailbox':'iap@twnic.tw',
            'mnt-by':'MAINT-TW-TWNIC',
            'nic-hdl':nic_hdl,
            'source':'APNIC',
        }
        print(json.dumps(client.whois_update('person',nic_hdl,object_data),indent=4))
    elif action == 'delete':
        print(json.dumps(client.whois_delete('person',nic_hdl),indent=4))
    else:
        raise NotImplementedError(f"{action} not supported")
    
def unittest_role(client,action):
    ## add, update, delete role
    role = 'TWNIC-ROLE NET104'
    nic_hdl = 'TN441-AP'
    if action == 'add':
        object_data = {
            'role':role,
            'address':[
                '104 Corporation',
                '10Fl., No. 119-1, Baujung Rd., Shindian City',
                'Songshan Dist., Taipei 105'],
            'country':'TW',
            'phone':'+886-2-25289696',
            'e-mail':'iap@twnic.tw',
            'admin-c':'NN553-AP',
            'tech-c':'NN553-AP',
            'abuse-mailbox':'iap@twnic.tw',
            'mnt-by':'MAINT-TW-TWNIC',
            'nic-hdl':'AUTO-1',
            'source':'APNIC',
        }
        print(json.dumps(client.whois_create(object_data),indent=4))
    elif action == 'update':
        object_data = {
            'role':role,
            'address':[
                '104 Corporation',
                '10Fl., No. 119-1, Baujung Rd., Shindian City',
                'Songshan Dist., Taipei 105'],
            'country':'TW',
            'phone':'+886-2-25289696',
            'e-mail':'iap@twnic.tw',
            'admin-c':'NN553-AP',
            'tech-c':'NN553-AP',
            'abuse-mailbox':'iap@twnic.tw',
            'mnt-by':'MAINT-TW-TWNIC',
            'remarks':'(oid:104IT)',
            'nic-hdl':nic_hdl,
            'source':'APNIC',
        }
        print(json.dumps(client.whois_update('role',nic_hdl,object_data),indent=4))
    elif action == 'update-raw':
        nic_hdl = "TR596-AP"
        attributes=[
	        {
	            "name": "role",
	            "value": "TWNIC ROLE-TWNIC_ADMIN_TECH"
	        },
	        {
	            "name": "nic-hdl",
	            "value": nic_hdl
	        },
	        {
	            "name": "address",
	            "value": "Taiwan Network Information center"
	        },
	        {
	            "name": "address",
	            "value": "3F., No. 123, Sec. 4, Bade Rd., Songshan Dist., Taipei 105, Taiwan"
	        },
	        {
	            "name": "address",
	            "value": "Taipei"
	        },
	        {
	            "name": "country",
	            "value": "TW"
	        },
	        {
	            "name": "phone",
	            "value": "+886-2-2528-9696"
	        },
	        {
	            "name": "e-mail",
	            "value": "ip@twnic.tw"
	        },
	        {
	            "name": "abuse-mailbox",
	            "value": "ip@twnic.net.tw"
	        },
	        {
	            "name": "admin-c",
	            "value": "IT176-AP"
	        },
	        {
	            "name": "tech-c",
	            "value": "IT176-AP"
	        },
	        {
	            "name": "remarks",
	            "value": "(hid:NWH0612-TW,+,YW0628-S-TW)"
	        },
	        {
	            "name": "mnt-by",
	            "value": "MAINT-TW-TWNIC"
	        },
	        {
	            "name": "source",
	            "value": "APNIC"
	        }
	    ]
        print(client.whois_update_raw('role',nic_hdl,attributes))
    elif action == 'delete':
        print(json.dumps(client.whois_delete('role',nic_hdl),indent=4))
    else:
        raise NotImplementedError(f"{action} not supported")
def unittest_whoisasn(client,action):
    aut_num =  "AS17718"
    object_data = {
        "country": "TW",
        "as-name": "TWNIC",
        "admin-c": "TR595-AP",
        "tech-c": "TR595-AP",
        "abuse-c": "TR595-AP",
        "aut-num": aut_num,
        "mnt-irt": "IRT-TWNIC-AP",
        "descr": [
            "Taiwan Network Information center",
            "3F., No. 123, Sec. 4, Bade Rd., Songshan Dist., Taipei 105, Taiwan",
            "Taipei"
        ],
        #"default": [],
        "export": [
            "to AS10133 announce AS17718",
            "to AS131644 announce ANY"
        ],
        "import": [
            "from AS10133 action pref=100; accept ANY",
            "from AS131644 accept ANY"
        ],
        "remarks": [
            "(oid:TWNIC)"
        ],
        "mnt-by": [
            "MAINT-TW-TWNIC"
        ],
        "source": "APNIC",
        #"notify": [
        #    "iapyeh@twnic.tw",
        #    "timwang@twnic.tw"
        #]
    }
    
    if action == 'update':
        print(json.dumps(client.whois_update('aut-num',aut_num,object_data),indent=4))
    elif action == 'get':
        print(json.dumps(client.get_whois('asn',aut_num),indent=4))
    

def unittest_whoisipv4(client,action):
    range =  "119.75.240.0 - 119.75.255.255"
    #range = '202.5.8.0 - 202.5.11.255' ## not found
    object_data = {
        "inetnum": range,
        "netname": "TWNIC-NET",
        "descr": [
            "Taiwan Network Information Center",
            "TWNIC"
        ],
        "country": [
            "TW"
        ],
        "admin-c": [
            "TRS11-AP"
        ],
        "tech-c": [
            "TRS11-AP"
        ],
        "abuse-c": [
            "TRS11-AP"
        ],
        "status": "ASSIGNED PORTABLE",
        "mnt-by": [
            "MAINT-TW-TWNIC"
        ],
        "mnt-irt": "IRT-TWNIC-TW",
        #"last-modified": "2021-11-04T00:48:44Z",
        "source": "APNIC"
    }        
    if action == 'add':
        print(client.whois_create(object_data))
    elif action == 'get':
        print(client.whois_get('inetnum',range))
    elif action == 'update':
        print(client.whois_update('inetnum',range,object_data))
    elif action == 'delete':
        print(client.whois_delete('inetnum',range))

def unittest_whoisipv6(client,action):
    #id =  "119.75.248.0 - 119.75.255.255"
    inet6num = '2001:44F0::/32'.lower()
    object_data_raw = [
        {
            "name": "inet6num",
            "value": "2001:44f0::/32"
        },
        {
            "name": "netname",
            "value": "IPv6PO-NET"
        },
        {
            "name": "descr",
            "value": "Taiwan IPv6 Development Program."
        },
        {
            "name": "descr",
            "value": "4F-2, No.9, Roosevelt Rd. Sec 2,"
        },
        {
            "name": "descr",
            "value": "Taipei 100, Taiwan, R.O.C."
        },
        {
            "name": "country",
            "value": "TW"
        },
        {
            "name": "admin-c",
            "value": "TWA2-AP"
        },
        {
            "name": "tech-c",
            "value": "TWA2-AP"
        },
        {
            "name": "abuse-c",
            "value": "AT939-AP"
        },
        {
            "name": "status",
            "value": "ALLOCATED PORTABLE"
        },
        {
            "name": "mnt-by",
            "value": "MAINT-TW-TWNIC"
        },
        {
            "name": "mnt-lower",
            "value": "MAINT-TW-TWNIC"
        },
        {
            "name": "mnt-irt",
            "value": "IRT-TWNIC-AP"
        },
        {
            "name": "source",
            "value": "APNIC"
        }
    ]
    object_data = {
        #"inet6num": urllib.parse.quote_plus(inet6num),
        "inet6num": inet6num.lower(),
        "country": "TW",
        "netname": "IPv6PO-NET",
        "admin-c": "TR595-AP",
        "tech-c": "TR595-AP",
        "abuse-c": "TR595-AP",
        "mnt-irt": "IRT-TWNIC-AP",
        "descr": [
            "Taiwan Network Information center",
            "3F., No. 123, Sec. 4, Bade Rd., Songshan Dist., Taipei 105, Taiwan",
            "Taipei"
        ],
        #"remarks": [],
        "status": "ASSIGNED PORTABLE",
        "mnt-by": [
            "MAINT-TW-TWNIC"
        ],
        "mnt-lower": [
            "MAINT-TW-TWNIC"
        ],
        "source": "APNIC",
    }
    if action == 'add':
        print(client.whois_create(object_data))
    elif action == 'update':
        print(client.whois_update('inet6num',inet6num,object_data))
    elif action == 'update-raw':
        print(client.whois_update_raw('inet6num','2001:44F0::%2F32',object_data_raw))
    elif action == 'get':
        print(json.dumps(client.whois_get_ipv6(inet6num),indent=4))

def unittest_whoisroute6(client,action):
    #id =  "119.75.248.0 - 119.75.255.255"
    cidr = '2400:85a0::/32'.lower()
    asn = 18183
    if action == 'get':
        print(json.dumps(client.whois_get('route6',cidr,asn),indent=4))
    elif action == 'update':
        obj = {
            'route6':"2400:85a0::/32",
            'origin':'AS18183',
            'descr':"Taiwan Network Information Center 3F., No. 123, Sec. 4, Bade Rd., Songshan Dist.",
            'mnt-by': "MAINT-TW-TWNIC",
            'source': 'APNIC'
        }
        key = f'{cidr}AS{asn}'
        print(json.dumps(client.whois_update('whois_route6',key,obj),indent=4))

def unittest_rdns(client,action):
    #range='182.173.0.0/18'
    #range='103.159.176.0/23' ## having "ds_rdatas"(DNSSEC Delegation Signer (DS) record)
    #range='203.119.94.0/24' ## testing for delete,update,create
    if action == 'list':
        if 0:
            for mask in range(18,19):
                cidr = '27.100.64.0/%s'% mask
                try:
                    ret = client.get_rdns(cidr)
                    print(cidr,json.dumps(ret,indent=4))
                except APIRequestError as e:
                    print(cidr,e)
        elif 1:
            cidr = '61.56.0.0/13'
            try:
                ret = client.get_rdns(cidr)
                print(cidr,json.dumps(ret,indent=4))
            except APIRequestError as e:
                print(cidr,e)
    elif action == 'delete':
        cidr = '182.173.5.0/24'
        ret = client.rdns_delete({'range':range})
        print(json.dumps(ret,indent=4))
    elif action in ('create', 'update'):
        rdns_record =[
             {
                "contacts": [
                    {
                        "type": "admin-c",
                        "value": "NNA1-AP"
                    },
                    {
                        "type": "tech-c",
                        "value": "NNA1-AP"
                    },
                    {
                        "type": "zone-c",
                        "value": "NNA1-AP"
                    }
                ],
                "ds_rdatas": [],
                "mnt_bys": [
                    "MAINT-TW-TWNIC"
                ],
                "nameservers": [
                    "ns5.sparqnet.net"
                ],
                "range": '182.173.4.0/23'
            } ,
             {
                "contacts": [
                    {
                        "type": "admin-c",
                        "value": "TWA2-AP"
                    },
                    {
                        "type": "tech-c",
                        "value": "TWA2-AP"
                    },
                    {
                        "type": "zone-c",
                        "value": "TWA2-AP"
                    }
                ],
                "ds_rdatas": [],
                "mnt_bys": [
                    "MAINT-TW-TWNIC"
                ],
                "nameservers": [
                    "ptr1.twnic.net.tw"
                ],
                "range": '182.173.6.0/23'
            } ,
        ]                    
        if action == 'update':
            rdns_record = rdns_record[0]
            rdns_record['range'] = '61.61.0.0/24'
            #rdns_record['nameservers'] = [ "ptr1.twnic.net.tw", "ptr2.twnic.net.tw"]
            ret = client.rdns_update(rdns_record)
        else:      
            rdns_record = rdns_record[0]
            rdns_record['range'] = '182.173.4.0/21'
            ret = client.rdns_create(rdns_record)
        print(json.dumps(ret,indent=4))
def unittest_rdns_domain(client,action=None):
    try:
        domain = '14.173.182.in-addr.arpa'
        ret = client.whois_get_domain(domain)
        print(domain,json.dumps(ret,indent=4))
    except APIRequestError as e:
        print(domain,e)
def unittest_route_prevalidation(client,action):
    route_record = {
        "range": "61.67.121.0/24",
        'autnum':1234,
        'max_length':24,
        'roa_enabled':False,
        'whois_enabled':True,
    }
    ret = client.route_prevalidation_create(route_record)
    print(json.dumps(ret,indent=4))

def unittest_route(client,action):
    if 1:
        ret = client.get_route(314926)
        print(json.dumps(ret,indent=4))
        return
    if 0:
        id=f"61.67.121.0/24AS314926"
        ret = client.get_route(id)
        print(json.dumps(ret,indent=4))
        return
    route_record = {
        "range": "61.67.121.0/24",
        'autnum':56789,
        'max_length':24,
        'roa_enabled':False,
        'whois_enabled':True,
    }
    #action = 'update'
    if action == 'create':
        ret = client.route_create(route_record)
        print(json.dumps(ret,indent=4))
    elif action == 'delete':
        route_id = 314951
        ret = client.route_delete({'id':route_id})
        print(json.dumps(ret,indent=4))
    elif action == 'update':
        route_id = 314951
        ## route_record['autnum'] = 5678 不能改
        route_record['max_length'] = 24 # 不能變小
        route_record['id'] = route_id
        ret = client.route_update(route_record)
        print(json.dumps(ret,indent=4))

def unittest(apikey):
    ## on rms4
    client = ApnicApiClient('TWNIC-TW',apikey)
    #print(client.get_delegation_asn(18415))
    #for i in client.get_delegation_asn():
    #    print('>>',i)
    #for i in client.get_mntner():
    #    print('>>',i)
    #for i in client.get_irt():
    #    print('>>',i)
    #for i in client.get_route():
    #    print('>>',i)
    #print(client.get_route(135403))
    #for i in client.get_version_update():
    #    print('>>',i)
    #for i in client.get_task():
    #    print('>>',i)
    #for i in client.get_test_object():
    #    print('>>',i)
    #print(client.get_whois_asn(18415))
    #unittest_role(client)
    #unittest_whoisipv4(client)
    #unittest_whoisipv4_delete(client)
    if 0:
        #nic_hdl = 'AT939-AP'
        nic_hdl = 'XW3485-AP'
        nic_hdl = 'JJL21-AP'
        entry = client.get_whois_person(nic_hdl)    
        print(entry)    
    elif '-task' in sys.argv:
        task_id = int(sys.argv[ 1 + sys.argv.index('-task')])
        unitest_task(client,task_id)
    elif 0:
        #unittest_role(client,'add')
        #unittest_role(client,'update')
        unittest_role(client,'update-raw')
        #unittest_role(client,'delete')
    elif 0:
        unittest_person(client,'add')
        #unittest_person(client,'update')
        #unittest_person(client,'delete')
    elif 0:
        #unittest_whoisipv4(client,'add')
        unittest_whoisipv4(client,'get')
        #unittest_whoisipv4(client,'delete')
    elif 0:
        #unittest_whoisasn(client,'update')
        unittest_whoisasn(client,'get')
    elif 0:
        #unittest_whoisipv6(client,'update')
        #unittest_whoisipv6(client,'update-raw')
        unittest_whoisipv6(client,'get')
    elif 0:
        unittest_rdns(client,'list')
        #unittest_rdns(client,'create')
        #unittest_rdns(client,'update')
        #unittest_rdns(client,'delete')
    elif 0:
        ## 這個get_irt拿不到什麼有用的資料
        #print(client.get_irt('IRT-ASUS-TW'))
        ## 要用這個whois_get_irt才可拿有用的資料
        print(client.whois_get_irt('IRT-ASUS-TW'))
    elif 0:
        unittest_rdns_domain(client)
    elif 0:
        jsonfile = 'ipv4_aggregated_delegation.json'
        if not os.path.exists(jsonfile):
            items = []
            for i in client.get_delegation_aggregate_ipv4():
                print('>>',i)
                items.append(i)
            with open(jsonfile,'w') as fd:
                json.dump(items,fd)
        else:
            with open(jsonfile) as fd:
                items = json.load(fd)
        for item in items:
            for rangedata in item['_embedded']['delegation-aggregate-ipv4']:
                if '61.' in rangedata['range']:
                    print(json.dumps(rangedata['range'],indent=4))
    elif 0:
        ret = client.whois_get_route('2.58.240.0/24','9678')
        print(json.dumps(ret,indent=4))
    elif 0:
        unittest_route_prevalidation(client,'update')
    elif 0:
        #unittest_route(client,'create')
        #unittest_route(client,'update')
        unittest_route(client,'delete')
    elif 0:
        cache_file = '/tmp/route.cache'
        if not os.path.exists(cache_file):
            ## build cache
            c = 0
            routes = []
            for obj in client.get_route():
                routes.append(obj)
                c += 1
                #if c > 3:
                #    break
                print(c,json.dumps(obj,indent=4))
            with open(cache_file,'w') as fd:
                json.dump(routes,fd)
        else:
            with open(cache_file) as fd:
                routes = json.load(fd)
        
        stop = 0
        c = 0
        for obj in routes:
            print('*' * 40)
            print(json.dumps(obj,indent=4))
            for route_obj in obj['_embedded']['route']:
                c += 1
                #if not '103.104.148.0' in route_obj['range']: continue
                #print(c,json.dumps(route_obj,indent=4))
                #ret = client.whois_get_route(route_obj['range'],route_obj['autnum'])
                #print(c,json.dumps(ret,indent=4))
                stop = 1
                break
            if stop: break
    elif 0:
        #unittest_whoisroute6(client,'get')
        unittest_whoisroute6(client,'update')
    #time.sleep(1)
    #unitest_task(client)
if __name__ == '__main__':
    if 1:
        setLogger(level=logging.DEBUG)
    else:
        from twisted.python import log
        log.startLogging(sys.stdout)
        setLogger(log)
    wd = os.path.normpath(os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
    remove_wd = False
    if wd not in sys.path:
        remove_wd = True
        sys.path.insert(0,wd)
    from importconfig import *
    if remove_wd:
        sys.path.remove(wd)
    if 1:
        unittest(config.apnic_apikey)  
    else:
        url = 'https://registry-api.apnic.net/v1/TWNIC-TW/route?after=315202'
        client = ApnicApiClient('TWNIC-TW',config.apnic_apikey)
        ret = client.get_url(url)
        ## The following response returned, no idea is it normal or not
        ## {"_embedded":{"route":[{}]},"_links":{"self":{"href":"https://registry-api.apnic.net/v1/TWNIC-TW/route"}}}
        print(ret.text)
    
