## 2025/12/4 set use_cache to False (default not to use cache)
import threading
import logging
import logging.handlers
import sys,os,requests,time,json
from .apnicregistryapi import setLogger
global logger
logger = None
import copy
class ApnicWhoisClient(object):
    def __init__(self,cache_filepath=None,use_cache=False):
        self.baseurl = 'https://wq.apnic.net/query'
        self.session_lock = threading.Lock()
        self.throttle = 1.5
        self.last_request = 0
        if cache_filepath:
            assert os.path.exists(cache_filepath),f"{cache_filepath} not found"
        self.cache_filepath = os.path.abspath(cache_filepath if cache_filepath else '.apicwhoisclient-cache')
        self.use_cache = use_cache
        self.load_cache()
        if logger: logger.msg(f"initial cache={self.cache_filepath} size={len(self.cache)}")
        self.session = requests.Session()
    
    def search(self,text,force=False):
        if self.use_cache and (not force and text.lower() in self.cache):
            return copy.deepcopy(self.cache[text.lower()])
        url = self.baseurl + '?searchtext=' + text

        ## control speed
        delta = (time.time() - self.last_request)
        if  delta < self.throttle:
            if logger: logger.msg(f".",level=logging.DEBUG)
            time.sleep(self.throttle - delta)
        start = time.time()
        req = self.session.get(url)
        self.last_request = time.time()
        spend = time.time() - start
        if spend > 3:
            if logger: logger.msg(f"searching {text} spend {spend}s",level=logging.WARNING)

        if req.status_code == 200:
            try:     
                self.session_lock.acquire()
                entries = req.json()
                if self.use_cache:
                    self.cache[text.lower()] = entries
                ## 注意：entries有可能重複，例如搜尋email時，回應irt,person，但irt當中又有同一個person
                return entries
            except json.decoder.JSONDecodeError:
                if logger: logger.err(f'Json Error!=>{[req.text]}')
                return None
            finally:
                self.session_lock.release()
                if self.use_cache and len(self.cache) % 10 == 0:
                    self.save_cache()
        else:
            if logger: logger.msg(f'Server Complains:{req.status_code} for {text}:{req.text}',level=logging.WARNING)
            if req.status_code == 429:
                if logger: logger.msg('Suspending 10 seconds',level=logging.DEBUG)
                time.sleep(10)
                #self.generate_session()
            return None
    def entry_to_object(self,entry)->dict:
        obj = {
            'objectType':entry['objectType'],
            'primaryKey':entry['primaryKey'],
        }
        ## flatten the object's value
        for item in entry['attributes']:
            if 'name' in item:
                key = item['name']
                try:
                    values = item['values']
                except KeyError:
                    try:
                        ## eg. mnt-by
                        values = item['links']
                    except KeyError:
                        values = item
            elif 'links' in item:
                ## when objectypte is "irt", it contains "links"
                key = 'links'
                values = item[key]
            else:
                if logger: logger.err(json.dumps(entry,indent=4))
                raise ValueError('unknown item')

            if isinstance(values,list) and len(values)==1:
                values = values[0]
            
            try:
                obj[key]
            except KeyError:
                obj[key] = values 
            else:
                ## the response would reply like this:
                #{
                #    "name": "e-mail",
                #   "values": [
                #        "brown@global-plus-tech.com"
                #    ]
                #},
                #{
                #    "name": "e-mail",
                #    "values": [
                #        "ysf5228@ms3.hinet.net"
                #    ]
                #},
                ## not like this
                #{
                #    "name": "e-mail",
                #    "values": [
                #        "brown@global-plus-tech.com".
                #        "ysf5228@ms3.hinet.net"
                #    ]
                #},
                ## merge values
                if isinstance(obj[key],list):
                    if isinstance(values,list):
                        obj[key].extend(values)
                    else:
                        obj[key].append(values)
                else:
                    if isinstance(values,list):
                        obj[key] = [obj[key]] + values
                    else:
                        obj[key] = [obj[key], values]
        for k,v in obj.copy().items():
            if isinstance(v,list) and len(v)==1:
                obj[k] = v[0]
        return obj
    def search_object(self,email,force=False):
        result = []
        entries = self.search(email,force=force)
        if entries is None: return None
        for entry in entries :
            ## skip comments
            if entry['type'] == 'object':
                obj = self.entry_to_object(entry)
                result.append(obj)
        return result

    def iterate_cache(self):
        for email, entries in self.cache.items():
            result = []            
            if entries is None:
                yield email,None
            for entry in entries :
                if entry['type'] == 'object':
                    obj = {
                        'objectType':entry['objectType'],
                        'primaryKey':entry['primaryKey'],
                    }
                    for item in entry['attributes']:
                        if 'name' in item:
                            key = item['name']
                            try:
                                values = item['values']
                            except KeyError:
                                values = item
                        elif 'links' in item:
                            ## when objectypte is "irt", it contains "links"
                            key = 'links'
                            values = item[key]
                        else:
                            if logger: logger.err(json.dumps(entry,indent=4))
                            raise ValueError('unknown item')
                        obj[key] = values                
                    for k,v in obj.copy().items():
                        if isinstance(v,list) and len(v)==1:
                            obj[k] = v[0]
                    result.append(obj)
            yield email, result    
    ## cache managements
    def save_cache(self,filepath=None):
        if self.use_cache:
            if filepath is None: filepath = self.cache_filepath
            self.session_lock.acquire()
            with open(filepath,'w') as fd:
                json.dump(self.cache,fd)
            self.session_lock.release()
            if logger: logger.msg(f"cache saved,cache size={len(self.cache)}")
    
    def load_cache(self,filepath=None):
        if self.use_cache:
            if filepath is None: filepath = self.cache_filepath
            if os.path.exists(filepath):
                with open(filepath) as fd:
                    self.cache = json.load(fd)
            else:
                self.cache = {}
        else:
            self.cache = {}
    
    def reset_cache(self,filepath=None):
        if self.use_cache:
            if filepath is None: filepath = self.cache_filepath
            if os.path.exists(filepath):
                os.unlink(filepath)
        self.cache = {}

    def __del__(self):
        self.save_cache()

    @property
    def cache_size(self):
        return len(self.cache)

    def get_objects_of_email(self,email,filter=None,force=False):
        """
        dupicating object whould be removed
        """
        whois_objects = self.search_object(email,force=force)
        known_types = ['person','role','irt']
        objects = {}
        for t in known_types: objects[t] = []
        
        appended_person = set() ## only check for person
        for obj in whois_objects:
            if obj['objectType'] == 'person':
                try:
                    if obj['nic-hdl'] in appended_person: continue
                except KeyError:
                    #print(f'This "person" object of {email} has no "nic-hdl"')
                    #print(json.dumps(obj,indent=4))
                    continue
                except TypeError:
                    ## eg. 'nic-hdl': ['', 'Answer from RIR truncated']
                    if logger: logger.msg('skip obj=%s' % obj,level=logging.DEBUG)
                    continue
            ## debugging 
            if not obj['objectType'] in known_types:
                known_types.append(obj['objectType'])
                objects[obj['objectType']] = [obj]
                if logger: logger.msg(f"{email} has unknown objectType:{obj['objectType']}",level=logging.WARNING)
                continue
            ## flatten mnt-by
            ## Attention: write to "mnt_by", keep original "mnt-by"
            if 'mnt-by' in obj:
                if isinstance(obj['mnt-by'],str):
                    obj['mnt_by'] = obj['mnt-by']
                elif isinstance(obj['mnt-by'],list):
                    mnt_by = []
                    for item in obj['mnt-by']:
                        mnt_by.append(item['text'])
                    obj['mnt_by'] = mnt_by
                elif isinstance(obj['mnt-by'],dict):
                    obj['mnt_by'] = obj['mnt-by']['text']
                elif 'links' in obj['mnt-by']:
                    if isinstance(obj['mnt-by']['links'],list):
                        ## 'links' is a list
                        ## only take the first object
                        mnt_by = []
                        for item in obj['mnt-by']['links']:
                            mnt_by.append(item['text'])
                        obj['mnt_by'] = mnt_by
                    elif isinstance(obj['mnt-by']['links'],dict):
                        ## 'links' is a dict
                        obj['mnt_by'] = obj['mnt-by']['links']['text']
                    else:
                        raise ValueError(f"unhandled {obj['mnt-by']}")
                else:
                    raise ValueError(f"unhandled {obj['mnt-by']}")
            else:
                obj['mnt_by'] = ''
            if filter is None or filter(obj):
                if obj['objectType'] == 'person':
                    appended_person.add(obj['nic-hdl'])
                objects[obj['objectType']].append(obj)
        return objects

def unittest_whois():
    results = ApnicWhoisClient().search_email('noc@fast-line.tw')
    for item in results:
        print(json.dumps(item,indent=4))
        print('=' * 40)
if __name__ == '__main__':
    logger = setLogger()
    unittest_whois()