from apnic.apnicregistryapi import ApnicApiClient,setLogger,APIRequestError
import os,json,datetime,time
import ipaddress,logging
import json,sys
global logger
class Agent(object):
    def __init__(self, nir, apikey,data_folder):
        self.api_client = ApnicApiClient(nir, apikey)
        self.data_folder = data_folder
        self.session_id = f'{datetime.datetime.now().strftime("%Y%m%d")}'
    
    def has_file(self, filename):
        file_path = os.path.join(self.data_folder, filename)
        return os.path.exists(file_path)
    
    def save_to_file(self, data,filename):
        file_path = os.path.join(self.data_folder, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logger.msg(f'Saved data to {file_path}')
        return file_path

    def read_from_file(self, filename):
        file_path = os.path.join(self.data_folder, filename)
        with open(file_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)
        return entries

    def save_list_entries(self,topic,objname,force=False):
        filename = f'{topic}.json'
        if (not force) and self.has_file(filename):
            logger.msg(f'{filename} already exists, skipping download.')
        else:
            entries  = []
            getter = getattr(self.api_client,f'get_{topic}')
            for chunk in getter():
                try:
                    for entry in chunk['_embedded'][f'{objname}']:
                        entries.append(entry)
                        logger.msg(str(entry))
                except KeyError:
                    logger.msg(f'KeyError: {chunk}')
                    raise
            self.save_to_file(entries,filename)
            logger.msg(f'{filename} created.')
    

    def retrieve_list_entries(self,force=False):  
        '''
        從apnic取得第一層的清單資料

        :force: bool
            if True, get data from APNIC 
            if False, get data only if no chching file existed.
        '''        
        """ get 1st level objects from apnic """      
        self.save_list_entries('delegation_asn','delegation-autnum',force=force)
        return
        self.save_list_entries('delegation_ipv4','delegation-ipv4',force=force)
        self.save_list_entries('delegation_ipv6','delegation-ipv6',force=force)
        self.save_list_entries('delegation_aggregate_asn','delegation-aggregate-autnum',force=force)
        self.save_list_entries('delegation_aggregate_ipv4','delegation-aggregate-ipv4',force=force)
        self.save_list_entries('delegation_aggregate_ipv6','delegation-aggregate-ipv6',force=force)
        self.save_list_entries('route','route',force=force)
        self.save_list_entries('mntner','mntner',force=force)
        self.save_list_entries('irt','irt',force=force)

    
    def dig_objects_of_topic(self,topic,key_field,request_field):
        assert topic in ('delegation_asn','delegation_ipv4','delegation_ipv6','irt','mntner')
        ## target file to save data
        filename = f'{topic}_objects.json'
        if self.has_file(filename):
            logger.msg(f'{filename} existed')
        else:
            object_entries = {}
            entries = self.read_from_file(f'{topic}.json')
            for idx,entry in enumerate(entries):
                key = entry[key_field]
                print(f'{idx+1}/{len(entries)}:{key}',end='')
                assert object_entries.get(key) is None
                try:
                    getter = getattr(self.api_client,f'get_{topic}')
                    data = getter(entry[request_field])
                except APIRequestError as e:
                    print(':ERROR')
                    logger.msg(f'{topic} {key}:{e}',level=logging.WARNING)
                    object_entries[key] = None
                else:
                    print(':OK')
                    object_entries[key] = data
                    if idx == 0: print(data)
                time.sleep(1)
            self.save_to_file(object_entries,filename)

    def dig_whois_by_topic(self,topic,key_field,*request_field,force=False):
        assert topic in ('delegation_asn','delegation_ipv4','delegation_ipv6','irt','mntner','route')
        ## target file to save data
        if len(topic.split('_')) == 2:
            ## ipv4,asn,ipv6
            topic_name = topic.split('_')[1]
        else:
            ## irt
            topic_name = topic
        filename = f'whois_{topic_name}.json'
        if self.has_file(filename):
            if force:
                logger.msg(f'override existing {filename}')
            else:
                logger.msg(f'keep existing {filename}')
                return
        whois_entries = {}
        entries = self.read_from_file(f'{topic}.json')
        for idx,entry in enumerate(entries):
            key = entry[key_field]
            print(f'{idx+1}/{len(entries)}:{key}',end='')
            assert whois_entries.get(key) is None
            try:
                getter = getattr(self.api_client,f'get_whois_{topic_name}')
                args = []
                for f in request_field:
                    args.append(entry[f])
                data = getter(*args)
            except APIRequestError as e:
                print(':ERROR')
                logger.msg(f'{topic_name} {key}:{e}',level=logging.WARNING)
                whois_entries[key] = None
            else:
                print(':OK')
                whois_entries[key] = data
                if idx == 0: print(data)
            time.sleep(1)
        self.save_to_file(whois_entries,filename)


    def dig_objects(self):
        """ get delegation entries one by one, finally got the same data as the list request """
        self.dig_objects_of_topic('delegation_ipv4','id','id')
        self.dig_objects_of_topic('delegation_ipv6','id','id')
        self.dig_objects_of_topic('delegation_asn','number','number')
        self.dig_objects_of_topic('irt','irt','irt')

    def dig_whois(self,force=False):
        '''
        get whois data of ipv4,ipv6,asn,irt,route from apnic 
        '''
        self.dig_whois_by_topic('delegation_ipv4','id','range',force=force)
        self.dig_whois_by_topic('delegation_ipv6','id','range',force=force)
        self.dig_whois_by_topic('delegation_asn','number','number',force=force)
        self.dig_whois_by_topic('irt','irt','irt',force=force)
        self.dig_whois_by_topic('route','id','range','autnum',force=force)

    def dig_whois_person(self,force=False):
        """ collecting nic-hdl, then making requests to whois api """
        person_ids = set()
        mntner_ids = set()
        irt_ids = set()
        statistics = {}
        for topic in ('ipv4','ipv6','asn','irt'):
            entries = self.read_from_file(f'whois_{topic}.json')
            statistics[topic] = {'total':len(entries),'no-data':0}
            for key, entry in entries.items():
                if entry is None: 
                    logger.msg(f'{topic}:{key} has not whois data')
                    statistics[topic]['no-data'] += 1
                    continue
                for item in entry['attributes']:
                    if item['name'] in ('admin-c','tech-c','abuse-c'): person_ids.add(item['value'])
                    elif item['name'] in ('mnt-by','mnt-lower'): mntner_ids.add(item['value'])
                    elif item['name'] in ('mnt-irt',): irt_ids.add(item['value'])

        entries = self.read_from_file(f'rdns.json')
        statistics['rdns'] = {'total':len(entries),'no-data':0}
        for cidr, entry in entries.items():
            if entry is None: 
                logger.msg(f'rdns:{key} has not whois data')
                statistics['rdns']['no-data'] += 1
                continue
            for record in entry['_embedded']["rdns-record"]:
                for item in record['contacts']:
                    if item['type'] in ('admin-c','tech-c','abuse-c'): person_ids.add(item['value'])
                for item in record['mnt_bys']:
                    mntner_ids.add(item)

        statistics['person'] = {'origin':0,'added':0,'unlinked':0,'missing':0}
        filename = 'whois_person.json'
        if self.has_file(filename):
            if not force:
                logger.msg(f'keep existing {filename}')
                return 
            existing_persons = self.read_from_file(filename)
        else:
            existing_persons = {}
        statistics['person']['origin'] = len(existing_persons)
        
        ## person id does not appearred in ipv4,asn,ipv6 whois entries
        for id in existing_persons:
            if not id in person_ids:
                statistics['person']['unlinked'] += 1
        
        ## person id do appearred in ipv4,asn,ipv6 whois entries
        for id in person_ids:
            ## Note: "changes" not checked yet
            if (not id in existing_persons) or existing_persons[id] is None :
                logger.msg(f'adding person {id}')
                try:
                    existing_persons[id] = self.api_client.get_whois_person(id)
                    statistics['person']['added'] += 1
                except APIRequestError as e:
                    statistics['person']['missing'] += 1
                    existing_persons[id] = None
                    logger.msg(f'missing {id}:{e}')
                time.sleep(1)

        self.save_to_file(existing_persons,filename)

        logger.msg(f'{len(person_ids)} person ids has found.')
        logger.msg(f'{len(mntner_ids)} mntner ids has found.')
        logger.msg(f'{len(irt_ids)} irt ids has found')
        for topic in ('ipv4','ipv6','asn'):
            logger.msg(f'In {statistics[topic]["total"]} items of delegation_{topic}, {statistics[topic]["no-data"]} has no whois data ')
        logger.msg(f'{len(existing_persons)} person ids in datastore')
        logger.msg(f'{statistics["person"]["unlinked"]} person ids are unlinked')
        logger.msg(f'{statistics["person"]["missing"]} person ids are missing')
        logger.msg(f'{statistics["person"]["added"]} person ids are added in this session')

    def dig_rdns(self,force=False):
        """ collecting range, then making requests to rdns api """
        ranges = set()

        entries = self.read_from_file(f'delegation_ipv4.json')
        for entry in entries:
            #nw = ipaddress.ip_network(entry['range'])
            #ranges.add(f'{nw[0]} - {nw[-1]}')
            ranges.add(entry['range'])

        entries = self.read_from_file(f'delegation_ipv6.json')
        for entry in entries:
            ranges.add(entry['range'])

        statistics = {
            'origin':0,
            'unlinked':0,
            'missing':0,
            'added':0
        }
        filename = 'rdns.json'
        if self.has_file(filename):
            if not force:
                logger.msg(f'keep existing {filename}')
                return
            existing_rdns = self.read_from_file(filename)
        else:
            existing_rdns = {}
        
        statistics['origin'] = len(existing_rdns)
        
        ## person id does not appearred in ipv4,asn,ipv6 whois entries
        for cidr in existing_rdns:
            if not cidr in ranges:
                statistics['unlinked'] += 1
        
        ## person id do appearred in ipv4,asn,ipv6 whois entries
        for cidr in ranges:
            ## Note: "changes" not checked yet
            if (not cidr in existing_rdns) or existing_rdns[cidr] is None :
                logger.msg(f'adding rdns {cidr}')
                try:
                    existing_rdns[cidr] = self.api_client.get_rdns(cidr)
                    statistics['added'] += 1
                except APIRequestError as e:
                    statistics['missing'] += 1
                    existing_rdns[cidr] = None
                    logger.msg(f'missing {cidr}:{e}')
                time.sleep(1)

        self.save_to_file(existing_rdns,filename)
        logger.msg(f'{len(existing_rdns)} rdns items in datastore')
        logger.msg(f'{statistics["unlinked"]} rdns items are unlinked')
        logger.msg(f'{statistics["missing"]} rdns items are missing')
        logger.msg(f'{statistics["added"]} rdns items are added in this session')
    
    def get_matrix(self):
        for topic in ('ipv4','ipv6','asn','aggregate_ipv4','aggregate_ipv6','aggregate_asn'):
            entries = self.read_from_file(f'delegation_{topic}.json')
            print(f'delegation_{topic}: {len(entries)}')
        for topic in ('irt','mntner','route','rdns'):
            entries = self.read_from_file(f'{topic}.json')
            print(f'{topic}: {len(entries)}')
        for topic in ('ipv4','ipv6','asn','irt','route','person'):
            entries = self.read_from_file(f'whois_{topic}.json')
            missing = 0
            assert isinstance(entries,dict)
            for key,value in entries.items():
                if value is None:
                    missing += 1
            print(f'whois_{topic}: {len(entries)-missing},missing:{missing}')

def get_data_from_apnic(agent,force=False):
    ## 1st tier data
    agent.retrieve_list_entries(force=force)
    ## data about whois
    #agent.dig_whois(force=force)
    ## 2nd tier data
    #agent.dig_rdns(force=force)
    ## data about handle in whois
    #agent.dig_whois_person(force=force)    

def main():
    '''
    從apnic wohis database把所有屬於twnic的資料拉回本機
    '''
    global logger
    logger = setLogger(level=logging.DEBUG)
    ## config is vsdconfig.py module
    account = 'TWNIC-TW'
    print(config)
    apikey = config.apikey
    data_folder = config.data_folder
    agent = Agent(account,apikey,data_folder)
    get_data_from_apnic(agent,force=True)

if __name__ == '__main__':
    config_folder = os.path.abspath(os.path.join(os.path.dirname(__file__),'../..'))
    assert os.path.exists(os.path.join(config_folder,'importconfig.py'))
    sys.path.insert(0,config_folder)
    from importconfig import *
    sys.path.remove(config_folder)

    main()