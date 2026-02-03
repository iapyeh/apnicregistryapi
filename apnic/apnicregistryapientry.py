import json,copy,ipaddress,math
## 轉換apnic 得到的格式為容易使用的資料

class GenericEntry(object):
    def __getattr__(self,k):
        if not k in self._attrs:
            return self.apnic_attributes[k]
        return object.__getattr__(self,k)
    def __getitem__(self,k):
        return self.apnic_attributes[k]
    def get(self,k,default=None):
        return self.apnic_attributes.get(k,default)
    def dump(self):
        return json.dumps(self.apnic_entry,indent=4)

class DelegationEntry(GenericEntry):
    ## these attribute names has list value
    def __init__(self,typename,apnic_entry):
        assert typename in ('ipv4','ipv6','asn','irt')
        self.typename = typename
        self.apnic_entry = apnic_entry
        self.id = None
        self.parse_apnic_entry()
        if typename in ('ipv4','ipv6','asn'):
            assert self.id
    def parse_apnic_entry(self):
        self.apnic_attributes = {}
        ## {'_links': {'self': {'href': 'https://registry-api.apnic.net/v1/TWNIC-TW/delegation/ipv4/223.200.0.0'}}, 'date': '2010-08-10', 'id': '223.200.0.0', 'range': '223.200.0.0/16', 'type': 'allocated'} 
        for k,v in self.apnic_entry.items():
            if k == '_links': continue
            self.apnic_attributes[k] = v
            if k == 'id':
                self.id = v
    def dump(self):
        return json.dumps(self.apnic_attributes,indent=4)

class APIEntry(GenericEntry):
    ## these attribute names has list value
    _list_attrs = []
    _attrs = ('id','apnic_entry','apnic_attributes')
    def __init__(self,id,apnic_entry):
        self.id = id
        self.apnic_entry = apnic_entry
        self.parse_apnic_entry()
    def parse_apnic_entry(self):
        self.apnic_attributes = {}
        for attr_item in self.apnic_entry['attributes']:
            try:
                self.apnic_attributes[attr_item['name']]
            except KeyError:
                self.apnic_attributes[attr_item['name']] = attr_item['value']
            else:
                if isinstance(self.apnic_attributes[attr_item['name']],list):
                    self.apnic_attributes[attr_item['name']].append(attr_item['value'])
                else:
                    ## escalate string to list of string
                    self.apnic_attributes[attr_item['name']] = [self.apnic_attributes[attr_item['name']],attr_item['value']]

## decorator to generate attribute value from. rms's entry
apnic_attribute_factory = {}
def attribute(key,attrname,is_primary=False):
    """
    key is class's name 
    if is_primary is True, this attribute is the primary attribute of this class,
    the original primary attrname is replaced if new one is registered(see WhoisRoute6Entry as an example)
    """
    try:
        apnic_attribute_factory[key]
    except KeyError:
        ## initialize this class's storage 
        apnic_attribute_factory[key] = {'primary':None,'attrs':{}}

    def gen(func):
        apnic_attribute_factory[key]['attrs'][attrname] = func
        if is_primary: 
            apnic_attribute_factory[key]['primary'] = attrname
        return func
    return gen

class ObjectEntry(object):
    ## these attribute names has list value
    ## child class should assign this value
    typename = None
    ## when key attribute is not the same as typename (eg. whois_route)
    key_attr = None
    ## parsing these attributes into list value
    _list_attrs = ['address','e-mail','phone','fax-no','remarks','mnt-by'] + \
        ['descr','remarks','import','export','default','tech-c','admin-c','abuse-c']+\
        ['mnt-lower','notify','mnt-routes','mnt_bys','nserver','ds_rdatas','ds-rdata']
    ## 用於判斷是否有異動的屬性
    _diff_attrs = []
    def __init__(self,apnic_entry=None,db_entry=None):
        """
            apnic_entry is got by apnic api (eg. apiclient.get_whois_asn())
        """
        assert self.typename in ('person','role','irt','inetnum','inet6num','aut-num','rdns','domain','whois_route','whois_route6','route')

        ## id's value would be assigned in self.parse_apnic_entry()
        self.id = None 
        self.apnic_entry = apnic_entry
        self.apnic_attributes = {}
        self.parse_apnic_entry()
        self.db_entry = db_entry 
        self.register_apnic_attributes()
    def parse_apnic_entry(self):
        if not self.apnic_entry: return
        for attr_item in self.apnic_entry['attributes']:
            if attr_item['name'] in self._list_attrs:
                try:
                    self.apnic_attributes[attr_item['name']].append(attr_item['value'])
                except KeyError:
                    self.apnic_attributes[attr_item['name']] = [attr_item['value']]
            else:
                try:
                    self.apnic_attributes[attr_item['name']]
                except KeyError:
                    self.apnic_attributes[attr_item['name']] = attr_item['value']
                else:
                    raise ValueError(f"{attr_item['name']} multiple values were found,\"{self.apnic_attributes[attr_item['name']]}\" and \"{attr_item['value']}\"")
        self.id = self.apnic_attributes[self.key_attr or self.typename]
    
    def __getattr__(self,k):
        if not k in ('id','apnic_entry','apnic_attributes','db_entry'):
            return self.apnic_attributes[k]
        return object.__getattr__(self,k)

    def __setitem__(self,attr,v):
        if self.db_entry and self.apnic_entry:
            self.apnic_attributes[attr] = v
            self.db_entry[attr] = v
        elif self.apnic_entry:
            self.apnic_attributes[attr] = v
        elif self.db_entry:
            self.db_entry[attr] = v
        else:
            raise ValueError(f'{self} has not data')

    def __getitem__(self,attr):
        if self.apnic_entry:
            v = self.apnic_attributes[attr]            
        elif self.db_entry:
            v = apnic_attribute_factory[self.__class__.__name__]['attrs'][attr](self)
        else:
            raise ValueError(f'{self} has not data')

        if v is None:
            if attr in self._list_attrs:
                return []
            else:
                return None
        elif attr in self._list_attrs and not isinstance(v,list):
            return [v]
        else:
            return v

    def get(self,attr,flatten=True):
        try:
            v = self.__getitem__(attr)
        except KeyError:
            return None
        else:
            if flatten and (isinstance(v,list) or isinstance(v,tuple)):
                return ' '.join(v)
            else:
                return v

    def json_serializable(self):
        if self.apnic_entry:
            return self.apnic_attributes
        elif self.db_entry:
            return self.generate_apnic_entry(as_dict=True)
        else:
            raise ValueError(f'{self} has not data')
    
    def dump(self):
        return json.dumps(self.json_serializable(),indent=4)

    def register(self,name,is_primary=False):
        """
        for child's implementation of register_apnic_attributes()
        """
        return attribute(self.__class__.__name__,name,is_primary)
    
    def register_apnic_attributes(self):
        raise NotImplementedError('register_apnic_attributes not implemented')

    def misc_text_parser(self,misc_text):
        """ convert text into dict , format:
            attrname1: value 1
            attrname2: value 2
            attrname2: value 3
            result:
                {
                'attrname1':'value1',
                'attrname2':['value2','value3']
                }
        """
        ret = {}
        if not misc_text: return ret
        for line in misc_text.splitlines():
            line = line.strip()
            if not line: continue
            try:
                k,v = [x.strip() for x in line.split(':',1)]
            except ValueError:
                pass
            else:
                try:
                    ret[k]
                except KeyError:
                    ret[k] = v
                else:
                    if isinstance(ret[k],list):
                        ret[k].append(v)
                    else:
                        ## convert scalar to list
                        ret[k] = [ret[k],v]
        return ret            
    def misc_attrs(self):
        ## no other attrs when calling generate_apnic_entry()
        ## could be overrided to provide attributes (like ipv4)
        return ''

    def generate_apnic_entry(self,as_dict=False):
        """
        when self.db_entry was given,
            as_dict: True
                generate a dict like the one returned from apnic, but no "_links'
                    {
                        'attributes':[
                            {name:attr,value:value of attr},
                            ...
                        ]
                    }
            as_dict: False
                generate a dict like below
                    {
                        attr: value of attr,
                        ...
                    }
        """
        if self.db_entry is None:
            return {'attributes':copy.deepcopy(self.apnic_attributes)}
        else:
            ## default attributes
            def mnt_by():
                return self.apnic_attributes.get('mnt-by') or ['MAINT-TW-TWNIC']
            def source():
                return (self.apnic_attributes.get('source') or 'APNIC').upper()
            
            attrnames =  list(apnic_attribute_factory[self.__class__.__name__]['attrs'].keys())
            ## put the primary attribute as 1st item
            attrnames.sort(key=lambda x:0 if x == apnic_attribute_factory[self.__class__.__name__]['primary'] else 1)
            if as_dict:
                ret = {}
                for attrname in attrnames:
                    factory = apnic_attribute_factory[self.__class__.__name__]['attrs'][attrname]
                    v = factory(self)
                    if v is not None:
                        ret[attrname] = v  

                ## add default attributes
                ret['source'] = source()
                if not 'mnt_bys' in ret:
                    ## rdns object use "mnt_bys"
                    ret['mnt-by'] = mnt_by()

                ## dealing with overwriting attrs
                misc = self.misc_attrs()
                if 'auth' in misc:
                    misc_auth = misc['auth']
                    if isinstance(misc_auth,str):
                        misc_auth = [misc_auth]
                    del  misc['auth']
                else:
                    misc_auth = None
                ret.update(misc)
                
                ## marge misc['auth'[
                if misc_auth:
                    if not ret.get('auth'):
                        ret['auth'] = []
                    if isinstance(ret['auth'],list):
                        ret['auth'].extend(misc_auth)
                    else:
                        misc_auth.append(ret['auth'])
                        ret['auth'] = misc_auth

                return ret
            else:
                apnic_attributes_new = []
                ## misc當中的欄位可以蓋掉其他欄位(auth 是例外，auth是附加）
                misc = self.misc_attrs()
                if 'auth' in misc:
                    misc_auth = misc['auth']
                    del  misc['auth']
                else:
                    misc_auth = None

                for attrname in attrnames:
                    factory = apnic_attribute_factory[self.__class__.__name__]['attrs'][attrname]
                    ## misc當中的欄位可以蓋掉其他欄位
                    if attrname in misc: continue
                    values = factory(self)
                    if not (isinstance(values,list) or isinstance(values,tuple)):
                        values = [values]
                    if attrname == 'auth' and misc_auth:
                        if isinstance(misc_auth,list):
                            values.extend(misc_auth)
                        else:
                            values.append(misc_auth)
                    for value in values:
                        if value is not None:
                            apnic_attributes_new.append({'name':attrname,'value':value})
                ## add default attributes
                if not 'mnt_bys' in apnic_attribute_factory:
                    ## rdns object already having "mnt_bys", so only add "mnt-by" for non-rdns
                    apnic_attributes_new.append({'name':'mnt-by','value':mnt_by()})
                apnic_attributes_new.append({'name':'source','value':source()})
                for attrname, values in misc.items():
                    if not isinstance(v,(list,tuple)):
                        values = [values]
                    for value in values:
                        apnic_attributes_new.append({'name':attrname,'value':value})
                return {'attributes':apnic_attributes_new}

    def normalize_for_compare(self,attr,value):
        if value is None:
            return value
        elif isinstance(value,list):
            ## flatten list to string
            value = ' '.join([x.strip() for x in value])
        if attr == 'address':
            values = value.replace(',',' ').replace('.','').split()
            value = ' '.join(values)
        elif attr == 'phone':
            values = []
            for v in value:
                if v.isdigit():
                    values.append(v)
            value = ''.join(values)
        return value.upper()

    def diff(self,obj,includes_all=False):
        """
        只能比較一樣data source的物件，例如同樣是apnic object或同樣是rmsdb的記錄
        """
        assert isinstance(obj,self.__class__),f"{obj} is not an instance of {self.__class__}"
        assert len(self._diff_attrs) > 0 , f"_diff_attrs has not been set for {self.__class__}"
        difference = {}
        def same(v1,v2):
            if v1 is None or v2 is None:
                return v1 is None and v2 is None
            elif isinstance(v1,str):
                return v1 == v2
            elif isinstance(v1,list):
                if len(v1) == len(v2):
                    for idx,item in enumerate(v1):
                        if item != v2[idx]: return False
                    return True
                else:
                    return False
            else:
                raise ValueError(f"{v1} and {v2} are not comparable")
        for attr in self._diff_attrs:
            self_v = self.normalize_for_compare(attr,self.get(attr))
            obj_v = self.normalize_for_compare(attr,obj.get(attr))
            if includes_all:
                difference[attr] = (self.get(attr),obj.get(attr))
            elif not same(self_v,obj_v):
                difference[attr] = (self.get(attr),obj.get(attr))
        return difference

class WhoisPersonEntry(ObjectEntry):
    typename = 'person'
    _diff_attrs = ('e-mail','nic-hdl','person','phone','address','remarks')
    def register_apnic_attributes(self):
        @self.register('person',True)
        def person(self):
            return self.db_entry['handle_whois']['whois_person'].strip()
        @self.register('nic-hdl')
        def nic_hdl(self):
            if self.db_entry['apnic_person'] and self.db_entry['apnic_person']['nic_hdl']:    
                return self.db_entry['apnic_person']['nic_hdl']
            else:
                ## for creating new object
                return 'AUTO-1'
        @self.register('address')
        def address(self):
            ## 正規化，連接的,之後固定留一個空白成為", "
            streetaddress = self.db_entry['org']['streetaddress']
            assert streetaddress is not None
            addr = ', '.join([x.strip() for x in filter(None,streetaddress.strip().split(','))])
            city = self.db_entry['org']['city']
            if city is None or city.strip() == '':
                return [addr]
            else:
                city = ', '.join([x.strip() for x in filter(None,city.strip().split(','))])
                return [addr,city]
        @self.register('country')
        def country(self):
            return 'TW'
        @self.register('phone')
        def phone(self):
            v = (self.db_entry['handle_whois']['whois_phone']).strip()
            if v.startswith('+'):
                return v
            elif v:
                if v[0] == '0':
                    return f"+886-{v[1:]}"
                else:
                    return f"+886-{v}"
            else:
                return None
        @self.register('e-mail')
        def email(self):
            return (self.db_entry['handle_whois']['whois_email']).lower().strip()
        @self.register('remarks')
        def remarks(self):
            return f"(hid:{self.db_entry['handle']['id'].upper()})"

class WhoisRoleEntry(ObjectEntry):
    typename = 'role'
    _diff_attrs = ('e-mail','nic-hdl','role','admin-c','tech-c',\
                   'abuse-mailbox','country','fax-no','phone','address','remarks')

    def register_apnic_attributes(self):
        @self.register('role',True)
        def role(self):
            role_prefix = 'TWNIC ROLE-'
            role_value = self.db_entry['apnic_role']['role'].strip()
            if not role_value:
                role_value = self.db_entry['org']['id'].upper()
            if not role_value.startswith(role_prefix):
                role_value = f"{role_prefix}{role_value}"
            return role_value

        @self.register('nic-hdl')
        def nic_hdl(self):
            if self.db_entry['apnic_role'] and self.db_entry['apnic_role']['nic_hdl']:    
                ## "TEMP@" is placeholder, caller should remove it before calling gen_apnic_entry()
                assert not self.db_entry['apnic_role']['nic_hdl'].startswith('TEMP@')
                return self.db_entry['apnic_role']['nic_hdl']
            else:
                ## for creating new object
                return 'AUTO-1'
        @self.register('address')
        def address(self):
            org_englishname = self.db_entry['org']['englishname'].strip()
            ## 正規化，連接的,之後固定留一個空白成為", "
            streetaddress = self.db_entry['org']['streetaddress']
            assert streetaddress is not None
            addr = ', '.join([x.strip() for x in filter(None,streetaddress.strip().split(','))])
            city = self.db_entry['org']['city']
            if city is None or city.strip() == '':
                return [org_englishname,addr]
            else:
                city = ', '.join([x.strip() for x in filter(None,city.strip().split(','))])
                return [org_englishname,addr,city]
        @self.register('country')
        def country(self):
            return 'TW'
        @self.register('phone')
        def phone(self):
            v = (self.db_entry['adminhandle']['whois_phone']).strip()
            if v.startswith('+'):
                return v
            elif v:
                if v[0] == '0':
                    return f"+886-{v[1:]}"
                else:
                    return f"+886-{v}"
            else:
                return None
        @self.register('e-mail')
        def email(self):
            return  (self.db_entry['adminhandle']['whois_email']).lower().strip()
        @self.register('abuse-mailbox')
        def abuse_mailbox(self):
            return (self.db_entry['spamhandle']['whois_email']).lower().strip()
        @self.register('admin-c')
        def admin_c(self):
            return (self.db_entry['adminhandle']['nic_hdl']).strip()
        @self.register('tech-c')
        def tech_c(self):
            return (self.db_entry['techhandle']['nic_hdl']).strip()
        @self.register('remarks')
        def remarks(self):
            ## user's remarks
            remarks = []
            if self.db_entry['apnic_role']['remarks'] and self.db_entry['apnic_role']['remarks'].strip():
                remarks.append(self.db_entry['apnic_role']['remarks'].strip())
            ## rms's remarks
            handle_ids = []
            for field in ('adminhandle','techhandle','spamhandle'):
                handle_id = self.db_entry['apnic_role'][field]
                if not handle_id:
                    handle_id = self.db_entry['org'][field]
                handle_ids.append(handle_id.upper())
            ## convert (TT0815-S-TW,TT0815-S-TW,TT0815-S-TW) to (TT0815-S-TW,+,+)
            final_handle_ids = [handle_ids[0]]
            for i in (1,2):
                if handle_ids[i] == handle_ids[i-1]:
                    final_handle_ids.append('+')
                else:
                    final_handle_ids.append(handle_ids[i])
            ## convert (TT0815-S-TW,+,+) to (TT0815-S-TW)
            if final_handle_ids[1] == '+' and final_handle_ids[2]== '+':
                del final_handle_ids[1:]
            ## convert (TT0815-S-TW,TT0815-T-TW,+) to (TT0815-S-TW,TT0815-T-TW)
            elif final_handle_ids[2]== '+':
                del final_handle_ids[2:]
            ## org-id 已經在role中，所以此欄位不放oid
            remarks.append(f"(hid:{','.join(final_handle_ids)})")
            return "\n".join(remarks)
    def misc_attrs(self):
        return self.misc_text_parser(self.db_entry['apnic_role']['role_misc'])

class WhoisIrtEntry(ObjectEntry):
    typename = 'irt'
    _diff_attrs = ('e-mail','irt','admin-c','tech-c',\
                   'abuse-mailbox','country','fax-no','phone','address','remarks')

    def register_apnic_attributes(self):

        @self.register('irt',True)
        def irt(self):
            if self.db_entry['apnic_irt'] and self.db_entry['apnic_irt']['irt']:    
                ## "TEMP@" is placeholder, caller should remove it before calling gen_apnic_entry()
                assert not self.db_entry['apnic_irt']['irt'].startswith('TEMP@')
                irt_prefix = 'IRT-'
                irt_value = self.db_entry['apnic_irt']['irt'].strip()
                if not irt_value:
                    irt_value = self.db_entry['org']['id'].upper()
                if not irt_value.startswith(irt_prefix):
                    irt_value = f"{irt_prefix}{irt_value}"
                return irt_value
            else:
                ## for creating new object
                return 'AUTO-1'
        @self.register('address')
        def address(self):
            org_englishname = self.db_entry['org']['englishname'].strip()
            ## 正規化，連接的,之後固定留一個空白成為", "
            streetaddress = self.db_entry['org']['streetaddress']
            assert streetaddress is not None
            addr = ', '.join([x.strip() for x in filter(None,streetaddress.strip().split(','))])
            city = self.db_entry['org']['city']
            if city is None or city.strip() == '':
                return [org_englishname,addr]
            else:
                city = ', '.join([x.strip() for x in filter(None,city.strip().split(','))])
                return [org_englishname,addr,city]
        @self.register('phone')
        def phone(self):
            if self.db_entry['apnic_irt']['admin_c'] and self.db_entry['apnic_irt']['admin_c']['adminhandle']:
                ## admin_c is not default role
                v = self.db_entry['apnic_irt']['admin_c']['adminhandle']['whois_phone'].strip()
            else:
                v = self.db_entry['adminhandle']['whois_phone'].strip()
            if v.startswith('+'):
                return v
            elif v:
                if v[0] == '0':
                    return f"+886-{v[1:]}"
                else:
                    return f"+886-{v}"
            else:
                return None
        @self.register('e-mail')
        def email(self):
            if self.db_entry['apnic_irt']['admin_c'] and self.db_entry['apnic_irt']['admin_c']['adminhandle']:
                ## admin_c is not default role
                return self.db_entry['apnic_irt']['admin_c']['adminhandle']['whois_email'].lower().strip()
            else:
                return self.db_entry['adminhandle']['whois_email'].lower().strip()
        @self.register('abuse-mailbox')
        def abuse_mailbox(self):
            if self.db_entry['apnic_irt']['abuse_c'] and self.db_entry['apnic_irt']['abuse_c']['spamhandle']:
                return self.db_entry['apnic_irt']['abuse_c']['spamhandle']['whois_email'].lower().strip()
            else:
                return self.db_entry['spamhandle']['whois_email'].lower().strip()
        @self.register('admin-c')
        def admin_c(self):
            if self.db_entry['apnic_irt']['admin_c']:
                return self.db_entry['apnic_irt']['admin_c']['role']['nic_hdl']
            else:
                return self.db_entry['apnic_role']['nic_hdl']
        @self.register('tech-c')
        def tech_c(self):
            if self.db_entry['apnic_irt']['tech_c']:
                return self.db_entry['apnic_irt']['tech_c']['role']['nic_hdl']
            else:
                return self.db_entry['apnic_role']['nic_hdl']
        @self.register('remarks')
        def remarks(self):
            ## user's remarks
            remarks = []
            if self.db_entry['apnic_irt']['remarks'] and self.db_entry['apnic_irt']['remarks'].strip():
                remarks.append(self.db_entry['apnic_irt']['remarks'].strip())
            remarks.append(f"(oid:{self.db_entry['org']['id'].upper()})")
            return "\n".join(remarks)

        @self.register('auth')
        def auth(self):
            auth = []
            if self.db_entry['settings'].get('irt') and 'auth' in self.db_entry['settings']['irt']:
                for value in self.db_entry['settings']['irt']['auth']:
                    auth.append(value)

            ## <SSO email> 不能隨便加，故取消此項目
            ## add adminhandle's email
            #sso_item = f"SSO {self.db_entry['sso_email']}"
            #if not sso_item in auth:
            #    auth.append(sso_item)
            return auth
    def misc_attrs(self):
        return self.misc_text_parser(self.db_entry['apnic_irt']['irt_misc'])

class WhoisAsnEntry(ObjectEntry):
    typename = 'aut-num'
    _diff_attrs = ['aut-num','as-name','default','import','export','descr','admin-c','tech-c','abuse-c','mnt-irt','remarks']
    def register_apnic_attributes(self):
        @self.register('country')
        def country(self):
            return 'TW'        
        @self.register('aut-num',True)
        def aut_num(self):
            return 'AS%s' % self.db_entry['ispasn']['asn']
        @self.register('as-name')
        def asname(self):
            return self.db_entry['asn']['asname']
        @self.register('admin-c')
        def admin_c(self):
            return self.db_entry['ispasn']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('tech-c')
        def tech_c(self):
            return self.db_entry['ispasn']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('abuse-c')
        def abuse_c(self):
            return self.db_entry['ispasn']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('mnt-irt')
        def irt(self):
            return self.db_entry['ispasn']['irt'] or self.db_entry['apnic_irt']['irt']
        @self.register('descr')
        def descr(self):
            rows = [
                self.db_entry['org']['englishname'].strip(),
                self.db_entry['org']['streetaddress'].strip(),
            ]
            if self.db_entry['org']['city']:
                rows.append(self.db_entry['org']['city'].strip())
            return list(filter(None,rows))
        @self.register('default')
        def defaultpolicy(self):
            def reformat_default(body):
                newbody = []
                if 'default' in body:
                    lines = [x.replace('\n','').replace('\r','') for x in body.split('default')]
                    prefix = ''
                elif 'to' in body:
                    lines = [x.replace('\n','').replace('\r','') for x in body.split('to')]
                    prefix = 'to '
                else:
                    lines = body.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    newbody.append(prefix+line)
                return newbody     
            rows = reformat_default(self.db_entry['asn']['defaultpolicy'])
            return list(rows)
        @self.register('export')
        def exportpolicy(self):
            def reformat_exportpolicy(body):
                newbody = []
                if 'export' in body:
                    lines = [x.replace('\n','').replace('\r','') for x in body.split('export')]
                    prefix = ''
                elif 'to' in body:
                    lines = [x.replace('\n','').replace('\r','') for x in body.split('to')]
                    prefix = 'to '
                else:
                    lines = body.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    newbody.append(prefix+line)
                return newbody     
            rows = reformat_exportpolicy(self.db_entry['asn']['exportpolicy'])
            return list(rows)
        @self.register('import')
        def importpolicy(self):
            def reformat_import(body):
                newbody = []
                if 'import' in body:
                    ## omit "import"
                    lines = [x.replace('\n','').replace('\r','') for x in body.split('import')]
                    prefix = ''
                elif 'from' in body:
                    lines = [x.replace('\n','').replace('\r','') for x in body.split('from')]
                    prefix = 'from '
                else:
                    lines = body.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    newbody.append(prefix+line)
                return newbody            
            rows = reformat_import(self.db_entry['asn']['importpolicy'])
            return list(rows)
        @self.register('remarks')
        def remarks(self):
            """
            when self.db_entry['asn']['remarks'] is "", this would returns []
            """
            default_items = [f"(oid:{self.db_entry['org']['id'].upper()})"]
            remarks = []
            if self.db_entry['asn']['remarks']:
                rms_remarks = self.db_entry['asn']['remarks'].strip().splitlines(False)
                for item in rms_remarks:
                    if item in default_items:
                        default_items.remove(item)
                    remarks.append(item)
            return remarks + default_items

    def misc_attrs(self):
        return self.misc_text_parser(self.db_entry['ispasn']['aut_num_misc'])

class WhoisIPv4Entry(ObjectEntry):
    typename = 'inetnum'
    _diff_attrs = ['inetnum','netname','descr','country','admin-c','tech-c','abuse-c','remarks','mnt-by','mnt-irt']
    def register_apnic_attributes(self):
        @self.register('country')
        def country(self):
            return 'TW'
        @self.register('inetnum',True)
        def inetnum(self):
            return f"{self.db_entry['ipv4ispip']['startip']} - {self.db_entry['ipv4ispip']['endip']}"
        @self.register('netname')
        def netname(self):
            return self.db_entry['ipv4ispip']['netname']
        @self.register('admin-c')
        def admin_c(self):
            return self.db_entry['ipv4ispip']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('tech-c')
        def tech_c(self):
            return self.db_entry['ipv4ispip']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('abuse-c')
        def abuse_c(self):
            return self.db_entry['ipv4ispip']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('mnt-irt')
        def irt(self):
            return self.db_entry['ipv4ispip']['irt'] or self.db_entry['apnic_irt']['irt']
        @self.register('descr')
        def descr(self):
            rows = [
                self.db_entry['org']['englishname'].strip(),
                self.db_entry['org']['streetaddress'].strip(),
            ]
            if self.db_entry['org']['city']:
                rows.append(self.db_entry['org']['city'].strip())
            return list(filter(None,rows))
        @self.register('remarks')
        def remarks(self):
            """
            when self.db_entry['ipv4ispip']['remarks'] is "", this would returns []
            """
            if self.db_entry['ipv4ispip']['remarks']:
                remarks = self.db_entry['ipv4ispip']['remarks'].strip().splitlines(False)
                rms_remarks = [f"(oid:{self.db_entry['org']['id'].upper()})"]
                for item in rms_remarks:
                    if item not in remarks:
                        remarks.append(item)
                return remarks
            else:
                return []
        @self.register('status')
        def status(self):
            options = ('ALLOCATED PORTABLE','ASSIGNED PORTABLE')
            if self.db_entry['ipv4ispip']['opiniontype'] in options:
                return self.db_entry['ipv4ispip']['opiniontype']
            else:
                return options[0]
    def misc_attrs(self):
        return self.misc_text_parser(self.db_entry['ipv4ispip']['inetnum_misc'])

class WhoisIPv6Entry(ObjectEntry):
    typename = 'inet6num'
    _diff_attrs = ['inet6num','netname','descr','country','admin-c','tech-c','abuse-c','remarks','mnt-by','mnt-irt']
    def register_apnic_attributes(self):
        @self.register('country')
        def country(self):
            return 'TW'
        @self.register('inet6num',True)
        def inet6num(self):
            return f"{self.db_entry['ipv6ispip']['msbip']}/{self.db_entry['ipv6ispip']['prefixlength']}"
        @self.register('netname')
        def netname(self):
            return self.db_entry['ipv6ispip']['netname']
        @self.register('admin-c')
        def admin_c(self):
            return self.db_entry['ipv6ispip']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('tech-c')
        def tech_c(self):
            return self.db_entry['ipv6ispip']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('abuse-c')
        def abuse_c(self):
            return self.db_entry['ipv6ispip']['role'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('mnt-irt')
        def irt(self):
            return self.db_entry['ipv6ispip']['irt'] or self.db_entry['apnic_irt']['irt']
        @self.register('descr')
        def descr(self):
            rows = [
                self.db_entry['org']['englishname'].strip(),
                self.db_entry['org']['streetaddress'].strip(),
            ]
            if self.db_entry['org']['city']:
                rows.append(self.db_entry['org']['city'].strip())
            return list(filter(None,rows))
        @self.register('remarks')
        def remarks(self):
            """
            when self.db_entry['ipv6ispip']['remarks'] is "", this would returns []
            """
            if self.db_entry['ipv6ispip']['remarks']:
                remarks = self.db_entry['ipv6ispip']['remarks'].strip().splitlines(False)
                rms_remarks = [f"(oid:{self.db_entry['org']['id'].upper()})"]
                for item in rms_remarks:
                    if item not in remarks:
                        remarks.append(item)
                return remarks
            else:
                return []
        @self.register('status')
        def status(self):
            options = ('ALLOCATED PORTABLE','ASSIGNED PORTABLE')
            if self.db_entry['ipv6ispip']['opiniontype'] in options:
                return self.db_entry['ipv6ispip']['opiniontype']
            else:
                return options[0]
    def misc_attrs(self):
        return self.misc_text_parser(self.db_entry['ipv6ispip']['inet6num_misc'])

class RdnsEntry(ObjectEntry):
    """
    apnic 這裡好像有點怪，他的object 網頁上的domain object跟他的api回來的物件的attr不太相同
        (eg. 取回來的資料沒有"nserver"，而是"nameservers")
    這裡給的不能說是apnic的domain,而是比較像是一個沒有文件的"rdns record"（根據api實際行為）
    所以，使用時要呼叫apnic registry api clent的 rdns_update(), 而不是 whois_update()
    """
    typename = 'rdns' ## this is for generating the url for making api request
    _diff_attrs = ['range','country','nameservers','ds_rdatas','admin-c','tech-c','zone-c','descr']
    def register_apnic_attributes(self):
        @self.register('country')
        def country(self):
            return 'TW'

        @self.register('range', True)
        def range(self):
            return self.db_entry['rdns_domain']['cidr']
        
        @self.register('contacts')
        def contacts(self):
            def admin_c():
                return {'type':'admin-c','value':self.db_entry['rdns_domain']['admin_c'] or self.db_entry['apnic_role']['nic_hdl']}
            def tech_c():
                return {'type':'tech-c','value':self.db_entry['rdns_domain']['tech_c'] or self.db_entry['apnic_role']['nic_hdl']}
            def zone_c():
                return {'type':'zone-c','value':self.db_entry['rdns_domain']['zone_c'] or self.db_entry['apnic_role']['nic_hdl']}
            return [admin_c(),tech_c(),zone_c()]
            
        @self.register('nameservers')
        def nameservers(self):
            ret = []
            for line in self.db_entry['rdns_domain']['nameservers'].splitlines(False):
                line = line.strip()
                if line: ret.append(line)
            return ret
        @self.register('ds_rdatas')
        def ds_rdatas(self):
            ret = []
            for line in self.db_entry['rdns_domain']['ds_rdatas'].splitlines(False):
                line = line.strip()
                if line: ret.append(line)
            return ret
        @self.register('descr')
        def descr(self):
            return f"reverse zone for {self.db_entry['rdns_domain']['cidr']}"
        @self.register('mnt_bys')
        def mnt_bys(self):
            return ["MAINT-TW-TWNIC"]

def get_domain_from_cidr(cidr):
    """ returns the reverse domain name (PTR) from cidr """
    startip,mask = cidr.split('/')
    if '.' in startip:
        startip = ipaddress.IPv4Address(startip)
        digits = int(int(mask) / 8)
        assert digits * 8 == int(mask), f"{mask} is invalid for domain"
        return '.'.join(startip.reverse_pointer.split('.')[-digits-2:])
    else:
        """ examples:
            2001:4540:0000:0000:0000:0000:0000:0000/28
            4.5.4.1.0.0.2.ip6.arpa
            2400:4500:0000:0000:0000:0000:0000:0000/32
            0.0.5.4.0.0.4.2.ip6.arpa
            2001:0de4:0000:0000:0000:0000:0000:0000/48
            0.0.0.0.4.e.d.0.1.0.0.2.ip6.arpa
            2001:b000:0000:0000:0000:0000:0000:0000/24
            0.b.1.0.0.2.ip6.arpa
            2001:b300:0000:0000:0000:0000:0000:0000/24
            3.b.1.0.0.2.ip6.arpa        
        """
        msbip = ipaddress.IPv6Address(startip)
        digits = int(int(mask) / 4)
        return '.'.join(msbip.reverse_pointer.split('.')[-digits-2:])

def cut_ipv4(cidr):
    network = ipaddress.ip_network(cidr)
    startip,mask = cidr.split('/')
    mask = int(mask)
    if mask == 24:
        return None
    else:
        n = 2 ** (32-mask-1)
        m = n/256
        if m >= 256:
            m = str(m/256) + '+'
        assert int(m) == m
        #print(cidr,'-->',int(m),(f'{network[0]}/{mask+1}',f'{network[n]}/{mask+1}'))
        return (f'{network[0]}/{mask+1}',f'{network[n]}/{mask+1}')

def get_masks(startip,endip):
    if isinstance(startip,str):
        startip = ipaddress.IPv4Address(startip)
    if isinstance(endip,str):
        endip = ipaddress.IPv4Address(endip)
    n = int(endip) - int(startip) + 1
    masks = []
    while n > 0:
        m = math.floor(math.log2(n))
        masks.append(32-m)
        n = n - 2 ** m
    return masks


def gen_subroutes(cidr,max_length):
    startip,startmask = cidr.split('/')
    startmask = int(startmask)
    ret = []
    network = ipaddress.ip_network(cidr)
    network_size = (int(network[-1])-int(network[0])+1)
    for mask in range(startmask,max_length+1):
        start = ipaddress.ip_address(startip)
        n = 2 ** (mask - startmask)
        assert network_size % n == 0
        chunk_size = int(network_size / n)
        for i in range(n):
            ret.append(f"{str(start)}/{mask}")
            start += chunk_size
    return ret

class RdnsDomainEntry(ObjectEntry):
    """
    """
    typename = 'domain' 
    _diff_attrs = ['domain','country','nserver','descr','admin-c','tech-c','zone-c','ds-rdata']
    def register_apnic_attributes(self):
        @self.register('country')
        def country(self):
            return 'TW'
        @self.register('domain',True)
        def domain(self):
            return get_domain_from_cidr(self.db_entry['rdns_domain']['cidr'])
        
        @self.register('admin-c')
        def admin_c(self):
            return self.db_entry['rdns_domain']['admin_c'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('tech-c')
        def tech_c(self):
            return self.db_entry['rdns_domain']['tech_c'] or self.db_entry['apnic_role']['nic_hdl']
        @self.register('zone-c')
        def zone_c(self):
            return self.db_entry['rdns_domain']['zone_c'] or self.db_entry['apnic_role']['nic_hdl']
            
        @self.register('nserver')
        def nserver(self):
            ret = []
            for line in self.db_entry['rdns_domain']['nameservers'].splitlines(False):
                line = line.strip()
                if line: ret.append(line)
            return ret
        @self.register('ds-rdata')
        def ds_rdata(self):
            ## eg. ds-rdata: 64431 5 1 278BF194C29A812B33935BB2517E17D1486210FA
            ret = []
            for line in self.db_entry['rdns_domain']['ds_rdatas'].splitlines(False):
                line = line.strip()
                if line: ret.append(line)
            return ret
        @self.register('descr')
        def descr(self):
            return f"reverse zone for {self.db_entry['rdns_domain']['cidr']}"

    def misc_attrs(self):
        return self.misc_text_parser(self.db_entry['rdns_domain']['rdns_misc'])

class RouteEntry(ObjectEntry):
    typename = 'route' 
    key_attr = 'range'
    _diff_attrs = ['range','autnum','max_length','id','whois_enabled','roa_enabled']
    def register_apnic_attributes(self):
        @self.register('range',True)
        def range(self):
            return self.db_entry['apnic_route']['cidr']
        @self.register('autnum')
        def autnum(self):
            ## this should be an integer
            return self.db_entry['apnic_route']['autnum']
        @self.register('id')
        def route_id(self):
            return int(self.db_entry['apnic_route']['route_id'])
        @self.register('max_length')
        def max_length(self):
            return self.db_entry['apnic_route']['max_length']
        @self.register('whois_enabled')
        def whois_enabled(self):
            return self.db_entry['apnic_route']['whois_enabled'] == 1
        @self.register('roa_enabled')
        def roa_enabled(self):
            return self.db_entry['apnic_route']['roa_enabled'] == 1
        @self.register('subroutes')
        def subroutes(self):
            subroutes = []
            if self.db_entry['apnic_route']['subroutes']: ## could be "None"
                for line in self.db_entry['apnic_route']['subroutes'].splitlines(False):
                    line = line.strip()
                    if line and ('/' in line): ## simply validate cidr format
                        subroutes.append(line)
            return subroutes if len(subroutes) > 0 else None


class WhoisRouteEntry(ObjectEntry):
    """
    """
    typename = 'whois_route' 
    key_attr = 'route'
    _diff_attrs = ['route','origin','descr']
    def register_apnic_attributes(self):
        @self.register('route',True)
        def route(self):
            return self.db_entry['apnic_route']['cidr']
        @self.register('origin')
        def origin(self):
            ## origin: AS12345
            return f"AS{self.db_entry['apnic_route']['autnum']}"
        @self.register('country')
        def country(self):
            return 'TW'
        @self.register('descr')
        def descr(self):
            rows = [
                self.db_entry['org']['englishname'].strip(),
                self.db_entry['org']['streetaddress'].strip(),
            ]
            if self.db_entry['org']['city']:
                rows.append(self.db_entry['org']['city'].strip())
            return list(filter(None,rows))
        @self.register('notify')
        def notify(self):
            if self.db_entry['apnic_route']['notify']:
                return self.db_entry['adminhandle']['email']
            else:
                return None

    def misc_attrs(self):
        return self.misc_text_parser(self.db_entry['apnic_route']['whois_route_misc'] or '')

class WhoisRoute6Entry(WhoisRouteEntry):
    """
    """
    typename = 'whois_route6' 
    key_attr = 'route6'
    def register_apnic_attributes(self):
        super().register_apnic_attributes()
        ## replace primary key 'route' with 'route6'
        @self.register('route6',True)
        def route6(self):
            return self.db_entry['apnic_route']['cidr']
        @self.register('route')
        def route(self):
            return None
        

def whois_entry_factory(typename,apnic_entry=None):
    if typename == 'aut-num' or typename == 'asn':
        return WhoisAsnEntry(apnic_entry=apnic_entry)
    elif typename == 'inetnum' or typename == 'ipv4':
        return WhoisIPv4Entry(apnic_entry=apnic_entry)
    elif typename == 'inet6num' or typename == 'ipv6':
        return WhoisIPv6Entry(apnic_entry=apnic_entry)
    elif typename == 'person':
        return WhoisPersonEntry(apnic_entry=apnic_entry)
    elif typename == 'role':
        return WhoisRoleEntry(apnic_entry=apnic_entry)
    elif typename == 'irt':
        return WhoisIrtEntry(apnic_entry=apnic_entry)
    elif typename == 'rdns':
        return RdnsEntry(apnic_entry=apnic_entry)
    elif typename == 'domain':
        return RdnsDomainEntry(apnic_entry=apnic_entry)
    elif typename == 'route':
        return RouteEntry(apnic_entry=apnic_entry)
    elif typename == 'whois_route':
        return WhoisRouteEntry(apnic_entry=apnic_entry)
    elif typename == 'whois_route6':
        return WhoisRoute6Entry(apnic_entry=apnic_entry)
    else:
        raise NotImplementedError(typename + ' not implemented in whois_entry_factory')
        #return WhoisEntry(obj_id,apnic_entry)

